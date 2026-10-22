"""Chapter 10: Python application egress policy, not a network sandbox.

The current chapter uses requests. This companion uses urllib to avoid an
additional HTTP dependency; EgressFirewall.safe_fetch retains the book's API.
"""

from __future__ import annotations

import re
import ssl
from dataclasses import dataclass
from typing import Callable, Mapping
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

MAX_REQUEST_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 1024 * 1024
SOCKET_TIMEOUT_SECONDS = 10


@dataclass(frozen=True)
class EgressResponse:
    status_code: int
    headers: Mapping[str, str]
    content: bytes

    @property
    def text(self) -> str:
        return self.content.decode("utf-8")


Transport = Callable[[str, str, Mapping[str, str], bytes | None, float], EgressResponse]


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _urllib_transport(url: str, method: str, headers: Mapping[str, str], body: bytes | None, timeout: float) -> EgressResponse:
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols(["http/1.1"])
    # Ignore ambient proxy environment variables. A deployment with a required
    # egress proxy must supply its trusted adapter explicitly.
    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context), _NoRedirect())
    request = Request(url, data=body, headers=dict(headers), method=method)
    try:
        response = opener.open(request, timeout=timeout)
    except HTTPError as error:
        response = error  # includes redirects, which remain un-followed
    with response:
        status = response.status
        if 300 <= status < 400:
            return EgressResponse(status, dict(response.headers), b"")
        content = response.read(MAX_RESPONSE_BYTES + 1)
        if len(content) > MAX_RESPONSE_BYTES:
            raise ValueError("egress response exceeds limit")
        return EgressResponse(status, dict(response.headers), content)


class EgressFirewall:
    def __init__(self, allowed_domains: list[str], *, transport: Transport | None = None):
        self.allowed_hosts: frozenset[str] = frozenset(self._hostname(value) for value in allowed_domains)
        if not self.allowed_hosts:
            raise ValueError("an explicit hostname allowlist is required")
        self._transport = _urllib_transport if transport is None else transport

    @staticmethod
    def _hostname(value: str) -> str:
        if not isinstance(value, str):
            raise ValueError("invalid hostname policy")
        hostname = value.strip().lower()
        if not hostname or len(hostname) > 253 or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in hostname.split(".")
        ):
            raise ValueError("invalid hostname policy")
        return hostname

    def safe_fetch(self, url: str, method: str = "GET", **kwargs) -> EgressResponse:
        """Exact host, HTTPS, no redirects, bounded bytes, fixed socket timeout.

        Accepted kwargs are data (str/bytes) and headers (Accept/Content-Type).
        Caller-controlled redirects, timeout, proxies, auth and TLS options are
        deliberately unavailable. Add scoped credentials in a trusted adapter.
        """
        if not isinstance(url, str) or len(url) > 4096 or any(ord(c) < 33 for c in url):
            raise ValueError("invalid URL")
        parsed = urlsplit(url)
        try:
            port = parsed.port
        except ValueError:
            raise ValueError("invalid URL port") from None
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("egress requires a complete HTTPS URL")
        if parsed.username is not None or parsed.password is not None or port not in (None, 443) or parsed.fragment:
            raise ValueError("URL credentials, alternate ports and fragments are not allowed")
        if parsed.hostname.lower() not in self.allowed_hosts:
            raise ValueError("egress hostname is not approved")
        if method not in ("GET", "POST") or set(kwargs) - {"data", "headers"}:
            raise ValueError("egress method or option is not approved")
        body = kwargs.get("data")
        if body is not None and not isinstance(body, (str, bytes)):
            raise ValueError("egress data must be a bounded string or bytes")
        body = body.encode("utf-8") if isinstance(body, str) else body
        if method == "GET" and body is not None:
            raise ValueError("GET body is not allowed")
        if body is not None and len(body) > MAX_REQUEST_BYTES:
            raise ValueError("egress request exceeds limit")
        supplied_headers = kwargs.get("headers", {})
        if not isinstance(supplied_headers, dict):
            raise ValueError("invalid headers")
        headers: dict[str, str] = {}
        for name, value in supplied_headers.items():
            if not isinstance(name, str) or name.lower() not in {"accept", "content-type"}:
                raise ValueError("egress header is not approved")
            if not isinstance(value, str) or len(value) > 1000 or any(ord(c) < 32 or ord(c) > 126 for c in value):
                raise ValueError("invalid egress header")
            headers[name] = value
        response = self._transport(url, method, headers, body, SOCKET_TIMEOUT_SECONDS)
        if 300 <= response.status_code < 400:
            raise ValueError("egress redirects are not allowed")
        if len(response.content) > MAX_RESPONSE_BYTES:
            raise ValueError("egress response exceeds limit")
        return response


def demo() -> None:
    client = EgressFirewall(
        ["api.github.com", "vault.internal.example"],
        transport=lambda *_: EgressResponse(200, {"Content-Type": "text/plain"}, b"approved offline fixture"),
    )
    assert client.safe_fetch("https://api.github.com/users/octocat").status_code == 200
    for destination in ("https://api.github.com.attacker.example/", "https://169.254.169.254/"):
        try:
            client.safe_fetch(destination)
        except ValueError:
            print("Blocked unapproved destination before transport.")
    print("Approved offline response accepted; no network request was sent.")


if __name__ == "__main__":
    demo()
