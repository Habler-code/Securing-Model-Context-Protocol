"""Chapter 3: trusted OAuth endpoints, PKCE, state and a bounded token exchange.

This is the Python standard-library companion to the current chapter. The static
issuer profile stands in for metadata that a real client must establish safely.
The functions are building blocks, not a complete browser/callback application.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import ssl
from collections.abc import Mapping, Sequence
from types import MappingProxyType
from urllib.error import HTTPError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener


TRUSTED_ISSUER = "https://auth.example.com"
TRUSTED_OAUTH_PROFILE = MappingProxyType({
    "issuer": TRUSTED_ISSUER,
    "authorization_endpoint": f"{TRUSTED_ISSUER}/authorize",
    "token_endpoint": f"{TRUSTED_ISSUER}/oauth/token",
})
MCP_RESOURCE = "https://mcp.example.com"
MAX_TOKEN_RESPONSE = 1_048_576


def require_trusted_endpoint(endpoint: str, endpoint_kind: str, issuer: str) -> None:
    """Require the exact endpoint from this independently trusted issuer profile."""
    try:
        if endpoint_kind not in {"authorization_endpoint", "token_endpoint"}:
            raise ValueError
        if issuer != TRUSTED_ISSUER or endpoint != TRUSTED_OAUTH_PROFILE[endpoint_kind]:
            raise ValueError
        parsed = urlsplit(endpoint)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.fragment):
            raise ValueError
    except Exception:
        raise ValueError("OAuth endpoint is not trusted") from None


class NoRedirect(HTTPRedirectHandler):
    """Never resend an authorization code or verifier to a redirect destination."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise HTTPError("", code, "OAuth redirect refused", None, None) from None


TOKEN_OPENER = build_opener(
    HTTPSHandler(context=ssl.create_default_context()),
    NoRedirect(),
)


def base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _challenge(verifier: str) -> str:
    if not isinstance(verifier, str) or re.fullmatch(r"[A-Za-z0-9._~-]{43,128}", verifier) is None:
        raise RuntimeError("Invalid OAuth flow") from None
    return base64url(hashlib.sha256(verifier.encode("ascii")).digest())


def make_pkce_and_state() -> dict[str, str]:
    verifier = base64url(secrets.token_bytes(32))
    return {
        "verifier": verifier,
        "challenge": _challenge(verifier),
        "state": secrets.token_urlsafe(32),
        "issuer": TRUSTED_ISSUER,
    }


def _nonempty_ascii(value: object, maximum: int = 8_192) -> str:
    if (not isinstance(value, str) or not value or len(value) > maximum
            or any(ord(char) < 33 or ord(char) > 126 for char in value)):
        raise RuntimeError("Invalid OAuth input") from None
    return value


def build_authorization_url(
    authorization_endpoint: str,
    client_id: str,
    redirect_uri: str,
    scopes: Sequence[str],
    flow: Mapping[str, str],
) -> str:
    """Build an authorization URL from configured client data and a pending flow.

    client_id and redirect_uri are trusted registered-client configuration.
    Persist flow securely before navigating to this URL; never expose its
    verifier to the browser, model context or an audit log.
    """
    try:
        require_trusted_endpoint(authorization_endpoint, "authorization_endpoint", flow["issuer"])
        _nonempty_ascii(client_id, 2_048)
        _nonempty_ascii(redirect_uri, 2_048)
        _nonempty_ascii(flow["state"], 1_024)
        if flow["challenge"] != _challenge(flow["verifier"]):
            raise ValueError
        if isinstance(scopes, (str, bytes)) or not scopes or len(scopes) > 100:
            raise ValueError
        scope_tokens = [_nonempty_ascii(scope, 200) for scope in scopes]
        separator = "&" if urlsplit(authorization_endpoint).query else "?"
        return authorization_endpoint + separator + urlencode({
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(scope_tokens),
            "state": flow["state"],
            "code_challenge": flow["challenge"],
            "code_challenge_method": "S256",
            "resource": MCP_RESOURCE,
        })
    except Exception:
        raise RuntimeError("Could not build OAuth authorization request") from None


def validate_callback(
    expected_state: str,
    received_state: str | None,
    expected_issuer: str,
    received_issuer: str | None,
) -> None:
    """Check state and the required issuer parameter after strict callback parsing."""
    try:
        expected = _nonempty_ascii(expected_state, 1_024)
        received = _nonempty_ascii(received_state, 1_024)
        if not hmac.compare_digest(expected, received):
            raise ValueError
        if expected_issuer != TRUSTED_ISSUER or received_issuer != expected_issuer:
            raise ValueError
    except Exception:
        raise RuntimeError("OAuth callback validation failed") from None


def exchange_code_for_token(
    token_endpoint: str,
    code: str,
    redirect_uri: str,
    client_id: str,
    code_verifier: str,
    expected_issuer: str,
) -> dict[str, object]:
    """Exchange only at the trusted endpoint; reject redirects and oversized JSON."""
    try:
        require_trusted_endpoint(token_endpoint, "token_endpoint", expected_issuer)
        _nonempty_ascii(code)
        _nonempty_ascii(redirect_uri, 2_048)
        _nonempty_ascii(client_id, 2_048)
        _challenge(code_verifier)
        body = urlencode({
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "code_verifier": code_verifier,
            "resource": MCP_RESOURCE,
        }).encode("ascii")
        request = Request(token_endpoint, data=body, method="POST", headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        })
        with TOKEN_OPENER.open(request, timeout=10) as response:
            raw = response.read(MAX_TOKEN_RESPONSE + 1)
        if len(raw) > MAX_TOKEN_RESPONSE:
            raise ValueError
        result = json.loads(raw.decode("utf-8"))
        if not isinstance(result, dict):
            raise ValueError
        access_token = result.get("access_token")
        token_type = result.get("token_type")
        if not isinstance(access_token, str) or not access_token.strip():
            raise ValueError
        if not isinstance(token_type, str) or token_type.casefold() != "bearer":
            raise ValueError
        return result
    except Exception:
        # Do not expose exception chains containing response bodies or credentials.
        raise RuntimeError("OAuth token exchange failed") from None


def demo() -> None:
    flow = make_pkce_and_state()
    url = build_authorization_url(TRUSTED_OAUTH_PROFILE["authorization_endpoint"],
                                  "offline-client", "https://client.example.com/callback",
                                  ("docs:read",), flow)
    validate_callback(flow["state"], flow["state"], flow["issuer"], flow["issuer"])
    print({"authorization_origin": urlsplit(url).netloc, "pkce": "S256", "callback": "accepted", "network_requests": 0})
    try:
        validate_callback(flow["state"], "wrong-state", flow["issuer"], flow["issuer"])
    except RuntimeError:
        print({"callback": "rejected_state_mismatch"})


if __name__ == "__main__":
    demo()
