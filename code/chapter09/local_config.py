"""Chapter 9's configuration admission, environment clearing and protected jail."""

from __future__ import annotations

import io
import json
import logging
import os
import secrets
import stat
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import MutableMapping, TextIO
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)
MAX_CONFIG_BYTES = 16 * 1024
MAX_FILE_BYTES = 1024 * 1024
APPROVED_API_ORIGINS = frozenset({"https://api.example.com"})


@dataclass(frozen=True)
class ServerConfig:
    api_base_url: str
    tenant_id: str
    sandbox_dir: str
    api_token: str = field(repr=False)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate configuration key")
        result[key] = value
    return result


def load_secure_config(
    config_path: str | Path, *, environment: MutableMapping[str, str] | None = None,
) -> ServerConfig:
    """Path and approved origins are deployment policy, not tool-call input.

    `environment` is test injection; normal startup consumes and removes the
    token from os.environ exactly as the chapter describes.
    """
    with Path(config_path).open("rb") as source:
        encoded = source.read(MAX_CONFIG_BYTES + 1)
    if len(encoded) > MAX_CONFIG_BYTES:
        raise RuntimeError("startup blocked: configuration exceeds policy")
    try:
        raw = json.loads(encoded.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeError, ValueError):
        raise RuntimeError("startup blocked: invalid configuration JSON") from None
    if not isinstance(raw, dict) or set(raw) != {"apiBaseUrl", "tenantId", "sandboxDir"}:
        raise RuntimeError("startup blocked: expected non-secret configuration fields only")
    if any(not isinstance(raw[key], str) or not raw[key].strip() for key in raw):
        raise RuntimeError("startup blocked: configuration values must be nonempty strings")
    base, tenant, sandbox = (raw[key].strip() for key in ("apiBaseUrl", "tenantId", "sandboxDir"))
    if len(tenant) > 100 or any(ord(c) < 32 for c in tenant):
        raise RuntimeError("startup blocked: invalid tenant identifier")
    try:
        parsed = urlsplit(base)
        origin = f"{parsed.scheme}://{parsed.hostname or ''}"
        if parsed.port is not None:
            origin += f":{parsed.port}"
    except ValueError:
        raise RuntimeError("startup blocked: invalid apiBaseUrl") from None
    if (
        parsed.scheme != "https" or parsed.username is not None or parsed.password is not None
        or parsed.query or parsed.fragment or origin not in APPROVED_API_ORIGINS
    ):
        raise RuntimeError("startup blocked: API origin is not approved")
    sandbox_dir = Path(sandbox).resolve(strict=True)
    if not sandbox_dir.is_dir():
        raise RuntimeError("startup blocked: sandbox directory does not exist")
    source_env = os.environ if environment is None else environment
    token = source_env.pop("MCP_API_TOKEN", "")
    if not isinstance(token, str) or not token or len(token) > 8192 or any(ord(c) < 33 for c in token):
        raise RuntimeError("startup blocked: missing or invalid MCP_API_TOKEN")
    return ServerConfig(base, tenant, str(sandbox_dir), token)


def secure_read_file(base_dir: str, requested_path: str) -> str:
    """Canonical containment for a root protected from concurrent hostile writes.

    Like the book, this does NOT implement a confined-open primitive for every
    path component. OS isolation and protected directory ownership are required.
    """
    if not isinstance(requested_path, str) or not requested_path or "\x00" in requested_path:
        raise PermissionError("invalid sandbox path")
    base = Path(base_dir).resolve(strict=True)
    requested = (base / requested_path).resolve(strict=False)
    if not requested.is_relative_to(base):
        logger.warning("sandbox path denied")  # Do not log an attacker-supplied path.
        raise PermissionError("path is outside the permitted sandbox")
    # Check before opening as well: an accidental FIFO/device inside a trusted
    # root must not block the read before the post-open regular-file check.
    if not stat.S_ISREG(requested.stat().st_mode):
        raise PermissionError("sandbox read requires a regular file")
    with requested.open("rb") as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise PermissionError("sandbox read requires a regular file")
        encoded = source.read(MAX_FILE_BYTES + 1)
    if len(encoded) > MAX_FILE_BYTES:
        raise ValueError("sandbox file exceeds read policy")
    return encoded.decode("utf-8")


def log_server_start(config: ServerConfig, *, stream: TextIO | None = None) -> None:
    """Keep MCP stdout protocol-only; diagnostics contain no token material."""
    event = {"event": "mcp_server.start", "sandbox_jail": config.sandbox_dir, "apiToken": "[redacted]"}
    if stream is None:
        logger.info("%s", json.dumps(event))
    else:
        print(json.dumps(event), file=stream)


def child_environment() -> dict[str, str]:
    """Ordinary helpers receive no API credential, only required non-secret env."""
    return {"LANG": "C.UTF-8"}


def main(config_path: str = "config.json") -> None:
    try:
        config = load_secure_config(config_path)
        log_server_start(config)
        # A real launcher chooses a fixed executable, uses child_environment(),
        # captures startup failure for the operator, and applies an OS sandbox.
    except (OSError, RuntimeError, ValueError):
        logger.error("failed to start local MCP server")
        raise SystemExit(1) from None


def demo() -> None:
    with tempfile.TemporaryDirectory(prefix="mcp-local-config-") as temporary:
        root = Path(temporary)
        (root / "document.txt").write_text("approved document", encoding="utf-8")
        config_path = root / "config.json"
        config_path.write_text(json.dumps({
            "apiBaseUrl": "https://api.example.com", "tenantId": "demo-tenant", "sandboxDir": str(root),
        }), encoding="utf-8")
        environment = {"MCP_API_TOKEN": secrets.token_urlsafe(32)}
        config = load_secure_config(config_path, environment=environment)
        assert "MCP_API_TOKEN" not in environment
        assert secure_read_file(config.sandbox_dir, "document.txt") == "approved document"
        capture = io.StringIO()
        log_server_start(config, stream=capture)
        assert config.api_token not in capture.getvalue() and config.api_token not in repr(config)
        assert "MCP_API_TOKEN" not in child_environment()
        print("Configuration accepted, startup token removed, protected jail read accepted.")
        try:
            load_secure_config(config_path, environment={})
        except RuntimeError:
            print("Missing credential blocked startup.")


# Compatibility names for the earlier companion; the current book names above
# are authoritative. These wrappers do not change the security policy.
Config = ServerConfig
load_config = load_secure_config
log_start = log_server_start


def redact(_: str) -> str:
    return "[redacted]"


if __name__ == "__main__":
    logging.basicConfig(stream=sys.stderr, level=logging.INFO)
    demo()
