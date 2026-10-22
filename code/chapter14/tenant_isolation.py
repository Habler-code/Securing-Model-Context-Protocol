"""Runnable tenant-isolation examples for Chapter 14.

The module deliberately avoids real credentials and external services. Integrate
the same checks with a validated OAuth/OIDC token, secret manager, cache, and
database driver in a non-production environment before deployment.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
from dataclasses import dataclass
from typing import Any, Protocol


IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
ALLOWED_ROLES = frozenset({"viewer", "user", "admin"})
LOGGER = logging.getLogger("mcp.audit")


@dataclass(frozen=True)
class TenantIdentity:
    tenant_id: str
    user_id: str
    role: str


@dataclass(frozen=True)
class ApplicationContext:
    context_id: str
    tenant_id: str
    user_id: str


@dataclass(frozen=True)
class HandleRecord:
    handle_id: str
    tenant_id: str
    owner_user_id: str
    resource_version: int


class SecretStore(Protocol):
    def get_secret(self, path: str) -> str: ...


def _required_identifier(claims: dict[str, Any], claim_name: str) -> str:
    value = claims.get(claim_name)
    if not isinstance(value, str) or not IDENTIFIER_PATTERN.fullmatch(value):
        raise PermissionError(f"Invalid required claim: {claim_name}")
    return value


def extract_tenant_identity(verified_claims: dict[str, Any]) -> TenantIdentity:
    """Normalize claims only after signature and token-policy validation."""
    tenant_id = _required_identifier(verified_claims, "tenant_id")
    user_id = _required_identifier(verified_claims, "sub")
    role = _required_identifier(verified_claims, "role")
    if role not in ALLOWED_ROLES:
        raise PermissionError("Unrecognized role")
    return TenantIdentity(tenant_id, user_id, role)


def validate_context_boundary(
    context: ApplicationContext,
    identity: TenantIdentity,
) -> None:
    """Reject application context bound to a different principal."""
    if (
        context.tenant_id != identity.tenant_id
        or context.user_id != identity.user_id
    ):
        raise PermissionError("Application context boundary check failed")


def _validated_path_segment(value: str, field: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER_PATTERN.fullmatch(value):
        raise ValueError(f"Invalid secret path segment: {field}")
    return value


def get_tenant_credentials(
    store: SecretStore,
    identity: TenantIdentity,
    service: str,
) -> str:
    """Retrieve one service credential for the authenticated tenant."""
    tenant = _validated_path_segment(identity.tenant_id, "tenant_id")
    service_name = _validated_path_segment(service, "service")
    return store.get_secret(f"tenants/{tenant}/services/{service_name}/api_key")


def authorize_handle_action(
    record: HandleRecord,
    identity: TenantIdentity,
    action: str,
    allowed_actions: frozenset[str],
) -> HandleRecord:
    """Authorize the current caller for one action on a resolved handle."""
    if record.tenant_id != identity.tenant_id:
        raise PermissionError("Handle does not belong to this tenant")
    if record.owner_user_id != identity.user_id and identity.role != "admin":
        raise PermissionError("Caller does not own this handle")
    if action not in allowed_actions:
        raise PermissionError("Action is not permitted for this handle")
    return record


def tenant_cache_key(
    tenant_id: str,
    logical_key: str,
    cache_key_secret: bytes,
) -> str:
    """Build an opaque, tenant-bound cache key."""
    tenant = _validated_path_segment(tenant_id, "tenant_id")
    if not isinstance(logical_key, str) or not logical_key:
        raise ValueError("logical_key must be a non-empty string")
    logical_key_bytes = logical_key.encode("utf-8")
    if len(logical_key_bytes) > 1_024:
        raise ValueError("logical_key exceeds the byte limit")
    if not isinstance(cache_key_secret, bytes) or len(cache_key_secret) < 32:
        raise ValueError("cache_key_secret must contain at least 32 bytes")
    material = tenant.encode("utf-8") + b"\x00" + logical_key_bytes
    digest = hmac.new(cache_key_secret, material, hashlib.sha256).hexdigest()
    return f"tenant:v1:{digest}"


def private_cache_key(
    identity: TenantIdentity,
    server_id: str,
    method: str,
    parameters: dict[str, Any],
    authorization_context: str,
    cache_key_secret: bytes,
) -> str:
    """Partition a personalized response by caller and authorization state."""
    for value in (server_id, method, authorization_context):
        if not isinstance(value, str) or not value:
            raise ValueError("private cache context is incomplete")
    logical_key = json.dumps(
        {
            "subject": identity.user_id,
            "role": identity.role,
            "server": server_id,
            "method": method,
            "parameters": parameters,
            "authorization_context": authorization_context,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return tenant_cache_key(identity.tenant_id, logical_key, cache_key_secret)


def fetch_document(
    connection: Any, identity: TenantIdentity, document_id: str
) -> Any:
    """Use a psycopg-compatible adapter with transaction-local tenant state."""
    if not isinstance(document_id, str) or not document_id:
        raise ValueError("document_id is required")
    with connection.transaction():
        connection.execute(
            "SELECT set_config('app.tenant_id', %s, true)",
            (identity.tenant_id,),
        )
        return connection.execute(
            """SELECT document_id, title, body FROM documents
            WHERE tenant_id = %s AND document_id = %s""",
            (identity.tenant_id, document_id),
        ).fetchone()


def audit_tool_decision(
    tenant_ref: str, user_ref: str, tool: str, decision: str, reason_code: str
) -> None:
    """Send minimal fields to an application-configured structured logger."""
    if decision not in {"allow", "deny", "error"}:
        raise ValueError("invalid authorization decision")
    fields = (tenant_ref, user_ref, tool, reason_code)
    if any(not isinstance(value, str) or not value or len(value) > 256 for value in fields):
        raise ValueError("audit references must be bounded non-empty strings")
    LOGGER.info(
        "tool_authorization",
        extra={"tenant_ref": tenant_ref, "user_ref": user_ref, "tool": tool,
               "decision": decision, "reason_code": reason_code},
    )


def _expect_denied(operation: Any) -> None:
    try:
        operation()
    except (PermissionError, ValueError):
        return
    raise AssertionError("Expected the cross-boundary operation to be denied")


def run_boundary_checks() -> None:
    """Exercise same-tenant success and representative cross-tenant failures."""
    alice = extract_tenant_identity(
        {"tenant_id": "tenant-a", "sub": "alice", "role": "user"}
    )
    bob = extract_tenant_identity(
        {"tenant_id": "tenant-b", "sub": "bob", "role": "user"}
    )
    context = ApplicationContext("ctx_4f0a", "tenant-a", "alice")
    validate_context_boundary(context, alice)
    _expect_denied(lambda: validate_context_boundary(context, bob))

    record = HandleRecord("cst_A7K9", "tenant-a", "alice", 1)
    authorize_handle_action(record, alice, "read", frozenset({"read"}))
    _expect_denied(
        lambda: authorize_handle_action(
            record, bob, "read", frozenset({"read"})
        )
    )
    _expect_denied(
        lambda: authorize_handle_action(
            record, alice, "export", frozenset({"read"})
        )
    )

    key_secret = bytes(range(32))
    key_a = tenant_cache_key("tenant-a", "tools/list", key_secret)
    key_b = tenant_cache_key("tenant-b", "tools/list", key_secret)
    assert key_a != key_b


if __name__ == "__main__":
    run_boundary_checks()
    print("Tenant-isolation checks passed without exposing tenant data or secrets.")
