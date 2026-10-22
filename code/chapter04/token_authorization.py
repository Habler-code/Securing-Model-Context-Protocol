"""Chapter 4: verify JWTs, then enforce tenant, resource policy and tool scope.

The current chapter uses PyJWT with cryptography; configure the exact issuer
and metadata-validated JWKS URI before serving requests. The offline demo never
contacts an identity provider and keeps its ephemeral private key in memory.
"""
from collections.abc import Callable, Mapping
from dataclasses import dataclass
import ssl
from typing import Any
from urllib.parse import urlsplit

import jwt
from jwt import PyJWKClient
from jwt.exceptions import PyJWKClientError


TRUSTED_ISSUER = ""
TRUSTED_JWKS_URI = ""
jwks_client: Any = None


def configure_trusted_jwks(
    issuer: str,
    jwks_uri: str,
    *,
    signing_key_client: Any = None,
) -> None:
    """Configure once at startup after validating issuer metadata/endpoint policy.

    The optional resolver is a trusted adapter boundary for offline fixtures or
    an organization's governed JWKS cache. It is never request-supplied input.
    """
    global TRUSTED_ISSUER, TRUSTED_JWKS_URI, jwks_client
    for value in (issuer, jwks_uri):
        _text(value)
        parts = urlsplit(value)
        if (parts.scheme != "https" or not parts.hostname or parts.username is not None
                or parts.password is not None or parts.fragment):
            raise ValueError("issuer and JWKS URI require approved HTTPS URLs")
    client = signing_key_client
    if client is None:
        client = PyJWKClient(
            jwks_uri, cache_keys=False, cache_jwk_set=True, lifespan=300,
            timeout=5, ssl_context=ssl.create_default_context(), cooldown_duration=30,
        )
    if not callable(getattr(client, "get_signing_key_from_jwt", None)):
        raise ValueError("invalid signing-key adapter")
    TRUSTED_ISSUER, TRUSTED_JWKS_URI, jwks_client = issuer, jwks_uri, client


def _text(value: object) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 2_048:
        raise ValueError("invalid claim or policy value")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("invalid claim or policy value")
    return value


@dataclass(frozen=True)
class TokenClaims:
    """Already verified token claims, with application tenant/scope mappings."""

    iss: str
    aud: str
    sub: str
    tenant_id: str
    scopes: tuple[str, ...]

    def __post_init__(self) -> None:
        for value in (self.iss, self.aud, self.sub, self.tenant_id):
            _text(value)
        if not isinstance(self.scopes, tuple) or len(self.scopes) > 100:
            raise ValueError("scopes must be a bounded tuple")
        for scope in self.scopes:
            _text(scope)
            if " " in scope:
                raise ValueError("each scope must be a single scope token")


TOOL_SCOPE: dict[str, str] = {
    "read_resource": "docs:read",
    "search": "search:read",
    "create_ticket": "tickets:write",
}


def validate_and_parse_token(raw_token: str, expected_aud: str) -> TokenClaims:
    """Verify RS256, issuer, audience and time/identity claims before normalization."""
    try:
        _text(expected_aud)
        if not TRUSTED_ISSUER or not TRUSTED_JWKS_URI or jwks_client is None:
            raise ValueError("token verifier is not configured")
        if not isinstance(raw_token, str) or not raw_token or len(raw_token) > 65_536:
            raise ValueError("invalid token input")
        signing_key = jwks_client.get_signing_key_from_jwt(raw_token)
        payload = jwt.decode(
            raw_token, signing_key.key, algorithms=["RS256"], audience=expected_aud,
            issuer=TRUSTED_ISSUER,
            options={"require": ["exp", "iss", "aud", "sub", "tenant_id"]},
        )
        raw_scope = payload.get("scope", "")
        if not isinstance(raw_scope, str) or len(raw_scope) > 8_192:
            raise ValueError("invalid scope claim")
        return TokenClaims(
            iss=_text(payload.get("iss")), aud=expected_aud,
            sub=_text(payload.get("sub")), tenant_id=_text(payload.get("tenant_id")),
            scopes=tuple(raw_scope.split()),
        )
    except Exception:
        # Keep raw tokens, key-selection details and exceptions out of client errors.
        raise PermissionError("invalid token") from None


def require_aud(claims: TokenClaims, expected_aud: str) -> None:
    _text(expected_aud)
    if claims.aud != expected_aud:
        raise PermissionError("invalid audience")


def require_tenant(claims: TokenClaims, requested_tenant_id: str) -> None:
    try:
        tenant_id = _text(requested_tenant_id)
    except ValueError as error:
        raise PermissionError("invalid tenant binding") from error
    if claims.tenant_id != tenant_id:
        raise PermissionError("cross-tenant access blocked")


def require_scope(claims: TokenClaims, required: str) -> None:
    if required not in claims.scopes:
        raise PermissionError("insufficient scope")


def authorize_tool_call(
    claims: TokenClaims,
    tool_name: str,
    args: Mapping[str, object],
    subject_policy: Callable[[str, str, str, Mapping[str, object]], bool],
) -> None:
    """Apply the chapter's tenant, application-resource policy and scope gate.

    Construct claims through validate_and_parse_token; it binds issuer/audience.
    subject_policy must query trusted tenant-scoped application policy, not ask
    a model whether the caller should be allowed.
    """
    if not isinstance(claims, TokenClaims) or not isinstance(args, Mapping) or not isinstance(tool_name, str):
        raise PermissionError("invalid authorization input")
    require_tenant(claims, args.get("tenantId"))  # type: ignore[arg-type]
    try:
        policy_allowed = subject_policy(claims.sub, claims.tenant_id, tool_name, args)
    except Exception:
        raise PermissionError("resource policy unavailable") from None
    if policy_allowed is not True:
        raise PermissionError("subject is not authorized for the requested resource")
    required_scope = TOOL_SCOPE.get(tool_name)
    if required_scope is None:
        raise PermissionError("unknown tool")
    require_scope(claims, required_scope)


def demo() -> None:
    from datetime import datetime, timedelta, timezone
    from types import SimpleNamespace
    from cryptography.hazmat.primitives.asymmetric import rsa

    issuer = "https://identity.example.test"
    audience = "https://mcp.example.test"
    key = rsa.generate_private_key(public_exponent=65_537, key_size=2_048)

    class OfflineKeys:
        def get_signing_key_from_jwt(self, _token):
            return SimpleNamespace(key=key.public_key())

    configure_trusted_jwks(issuer, "https://identity.example.test/configured-jwks", signing_key_client=OfflineKeys())
    token = jwt.encode({
        "iss": issuer, "aud": audience, "sub": "reader-example", "tenant_id": "tenant-example",
        "scope": "search:read", "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
    }, key, algorithm="RS256", headers={"kid": "ephemeral-demo-key"})
    claims = validate_and_parse_token(token, audience)
    policy = lambda subject, tenant, tool, args: subject == "reader-example" and tenant == "tenant-example" and args.get("resourceId") == "document-example"
    args = {"tenantId": "tenant-example", "resourceId": "document-example"}
    authorize_tool_call(claims, "search", args, policy)
    print({"search": "authorized"})
    try:
        authorize_tool_call(claims, "create_ticket", args, policy)
    except PermissionError:
        print({"create_ticket": "denied_missing_scope"})


if __name__ == "__main__":
    demo()
