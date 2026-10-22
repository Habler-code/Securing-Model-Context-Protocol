"""Chapter 5: normalize verified provider evidence into app-owned membership.

The upstream verifier establishes issuer/subject and token validity. The local
membership adapter supplies application user, tenant and roles. This module
does not validate tokens, call a provider or infer membership from email.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass


@dataclass(frozen=True)
class Principal:
    user_id: str
    tenant_id: str
    roles: tuple[str, ...]
    issuer: str
    subject: str


@dataclass(frozen=True)
class ProviderClaimProfile:
    tenant_claim: str | None
    user_claim: str | None


@dataclass(frozen=True)
class VerifiedMembership:
    issuer: str
    subject: str
    user_id: str
    tenant_id: str
    roles: tuple[str, ...]


def required_string_claim(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 2_048:
        raise ValueError(f"missing or invalid {name} claim")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError(f"missing or invalid {name} claim")
    return value


def normalize_claims(
    claims: Mapping[str, object],
    *,
    trusted_issuer_profiles: Mapping[str, ProviderClaimProfile],
    membership: VerifiedMembership,
) -> Principal:
    if not isinstance(claims, Mapping) or not isinstance(trusted_issuer_profiles, Mapping):
        raise ValueError("invalid verified identity input")
    issuer = required_string_claim(claims.get("iss"), "issuer")
    subject = required_string_claim(claims.get("sub"), "subject")
    profile = trusted_issuer_profiles.get(issuer)
    if not isinstance(profile, ProviderClaimProfile):
        raise ValueError("issuer has no approved claim profile")
    if not isinstance(membership, VerifiedMembership):
        raise ValueError("membership does not match the verified identity")
    if membership.issuer != issuer or membership.subject != subject:
        raise ValueError("membership does not match the verified identity")
    required_string_claim(membership.tenant_id, "membership tenant")
    required_string_claim(membership.user_id, "membership user")
    if not isinstance(membership.roles, tuple) or len(membership.roles) > 100:
        raise ValueError("membership roles are invalid")
    for role in membership.roles:
        required_string_claim(role, "membership role")

    if profile.tenant_claim is not None:
        tenant_claim = required_string_claim(profile.tenant_claim, "profile tenant field")
        token_tenant = required_string_claim(claims.get(tenant_claim), tenant_claim)
        if token_tenant != membership.tenant_id:
            raise ValueError("token tenant does not match app membership")
    if profile.user_claim is not None:
        user_claim = required_string_claim(profile.user_claim, "profile user field")
        token_user = required_string_claim(claims.get(user_claim), user_claim)
        if token_user != membership.user_id:
            raise ValueError("token user does not match app membership")

    return Principal(
        issuer=issuer, subject=subject, tenant_id=membership.tenant_id,
        user_id=membership.user_id, roles=membership.roles,
    )


def demo() -> None:
    issuer = "https://identity.example.test"
    profile = {issuer: ProviderClaimProfile(None, None)}
    membership = VerifiedMembership(issuer, "external-subject", "user-example", "tenant-example", ("reader",))
    principal = normalize_claims({"iss": issuer, "sub": "external-subject", "roles": ["admin"]},
                                 trusted_issuer_profiles=profile, membership=membership)
    print({"user": principal.user_id, "tenant": principal.tenant_id, "roles": principal.roles})
    try:
        normalize_claims({"iss": issuer, "sub": "another-subject"}, trusted_issuer_profiles=profile, membership=membership)
    except ValueError:
        print({"decision": "denied_membership_identity_mismatch"})


if __name__ == "__main__":
    demo()
