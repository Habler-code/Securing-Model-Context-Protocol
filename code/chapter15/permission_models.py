"""Runnable permission-model examples for Chapter 15."""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from enum import IntEnum
from threading import Lock
from typing import Any, Mapping, Protocol


class RiskLevel(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3


class AssuranceLevel(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3


TOOL_RISK_LEVELS: dict[str, RiskLevel] = {
    "read_resource": RiskLevel.LOW,
    "search": RiskLevel.LOW,
    "create_ticket": RiskLevel.MEDIUM,
    "update_status": RiskLevel.MEDIUM,
    "admin_export": RiskLevel.HIGH,
    "delete_project": RiskLevel.HIGH,
}

ROLE_ALLOWED_TOOLS: dict[str, frozenset[str]] = {
    "viewer": frozenset({"read_resource", "search"}),
    "user": frozenset(
        {"read_resource", "search", "create_ticket", "update_status"}
    ),
    "admin": frozenset(TOOL_RISK_LEVELS),
}


@dataclass(frozen=True)
class Principal:
    role: str
    tenant_id: str
    user_id: str


@dataclass(frozen=True)
class PermissionScope:
    tool: str
    resource_type: str
    resource_id: str | None = None
    all_resources: bool = False

    def __post_init__(self) -> None:
        if not self.tool or not self.resource_type:
            raise ValueError("Tool and resource_type are required")
        has_exact_resource = self.resource_id is not None
        if self.all_resources == has_exact_resource:
            raise ValueError(
                "Specify either one resource_id or all_resources=True"
            )
        if has_exact_resource and not self.resource_id:
            raise ValueError("resource_id must be non-empty")


@dataclass(frozen=True)
class TieredPermission:
    principal: Principal
    scopes: frozenset[PermissionScope]
    max_risk_without_approval: RiskLevel

    def __post_init__(self) -> None:
        if (
            not isinstance(self.max_risk_without_approval, RiskLevel)
            or self.max_risk_without_approval >= RiskLevel.HIGH
        ):
            raise ValueError("Autonomous risk ceiling must be LOW or MEDIUM")


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason_code: str
    required_controls: tuple[str, ...] = ()

    def __bool__(self) -> bool:
        """Preserve Boolean use of the chapter's intermediate scope check."""
        return self.allowed

    @property
    def reason(self) -> str:
        """Chapter spelling for the complete companion's stable reason code."""
        return self.reason_code

    @property
    def required_approvals(self) -> list[str] | None:
        return list(self.required_controls) if self.required_controls else None


@dataclass(frozen=True)
class TrustSignals:
    session_age_minutes: int
    mfa_verified: bool
    anomaly_score: float
    failed_attempts_recent: int

    def __post_init__(self) -> None:
        counts = (self.session_age_minutes, self.failed_attempts_recent)
        if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in counts):
            raise ValueError("Signal counts must be non-negative")
        if isinstance(self.anomaly_score, bool) or not isinstance(self.anomaly_score, (int, float)) or not 0.0 <= self.anomaly_score <= 1.0:
            raise ValueError("anomaly_score must be between 0 and 1")
        if not isinstance(self.mfa_verified, bool):
            raise ValueError("mfa_verified must be a boolean")


def authorize_role(principal: Principal, tool: str) -> RiskLevel:
    """Apply the coarse role gate and return the reviewed Tool risk."""
    allowed_tools = ROLE_ALLOWED_TOOLS.get(principal.role)
    if allowed_tools is None or tool not in allowed_tools:
        raise PermissionError("Role does not permit the requested Tool")
    try:
        return TOOL_RISK_LEVELS[tool]
    except KeyError as exc:
        raise PermissionError("Tool has no reviewed risk classification") from exc


def authorize_tool(
    principal: Principal, tool: str, has_approval: bool = False
) -> None:
    """Illustrate the chapter's coarse role/risk mechanism only.

    The Boolean models control flow; it is not an approval credential. Every
    execution still needs server_authorization_gate with an actual verifier.
    """
    if not isinstance(has_approval, bool):
        raise PermissionError("illustrative approval state must be a boolean")
    risk = authorize_role(principal, tool)
    if risk is RiskLevel.HIGH and not has_approval:
        raise PermissionError("high-risk tool requires explicit approval")


def scope_allows(
    permission: TieredPermission,
    tool: str,
    resource_type: str,
    resource_id: str,
) -> bool:
    if not tool or not resource_type or not resource_id:
        return False
    exact = PermissionScope(tool, resource_type, resource_id)
    broad = PermissionScope(tool, resource_type, all_resources=True)
    return exact in permission.scopes or broad in permission.scopes


# The chapter uses the private spelling; keep both names for existing readers.
_scope_allows = scope_allows


def check_tiered_permission(
    permission: TieredPermission,
    tool: str,
    resource_type: str,
    resource_id: str,
) -> PolicyDecision:
    """Evaluate role, Resource scope, and the autonomous risk ceiling."""
    try:
        risk = authorize_role(permission.principal, tool)
    except PermissionError:
        return PolicyDecision(False, "role_or_tool_denied")
    if not scope_allows(permission, tool, resource_type, resource_id):
        return PolicyDecision(False, "resource_scope_denied")
    if risk > permission.max_risk_without_approval:
        return PolicyDecision(
            False,
            "approval_required",
            ("transaction_approval",),
        )
    return PolicyDecision(True, "role_scope_and_risk_allowed")


def compute_assurance_level(signals: TrustSignals) -> AssuranceLevel:
    """Apply a reviewed policy to trusted session signals."""
    if signals.anomaly_score > 0.7 or signals.failed_attempts_recent > 5:
        return AssuranceLevel.LOW
    if not signals.mfa_verified or signals.session_age_minutes > 60:
        return AssuranceLevel.MEDIUM
    return AssuranceLevel.HIGH


def compute_trust_level(signals: TrustSignals) -> str:
    """Return the string vocabulary used by the chapter's smaller snippets."""
    return compute_assurance_level(signals).name.lower()


ASSURANCE_RISK_CEILING: dict[AssuranceLevel, RiskLevel] = {
    AssuranceLevel.LOW: RiskLevel.LOW,
    AssuranceLevel.MEDIUM: RiskLevel.MEDIUM,
    AssuranceLevel.HIGH: RiskLevel.HIGH,
}

TRUST_RISK_CEILING = {"low": "low", "medium": "medium", "high": "high"}


def authorize_with_assurance(
    principal: Principal, tool: str, assurance: AssuranceLevel
) -> PolicyDecision:
    """Apply a current assurance ceiling without expanding the role grant."""
    if not isinstance(assurance, AssuranceLevel):
        return PolicyDecision(False, "unknown_assurance")
    try:
        risk = authorize_role(principal, tool)
    except PermissionError:
        return PolicyDecision(False, "role_or_tool_denied")
    if risk > ASSURANCE_RISK_CEILING[assurance]:
        return PolicyDecision(False, "step_up_required", ("step_up_authentication",))
    return PolicyDecision(True, "role_and_assurance_allowed")


def authorize_with_trust(
    principal: Principal, tool: str, trust_level: str
) -> None:
    """Apply the chapter's role/assurance mechanism, without execution rights."""
    if not isinstance(trust_level, str) or trust_level not in TRUST_RISK_CEILING:
        raise PermissionError("unknown trust level")
    decision = authorize_with_assurance(
        principal, tool, AssuranceLevel[trust_level.upper()]
    )
    if not decision.allowed:
        raise PermissionError(decision.reason_code)


def host_policy_gate(
    principal: Principal, tool: str, trust_level: str
) -> PolicyDecision:
    """Reject early or request approval; only the complete Server gate admits."""
    try:
        authorize_with_trust(principal, tool, trust_level)
        risk = authorize_role(principal, tool)
    except PermissionError:
        return PolicyDecision(False, "host_role_or_assurance_denied")
    if risk is RiskLevel.HIGH:
        return PolicyDecision(False, "approval_required", ("transaction_approval",))
    return PolicyDecision(True, "host_policy_allowed")


def build_request_digest(
    tool: str,
    resource_type: str,
    resource_id: str,
    arguments: Mapping[str, Any],
) -> str:
    """Hash one deterministic representation of the action under review."""
    normalized = json.dumps(
        {
            "tool": tool,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "arguments": arguments,
        },
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


class ApprovalVerifier(Protocol):
    def verify_and_consume(
        self,
        artifact: str,
        *,
        principal: Principal,
        tool: str,
        resource_type: str,
        resource_id: str,
        request_digest: str,
        approval_purpose: str,
    ) -> bool: ...


@dataclass(frozen=True)
class ApprovalGrant:
    tenant_id: str
    user_id: str
    tool: str
    resource_type: str
    resource_id: str
    request_digest: str
    approval_purpose: str


class OneTimeApprovalVerifier:
    """Single-process test verifier with atomic one-time consumption."""

    def __init__(self, grants: Mapping[str, ApprovalGrant]) -> None:
        self._grants = dict(grants)
        self._lock = Lock()

    def verify_and_consume(
        self,
        artifact: str,
        *,
        principal: Principal,
        tool: str,
        resource_type: str,
        resource_id: str,
        request_digest: str,
        approval_purpose: str,
    ) -> bool:
        with self._lock:
            grant = self._grants.get(artifact)
            if grant is None:
                return False
            expected = (
                principal.tenant_id,
                principal.user_id,
                tool,
                resource_type,
                resource_id,
                request_digest,
                approval_purpose,
            )
            actual = (
                grant.tenant_id,
                grant.user_id,
                grant.tool,
                grant.resource_type,
                grant.resource_id,
                grant.request_digest,
                grant.approval_purpose,
            )
            valid = all(
                hmac.compare_digest(left, right)
                for left, right in zip(actual, expected, strict=True)
            )
            if valid:
                del self._grants[artifact]
            return valid


def server_authorization_gate(
    permission: TieredPermission,
    tool: str,
    resource_type: str,
    resource_id: str,
    assurance: AssuranceLevel,
    request_digest: str,
    approval_artifact: str | None,
    verifier: ApprovalVerifier,
) -> PolicyDecision:
    """Apply authoritative Server policy and verify any approval."""
    if not isinstance(assurance, AssuranceLevel):
        return PolicyDecision(False, "unknown_assurance")
    if not isinstance(request_digest, str) or not request_digest:
        return PolicyDecision(False, "invalid_request_digest")
    try:
        risk = authorize_role(permission.principal, tool)
    except PermissionError:
        return PolicyDecision(False, "role_or_tool_denied")
    if not scope_allows(permission, tool, resource_type, resource_id):
        return PolicyDecision(False, "resource_scope_denied")
    if risk > ASSURANCE_RISK_CEILING[assurance]:
        return PolicyDecision(
            False,
            "step_up_required",
            ("step_up_authentication",),
        )
    approval_required = (
        risk > permission.max_risk_without_approval
        or risk == RiskLevel.HIGH
    )
    if approval_required:
        if approval_artifact is None:
            return PolicyDecision(
                False,
                "approval_required",
                ("transaction_approval",),
            )
        try:
            approval_is_valid = verifier.verify_and_consume(
                approval_artifact,
                principal=permission.principal,
                tool=tool,
                resource_type=resource_type,
                resource_id=resource_id,
                request_digest=request_digest,
                approval_purpose="transaction_approval",
            )
        except Exception:
            return PolicyDecision(False, "approval_verifier_error")
        if approval_is_valid is not True:
            return PolicyDecision(False, "invalid_approval_artifact")
    return PolicyDecision(True, "server_policy_allowed")


def demonstrate_support_scenario() -> None:
    viewer = Principal("viewer", "tenant-a", "viewer-7")
    support_user = Principal("user", "tenant-a", "agent-42")
    admin = Principal("admin", "tenant-a", "admin-3")

    update_scope = PermissionScope("update_status", "ticket", "SR-1042")
    export_scope = PermissionScope("admin_export", "support_archive", "2026-Q3")
    viewer_permission = TieredPermission(
        viewer,
        frozenset({update_scope}),
        RiskLevel.MEDIUM,
    )
    user_permission = TieredPermission(
        support_user,
        frozenset({update_scope}),
        RiskLevel.MEDIUM,
    )
    admin_permission = TieredPermission(
        admin,
        frozenset({export_scope}),
        RiskLevel.MEDIUM,
    )

    update_digest = build_request_digest(
        "update_status",
        "ticket",
        "SR-1042",
        {"status": "resolved"},
    )
    export_digest = build_request_digest(
        "admin_export",
        "support_archive",
        "2026-Q3",
        {"format": "csv"},
    )
    approval_token = "approval-001"
    verifier = OneTimeApprovalVerifier(
        {
            approval_token: ApprovalGrant(
                admin.tenant_id,
                admin.user_id,
                "admin_export",
                "support_archive",
                "2026-Q3",
                export_digest,
                "transaction_approval",
            )
        }
    )

    cases = [
        (
            "viewer update",
            server_authorization_gate(
                viewer_permission,
                "update_status",
                "ticket",
                "SR-1042",
                AssuranceLevel.HIGH,
                update_digest,
                None,
                verifier,
            ),
        ),
        (
            "user update SR-1042",
            server_authorization_gate(
                user_permission,
                "update_status",
                "ticket",
                "SR-1042",
                AssuranceLevel.HIGH,
                update_digest,
                None,
                verifier,
            ),
        ),
        (
            "admin export without approval",
            server_authorization_gate(
                admin_permission,
                "admin_export",
                "support_archive",
                "2026-Q3",
                AssuranceLevel.HIGH,
                export_digest,
                None,
                verifier,
            ),
        ),
        (
            "admin export with approval",
            server_authorization_gate(
                admin_permission,
                "admin_export",
                "support_archive",
                "2026-Q3",
                AssuranceLevel.HIGH,
                export_digest,
                approval_token,
                verifier,
            ),
        ),
        (
            "admin export replay",
            server_authorization_gate(
                admin_permission,
                "admin_export",
                "support_archive",
                "2026-Q3",
                AssuranceLevel.HIGH,
                export_digest,
                approval_token,
                verifier,
            ),
        ),
    ]
    expected = [
        "role_or_tool_denied",
        "server_policy_allowed",
        "approval_required",
        "server_policy_allowed",
        "invalid_approval_artifact",
    ]
    for (label, decision), expected_reason in zip(cases, expected, strict=True):
        assert decision.reason_code == expected_reason
        print(f"{label}: {decision.reason_code}")


if __name__ == "__main__":
    demonstrate_support_scenario()
