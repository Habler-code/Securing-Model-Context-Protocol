"""Runnable governance examples for Chapter 19."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
import re
from threading import RLock


class ApprovalStatus(Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    DEPRECATED = "deprecated"


class RiskTier(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


MAX_HIGH_RISK_REVIEW_AUTH_AGE_SECONDS = 300
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class VerifiedReviewer:
    """Identity claims created by trusted Server authentication middleware."""

    subject_ref: str
    roles: frozenset[str]
    identity_issuer: str
    authenticated_at: datetime
    assurance_level: str

    def __post_init__(self) -> None:
        if any(not isinstance(value, str) or not value.strip() for value in (self.subject_ref, self.identity_issuer, self.assurance_level)):
            raise ValueError("reviewer identity is incomplete")
        if not isinstance(self.roles, frozenset) or any(not isinstance(role, str) or not role for role in self.roles):
            raise ValueError("reviewer roles must be an immutable set of strings")
        if not isinstance(self.authenticated_at, datetime) or self.authenticated_at.utcoffset() is None:
            raise ValueError("reviewer authentication time must be aware")


@dataclass(frozen=True)
class ApprovalRecord:
    approver_ref: str
    approver_roles: frozenset[str]
    identity_issuer: str
    assurance_level: str
    evidence_refs: tuple[str, ...]
    approved_at: str


@dataclass(frozen=True)
class ToolRegistration:
    qualified_name: str
    version: str
    publisher: str
    artifact_sha256: str
    schema_sha256: str
    risk_tier: RiskTier
    data_classification: str
    requested_by: str
    status: ApprovalStatus = ApprovalStatus.PENDING
    approvals: tuple[ApprovalRecord, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.risk_tier, RiskTier):
            raise ValueError("risk_tier must be a reviewed RiskTier value")
        if not isinstance(self.status, ApprovalStatus):
            raise ValueError("status must be an ApprovalStatus value")
        if not self.qualified_name.strip() or not self.publisher.strip():
            raise ValueError("tool identity is incomplete")
        if not self.version.strip() or not self.requested_by.strip():
            raise ValueError("version and requester are required")
        if not SHA256_PATTERN.fullmatch(self.artifact_sha256):
            raise ValueError("artifact digest must be lowercase SHA-256")
        if not SHA256_PATTERN.fullmatch(self.schema_sha256):
            raise ValueError("schema digest must be lowercase SHA-256")

    @property
    def key(self) -> tuple[str, str, str, str, str]:
        return (
            self.qualified_name,
            self.publisher,
            self.version,
            self.artifact_sha256,
            self.schema_sha256,
        )


@dataclass
class GovernanceRegistry:
    tools: dict[
        tuple[str, str, str, str, str], ToolRegistration
    ] = field(default_factory=dict)
    _lock: RLock = field(default_factory=RLock, repr=False, init=False)

    def register_tool(self, registration: ToolRegistration) -> None:
        with self._lock:
            self._register_tool(registration)

    def _register_tool(self, registration: ToolRegistration) -> None:
        if registration.status is not ApprovalStatus.PENDING:
            raise ValueError("new registrations must be pending")
        if registration.approvals:
            raise ValueError("new registrations cannot contain approvals")
        if registration.key in self.tools:
            raise ValueError("exact tool artifact is already registered")
        self.tools[registration.key] = registration

    def record_approval(
        self,
        key: tuple[str, str, str, str, str],
        reviewer: VerifiedReviewer,
        evidence_refs: tuple[str, ...],
        *,
        decision_time: datetime | None = None,
    ) -> ToolRegistration:
        with self._lock:
            return self._record_approval(key, reviewer, evidence_refs, decision_time=decision_time)

    def _record_approval(
        self,
        key: tuple[str, str, str, str, str],
        reviewer: VerifiedReviewer,
        evidence_refs: tuple[str, ...],
        *,
        decision_time: datetime | None = None,
    ) -> ToolRegistration:
        tool = self.tools.get(key)
        if tool is None:
            raise ValueError("tool artifact is not registered")
        if tool.status is not ApprovalStatus.PENDING:
            raise ValueError("tool artifact is not pending approval")

        now = decision_time or datetime.now(timezone.utc)
        if now.tzinfo is None or reviewer.authenticated_at.tzinfo is None:
            raise ValueError("decision and authentication times must be aware")
        if not reviewer.subject_ref.strip() or not reviewer.identity_issuer.strip():
            raise ValueError("verified reviewer identity is incomplete")
        if reviewer.assurance_level not in {"aal1", "aal2", "aal3"}:
            raise PermissionError("unrecognized authentication assurance")
        if reviewer.authenticated_at > now:
            raise PermissionError("reviewer authentication is in the future")
        if reviewer.subject_ref == tool.requested_by:
            raise PermissionError("requester cannot approve this tool")
        if any(a.approver_ref == reviewer.subject_ref for a in tool.approvals):
            raise PermissionError("approver has already decided")
        if "tool_approver" not in reviewer.roles:
            raise PermissionError("tool approver role is required")
        if not isinstance(evidence_refs, tuple) or not evidence_refs or any(not isinstance(ref, str) or not ref.strip() for ref in evidence_refs):
            raise ValueError("approval requires non-empty evidence references")

        if tool.risk_tier is RiskTier.HIGH:
            if reviewer.assurance_level not in {"aal2", "aal3"}:
                raise PermissionError("high-risk approval needs step-up assurance")
            if now - reviewer.authenticated_at > timedelta(
                seconds=MAX_HIGH_RISK_REVIEW_AUTH_AGE_SECONDS
            ):
                raise PermissionError("high-risk reviewer authentication is stale")

        approval = ApprovalRecord(
            approver_ref=reviewer.subject_ref,
            approver_roles=reviewer.roles,
            identity_issuer=reviewer.identity_issuer,
            assurance_level=reviewer.assurance_level,
            evidence_refs=evidence_refs,
            approved_at=now.isoformat(),
        )
        approvals = (*tool.approvals, approval)
        required_count = 2 if tool.risk_tier is RiskTier.HIGH else 1
        has_security_approver = any(
            "security_approver" in item.approver_roles
            for item in approvals
        )
        approved = len(approvals) >= required_count
        if tool.risk_tier is RiskTier.HIGH:
            approved = approved and has_security_approver

        updated = replace(
            tool,
            approvals=approvals,
            status=(
                ApprovalStatus.APPROVED
                if approved
                else ApprovalStatus.PENDING
            ),
        )
        self.tools[key] = updated
        return updated

    def assert_enabled(
        self,
        key: tuple[str, str, str, str, str],
    ) -> ToolRegistration:
        with self._lock:
            tool = self.tools.get(key)
            if tool is None or tool.status is not ApprovalStatus.APPROVED:
                raise PermissionError("tool artifact is not approved")
            return tool


@dataclass(frozen=True)
class TrainingModule:
    topic: str
    threat_concepts: tuple[str, ...]
    scenario_exercise: str
    assessment_criteria: str


MCP_SECURITY_TRAINING: tuple[TrainingModule, ...] = (
    TrainingModule(
        topic="Instruction and data boundaries",
        threat_concepts=(
            "direct and indirect prompt injection",
            "untrusted tool output",
            "policy independent of model intent",
        ),
        scenario_exercise=(
            "Review a sanitized trace and identify where data was "
            "mistaken for control"
        ),
        assessment_criteria=(
            "Locate the failed boundary and propose a verifiable gate"
        ),
    ),
    TrainingModule(
        topic="Tool identity and schema integrity",
        threat_concepts=(
            "schema drift",
            "cross-server shadowing",
            "post-update privilege review",
        ),
        scenario_exercise=(
            "Compare approved and advertised manifests in a test registry"
        ),
        assessment_criteria=(
            "Detect identity or digest mismatch and choose safe disposition"
        ),
    ),
)


@dataclass(frozen=True)
class ComplianceEvidence:
    control_id: str
    evidence_type: str
    location: str
    owner: str
    collected_at: datetime
    valid_until: datetime
    content_sha256: str

    def __post_init__(self) -> None:
        if self.collected_at.tzinfo is None or self.valid_until.tzinfo is None:
            raise ValueError("evidence timestamps must be timezone aware")
        if self.valid_until < self.collected_at:
            raise ValueError("evidence validity cannot end before collection")
        if not SHA256_PATTERN.fullmatch(self.content_sha256):
            raise ValueError("evidence digest must be lowercase SHA-256")

    def is_current(self, at: datetime) -> bool:
        if at.tzinfo is None:
            raise ValueError("report time must be timezone aware")
        return self.collected_at <= at <= self.valid_until


def generate_compliance_report(
    registry: GovernanceRegistry,
    evidence: list[ComplianceEvidence],
    at: datetime | None = None,
) -> dict[str, object]:
    """Summarize registry state and evidence currency, not compliance."""
    report_time = at or datetime.now(timezone.utc)
    if report_time.tzinfo is None:
        raise ValueError("report time must be timezone aware")

    current = [item for item in evidence if item.is_current(report_time)]
    noncurrent = [item for item in evidence if not item.is_current(report_time)]
    with registry._lock:
        registrations = tuple(registry.tools.values())
    approved_tools = sum(
        item.status is ApprovalStatus.APPROVED
        for item in registrations
    )
    pending_tools = sum(
        item.status is ApprovalStatus.PENDING
        for item in registrations
    )

    return {
        "report_generated": report_time.isoformat(),
        "registered_tool_artifacts": len(registrations),
        "approved_tool_artifacts": approved_tools,
        "pending_tool_artifacts": pending_tools,
        "current_evidence_records": len(current),
        "noncurrent_evidence_records": len(noncurrent),
        "controls_with_current_evidence": sorted(
            {item.control_id for item in current}
        ),
    }


@dataclass(frozen=True)
class DataRetentionPolicy:
    policy_id: str
    data_category: str
    max_retention_days: int
    deletion_method: str
    rationale: str
    approved_by: str
    legal_hold_supported: bool


EXAMPLE_RETENTION_POLICIES: tuple[DataRetentionPolicy, ...] = (
    DataRetentionPolicy(
        "example-audit-events", "pseudonymized_tool_audit_events", 90,
        "verified_automated_purge",
        "illustrative business and assurance evidence window",
        "example-privacy-and-security-owner", True,
    ),
    DataRetentionPolicy(
        "example-tool-output-cache", "cached_tool_outputs", 7,
        "verified_cache_expiry", "illustrative short-lived operational cache",
        "example-data-owner", False,
    ),
)


def validate_retention_policy(policy: DataRetentionPolicy) -> None:
    if isinstance(policy.max_retention_days, bool) or not isinstance(policy.max_retention_days, int) or policy.max_retention_days <= 0:
        raise ValueError("retention period must be positive")
    if not isinstance(policy.legal_hold_supported, bool):
        raise ValueError("legal_hold_supported must be a boolean")
    if not policy.rationale.strip() or not policy.approved_by.strip():
        raise ValueError("retention policy needs rationale and owner")


def _demo() -> None:
    now = datetime.now(timezone.utc)
    registry = GovernanceRegistry()
    registration = ToolRegistration(
        qualified_name="com.example.tickets.export_cases",
        version="2.4.1",
        publisher="example-security",
        artifact_sha256="a" * 64,
        schema_sha256="b" * 64,
        risk_tier=RiskTier.HIGH,
        data_classification="confidential",
        requested_by="requester-17",
    )
    registry.register_tool(registration)

    reviewer_one = VerifiedReviewer(
        subject_ref="reviewer-41",
        roles=frozenset({"tool_approver"}),
        identity_issuer="https://id.example.test",
        authenticated_at=now,
        assurance_level="aal2",
    )
    reviewer_two = VerifiedReviewer(
        subject_ref="reviewer-82",
        roles=frozenset({"tool_approver", "security_approver"}),
        identity_issuer="https://id.example.test",
        authenticated_at=now,
        assurance_level="aal2",
    )
    registry.record_approval(
        registration.key,
        reviewer_one,
        ("evidence://scan/41",),
        decision_time=now,
    )
    registry.record_approval(
        registration.key,
        reviewer_two,
        ("evidence://review/82",),
        decision_time=now,
    )
    enabled = registry.assert_enabled(registration.key)
    print(f"enabled: {enabled.qualified_name}@{enabled.version}")

    policy = DataRetentionPolicy(
        policy_id="example-audit-events",
        data_category="pseudonymized_tool_audit_events",
        max_retention_days=90,
        deletion_method="verified_automated_purge",
        rationale="illustrative business and assurance evidence window",
        approved_by="example-privacy-and-security-owner",
        legal_hold_supported=True,
    )
    validate_retention_policy(policy)
    print(f"validated retention policy: {policy.policy_id}")


if __name__ == "__main__":
    _demo()
