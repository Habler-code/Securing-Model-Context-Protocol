"""Runnable human-approval and break-glass examples for Chapter 20."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
from hashlib import sha256
import json
import re
import secrets
from threading import Barrier, Lock, Thread
from typing import Any, Mapping


class RiskTier(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class DelegationHop:
    principal_ref: str
    agent_ref: str
    purpose: str

    def __post_init__(self) -> None:
        if any(not isinstance(value, str) or not value.strip() or "\x00" in value for value in (self.principal_ref, self.agent_ref, self.purpose)):
            raise ValueError("delegation hop must contain valid identifiers and purpose")


@dataclass(frozen=True)
class InvocationContext:
    qualified_tool: str
    tool_version: str
    artifact_sha256: str
    schema_sha256: str
    tenant_ref: str
    actor_ref: str
    resource_version: str
    data_classification: str
    item_count: int
    delegation_chain: tuple[DelegationHop, ...] = ()
    external_side_effect: bool = False
    privilege_change: bool = False
    irreversible: bool = False

    def __post_init__(self) -> None:
        required = (
            self.qualified_tool,
            self.tool_version,
            self.tenant_ref,
            self.actor_ref,
            self.resource_version,
            self.data_classification,
        )
        if any(not isinstance(value, str) or not value.strip() for value in required):
            raise ValueError("invocation context contains an empty identifier")
        if any("\x00" in value for value in required):
            raise ValueError("invocation identifiers cannot contain null bytes")
        if not SHA256_PATTERN.fullmatch(self.artifact_sha256):
            raise ValueError("artifact_sha256 must be lowercase SHA-256")
        if not SHA256_PATTERN.fullmatch(self.schema_sha256):
            raise ValueError("schema_sha256 must be lowercase SHA-256")
        if isinstance(self.item_count, bool) or not isinstance(self.item_count, int) or self.item_count < 0:
            raise ValueError("item_count cannot be negative")
        if self.data_classification not in {"public", "internal", "confidential", "restricted"}:
            raise ValueError("unknown data classification")
        if any(not isinstance(value, bool) for value in (self.external_side_effect, self.privilege_change, self.irreversible)):
            raise ValueError("side-effect flags must be booleans")
        if not isinstance(self.delegation_chain, tuple) or any(not isinstance(hop, DelegationHop) for hop in self.delegation_chain):
            raise ValueError("delegation_chain must be an immutable tuple of hops")
        if len(self.delegation_chain) > 8:
            raise ValueError("delegation depth exceeds policy")
        if any(
            not hop.principal_ref.strip()
            or not hop.agent_ref.strip()
            or not hop.purpose.strip()
            for hop in self.delegation_chain
        ):
            raise ValueError("delegation hop is incomplete")
        if len({hop.agent_ref for hop in self.delegation_chain}) != len(self.delegation_chain):
            raise ValueError("delegation chain contains an agent loop")


BASELINE_TOOL_RISK: dict[str, RiskTier] = {
    "trusted.search.search": RiskTier.LOW,
    "trusted.resources.read_resource": RiskTier.LOW,
    "trusted.tickets.create_ticket": RiskTier.MEDIUM,
    "trusted.tickets.export_cases": RiskTier.HIGH,
    "trusted.admin.delete_project": RiskTier.HIGH,
    "trusted.mail.send_external": RiskTier.HIGH,
}


def classify_invocation(context: InvocationContext) -> RiskTier:
    baseline = BASELINE_TOOL_RISK.get(
        context.qualified_tool,
        RiskTier.HIGH,
    )
    if (
        context.data_classification in {"confidential", "restricted"}
        or context.external_side_effect
        or context.privilege_change
        or context.irreversible
    ):
        return RiskTier.HIGH
    if context.item_count > 25 and baseline is RiskTier.LOW:
        return RiskTier.MEDIUM
    return baseline


def canonicalize_arguments(arguments: Mapping[str, Any]) -> str:
    if not isinstance(arguments, Mapping):
        raise TypeError("tool arguments must be a mapping")
    if any(not isinstance(key, str) for key in arguments):
        raise TypeError("tool argument names must be strings")
    return json.dumps(
        dict(arguments),
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def digest_text(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


def delegation_digest(chain: tuple[DelegationHop, ...]) -> str:
    serialized = canonicalize_arguments(
        {
            "chain": [
                {
                    "principal_ref": hop.principal_ref,
                    "agent_ref": hop.agent_ref,
                    "purpose": hop.purpose,
                }
                for hop in chain
            ]
        }
    )
    return digest_text(serialized)


def invocation_digest(context: InvocationContext) -> str:
    """Bind every governed field, including release, scope, effects, and actor."""
    return digest_text(canonicalize_arguments(asdict(context)))


@dataclass(frozen=True)
class ApprovalRequest:
    request_id: str
    qualified_tool: str
    tool_version: str
    artifact_sha256: str
    schema_sha256: str
    tenant_ref: str
    actor_ref: str
    resource_version: str
    risk_tier: str
    arguments_json: str
    arguments_sha256: str
    delegation_sha256: str
    requested_at: datetime
    approval_deadline: datetime
    context_sha256: str = ""
    model_rationale: str = "High-impact operation requires explicit review."

    def __post_init__(self) -> None:
        if self.requested_at.utcoffset() is None or self.approval_deadline.utcoffset() is None:
            raise ValueError("approval request timestamps must be aware")
        if self.approval_deadline <= self.requested_at:
            raise ValueError("approval deadline must follow request creation")
        if not isinstance(self.model_rationale, str) or not self.model_rationale.strip() or len(self.model_rationale) > 1_000:
            raise ValueError("model rationale must contain 1 to 1000 characters")


@dataclass(frozen=True)
class VerifiedApprover:
    subject_ref: str
    tenant_ref: str
    roles: frozenset[str]
    identity_issuer: str
    authenticated_at: datetime
    assurance_level: str

    def __post_init__(self) -> None:
        if any(
            not isinstance(value, str) or not value.strip() or len(value) > 2_048
            for value in (
                self.subject_ref,
                self.tenant_ref,
                self.identity_issuer,
                self.assurance_level,
            )
        ):
            raise ValueError("verified approver identity is incomplete")
        if (
            not isinstance(self.roles, frozenset)
            or len(self.roles) > 64
            or any(not isinstance(role, str) or not role.strip() or len(role) > 128 for role in self.roles)
        ):
            raise ValueError("approver roles must be a bounded frozenset of strings")
        if not isinstance(self.authenticated_at, datetime) or self.authenticated_at.utcoffset() is None:
            raise ValueError("approver authentication time must be timezone aware")


@dataclass(frozen=True)
class ApprovalGrant:
    token_digest: str
    request_id: str
    qualified_tool: str
    tool_version: str
    artifact_sha256: str
    schema_sha256: str
    tenant_ref: str
    actor_ref: str
    resource_version: str
    arguments_sha256: str
    delegation_sha256: str
    approved_by: str
    approved_at: datetime
    expires_at: datetime
    consumed_at: datetime | None = None
    context_sha256: str = ""
    risk_tier: str = RiskTier.HIGH.value
    approver_issuer: str = ""
    approver_assurance_level: str = ""
    approver_authenticated_at: datetime | None = None


APPROVAL_REQUEST_LIFETIME_SECONDS = 300
TOKEN_LIFETIME_SECONDS = 300
MAX_STEP_UP_AGE_SECONDS = 120


def create_approval_request(
    context: InvocationContext,
    arguments: Mapping[str, Any],
    model_rationale: str = "High-impact operation requires explicit review.",
    *,
    now: datetime | None = None,
) -> ApprovalRequest:
    created = now or datetime.now(timezone.utc)
    if created.tzinfo is None:
        raise ValueError("request time must be timezone aware")
    if classify_invocation(context) is not RiskTier.HIGH:
        raise ValueError("approval request is reserved for high-risk calls")
    arguments_json = canonicalize_arguments(arguments)
    return ApprovalRequest(
        request_id=secrets.token_urlsafe(24),
        qualified_tool=context.qualified_tool,
        tool_version=context.tool_version,
        artifact_sha256=context.artifact_sha256,
        schema_sha256=context.schema_sha256,
        tenant_ref=context.tenant_ref,
        actor_ref=context.actor_ref,
        resource_version=context.resource_version,
        risk_tier=RiskTier.HIGH.value,
        arguments_json=arguments_json,
        arguments_sha256=digest_text(arguments_json),
        delegation_sha256=delegation_digest(context.delegation_chain),
        requested_at=created,
        approval_deadline=(
            created
            + timedelta(seconds=APPROVAL_REQUEST_LIFETIME_SECONDS)
        ),
        context_sha256=invocation_digest(context),
        model_rationale=model_rationale,
    )


@dataclass
class ApprovalStore:
    _lock: Lock = field(default_factory=Lock)
    _requests: dict[str, ApprovalRequest] = field(default_factory=dict)
    _grants: dict[str, ApprovalGrant] = field(default_factory=dict)
    _decided_requests: set[str] = field(default_factory=set)

    def save_request(self, request: ApprovalRequest) -> None:
        if not SHA256_PATTERN.fullmatch(request.context_sha256):
            raise ValueError("request must bind a complete invocation context")
        if digest_text(request.arguments_json) != request.arguments_sha256:
            raise ValueError("request arguments do not match their digest")
        with self._lock:
            if request.request_id in self._requests:
                raise ValueError("approval request already exists")
            self._requests[request.request_id] = request

    def approve_request(
        self,
        request_id: str,
        approver: VerifiedApprover,
        at: datetime | None = None,
        *,
        now: datetime | None = None,
    ) -> str:
        if now is not None and at is not None:
            raise ValueError("supply only one approval time")
        decision_time = now or at or datetime.now(timezone.utc)
        if (
            decision_time.tzinfo is None
            or approver.authenticated_at.tzinfo is None
        ):
            raise ValueError("decision timestamps must be timezone aware")
        if approver.authenticated_at > decision_time:
            raise PermissionError("approver authentication is in the future")
        if approver.assurance_level not in {"aal2", "aal3"}:
            raise PermissionError("step-up authentication is required")
        if "hitl_approver" not in approver.roles:
            raise PermissionError("human approval role is required")
        with self._lock:
            request = self._requests.get(request_id)
            if request is None:
                raise ValueError("unknown approval request")
            if request_id in self._decided_requests:
                raise PermissionError("approval request already decided")
            if (
                decision_time >= request.approval_deadline
                or decision_time - request.requested_at
                >= timedelta(seconds=APPROVAL_REQUEST_LIFETIME_SECONDS)
            ):
                self._decided_requests.add(request_id)
                raise PermissionError("approval request expired")
            if approver.subject_ref == request.actor_ref:
                raise PermissionError("requester cannot approve this request")
            if approver.tenant_ref != request.tenant_ref:
                raise PermissionError("approver tenant does not match request")
            if approver.authenticated_at < request.requested_at:
                raise PermissionError("step-up must follow request creation")
            if decision_time - approver.authenticated_at > timedelta(
                seconds=MAX_STEP_UP_AGE_SECONDS
            ):
                raise PermissionError("step-up authentication is stale")

            for _ in range(3):
                raw_token = secrets.token_urlsafe(32)
                token_digest = digest_text(raw_token)
                if token_digest not in self._grants:
                    break
            else:
                raise RuntimeError("approval token generation collision limit reached")
            grant = ApprovalGrant(
                token_digest=token_digest,
                request_id=request.request_id,
                qualified_tool=request.qualified_tool,
                tool_version=request.tool_version,
                artifact_sha256=request.artifact_sha256,
                schema_sha256=request.schema_sha256,
                tenant_ref=request.tenant_ref,
                actor_ref=request.actor_ref,
                resource_version=request.resource_version,
                arguments_sha256=request.arguments_sha256,
                delegation_sha256=request.delegation_sha256,
                approved_by=approver.subject_ref,
                approved_at=decision_time,
                expires_at=(
                    decision_time
                    + timedelta(seconds=TOKEN_LIFETIME_SECONDS)
                ),
                context_sha256=request.context_sha256,
                risk_tier=request.risk_tier,
                approver_issuer=approver.identity_issuer,
                approver_assurance_level=approver.assurance_level,
                approver_authenticated_at=approver.authenticated_at,
            )
            self._grants[token_digest] = grant
            self._decided_requests.add(request_id)
            return raw_token

    def consume(
        self,
        raw_token: str,
        request_id: str,
        context: InvocationContext,
        arguments: Mapping[str, Any] | RiskTier | None = None,
        arguments_json: str | None = None,
        at: datetime | None = None,
        *,
        now: datetime | None = None,
        risk_tier: RiskTier | None = None,
    ) -> ApprovalGrant:
        """Consume a bound Mapping or the chapter's exact canonical JSON form."""
        if now is not None and at is not None:
            raise ValueError("supply only one redemption time")
        consumed_time = now or at or datetime.now(timezone.utc)
        if consumed_time.tzinfo is None:
            raise ValueError("consumption time must be timezone aware")
        if not isinstance(raw_token, str) or not raw_token:
            raise PermissionError("invalid approval grant")
        if isinstance(arguments, RiskTier):
            if risk_tier is not None:
                raise ValueError("supply only one risk tier")
            risk_tier, arguments = arguments, None
        current_risk = classify_invocation(context)
        if risk_tier is not None and (
            not isinstance(risk_tier, RiskTier) or risk_tier is not current_risk
        ):
            raise PermissionError("approval risk tier does not match current policy")
        if arguments_json is not None:
            if arguments is not None or not isinstance(arguments_json, str):
                raise ValueError("supply a Mapping or canonical JSON, not both")
            try:
                parsed = json.loads(arguments_json)
                normalized = canonicalize_arguments(parsed)
            except (TypeError, ValueError) as exc:
                raise ValueError("invalid canonical arguments JSON") from exc
            if normalized != arguments_json:
                raise ValueError("arguments JSON must use the approved canonical encoding")
        else:
            normalized = canonicalize_arguments(arguments)
        arguments_digest = digest_text(normalized)
        token_digest = digest_text(raw_token)
        with self._lock:
            grant = self._grants.get(token_digest)
            if grant is None:
                raise PermissionError("invalid approval grant")
            if grant.consumed_at is not None:
                raise PermissionError("approval grant already consumed")
            if consumed_time >= grant.expires_at:
                raise PermissionError("approval grant expired")
            if consumed_time < grant.approved_at:
                raise PermissionError("approval grant is not yet valid")
            expected = (
                request_id,
                context.qualified_tool,
                context.tool_version,
                context.artifact_sha256,
                context.schema_sha256,
                context.tenant_ref,
                context.actor_ref,
                context.resource_version,
                arguments_digest,
                delegation_digest(context.delegation_chain),
                invocation_digest(context),
                current_risk.value,
            )
            actual = (
                grant.request_id,
                grant.qualified_tool,
                grant.tool_version,
                grant.artifact_sha256,
                grant.schema_sha256,
                grant.tenant_ref,
                grant.actor_ref,
                grant.resource_version,
                grant.arguments_sha256,
                grant.delegation_sha256,
                grant.context_sha256,
                grant.risk_tier,
            )
            if not all(secrets.compare_digest(left.encode("utf-8"), right.encode("utf-8")) for left, right in zip(expected, actual, strict=True)):
                raise PermissionError("approval grant context mismatch")
            consumed = replace(grant, consumed_at=consumed_time)
            self._grants[token_digest] = consumed
            return consumed


@dataclass(frozen=True)
class ToolPolicy:
    auto_execute: bool
    requires_approval: bool
    requires_step_up_auth: bool
    rate_limit_per_hour: int


DEFAULT_POLICIES: dict[RiskTier, ToolPolicy] = {
    RiskTier.LOW: ToolPolicy(True, False, False, 1_000),
    RiskTier.MEDIUM: ToolPolicy(True, False, False, 100),
    RiskTier.HIGH: ToolPolicy(False, True, True, 10),
}


def enforce_hitl_policy(
    context: InvocationContext,
    arguments: Mapping[str, Any],
    store: ApprovalStore,
    approval_token: str | None = None,
    request_id: str | None = None,
    *,
    now: datetime | None = None,
) -> str:
    """Return the immutable JSON that the authorized executor must execute.

    This hook enforces human approval only. Ordinary authorization, schemas,
    rate limits, resource preconditions, and durable audit are separate gates.
    """
    policy = DEFAULT_POLICIES[classify_invocation(context)]
    arguments_json = canonicalize_arguments(arguments)
    if policy.requires_approval:
        if approval_token is None or request_id is None:
            raise PermissionError("high-risk invocation requires approval")
        store.consume(
            raw_token=approval_token,
            request_id=request_id,
            context=context,
            risk_tier=classify_invocation(context),
            arguments_json=arguments_json,
            now=now,
        )
    return arguments_json


class FatigueAction(Enum):
    CONTINUE = "continue"
    REQUIRE_BATCH_REVIEW = "require_batch_review"
    PAUSE_SESSION = "pause_session"


@dataclass(frozen=True)
class ApprovalFatigueGuard:
    require_batch_review_after: int = 5
    pause_session_after: int = 10
    pause_seconds: int = 60

    def __post_init__(self) -> None:
        values = (self.require_batch_review_after, self.pause_session_after, self.pause_seconds)
        if any(isinstance(value, bool) or not isinstance(value, int) or value < 1 for value in values):
            raise ValueError("fatigue policy values must be positive integers")
        if self.pause_session_after <= self.require_batch_review_after:
            raise ValueError("pause threshold must exceed batch threshold")


@dataclass(frozen=True)
class FatigueDecision:
    action: FatigueAction
    reason: str
    retry_after_seconds: int = 0


def evaluate_approval_fatigue(
    approvals_this_session: int,
    guard: ApprovalFatigueGuard = ApprovalFatigueGuard(),
) -> FatigueDecision:
    if isinstance(approvals_this_session, bool) or not isinstance(approvals_this_session, int) or approvals_this_session < 0:
        raise ValueError("approval count must be a non-negative integer")
    if approvals_this_session >= guard.pause_session_after:
        return FatigueDecision(FatigueAction.PAUSE_SESSION, "approval volume reached the session safety limit", guard.pause_seconds)
    if approvals_this_session >= guard.require_batch_review_after:
        return FatigueDecision(FatigueAction.REQUIRE_BATCH_REVIEW, "review exact batch scope and repeated workflow design")
    return FatigueDecision(FatigueAction.CONTINUE, "approval volume is below the review threshold")


@dataclass(frozen=True)
class BreakGlassPolicy:
    allowed_tools: frozenset[str]
    max_items: int
    lifetime_seconds: int = 300

    def __post_init__(self) -> None:
        if not isinstance(self.allowed_tools, frozenset) or not self.allowed_tools or len(self.allowed_tools) > 128 or any(
            not isinstance(tool, str) or not tool.strip() or len(tool) > 256
            for tool in self.allowed_tools
        ):
            raise ValueError("break-glass policy needs named allowed tools")
        if isinstance(self.max_items, bool) or not isinstance(self.max_items, int) or self.max_items <= 0:
            raise ValueError("max_items must be positive")
        if isinstance(self.lifetime_seconds, bool) or not isinstance(self.lifetime_seconds, int) or not 0 < self.lifetime_seconds <= 900:
            raise ValueError("lifetime_seconds must be between 1 and 900")


@dataclass(frozen=True)
class BreakGlassRequest:
    request_id: str
    incident_ref: str
    requested_by: str
    tenant_ref: str
    qualified_tool: str
    arguments_sha256: str
    resource_version: str
    requested_at: datetime
    expires_at: datetime
    approvals: tuple[tuple[str, frozenset[str]], ...] = ()
    consumed_at: datetime | None = None
    context_sha256: str = ""
    approval_times: tuple[datetime, ...] = ()


@dataclass
class BreakGlassStore:
    policy: BreakGlassPolicy
    _lock: Lock = field(default_factory=Lock)
    _requests: dict[str, BreakGlassRequest] = field(default_factory=dict)

    def create_request(
        self,
        context: InvocationContext,
        arguments: Mapping[str, Any],
        incident_ref: str,
        *,
        now: datetime,
    ) -> BreakGlassRequest:
        if now.tzinfo is None:
            raise ValueError("request time must be timezone aware")
        if context.qualified_tool not in self.policy.allowed_tools:
            raise PermissionError("tool is outside break-glass policy")
        if context.item_count > self.policy.max_items:
            raise PermissionError("request exceeds break-glass scope")
        if not incident_ref.strip():
            raise ValueError("incident reference is required")
        request = BreakGlassRequest(
            request_id=secrets.token_urlsafe(24),
            incident_ref=incident_ref,
            requested_by=context.actor_ref,
            tenant_ref=context.tenant_ref,
            qualified_tool=context.qualified_tool,
            arguments_sha256=digest_text(canonicalize_arguments(arguments)),
            resource_version=context.resource_version,
            requested_at=now,
            expires_at=now + timedelta(seconds=self.policy.lifetime_seconds),
            context_sha256=invocation_digest(context),
        )
        with self._lock:
            self._requests[request.request_id] = request
        return request

    def authorize(
        self,
        request_id: str,
        approver: VerifiedApprover,
        *,
        now: datetime,
    ) -> BreakGlassRequest:
        if now.tzinfo is None:
            raise ValueError("decision time must be timezone aware")
        if approver.authenticated_at > now:
            raise PermissionError("approver authentication is in the future")
        with self._lock:
            request = self._requests.get(request_id)
            if request is None:
                raise ValueError("unknown break-glass request")
            if now >= request.expires_at or request.consumed_at is not None:
                raise PermissionError("break-glass request is not active")
            if approver.subject_ref == request.requested_by:
                raise PermissionError("requester cannot approve emergency use")
            if approver.authenticated_at < request.requested_at:
                raise PermissionError("step-up must follow request creation")
            if now - approver.authenticated_at > timedelta(
                seconds=MAX_STEP_UP_AGE_SECONDS
            ):
                raise PermissionError("step-up authentication is stale")
            if approver.tenant_ref != request.tenant_ref:
                raise PermissionError("approver tenant does not match")
            if approver.assurance_level not in {"aal2", "aal3"}:
                raise PermissionError("step-up authentication is required")
            if any(
                subject == approver.subject_ref
                for subject, _ in request.approvals
            ):
                raise PermissionError("approver has already decided")
            permitted = {"incident_commander", "security_duty_officer"}
            if not approver.roles.intersection(permitted):
                raise PermissionError("emergency approval role is required")
            updated = replace(
                request,
                approvals=(
                    *request.approvals,
                    (approver.subject_ref, approver.roles),
                ),
                approval_times=(*request.approval_times, now),
            )
            self._requests[request_id] = updated
            return updated

    def consume(
        self,
        request_id: str,
        context: InvocationContext,
        arguments: Mapping[str, Any],
        *,
        now: datetime,
    ) -> BreakGlassRequest:
        if now.tzinfo is None:
            raise ValueError("consumption time must be timezone aware")
        with self._lock:
            request = self._requests.get(request_id)
            if request is None:
                raise ValueError("unknown break-glass request")
            if request.consumed_at is not None or now >= request.expires_at:
                raise PermissionError("break-glass request is not active")
            if now < request.requested_at or any(now < at for at in request.approval_times):
                raise PermissionError("break-glass approval is not yet valid")
            distinct_roles = {
                role
                for _, roles in request.approvals
                for role in roles
            }
            required = {"incident_commander", "security_duty_officer"}
            if len(request.approvals) < 2 or not required.issubset(
                distinct_roles
            ):
                raise PermissionError("two-role emergency quorum is required")
            if (
                context.qualified_tool != request.qualified_tool
                or context.qualified_tool not in self.policy.allowed_tools
                or context.item_count > self.policy.max_items
                or context.tenant_ref != request.tenant_ref
                or context.actor_ref != request.requested_by
                or context.resource_version != request.resource_version
                or invocation_digest(context) != request.context_sha256
                or digest_text(canonicalize_arguments(arguments))
                != request.arguments_sha256
            ):
                raise PermissionError("break-glass context mismatch")
            consumed = replace(request, consumed_at=now)
            self._requests[request_id] = consumed
            return consumed


def assert_single_concurrent_redemption(
    store: ApprovalStore,
    raw_token: str,
    request_id: str,
    context: InvocationContext,
    arguments: Mapping[str, Any],
    *,
    now: datetime | None = None,
) -> None:
    """Exercise the one-time invariant from two concurrent workers."""
    barrier = Barrier(2)
    outcomes: list[str] = []
    outcomes_lock = Lock()

    def redeem() -> None:
        barrier.wait()
        try:
            store.consume(raw_token, request_id, context, arguments, now=now)
            outcome = "consumed"
        except PermissionError:
            outcome = "denied"
        with outcomes_lock:
            outcomes.append(outcome)

    workers = [Thread(target=redeem) for _ in range(2)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()
    if sorted(outcomes) != ["consumed", "denied"]:
        raise AssertionError(f"unexpected redemption outcomes: {outcomes}")


def _demo() -> None:
    now = datetime.now(timezone.utc)
    context = InvocationContext(
        qualified_tool="trusted.tickets.export_cases",
        tool_version="2.4.1",
        artifact_sha256="a" * 64,
        schema_sha256="b" * 64,
        tenant_ref="tenant-17",
        actor_ref="requester-17",
        resource_version="cases-etag-41",
        data_classification="restricted",
        item_count=8_400,
        delegation_chain=(
            DelegationHop("requester-17", "planner-4", "case export"),
            DelegationHop("requester-17", "executor-9", "deliver export"),
        ),
        external_side_effect=True,
    )
    arguments = {
        "case_set": "approved-set-41",
        "recipient": "external-counsel@example.test",
    }
    request = create_approval_request(context, arguments, now=now)
    store = ApprovalStore()
    store.save_request(request)
    approver = VerifiedApprover(
        subject_ref="approver-82",
        tenant_ref=context.tenant_ref,
        roles=frozenset({"hitl_approver"}),
        identity_issuer="https://id.example.test",
        authenticated_at=now + timedelta(seconds=1),
        assurance_level="aal2",
    )
    raw_token = store.approve_request(
        request.request_id,
        approver,
        now=now + timedelta(seconds=2),
    )
    assert_single_concurrent_redemption(
        store,
        raw_token,
        request.request_id,
        context,
        arguments,
        now=now + timedelta(seconds=3),
    )
    print("concurrent redemption invariant passed")
    assert evaluate_approval_fatigue(10).action is FatigueAction.PAUSE_SESSION
    print("approval fatigue decision: pause_session")

    emergency_context = replace(context, item_count=5)
    emergency = BreakGlassStore(
        BreakGlassPolicy(frozenset({context.qualified_tool}), max_items=10)
    )
    emergency_request = emergency.create_request(
        emergency_context, arguments, "INC-synthetic-1", now=now
    )
    for subject, role in (
        ("commander-1", "incident_commander"),
        ("security-2", "security_duty_officer"),
    ):
        emergency.authorize(
            emergency_request.request_id,
            replace(approver, subject_ref=subject, roles=frozenset({role})),
            now=now + timedelta(seconds=2),
        )
    emergency.consume(
        emergency_request.request_id,
        emergency_context,
        arguments,
        now=now + timedelta(seconds=3),
    )
    print("two-role break-glass request consumed once; no tool was executed")


if __name__ == "__main__":
    _demo()
