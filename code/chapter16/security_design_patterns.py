"""Runnable security-design-pattern examples for Chapter 16."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol


@dataclass(frozen=True)
class VerifiedClaims:
    """Claims returned by a successful token validator."""

    values: Mapping[str, Any]
    issuer: str
    audience: str


@dataclass(frozen=True)
class NormalizedIdentity:
    tenant_id: str
    user_id: str
    roles: frozenset[str]
    scopes: frozenset[str]


class IdentityExtractor(Protocol):
    def extract(self, claims: VerifiedClaims | Mapping[str, Any]) -> NormalizedIdentity: ...


def _claim_values(verified: VerifiedClaims | Mapping[str, Any]) -> Mapping[str, Any]:
    """Accept either chapter notation after the same upstream validation gate."""
    if isinstance(verified, VerifiedClaims):
        return verified.values
    if isinstance(verified, Mapping):
        return verified
    raise PermissionError("claims must be a validated mapping")


def _required_string(claims: Mapping[str, Any], name: str) -> str:
    value = claims.get(name)
    if not isinstance(value, str) or not value:
        raise PermissionError(f"Invalid required claim: {name}")
    return value


def _roles(claims: Mapping[str, Any], name: str) -> frozenset[str]:
    value = claims.get(name, ())
    if not isinstance(value, (list, tuple)) or any(
        not isinstance(role, str) or not role for role in value
    ):
        raise PermissionError(f"Invalid roles claim: {name}")
    return frozenset(value)


def _scopes(claims: Mapping[str, Any]) -> frozenset[str]:
    value = claims.get("scope", "")
    if not isinstance(value, str):
        raise PermissionError("Invalid scope claim")
    return frozenset(value.split())


class StandardClaimsExtractor:
    """Normalize one reviewed OIDC claim profile."""

    def extract(self, verified: VerifiedClaims | Mapping[str, Any]) -> NormalizedIdentity:
        claims = _claim_values(verified)
        tenant_id = claims.get("tenant_id") or claims.get("org_id")
        if not isinstance(tenant_id, str) or not tenant_id:
            raise PermissionError("Invalid tenant claim")
        return NormalizedIdentity(
            tenant_id=tenant_id,
            user_id=_required_string(claims, "sub"),
            roles=_roles(claims, "roles"),
            scopes=_scopes(claims),
        )


class NamespacedClaimsExtractor:
    """Normalize an issuer profile that uses namespaced custom claims."""

    TENANT_CLAIM = "https://example.test/claims/tenant_id"
    ROLES_CLAIM = "https://example.test/claims/roles"

    def extract(self, verified: VerifiedClaims | Mapping[str, Any]) -> NormalizedIdentity:
        claims = _claim_values(verified)
        return NormalizedIdentity(
            tenant_id=_required_string(claims, self.TENANT_CLAIM),
            user_id=_required_string(claims, "sub"),
            roles=_roles(claims, self.ROLES_CLAIM),
            scopes=_scopes(claims),
        )


@dataclass(frozen=True)
class VerifiedWorkloadIdentity:
    """Identity established by the authenticated transport."""

    subject: str


@dataclass(frozen=True)
class VerifiedServiceRequest:
    """Chapter notation populated by transport and local receiver policy."""

    caller_subject: str
    receiving_service: str
    identity: NormalizedIdentity
    action: str


ALLOWED_SERVICE_CALLS: dict[str, frozenset[str]] = {
    "mcp-client": frozenset({"mcp-server"}),
    "mcp-server": frozenset({"tool-runtime-low", "tool-runtime-high"}),
    "tool-runtime-low": frozenset({"data-store-readonly"}),
    "tool-runtime-high": frozenset({"data-store-readwrite", "external-api"}),
    "spiffe://example.test/client": frozenset({"mcp-server"}),
    "spiffe://example.test/server": frozenset(
        {"tool-runtime-low", "tool-runtime-high"}
    ),
    "spiffe://example.test/runtime-low": frozenset({"data-store-readonly"}),
    "spiffe://example.test/runtime-high": frozenset(
        {"data-store-readwrite", "external-api"}
    ),
}


def authorize_service_call(
    caller: VerifiedWorkloadIdentity | VerifiedServiceRequest,
    receiving_service: str | None = None,
) -> None:
    """Authorize the transport-derived caller at the receiver."""
    if isinstance(caller, VerifiedServiceRequest):
        if receiving_service is not None:
            raise ValueError("receiver must not override a verified service request")
        receiving_service = caller.receiving_service
        subject = caller.caller_subject
    elif isinstance(caller, VerifiedWorkloadIdentity):
        subject = caller.subject
    else:
        raise PermissionError("verified workload identity is required")
    allowed_targets = ALLOWED_SERVICE_CALLS.get(subject)
    if allowed_targets is None or receiving_service not in allowed_targets:
        raise PermissionError("Workload is not permitted to call this service")


@dataclass(frozen=True)
class LayeredCheckResult:
    layer: str
    passed: bool
    reason_code: str


def run_defense_layers(
    checks: tuple[tuple[str, Callable[[], bool], str], ...],
) -> tuple[LayeredCheckResult, ...]:
    """Run independent, side-effect-free checks for one request."""
    results: list[LayeredCheckResult] = []
    seen: set[str] = set()
    for layer_name, check_fn, denial_code in checks:
        if not isinstance(layer_name, str) or not layer_name or layer_name in seen:
            raise ValueError("defense layer names must be non-empty and unique")
        seen.add(layer_name)
        try:
            passed = check_fn()
            if not isinstance(passed, bool):
                passed = False
                reason_code = "invalid_check_result"
            else:
                reason_code = "passed" if passed else denial_code
        except Exception:
            passed = False
            reason_code = "check_error"
        results.append(LayeredCheckResult(layer_name, passed, reason_code))
    return tuple(results)


REQUIRED_DEFENSE_LAYERS = frozenset({"prevent", "contain", "detect", "respond"})


def enforce_defense_layers(
    results: tuple[LayeredCheckResult, ...],
    *,
    required_layers: frozenset[str] = REQUIRED_DEFENSE_LAYERS,
) -> None:
    """Require a complete set of explicit successful control results."""
    names = [result.layer for result in results]
    if (
        not required_layers
        or len(names) != len(set(names))
        or not required_layers.issubset(names)
        or any(result.passed is not True for result in results)
    ):
        raise PermissionError("Request denied by security policy")


VALID_RISK_LEVELS = frozenset({"low", "medium", "high"})


@dataclass(frozen=True)
class PolicyContext:
    tenant_id: str
    user_id: str
    session_id: str
    tool: str
    resource_id: str
    request_digest: str
    risk: str
    anomaly_score: float
    step_up_artifact: str | None = None
    approval_artifact: str | None = None


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason_code: str
    required_controls: tuple[str, ...] = ()

    @property
    def reason(self) -> str:
        return self.reason_code


class ContextControlVerifier(Protocol):
    def verify_step_up(
        self,
        artifact: str,
        *,
        tenant_id: str,
        user_id: str,
        session_id: str,
        max_age_seconds: int,
    ) -> bool: ...

    def verify_and_consume_approval(
        self,
        artifact: str,
        *,
        context: PolicyContext,
        purpose: str,
    ) -> bool: ...


def decide(
    context: PolicyContext,
    step_up_artifact: str | ContextControlVerifier | None = None,
    approval_artifact: str | None = None,
    verifier: ContextControlVerifier | None = None,
) -> PolicyDecision:
    """Apply contextual restrictions and verify additional controls."""
    # The chapter passes artifacts in ctx and calls decide(ctx, verifier).
    # Existing callers can continue supplying the two artifacts separately.
    if verifier is None and step_up_artifact is not None and not isinstance(step_up_artifact, str):
        verifier = step_up_artifact
        step_up_artifact = context.step_up_artifact
        approval_artifact = context.approval_artifact
    if verifier is None:
        return PolicyDecision(False, "control_verifier_unavailable")
    if step_up_artifact is None:
        step_up_artifact = context.step_up_artifact
    if approval_artifact is None:
        approval_artifact = context.approval_artifact
    identity_fields = (
        context.tenant_id,
        context.user_id,
        context.session_id,
        context.tool,
        context.resource_id,
        context.request_digest,
    )
    if any(not isinstance(value, str) or not value for value in identity_fields):
        return PolicyDecision(False, "missing_identity")
    if not isinstance(context.risk, str) or context.risk not in VALID_RISK_LEVELS:
        return PolicyDecision(False, "unknown_risk")
    if (
        isinstance(context.anomaly_score, bool)
        or not isinstance(context.anomaly_score, (int, float))
        or not 0.0 <= context.anomaly_score <= 1.0
    ):
        return PolicyDecision(False, "invalid_anomaly_signal")

    controls: list[str] = []
    if context.risk == "high":
        controls.append("transaction_approval")
    if context.anomaly_score >= 0.8:
        controls.append("step_up_authentication")
    required_controls = tuple(controls)

    if "step_up_authentication" in required_controls:
        if step_up_artifact is None:
            return PolicyDecision(
                False,
                "additional_controls_required",
                required_controls,
            )
        try:
            step_up_is_valid = verifier.verify_step_up(
                step_up_artifact,
                tenant_id=context.tenant_id,
                user_id=context.user_id,
                session_id=context.session_id,
                max_age_seconds=300,
            )
        except Exception:
            return PolicyDecision(False, "control_verifier_error")
        if step_up_is_valid is not True:
            return PolicyDecision(False, "invalid_step_up_artifact")

    if "transaction_approval" in required_controls:
        if approval_artifact is None:
            return PolicyDecision(
                False,
                "additional_controls_required",
                required_controls,
            )
        try:
            approval_is_valid = verifier.verify_and_consume_approval(
                approval_artifact,
                context=context,
                purpose="transaction_approval",
            )
        except Exception:
            return PolicyDecision(False, "control_verifier_error")
        if approval_is_valid is not True:
            return PolicyDecision(False, "invalid_approval_artifact")

    return PolicyDecision(True, "context_policy_allowed")


class DemoContextVerifier:
    """Synthetic fixtures only: predictable strings are not real credentials.

    Production adapters authenticate artifacts, check timestamps and context,
    and consume approvals transactionally. This adapter performs no such I/O.
    """
    def __init__(self) -> None:
        self._consumed: set[str] = set()

    def verify_step_up(
        self,
        artifact: str,
        *,
        tenant_id: str,
        user_id: str,
        session_id: str,
        max_age_seconds: int,
    ) -> bool:
        expected = f"step:{tenant_id}:{user_id}:{session_id}"
        return artifact == expected and max_age_seconds == 300

    def verify_and_consume_approval(
        self,
        artifact: str,
        *,
        context: PolicyContext,
        purpose: str,
    ) -> bool:
        expected = (
            f"approve:{context.tenant_id}:{context.user_id}:"
            f"{context.request_digest}:{purpose}"
        )
        if artifact != expected or artifact in self._consumed:
            return False
        self._consumed.add(artifact)
        return True


def demo() -> None:
    standard = StandardClaimsExtractor().extract(
        VerifiedClaims(
            values={
                "tenant_id": "tenant-a",
                "sub": "agent-42",
                "roles": ["support"],
                "scope": "tickets.read support.export",
            },
            issuer="https://id.example.test",
            audience="tickets-server",
        )
    )
    namespaced = NamespacedClaimsExtractor().extract(
        VerifiedClaims(
            values={
                "https://example.test/claims/tenant_id": "tenant-a",
                "https://example.test/claims/roles": ["support"],
                "sub": "agent-42",
                "scope": "tickets.read support.export",
            },
            issuer="https://partner-id.example.test",
            audience="tickets-server",
        )
    )
    assert standard == namespaced

    authorize_service_call(
        VerifiedWorkloadIdentity("spiffe://example.test/client"),
        "mcp-server",
    )

    layered = run_defense_layers(
        (
            ("prevent", lambda: "support.export" in standard.scopes, "scope_denied"),
            ("contain", lambda: True, "runtime_not_isolated"),
            ("detect", lambda: True, "audit_unavailable"),
            ("respond", lambda: True, "revocation_state_stale"),
        )
    )
    enforce_defense_layers(layered)

    context = PolicyContext(
        tenant_id="tenant-a",
        user_id="agent-42",
        session_id="session-7",
        tool="export_cases",
        resource_id="quarterly-report",
        request_digest="sha256:7c9f...",
        risk="high",
        anomaly_score=0.91,
    )
    verifier = DemoContextVerifier()
    missing = decide(context, None, None, verifier)
    allowed = decide(
        context,
        "step:tenant-a:agent-42:session-7",
        "approve:tenant-a:agent-42:sha256:7c9f...:transaction_approval",
        verifier,
    )
    replayed = decide(
        context,
        "step:tenant-a:agent-42:session-7",
        "approve:tenant-a:agent-42:sha256:7c9f...:transaction_approval",
        verifier,
    )
    assert missing.required_controls == (
        "transaction_approval",
        "step_up_authentication",
    )
    assert allowed.allowed is True
    assert replayed.reason_code == "invalid_approval_artifact"

    print("identity profiles: equivalent")
    print("service call: allowed")
    print("defense layers:", [result.reason_code for result in layered])
    print("first contextual decision:", missing.reason_code)
    print("approved decision:", allowed.reason_code)
    print("replay decision:", replayed.reason_code)


if __name__ == "__main__":
    demo()
