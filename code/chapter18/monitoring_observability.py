"""Runnable examples for Chapter 18: Monitor and Observe MCP Systems."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import math
import re
import secrets


MAX_AUDIT_FIELD_CHARS = 256


def utc_now() -> str:
    """Return an RFC 3339-compatible UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class ToolAuditEvent:
    event_id: str
    trace_id: str
    request_id: str
    tenant_ref: str
    actor_ref: str
    server_id: str
    tool_alias: str
    risk_tier: str
    decision: str
    reason_code: str
    input_ref: str
    output_bytes: int = 0
    occurred_at: str = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        for name in ("event_id", "trace_id", "request_id", "tenant_ref", "actor_ref", "server_id", "tool_alias", "risk_tier", "decision", "reason_code", "input_ref", "occurred_at"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip() or len(value) > MAX_AUDIT_FIELD_CHARS:
                raise ValueError(f"invalid bounded audit field: {name}")
        validate_trace_id(self.trace_id)
        try:
            timestamp = datetime.fromisoformat(self.occurred_at)
        except ValueError as exc:
            raise ValueError("occurred_at must be an ISO8601 timestamp") from exc
        if timestamp.utcoffset() is None:
            raise ValueError("occurred_at must be timezone aware")
        if self.risk_tier not in {"low", "medium", "high"}:
            raise ValueError("invalid risk tier")
        if self.decision not in {"allow", "deny", "error"}:
            raise ValueError("invalid decision")
        if isinstance(self.output_bytes, bool) or not isinstance(self.output_bytes, int) or self.output_bytes < 0:
            raise ValueError("output_bytes cannot be negative")


def encode_audit_event(event: ToolAuditEvent) -> str:
    """Encode one event as a single NDJSON record."""
    return json.dumps(
        asdict(event),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    )


def emit_audit_event(event: ToolAuditEvent) -> None:
    """Emit to a dedicated collector stream, never an MCP stdio stdout pipe."""
    print(encode_audit_event(event), flush=True)


MetricKey = tuple[str, str]


@dataclass
class ToolUsageMetrics:
    invocation_counts: dict[MetricKey, int] = field(
        default_factory=lambda: defaultdict(int)
    )
    denial_counts: dict[MetricKey, int] = field(
        default_factory=lambda: defaultdict(int)
    )
    bytes_read: dict[MetricKey, int] = field(
        default_factory=lambda: defaultdict(int)
    )
    last_invocation: dict[MetricKey, str] = field(default_factory=dict)
    max_keys: int = 1_024
    dropped_series: int = 0

    def __post_init__(self) -> None:
        if isinstance(self.max_keys, bool) or not isinstance(self.max_keys, int) or self.max_keys < 1:
            raise ValueError("max_keys must be a positive integer")

    def record_invocation(
        self,
        subject_ref: str,
        tool_alias: str,
        allowed: bool,
        bytes_accessed: int = 0,
    ) -> None:
        """Record one validated invocation using pseudonymous keys."""
        if isinstance(bytes_accessed, bool) or not isinstance(bytes_accessed, int) or bytes_accessed < 0:
            raise ValueError("bytes_accessed cannot be negative")
        if not isinstance(allowed, bool):
            raise ValueError("allowed must be a boolean")
        if any(not isinstance(value, str) or not value or len(value) > 128 for value in (subject_ref, tool_alias)):
            raise ValueError("metric labels must be bounded non-empty strings")

        key = (subject_ref, tool_alias)
        if key not in self.last_invocation and len(self.last_invocation) >= self.max_keys:
            self.dropped_series += 1
            raise ValueError("metric series capacity reached")
        if allowed:
            self.invocation_counts[key] += 1
            self.bytes_read[key] += bytes_accessed
        else:
            self.denial_counts[key] += 1

        self.last_invocation[key] = utc_now()


@dataclass(frozen=True)
class SpikeRule:
    ratio_threshold: float = 10.0
    minimum_current_count: int = 50
    minimum_baseline_count: int = 5
    cold_start_threshold: int = 100

    def __post_init__(self) -> None:
        if isinstance(self.ratio_threshold, bool) or not isinstance(self.ratio_threshold, (int, float)) or not math.isfinite(self.ratio_threshold) or self.ratio_threshold <= 1:
            raise ValueError("ratio_threshold must be finite and greater than 1")
        counts = (self.minimum_current_count, self.minimum_baseline_count, self.cold_start_threshold)
        if any(isinstance(value, bool) or not isinstance(value, int) or value < 1 for value in counts):
            raise ValueError("rule count thresholds must be positive integers")


@dataclass(frozen=True)
class AnomalyAlert:
    rule_name: str
    subject_ref: str
    tool_alias: str
    current_count: int
    baseline_count: int
    window_minutes: int
    explanation: str
    triggered_at: str


def check_invocation_spike(
    current_count: int,
    baseline_count: int,
    window_minutes: int,
    subject_ref: str,
    tool_alias: str,
    rule: SpikeRule = SpikeRule(),
) -> AnomalyAlert | None:
    """Compare equivalent windows and handle sparse baselines explicitly."""
    if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in (current_count, baseline_count, window_minutes)):
        raise ValueError("counts and window must be non-negative")
    if window_minutes == 0:
        raise ValueError("window_minutes must be positive")

    if baseline_count < rule.minimum_baseline_count:
        if current_count < rule.cold_start_threshold:
            return None
        explanation = (
            f"cold-start count {current_count} reached "
            f"absolute threshold {rule.cold_start_threshold}"
        )
    else:
        ratio = current_count / baseline_count
        if (
            current_count < rule.minimum_current_count
            or ratio < rule.ratio_threshold
        ):
            return None
        explanation = (
            f"count ratio {ratio:.1f} reached "
            f"threshold {rule.ratio_threshold:.1f}"
        )

    return AnomalyAlert(
        rule_name="invocation_spike",
        subject_ref=subject_ref,
        tool_alias=tool_alias,
        current_count=current_count,
        baseline_count=baseline_count,
        window_minutes=window_minutes,
        explanation=explanation,
        triggered_at=utc_now(),
    )


TRACE_ID_PATTERN = re.compile(r"^[0-9a-f]{32}$")
ZERO_TRACE_ID = "0" * 32


def is_valid_trace_id(value: object) -> bool:
    """Check identifier shape only, without establishing a trusted parent."""
    return (
        isinstance(value, str)
        and TRACE_ID_PATTERN.fullmatch(value) is not None
        and value != ZERO_TRACE_ID
    )


def new_trace_id() -> str:
    """Return a valid, unpredictable 16-byte W3C trace identifier."""
    for _ in range(3):
        value = secrets.token_hex(16)
        if is_valid_trace_id(value):
            return value
    raise RuntimeError("could not generate a valid nonzero trace ID")


def validate_trace_id(value: str) -> str:
    """Validate a trace-id field; this does not establish identity."""
    if not is_valid_trace_id(value):
        raise ValueError("invalid W3C trace-id")
    return value


@dataclass(frozen=True)
class IncidentAction:
    action: str
    target: str
    priority: int


@dataclass(frozen=True)
class IncidentPlaybook:
    trigger: str
    severity: str
    actions: tuple[IncidentAction, ...]


PLAYBOOKS: dict[str, IncidentPlaybook] = {
    "credential_theft": IncidentPlaybook(
        trigger="validated token misuse signal",
        severity="critical",
        actions=(
            IncidentAction("preserve_audit_evidence", "case", 1),
            IncidentAction("revoke_tokens", "affected_subject", 1),
            IncidentAction("rotate_secrets", "affected_services", 2),
            IncidentAction("quarantine_server", "suspected_server", 2),
            IncidentAction("notify_incident_commander", "security", 3),
        ),
    ),
    "data_exfiltration": IncidentPlaybook(
        trigger="validated anomalous data-access sequence",
        severity="high",
        actions=(
            IncidentAction("preserve_audit_evidence", "case", 1),
            IncidentAction("block_egress", "affected_runtime", 1),
            IncidentAction("disable_tool", "suspected_tool", 2),
            IncidentAction("review_tenant_scope", "affected_tenant", 2),
        ),
    ),
}


def plan_playbook_actions(playbook_name: str) -> tuple[str, ...]:
    """Return an ordered plan for an authorized response system."""
    try:
        playbook = PLAYBOOKS[playbook_name]
    except KeyError as exc:
        raise ValueError(f"unknown playbook: {playbook_name}") from exc

    ordered = sorted(playbook.actions, key=lambda item: item.priority)
    return tuple(
        f"P{item.priority}:{item.action}:{item.target}"
        for item in ordered
    )


def _demo() -> None:
    trace_id = validate_trace_id(new_trace_id())
    event = ToolAuditEvent(
        event_id="event-001",
        trace_id=trace_id,
        request_id="request-001",
        tenant_ref="tenant-ref-3d7a",
        actor_ref="actor-ref-91be",
        server_id="tickets-server@2.4.1",
        tool_alias="export",
        risk_tier="high",
        decision="allow",
        reason_code="approved_export",
        input_ref="input-hmac-ref-782c",
        output_bytes=4096,
    )
    print(encode_audit_event(event))

    metrics = ToolUsageMetrics()
    metrics.record_invocation("actor-ref-91be", "export", True, 4096)

    alert = check_invocation_spike(72, 6, 5, "actor-ref-91be", "export")
    assert alert is not None
    print(alert.explanation)
    print(*plan_playbook_actions("data_exfiltration"), sep="\n")


if __name__ == "__main__":
    _demo()
