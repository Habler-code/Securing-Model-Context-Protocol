# Chapter 18 — Monitor and observe MCP systems

`monitoring_observability.py` supplies privacy-aware audit records, bounded
in-process metrics, explainable spike detection, trace-ID validation, and
incident-response plans. It makes no external service calls.

The companion was compared with the chapter manuscript on
22 October 2026. It includes `MAX_AUDIT_FIELD_CHARS`, aware ISO8601 timestamp
checks, `emit_audit_event`, `is_valid_trace_id`, and the bounded three-attempt
trace-ID generator. The companion additionally rejects malformed counters and
caps metric series so failures can be exercised safely offline.

Run from `code/` with Python 3.11 or later:

```bash
python chapter18/monitoring_observability.py
python -m unittest discover -s tests -p test_late_regressions.py -v
```

The demo prints one JSON audit record, the explanation
`count ratio 12.0 reached threshold 10.0`, and ordered containment-plan steps.
Timestamps and trace IDs vary between runs.

`encode_audit_event` returns one JSON record; `emit_audit_event` prints it with a
newline and flushes the process buffer. JSON encoding escapes embedded
newlines. References must be generated upstream without raw credentials,
arguments, or output. A supervised collector must still authenticate producers,
protect transport/storage, monitor delivery, apply retention, and implement
degraded-mode policy. A successful print is not proof of durable acceptance.
Use a dedicated collector stream: this emitter must never share an MCP stdio
stdout pipe, which is reserved for protocol messages.

The metrics collector caps distinct `(subject_ref, tool_alias)` keys at 1024
by default. New series beyond capacity raise an error and increment
`dropped_series`; the caller must handle this explicitly and report health.
Counters have no automatic time-window rotation. A production exporter should
use bounded registered labels and a protected store for per-subject detail.

Compare equal time windows when calling `check_invocation_spike`. The sample
thresholds are illustrative and return a triage signal, not proof of an attack.
`invocation_spike_contract.txt` reproduces the chapter's platform-neutral query
contract for mapping the rule into a SIEM; it is deliberately not vendor syntax
or an executable query. Deduplicate observations into one authoritative
invocation and preserve tenant scope before aggregation.
Trace IDs provide correlation and never grant identity or authorization.
`plan_playbook_actions` only returns a plan; it does not revoke tokens, alter
networks, or perform any incident action.

Tests cover NDJSON newline escaping, metric bounds/types, sparse-baseline and
ratio boundaries, malformed trace IDs, and invalid rule thresholds. Delivery,
retention, authorization of responders, and real telemetry load require
deployment tests.
