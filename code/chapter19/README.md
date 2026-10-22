# Chapter 19 — Govern MCP systems and demonstrate compliance

`governance_compliance.py` implements exact-artifact registration, independent
approval, high-risk review quorum, runtime admission, evidence currency, and
illustrative retention-policy validation.

The companion was compared with the chapter manuscript on
22 October 2026. The registry, reviewer, evidence, training, report, and retention
types retain the chapter's names, fields, and exact-artifact key. It includes
both `EXAMPLE_RETENTION_POLICIES` entries. Extra input validation and a process
lock make malformed tiers and concurrent reviews testable; an optional
`decision_time` supports deterministic tests.

Run from `code/` with Python 3.11 or later:

```bash
python chapter19/governance_compliance.py
python -m unittest discover -s tests -p test_late_regressions.py -v
```

Expected output includes `enabled: com.example.tickets.export_cases@2.4.1` and
`validated retention policy: example-audit-events`.

Risk tiers and approval states must be actual enum values. Parse external input
explicitly at the boundary and reject unknown values; silently accepting a
string instead of an enum can skip high-risk policy. A registration is keyed by
name, publisher, version, artifact digest, and schema digest.

`VerifiedReviewer` is produced by trusted identity middleware. The registry
requires independent reviewers, evidence references, and the `tool_approver`
role. High-risk releases need two distinct reviewers, a security approver, AAL2
or AAL3, and recent authentication. In-process locking keeps concurrent updates
consistent in this example; production requires shared transactional storage,
reviewer-role freshness, protected evidence, revocation, and durable audit.
Treat the public `tools` dictionary as trusted internal state and do not expose
it as a request-writable object.

Recent authentication and an assurance label do not prove a challenge was bound
to a particular approval. Trusted middleware must establish that binding when
the deployment requires decision-specific step-up.

`generate_compliance_report` reports registry counts and evidence currency. It
does not prove legal compliance, validate evidence contents, or issue an audit
opinion. Retention periods are organization-specific policy examples. The
validator does not delete records or implement legal holds.
Time-current evidence can still describe an obsolete configuration. As stated
in the chapter, production evidence must bind the tested configuration/release,
be invalidated when it changes, and be recollected. The compact report does not
implement that configuration comparison.

Tests cover malformed risk/state values, self and duplicate review, stale/weak
authentication, pending versus approved admission, the high-risk quorum,
evidence freshness, and retention field validation. Real evidence retrieval,
legal holds, access review, and deletion workflows need separate integration
verification.
