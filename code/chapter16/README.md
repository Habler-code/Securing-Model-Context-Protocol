# Chapter 16 — Applying security design patterns

`security_design_patterns.py` implements two identity extractors, workload-call
authorization, four defense layers, and a contextual decision walkthrough.

The companion was compared with the chapter manuscript on
22 October 2026. The chapter's callable forms are supported:

```python
identity = StandardClaimsExtractor().extract(validated_claims)
request = VerifiedServiceRequest("mcp-client", "mcp-server", identity, "tools/call")
authorize_service_call(request)
decision = decide(context_with_artifacts, verifier)
```

The dictionary in this example must already have passed token validation.
`VerifiedClaims` is also accepted as an explicit pipeline marker. The alternate
service form takes `VerifiedWorkloadIdentity` plus a local receiving service.
The allowlist includes the chapter's local identity labels and illustrative
SPIFFE subjects; deployment policy must provision the exact authenticated
subjects, never choose one from a request body.

`PolicyContext` accepts `step_up_artifact` and `approval_artifact` fields for
`decide(ctx, verifier)`. Existing four-argument calls remain available. The
companion verifier protocol spells out principal/session/age binding for
step-up and purpose/context binding for approval, rather than leaving the
interface undefined. `PolicyDecision.reason` aliases its stable `reason_code`.

Run from `code/` with Python 3.11 or later:

```bash
python chapter16/security_design_patterns.py
python -m unittest discover -s tests -p test_late_regressions.py -v
```

The demo reports equivalent identity profiles, an allowed service call, four
passed defenses, missing controls, an allowed contextual decision, and a denied
approval replay.

`VerifiedClaims` marks data produced by an upstream token validator; constructing
it is not authentication. That validator checks signature, issuer, audience,
lifetime, and issuer policy, and chooses the reviewed extractor for that issuer.
The workload subject similarly comes from authenticated transport such as a
verified mTLS/SPIFFE identity; request headers cannot select it.

Defense checks must be bounded, read-only functions returning actual booleans.
The default enforcement requires each of `prevent`, `contain`, `detect`, and
`respond` exactly once. Missing, duplicate, false, malformed, or exception
results deny execution. The demo uses synthetic control checks, not an actual
sandbox, audit service, or revocation feed.

`DemoContextVerifier` uses predictable fixture strings so the walkthrough can
run without external infrastructure. Those strings are not secure tokens and
the adapter does not authenticate or timestamp them. A production verifier must
validate fresh step-up evidence, bind approvals to the complete action and
session context, and consume them in a shared transactional store. Chapter 20
shows a fuller in-memory approval protocol.

Tests cover both claim profiles, malformed roles, workload allowlist denial,
required defense completeness, nonboolean checks, and check exceptions. Token
validation, transport identities, and policy-engine availability require
separate integration tests.
