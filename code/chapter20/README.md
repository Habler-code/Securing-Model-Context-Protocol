# Chapter 20 — Control high-impact MCP actions with human approval

`hitl_controls.py` implements risk classification, immutable approval requests,
delegation binding, fresh independent approval, one-time grants, concurrency
checks, an enforcement hook, fatigue decisions, and a controlled break-glass
store. All identities and operations in the demo are synthetic.

The companion was compared with the chapter manuscript on
22 October 2026. It supports the displayed canonical redemption call:

```python
store.consume(
    raw_token=token,
    request_id=request.request_id,
    context=context,
    risk_tier=classify_invocation(context),
    arguments_json=canonicalize_arguments(arguments),
    at=redemption_time,
)
```

Existing Mapping-based redemption and the `now` test-clock keyword remain
available; supply only one time and one argument representation. Canonical JSON
must be the exact compact encoding used at creation. The grant records the
computed risk tier as well as the complete context digest.

The companion adds a required trusted `resource_version`, bounded delegation
hops, and a digest covering all governed effects to the chapter's smaller
`InvocationContext`. Supply those fields from the authoritative resource and
orchestrator, not model suggestions. It also implements the chapter's described
emergency procedure as an offline `BreakGlassStore`; the chapter correctly
identifies the displayed emergency steps as operating requirements rather than
an existing production integration.

For the offline running case, the additional field is explicit:

```python
context = InvocationContext(
    qualified_tool="trusted.tickets.export_cases",
    tool_version="2.4.1",
    artifact_sha256="a" * 64,
    schema_sha256="b" * 64,
    tenant_ref="tenant-example",
    actor_ref="requester-example",
    resource_version="synthetic-etag-v1",
    data_classification="restricted",
    item_count=5,
)
```

Those identifiers and digests are synthetic test values. At a real boundary,
the governed release registry supplies release/schema digests and an
authenticated resource adapter supplies the exact version or immutable snapshot
identifier. There is no implicit unversioned fallback.

`approve_request` accepts the chapter's positional or keyword `at` argument;
`now` remains a test-clock alias, and using both is rejected. Both the stored
deadline and the fixed request-lifetime ceiling are enforced. Grants retain
approver issuer, assurance, and authentication time. Token collisions retry at
most three times, then fail without overwriting a grant or deciding the request.
Approver roles and emergency Tool allowlists require bounded `frozenset[str]`
values so authorization always uses exact membership.

Run from `code/` with Python 3.11 or later:

```bash
python chapter20/hitl_controls.py
python -m unittest discover -s tests -p test_late_regressions.py -v
```

Expected output reports a passed concurrent-redemption check, a session-pause
decision, and a two-role break-glass request consumed once. No tool is executed.

`InvocationContext` must come from governed registry and authenticated
orchestration state. It rejects invalid data classes/counts/flags and repeated
agents in the bounded delegation chain. `create_approval_request` snapshots
canonical arguments, a bounded model rationale, and a digest of every governed
context field: tool release and schema, tenant, actor, resource version, data
class, count, effects, and delegation. The rationale is untrusted display data;
it never determines authorization.

Use `ApprovalStore` to record a request, approve it as a different fresh,
authorized tenant member, and issue a random opaque token. Only the token hash
is stored. Consumption checks context, arguments, lifetime, and one-time state
inside one lock. Grants cannot be consumed before approval. The demo uses an
explicit synthetic clock to test concurrency without sleeping.

`enforce_hitl_policy` returns the same immutable JSON that was checked. Execute
that snapshot rather than a caller mapping that may change afterward. The hook
enforces human approval only; schema checks, ordinary object authorization,
listed rate limits, resource preconditions/idempotency, and durable audit remain
required at the real execution boundary. It does not execute any tool.

`evaluate_approval_fatigue` returns continue/batch-review/pause decisions at the
chapter's illustrative thresholds. A Host must enforce those decisions; this
function does not manage session state or pause a process itself.

The separate `BreakGlassStore` requires an allowlisted emergency tool, bounded
item count, incident reference, short expiry, two distinct emergency reviewers,
and fresh tenant-matched assurance. It binds the complete invocation context,
rechecks current emergency policy, and consumes once. An unavailable quorum
denies execution. It grants no standing emergency authority and executes no
incident action.

Tests mutate each governed context field, arguments, time, release, actor,
delegation, and emergency scope; exercise quorum, replay, expiry, not-yet-valid
grants, fatigue boundaries, immutable execution input, and simultaneous
redemption. These are offline in-memory tests. Run the same invariants against
the real shared datastore, with retries and lost responses, before deployment.
An in-process lock cannot make a remote business side effect atomic.
