# Chapter 6 — Keep context separate from Host policy

Book section: “Implementation: structured context and host-owned policy in Python.”

`untrusted_content.py` follows the current Python listing: `Provenance`,
`RetrievedText`, `render_for_context`, the request/policy/approval/dispatch records,
`SessionContext`, and async `execute_tool_call`. It uses only the standard library;
the chapter's baseline is Python 3.12 or later.

From `code/`:

```sh
python chapter06/untrusted_content.py
python -m unittest discover -s tests -p test_early_python.py -v
```

The demo preserves an injected closing marker as JSON data, permits a synthetic
read through an offline dispatcher, and blocks an export when approval is denied.
No model, real credential, MCP Server or network connection is used.

## Core flow and trusted adapters

Protected registry data supplies canonical Tool identity, authenticated Server
binding and risk. The session allowlist must permit the exact canonical ID.
`validate_and_freeze_args` validates one snapshot; a high-risk request passes
that same snapshot to `request_human_approval`; dispatch receives it with the
protected policy, request ID, transport token and optional opaque grant.

The companion validates registry bindings and risk labels at startup, snapshots
registry/allowlist data, and requires deeply immutable callback output. Read-only
mappings and tuples are accepted; mutable dictionaries/lists are rejected at
the dispatch boundary. The Token and approval-grant fields are excluded from
dataclass representations to reduce accidental diagnostic exposure.

Provenance labels must be derived by a trusted ingestion component. The code
retains the chapter's `trusted` label as one possible ingestion classification;
no label turns retrieved content into Host instructions or authorization. JSON
serialization protects the envelope's structure, not a model's interpretation.
The companion adds bounds and basic type/time validation to that envelope.

## Offline adapter scope

`make_offline_context` wires an explicit fixture schema, protected registry,
synthetic authenticated channel and independent Server resource check.
`OfflineApprovals` receives an explicit test reviewer decision and issues an
unpredictable, 60-second, request/user/Tool/Server/argument-bound grant. A lock
makes successful consumption one-time inside this process. The tests demonstrate
replay, expiry, identity and argument mismatch denials. These are demonstration
adapters added to exercise the chapter's callback interfaces; they are not
external human review, a durable approval database, or real token verification.

Production adapters must verify identity/tokens, enforce the real Tool schema,
bind approval to the immutable action, route only to the authenticated Server,
and recheck tenant/resource policy there. Multiprocess grant consumption needs
transactional shared storage. Definition quarantine, registry migration,
workflow prerequisites, approval-queue controls, idempotency, durable audit,
timeouts and behavioral monitoring remain explicit integration responsibilities.
This compact example does not claim to implement the full workflow state machine.

Tests cover policy/allowlist denial, invalid bindings/risks, mutable arguments,
approval denial, shared immutable snapshots, independent Server authorization,
one-time grant consumption and structured content handling.
