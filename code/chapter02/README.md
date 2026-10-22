# Chapter 2 — Apply a policy-first Tool gate

Book section: “Implementation (Python): Policy-first tool gate with defense-in-depth.”

`policy_gate.py` assembles the current chapter's `ToolCall`, `PolicyError`,
`TOOL_RISK` and `handle_tool_call(call)` APIs. It checks trusted identity, tenant
binding, arguments and registered Tool risk, then records and returns a decision.
A low-risk search succeeds; medium- and high-risk calls require approval.

From `code/`, after the shared Python setup:

```sh
python chapter02/policy_gate.py
python -m unittest discover -s tests -p test_early_python.py -v
```

The demo does not invoke an MCP Server or external service. The returned result
is a policy decision, not evidence that a transport or Server authorization ran.

## Companion corrections and fixture contracts

The chapter explicitly calls its listing a teaching skeleton. This assembled
module fixes the indentation of the final exception handler, validates bounded
identity fields, and rejects non-string tenant arguments instead of coercing
them with `str()`. It copies arguments through JSON and measures UTF-8 bytes
against the 100,000-byte limit. It does not mutate the caller's argument mapping.

The chapter requires exact per-Tool schemas when integrating the gate. The
companion supplies small explicit fixture contracts: `read_resource` takes
`tenantId` and `resourceId`; `search` takes `tenantId` and `query`;
`create_ticket` takes `tenantId`, `title` and `body`; `admin_export` takes
`tenantId` and `format`. Unknown fields, nested objects, wrong types and oversized
strings are rejected. Replace those fixture contracts with the approved real
Tool schemas when integrating. The risk behavior follows the chapter: only low
risk can proceed autonomously in this introductory gate.

## Trust boundary

Authentication middleware supplies `ToolCall.user_id` and `tenant_id`. Never
populate them from the model or request arguments. The Host must make this gate
mandatory before every outbound Tool invocation. This example does not verify
OAuth tokens, implement RBAC, execute approvals or resolve resource ownership.
Those controls are developed in later chapters and must also run at the Server.
Only selected identity/decision metadata enters logging; raw arguments and
credentials do not.

Tests cover positive decisions, missing identity, tenant mismatches and types,
unknown Tools, medium/high risk, argument contracts, serialization failures and
preservation of the original arguments.
