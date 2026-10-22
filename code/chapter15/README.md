# Chapter 15 — Enforcing permission models with RBAC

`permission_models.py` combines role policy, exact/broad resource scopes,
autonomous risk ceilings, trusted session assurance, and one-time approval
verification. `authorize_with_assurance` supplies the chapter's intermediate
role-and-assurance gate; `server_authorization_gate` composes the final checks.

The companion was compared with the chapter manuscript on
22 October 2026. The chapter intentionally presents smaller mechanisms before
describing the complete companion. These names are also available here:
`authorize_tool`, `compute_trust_level`, `authorize_with_trust`, and
`host_policy_gate`. They demonstrate individual role, trust, or Host checks;
none substitutes for the integrated Server gate.

| Chapter shorthand | Complete companion representation |
| --- | --- |
| `"low"`, `"medium"`, `"high"` | `RiskLevel` and `AssuranceLevel` enums; string trust adapters remain available |
| Wildcard `resource_id=None` | Explicit `PermissionScope(..., all_resources=True)` |
| Boolean scope result | `PolicyDecision.allowed`; Boolean use also returns that field |
| `reason`, `required_approvals` | Read-only properties over `reason_code`, `required_controls` |
| `has_approval=True` | Illustration only; final gate requires a bound artifact and verifier |

The final Server API takes `TieredPermission`, Resource identity, current
`AssuranceLevel`, recomputed request digest, and the approval verifier. It
deliberately does not accept the chapter's illustrative Boolean as execution
authorization.

Run from `code/` with Python 3.11 or later:

```bash
python chapter15/permission_models.py
python -m unittest discover -s tests -p test_late_regressions.py -v
```

The demo prints these outcomes in order:

```text
viewer update: role_or_tool_denied
user update SR-1042: server_policy_allowed
admin export without approval: approval_required
admin export with approval: server_policy_allowed
admin export replay: invalid_approval_artifact
```

Principals, scopes, risk classifications, and session signals must come from
trusted server state. Stronger assurance satisfies a prerequisite; it cannot
expand a role or resource grant. Recompute the request digest from validated
arguments at the enforcement boundary rather than trusting a caller's digest.

`OneTimeApprovalVerifier` is a synthetic single-process test adapter. Its
preloaded identifier is not a production approval credential. It demonstrates
atomic one-time consumption and tenant/actor/action/resource/digest binding;
it does not issue approvals, authenticate approvers, or enforce artifact expiry.
Use the more complete Chapter 20 flow or a reviewed adapter with those controls
for a real service. Ordinary authorization and the eventual side effect must
also recheck current resource state.

Tests cover role limits, assurance reduction, invalid signals, deterministic
digest behavior, approval binding, and replay. Real identity-provider freshness,
shared-store transactions, audit delivery, and policy updates need integration
tests with the deployment's actual adapters.
