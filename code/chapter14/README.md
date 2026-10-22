# Chapter 14 — Multi-tenancy and data isolation

`tenant_isolation.py` covers claim normalization, tenant-bound context and
handles, scoped secret paths, private cache partitioning, parameterized database
access, and minimal audit events. All default demonstrations are offline.

The code was compared with the chapter manuscript on 22 October 2026.
The identity/context/secret/handle/cache/database/audit API names match the
chapter. The file assembles its separate listings into complete Python blocks.
`private_cache_key` is an additional working
example of the caller-and-authorization partition described in the prose.

Run from `code/` with Python 3.11 or later:

```bash
python chapter14/tenant_isolation.py
python -m unittest discover -s tests -p test_late_regressions.py -v
```

Expected final line: `Tenant-isolation checks passed without exposing tenant
data or secrets.`

`extract_tenant_identity` accepts claims only after a real validator has checked
signature, trusted issuer, audience, lifetime, and provider policy. Dataclasses
and synthetic dictionaries do not validate tokens. `allowed_actions` for a
handle comes from server policy, not caller input.

`tenant_cache_key` partitions by tenant plus a supplied logical key. For
personalized responses, use `private_cache_key`, which also includes user,
role, server, method, parameters, and an authorization-context version/reference.
Obtain the HMAC key from an approved secret manager, rotate it under policy, and
invalidate entries after permission changes. A cache hit still needs current
authorization and provenance checks on the cached value.

`fetch_document` uses the psycopg 3-style `transaction`, `execute`, and `fetchone`
interfaces. It binds values separately and sets tenant state for that transaction
only. `tenant_documents.sql` supplies the matching PostgreSQL table and RLS
policy for a disposable integration database. Create a separate non-owner
application role with only necessary table privileges and without superuser or
`BYPASSRLS`; do not run application queries as the schema owner.

The offline adapter test verifies transaction use and parameter binding, not
PostgreSQL enforcement. Before deployment, run two-tenant read/write tests
against the real database, including a missing tenant setting, pooled connection
reuse, cross-tenant identifiers, and the actual application role.

`audit_tool_decision` sends fields to the application's logger. Configure a
structured formatter and protected collector; the function alone does not
establish durable delivery, retention, or tenant-safe analyst access.
