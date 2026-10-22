# Validation scope

The companion was reconciled with the chapter manuscripts on 22 October 2026.
Chapter READMEs map
the displayed APIs to complete modules and identify deliberate adaptations.
The repository contains examples, not manuscript files or reviewer discussions.

## Reproduce the checks

From `code/`, in the isolated environment described in the README:

```sh
python -m pip install -r requirements.lock
python -m pip check
python -m compileall -q chapter02 chapter03 chapter04 chapter05 chapter06 chapter07 chapter08 chapter09 chapter10 chapter11 chapter12 chapter13 chapter14 chapter15 chapter16 chapter17 chapter18 chapter19 chapter20 tests
python -m unittest discover -s tests -v
```

The full suite includes each runnable chapter demo. Tests construct local
fixtures, generate temporary cryptographic keys and opaque approval tokens,
and use deterministic clocks where time boundaries matter. No production
credential or private key is committed. Fixed strings explicitly identified as
fixture artifacts are not valid production approval credentials.

## What the tests exercise

- Exact issuer/audience/scope and tenant policy, real synthetic JWT signatures,
  PKCE/state helpers, membership binding and immutable dispatch arguments.
- Schema pinning, closed output contracts, byte/type/depth limits, protocol
  error mappings, header/body equality and prohibited external references.
- Process operation/path allowlists, minimal child environments, output/time
  budgets, configuration redaction, approved URLs and bounded HTTP fixtures.
- Secret expiry/failure, tenant/cache partitioning and parameterized database
  adapter calls.
- Role/assurance separation, complete defense layers, signed artifact/SBOM
  tampering, bounded metrics, governance quorum and evidence freshness.
- Complete approval-context binding, expiry/not-yet-valid grants, exact
  immutable role/tool sets, replay, token collisions, emergency quorum and
  concurrent one-time redemption.

## What remains integration work

No live identity provider, JWKS rotation service, OAuth browser session,
PostgreSQL instance, secret manager, MCP deployment, gateway, service mesh,
container sandbox, SIEM, or external policy engine was provisioned by this
suite. The chapter guides describe the adapters and prerequisites needed for
each deployment.

Network fixtures test application policy; they do not prove DNS rebinding
protection, end-to-end TLS deployment, revocation behavior, or a wall-clock
deadline against slow network peers. The PostgreSQL fixture needs real RLS and
connection-pool tests under a non-owner application role. Human approval and
governance need shared-store, audit-delivery and side-effect tests before use
across replicas. The process example is POSIX-specific and is not an OS sandbox.

Passing these checks provides reproducible evidence for the tested behaviors,
not a guarantee of vulnerability freedom, complete MCP conformance or regulatory
compliance. Review the relevant primary documentation linked in the chapter
guides when changing protocol revisions, providers, libraries or runtime policy.
