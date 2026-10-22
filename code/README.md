# Python companion examples

These examples accompany *Securing Model Context Protocol*. They assemble the
book's split listings into runnable teaching modules, with offline fixtures,
negative tests, and explicit integration boundaries. Chapter 1 is conceptual;
Chapters 2–20 have executable Python demonstrations.

The examples were compared with the current chapter files on 22 October 2026.
Each chapter README identifies the corresponding APIs and explains corrections,
additional safeguards, and intentional differences. In particular, Chapter 11
now presents Python listings assembled in
[`bounded_body_walkthrough.py`](bounded_body_walkthrough.py) and
[`validation_walkthrough.py`](validation_walkthrough.py). These printed
exercises reuse the shared `chapter11` guards and request validator. The folder
descriptions below describe the examples; they do not rename the book's chapter
titles.

## Set up

Use Python 3.12 or later. The baseline validation environment is Python 3.12.
Chapter 8's process-boundary implementation requires macOS or Linux and a
protected, root-owned `/usr/bin/git`; it is not a Windows implementation.

From this `code` directory:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.lock
python -m pip check
```

On Windows, activate the environment with `.venv\Scripts\Activate.ps1` in
PowerShell. The portable examples can run there, but the POSIX-specific Chapter
8 demo is not supported.

`requirements.txt` lists the three direct dependencies: PyJWT, cryptography,
and jsonschema. `requirements.lock` also pins their transitive dependencies.
The lock contains exact versions, not artifact hashes; install only from a
trusted package index and review dependency updates. No Node.js tooling is
required by this companion.

## Run and test

```sh
python chapter04/token_authorization.py
python chapter11/demo.py
python -m unittest discover -s tests -p test_chapter11_walkthroughs.py -v
python chapter20/hitl_controls.py
python -m unittest discover -s tests -v
```

The suite includes subprocess smoke tests for all runnable chapter demos, plus
printed Chapter 11 exercise parity checks and positive, negative, tampering,
expiry, and concurrency checks. Demos use synthetic
identifiers and ephemeral values, contact no external services, and never
execute a real administrative Tool. Chapter 8 runs fixed local Git operations;
Chapter 9 uses a temporary directory. No cloud account, API credential, model,
MCP listener, database, or container runtime is needed for the offline suite.

## Find an example

| Chapter | Example focus | Entry point and detailed guide |
| --- | --- | --- |
| 1 | Trust boundaries and architecture; conceptual only | [Guide](chapter01/README.md) |
| 2 | Policy-first Tool gate | [policy_gate.py](chapter02/policy_gate.py) · [Guide](chapter02/README.md) |
| 3 | PKCE, callback state, issuer and token-exchange helpers | [oauth_pkce.py](chapter03/oauth_pkce.py) · [Guide](chapter03/README.md) |
| 4 | JWT validation, tenant/resource policy and Tool scopes | [token_authorization.py](chapter04/token_authorization.py) · [Guide](chapter04/README.md) |
| 5 | Verified identity-provider claim and membership mapping | [principal_mapping.py](chapter05/principal_mapping.py) · [Guide](chapter05/README.md) |
| 6 | Untrusted context and Host-owned policy | [untrusted_content.py](chapter06/untrusted_content.py) · [Guide](chapter06/README.md) |
| 7 | Schema pinning, Tool poisoning and untrusted output | [tool_poisoning.py](chapter07/tool_poisoning.py) · [Guide](chapter07/README.md) |
| 8 | Bounded, no-shell process execution | [safe_process.py](chapter08/safe_process.py) · [Guide](chapter08/README.md) |
| 9 | Local configuration, credential inheritance and filesystem jail | [local_config.py](chapter09/local_config.py) · [Guide](chapter09/README.md) |
| 10 | Application egress policy | [egress_firewall.py](chapter10/egress_firewall.py) · [Guide](chapter10/README.md) |
| 11 | Printed Python walkthroughs, bounded input, protocol/header contracts and output validation | [bounded_body_walkthrough.py](bounded_body_walkthrough.py) · [validation_walkthrough.py](validation_walkthrough.py) · [demo.py](chapter11/demo.py) · [Guide](chapter11/README.md) |
| 12 | Bounded bodies and an authoritative custom Tool index | [tool_index.py](chapter12/tool_index.py) · [Guide](chapter12/README.md) |
| 13 | Rotation-aware, fail-closed secret caching | [secret_cache.py](chapter13/secret_cache.py) · [Guide](chapter13/README.md) |
| 14 | Tenant-scoped data, handles, caches and database adapters | [tenant_isolation.py](chapter14/tenant_isolation.py) · [Guide](chapter14/README.md) |
| 15 | Roles, scopes, assurance and approval enforcement | [permission_models.py](chapter15/permission_models.py) · [Guide](chapter15/README.md) |
| 16 | Identity, workload calls, defense layers and contextual policy | [security_design_patterns.py](chapter16/security_design_patterns.py) · [Guide](chapter16/README.md) |
| 17 | Signed releases, SBOM binding and supply-chain gates | [supply_chain_security.py](chapter17/supply_chain_security.py) · [Guide](chapter17/README.md) |
| 18 | Audit records, bounded metrics and incident plans | [monitoring_observability.py](chapter18/monitoring_observability.py) · [Guide](chapter18/README.md) |
| 19 | Exact-artifact governance, review quorum and evidence currency | [governance_compliance.py](chapter19/governance_compliance.py) · [Guide](chapter19/README.md) |
| 20 | Bound, one-time human approval and emergency access | [hitl_controls.py](chapter20/hitl_controls.py) · [Guide](chapter20/README.md) |

## Understand the boundary

These are educational implementations, not production MCP services or a claim
of complete protocol coverage. Identity markers and fixture claims are not
authentication. A schema or hash match is not authorization. An in-memory lock
does not coordinate different replicas or make a remote business operation
atomic.

Before deployment, supply validated identity, tenant/resource authorization,
reviewed Tool schemas, connection-time egress controls, real deadlines, shared
transactional storage, resource-version preconditions, revocation, and protected
audit delivery as required by the chapter. Run the invariants against those
actual integrations. The Chapter 14 SQL fixture and Chapter 10 Compose baseline
are supporting material, not verified live deployments. Incident-response and
compliance helpers return decisions or plans; they do not perform incident
actions or establish legal compliance.

See [VALIDATION.md](VALIDATION.md) for the verification scope and limitations.
