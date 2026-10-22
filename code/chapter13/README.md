# Chapter 13 — Secrets management

`secret_cache.py` implements the chapter's rotation-aware, fail-closed cache.
`SecretProvider` is the adapter boundary; `DemoProvider` creates ephemeral
synthetic values and never contacts a secret manager.

The companion was compared with the chapter manuscript on
22 October 2026. Both source API styles are available:

| Chapter listing | Companion API |
| --- | --- |
| String-returning provider | `PlaintextSecretProvider` and `MockVaultProvider` |
| `ThreadSafeSecretCache.read` | Returns a string; `clear_memory(name)` or `clear_memory()` drops cached references |
| Version-aware provider integration | `SecretProvider`, `ProviderSecret`, and `SecretCache` |
| `CachedSecret.value` in the smaller listing | The rich internal record stores `ProviderSecret` plus local expiry |
| Single-argument placeholder database function | `execute_database_query(query, cache, query_runner)` explicitly injects credential and query adapters |

`MockVaultProvider` returns one synthetic value per instance, generated at
runtime. It performs no vault authentication or rotation. The string interface
reports its version as unavailable rather than inventing provider metadata.
Example use after importing this module:

```python
cache = ThreadSafeSecretCache(MockVaultProvider(), ttl_seconds=30)
credential = cache.read("postgres_agent_role")  # Do not print or return it.
cache.clear_memory("postgres_agent_role")
cache.clear_memory()
```

Run from `code/` with Python 3.11 or later:

```bash
python chapter13/secret_cache.py
python -m unittest discover -s tests -p test_late_regressions.py -v
```

Expected final line: `Secret cache demonstration completed without printing
secret values.`

`read` reuses a value until its TTL expires. `invalidate` drops one reference;
`refresh` invalidates and retrieves again. Reads prune expired entries, and a
configurable capacity (128 entries by default) evicts the least recently used
entry when full. The TTL maximum is a teaching policy, not a guarantee that a
provider credential remains valid for that long. Set it below the provider's
lease/rotation policy and invalidate promptly on revocation or authentication
failure.

A provider error never causes an expired credential to be returned. Logs
contain the validated identifier and exception type, not provider exception
text or secret values. `ProviderSecret` hides its value from the default
representation; this is accidental-disclosure protection, not encryption or
secure memory erasure.

Production adapters must authenticate with workload identity, enforce path
authorization, use bounded SDK timeouts, retrieve current versions, and send
audit events through a protected pipeline. The single process lock does not
coordinate different server instances. Python strings may remain in memory
after invalidation; no zeroization claim is made.

`execute_database_query` shows credential acquisition around an injected query
adapter. It does not validate SQL or make arbitrary SQL safe. The real adapter
must choose fixed statements and bind parameters; the cache is not an injection
defense.

Tests exercise cache hits/expiry, refresh, invalid identifiers/TTL, capacity,
provider failure, and suppression of secret material in logs and representations.
