# Chapter 9 — Protect local startup and filesystem access

`local_config.py` assembles the current chapter's four Python segments using the same main APIs: `ServerConfig`, `load_secure_config`, `secure_read_file`, `log_server_start`, and `main`. It was checked against the latest Chapter 9 export on 22 October 2026.

From the repository's `code` directory in the documented Python virtual environment:

```sh
python chapter09/local_config.py
python -m unittest discover -s tests -p test_middle_python.py -v
```

The offline demo writes only non-secret temporary configuration, generates an in-memory fixture token, removes that token from its injected environment, reads one file inside a protected temporary jail, verifies full redaction, and rejects startup without a credential. No HTTP request or MCP listener is created.

## Relation to the chapter

| Current manuscript segment | Companion implementation |
| --- | --- |
| Segment 1: Immutable configuration | `ServerConfig` includes API URL, tenant, sandbox directory and an in-memory token excluded from `repr` |
| Segment 2: Secure startup and environment clearing | `load_secure_config` validates non-secret fields and approved HTTPS origin, canonicalizes the existing jail, and consumes `MCP_API_TOKEN` with `pop` |
| Segment 3: Canonical filesystem jail | `secure_read_file` rejects traversal, sibling-prefix confusion and symlinks resolving outside the protected root |
| Segment 4: Audit and failure handling | `log_server_start` emits only a redacted marker; `main` fails with exit status 1 |

The approved origin matches the chapter's `https://api.example.com` fixture. This is reserved example data, not a live service integration. Update protected policy and configuration together for a real service. `config.example.json` is intentionally incomplete until its sandbox path is replaced with an approved existing directory. It never contains a secret.

## Additions and trust assumptions

The companion additionally bounds configuration/file reads, rejects duplicate and unexpected configuration fields, excludes the token from dataclass representation, and supplies `child_environment()` with no credential for ordinary helper processes. The optional `environment` parameter exists for isolated tests; normal startup removes the token from actual `os.environ`. That removal prevents ordinary later inheritance but does not erase prior copies or protect the in-memory token from a compromised process.

The config file path, origin allowlist, jail and its ancestors are trusted launch/deployment policy. The jail check assumes an attacker cannot replace directory entries between validation and opening. It does **not** implement confined-open protection across every path component. Use protected mounts and OS isolation; hostile shared filesystems need suitable descriptor-based access controls. The regular-file and byte checks do not create that OS boundary.

Startup diagnostics use the Python logger, which a host should configure on stderr; stdout remains available for MCP protocol messages. Host-side startup capture, operator notification and retry limits are deployment integration requirements. `child_environment` only returns a dictionary; it does not launch a process or create a sandbox. Network URL admission does not pin DNS addresses: connection-time destination controls belong to the request adapter/network layer.

Tests cover exact field types, missing credentials, environment clearing, duplicate keys, approved origins, embedded URL credentials, full redaction, protected-jail reads, traversal, sibling-prefix and symlink denial, read limits, and visible startup failure. No secret or certificate is embedded.

Primary references: [Python dataclasses](https://docs.python.org/3/library/dataclasses.html), [Python process environment](https://docs.python.org/3/library/os.html#os.environ), and [MCP stdio transport](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio).
