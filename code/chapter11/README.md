# Chapter 11 — Validate each request boundary in Python

This Python companion translates the chapter's TypeScript/Zod snippets. It preserves the selected MCP methods, JSON field names, protocol revision and business limits. The chapter and this companion present the same contracts in different languages.

From the repository's `code` directory with its pinned Python requirements installed:

```sh
python chapter11/demo.py
python -m unittest discover -s tests -p test_middle_python.py -v
```

The demo performs an offline walkthrough: bounded bytes, strict JSON, metadata, routing headers, selected Tool arguments, trusted identity and a rejected cross-tenant project. It starts no HTTP/MCP server and dispatches no real Tool.

## Book-to-Python mapping

| Current manuscript example | Python companion |
| --- | --- |
| Three stages of `readBoundedJson` | `bounded_body.py`: async `read_bounded_json` and `MAX_REQUEST_BYTES = 1_048_576` |
| `validateRequest`, request/method/Tool schemas | `request_validation.py`: `validate_request` and reviewed Draft 2020-12 schemas |
| `search` | Query trimmed to 1–500 characters, integer limit 1–50, default 10 |
| `create_ticket` | Trimmed title 1–200, body at most 10,000, UUID `projectId` |
| `resources/read` | At most 2,048-character URI and exact approved Resource origin |
| HTTP routing and mirrors described in prose | `validate_routing_headers`, `compile_mirror_policy`, `mirrored_parameters`, `encode_header_value`, `decode_header_value` |
| Trusted-context / ownership / authorization distinction | `validate_context` and separate `authorize_ticket_project` |
| Output and safe-error sections | `validate_tool_output` and `safe_error` |

The book's `Chapter11/request-validation.ts` module corresponds to `code/chapter11/request_validation.py`; the three bounded-body stages are assembled in `code/chapter11/bounded_body.py`. Shared local errors are in `errors.py`. Python helpers use snake_case; wire fields such as `projectId`, `tenantId`, `resultType` and namespaced metadata retain their exact protocol spelling.

## Protocol and schema behavior

The pipeline targets **MCP 2026-07-28**. Before full method validation, a missing/non-string protocol version receives `-32602`, while a present unsupported version receives `-32022` with `supported` and `requested`. Required Client capabilities use `-32021` with `requiredCapabilities`; they describe compatibility and never grant authorization. Verified user and tenant identifiers are preserved unchanged, independently of model arguments.

`safe_error` follows this revision's [MCP error-response profile](https://modelcontextprotocol.io/specification/2026-07-28/basic): it echoes a valid known request ID and omits the field when the ID is unknown or malformed. Formatting an error cannot fail simply because an attacker supplied a Boolean, list, invalid number or another malformed identifier. The generic JSON-RPC 2.0 unknown-ID convention differs; transport integration must use the declared MCP revision's schema.

Raw header pairs preserve duplicates that a normalized framework header object may hide. Header names are case-insensitive; body strings are preserved exactly. The Base64 sentinel rules handle whitespace, Unicode and sentinel-like literal strings. Boolean mirrors use lowercase text; safe integers compare numerically. Missing/null arguments omit the header, and a forged recognized header without a body value is rejected. Compare against **original parsed arguments**, before business defaults or trimming. Do not mirror credentials, personal identifiers or free-form content into headers.

`compile_local_schema` uses `jsonschema.Draft202012Validator`. Static contracts are checked once and reused. The admission wrapper bounds bytes/depth/nodes, rejects unsupported dialects and external `$ref`/`$dynamicRef`, and uses a registry that cannot retrieve from the network. It is not a CPU/memory deadline for arbitrary hostile schema execution. Dynamic schemas still require review, safe recursion/regex policy and validation in a separately constrained worker with a parent termination deadline; same-thread timers cannot interrupt synchronous validation.

## Companion additions and deployment requirements

Extra runnable guards include rejecting blank-after-whitespace identity values while preserving exact nonblank identifiers, inspecting a contiguous buffer's actual byte count before copying it, skipping empty chunks, copied mutable buffers, duplicate-member/non-JSON-number rejection, a depth/node cap, a 200-character request-ID cap, explicit response categories, routing helpers, a fixture project-ownership gate and a closed output contract. Multi-byte memoryviews are bounded by bytes rather than element count; non-contiguous views are rejected. `max_bytes` can lower but cannot raise the fixed 1 MiB ceiling. These are documented companion additions, not claims that all code appears in the book's displayed snippets.

The selected output contract has a tenant label, text and classification; unknown fields or cross-tenant values are blocked. Text may still contain hostile instructions and remains `untrusted-tool-data`. The returned object is an internal teaching record, not a complete MCP Tool response. An actual adapter should use exact official SDK types and authenticated connection provenance. No filter claims to remove every prompt injection or detect every secret.

HTTP byte/read deadlines, cancellation, concurrency/rate budgets, authentication middleware, every supported adapter, per-resource authorization, distributed quotas, MRTR/subscriptions and full Tool dispatch require deployment integration. A bounded parser alone cannot stop a slow peer or prove identity provenance. No raw request or exception detail is logged; unexpected errors become a stable internal error with a random correlation ID.

Tests cover bounded/reused/chunked bodies, empty chunks, multi-byte and strided memoryviews, invalid UTF-8/JSON, duplicate members, nesting/byte limits, wrong methods/tools/fields/types, missing or whitespace-only trusted identity, version/error mapping, header duplicates and sentinel encoding, mirrors and optional arguments, real 2020-12 validation, prohibited external references, Resource origins, project ownership and untrusted output. No live service or certificate is needed.

Verified primary references: [MCP base protocol](https://modelcontextprotocol.io/specification/2026-07-28/basic), [Streamable HTTP](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http), [MCP error schema](https://modelcontextprotocol.io/specification/2026-07-28/schema), and [jsonschema validation](https://python-jsonschema.readthedocs.io/en/stable/validate/).
