# Chapter 11 — Validate each request boundary in Python

Chapter 11 now presents Python listings. The three printed body stages are assembled exactly in [`../bounded_body_walkthrough.py`](../bounded_body_walkthrough.py); the printed request schemas, context admission and validation wrapper are assembled in [`../validation_walkthrough.py`](../validation_walkthrough.py). They reuse the shared `chapter11` helpers for the selected MCP methods, JSON field names, protocol revision and business limits.

Use Python 3.12 or later with the pinned requirements installed from `requirements.lock`. From the repository's `code` directory:

```sh
python bounded_body_walkthrough.py
python validation_walkthrough.py
python chapter11/demo.py
python -m unittest discover -s tests -p test_chapter11_walkthroughs.py -v
python -m unittest discover -s tests -p test_middle_python.py -v
```

The two printed exercise modules define functions and compile the selected schemas; running them checks their imports and schema setup without producing demonstration output. The separate `chapter11/demo.py` performs a visible offline walkthrough: bounded bytes, strict JSON, metadata, routing headers, selected Tool arguments, trusted identity and a rejected cross-tenant project. It starts no HTTP/MCP server and dispatches no real Tool.

## Printed listings and shared implementation

| Printed chapter example | Companion file or helper |
| --- | --- |
| Three stages of `read_bounded_json` | `code/bounded_body_walkthrough.py`, importing shared guards and `MAX_REQUEST_BYTES = 1_048_576` from `chapter11/bounded_body.py` |
| `validate_request`, request/method/Tool schemas | `code/validation_walkthrough.py`, using `chapter11/request_validation.py` for the canonical pipeline and reviewed Draft 2020-12 validator |
| `search` | Query trimmed to 1–500 characters, integer limit 1–50, default 10 |
| `create_ticket` | Trimmed title 1–200, body at most 10,000, UUID `projectId` |
| `resources/read` | At most 2,048-character URI and exact approved Resource origin |
| HTTP routing and mirrors described in prose | `validate_routing_headers`, `compile_mirror_policy`, `mirrored_parameters`, `encode_header_value`, `decode_header_value` |
| Trusted-context / ownership / authorization distinction | `validate_context` and separate `authorize_ticket_project` |
| Output and safe-error sections | `validate_tool_output` and `safe_error` |

The root exercise files are the exact assembled printed snippets. `chapter11/bounded_body.py` also provides a canonical complete reader so tests can compare the book assembly with shared behavior. `chapter11/request_validation.py` performs protocol classification, metadata checks, argument normalization, explicit UUID validation and exact Resource-origin policy before the printed wrapper checks its displayed schemas. Shared local errors are in `chapter11/errors.py`. Python helpers use snake_case; wire fields such as `projectId`, `tenantId`, `resultType` and namespaced metadata retain their exact protocol spelling.

## Protocol and schema behavior

The pipeline targets **MCP 2026-07-28**. Before full method validation, a missing/non-string protocol version receives `-32602`, while a present unsupported version receives `-32022` with `supported` and `requested`. Required Client capabilities use `-32021` with `requiredCapabilities`; they describe compatibility and never grant authorization. Verified user and tenant identifiers are preserved unchanged, independently of model arguments.

`safe_error` follows this revision's [MCP error-response profile](https://modelcontextprotocol.io/specification/2026-07-28/basic): it echoes a valid known request ID and omits the field when the ID is unknown or malformed. Formatting an error cannot fail simply because an attacker supplied a Boolean, list, invalid number or another malformed identifier. The generic JSON-RPC 2.0 unknown-ID convention differs; transport integration must use the declared MCP revision's schema.

Raw header pairs preserve duplicates that a normalized framework header object may hide. Header names are case-insensitive; body strings are preserved exactly. The Base64 sentinel rules handle whitespace, Unicode and sentinel-like literal strings. Boolean mirrors use lowercase text; safe integers compare numerically. Missing/null arguments omit the header, and a forged recognized header without a body value is rejected. Compare against **original parsed arguments**, before business defaults or trimming. Do not mirror credentials, personal identifiers or free-form content into headers.

`compile_local_schema` uses `jsonschema.Draft202012Validator`. Static contracts are checked once and reused. The admission wrapper bounds bytes/depth/nodes, rejects unsupported dialects and external `$ref`/`$dynamicRef`, and uses a registry that cannot retrieve from the network. It is not a CPU/memory deadline for arbitrary hostile schema execution. Dynamic schemas still require review, safe recursion/regex policy and validation in a separately constrained worker with a parent termination deadline; same-thread timers cannot interrupt synchronous validation.

## Companion additions and deployment requirements

The printed body walkthrough counts contiguous buffers by their actual byte size before copying, skips empty chunks, owns mutable buffers, and reuses duplicate-member/non-JSON-number rejection and the structure cap. Multi-byte memoryviews are bounded by bytes rather than element count; non-contiguous views are rejected. `max_bytes` can lower but cannot raise the fixed 1 MiB ceiling. The printed request wrapper reuses the canonical pipeline, including blank-identity rejection with exact preservation of nonblank identifiers, protocol classification, defaults, trimming, UUID checks and Resource-origin policy. Additional shared helpers implement routing-header comparison, project ownership and the selected output contract; the small printed schemas alone do not provide those integrations.

The selected output contract has a tenant label, text and classification; unknown fields or cross-tenant values are blocked. Text may still contain hostile instructions and remains `untrusted-tool-data`. The returned object is an internal teaching record, not a complete MCP Tool response. An actual adapter should use exact official SDK types and authenticated connection provenance. No filter claims to remove every prompt injection or detect every secret.

HTTP byte/read deadlines, cancellation, concurrency/rate budgets, authentication middleware, every supported adapter, per-resource authorization, distributed quotas, MRTR/subscriptions and full Tool dispatch require deployment integration. A bounded parser alone cannot stop a slow peer or prove identity provenance. No raw request or exception detail is logged; unexpected errors become a stable internal error with a random correlation ID.

Tests cover bounded/reused/chunked bodies, empty chunks, multi-byte and strided memoryviews, invalid UTF-8/JSON, duplicate members, nesting/byte limits, wrong methods/tools/fields/types, missing or whitespace-only trusted identity, version/error mapping, header duplicates and sentinel encoding, mirrors and optional arguments, real 2020-12 validation, prohibited external references, Resource origins, project ownership and untrusted output. No live service or certificate is needed.

`test_chapter11_walkthroughs.py` compares 13 body fixtures and 25 request fixtures with the canonical helpers, checks the exact reviewed book-source fingerprints, and imports both printed modules from an unrelated working directory. Accepted normalized values and stable error categories must remain aligned. If a printed snippet changes, update the book assembly and revalidate its source fingerprint and behavior together.

Verified primary references: [MCP base protocol](https://modelcontextprotocol.io/specification/2026-07-28/basic), [Streamable HTTP](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http), [MCP error schema](https://modelcontextprotocol.io/specification/2026-07-28/schema), and [jsonschema validation](https://python-jsonschema.readthedocs.io/en/stable/validate/).
