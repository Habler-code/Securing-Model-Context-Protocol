# Chapter 7 — Tool poisoning

`tool_poisoning.py` implements the current chapter's input-schema pinning and closed JSON output contract, plus optional complete-definition and follow-up policy checks. It was compared with the latest Chapter 7 export on 22 October 2026. Install the root's pinned Python requirements, including `jsonschema`, in the example virtual environment first.

From the repository's `code` directory:

```sh
python3 chapter07/tool_poisoning.py
python3 -m unittest discover -s tests -p test_middle_python.py -v
```

The demo accepts an approved definition, blocks a changed description, labels instruction-like output as untrusted data, and denies an unauthorized follow-up. It makes no network calls and launches no tool.

## Relation to the chapter

| Manuscript section | Companion implementation |
| --- | --- |
| Part 1: Input-schema pinning | `APPROVED_TOOL_SCHEMAS`, `ALLOWED_TOOL_SCHEMA_SHA256`, `sha256_json`, and the two-argument `verify_tool_schema` match the current chapter |
| Namespace and Tool Name Conflicts | `qualified_tool_name` binds a tool to a host-trusted server identity |
| Part 2: Strict output validation | `validate_and_prepare_output` accepts encoded JSON up to 20,000 bytes, requires closed `status`/`data`, bounds data at 5,000 characters, and adds the generic untrusted provenance label |
| Advanced Tool Poisoning Attacks via Tool Outputs | Typed output is kept as data and cannot grant another tool permission |

## Trust assumptions and limits

The server identity comes from the Host's approved connection configuration. A self-reported tool name or server label is not an authenticated identity. Authenticated scopes are supplied by a separate authorization layer. Tenant ownership is established before dispatch; an output's tenant label alone does not prove ownership.

The default two-argument `verify_tool_schema` pins only an input schema, exactly as in the current chapter. `ToolPolicy` and the optional third policy argument add a **separate companion** complete-definition check, including descriptions and the name. `authorize_tool_call` and the typed tenant-bound `validate_tool_output` are additional independent policy examples. Dot-qualified names are host routing aliases; the Server receives its underlying Tool name.

The approved input schemas and demo definitions are **fixed source-code fixtures**, not values retrieved from a server. In a deployment, publish reviewed pins through an independently controlled manifest. Never compute an approval from the current untrusted server response. A hash proves equality with that manifest, not who created it or whether its behavior is safe. The stable JSON serialization is specific to this example and is not an implementation of RFC 8785.

`validate_and_prepare_output` removes nonprintable characters except newline and tab; printable instructions remain untrusted. The extra legacy `sanitize_tool_output` helper is labeled a **heuristic**, with a regression test demonstrating a paraphrase bypass. It is not part of the current chapter's closed-schema implementation and passing it is never an execution permit. Production hosts must keep output outside privileged instructions and authorize every follow-up independently.

Tests cover approved/changed definitions, server shadowing, scope denial, unexpected fields, output byte limits, cross-tenant labels, and instructions that cannot grant authority.

Security review: no credentials or certificates are embedded; SHA-256 is used only for definition integrity. The example does not implement TLS, transport authentication, signing infrastructure, or a complete MCP server.
