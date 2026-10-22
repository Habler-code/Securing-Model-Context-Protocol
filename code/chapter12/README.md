# Chapter 12 — Remote MCP architecture

`tool_index.py` collects the chapter's bounded-body reader and authoritative
custom tool-index example. The tool index is an application pattern for
progressive disclosure; it does not replace standard MCP tool discovery or
authorize execution merely because a definition was disclosed.

The code was compared with the chapter manuscript on 22 October 2026.
It preserves `MAX_BODY_BYTES`, `read_bounded_body`, `ToolDefinition`, and all
`ToolIndex` methods. The runnable file joins the chapter's split class excerpts
and adds input checks and an offline demonstration. Its digest remains the
chapter's local schema fingerprint; it is not a signature or JCS implementation.

Run from `code/` with Python 3.11 or later:

```bash
python chapter12/tool_index.py
python -m unittest discover -s tests -p test_late_regressions.py -v
```

The demo prints an unauthorized-disclosure denial followed by a successful
bounded-read and index check. It does not open a network listener.

The reader accepts already-decoded byte chunks, rejects data beyond the exact
byte limit, and returns bytes for subsequent parsing. HTTP deadlines,
decompression limits, cancellation, connection limits, TLS, and authentication
belong in the real transport implementation. The reader alone cannot prevent a
slow client from holding a connection open.

`ToolIndex` snapshots the registry and returns defensive copies. Its
`can_disclose` callback receives a principal established by trusted
authentication middleware. A model-provided principal or allow-all callback
does not establish an authorization boundary. Recheck current permission when
the tool executes, including tenant and object scope.

Tests cover exact limits, overflow, invalid limits/chunks, unauthorized
disclosure, and mutation of the caller's original registry or returned schema.
Gateway behavior and real transport failures require deployment integration
tests beyond this offline example.
