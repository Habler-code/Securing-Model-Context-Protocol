"""Offline Python walkthrough of Chapter 11's selected validation contracts."""

import asyncio
import json

try:
    from .bounded_body import read_bounded_json
    from .request_validation import PROTOCOL_VERSION, authorize_ticket_project, validate_request, validate_routing_headers
except ImportError:
    from bounded_body import read_bounded_json
    from request_validation import PROTOCOL_VERSION, authorize_ticket_project, validate_request, validate_routing_headers


async def demo() -> None:
    request = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
        "name": "search", "arguments": {"query": "approved records"}, "_meta": {
            "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
            "io.modelcontextprotocol/clientCapabilities": {},
        },
    }}

    async def chunks():
        yield json.dumps(request).encode("utf-8")

    raw = await read_bounded_json(chunks())
    context = {"userId": "demo-user", "tenantId": "demo-tenant"}
    validate_routing_headers([
        ("MCP-Protocol-Version", PROTOCOL_VERSION), ("Mcp-Method", "tools/call"), ("Mcp-Name", "search"),
    ], raw)
    validated = validate_request(raw, context)
    assert validated["context"] == context
    try:
        authorize_ticket_project(context, "project", {"project": "other-tenant"}, True)
    except ValueError:
        print("Cross-tenant project blocked before dispatch.")
    print("Bounded request, metadata, routing and tool arguments accepted offline.")


if __name__ == "__main__":
    asyncio.run(demo())
