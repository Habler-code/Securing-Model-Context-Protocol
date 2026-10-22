"""Shared Python request contracts for Chapter 11 and MCP revision 2026-07-28.

The book's code/validation_walkthrough.py imports this module for protocol and
metadata checks, normalization, UUID and Resource policy, and local Draft
2020-12 schema admission. The printed wrapper then checks its displayed schemas.
It is not a complete MCP server or transport implementation.
"""

from __future__ import annotations

import base64
import binascii
import copy
import json
import re
import uuid
from decimal import Decimal, InvalidOperation
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator, ValidationError
from referencing import Registry
from referencing.exceptions import NoSuchResource

try:
    from .bounded_body import MAX_REQUEST_BYTES, bound_structure, read_bounded_json
    from .errors import ValidationFault
except ImportError:
    from bounded_body import MAX_REQUEST_BYTES, bound_structure, read_bounded_json
    from errors import ValidationFault

PROTOCOL_VERSION = "2026-07-28"
VERSION_KEY = "io.modelcontextprotocol/protocolVersion"
CAPABILITIES_KEY = "io.modelcontextprotocol/clientCapabilities"
MAX_SAFE_INTEGER = 2**53 - 1
MAX_SCHEMA_BYTES = 64 * 1024
_HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z", re.IGNORECASE)
_ALLOWED_RESOURCE_ORIGINS = frozenset({"https://resources.internal.example"})

SEARCH_ARGS = {
    "type": "object", "properties": {
        "query": {"type": "string", "minLength": 1, "maxLength": 500},
        "limit": {"type": "integer", "minimum": 1, "maximum": 50},
    }, "required": ["query", "limit"], "additionalProperties": False,
}
CREATE_TICKET_ARGS = {
    "type": "object", "properties": {
        "title": {"type": "string", "minLength": 1, "maxLength": 200},
        "body": {"type": "string", "maxLength": 10_000},
        "projectId": {"type": "string"},
    }, "required": ["title", "body", "projectId"], "additionalProperties": False,
}
TOOL_OUTPUT = {
    "type": "object", "properties": {
        "tenantId": {"type": "string", "minLength": 1, "maxLength": 200},
        "text": {"type": "string", "maxLength": 8_000},
        "classification": {"enum": ["public", "internal"]},
    }, "required": ["tenantId", "text", "classification"], "additionalProperties": False,
}


def _deny_retrieval(uri: str):
    raise NoSuchResource(ref=uri)


def compile_local_schema(schema: dict[str, Any]) -> Draft202012Validator:
    """Admit a reviewed, bounded 2020-12 schema with no remote retrieval.

    This does not establish a CPU/memory deadline for arbitrary hostile schema
    execution. Use a separately constrained worker for dynamic untrusted schemas.
    """
    bound_structure(schema)
    if len(json.dumps(schema, allow_nan=False).encode("utf-8")) > MAX_SCHEMA_BYTES:
        raise ValueError("schema exceeds admission policy")
    pending: list[Any] = [schema]
    while pending:
        node = pending.pop()
        if isinstance(node, dict):
            if "$schema" in node and node["$schema"] != "https://json-schema.org/draft/2020-12/schema":
                raise ValueError("unsupported schema dialect")
            for keyword in ("$ref", "$dynamicRef"):
                if keyword in node and (not isinstance(node[keyword], str) or not node[keyword].startswith("#")):
                    raise ValueError("external schema references are disabled")
            pending.extend(node.values())
        elif isinstance(node, list):
            pending.extend(node)
    approved_copy = copy.deepcopy(schema)
    Draft202012Validator.check_schema(approved_copy)
    return Draft202012Validator(approved_copy, registry=Registry(retrieve=_deny_retrieval))


_SEARCH = compile_local_schema(SEARCH_ARGS)
_TICKET = compile_local_schema(CREATE_TICKET_ARGS)
_OUTPUT = compile_local_schema(TOOL_OUTPUT)


def _strict_object(value: Any, required: set[str], optional: set[str] | None = None) -> dict[str, Any]:
    if not isinstance(value, dict) or not required.issubset(value) or set(value) - required - (optional or set()):
        raise ValidationFault(-32602, "Invalid request parameters")
    return value


def _text(value: Any, maximum: int, *, minimum: int = 1) -> str:
    if not isinstance(value, str) or not minimum <= len(value) <= maximum:
        raise ValidationFault(-32602, "Invalid request parameters")
    return value


def _request_id(value: Any) -> None:
    if isinstance(value, str) and 1 <= len(value) <= 200:
        return
    if type(value) in (int, float) and value == int(value) and abs(value) <= MAX_SAFE_INTEGER:
        return
    raise ValidationFault(-32602, "Invalid request parameters")


def validate_context(context: Any) -> dict[str, str]:
    obj = _strict_object(context, {"userId", "tenantId"})
    # Preserve authentication-derived identifiers exactly; do not trim them.
    trusted = {"userId": _text(obj["userId"], 200), "tenantId": _text(obj["tenantId"], 200)}
    if any(not identifier.strip() for identifier in trusted.values()):
        raise ValidationFault(-32602, "Invalid request parameters")
    return trusted


def _metadata(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or VERSION_KEY not in value or CAPABILITIES_KEY not in value:
        raise ValidationFault(-32602, "Invalid request parameters")
    _text(value[VERSION_KEY], 50)
    if not isinstance(value[CAPABILITIES_KEY], dict):
        raise ValidationFault(-32602, "Invalid request parameters")
    if "io.modelcontextprotocol/clientInfo" in value:
        info = _strict_object(value["io.modelcontextprotocol/clientInfo"], {"name", "version"})
        _text(info["name"].strip() if isinstance(info["name"], str) else None, 200)
        _text(info["version"].strip() if isinstance(info["version"], str) else None, 100)
    return value


def validate_request(raw: Any, context: Any) -> dict[str, Any]:
    """Validate shape, metadata and tool semantics. Authorization remains separate."""
    bound_structure(raw)
    trusted = validate_context(context)
    # Precheck exactly the field called out by the current chapter's prose.
    try:
        version = raw["params"]["_meta"][VERSION_KEY]
    except (TypeError, KeyError):
        raise ValidationFault(-32602, "Invalid request parameters") from None
    _text(version, 50)
    if version != PROTOCOL_VERSION:
        raise ValidationFault(-32022, "Unsupported protocol version", data={
            "supported": [PROTOCOL_VERSION], "requested": version,
        })
    envelope = _strict_object(raw, {"jsonrpc", "id", "method", "params"})
    if envelope["jsonrpc"] != "2.0":
        raise ValidationFault(-32602, "Invalid request parameters")
    _request_id(envelope["id"])
    method = _text(envelope["method"], 200)
    if method not in ("tools/call", "resources/read"):
        raise ValidationFault(-32601, "Method not found", 404)
    request = copy.deepcopy(envelope)
    if method == "tools/call":
        params = _strict_object(request["params"], {"name", "arguments", "_meta"})
        _metadata(params["_meta"])
        name = params["name"]
        if name not in ("search", "create_ticket"):
            raise ValidationFault(-32602, "Invalid request parameters")
        args = copy.deepcopy(params["arguments"])
        if not isinstance(args, dict):
            raise ValidationFault(-32602, "Invalid request parameters")
        try:
            if name == "search":
                if isinstance(args.get("query"), str):
                    args["query"] = args["query"].strip()
                args.setdefault("limit", 10)
                _SEARCH.validate(args)
            else:
                if isinstance(args.get("title"), str):
                    args["title"] = args["title"].strip()
                _TICKET.validate(args)
                if not _UUID.fullmatch(args["projectId"]):
                    raise ValueError("invalid project UUID")
        except (ValidationError, ValueError):
            raise ValidationFault(-32602, "Invalid request parameters") from None
        params["arguments"] = args
    else:
        params = _strict_object(request["params"], {"uri", "_meta"})
        _metadata(params["_meta"])
        uri = _text(params["uri"], 2_048)
        try:
            parsed = urlsplit(uri)
            origin = f"{parsed.scheme}://{parsed.hostname or ''}"
            if parsed.port not in (None, 443):
                origin += f":{parsed.port}"
        except ValueError:
            raise ValidationFault(-32602, "Invalid resource URI") from None
        if parsed.username is not None or parsed.password is not None or parsed.fragment or origin not in _ALLOWED_RESOURCE_ORIGINS:
            raise ValidationFault(-32602, "Invalid resource URI")
    request["context"] = trusted
    return request


def require_client_capability(meta: Mapping[str, Any], capability: str) -> None:
    capabilities = meta.get(CAPABILITIES_KEY)
    if not isinstance(capabilities, dict) or not isinstance(capabilities.get(capability), dict):
        raise ValidationFault(-32021, "Required client capability is missing", data={"requiredCapabilities": {capability: {}}})


def authorize_ticket_project(context: Any, project_id: str, project_tenants: Mapping[str, str], may_create: bool) -> None:
    trusted = validate_context(context)
    if may_create is not True or project_tenants.get(project_id) != trusted["tenantId"]:
        raise ValidationFault(-32602, "Project is unavailable")


def encode_header_value(value: str | int | bool) -> str:
    if type(value) not in (str, int, bool) or (type(value) is int and abs(value) > MAX_SAFE_INTEGER):
        raise ValueError("invalid mirrored primitive")
    text = str(value).lower() if isinstance(value, bool) else str(value)
    sentinel = text.startswith("=?base64?") and text.endswith("?=")
    if all(c == "\t" or 32 <= ord(c) <= 126 for c in text) and text.strip() == text and not sentinel:
        return text
    return f"=?base64?{base64.b64encode(text.encode('utf-8')).decode('ascii')}?="


def decode_header_value(value: str) -> str:
    if not isinstance(value, str) or any(c != "\t" and not 32 <= ord(c) <= 126 for c in value) or value.strip() != value:
        raise ValidationFault(-32020, "Header mismatch")
    if value.startswith("=?base64?") and value.endswith("?="):
        encoded = value[9:-2]
        try:
            decoded = base64.b64decode(encoded, validate=True)
            if base64.b64encode(decoded).decode("ascii") != encoded:
                raise ValueError("noncanonical base64")
            return decoded.decode("utf-8")
        except (binascii.Error, UnicodeError, ValueError):
            raise ValidationFault(-32020, "Header mismatch") from None
    return value


def compile_mirror_policy(schema: dict[str, Any]) -> list[dict[str, Any]]:
    compile_local_schema(schema)
    rules: list[dict[str, Any]] = []
    names: set[str] = set()

    def visit(node: Any, path: list[str] | None) -> None:
        if isinstance(node, list):
            for child in node:
                visit(child, None)
        elif isinstance(node, dict):
            if "x-mcp-header" in node:
                name = node["x-mcp-header"]
                if not path or not isinstance(name, str) or not _HEADER_NAME.fullmatch(name) or name.lower() in names or node.get("type") not in ("string", "integer", "boolean"):
                    raise ValueError("invalid x-mcp-header declaration")
                names.add(name.lower())
                rules.append({"name": name, "path": path, "type": node["type"]})
            for key, child in node.items():
                if key == "properties" and isinstance(child, dict):
                    for property_name, definition in child.items():
                        visit(definition, None if path is None else [*path, property_name])
                elif isinstance(child, (dict, list)):
                    visit(child, None)

    visit(schema, [])
    return rules


def mirrored_parameters(rules: Sequence[dict[str, Any]], args: Any) -> dict[str, str | int | bool | None]:
    values: dict[str, str | int | bool | None] = {}
    for rule in rules:
        value = args
        for key in rule["path"]:
            value = value.get(key) if isinstance(value, dict) else None
        if value is not None:
            expected_type = {"string": str, "integer": int, "boolean": bool}[rule["type"]]
            if expected_type is int and type(value) in (int, float) and abs(value) <= MAX_SAFE_INTEGER and value == int(value):
                value = int(value)
            elif type(value) is not expected_type or (expected_type is int and abs(value) > MAX_SAFE_INTEGER):
                raise ValidationFault(-32602, "Invalid mirrored parameter")
        values[rule["name"]] = value  # Retain absent declarations to reject forged headers.
    return values


def validate_routing_headers(raw_headers: Sequence[tuple[str, str]], raw_request: dict[str, Any], mirrored: Mapping[str, str | int | bool | None] | None = None) -> None:
    headers: dict[str, str] = {}
    for name, value in raw_headers:
        if not isinstance(name, str) or not _HEADER_NAME.fullmatch(name) or not isinstance(value, str):
            raise ValidationFault(-32020, "Header mismatch")
        key = name.lower()
        if key in headers and (key.startswith("mcp-") or key == "content-type"):
            raise ValidationFault(-32020, "Header mismatch")
        headers[key] = value
    try:
        params = raw_request["params"]
        expected = {
            "mcp-protocol-version": params["_meta"][VERSION_KEY],
            "mcp-method": raw_request["method"],
            "mcp-name": params["name"] if raw_request["method"] == "tools/call" else params["uri"],
        }
    except (KeyError, TypeError):
        raise ValidationFault(-32602, "Invalid request parameters") from None
    for key, value in expected.items():
        actual = headers.get(key)
        if actual is None or (decode_header_value(actual) if key == "mcp-name" else actual) != value:
            raise ValidationFault(-32020, "Header mismatch")
    for name, value in (mirrored or {}).items():
        actual = headers.get(f"mcp-param-{name.lower()}")
        if value is None:
            if actual is not None:
                raise ValidationFault(-32020, "Header mismatch")
            continue
        if actual is None:
            raise ValidationFault(-32020, "Header mismatch")
        decoded = decode_header_value(actual)
        if type(value) is int:
            try:
                if abs(value) > MAX_SAFE_INTEGER or not re.fullmatch(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?", decoded) or Decimal(decoded) != value:
                    raise ValueError("integer mismatch")
            except (ValueError, InvalidOperation):
                raise ValidationFault(-32020, "Header mismatch") from None
        elif decoded != (str(value).lower() if isinstance(value, bool) else value):
            raise ValidationFault(-32020, "Header mismatch")


def validate_tool_output(raw: Any, context: Any) -> dict[str, Any]:
    trusted = validate_context(context)
    bound_structure(raw)
    try:
        _OUTPUT.validate(raw)
    except ValidationError:
        raise ValidationFault(-32602, "Output unavailable") from None
    if raw["tenantId"] != trusted["tenantId"]:
        raise ValidationFault(-32602, "Output unavailable")
    if len(json.dumps(raw, ensure_ascii=False).encode("utf-8")) > 16_384:
        raise ValidationFault(-32602, "Output exceeds policy")
    return {"resultType": "complete", "structuredContent": copy.deepcopy(raw), "trust": "untrusted-tool-data"}


def safe_error(error: Exception, request_id: Any = None) -> dict[str, Any]:
    fault = error if isinstance(error, ValidationFault) else ValidationFault(-32603, "Internal error", 500)
    body: dict[str, Any] = {"jsonrpc": "2.0"}
    if request_id is not None:
        try:
            _request_id(request_id)
        except (ValueError, TypeError, OverflowError):
            # Error formatting must remain available for malformed requests.
            # MCP 2026-07-28 permits omitted id when it could not be read.
            pass
        else:
            body["id"] = request_id
    body["error"] = {"code": fault.code, "message": str(fault), "data": {**fault.data, "correlationId": str(uuid.uuid4())}}
    return {"httpStatus": fault.http_status, "body": body}
