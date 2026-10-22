from jsonschema import ValidationError

from chapter11.errors import ValidationFault
from chapter11.request_validation import (
    CAPABILITIES_KEY,
    MAX_SAFE_INTEGER,
    VERSION_KEY,
    compile_local_schema,
    validate_context,
    validate_request as validate_companion_request,
)

RequestId = {
    "anyOf": [
        {"type": "string", "minLength": 1, "maxLength": 200},
        {
            "type": "integer",
            "minimum": -MAX_SAFE_INTEGER,
            "maximum": MAX_SAFE_INTEGER,
        },
    ]
}

McpRequestMeta = {
    "type": "object",
    "properties": {
        VERSION_KEY: {
            "type": "string", "minLength": 1, "maxLength": 50
        },
        CAPABILITIES_KEY: {"type": "object"},
    },
    "required": [VERSION_KEY, CAPABILITIES_KEY],
    "additionalProperties": True,
}

SearchArgs = {
    "type": "object",
    "properties": {
        "query": {
            "type": "string", "minLength": 1, "maxLength": 500
        },
        "limit": {"type": "integer", "minimum": 1, "maximum": 50},
    },
    "required": ["query", "limit"],
    "additionalProperties": False,
}

CreateTicketArgs = {
    "type": "object",
    "properties": {
        "title": {
            "type": "string", "minLength": 1, "maxLength": 200
        },
        "body": {"type": "string", "maxLength": 10_000},
        "projectId": {"type": "string"},
    },
    "required": ["title", "body", "projectId"],
    "additionalProperties": False,
}

ToolName = ["search", "create_ticket"]

ToolCallRequest = {
    "type": "object",
    "properties": {
        "jsonrpc": {"const": "2.0"},
        "id": RequestId,
        "method": {"const": "tools/call"},
        "params": {
            "type": "object",
            "properties": {
                "name": {"enum": ToolName},
                "arguments": {},
                "_meta": McpRequestMeta,
            },
            "required": ["name", "arguments", "_meta"],
            "additionalProperties": False,
        },
    },
    "required": ["jsonrpc", "id", "method", "params"],
    "additionalProperties": False,
}

ResourceReadRequest = {
    "type": "object",
    "properties": {
        "jsonrpc": {"const": "2.0"},
        "id": RequestId,
        "method": {"const": "resources/read"},
        "params": {
            "type": "object",
            "properties": {
                "uri": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 2_048,
                },
                "_meta": McpRequestMeta,
            },
            "required": ["uri", "_meta"],
            "additionalProperties": False,
        },
    },
    "required": ["jsonrpc", "id", "method", "params"],
    "additionalProperties": False,
}

SupportedRequest = compile_local_schema(
    {"oneOf": [ToolCallRequest, ResourceReadRequest]}
)

def bind_trusted_context(context: dict[str, str]) -> dict[str, str]:
    # The caller supplies verified authentication context.
    # Reject blank IDs; preserve each nonblank ID exactly.
    return validate_context(context)

ToolArguments = {
    "search": compile_local_schema(SearchArgs),
    "create_ticket": compile_local_schema(CreateTicketArgs),
}

def validate_request(raw, context):
    trusted = bind_trusted_context(context)
    try:
        # Classify the revision before generic schema errors.
        # Check metadata and URI policy; normalize Tool arguments.
        request = validate_companion_request(raw, trusted)

        # Check the displayed contracts on the normalized request.
        message = {
            key: value
            for key, value in request.items()
            if key != "context"
        }
        SupportedRequest.validate(message)
        if request["method"] == "tools/call":
            schema = ToolArguments[request["params"]["name"]]
            schema.validate(request["params"]["arguments"])
        return request
    except ValidationFault:
        raise
    except ValidationError:
        raise ValidationFault(
            -32602, "Invalid request parameters"
        ) from None
