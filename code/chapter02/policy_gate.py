"""Chapter 2: a Python policy-first Host gate with explicit trusted identity.

The result is a policy decision, not an MCP invocation. The Host supplies the
verified user/tenant and must make this gate mandatory before transport dispatch.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import logging
from typing import Any, Literal


logger = logging.getLogger(__name__)
TOOL_RISK: dict[str, Literal["low", "medium", "high"]] = {
    "read_resource": "low", "search": "low", "create_ticket": "medium", "admin_export": "high",
}


@dataclass(frozen=True)
class ToolCall:
    tool: str
    args: dict[str, Any]
    tenant_id: str
    user_id: str
    request_id: str


class PolicyError(Exception):
    pass


def _identifier(value: object) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 200:
        raise PolicyError("missing or invalid identity context")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise PolicyError("missing or invalid identity context")
    return value


def _validate_args(tool: str, args: dict[str, Any]) -> dict[str, Any]:
    # These are explicit companion fixture contracts, not production Tool schemas.
    keys = {
        "read_resource": {"tenantId", "resourceId"},
        "search": {"tenantId", "query"},
        "create_ticket": {"tenantId", "title", "body"},
        "admin_export": {"tenantId", "format"},
    }.get(tool)
    if keys is None or set(args) != keys:
        raise PolicyError("invalid Tool argument shape")
    for key, value in args.items():
        maximum = 10_000 if key == "body" else 500 if key == "query" else 200
        if not isinstance(value, str) or not value.strip() or len(value) > maximum:
            raise PolicyError("invalid Tool argument type or size")
    if tool == "admin_export" and args["format"] not in {"csv", "json"}:
        raise PolicyError("invalid export format")
    return args


def handle_tool_call(call: ToolCall) -> dict[str, Any]:
    try:
        if not isinstance(call, ToolCall) or not isinstance(call.args, dict):
            raise PolicyError("invalid Tool request")
        _identifier(call.user_id)
        _identifier(call.tenant_id)
        _identifier(call.request_id)
        requested_tenant = call.args.get("tenantId")
        if not isinstance(requested_tenant, str) or requested_tenant != call.tenant_id:
            raise PolicyError("cross-tenant access blocked")
        # Take a detached JSON snapshot; no argument is silently converted into an identity.
        serialized = json.dumps(call.args, allow_nan=False, ensure_ascii=False)
        if len(serialized.encode("utf-8")) > 100_000:
            raise PolicyError("arguments too large")
        risk = TOOL_RISK.get(call.tool)
        if risk is None:
            raise PolicyError("unknown tool")
        _validate_args(call.tool, json.loads(serialized))
        allow = risk == "low"
        logger.info(json.dumps({
            "event": "mcp.policy_decision", "request_id": call.request_id,
            "tool": call.tool, "risk": risk, "tenant": call.tenant_id,
            "user": call.user_id, "allow": allow,
            "reason": "allowed" if allow else "approval_required",
        }))
        if not allow:
            return {"ok": False, "error": "medium- or high-risk Tool requires approval"}
        return {"ok": True, "tool": call.tool}
    except PolicyError as error:
        # No raw arguments, credentials or arbitrary exception message enters the audit.
        try:
            logger.warning("policy_block", extra={"reason_code": str(error)})
        except Exception:
            pass  # The request remains denied when the audit adapter is unavailable.
        return {"ok": False, "error": str(error)}
    except (TypeError, ValueError, RecursionError):
        return {"ok": False, "error": "arguments are not serializable"}
    except Exception:
        return {"ok": False, "error": "internal error"}


def demo() -> None:
    search = ToolCall("search", {"tenantId": "tenant-example", "query": "security"},
                      "tenant-example", "reader-example", "request-1")
    export = ToolCall("admin_export", {"tenantId": "tenant-example", "format": "csv"},
                      "tenant-example", "reader-example", "request-2")
    print(handle_tool_call(search))
    print(handle_tool_call(export))


if __name__ == "__main__":
    demo()
