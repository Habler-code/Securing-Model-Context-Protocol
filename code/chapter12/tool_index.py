"""Authoritative tool-index example for Chapter 12."""

from collections.abc import Callable, Iterable, Mapping
from copy import deepcopy
from dataclasses import dataclass
from hashlib import sha256
import json
from typing import Any


MAX_BODY_BYTES = 1_048_576


def read_bounded_body(
    chunks: Iterable[bytes], max_bytes: int = MAX_BODY_BYTES
) -> bytes:
    """Read decoded chunks with a byte limit; transport deadlines are separate."""
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes <= 0:
        raise ValueError("invalid body-size policy")
    body = bytearray()
    for chunk in chunks:
        if not isinstance(chunk, bytes):
            raise TypeError("body chunks must be bytes")
        if len(body) + len(chunk) > max_bytes:
            raise ValueError("request body exceeds limit")
        body.extend(chunk)
    return bytes(body)


@dataclass(frozen=True)
class ToolDefinition:
    name: str
    description: str
    version: str
    input_schema: Mapping[str, Any]
    risk: str
    schema_sha256: str = ""


class ToolDefinitionDenied(PermissionError):
    """Raised when a caller cannot obtain a tool definition."""


class ToolIndex:
    def __init__(
        self,
        registry: Mapping[str, ToolDefinition],
        can_disclose: Callable[[str, ToolDefinition], bool],
    ) -> None:
        self._registry: dict[str, ToolDefinition] = {}
        for name, tool in registry.items():
            if name != tool.name:
                raise ValueError("registry key does not match Tool name")
            self._registry[name] = self._snapshot(tool)
        self._can_disclose = can_disclose

    @staticmethod
    def _snapshot(tool: ToolDefinition) -> ToolDefinition:
        schema = deepcopy(dict(tool.input_schema))
        encoded = json.dumps(
            schema,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        return ToolDefinition(
            name=tool.name,
            description=tool.description,
            version=tool.version,
            input_schema=schema,
            risk=tool.risk,
            schema_sha256=sha256(encoded).hexdigest(),
        )

    @classmethod
    def _defensive_copy(cls, tool: ToolDefinition) -> ToolDefinition:
        return cls._snapshot(tool)

    def list_summaries(self, principal_id: str) -> list[dict[str, str]]:
        return [
            {"name": tool.name, "description": tool.description}
            for tool in self._registry.values()
            if self._can_disclose(
                principal_id,
                self._defensive_copy(tool),
            )
        ]

    def get_definition(
        self,
        principal_id: str,
        tool_name: str,
    ) -> ToolDefinition:
        tool = self._registry.get(tool_name)
        if tool is None or not self._can_disclose(
            principal_id,
            self._defensive_copy(tool),
        ):
            raise ToolDefinitionDenied("tool definition is not available")
        return self._defensive_copy(tool)


def demo() -> None:
    tool = ToolDefinition(
        "read_ticket", "Read one ticket", "1.0.0", {"type": "object"}, "low"
    )
    index = ToolIndex({tool.name: tool}, lambda actor, _tool: actor == "support")
    assert index.get_definition("support", "read_ticket").schema_sha256
    assert index.list_summaries("unknown") == []
    assert read_bounded_body((b"{", b"}"), max_bytes=2) == b"{}"
    try:
        index.get_definition("unknown", "read_ticket")
    except ToolDefinitionDenied:
        print("unauthorized tool disclosure denied")
    else:
        raise AssertionError("tool disclosure must be denied")
    print("bounded read and authorized tool index checks passed")


if __name__ == "__main__":
    demo()
