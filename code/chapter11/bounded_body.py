"""Shared bounded-body guards for Chapter 11's printed Python walkthrough.

code/bounded_body_walkthrough.py assembles the three printed stages and imports
the structure and strict-JSON checks here. This module also supplies a complete
reader for canonical behavior tests; transport deadlines remain separate.
"""

from __future__ import annotations

import json
import math
from collections.abc import AsyncIterable
from typing import Any

try:
    from .errors import ValidationFault
except ImportError:  # direct chapter-local demo execution
    from errors import ValidationFault

MAX_REQUEST_BYTES = 1_048_576


def bound_structure(value: Any) -> None:
    """A bounded JSON-tree admission guard, not an isolated validation worker."""
    pending = [(value, 0)]
    nodes = 0
    while pending:
        current, depth = pending.pop()
        nodes += 1
        if nodes > 20_000 or depth > 32:
            raise ValidationFault(-32602, "Request structure exceeds policy")
        if isinstance(current, dict):
            if any(not isinstance(key, str) for key in current):
                raise ValidationFault(-32602, "Invalid JSON object key")
            pending.extend((child, depth + 1) for child in current.values())
        elif isinstance(current, list):
            pending.extend((child, depth + 1) for child in current)
        elif current is not None and type(current) not in (str, bool, int, float):
            raise ValidationFault(-32602, "Invalid JSON value")
        elif isinstance(current, float) and not math.isfinite(current):
            raise ValidationFault(-32602, "Invalid JSON number")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise ValueError("duplicate object member")
        output[key] = value
    return output


def _reject_constant(_: str) -> None:
    raise ValueError("non-JSON numeric constant")


async def read_bounded_json(body: AsyncIterable[bytes], max_bytes: int = MAX_REQUEST_BYTES) -> Any:
    """Bound bytes before parsing; the transport must separately enforce time.

    Async iteration lets the hosting HTTP framework cancel the incoming stream.
    This helper never dispatches a tool or opens a listener.
    """
    # Stage 1: admit the size policy before reading.
    if type(max_bytes) is not int or not 0 < max_bytes <= MAX_REQUEST_BYTES:
        raise ValueError("invalid request-size policy")
    # Stage 2: own and count raw bytes as they arrive.
    chunks: list[bytes] = []
    total = 0
    async for chunk in body:
        if not isinstance(chunk, (bytes, bytearray, memoryview)):
            raise ValidationFault(-32700, "Invalid request body")
        # Inspect the actual buffer byte count before allocating a copy. len()
        # on a multi-byte memoryview counts elements, not encoded bytes.
        with memoryview(chunk) as view:
            if not view.c_contiguous:
                raise ValidationFault(-32700, "Request body buffer must be contiguous")
            count = view.nbytes
            if not count:
                continue
            if count > max_bytes - total:
                raise ValidationFault(-32600, "Request body exceeds limit", 413)
            owned = view.tobytes()
        total += count
        chunks.append(owned)
    # Stage 3: strict UTF-8 decoding and non-executing parsing.
    try:
        parsed = json.loads(
            b"".join(chunks).decode("utf-8"),
            object_pairs_hook=_unique_object, parse_constant=_reject_constant,
        )
        bound_structure(parsed)
        return parsed
    except ValidationFault:
        raise
    except (UnicodeError, ValueError, RecursionError):
        raise ValidationFault(-32700, "Invalid UTF-8 JSON") from None
