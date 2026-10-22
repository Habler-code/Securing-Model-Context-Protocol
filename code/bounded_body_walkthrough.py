from collections.abc import AsyncIterable
import json

from chapter11.bounded_body import (
    MAX_REQUEST_BYTES,
    bound_structure,
    _unique_object,
    _reject_constant,
)
from chapter11.errors import ValidationFault


async def read_bounded_json(
    body: AsyncIterable[bytes],
    max_bytes: int = MAX_REQUEST_BYTES,
):
    if (
        type(max_bytes) is not int
        or not 0 < max_bytes <= MAX_REQUEST_BYTES
    ):
        raise ValueError("invalid request-size policy")

    chunks: list[bytes] = []
    total = 0

    async for chunk in body:
        if not isinstance(chunk, (bytes, bytearray, memoryview)):
            raise ValidationFault(-32700, "Invalid request body")
        with memoryview(chunk) as view:
            if not view.c_contiguous:
                raise ValidationFault(
                    -32700, "Non-contiguous body buffer"
                )
            count = view.nbytes
            if not count:
                continue
            if count > max_bytes - total:
                raise ValidationFault(
                    -32600, "Request body exceeds limit", 413
                )
            owned = view.tobytes()
        total += count
        chunks.append(owned)

    try:
        parsed = json.loads(
            b"".join(chunks).decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
        bound_structure(parsed)
        return parsed
    except ValidationFault:
        raise
    except (UnicodeError, ValueError, RecursionError):
        raise ValidationFault(
            -32700, "Invalid UTF-8 JSON"
        ) from None
