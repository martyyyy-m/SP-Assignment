import asyncio
import json
import struct
from typing import Any, Dict, Optional

import asyncio
import json
import struct
from typing import Any, Dict, Optional

"""
framing.py — tiny length-prefixed JSON framing for asyncio streams.

Protocol (simple on purpose):
- Each message = 4-byte little-endian unsigned length (N) + N bytes of UTF-8 JSON.
- Hard cap at 4 MiB so a buggy peer can’t make us allocate silly amounts of memory.
- JSON is compact (no extra spaces); keys/values are whatever your app needs.

Why this style?
- Plays nicely with Python, Node, Go, etc. (everyone understands length-prefix).
- Streaming-friendly: we can read exactly N bytes and hand off a clean dict.

"""

# Length-prefixed JSON framing (simple & interop-friendly).
MAX_FRAME_SIZE = 4 * 1024 * 1024  # 4 MiB hard limit
LENGTH_STRUCT = struct.Struct("<I")  # little-endian unsigned 32-bit length


async def read_exactly(reader: asyncio.StreamReader, n: int) -> bytes:
    """Tiny wrapper so callers read a fixed number of bytes with a clear name."""
    return await reader.readexactly(n)


async def read_frame(reader: asyncio.StreamReader) -> Optional[Dict[str, Any]]:
    """
    Read one framed JSON message and return it as a dict.

    Raises:
        ValueError: if the frame is too big or the JSON is invalid.

    Returns:
        dict parsed from JSON. (None is never returned; kept for symmetry/typing.)
    """
    # 1) Read the 4-byte length prefix.
    len_bytes = await reader.readexactly(4)
    (length,) = LENGTH_STRUCT.unpack(len_bytes)

    # Quick sanity check before allocating/reading the body.
    if length > MAX_FRAME_SIZE:
        raise ValueError(f"Frame too large: {length} > {MAX_FRAME_SIZE}")

    # 2) Read the JSON payload exactly as long as the prefix said.
    payload = await read_exactly(reader, length)

    # 3) Decode + parse. If it’s not valid UTF-8 JSON, surface a clean error.
    try:
        return json.loads(payload.decode("utf-8"))
    except json.JSONDecodeError as exc:
        # Keep the message short; no payload echo to avoid leaking big data.
        raise ValueError(f"Invalid JSON frame: {exc}") from exc


async def write_frame(writer: asyncio.StreamWriter, obj: Dict[str, Any]) -> None:
    """
    Serialize a dict to compact JSON and write it as a framed message.

    The JSON is written with no extra whitespace to keep frames small.
    """
    # Compact JSON: stable separators, keep non-ASCII as UTF-8 (not \u escapes).
    payload = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    if len(payload) > MAX_FRAME_SIZE:
        raise ValueError("Frame exceeds maximum size")

    # Prefix with 4-byte little-endian length, then the payload itself.
    writer.write(LENGTH_STRUCT.pack(len(payload)))
    writer.write(payload)
    await writer.drain()  # Let the transport flush; important under backpressure.

