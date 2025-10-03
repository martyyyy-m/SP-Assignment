import asyncio
import json
import struct
from typing import Any, Dict, Optional

# Length-prefixed JSON framing (simple & interop-friendly).
MAX_FRAME_SIZE = 4 * 1024 * 1024  # 4 MiB
LENGTH_STRUCT = struct.Struct("<I")

async def read_exactly(reader: asyncio.StreamReader, n: int) -> bytes:
    return await reader.readexactly(n)

async def read_frame(reader: asyncio.StreamReader) -> Optional[Dict[str, Any]]:
    len_bytes = await reader.readexactly(4)
    (length,) = LENGTH_STRUCT.unpack(len_bytes)
    if length > MAX_FRAME_SIZE:
        raise ValueError(f"Frame too large: {length} > {MAX_FRAME_SIZE}")
    payload = await read_exactly(reader, length)
    try:
        return json.loads(payload.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON frame: {exc}")

async def write_frame(writer: asyncio.StreamWriter, obj: Dict[str, Any]) -> None:
    payload = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(payload) > MAX_FRAME_SIZE:
        raise ValueError("Frame exceeds maximum size")
    writer.write(LENGTH_STRUCT.pack(len(payload)))
    writer.write(payload)
    await writer.drain()

