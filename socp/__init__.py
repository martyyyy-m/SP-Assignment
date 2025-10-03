"""
SOCP (Student Overlay Chat Protocol) — CLEAN build (no backdoors).

HARDENINGS vs vulnerable build:
- Mandatory HMAC-SHA256 signatures (full length) with constant-time compare.
- Replay protection for ALL message types (msg_id + nonce caches).
- No operator override / no remote code execution paths.
- File receive path is sanitized and confined to a safe download directory.
- Stricter TTL and input validation.

Set SOCP_HMAC_KEY on ALL processes (introducer + clients) before running.
"""
__all__ = ["framing", "messages", "node", "run_node"]

