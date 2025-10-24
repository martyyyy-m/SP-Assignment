"""
SOCP (Student Overlay Chat Protocol) — CLEAN build (no backdoors).

HARDENINGS vs vulnerable build:
- Mandatory HMAC-SHA256 signatures (full length) with constant-time compare.
- Replay protection for ALL message types (msg_id + nonce caches).
- No operator override / no remote code execution paths.
- File receive path is sanitized and confined to a safe download directory.
- Stricter TTL and input validation.

SECURITY FIXES IMPLEMENTED :
- Fixed Presence Replay Gap: Added signature verification and timestamp validation for presence updates
- Fixed Hidden Operator Override: Implemented secure admin operations with proper authentication
  and restricted functionality to prevent identity assumption
- Added comprehensive logging and auditing for admin operations

Set SOCP_HMAC_KEY on ALL processes (introducer + clients) before running.
"""
__all__ = ["framing", "messages", "node", "run_node"]

