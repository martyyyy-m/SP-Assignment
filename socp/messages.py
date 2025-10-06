import time
import uuid
import os
from typing import Any, Dict, Optional
from . import crypto
import json
import hashlib

"""
messages.py — message envelopes, canonicalization, and signatures.

What this module does:
- Builds a standard message "envelope" we send over the wire (version, ids, ttl, etc.).
- Creates deterministic bytes for signing (so signatures verify across machines).
- Computes a content hash tailored to the message type (DM, group, file, etc.).
- Adds two signatures when needed:
    1) content_sig  — end-to-end integrity for the message body.
    2) sig          — transport-level signature over the whole envelope.

Why two signatures?
- content_sig: protects what the sender actually said (even if the envelope is
  re-wrapped or re-routed).
- sig: protects the envelope metadata itself (e.g., timestamp, from/to, ttl).
"""

VERSION = "1.1-clean"


def now_ms() -> int:
    """Current time in milliseconds (used for timestamp_ms)."""
    return int(time.time() * 1000)


def new_envelope(
    msg_type: str,
    from_id: str,
    to_id: Optional[str] = None,
    group: Optional[str] = None,
    ttl: int = 8,
) -> Dict[str, Any]:
    """
    Create a fresh message envelope with a unique msg_id and a random nonce.

    Args:
        msg_type: One of the message type constants below (e.g., DIRECT_MSG).
        from_id:  Sender identifier (stable string).
        to_id:    Receiver identifier (for direct messages).
        group:    Group/channel id (for group messages).
        ttl:      Hop/time limit — routers can drop once it reaches 0.

    Returns:
        Dict representing the envelope; 'body' is an empty dict ready to fill.
        'sig' and 'content_sig' are None until we sign.
    """
    env = {
        "version": VERSION,
        "msg_type": msg_type,
        "msg_id": str(uuid.uuid4()),         # unique per message
        "timestamp_ms": now_ms(),            # sender's clock in ms
        "from": from_id,
        "to": to_id,
        "group": group,
        "ttl": ttl,
        "sig": None,                         # transport signature (set by sign_envelope)
        "nonce": str(uuid.uuid4()),          # random per-message value to avoid replay
        "body": {},                          # caller fills this
        "content_sig": None,                 # end-to-end signature (set by sign_content)
    }
    return env


# -----------------------
# Public message type tags
# -----------------------
# These are intentionally simple strings so they serialize neatly.
HELLO = "HELLO"
PRESENCE_UPDATE = "PRESENCE_UPDATE"
MEMBER_LIST_REQUEST = "MEMBER_LIST_REQUEST"
MEMBER_LIST_RESPONSE = "MEMBER_LIST_RESPONSE"
DIRECT_MSG = "DIRECT_MSG"
GROUP_MSG = "GROUP_MSG"
FILE_OFFER = "FILE_OFFER"
FILE_ACCEPT = "FILE_ACCEPT"
FILE_CHUNK = "FILE_CHUNK"
FILE_COMPLETE = "FILE_COMPLETE"
PING = "PING"
PONG = "PONG"


def canonical_bytes(env: Dict[str, Any]) -> bytes:
    """
    Deterministic JSON for envelope signing.

    We drop 'sig' from the object (we're computing it!) and then dump with
    sorted keys and compact separators so the same structure always yields the
    exact same bytes across platforms.
    """
    e = {k: v for k, v in env.items() if k != "sig"}
    return json.dumps(e, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_content_hash(env: Dict[str, Any]) -> bytes:
    """
    Compute a SHA-256 digest of the *meaningful* content for content_sig.

    Rationale:
    - Different message kinds care about different fields. We keep the input
      small and stable by hashing just what matters for that kind.
    - Using a digest keeps RSA signing inputs fixed length and tidy.
    """
    mt = env.get("msg_type", "")
    body = env.get("body", {})
    from_id = env.get("from", "")
    to_id = env.get("to", "")
    ts = str(env.get("timestamp_ms", 0))

    if mt == "DIRECT_MSG":
        # DM integrity ties together: encrypted payload, sender, receiver, time.
        ciphertext = body.get("content", "")
        data = (
            ciphertext.encode("utf-8")
            + from_id.encode("utf-8")
            + to_id.encode("utf-8")
            + ts.encode("utf-8")
        )
    elif mt == "GROUP_MSG":
        # Group messages skip 'to_id'; everyone in the group can verify the same hash.
        content = body.get("content", "")
        data = content.encode("utf-8") + from_id.encode("utf-8") + ts.encode("utf-8")
    elif mt.startswith("FILE_") or mt == "PUBLIC_CHANNEL_KEY_SHARE":
        # File/key-share flows: fix ordering of 'shares' JSON so the hash is stable.
        shares = json.dumps(body.get("shares", {}), sort_keys=True, separators=(",", ":"))
        creator_pub = body.get("creator_pub", "")
        data = shares.encode("utf-8") + creator_pub.encode("utf-8")
    else:
        # Default: canonicalize the whole body. Keeps odd cases covered.
        data = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")

    return hashlib.sha256(data).digest()


def sign_content(env: Dict[str, Any], privkey) -> Dict[str, Any]:
    """
    Attach end-to-end content signature (RSA-PSS + SHA-256) as env['content_sig'].

    Call this *after* you've filled env['body'].
    """
    content_hash = compute_content_hash(env)
    env["content_sig"] = crypto.sign(privkey, content_hash)
    return env


def sign_envelope(env: Dict[str, Any], privkey) -> Dict[str, Any]:
    """
    Sign the entire envelope (minus 'sig' itself) and store it in env['sig'].

    This protects metadata like timestamp, from/to, ttl, etc.
    """
    env["sig"] = crypto.sign(privkey, canonical_bytes(env))
    return env


def verify_content(env: Dict[str, Any], pubkey) -> bool:
    """
    Check env['content_sig'] against the recomputed content hash.
    Returns True if valid; False if missing/invalid.
    """
    csig = env.get("content_sig")
    if not csig:
        return False
    hsh = compute_content_hash(env)
    return crypto.verify(pubkey, hsh, csig)


def verify_envelope(env: Dict[str, Any], pubkey) -> bool:
    """
    Verify env['sig'] over the canonical envelope bytes.
    Returns True if valid; False otherwise.
    """
    sig = env.get("sig")
    if not sig:
        return False
    return crypto.verify(pubkey, canonical_bytes(env), sig)


def sign(env: Dict[str, Any], privkey) -> Dict[str, Any]:
    """
    Convenience helper: sign both layers (content first, then envelope).

    Typical usage:
        env = new_envelope(DIRECT_MSG, from_id, to_id=peer)
        env["body"] = {"content": "..."}    # fill body
        env = sign(env, my_private_key)     # adds content_sig and sig
    """
    env = sign_content(env, privkey)
    env = sign_envelope(env, privkey)
    return env