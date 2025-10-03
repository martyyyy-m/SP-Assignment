import time
import uuid
import os
from typing import Any, Dict, Optional
from . import crypto
import json
import hashlib

VERSION = "1.1-clean"

def now_ms() -> int:
    return int(time.time() * 1000)

def new_envelope(msg_type: str,
                 from_id: str,
                 to_id: Optional[str] = None,
                 group: Optional[str] = None,
                 ttl: int = 8) -> Dict[str, Any]:
    """Standard envelope with msg_id + nonce."""
    env = {
        "version": VERSION,
        "msg_type": msg_type,
        "msg_id": str(uuid.uuid4()),
        "timestamp_ms": now_ms(),
        "from": from_id,
        "to": to_id,
        "group": group,
        "ttl": ttl,
        "sig": None,          # transport signature
        "nonce": str(uuid.uuid4()),
        "body": {},
        "content_sig": None,  # end-to-end content signature
    }
    return env

# Message types (no admin/backdoor types in clean build)
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
    import json
    e = {k: v for k, v in env.items() if k != "sig"}
    return json.dumps(e, sort_keys=True, separators=(",", ":")).encode("utf-8")

def compute_content_hash(env: Dict[str, Any]) -> bytes:
    """Compute SHA-256 hash over the canonical content for content_sig."""
    mt = env.get("msg_type", "")
    body = env.get("body", {})
    from_id = env.get("from", "")
    to_id = env.get("to", "")
    ts = str(env.get("timestamp_ms", 0))

    if mt == "DIRECT_MSG":
        ciphertext = body.get("content", "")
        data = (
            ciphertext.encode("utf-8")
            + from_id.encode("utf-8")
            + to_id.encode("utf-8")
            + ts.encode("utf-8")
        )
    elif mt == "GROUP_MSG":
        content = body.get("content", "")
        data = content.encode("utf-8") + from_id.encode("utf-8") + ts.encode("utf-8")
    elif mt.startswith("FILE_") or mt == "PUBLIC_CHANNEL_KEY_SHARE":
        shares = json.dumps(body.get("shares", {}), sort_keys=True, separators=(",", ":"))
        creator_pub = body.get("creator_pub", "")
        data = shares.encode("utf-8") + creator_pub.encode("utf-8")
    else:
        # fallback: hash canonical JSON of body
        data = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")

    return hashlib.sha256(data).digest()


def sign_content(env: Dict[str, Any], privkey) -> Dict[str, Any]:
    """
    Compute end-to-end content signature (content_sig) using RSA-PSS + SHA256.
    """
    content_hash = compute_content_hash(env)
    env["content_sig"] = crypto.sign(privkey, content_hash)
    return env

def sign_envelope(env: Dict[str, Any], privkey) -> Dict[str, Any]:
    """Sign entire envelope (transport sig)."""
    env["sig"] = crypto.sign(privkey, canonical_bytes(env))
    return env

def verify_content(env: Dict[str, Any], pubkey) -> bool:
    csig = env.get("content_sig")
    if not csig:
        return False
    hsh = compute_content_hash(env)
    return crypto.verify(pubkey, hsh, csig)

def verify_envelope(env: Dict[str, Any], pubkey) -> bool:
    sig = env.get("sig")
    if not sig:
        return False
    return crypto.verify(pubkey, canonical_bytes(env), sig)

def sign(env: Dict[str, Any], privkey) -> Dict[str, Any]:
    """
    Convenience wrapper: signs both content and envelope.
    Requires private key.
    """
    env = sign_content(env, privkey)
    env = sign_envelope(env, privkey)
    return env