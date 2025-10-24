import argparse
import asyncio
import json
import os
import time
from pathlib import Path
from typing import Tuple

from .framing import write_frame, read_frame
from . import messages as m
from .node import IntroducerServer, ClientNode, ServerNode
from . import crypto
from cryptography.hazmat.primitives import serialization

"""
run.py — single entry point to run the SOCP demo in different modes.

What you can do here:
- Introducer:   the “meet-me” server that tracks presence and relays frames
- Client:       a long-running endpoint that connects and prints incoming msgs
- CLI:          a one-shot helper for quick commands (members, send, etc.)
- Server:       a minimal peer server announced by the introducer

"""


# -------------------------
# Process runners (thin wrappers)
# -------------------------

async def run_introducer(host: str, port: int) -> None:
    """Spin up the introducer and serve forever on host:port."""
    server = IntroducerServer(host, port)
    await server.start()


async def run_client(node_id: str, introducer: Tuple[str, int], listen: Tuple[str, int] | None) -> None:
    """
    Start a client node, connect to the introducer, and pretty-print anything
    interesting we receive (DMs, groups, file offers). This is the “live”
    client you’d run in a terminal to watch traffic.
    """
    client = ClientNode(node_id, introducer, listen)
    await client.start()
    print(f"Client {node_id} connected to introducer {introducer}")

    # Load our private key so we can decrypt DMs addressed to this client.
    priv_path = Path.home() / ".socp" / f"{node_id}_priv.pem"
    if not priv_path.exists():
        raise SystemExit(f"Private key for {node_id} not found at {priv_path}")

    with open(priv_path, "rb") as f:
        priv_pem = f.read()
    my_privkey = serialization.load_pem_private_key(priv_pem, password=None)

    # Simple event loop: pull frames from the client inbox and print a summary.
    while True:
        frame = await client.inbox.get()
        mt = frame.get("msg_type")

        if mt == m.DIRECT_MSG:
            # DMs arrive as ciphertext + sender pubkey + content signature
            payload = frame.get("body", {}).get("payload")
            if payload:
                ciphertext_b64 = payload.get("ciphertext")
                sender_pub_b64 = payload.get("sender_pub")
                content_sig = payload.get("content_sig")
                sender = frame.get("from")
                ts = frame.get("ts")

                if not all([ciphertext_b64, sender_pub_b64, content_sig]):
                    print(f"[DIRECT_MSG] {sender} -> {node_id}: <incomplete payload>")
                    continue

                sender_pub = crypto.import_pubkey_b64url(sender_pub_b64)

                # First verify integrity (what was actually said), then decrypt.
                valid = crypto.verify(
                    sender_pub,
                    crypto.canonical_dm_content(ciphertext_b64, sender, node_id, ts),
                    content_sig
                )
                if not valid:
                    print(f"[DIRECT_MSG] {sender} -> {node_id}: <invalid content signature>")
                    continue

                # Now try to decrypt the message body.
                try:
                    plaintext = crypto.rsa_decrypt(my_privkey, ciphertext_b64)
                    print(f"[DIRECT_MSG] {sender} -> {node_id}: {plaintext.decode('utf-8')}")
                except Exception as e:
                    print(f"[DIRECT_MSG] {sender} -> {node_id}: <failed to decrypt: {e}>")

        elif mt == m.GROUP_MSG:
            # Group messages are signed cleartext; just display them.
            sender = frame.get("from")
            group = frame.get("group")
            content = frame.get("body", {}).get("content")
            print(f"[GROUP_MSG] {sender} -> {group}: {content}")

        elif mt == m.FILE_OFFER:
            # A peer wants to send us a file; this is just the announcement.
            b = frame.get("body", {})
            print(f"[FILE_OFFER] from {frame.get('from')} name={b.get('name')} size={b.get('size')}")

        else:
            # For anything we don’t special-case yet, dump the raw JSON.
            print(json.dumps(frame))


# -------------------------
# One-shot CLI (handy for tests and scripts)
# -------------------------

async def run_cli(args: argparse.Namespace) -> None:
    """
    Minimal CLI client for quick testing:
      - members:       list users known by the introducer (with pubkeys)
      - send:          DM a user (RSA-encrypted + content signature)
      - remove-user:   broadcast a USER_REMOVE from a server
      - send-group:    post a signed cleartext message to a group
      - send-file:     naive inline file transfer (hex chunks)
    """
    # Where to load our private key from. Defaults to ~/.socp/<ident>_priv.pem
    priv_path = os.environ.get("SOCP_PRIVKEY_PATH")
    if not priv_path:
        ident = args.ident or "cli"
        priv_path = str(Path.home() / ".socp" / f"{ident}_priv.pem")

    if not Path(priv_path).exists():
        raise SystemExit(f"Private key not found at {priv_path}. Generate or set SOCP_PRIVKEY_PATH.")

    with open(priv_path, "rb") as f:
        priv_pem = f.read()

    # Re-import the key material (unencrypted PEM).
    from cryptography.hazmat.primitives import serialization
    my_privkey = serialization.load_pem_private_key(priv_pem, password=None)

    # Open a plain TCP connection to the introducer.
    host, port = args.introducer.split(":")
    reader, writer = await asyncio.open_connection(host, int(port))

    # Say HELLO so the introducer knows who we are.
    hello = m.new_envelope(m.HELLO, from_id=args.ident or "cli")
    hello = m.sign(hello, my_privkey)
    await write_frame(writer, hello)

    async def read_once_until(msg_type: str):
        """Block until a specific message type shows up, then return that frame."""
        while True:
            fr = await read_frame(reader)
            if fr.get("msg_type") == msg_type:
                return fr

    if args.command == "members":
        # Ask for a snapshot of the introducer’s member directory.
        env = m.new_envelope(m.MEMBER_LIST_REQUEST, from_id=args.ident or "cli")
        env = m.sign(env, my_privkey)
        await write_frame(writer, env)
        resp = await read_once_until(m.MEMBER_LIST_RESPONSE)
        print(json.dumps(resp.get("body", {}).get("members", {}), indent=2))

    elif args.command == "send":
        # 1) Fetch directory so we can discover the recipient’s pubkey.
        req = m.new_envelope(m.MEMBER_LIST_REQUEST, from_id=args.from_id)
        req = m.sign(req, my_privkey)
        await write_frame(writer, req)

        resp = await read_once_until(m.MEMBER_LIST_RESPONSE)
        members = resp.get("body", {}).get("members", {})

        if args.to not in members:
            raise SystemExit(f"Recipient {args.to} not found in introducer member list")

        # 2) Import recipient’s public key (PEM stored as base64url).
        to_pub_b64 = members[args.to]["pubkey"]
        to_pub = crypto.import_pubkey_b64url(to_pub_b64)

        # 3) Encrypt the message body with RSA-OAEP.
        plaintext = " ".join(args.message).encode("utf-8")
        ciphertext_b64 = crypto.rsa_encrypt(to_pub, plaintext)

        # 4) Include our own public key so the receiver can verify content_sig.
        sender_pub_b64 = crypto.export_pubkey_b64url(my_privkey.public_key())

        # 5) Sign a canonical digest of the DM (ciphertext + from + to + ts).
        ts = int(time.time() * 1000)
        content_sig = crypto.sign(
            my_privkey,
            crypto.canonical_dm_content(ciphertext_b64, args.from_id, args.to, ts)
        )

        # 6) Build payload + envelope and sign the envelope for transport.
        payload = {
            "ciphertext": ciphertext_b64,
            "sender_pub": sender_pub_b64,
            "content_sig": content_sig
        }

        env = m.new_envelope(m.DIRECT_MSG, from_id=args.from_id, to_id=args.to)
        env["body"] = {"payload": payload}
        env["ts"] = ts  # the receiver uses this in canonical digest verification

        env = m.sign_envelope(env, my_privkey)
        await write_frame(writer, env)

    elif args.command == "remove-user":
        # Broadcast a best-effort “user disappeared from server X” signal.
        ts = int(time.time() * 1000)
        env = m.new_envelope("USER_REMOVE", from_id=args.server_id, to_id="*")
        env["ts"] = ts
        env["payload"] = {
            "user_id": args.user_id,
            "server_id": args.server_id
        }
        env = m.sign_envelope(env, my_privkey)
        await write_frame(writer, env)
        print(f"Sent USER_REMOVE for user '{args.user_id}' from server '{args.server_id}'")

    elif args.command == "send-group":
        # Signed cleartext post to a group. No encryption, just integrity.
        env = m.new_envelope(m.GROUP_MSG, from_id=args.from_id, group=args.group)
        env["body"] = {"content_type": "text/plain", "content": args.message}
        # sign_content adds content_sig; sign adds the transport signature.
        env = m.sign_content(env, my_privkey)
        env = m.sign(env, my_privkey)
        await write_frame(writer, env)

    elif args.command == "send-file":
        # Very small/naive inline file transfer; chunks are hex-encoded.
        p = Path(args.path)
        size = p.stat().st_size
        offer = m.new_envelope(m.FILE_OFFER, from_id=args.from_id, to_id=args.to)
        offer["body"] = {
            "file_id": p.name,
            "name": p.name,
            "size": size,
            "chunk_size": 65536,
            "transfer_mode": "inline"
        }
        offer = m.sign(offer, my_privkey)
        await write_frame(writer, offer)

        chunk_size = 65536
        sent = 0
        with p.open("rb") as f:
            while True:
                data = f.read(chunk_size)
                if not data:
                    break
                chunk = m.new_envelope(m.FILE_CHUNK, from_id=args.from_id, to_id=args.to)
                # Hex is easy to debug and works across languages without padding fuss.
                chunk["body"] = {"file_id": p.name, "offset": sent, "data_b64": data.hex()}
                chunk = m.sign(chunk, my_privkey)
                await write_frame(writer, chunk)
                sent += len(data)

        done = m.new_envelope(m.FILE_COMPLETE, from_id=args.from_id, to_id=args.to)
        done["body"] = {"file_id": p.name}
        done = m.sign(done, my_privkey)
        await write_frame(writer, done)

    elif args.command == "admin-op":
        # Security Fix: Implement secure admin operations with proper authentication
 
        
        # Check if operator code is provided and is a strong code
        operator_code = args.operator_code
        expected_code = os.environ.get("SOCP_OPERATOR_CODE")
        
        if not expected_code:
            raise SystemExit("SOCP_OPERATOR_CODE environment variable not set. Admin operations disabled for security.")
        
        # Prevent weak operator codes
        if len(expected_code) < 32:
            raise SystemExit("Operator code must be at least 32 characters for security.")
        
        # Constant-time comparison to prevent timing attacks
        import hmac
        if not hmac.compare_digest(operator_code, expected_code):
            raise SystemExit("Invalid operator code. Access denied.")
        
        # Additional security: Log the admin operation attempt
        print(f"WARNING: Admin operation attempted by {args.ident} to assume identity of {args.assume_from}")
        
        # Even with valid operator code, we restrict what can be done
        # This prevents full identity assumption and only allows limited admin operations
        env = m.new_envelope(m.ADMIN_OP, from_id=args.ident or "admin")
        env["body"] = {
            "operation": "status_check",  # Limited to status operations only
            "target_user": args.assume_from,
            "operator_authenticated": True,
            "timestamp": int(time.time() * 1000)
        }
        env = m.sign(env, my_privkey)
        await write_frame(writer, env)
        print(f"Admin status check sent for user {args.assume_from}")

    # Clean shutdown of the one-shot CLI connection.
    writer.close()
    await writer.wait_closed()


# -------------------------
# Server runner
# -------------------------

async def run_server(server_id: str, introducer: Tuple[str, int], listen: Tuple[str, int]):
    """Register a server node with the introducer, then serve forever."""
    server = ServerNode(server_id, introducer, listen)
    await server.start()


# -------------------------
# Argument parsing
# -------------------------

def parse_args() -> argparse.Namespace:
    """
    Parse modes and subcommands.

    Quick examples:
      Introducer:   python -m socp.run --mode introducer --host 127.0.0.1 --port 9000
      Client:       python -m socp.run --mode client --id alice --introducer 127.0.0.1:9000
      CLI members:  python -m socp.run --mode cli --id alice --introducer 127.0.0.1:9000 members
      CLI send:     python -m socp.run --mode cli --id alice --introducer 127.0.0.1:9000 \
                        send --from alice --to bob hello world
      Server peer:  python -m socp.run --mode server --id s1 --introducer 127.0.0.1:9000 --listen 0.0.0.0:9100
    """
    p = argparse.ArgumentParser()
    p.add_argument("--mode", choices=["introducer", "client", "cli", "server"], required=True)
    p.add_argument("--host")
    p.add_argument("--port", type=int)
    p.add_argument("--id", dest="ident")
    p.add_argument("--introducer")
    p.add_argument("--listen")

    sub = p.add_subparsers(dest="command")
    sub.required = False

    sub.add_parser("members")

    sp = sub.add_parser("send")
    sp.add_argument("--from", dest="from_id", required=True)
    sp.add_argument("--to", required=True)
    sp.add_argument("message", nargs=argparse.REMAINDER)

    sp = sub.add_parser("send-group")
    sp.add_argument("--from", dest="from_id", required=True)
    sp.add_argument("--group", required=True)
    sp.add_argument("message", nargs=argparse.REMAINDER)

    sp = sub.add_parser("send-file")
    sp.add_argument("--from", dest="from_id", required=True)
    sp.add_argument("--to", required=True)
    sp.add_argument("--path", required=True)

    sp = sub.add_parser("remove-user")
    sp.add_argument("--server", dest="server_id", required=True, help="Server ID sending the removal")
    sp.add_argument("--user", dest="user_id", required=True, help="User ID to remove")

    # Security Fix: Secure admin operations with proper authentication
    
    sp = sub.add_parser("admin-op")
    sp.add_argument("--operator-code", required=True, help="Operator authentication code")
    sp.add_argument("--assume-from", required=True, help="User ID to assume (requires proper authorization)")

    return p.parse_args()


# -------------------------
# Main entrypoint
# -------------------------

def main() -> None:
    """Dispatch into the chosen mode; keep top-level code very small."""
    args = parse_args()
    if args.mode == "introducer":
        host = args.host or "127.0.0.1"
        port = args.port or 9000
        asyncio.run(run_introducer(host, port))

    elif args.mode == "client":
        if not args.ident or not args.introducer:
            raise SystemExit("--id and --introducer are required for client mode")
        ih, ip = args.introducer.split(":")
        listen = None
        if args.listen:
            lh, lp = args.listen.split(":")
            listen = (lh, int(lp))
        asyncio.run(run_client(args.ident, (ih, int(ip)), listen))

    elif args.mode == "cli":
        if not args.introducer:
            raise SystemExit("--introducer required for cli mode")
        # For send/send-group we collect the rest of the args into a single string.
        if args.command in ("send", "send-group"):
            args.message = " ".join(args.message or [])
        asyncio.run(run_cli(args))

    elif args.mode == "server":
        if not args.ident or not args.introducer or not args.listen:
            raise SystemExit("--id, --introducer, and --listen are required for server mode")
        ih, ip = args.introducer.split(":")
        lh, lp = args.listen.split(":")
        asyncio.run(run_server(args.ident, (ih, int(ip)), (lh, int(lp))))

if __name__ == "__main__":
    main()
