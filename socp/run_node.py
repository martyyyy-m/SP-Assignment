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
run.py — one entry point for everything:
- Introducer    (meet-me server that tracks presence and relays frames)
- Client        (endpoints that talk via the introducer)
- CLI helper    (quick one-shot commands like listing members, send a DM)
- Server node   (peer servers that the introducer can announce)

"""


# -------------------------
# Top-level process runners
# -------------------------

async def run_introducer(host: str, port: int) -> None:
    """Spin up the introducer and serve forever."""
    server = IntroducerServer(host, port)
    await server.start()


async def run_client(node_id: str, introducer: Tuple[str, int], listen: Tuple[str, int] | None) -> None:
    """
    Start a client node, connect to the introducer, and print any messages
    we receive (DMs, group messages, file offers, etc.).

    This is the “long-running” client: it keeps an inbox and shows events.
    """
    # Create client node and connect
    client = ClientNode(node_id, introducer, listen)
    await client.start()
    print(f"Client {node_id} connected to introducer {introducer}")

    # Load our private key for decrypting incoming DMs
    priv_path = Path.home() / ".socp" / f"{node_id}_priv.pem"
    if not priv_path.exists():
        raise SystemExit(f"Private key for {node_id} not found at {priv_path}")

    with open(priv_path, "rb") as f:
        priv_pem = f.read()
    my_privkey = serialization.load_pem_private_key(priv_pem, password=None)

    # Event loop: pull frames from the client's inbox and handle a few types
    while True:
        frame = await client.inbox.get()
        mt = frame.get("msg_type")

        if mt == m.DIRECT_MSG:
            # DMs are: ciphertext + sender’s pubkey + content_sig
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

                # Verify “what was actually said” (canonical digest) before decrypting
                valid = crypto.verify(
                    sender_pub,
                    crypto.canonical_dm_content(ciphertext_b64, sender, node_id, ts),
                    content_sig
                )

                if not valid:
                    print(f"[DIRECT_MSG] {sender} -> {node_id}: <invalid content signature>")
                    continue

                # Decrypt after the signature checks out
                try:
                    plaintext = crypto.rsa_decrypt(my_privkey, ciphertext_b64)
                    print(f"[DIRECT_MSG] {sender} -> {node_id}: {plaintext.decode('utf-8')}")
                except Exception as e:
                    print(f"[DIRECT_MSG] {sender} -> {node_id}: <failed to decrypt: {e}>")

        elif mt == m.GROUP_MSG:
            # Group messages are signed cleartext (no encryption)
            sender = frame.get("from")
            group = frame.get("group")
            content = frame.get("body", {}).get("content")
            print(f"[GROUP_MSG] {sender} -> {group}: {content}")

        elif mt == m.FILE_OFFER:
            # Basic announcement that a peer wants to send a file
            b = frame.get("body", {})
            print(f"[FILE_OFFER] from {frame.get('from')} name={b.get('name')} size={b.get('size')}")

        else:
            # Fallback: just dump the whole frame for visibility
            print(json.dumps(frame))


# -------------------------
# CLI (one-shot) operations
# -------------------------

async def run_cli(args: argparse.Namespace) -> None:
    """
    Minimal CLI client for quick testing:
      - 'members'     → list users known by the introducer
      - 'send'        → DM a user (RSA-encrypted + content signature)
      - 'send-group'  → post a signed message to a group
      - 'send-file'   → naive inline file transfer (hex-encoded chunks)
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

    # Re-import the private key (unencrypted PEM)
    from cryptography.hazmat.primitives import serialization
    my_privkey = serialization.load_pem_private_key(priv_pem, password=None)

    # Open a plain TCP connection to the introducer
    host, port = args.introducer.split(":")
    reader, writer = await asyncio.open_connection(host, int(port))

    # Say HELLO first so the introducer knows who we are
    hello = m.new_envelope(m.HELLO, from_id=args.ident or "cli")
    hello = m.sign(hello, my_privkey)  # content + transport (content is empty here)
    await write_frame(writer, hello)

    async def read_once_until(msg_type: str):
        """Block until a specific message type arrives, then return that frame."""
        while True:
            fr = await read_frame(reader)
            if fr.get("msg_type") == msg_type:
                return fr

    if args.command == "members":
        # Ask the introducer for its present view of members (with pubkeys)
        env = m.new_envelope(m.MEMBER_LIST_REQUEST, from_id=args.ident or "cli")
        env = m.sign(env, my_privkey)
        await write_frame(writer, env)
        resp = await read_once_until(m.MEMBER_LIST_RESPONSE)
        print(json.dumps(resp.get("body", {}).get("members", {}), indent=2))

    elif args.command == "send":
        # 1) Fetch member list so we can grab the recipient’s pubkey
        req = m.new_envelope(m.MEMBER_LIST_REQUEST, from_id=args.from_id)
        req = m.sign(req, my_privkey)
        await write_frame(writer, req)

        resp = await read_once_until(m.MEMBER_LIST_RESPONSE)
        members = resp.get("body", {}).get("members", {})

        if args.to not in members:
            raise SystemExit(f"Recipient {args.to} not found in introducer member list")

        # 2) Recipient’s public key (PEM→Base64url in our protocol)
        to_pub_b64 = members[args.to]["pubkey"]
        to_pub = crypto.import_pubkey_b64url(to_pub_b64)

        # 3) Encrypt a small plaintext with RSA-OAEP
        plaintext = " ".join(args.message).encode("utf-8")
        ciphertext_b64 = crypto.rsa_encrypt(to_pub, plaintext)

        # 4) Sender’s public key (goes in payload so the receiver can verify)
        sender_pub_b64 = crypto.export_pubkey_b64url(my_privkey.public_key())

        # 5) Compute content signature over canonical DM digest
        ts = int(time.time() * 1000)
        content_sig = crypto.sign(
            my_privkey,
            crypto.canonical_dm_content(ciphertext_b64, args.from_id, args.to, ts)
        )

        # 6) Build payload + envelope, then sign envelope for transport
        payload = {
            "ciphertext": ciphertext_b64,
            "sender_pub": sender_pub_b64,
            "content_sig": content_sig
        }

        env = m.new_envelope(m.DIRECT_MSG, from_id=args.from_id, to_id=args.to)
        env["body"] = {"payload": payload}
        env["ts"] = ts  # tie signature digest to a concrete timestamp
        env = m.sign_envelope(env, my_privkey)

        await write_frame(writer, env)

    elif args.command == "send-group":
        # Signed cleartext post to a group (no encryption, just integrity)
        env = m.new_envelope(m.GROUP_MSG, from_id=args.from_id, group=args.group)
        env["body"] = {"content_type": "text/plain", "content": args.message}
        # Sign content first (adds content_sig), then transport
        env = m.sign_content(env, my_privkey)
        env = m.sign(env, my_privkey)
        await write_frame(writer, env)

    elif args.command == "send-file":
        # Very simple inline file transfer; chunks are hex-encoded for portability.
        p = Path(args.path)
        size = p.stat().st_size
        offer = m.new_envelope(m.FILE_OFFER, from_id=args.from_id, to_id=args.to)
        offer["body"] = {"file_id": p.name, "name": p.name, "size": size, "chunk_size": 65536, "transfer_mode": "inline"}
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
                # NOTE: hex, not Base64; easy to debug and consistent across languages.
                chunk["body"] = {"file_id": p.name, "offset": sent, "data_b64": data.hex()}
                chunk = m.sign(chunk, my_privkey)
                await write_frame(writer, chunk)
                sent += len(data)

        done = m.new_envelope(m.FILE_COMPLETE, from_id=args.from_id, to_id=args.to)
        done["body"] = {"file_id": p.name}
        done = m.sign(done, my_privkey)
        await write_frame(writer, done)

    # Clean shutdown of the one-shot CLI connection
    writer.close()
    await writer.wait_closed()


# -------------------------
# Server peer runner
# -------------------------

async def run_server(server_id: str, introducer: Tuple[str, int], listen: Tuple[str, int]):
    """Register a server node with the introducer, then serve forever."""
    server = ServerNode(server_id, introducer, listen)
    await server.start()


# -------------------------
# Arg parsing + main entry
# -------------------------

def parse_args() -> argparse.Namespace:
    """
    Parse all modes + subcommands.

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

    return p.parse_args()


def main() -> None:
    """Dispatch into the chosen mode. Keeps top-level nice and small."""
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
