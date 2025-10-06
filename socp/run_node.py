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

# Same interface as the vulnerable build, but without admin/backdoor commands.


async def run_introducer(host: str, port: int) -> None:
    server = IntroducerServer(host, port)
    await server.start()


async def run_client(node_id: str, introducer: Tuple[str, int], listen: Tuple[str, int] | None) -> None:
    # Create client node
    client = ClientNode(node_id, introducer, listen)
    await client.start()
    print(f"Client {node_id} connected to introducer {introducer}")

    # Load private key for decrypting messages
    priv_path = Path.home() / ".socp" / f"{node_id}_priv.pem"
    if not priv_path.exists():
        raise SystemExit(f"Private key for {node_id} not found at {priv_path}")

    with open(priv_path, "rb") as f:
        priv_pem = f.read()
    my_privkey = serialization.load_pem_private_key(priv_pem, password=None)

    while True:
        frame = await client.inbox.get()
        mt = frame.get("msg_type")

        if mt == m.DIRECT_MSG:
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

                # Verify content signature
                valid = crypto.verify(
                    sender_pub,
                    crypto.canonical_dm_content(ciphertext_b64, sender, node_id, ts),
                    content_sig
                )

                if not valid:
                    print(f"[DIRECT_MSG] {sender} -> {node_id}: <invalid content signature>")
                    continue

                # Decrypt ciphertext
                try:
                    plaintext = crypto.rsa_decrypt(my_privkey, ciphertext_b64)
                    print(f"[DIRECT_MSG] {sender} -> {node_id}: {plaintext.decode('utf-8')}")
                except Exception as e:
                    print(f"[DIRECT_MSG] {sender} -> {node_id}: <failed to decrypt: {e}>")

        elif mt == m.GROUP_MSG:
            sender = frame.get("from")
            group = frame.get("group")
            content = frame.get("body", {}).get("content")
            print(f"[GROUP_MSG] {sender} -> {group}: {content}")

        elif mt == m.FILE_OFFER:
            b = frame.get("body", {})
            print(f"[FILE_OFFER] from {frame.get('from')} name={b.get('name')} size={b.get('size')}")

        else:
            print(json.dumps(frame))

async def run_cli(args: argparse.Namespace) -> None:
    priv_path = os.environ.get("SOCP_PRIVKEY_PATH")
    if not priv_path:
        ident = args.ident or "cli"
        priv_path = str(Path.home() / ".socp" / f"{ident}_priv.pem")

    if not Path(priv_path).exists():
        raise SystemExit(f"Private key not found at {priv_path}. Generate or set SOCP_PRIVKEY_PATH.")

    with open(priv_path, "rb") as f:
        priv_pem = f.read()

    from cryptography.hazmat.primitives import serialization
    my_privkey = serialization.load_pem_private_key(priv_pem, password=None)

    host, port = args.introducer.split(":")
    reader, writer = await asyncio.open_connection(host, int(port))

    # Send HELLO
    hello = m.new_envelope(m.HELLO, from_id=args.ident or "cli")
    hello = m.sign(hello, my_privkey)
    await write_frame(writer, hello)

    async def read_once_until(msg_type: str):
        while True:
            fr = await read_frame(reader)
            if fr.get("msg_type") == msg_type:
                return fr

    if args.command == "members":
        env = m.new_envelope(m.MEMBER_LIST_REQUEST, from_id=args.ident or "cli")
        env = m.sign(env, my_privkey)
        await write_frame(writer, env)
        resp = await read_once_until(m.MEMBER_LIST_RESPONSE)
        print(json.dumps(resp.get("body", {}).get("members", {}), indent=2))

    elif args.command == "send":
        # Fetch member list from introducer
        req = m.new_envelope(m.MEMBER_LIST_REQUEST, from_id=args.from_id)
        req = m.sign(req, my_privkey)
        await write_frame(writer, req)

        # Wait for member list response
        resp = await read_once_until(m.MEMBER_LIST_RESPONSE)
        members = resp.get("body", {}).get("members", {})

        if args.to not in members:
            raise SystemExit(f"Recipient {args.to} not found in introducer member list")

        # Recipient's public key
        to_pub_b64 = members[args.to]["pubkey"]
        to_pub = crypto.import_pubkey_b64url(to_pub_b64)

        # Encrypt the plaintext
        plaintext = " ".join(args.message).encode("utf-8")
        ciphertext_b64 = crypto.rsa_encrypt(to_pub, plaintext)

        # Sender's public key
        sender_pub_b64 = crypto.export_pubkey_b64url(my_privkey.public_key())

        # Compute content signature (over ciphertext || from || to || ts)
        ts = int(time.time() * 1000)
        content_sig = crypto.sign(
            my_privkey,
            crypto.canonical_dm_content(ciphertext_b64, args.from_id, args.to, ts)
        )

        # Build payload
        payload = {
            "ciphertext": ciphertext_b64,
            "sender_pub": sender_pub_b64,
            "content_sig": content_sig
        }

        # Build envelope with correct from/to and payload
        env = m.new_envelope(m.DIRECT_MSG, from_id=args.from_id, to_id=args.to)
        env["body"] = {"payload": payload}
        env["ts"] = ts  # ensure timestamp is included

        # Sign envelope for transport
        env = m.sign_envelope(env, my_privkey)

        # Send
        await write_frame(writer, env)

    elif args.command == "send-group":
        env = m.new_envelope(m.GROUP_MSG, from_id=args.from_id, group=args.group)
        env["body"] = {"content_type": "text/plain", "content": args.message}
        env = m.sign_content(env, my_privkey)
        env = m.sign(env, my_privkey)
        await write_frame(writer, env)

    elif args.command == "send-file":
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
                chunk["body"] = {"file_id": p.name, "offset": sent, "data_b64": data.hex()}
                chunk = m.sign(chunk, my_privkey)
                await write_frame(writer, chunk)
                sent += len(data)

        done = m.new_envelope(m.FILE_COMPLETE, from_id=args.from_id, to_id=args.to)
        done["body"] = {"file_id": p.name}
        done = m.sign(done, my_privkey)
        await write_frame(writer, done)

    writer.close()
    await writer.wait_closed()

async def run_server(server_id: str, introducer: Tuple[str, int], listen: Tuple[str, int]):
    server = ServerNode(server_id, introducer, listen)
    await server.start()

def parse_args() -> argparse.Namespace:
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
