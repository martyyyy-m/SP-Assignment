import argparse
import asyncio
import json
import os
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
    client = ClientNode(node_id, introducer, listen)
    await client.start()
    print(f"Client {node_id} connected to introducer {introducer}")
    while True:
        frame = await client.inbox.get()
        mt = frame.get("msg_type")
        if mt in (m.DIRECT_MSG, m.GROUP_MSG):
            print(f"[{mt}] {frame.get('from')} -> {frame.get('to') or frame.get('group')}: {frame.get('body', {}).get('content')}")
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
        to_pub = crypto.import_pubkey_b64url(args.to_pubkey)
        encrypted = crypto.rsa_encrypt(to_pub, args.message.encode("utf-8"))

        env = m.new_envelope(m.DIRECT_MSG, from_id=args.from_id, to_id=args.to)
        env["body"]["content"] = encrypted
        env = m.sign_content(env, my_privkey)  # content signature
        env = m.sign(env, my_privkey)          # transport signature

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
    sp.add_argument(
    "--to_pubkey",
    required=True,
    help="Recipient's RSA public key in base64url format"
)

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

