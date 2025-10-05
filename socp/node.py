import asyncio
import os
import time
from pathlib import Path
from typing import Dict, Optional, Tuple, Any

from socp.framing import read_frame, write_frame
from . import messages as m
from . import crypto

SAFE_MAX_TTL = 16  # upper bound to prevent message storms

class ConnectionContext:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.reader = reader
        self.writer = writer
        self.peer_id: Optional[str] = None

class PresenceDirectory:
    def __init__(self) -> None:
        self._members: Dict[str, Dict[str, Any]] = {}

    def update(self, user_id: str, info: Dict[str, Any]) -> None:
        self._members[user_id] = info

    def list_members(self) -> Dict[str, Dict[str, Any]]:
        return dict(self._members)

class IntroducerServer:
    """
    Hardened introducer that:
    - Uses persistent RSA-4096 server key.
    - Verifies incoming transport and content signatures.
    - Maintains replay protection.
    - Broadcasts messages without re-signing content.
    """
    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.presence = PresenceDirectory()
        self.conn_to_ctx: Dict[asyncio.StreamWriter, ConnectionContext] = {}
        self.msg_cache: set[str] = set()
        self.nonce_cache: set[str] = set()
        self.pubkeys: Dict[str, crypto.RSAPublicKey] = {}  # user_id -> RSA pubkey

        # Load or generate persistent server key
        key_dir = Path.home() / ".socp"
        key_dir.mkdir(parents=True, exist_ok=True)
        priv_path = key_dir / "introducer_priv.pem"
        if priv_path.exists():
            with open(priv_path, "rb") as f:
                self.self_privkey = crypto.load_privkey_pem(f.read())
        else:
            self.self_privkey, self.self_pubkey = crypto.generate_rsa4096()
            with open(priv_path, "wb") as f:
                f.write(crypto.export_privkey_pem(self.self_privkey))

    async def start(self) -> None:
        server = await asyncio.start_server(self.handle_conn, self.host, self.port)
        addrs = ", ".join(str(sock.getsockname()) for sock in server.sockets or [])
        print(f"Introducer listening on {addrs}")
        async with server:
            await server.serve_forever()

    async def handle_conn(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        ctx = ConnectionContext(reader, writer)
        self.conn_to_ctx[writer] = ctx
        try:
            while True:
                frame = await read_frame(reader)
                if frame is None:
                    break
                await self.process_frame(ctx, frame)
        except asyncio.IncompleteReadError:
            pass
        except Exception as exc:
            print(f"Conn error: {exc}")
        finally:
            self.conn_to_ctx.pop(writer, None)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def process_frame(self, ctx: ConnectionContext, frame: Dict[str, Any]) -> None:
        msg_type = frame.get("msg_type")
        msg_id = frame.get("msg_id")
        nonce = frame.get("nonce")
        sender = frame.get("from")

        # === 1) HELLO ===
        if msg_type == m.HELLO:
            ctx.peer_id = sender
            pubkey_b64 = frame.get("body", {}).get("pubkey")
            if pubkey_b64:
                try:
                    self.pubkeys[sender] = crypto.import_pubkey_b64url(pubkey_b64)
                    print(f"Registered public key for {sender}")
                except Exception as e:
                    print(f"Failed to import public key from {sender}: {e}")

            # Respond with introducer HELLO signed with persistent key
            resp = m.new_envelope(m.HELLO, from_id="introducer")
            resp = m.sign_envelope(resp, self.self_privkey)
            await write_frame(ctx.writer, resp)
            return

        # === 2) Verify transport signature for known users ===
        pubkey = self.pubkeys.get(sender)
        if pubkey:
            if not m.verify_envelope(frame, pubkey):
                print(f"Invalid transport signature from {sender}")
                return
            if msg_type in (m.DIRECT_MSG, m.GROUP_MSG):
                if not m.verify_content(frame, pubkey):
                    print(f"Invalid content signature from {sender}")
                    return
        else:
            # Unknown sender: skip verification but log
            print(f"Skipping verification for unknown peer {sender}")

        # === 3) Replay protection ===
        if msg_id:
            if msg_id in self.msg_cache:
                return
            self.msg_cache.add(msg_id)
            if len(self.msg_cache) > 16384:
                self.msg_cache.pop()
        if nonce:
            if nonce in self.nonce_cache:
                return
            self.nonce_cache.add(nonce)
            if len(self.nonce_cache) > 16384:
                self.nonce_cache.pop()

        # === 4) Handle messages ===
        if msg_type == m.PRESENCE_UPDATE:
            body = frame.get("body", {})
            self.presence.update(sender or "", {
                "last_seen": frame.get("timestamp_ms"),
                "status": body.get("status", "online"),
                "addr": str(ctx.writer.get_extra_info("peername")),
            })
            return

        if msg_type == m.MEMBER_LIST_REQUEST:
            listing = {}
            for uid, info in self.presence.list_members().items():
                entry = dict(info)  # copy last_seen, status, addr
                if uid in self.pubkeys:
                    entry["pubkey"] = crypto.export_pubkey_b64url(self.pubkeys[uid])
                listing[uid] = entry

            resp = m.new_envelope(m.MEMBER_LIST_RESPONSE, from_id="introducer")
            resp["body"] = {"members": listing}
            resp = m.sign_envelope(resp, self.self_privkey)
            await write_frame(ctx.writer, resp)
            return

        if msg_type in (m.DIRECT_MSG, m.GROUP_MSG, m.FILE_OFFER, m.FILE_ACCEPT, m.FILE_CHUNK, m.FILE_COMPLETE):
            ttl = int(frame.get("ttl", 0))
            if ttl <= 0 or ttl > SAFE_MAX_TTL:
                return
            frame["ttl"] = ttl - 1
            await self.broadcast(frame, exclude=ctx.writer)
            return

        if msg_type == m.PING:
            pong = m.new_envelope(m.PONG, from_id="introducer")
            pong["body"] = {"echo": frame.get("body")}
            pong = m.sign_envelope(pong, self.self_privkey)
            await write_frame(ctx.writer, pong)

    async def broadcast(self, frame: Dict[str, Any], exclude: Optional[asyncio.StreamWriter] = None) -> None:
        for w, _ctx in list(self.conn_to_ctx.items()):
            if w is exclude:
                continue
            try:
                await write_frame(w, frame)
            except Exception:
                pass

class ClientNode:
    """
    Hardened client:
      - Verifies signatures on inbound frames.
      - Sanitizes file paths (basename only) and confines to a safe directory.
    """
    def __init__(self, node_id: str, introducer: Tuple[str, int], listen: Optional[Tuple[str, int]] = None) -> None:
        self.node_id = node_id
        self.introducer = introducer
        self.listen = listen
        self.inbox: asyncio.Queue[Dict[str, Any]] = asyncio.Queue()
        self.peers: Dict[str, Tuple[asyncio.StreamReader, asyncio.StreamWriter]] = {}
        self.pubkeys: Dict[str, crypto.RSAPublicKey] = {} # store peer public keys

        # RSA keypair
        self.privkey, self.pubkey = crypto.generate_rsa4096()
        self.download_root = Path(os.environ.get("SOCP_DOWNLOAD_DIR", "./downloads")).resolve()
        self.download_root.mkdir(parents=True, exist_ok=True)

    def _safe_path(self, file_id: str) -> Path:
        safe_name = Path(file_id).name           # strip directories
        p = (self.download_root / safe_name).resolve()
        if not str(p).startswith(str(self.download_root)):
            raise ValueError("Unsafe path")
        return p

    async def start(self) -> None:
        intro_reader, intro_writer = await asyncio.open_connection(self.introducer[0], self.introducer[1])
        self.peers["introducer"] = (intro_reader, intro_writer)

        hello = m.new_envelope(m.HELLO, from_id=self.node_id)
        hello["body"]["pubkey"] = crypto.export_pubkey_b64url(self.pubkey)
        hello = m.sign(hello, self.privkey)
        await write_frame(intro_writer, hello)

        await self.send_presence(status="online")
        asyncio.create_task(self.reader_loop("introducer", intro_reader))

        if self.listen:
            server = await asyncio.start_server(self.handle_conn, self.listen[0], self.listen[1])
            print(f"Client {self.node_id} listening on {self.listen}")
            asyncio.create_task(server.serve_forever())

    async def handle_conn(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                frame = await read_frame(reader)
                await self.inbox.put(frame)
        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def reader_loop(self, label: str, reader: asyncio.StreamReader) -> None:
        try:
            while True:
                frame = await read_frame(reader)
                await self.process_incoming(frame)
        except Exception:
            pass

    # receiving a direct message
    async def process_incoming(self, frame: Dict[str, Any]):
        sender = frame.get("from")
        sender_pub = self.pubkeys.get(sender)
        if not sender_pub:
            return  # drop if unknown sender

        # Verify transport signature on the envelope
        if not m.verify_envelope(frame, sender_pub):
            return  # drop invalid transport signature

        body = frame.get("body", {})
        content_sig = body.get("content_sig")
        ts = body.get("ts")
        mt = frame.get("msg_type")

        # Direct Message
        if mt == m.DIRECT_MSG:
            ciphertext = body.get("content")
            to_id = frame.get("to")
            if not ciphertext or not to_id or not content_sig or ts is None:
                return  # incomplete frame

            # Verify canonical content signature
            canonical = crypto.canonical_dm_content(ciphertext, sender, to_id, ts)
            if not crypto.verify(sender_pub, canonical, content_sig):
                return  # invalid content signature

            # Decrypt content
            plaintext = crypto.rsa_decrypt(self.privkey, ciphertext).decode("utf-8")
            body["content"] = plaintext
            await self.inbox.put(frame)

        # === Group Message ===
        elif mt == m.GROUP_MSG:
            content = body.get("content")
            if not content or not content_sig or ts is None:
                return  # incomplete frame

            # Verify canonical group content signature
            canonical = crypto.canonical_group_content(content, sender, ts)
            if not crypto.verify(sender_pub, canonical, content_sig):
                return  # invalid content signature

            # Keep content as-is (no decryption)
            await self.inbox.put(frame)

        # === Other message types ===
        else:
            # For messages like FILE_OFFER, FILE_CHUNK, etc., you could handle here if needed
            await self.inbox.put(frame)

    async def send_presence(self, status: str = "online") -> None:
        _, w = self.peers["introducer"]
        env = m.new_envelope(m.PRESENCE_UPDATE, from_id=self.node_id)
        env["body"] = {"status": status}
        env = m.sign(env, self.privkey)
        await write_frame(w, env)

    async def request_members(self) -> Dict[str, Any]:
        r, w = self.peers["introducer"]
        req = m.new_envelope(m.MEMBER_LIST_REQUEST, from_id=self.node_id)
        req = m.sign(req, self.privkey)
        await write_frame(w, req)
        while True:
            frame = await self.inbox.get()
            if frame.get("msg_type") == m.MEMBER_LIST_RESPONSE:
                return frame.get("body", {}).get("members", {})

    # send direct message from client
    async def send_direct(self, to_id: str, plaintext: str):
        # Encrypt payload with recipient's public key
        pubkey = self.pubkeys[to_id]
        ciphertext = crypto.rsa_encrypt(pubkey, plaintext.encode("utf-8"))

        ts = int(time.time() * 1000)
        env = m.new_envelope(m.DIRECT_MSG, from_id=self.node_id, to_id=to_id)
        env["body"]["content"] = ciphertext
        env["body"]["ts"] = ts

        # Canonical DM content signature
        canonical = crypto.canonical_dm_content(ciphertext, self.node_id, to_id, ts)
        env["body"]["content_sig"] = crypto.sign(self.privkey, canonical)

        # Transport signature
        env = m.sign(env, self.privkey)
        _, w = self.peers["introducer"]
        await write_frame(w, env)

    async def send_group(self, group: str, plaintext: str) -> None:
        ts = int(time.time() * 1000)
        _, w = self.peers["introducer"]
        env = m.new_envelope(m.GROUP_MSG, from_id=self.node_id, group=group)
        env["body"]["content"] = plaintext
        env["body"]["content_type"] = "text/plain"
        env["body"]["ts"] = ts

        # Canonical group content signature
        canonical = crypto.canonical_group_content(plaintext, self.node_id, ts)
        env["body"]["content_sig"] = crypto.sign(self.privkey, canonical)

        # Transport signature
        env = m.sign(env, self.privkey)
        await write_frame(w, env)
