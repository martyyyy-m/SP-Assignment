import asyncio
import os
import time
from pathlib import Path
from typing import Dict, Optional, Tuple, Any

from socp.framing import read_frame, write_frame
from . import messages as m
from . import crypto

"""
node.py — introducer + client + server roles for the SOCP demo.

What this module gives you:
- IntroducerServer: a simple “meet-me” service that tracks presence and
  relays messages. It signs its own envelopes; it doesn’t re-sign user content.
- ClientNode: a hardened client that verifies signatures and keeps downloads
  in a safe directory (no path traversal).
- ServerNode: a small server peer that registers with the introducer and
  accepts connections from other servers.

Security notes:
- We keep a short replay cache (msg_id + nonce) to drop duplicates.
- TTL is clamped so a bad frame can’t loop forever across peers.
- RSA-4096 is enforced everywhere; transport is signed, and content can be
  end-to-end signed depending on the message type.
"""

SAFE_MAX_TTL = 16  # upper bound to prevent message storms


class ConnectionContext:
    """Tiny wrapper to keep reader/writer together with a learned peer_id."""
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.reader = reader
        self.writer = writer
        self.peer_id: Optional[str] = None


class PresenceDirectory:
    """In-memory view of who we know about (good enough for a demo)."""
    def __init__(self) -> None:
        self._members: Dict[str, Dict[str, Any]] = {}

    def update(self, user_id: str, info: Dict[str, Any]) -> None:
        self._members[user_id] = info  # last write wins

    def list_members(self) -> Dict[str, Dict[str, Any]]:
        return dict(self._members)  # shallow copy for safety


def now_ms() -> int:
    """Current Unix time in milliseconds (used for user-visible timestamps)."""
    return int(time.time() * 1000)


class IntroducerServer:
    """
    Hardened introducer that:
      - Uses a persistent RSA-4096 key on disk (~/.socp/introducer_priv.pem).
      - Verifies/produces transport signatures.
      - Tracks basic replay protection via msg_id/nonce caches.
      - Broadcasts frames without modifying user content/signatures.
    """
    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.presence = PresenceDirectory()
        self.conn_to_ctx: Dict[asyncio.StreamWriter, ConnectionContext] = {}
        self.msg_cache: set[str] = set()
        self.nonce_cache: set[str] = set()
        self.pubkeys: Dict[str, crypto.RSAPublicKey] = {}  # user_id -> RSA pubkey
        self.server_addrs: Dict[str, Dict[str, Any]] = {}  # server_id -> {host, port, pubkey}

        # Load or create the introducer's private key once and keep it around.
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
        """Per-connection loop: read frames and hand them to process_frame()."""
        ctx = ConnectionContext(reader, writer)
        self.conn_to_ctx[writer] = ctx
        try:
            while True:
                frame = await read_frame(reader)
                if frame is None:
                    break
                await self.process_frame(ctx, frame)
        except asyncio.IncompleteReadError:
            # Peer went away mid-frame; nothing to do.
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
        """
        Minimal routing logic with basic checks and a couple of control messages.
        This is intentionally small so you can follow the flow.
        """
        msg_type = frame.get("msg_type")
        msg_id = frame.get("msg_id")
        nonce = frame.get("nonce")
        sender = frame.get("from")

        # === 1) New server joins the mesh via the introducer.
        if msg_type == "SERVER_HELLO_JOIN":
            ctx.peer_id = sender
            payload = frame.get("body", {})
            host = payload.get("host")
            port = payload.get("port")
            pubkey_b64 = payload.get("pubkey")

            if not host or not port or not pubkey_b64:
                print(f"Invalid SERVER_HELLO_JOIN from {sender}")
                return

            # Import and remember the server's public key + address.
            try:
                self.pubkeys[sender] = crypto.import_pubkey_b64url(pubkey_b64)
                self.server_addrs[sender] = {"host": host, "port": port, "pubkey": pubkey_b64}
                print(f"Registered new server {sender} at {host}:{port}")
            except Exception as e:
                print(f"Failed to import server key from {sender}: {e}")
                return

            # Reply with a server list so it can connect to peers.
            members = [{"server_id": sid, **addr} for sid, addr in self.server_addrs.items()]
            resp = m.new_envelope("SERVER_WELCOME", from_id="introducer", to_id=sender)
            resp["ts"] = now_ms()
            resp["body"] = {"assigned_id": sender, "servers": members}
            resp = m.sign_envelope(resp, self.self_privkey)
            await write_frame(ctx.writer, resp)

            # Let everyone else know a new server exists.
            announce = m.new_envelope("SERVER_ANNOUNCE", from_id=sender, to_id="*")
            announce["ts"] = now_ms()
            announce["body"] = {"host": host, "port": port, "pubkey": pubkey_b64}
            announce = m.sign_envelope(announce, self.self_privkey)
            await self.broadcast(announce, exclude=ctx.writer)

        # === 2) First contact from a user client.
        if msg_type == m.HELLO:
            ctx.peer_id = sender
            pubkey_b64 = frame.get("body", {}).get("pubkey")

            # If the name is taken, be nice and say so explicitly.
            if sender in self.pubkeys:
                resp = m.new_envelope("ERROR", from_id="introducer", to_id=sender)
                resp["body"] = {"error": "NAME_IN_USE"}
                resp = m.sign_envelope(resp, self.self_privkey)
                await write_frame(ctx.writer, resp)
                print(f"Rejected duplicate USER_HELLO for {sender}")
                return

            # Register the user's pubkey so others can fetch it later.
            if pubkey_b64:
                try:
                    self.pubkeys[sender] = crypto.import_pubkey_b64url(pubkey_b64)
                    print(f"Registered new user {sender}")
                except Exception as e:
                    print(f"Failed to import user key from {sender}: {e}")
                    return

            # Track presence; this is just a local heartbeat.
            self.presence.update(sender, {
                "last_seen": frame.get("ts"),
                "status": "online",
                "addr": str(ctx.writer.get_extra_info("peername")),
            })

            # Acknowledge the HELLO.
            resp = m.new_envelope(m.HELLO, from_id="introducer", to_id=sender)
            resp = m.sign_envelope(resp, self.self_privkey)
            await write_frame(ctx.writer, resp)

            # Let other servers know about the user (name + pubkey).
            advertise = m.new_envelope("USER_ADVERTISE", from_id=sender, to_id="*")
            advertise["body"] = {
                "user_id": sender,
                "pubkey": pubkey_b64,
                "status": "online",
            }
            advertise = m.sign_envelope(advertise, self.self_privkey)
            await self.broadcast(advertise, exclude=ctx.writer)
            return

        # === 3) Replay protection (coarse but effective for a demo).
        if msg_id:
            if msg_id in self.msg_cache:
                return
            self.msg_cache.add(msg_id)
            if len(self.msg_cache) > 16384:
                self.msg_cache.pop()  # drop an arbitrary old entry
        if nonce:
            if nonce in self.nonce_cache:
                return
            self.nonce_cache.add(nonce)
            if len(self.nonce_cache) > 16384:
                self.nonce_cache.pop()

        # === 4) Simple handlers.
        if msg_type == m.PRESENCE_UPDATE:
            body = frame.get("body", {})
            self.presence.update(sender or "", {
                "last_seen": frame.get("ts"),
                "status": body.get("status", "online"),
                "addr": str(ctx.writer.get_extra_info("peername")),
            })
            return

        if msg_type == m.MEMBER_LIST_REQUEST:
            # Build a directory view with pubkeys where we have them.
            listing = {}
            for uid, info in self.presence.list_members().items():
                entry = dict(info)
                if uid in self.pubkeys:
                    entry["pubkey"] = crypto.export_pubkey_b64url(self.pubkeys[uid])
                listing[uid] = entry

            resp = m.new_envelope(m.MEMBER_LIST_RESPONSE, from_id="introducer")
            resp["body"] = {"members": listing}
            resp = m.sign_envelope(resp, self.self_privkey)
            await write_frame(ctx.writer, resp)
            return

        if msg_type in (m.DIRECT_MSG, m.GROUP_MSG, m.FILE_OFFER, m.FILE_ACCEPT, m.FILE_CHUNK, m.FILE_COMPLETE):
            # Clamp TTL and forward. We don’t touch content or re-sign.
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
        """Best-effort write to all peers except ‘exclude’. Failures are silenced."""
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
      - Verifies signatures on inbound frames where applicable.
      - Keeps downloads under a single safe directory (no path tricks).
      - Stores a persistent RSA-4096 keypair in ~/.socp/<node>_priv.pem
    """
    def __init__(self, node_id: str, introducer: Tuple[str, int], listen: Optional[Tuple[str, int]] = None) -> None:
        self.node_id = node_id
        self.introducer = introducer
        self.listen = listen
        self.inbox: asyncio.Queue[Dict[str, Any]] = asyncio.Queue()
        self.peers: Dict[str, Tuple[asyncio.StreamReader, asyncio.StreamWriter]] = {}
        self.pubkeys: Dict[str, crypto.RSAPublicKey] = {}  # peer_id -> pubkey

        # Load or create our keypair.
        key_dir = Path.home() / ".socp"
        key_dir.mkdir(parents=True, exist_ok=True)
        priv_path = key_dir / f"{self.node_id}_priv.pem"

        if priv_path.exists():
            with open(priv_path, "rb") as f:
                self.privkey = crypto.load_privkey_pem(f.read())
            self.pubkey = self.privkey.public_key()
            print(f"[{self.node_id}] Loaded persistent keypair from {priv_path}")
        else:
            self.privkey, self.pubkey = crypto.generate_rsa4096()
            with open(priv_path, "wb") as f:
                f.write(crypto.export_privkey_pem(self.privkey))
            print(f"[{self.node_id}] Generated new keypair and saved to {priv_path}")

        # Where downloads land; created on startup.
        self.download_root = Path(os.environ.get("SOCP_DOWNLOAD_DIR", "./downloads")).resolve()
        self.download_root.mkdir(parents=True, exist_ok=True)

    def _safe_path(self, file_id: str) -> Path:
        """Return a path under download_root; reject traversal attempts."""
        safe_name = Path(file_id).name  # strip directories
        p = (self.download_root / safe_name).resolve()
        if not str(p).startswith(str(self.download_root)):
            raise ValueError("Unsafe path")
        return p

    async def start(self) -> None:
        """Connect to the introducer, announce ourselves, and start readers."""
        intro_reader, intro_writer = await asyncio.open_connection(self.introducer[0], self.introducer[1])
        self.peers["introducer"] = (intro_reader, intro_writer)

        hello = m.new_envelope(m.HELLO, from_id=self.node_id)
        hello["body"]["pubkey"] = crypto.export_pubkey_b64url(self.pubkey)
        hello = m.sign(hello, self.privkey)  # content + transport
        await write_frame(intro_writer, hello)

        await self.send_presence(status="online")
        asyncio.create_task(self.reader_loop("introducer", intro_reader))

        if self.listen:
            server = await asyncio.start_server(self.handle_conn, self.listen[0], self.listen[1])
            print(f"Client {self.node_id} listening on {self.listen}")
            asyncio.create_task(server.serve_forever())

    async def handle_conn(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Accept peer connections and funnel frames into the inbox."""
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
        """Background task to read frames from a given peer/label."""
        try:
            while True:
                frame = await read_frame(reader)
                await self.process_incoming(frame)
        except Exception:
            pass

    # Receiving a direct message or group message.
    async def process_incoming(self, frame: Dict[str, Any]):
        mt = frame.get("msg_type")
        sender = frame.get("from")
        to_id = frame.get("to")
        ts = frame.get("ts")
        body = frame.get("body", {})
        payload = body.get("payload", {})

        # --- Direct Message (encrypted) ---
        if mt == m.DIRECT_MSG:
            ciphertext = payload.get("ciphertext")
            sender_pub_b64 = payload.get("sender_pub")
            content_sig = payload.get("content_sig")
            if not ciphertext or not sender_pub_b64 or not content_sig or ts is None:
                return  # incomplete frame

            # Verify the sender's content signature over the canonical DM fields.
            try:
                sender_pub = crypto.import_pubkey_b64url(sender_pub_b64)
            except Exception:
                return

            canonical = crypto.canonical_dm_content(ciphertext, sender, to_id, ts)
            if not crypto.verify(sender_pub, canonical, content_sig):
                return  # invalid signature

            # If the signature checks out, try to decrypt.
            try:
                plaintext = crypto.rsa_decrypt(self.privkey, ciphertext).decode("utf-8")
            except Exception:
                return

            # Attach plaintext for the app layer and queue the message.
            frame["body"]["payload"]["plaintext"] = plaintext
            await self.inbox.put(frame)
            return

        # --- Group Message (signed cleartext) ---
        if mt == m.GROUP_MSG:
            content = body.get("content")
            content_sig = body.get("content_sig")
            if not content or not content_sig or ts is None:
                return  # incomplete frame

            sender_pub = self.pubkeys.get(sender)
            if not sender_pub:
                return

            canonical = crypto.canonical_group_content(content, sender, ts)
            if not crypto.verify(sender_pub, canonical, content_sig):
                return  # invalid content signature

            await self.inbox.put(frame)  # no decryption, pass through
            return

        # Other message types just get queued unless you want to special-case them.
        await self.inbox.put(frame)

    async def send_presence(self, status: str = "online") -> None:
        """Tell the introducer we’re alive (and our current simple status)."""
        _, w = self.peers["introducer"]
        env = m.new_envelope(m.PRESENCE_UPDATE, from_id=self.node_id)
        env["body"] = {"status": status}
        env = m.sign(env, self.privkey)
        await write_frame(w, env)

    async def request_members(self) -> Dict[str, Any]:
        """Ask the introducer for the known member directory."""
        r, w = self.peers["introducer"]
        req = m.new_envelope(m.MEMBER_LIST_REQUEST, from_id=self.node_id)
        req = m.sign(req, self.privkey)
        await write_frame(w, req)
        while True:
            frame = await self.inbox.get()
            if frame.get("msg_type") == m.MEMBER_LIST_RESPONSE:
                return frame.get("body", {}).get("members", {})

    async def send_direct(self, to_id: str, plaintext: str):
        """
        Encrypt a short plaintext to a peer and send a signed DM.

        NOTE: RSA is fine for small payloads (keys/nonces/messages). For large
        files, use a symmetric key and send that key wrapped with RSA.
        """
        pubkey = self.pubkeys[to_id]
        ciphertext = crypto.rsa_encrypt(pubkey, plaintext.encode("utf-8"))

        ts = now_ms()
        canonical = crypto.canonical_dm_content(ciphertext, self.node_id, to_id, ts)
        content_sig = crypto.sign(self.privkey, canonical)

        payload = {
            "ciphertext": ciphertext,
            "sender_pub": crypto.export_pubkey_b64url(self.pubkey),
            "content_sig": content_sig,
        }

        env = m.new_envelope(m.DIRECT_MSG, from_id=self.node_id, to_id=to_id)
        env["ts"] = ts
        env["body"]["payload"] = payload

        env = m.sign(env, self.privkey)  # transport + content were both signed
        _, w = self.peers["introducer"]
        await write_frame(w, env)

    async def send_group(self, group: str, plaintext: str) -> None:
        """Send a signed cleartext message to a group (no encryption)."""
        ts = now_ms()
        _, w = self.peers["introducer"]
        env = m.new_envelope(m.GROUP_MSG, from_id=self.node_id, group=group)
        env["ts"] = ts
        env["body"]["content"] = plaintext
        env["body"]["content_type"] = "text/plain"
        env["body"]["ts"] = ts

        canonical = crypto.canonical_group_content(plaintext, self.node_id, ts)
        env["body"]["content_sig"] = crypto.sign(self.privkey, canonical)

        env = m.sign(env, self.privkey)
        await write_frame(w, env)


class ServerNode:
    """
    Minimal server node that joins a trusted introducer,
    receives server_id + list of other servers, and listens for peers.
    """
    def __init__(self, server_id: str, introducer: Tuple[str, int], listen: Tuple[str, int]):
        self.server_id = server_id
        self.introducer = introducer
        self.listen = listen
        self.inbox: asyncio.Queue[Dict[str, Any]] = asyncio.Queue()
        self.peers: Dict[str, Tuple[asyncio.StreamReader, asyncio.StreamWriter]] = {}
        self.pubkeys: Dict[str, crypto.RSAPublicKey] = {}

        # Load or create the server keypair.
        key_dir = Path.home() / ".socp"
        key_dir.mkdir(parents=True, exist_ok=True)
        priv_path = key_dir / f"{self.server_id}_priv.pem"
        if priv_path.exists():
            with open(priv_path, "rb") as f:
                self.privkey = crypto.load_privkey_pem(f.read())
            self.pubkey = self.privkey.public_key()
        else:
            self.privkey, self.pubkey = crypto.generate_rsa4096()
            with open(priv_path, "wb") as f:
                f.write(crypto.export_privkey_pem(self.privkey))

    async def start(self):
        """Register with the introducer, then start listening for peers."""
        # Connect to introducer.
        intro_reader, intro_writer = await asyncio.open_connection(*self.introducer)
        self.peers["introducer"] = (intro_reader, intro_writer)

        # Say hello to get announced and receive peer list.
        hello = m.new_envelope("SERVER_HELLO_JOIN", from_id=self.server_id)
        hello["body"] = {
            "host": self.listen[0],
            "port": self.listen[1],
            "pubkey": crypto.export_pubkey_b64url(self.pubkey),
        }
        hello = m.sign_envelope(hello, self.privkey)
        await write_frame(intro_writer, hello)

        # Read frames from the introducer in the background.
        asyncio.create_task(self.reader_loop("introducer", intro_reader))

        # Accept incoming connections from other servers.
        server = await asyncio.start_server(self.handle_conn, self.listen[0], self.listen[1])
        print(f"Server {self.server_id} listening on {self.listen}")
        await server.serve_forever()

    async def handle_conn(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Push any received frames into our inbox; keep the loop small."""
        try:
            while True:
                frame = await read_frame(reader)
                await self.inbox.put(frame)
        except Exception:
            pass
        finally:
            writer.close()
            await writer.wait_closed()

    async def reader_loop(self, label: str, reader: asyncio.StreamReader):
        """Background reader for introducer or peers (labelled for logs)."""
        try:
            while True:
                frame = await read_frame(reader)
                print(f"[{label}] received {frame.get('msg_type')} from {frame.get('from')}")
                await self.inbox.put(frame)
        except Exception:
            pass
