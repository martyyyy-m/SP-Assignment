SOCP Chat Prototype (Python asyncio)

Group Members:
1. Preseia Reyes (A1852631)
2. Martin Mohanan (A1933931)
3. Ami Mevada (A1994216)
4. Jasjot Singh (A1959543)
5. Heet Parmeshwar Patel (A1963465)

Overview
This is a minimal, interoperable-style prototype of the overlay multi-party chat system described in the SOCP brief. It implements:
- Listing members (presence registry)
- Private (direct) and group messages
- Point-to-point file transfer over existing connections
- Length-prefixed JSON framing
- Simple overlay routing via a relay/introducer node

Security Model (Prototype)
- Transport: plaintext TCP with length-prefixed JSON frames (for simplicity).
- Authentication: none by default; messages carry claimed identities. This is sufficient for interop prototyping and lab use. In a production-leaning build, wrap connections in TLS and add signed tokens.
- Basic replay/loop defenses: message ID cache for most types, TTL decrement on forward.

We have implemented two Intentional Vulnerabilities (Backdoors) in this project

Ethical Scope
- No filesystem or OS access outside this application. Exploits only affect the running node’s behavior (presence and message attribution).

Quick Start
1) Requirements
   - Python 3.10+
   - See requirements.txt

2) Install
   - Option A (pip):
     pip install -r requirements.txt

3) IMPORTANT: run all commands from the project root directory
   - Example Windows PowerShell prompt should show: C:\desktop2\SP-Assignment>

4) Start an introducer/relay node (acts as directory + router)
   python3 -m socp.run_node --mode introducer --host 127.0.0.1 --port 9000

5) Start a server
  # Terminal 1
  python3 -m socp.run_node --mode server --id server_1 --introducer 127.0.0.1:9000 --listen 127.0.0.1:9201

6) Start two client nodes and connect them to the introducer (use two new terminals)
   # Terminal 2
   python3 -m socp.run_node --mode client --id alice --introducer 127.0.0.1:9000 --listen 127.0.0.1:9101

   # Terminal 3
   python3 -m socp.run_node --mode client --id bob --introducer 127.0.0.1:9000 --listen 127.0.0.1:9102

7) Verify: list members (can be done from any extra terminal)
   python3 -m socp.run_node --mode cli --introducer 127.0.0.1:9000 members

8) Send a direct message
   python3 -m socp.run_node --mode cli --introducer 127.0.0.1:9000 send --from alice --to bob "Hello Bob"

9) Send a group message (group is a free-form label)
   python3 -m socp.run_node --mode cli --introducer 127.0.0.1:9000 send-group --from alice --group cohort "Hello everyone"

10) File transfer (inline chunks over introducer)
   python -m socp.run_node --mode cli --introducer 127.0.0.1:9000 send-file --from alice --to bob --path README.txt

11) Removing a member
   python3 -m socp.run_node --mode cli --id server_1 --introducer 127.0.0.1:9000 remove-user --server server_1 --user alice


CLI Usage
- Introducer/Relay:
  python -m socp.run_node --mode introducer --host 127.0.0.1 --port 9000

- Client Node:
  python -m socp.run_node --mode client --id alice --introducer 127.0.0.1:9000 --listen 127.0.0.1:9101

- CLI Commands:
  members
  send --from <id> --to <id> "message"
  send-group --from <id> --group <name> "message"
  send-file --from <id> --to <id> --path <file>
  admin-op --operator-code <code> --assume-from <id>
  raw --json <path>   # send raw frame (advanced)

Wire Format (Length-Prefixed JSON)
- 4-byte little-endian unsigned length N
- N bytes of UTF-8 JSON

Common Envelope
{
  "version": "1.0",
  "msg_type": "DIRECT_MSG" | "GROUP_MSG" | ..., 
  "msg_id": "uuid4",
  "timestamp_ms": 0,
  "from": "alice",
  "to": "bob" | null,
  "group": "cohort" | null,
  "ttl": 8,
  "body": { }
}

Message Types (subset)
- HELLO, PRESENCE_UPDATE, MEMBER_LIST_REQUEST/RESPONSE
- DIRECT_MSG, GROUP_MSG, ACK, ERROR
- FILE_OFFER, FILE_ACCEPT, FILE_CHUNK, FILE_COMPLETE
- ADMIN_OP (intentional/hidden), PING/PONG

Troubleshooting
- ModuleNotFoundError: No module named 'socp'
  Run from the project root (the folder that contains the 'socp' directory), not from inside 'socp'.
- ConnectionRefusedError when starting a client
  Ensure the introducer is running and listening on the specified host:port.
- Windows Firewall prompts
  Allow access for Python when first binding to a port.
- Port already in use
  Change ports (e.g., 9001, 9101/9102/9111/9112) or stop the previous processes.

Limits
- Max frame size: 4 MiB
- Default file chunk size: 64 KiB
- TTL default: 8

License
Educational use for the SOCP assignment.
