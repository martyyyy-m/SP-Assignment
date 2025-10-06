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

Intentional Vulnerabilities (Week 9 requirement)
1) Presence replay gap (intentional): PRESENCE_UPDATE messages are not checked against the message ID replay cache. A forged PRESENCE_UPDATE can spoof a user’s status.
2) Hidden operator override (intentional): If environment variable SOCP_OPERATOR_CODE is set, the node accepts ADMIN_OP messages carrying a matching operator_code. These messages allow setting the `from` identity of subsequent relayed DIRECT_MSG/GROUP_MSG on this connection. This is confined to the application session and does not access the host OS.

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

5) Start two client nodes and connect them to the introducer (use two new terminals)
   # Terminal 2
   python3 -m socp.run_node --mode client --id alice --introducer 127.0.0.1:9000 --listen 127.0.0.1:9101

   # Terminal 3
   python3 -m socp.run_node --mode client --id bob --introducer 127.0.0.1:9000 --listen 127.0.0.1:9102

6) Verify: list members (can be done from any extra terminal)
   python3 -m socp.run_node --mode cli --introducer 127.0.0.1:9000 members

7) Send a direct message
   python3 -m socp.run_node --mode cli --introducer 127.0.0.1:9000 send --from alice --to bob "Hello Bob"

8) Send a group message (group is a free-form label)
   python3 -m socp.run_node --mode cli --introducer 127.0.0.1:9000 send-group --from alice --group cohort "Hello everyone"

9) File transfer (inline chunks over introducer)
   python -m socp.run_node --mode cli --introducer 127.0.0.1:9000 send-file --from alice --to bob --path README.txt

Vulnerability Demonstrations
A) Hidden operator override (identity forgery on a connection)
   - Open a new terminal and start a dedicated introducer with an operator code on port 9001:
     Windows PowerShell:
       $env:SOCP_OPERATOR_CODE = "let-me-in"
       python -m socp.run_node --mode introducer --host 127.0.0.1 --port 9001
   - In two more terminals, connect clients to port 9001:
       python -m socp.run_node --mode client --id alice --introducer 127.0.0.1:9001 --listen 127.0.0.1:9111
       python -m socp.run_node --mode client --id bob   --introducer 127.0.0.1:9001 --listen 127.0.0.1:9112
   - From a fourth terminal, trigger the override on your CLI connection:
       python -m socp.run_node --mode cli --introducer 127.0.0.1:9001 admin-op --operator-code let-me-in --assume-from charlie
   - Then send a message. Recipients should see it as from "charlie":
       python -m socp.run_node --mode cli --introducer 127.0.0.1:9001 send --from alice --to bob "This should look like it's from charlie"

B) Presence replay spoof (accepts forged presence)
   - Create a JSON file presence_spoof.json with content like:
     {"version":"1.0","msg_type":"PRESENCE_UPDATE","msg_id":"11111111-1111-1111-1111-111111111111","timestamp_ms":1759000000000,"from":"mallory","to":null,"group":null,"ttl":8,"body":{"status":"online"}}
   - Send the raw frame to the introducer (no replay check on PRESENCE_UPDATE by design):
     python -m socp.run_node --mode cli --introducer 127.0.0.1:9000 raw --json presence_spoof.json
   - Verify with members listing that "mallory" appears:
     python -m socp.run_node --mode cli --introducer 127.0.0.1:9000 members

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
