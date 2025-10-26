## Registration & Key Management

- Generate users and keys:
  ```bash
  setx SOCP_PASSPHRASE "your passphrase"
  python -m socp.run_node register --username alice
  python -m socp.run_node register --username bob
  ```
- Private keys are stored at `~/.socp/<user>_priv.pem` (encrypted if `SOCP_PASSPHRASE` is set).
- Public keys are written to `~/.socp/pub/<user>.pem` for discovery.

## Authenticated HELLO

- Client proves identity with `AUTH_RESPONSE` (signs nonce from `AUTH_CHALLENGE`).
- Introducer updates directory only after verifying the signature.

## DM & Group Messages

- DMs must carry `body.payload = {ciphertext, sender_pub, content_sig}`.
- Group messages must carry `body.content` and `body.content_sig`.
- Envelope signature is verified on all frames.

## Limits & Safety

- Max RSA DM ciphertext size ≈ 700 base64url characters (≈466B plaintext).
- Frame size capped to 256 KiB; per-connection token-bucket limiter enabled.
- File transfer: 64 KiB chunk cap, 16 MiB total cap, optional SHA-256 verification.
- CLI sending is restricted to files inside the current project directory tree.
