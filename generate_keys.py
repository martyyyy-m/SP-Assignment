from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from socp import crypto

# Quick one-off keygen for a demo user "bob".
# - RSA-4096 so it's consistent with the rest of the SOCP codebase.
# - Private key is written unencrypted under ~/.socp/bob_priv.pem
#   (fine for local testing; lock it down or use encryption for real use).

# 1) Generate RSA-4096 key pair.
privkey, pubkey = crypto.generate_rsa4096()

# 2) Make sure ~/.socp exists (where we keep demo keys).
key_dir = Path.home() / ".socp"
key_dir.mkdir(parents=True, exist_ok=True)

# 3) Save the private key as PEM.
#    Note: Using TraditionalOpenSSL here to match some tools; PKCS8 is also fine.
priv_path = key_dir / "bob_priv.pem"
with open(priv_path, "wb") as f:
    f.write(
        privkey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),  # demo only
        )
    )

# 4) Print the public key in Base64url so you can paste it into requests/config.
pub_b64url = crypto.export_pubkey_b64url(pubkey)
print("Bob's public key (base64url):")
print(pub_b64url)
