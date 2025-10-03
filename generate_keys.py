from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from socp import crypto

# Generate RSA-4096 key pair
privkey, pubkey = crypto.generate_rsa4096()

# Ensure ~/.socp exists
key_dir = Path.home() / ".socp"
key_dir.mkdir(parents=True, exist_ok=True)

# Save private key
priv_path = key_dir / "bob_priv.pem"
with open(priv_path, "wb") as f:
    f.write(privkey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

# Print public key in base64url format
pub_b64url = crypto.export_pubkey_b64url(pubkey)
print("Bob's public key (base64url):")
print(pub_b64url)