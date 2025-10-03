import base64
import json
import hashlib
from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidKey

# Base64 URL helpers (no padding)
def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def b64url_decode(data: str) -> bytes:
    pad_len = (-len(data)) % 4
    return base64.urlsafe_b64decode(data + "=" * pad_len)

# RSA Key Helpers
def enforce_rsa4096(key):
    if isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        if key.key_size != 4096:
            raise InvalidKey("Key must be RSA-4096 bits.")
    else:
        raise InvalidKey("Key must be RSA public/private key.")

def generate_rsa4096() -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    return priv, priv.public_key()

def export_pubkey_b64url(pub: rsa.RSAPublicKey) -> str:
    pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return b64url_encode(pem)

def import_pubkey_b64url(data: str) -> rsa.RSAPublicKey:
    pem = b64url_decode(data)
    return serialization.load_pem_public_key(pem)

def export_privkey_pem(priv: rsa.RSAPrivateKey) -> bytes:
    return priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

def load_privkey_pem(pem_bytes: bytes) -> rsa.RSAPrivateKey:
    return serialization.load_pem_private_key(pem_bytes, password=None)

# Encryption & Decryption
def rsa_encrypt(pub: rsa.RSAPublicKey, plaintext: bytes) -> str:
    enforce_rsa4096(pub)
    ct = pub.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return b64url_encode(ct)

def rsa_decrypt(priv: rsa.RSAPrivateKey, ct_b64: str) -> bytes:
    enforce_rsa4096(priv)
    ct = b64url_decode(ct_b64)
    return priv.decrypt(
        ct,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

# Signing & Verification
def sign(priv: rsa.RSAPrivateKey, data: bytes) -> str:
    enforce_rsa4096(priv)
    sig = priv.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return b64url_encode(sig)

def verify(pub: rsa.RSAPublicKey, data: bytes, sig_b64: str) -> bool:
    enforce_rsa4096(pub)
    sig = b64url_decode(sig_b64)
    try:
        pub.verify(
            sig,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# Canonical Signing for Messages
def canonical_dm_content(ciphertext_b64: str, from_id: str, to_id: str, ts: int) -> bytes:
    data = f"{ciphertext_b64}{from_id}{to_id}{ts}".encode("utf-8")
    return hashlib.sha256(data).digest()

def canonical_group_content(ciphertext_b64: str, from_id: str, ts: int) -> bytes:
    data = f"{ciphertext_b64}{from_id}{ts}".encode("utf-8")
    return hashlib.sha256(data).digest()

def canonical_pubkey_share_content(shares_b64: str, creator_pub_b64: str) -> bytes:
    data = f"{shares_b64}{creator_pub_b64}".encode("utf-8")
    return hashlib.sha256(data).digest()

# Transport Signature Helpers
def canonical_json_bytes(obj: dict) -> bytes:
    """Canonical JSON: sort keys, no whitespace variation."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

def transport_digest(obj: dict) -> bytes:
    return hashlib.sha256(canonical_json_bytes(obj)).digest()

# Proof of possession (Login model)
def prove_possession(priv: rsa.RSAPrivateKey, nonce: bytes) -> str:
    """Sign a nonce to prove key ownership during login."""
    return sign(priv, nonce)

# Directory API stubs
DIRECTORY = {}  # user_id -> pubkey (RSA public key object)

def register_user(user_id: str, pub: rsa.RSAPublicKey):
    enforce_rsa4096(pub)
    DIRECTORY[user_id] = pub

def get_pubkey(user_id: str) -> rsa.RSAPublicKey:
    return DIRECTORY[user_id]