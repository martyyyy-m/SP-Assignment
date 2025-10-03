import base64
from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import utils
import json

# Base64 URL helpers (no padding)
def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def b64url_decode(data: str) -> bytes:
    pad_len = (-len(data)) % 4
    return base64.urlsafe_b64decode(data + "=" * pad_len)

# RSA Key Helpers
def generate_rsa4096() -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    return priv, priv.public_key()

def export_pubkey_b64url(pub: rsa.RSAPublicKey) -> str:
    der = pub.public_bytes(serialization.Encoding.DER,
                           serialization.PublicFormat.SubjectPublicKeyInfo)
    return b64url_encode(der)

def import_pubkey_b64url(data: str) -> rsa.RSAPublicKey:
    der = b64url_decode(data)
    return serialization.load_der_public_key(der)

def export_privkey_pem(priv: rsa.RSAPrivateKey) -> bytes:
    return priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

def load_privkey_pem(pem_bytes: bytes) -> rsa.RSAPrivateKey:
    return serialization.load_pem_private_key(pem_bytes, password=None)

# Encryption & Decryption
def rsa_encrypt(pub: rsa.RSAPublicKey, plaintext: bytes) -> str:
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
    """Canonical byte string for DM content signature: SHA256(ciphertext || from || to || ts)"""
    s = f"{ciphertext_b64}|{from_id}|{to_id}|{ts}"
    return s.encode("utf-8")

def canonical_group_content(ciphertext_b64: str, from_id: str, ts: int) -> bytes:
    """Canonical byte string for group/public channel content signature: SHA256(ciphertext || from || ts)"""
    s = f"{ciphertext_b64}|{from_id}|{ts}"
    return s.encode("utf-8")

def canonical_pubkey_share_content(shares_b64: str, creator_pub_b64: str) -> bytes:
    """Canonical byte string for public channel key share signature: SHA256(shares || creator_pub)"""
    s = f"{shares_b64}|{creator_pub_b64}"
    return s.encode("utf-8")

def sha256_digest(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()
