"""
crypto.py — tiny RSA-4096 helpers.

Why this exists:
- Keep all RSA bits in one place so the rest of the code can call
  `encrypt/decrypt/sign/verify` without worrying about padding details.
- Use URL-safe Base64 without '=' padding so values drop cleanly into JSON/URLs.
- Enforce RSA-4096 everywhere so we don't end up mixing key sizes.

Notes:
- OAEP+SHA256 for encryption, PSS+SHA256 for signatures (modern, safe defaults).
- Functions return/accept bytes for raw data and str for Base64url strings.
"""

import base64
import json
import hashlib
from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidKey

# -----------------------------
# Base64 URL helpers (no padding)
# -----------------------------

def b64url_encode(data: bytes) -> str:
    """URL-safe Base64 without '=' padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(data: str) -> bytes:
    """Decode our URL-safe, no-padding Base64 back to bytes."""
    # Add the minimal padding back so Python's decoder is happy.
    pad_len = (-len(data)) % 4
    return base64.urlsafe_b64decode(data + "=" * pad_len)


# -------------
# RSA key utils
# -------------

def enforce_rsa4096(key):
    """
    Quick sanity check: we only accept RSA keys and only 4096-bit ones.
    This avoids accidental 2048/3072 keys sneaking in.
    """
    if isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        if key.key_size != 4096:
            raise InvalidKey("Key must be RSA-4096 bits.")
    else:
        raise InvalidKey("Key must be RSA public/private key.")


def generate_rsa4096() -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Generate a fresh RSA-4096 keypair (public exponent 65537)."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    return priv, priv.public_key()


def export_pubkey_b64url(pub: rsa.RSAPublicKey) -> str:
    """Export a public key as PEM, then Base64url-encode it for transport."""
    pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return b64url_encode(pem)


def import_pubkey_b64url(data: str) -> rsa.RSAPublicKey:
    """Inverse of export_pubkey_b64url()."""
    pem = b64url_decode(data)
    return serialization.load_pem_public_key(pem)


def export_privkey_pem(priv: rsa.RSAPrivateKey) -> bytes:
    """
    Export private key in PKCS#8 (unencrypted) form.
    Store safely if you write this to disk; this is the raw key.
    """
    return priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )


def load_privkey_pem(pem_bytes: bytes) -> rsa.RSAPrivateKey:
    """Load an unencrypted PKCS#8 PEM private key."""
    return serialization.load_pem_private_key(pem_bytes, password=None)


# ---------------------------
# Encryption & Decryption API
# ---------------------------

def rsa_encrypt(pub: rsa.RSAPublicKey, plaintext: bytes) -> str:
    """
    Encrypt bytes with RSA-OAEP(SHA-256) and return Base64url ciphertext.

    Tip: Keep plaintext small. RSA is for keys/nonces; big blobs should be
    encrypted with a symmetric key (then wrap that key with RSA).
    """
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
    """Reverse of rsa_encrypt(). Takes Base64url ciphertext, returns bytes."""
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


# -------------------------
# Signing & Verification API
# -------------------------

def sign(priv: rsa.RSAPrivateKey, data: bytes) -> str:
    """
    Sign raw bytes with RSA-PSS(SHA-256). Returns Base64url signature.

    PSS uses a random salt under the hood, so signatures differ each time
    even for the same input—this is expected.
    """
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
    """
    Verify a Base64url signature produced by `sign()`.
    Returns True on success, False on any failure (bad key, wrong data, etc.).
    """
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
        # We don't leak verify errors to callers; they just see False.
        return False


# -------------------------------------------------
# Canonical digests for signing different message types
# -------------------------------------------------

def canonical_dm_content(ciphertext_b64: str, from_id: str, to_id: str, ts: int) -> bytes:
    """
    Deterministic digest for a direct message.
    We concatenate the minimal fields and hash once, so the signature input
    is compact and ordering is fixed.
    """
    data = f"{ciphertext_b64}{from_id}{to_id}{ts}".encode("utf-8")
    return hashlib.sha256(data).digest()


def canonical_group_content(ciphertext_b64: str, from_id: str, ts: int) -> bytes:
    """Digest for a group message (no per-recipient 'to_id')."""
    data = f"{ciphertext_b64}{from_id}{ts}".encode("utf-8")
    return hashlib.sha256(data).digest()


def canonical_pubkey_share_content(shares_b64: str, creator_pub_b64: str) -> bytes:
    """Digest for publishing key shares (used in onboarding/rotation flows)."""
    data = f"{shares_b64}{creator_pub_b64}".encode("utf-8")
    return hashlib.sha256(data).digest()


# -----------------------------
# Transport / JSON canonicalization
# -----------------------------

def canonical_json_bytes(obj: dict) -> bytes:
    """
    Canonical JSON: sort keys and remove whitespace variation.
    This makes signatures stable across platforms and Python versions.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def transport_digest(obj: dict) -> bytes:
    """SHA-256 over canonical JSON. Handy before calling `sign()`."""
    return hashlib.sha256(canonical_json_bytes(obj)).digest()


# ---------------------------------------
# Simple proof-of-possession (login flow)
# ---------------------------------------

def prove_possession(priv: rsa.RSAPrivateKey, nonce: bytes) -> str:
    """
    Sign a random server-provided nonce to prove you hold the private key.
    Server verifies with your registered public key. No magic here.
    """
    return sign(priv, nonce)


# -------------------
# Tiny "directory" API
# -------------------

# In-memory user_id -> RSA public key store.
# This is obviously not persistent; it's enough for tests/demos.
DIRECTORY = {}  # user_id -> pubkey (RSA public key object)


def register_user(user_id: str, pub: rsa.RSAPublicKey):
    """Add/replace a user's public key in the directory after basic checks."""
    enforce_rsa4096(pub)
    DIRECTORY[user_id] = pub


def get_pubkey(user_id: str) -> rsa.RSAPublicKey:
    """
    Look up a user's public key. Will KeyError if they aren't registered.
    That's fine—callers should handle onboarding/404s upstream.
    """
    return DIRECTORY[user_id]