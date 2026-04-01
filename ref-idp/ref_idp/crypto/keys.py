"""Ed25519 key management utilities."""

import hashlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization


def generate_ed25519_keypair() -> tuple[bytes, bytes]:
    """Generate an Ed25519 keypair.

    Returns:
        (private_key_raw_bytes, public_key_raw_bytes) - both 32 bytes.
    """
    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_bytes, public_bytes


def load_private_key(path: str) -> Ed25519PrivateKey:
    """Load an Ed25519 private key from a PEM file."""
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)  # type: ignore[return-value]


def load_public_key(raw_bytes: bytes) -> Ed25519PublicKey:
    """Load an Ed25519 public key from raw 32-byte representation."""
    return Ed25519PublicKey.from_public_bytes(raw_bytes)


def verify_signature(public_key_bytes: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an Ed25519 signature.

    Args:
        public_key_bytes: Raw 32-byte public key.
        message: The signed message bytes.
        signature: The 64-byte signature.

    Returns:
        True if valid, False otherwise.
    """
    try:
        pub = load_public_key(public_key_bytes)
        pub.verify(signature, message)
        return True
    except Exception:
        return False


def compute_kid(public_key_bytes: bytes) -> str:
    """Compute a key ID from public key bytes.

    Returns the first 16 hex characters of the SHA-256 hash.
    """
    digest = hashlib.sha256(public_key_bytes).hexdigest()
    return digest[:16]
