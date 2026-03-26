"""Cryptographic utilities for AIP CLI using Ed25519."""

import hashlib
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def generate_keypair() -> tuple[bytes, bytes]:
    """Generate an Ed25519 keypair.

    Returns:
        (private_key_bytes, public_key_bytes) where both are raw 32-byte keys.
    """
    private_key = Ed25519PrivateKey.generate()
    private_key_bytes = private_key.private_bytes_raw()
    public_key_bytes = private_key.public_key().public_bytes_raw()
    return private_key_bytes, public_key_bytes


def save_private_key(path: Path, private_key_bytes: bytes) -> None:
    """Save raw 32-byte private key to file with 0o600 permissions."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        f.write(private_key_bytes)
    os.chmod(path, 0o600)


def load_private_key(path: Path) -> bytes:
    """Load raw 32-byte private key from file."""
    path = Path(path)
    with open(path, "rb") as f:
        return f.read()


def sign_token_request(
    private_key_bytes: bytes,
    agent_id: str,
    kid: str,
    audience: str,
    timestamp: str,
) -> str:
    """Sign a token request message.

    Message format: {agent_id}|{kid}|{audience}|{timestamp}

    Returns:
        Hex-encoded Ed25519 signature.
    """
    private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    message = f"{agent_id}|{kid}|{audience}|{timestamp}".encode()
    signature = private_key.sign(message)
    return signature.hex()


def compute_kid(public_key_bytes: bytes) -> str:
    """Compute the key ID as the first 16 chars of the SHA-256 hex digest."""
    digest = hashlib.sha256(public_key_bytes).hexdigest()
    return digest[:16]
