"""Re-exports from aip_identity_sdk.manage for backwards compatibility."""

import os
from pathlib import Path

from aip_identity_sdk.manage import (  # noqa: F401
    compute_kid,
    generate_keypair,
    load_private_key,
    sign_token_request,
)


def save_private_key(path: Path, private_key_bytes: bytes) -> None:
    """Save raw 32-byte private key to file with 0o600 permissions."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        f.write(private_key_bytes)
    os.chmod(path, 0o600)
