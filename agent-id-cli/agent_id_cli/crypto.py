"""Re-exports from agent_id_sdk.manage for backwards compatibility."""

from agent_id_sdk.manage import (
    generate_keypair,
    compute_kid,
    sign_token_request,
    load_private_key,
)

# save_private_key is not in agent_id_sdk.manage (save_agent handles it),
# but kept here for any direct callers.
import os
from pathlib import Path


def save_private_key(path: Path, private_key_bytes: bytes) -> None:
    """Save raw 32-byte private key to file with 0o600 permissions."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        f.write(private_key_bytes)
    os.chmod(path, 0o600)
