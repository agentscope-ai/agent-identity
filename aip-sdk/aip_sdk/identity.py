from __future__ import annotations

import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_der_private_key,
)


class AIPIdentity:
    """Represents an AIP agent identity with Ed25519 signing capability."""

    def __init__(
        self,
        agent_id: str,
        kid: str,
        private_key_bytes: bytes,
        idp_url: str,
    ) -> None:
        self._agent_id = agent_id
        self._kid = kid
        self._idp_url = idp_url

        # Try loading as PEM first, then raw 32-byte seed, then DER.
        self._private_key = _load_private_key(private_key_bytes)

    # -- class methods --------------------------------------------------------

    @classmethod
    def from_file(cls, agent_dir: str | Path | None = None) -> AIPIdentity:
        """Load identity from ``~/.aip/agents/{name}/``.

        *agent_dir* should be the directory that contains ``agent.json`` and
        ``private_key``.  If *None*, the first directory found under
        ``~/.aip/agents/`` is used.
        """
        if agent_dir is None:
            base = Path.home() / ".aip" / "agents"
            dirs = sorted(base.iterdir())
            if not dirs:
                raise FileNotFoundError(
                    f"No agent directories found under {base}"
                )
            agent_dir = dirs[0]
        else:
            agent_dir = Path(agent_dir)

        config_path = agent_dir / "agent.json"
        key_path = agent_dir / "private_key"

        with open(config_path) as f:
            config = json.load(f)

        private_key_bytes = key_path.read_bytes()

        return cls(
            agent_id=config["agent_id"],
            kid=config["kid"],
            private_key_bytes=private_key_bytes,
            idp_url=config["idp_url"],
        )

    @classmethod
    def from_env(cls) -> AIPIdentity:
        """Load identity from environment variables.

        Expected env vars:
        - ``AIP_AGENT_ID``
        - ``AIP_AGENT_KID``
        - ``AIP_PRIVATE_KEY`` (hex-encoded 32-byte Ed25519 seed)
        - ``AIP_IDP_URL``
        """
        agent_id = os.environ["AIP_AGENT_ID"]
        kid = os.environ["AIP_AGENT_KID"]
        private_key_hex = os.environ["AIP_PRIVATE_KEY"]
        idp_url = os.environ["AIP_IDP_URL"]

        private_key_bytes = bytes.fromhex(private_key_hex)
        return cls(
            agent_id=agent_id,
            kid=kid,
            private_key_bytes=private_key_bytes,
            idp_url=idp_url,
        )

    # -- properties -----------------------------------------------------------

    @property
    def agent_id(self) -> str:
        return self._agent_id

    @property
    def kid(self) -> str:
        return self._kid

    @property
    def idp_url(self) -> str:
        return self._idp_url

    # -- signing --------------------------------------------------------------

    def sign_token_request(self, audience: str, timestamp: int) -> str:
        """Sign a token request and return the hex-encoded signature.

        Message format: ``{agent_id}|{kid}|{audience}|{timestamp}``
        """
        message = f"{self._agent_id}|{self._kid}|{audience}|{timestamp}"
        signature = self._private_key.sign(message.encode())
        return signature.hex()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_private_key(data: bytes) -> Ed25519PrivateKey:
    """Attempt to interpret *data* as PEM, raw 32-byte seed, or DER."""
    # PEM
    if data.strip().startswith(b"-----"):
        key = load_pem_private_key(data, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise TypeError("PEM key is not Ed25519")
        return key

    # Raw 32-byte seed
    if len(data) == 32:
        return Ed25519PrivateKey.from_private_bytes(data)

    # DER
    try:
        key = load_der_private_key(data, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise TypeError("DER key is not Ed25519")
        return key
    except Exception:
        pass

    raise ValueError(
        "Unable to load Ed25519 private key from provided bytes "
        f"(length={len(data)})"
    )
