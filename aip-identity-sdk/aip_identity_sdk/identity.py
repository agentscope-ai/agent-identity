from __future__ import annotations

import json
import os
import zipfile
from pathlib import Path
from typing import BinaryIO

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
        idp_url: str | None = None,
    ) -> None:
        self._agent_id = agent_id
        self._kid = kid
        self._idp_url = idp_url or AIPIdentity._idp_url_from_agent_id(agent_id)

        # Try loading as PEM first, then raw 32-byte seed, then DER.
        self._private_key = _load_private_key(private_key_bytes)

    @staticmethod
    def _idp_url_from_agent_id(agent_id: str) -> str:
        """Derive IDP base URL from agent_id domain (e.g. 'aip:example.com:agent_x' -> 'https://example.com')."""
        parts = agent_id.split(":")
        if len(parts) >= 3:
            domain = parts[1]
            scheme = (
                "http"
                if domain == "localhost" or domain.startswith("localhost:")
                else "https"
            )
            return f"{scheme}://{domain}"
        raise ValueError(f"Cannot derive IDP URL from agent_id: {agent_id}")

    # -- class methods --------------------------------------------------------

    @classmethod
    def from_profile(cls, agent_dir: str | Path | None = None) -> AIPIdentity:
        """Load identity from ``~/.aip/agents/{name}/``.

        *agent_dir* should be the directory that contains ``agent.json`` and
        ``private_key``.  If *None*, the first directory found under
        ``~/.aip/agents/`` is used.
        """
        aip_home = Path(os.environ.get("AIP_HOME", Path.home() / ".aip"))
        base = aip_home / "agents"

        if agent_dir is None:
            dirs = sorted(base.iterdir()) if base.exists() else []
            if not dirs:
                raise FileNotFoundError(f"No agent directories found under {base}")
            agent_dir = dirs[0]
        else:
            agent_dir = Path(agent_dir)
            # If it's a plain name (not a path), resolve under ~/.aip/agents/
            if not agent_dir.is_absolute() and not agent_dir.exists():
                agent_dir = base / agent_dir

        config_path = agent_dir / "agent.json"
        key_path = agent_dir / "private_key"

        with open(config_path) as f:
            config = json.load(f)

        private_key_bytes = key_path.read_bytes()

        return cls(
            agent_id=config["agent_id"],
            kid=config["kid"],
            private_key_bytes=private_key_bytes,
            idp_url=config.get("idp_url"),
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
        idp_url = os.environ.get("AIP_IDP_URL")

        private_key_bytes = bytes.fromhex(private_key_hex)
        return cls(
            agent_id=agent_id,
            kid=kid,
            private_key_bytes=private_key_bytes,
            idp_url=idp_url,
        )

    @classmethod
    def from_zip(cls, file: str | Path | BinaryIO) -> AIPIdentity:
        """Load identity from a zip archive containing ``agent.json`` and ``private_key``.

        *file* can be a file path or a file-like object (e.g., ``BytesIO``).
        The zip is read in memory — no files are extracted to disk.
        """
        if isinstance(file, (str, Path)):
            file = open(file, "rb")  # noqa: SIM115

        with zipfile.ZipFile(file, "r") as zf:
            names = zf.namelist()
            config_entry = _find_in_zip(names, "agent.json")
            # Accept both private_key.pem (PEM) and private_key (raw/legacy)
            try:
                key_entry = _find_in_zip(names, "private_key.pem")
            except FileNotFoundError:
                key_entry = _find_in_zip(names, "private_key")

            config = json.loads(zf.read(config_entry))
            private_key_bytes = zf.read(key_entry)

        return cls(
            agent_id=config["agent_id"],
            kid=config["kid"],
            private_key_bytes=private_key_bytes,
            idp_url=config.get("idp_url"),
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

    @idp_url.setter
    def idp_url(self, value: str) -> None:
        self._idp_url = value

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


def _find_in_zip(names: list[str], filename: str) -> str:
    """Find *filename* in a zip, handling both flat and single-directory layouts."""
    if filename in names:
        return filename
    matches = [n for n in names if n.endswith(f"/{filename}")]
    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise FileNotFoundError(f"{filename} not found in zip archive")
    raise FileNotFoundError(f"Multiple {filename} entries found in zip archive")


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
        f"Unable to load Ed25519 private key from provided bytes (length={len(data)})"
    )
