from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time
import zipfile
from pathlib import Path
from typing import Any, BinaryIO

import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_der_private_key,
)


class Identity:
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
        self._idp_url = idp_url or Identity._idp_url_from_agent_id(agent_id)

        # Try loading as PEM first, then raw 32-byte seed, then DER.
        self._private_key = _load_private_key(private_key_bytes)

    @staticmethod
    def _idp_url_from_agent_id(agent_id: str) -> str:
        """Derive IDP base URL from agent_id domain.

        Format is ``aip:<domain>:<name>`` where ``<domain>`` may itself contain
        a port (e.g. ``agentid:localhost:8000:agent_x``). We split off the first
        segment (``aip``) and the last (``<name>``); everything in between is
        the domain, preserving any embedded colons.

        Examples:
            aip:example.com:agent_x        -> https://example.com
            aip:localhost:agent_x          -> http://localhost
            agentid:localhost:8000:agent_x     -> http://localhost:8000

        Note: for ModelScope (``aip:identity.modelscope.cn:...``) the embedded
        domain is NOT the API host — always pass ``idp_url`` explicitly; this
        derivation is a best-effort fallback for self-hosted IdPs.
        """
        parts = agent_id.split(":")
        if len(parts) < 3 or parts[0] not in ("agentid", "aip"):
            raise ValueError(f"Cannot derive IDP URL from agent_id: {agent_id}")
        domain = ":".join(parts[1:-1])
        is_localhost = domain == "localhost" or domain.startswith("localhost:")
        scheme = "http" if is_localhost else "https"
        return f"{scheme}://{domain}"

    # -- class methods --------------------------------------------------------

    @classmethod
    def from_profile(cls, agent_dir: str | Path | None = None) -> Identity:
        """Load identity from ``~/.agentid/agents/{name}/``.

        *agent_dir* should be the directory that contains ``agent.json`` and
        ``private_key``.  If *None*, the first directory found under
        ``~/.agentid/agents/`` is used.
        """
        aip_home = Path(os.environ.get("AGENTID_HOME", Path.home() / ".agentid"))
        base = aip_home / "agents"

        if agent_dir is None:
            dirs = sorted(base.iterdir()) if base.exists() else []
            if not dirs:
                raise FileNotFoundError(f"No agent directories found under {base}")
            agent_dir = dirs[0]
        else:
            agent_dir = Path(agent_dir)
            # If it's a plain name (not a path), resolve under ~/.agentid/agents/
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
    def from_env(cls) -> Identity:
        """Load identity from environment variables.

        Expected env vars:
        - ``AGENTID_AGENT_ID``
        - ``AGENTID_AGENT_KID``
        - ``AGENTID_AGENT_PRIVATE_KEY`` (hex-encoded 32-byte Ed25519 seed)
        - ``AGENTID_IDP_URL``
        """
        agent_id = os.environ["AGENTID_AGENT_ID"]
        kid = os.environ["AGENTID_AGENT_KID"]
        private_key_hex = os.environ["AGENTID_AGENT_PRIVATE_KEY"]
        idp_url = os.environ.get("AGENTID_IDP_URL")

        private_key_bytes = bytes.fromhex(private_key_hex)
        return cls(
            agent_id=agent_id,
            kid=kid,
            private_key_bytes=private_key_bytes,
            idp_url=idp_url,
        )

    @classmethod
    def from_zip(cls, file: str | Path | BinaryIO) -> Identity:
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
        """Sign a token request and return the base64url-encoded signature.

        Message format: ``{agent_id}|{kid}|{audience}|{timestamp}`` (UTF-8).
        The ModelScope Agent IdP expects the Ed25519 signature as base64url
        without padding (the JOSE convention) — ``_b64u`` produces exactly
        that. The signed bytes are identical regardless of encoding.
        """
        message = f"{self._agent_id}|{self._kid}|{audience}|{timestamp}"
        signature = self._private_key.sign(message.encode())
        return _b64u(signature)

    def public_jwk(self) -> dict[str, Any]:
        """Return this identity's public key as a JWK dict.

        Used as the ``jwk`` member of a DPoP proof's JWS header. Contains
        only the public components (``kty``, ``crv``, ``x``) — never the
        private key.
        """
        pub_bytes = self._private_key.public_key().public_bytes_raw()
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": _b64u(pub_bytes),
        }

    def sign_dpop_proof(
        self,
        *,
        htm: str,
        htu: str,
        access_token: str | None = None,
        iat: int | None = None,
        jti: str | None = None,
    ) -> str:
        """Sign a DPoP proof (RFC 9449) for one outbound HTTP request.

        Args:
            htm: HTTP method (e.g. ``"POST"``). Stored upper-cased in the
                proof per RFC 9449 §4.2.
            htu: Full request URL. Query string and fragment are stripped
                by the verifier; we pass through verbatim.
            access_token: When present, an ``ath`` claim is added binding
                the proof to ``base64url(sha256(access_token))``. Required
                when this proof accompanies an access token (the normal
                case for an authenticated request).
            iat: Override the timestamp (testing only). Defaults to
                ``int(time.time())``.
            jti: Override the nonce (testing only). Defaults to
                ``secrets.token_hex(16)``.

        Returns:
            The compact JWS to be sent as the ``DPoP`` HTTP header.
        """
        headers = {
            "alg": "EdDSA",
            "typ": "dpop+jwt",
            "jwk": self.public_jwk(),
        }
        payload: dict[str, Any] = {
            "htm": htm.upper(),
            "htu": htu,
            "iat": iat if iat is not None else int(time.time()),
            "jti": jti if jti is not None else secrets.token_hex(16),
        }
        if access_token is not None:
            digest = hashlib.sha256(access_token.encode("ascii")).digest()
            payload["ath"] = _b64u(digest)
        return pyjwt.encode(
            payload, self._private_key, algorithm="EdDSA", headers=headers
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _b64u(b: bytes) -> str:
    """Base64url encode (no padding) — the JOSE / DPoP / RFC 7638 convention."""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


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
