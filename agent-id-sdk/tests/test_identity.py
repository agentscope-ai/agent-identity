from __future__ import annotations

import json
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)

from agent_id_sdk.identity import AIPIdentity


def _make_agent_dir(tmp: Path) -> tuple[Path, Ed25519PrivateKey]:
    """Create a minimal agent directory with agent.json and private_key."""
    agent_dir = tmp / "test-agent"
    agent_dir.mkdir(parents=True)

    private_key = Ed25519PrivateKey.generate()

    config = {
        "agent_id": "agent-001",
        "kid": "key-001",
        "idp_url": "https://idp.example.com",
    }
    (agent_dir / "agent.json").write_text(json.dumps(config))

    # Write raw 32-byte seed.
    raw_bytes = private_key.private_bytes(
        Encoding.Raw, PrivateFormat.Raw, NoEncryption()
    )
    (agent_dir / "private_key").write_bytes(raw_bytes)

    return agent_dir, private_key


def test_from_file_loads_identity():
    with tempfile.TemporaryDirectory() as tmp:
        agent_dir, _ = _make_agent_dir(Path(tmp))
        identity = AIPIdentity.from_file(agent_dir)

        assert identity.agent_id == "agent-001"
        assert identity.kid == "key-001"
        assert identity.idp_url == "https://idp.example.com"


def test_sign_token_request_produces_hex():
    with tempfile.TemporaryDirectory() as tmp:
        agent_dir, private_key = _make_agent_dir(Path(tmp))
        identity = AIPIdentity.from_file(agent_dir)

        sig_hex = identity.sign_token_request("https://hub.example.com", 1700000000)
        sig_bytes = bytes.fromhex(sig_hex)

        # Ed25519 signatures are 64 bytes.
        assert len(sig_bytes) == 64

        # Verify the signature with the public key.
        message = "agent-001|key-001|https://hub.example.com|1700000000".encode()
        public_key = private_key.public_key()
        # Raises InvalidSignature if verification fails.
        public_key.verify(sig_bytes, message)


def test_from_env_loads_identity(monkeypatch):
    private_key = Ed25519PrivateKey.generate()
    raw = private_key.private_bytes(
        Encoding.Raw, PrivateFormat.Raw, NoEncryption()
    )

    monkeypatch.setenv("AIP_AGENT_ID", "agent-env")
    monkeypatch.setenv("AIP_AGENT_KID", "key-env")
    monkeypatch.setenv("AIP_PRIVATE_KEY", raw.hex())
    monkeypatch.setenv("AIP_IDP_URL", "https://idp.env.example.com")

    identity = AIPIdentity.from_env()
    assert identity.agent_id == "agent-env"
    assert identity.kid == "key-env"
    assert identity.idp_url == "https://idp.env.example.com"
