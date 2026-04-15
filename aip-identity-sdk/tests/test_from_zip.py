"""Tests for AIPIdentity.from_zip()."""

import json
import zipfile
from io import BytesIO

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aip_identity_sdk.identity import AIPIdentity


def _make_agent_config(
    agent_id="aip:test:agent_001", kid="testkid123", idp_url="http://localhost:8000"
):
    return {
        "agent_id": agent_id,
        "kid": kid,
        "name": "test-agent",
        "idp_url": idp_url,
        "principal_id": "p-001",
        "principal_external_id": "github:testuser",
        "principal_name": "Test User",
    }


def _make_zip(
    config: dict, private_key_bytes: bytes, nested_dir: str | None = None
) -> bytes:
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        prefix = f"{nested_dir}/" if nested_dir else ""
        zf.writestr(f"{prefix}agent.json", json.dumps(config))
        zf.writestr(f"{prefix}private_key", private_key_bytes)
    return buf.getvalue()


def test_from_zip_flat():
    pk = Ed25519PrivateKey.generate()
    seed = pk.private_bytes_raw()
    config = _make_agent_config()

    zip_bytes = _make_zip(config, seed)
    identity = AIPIdentity.from_zip(BytesIO(zip_bytes))

    assert identity.agent_id == config["agent_id"]
    assert identity.kid == config["kid"]
    assert identity.idp_url == config["idp_url"]

    # Verify signing works
    sig = identity.sign_token_request("https://hub.example.com", 1234567890)
    assert isinstance(sig, str)
    assert len(sig) > 0


def test_from_zip_nested_directory():
    pk = Ed25519PrivateKey.generate()
    seed = pk.private_bytes_raw()
    config = _make_agent_config()

    zip_bytes = _make_zip(config, seed, nested_dir="my-agent")
    identity = AIPIdentity.from_zip(BytesIO(zip_bytes))

    assert identity.agent_id == config["agent_id"]
    assert identity.kid == config["kid"]


def test_from_zip_missing_agent_json():
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("private_key", b"\x00" * 32)

    with pytest.raises(FileNotFoundError, match="agent.json"):
        AIPIdentity.from_zip(BytesIO(buf.getvalue()))


def test_from_zip_missing_private_key():
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("agent.json", json.dumps(_make_agent_config()))

    with pytest.raises(FileNotFoundError, match="private_key"):
        AIPIdentity.from_zip(BytesIO(buf.getvalue()))


def test_from_zip_file_path(tmp_path):
    pk = Ed25519PrivateKey.generate()
    seed = pk.private_bytes_raw()
    config = _make_agent_config()

    zip_path = tmp_path / "agent.zip"
    zip_path.write_bytes(_make_zip(config, seed))

    identity = AIPIdentity.from_zip(zip_path)
    assert identity.agent_id == config["agent_id"]
