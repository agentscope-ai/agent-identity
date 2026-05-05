"""Tests for ``python -m agent_id_service_sdk.keygen``."""

from __future__ import annotations

import json
import os

from agent_id_service_sdk.keygen import main
from agent_id_service_sdk.manifest_signing import sign_manifest, build_manifest

import jwt as pyjwt
from cryptography.hazmat.primitives.serialization import load_pem_private_key


def test_human_output_emits_pem_and_jwk(capsys):
    rc = main(["--kid", "test-kid"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "BEGIN PRIVATE KEY" in out
    assert "END PRIVATE KEY" in out
    assert "kid: test-kid" in out
    assert '"kty": "OKP"' in out
    assert '"crv": "Ed25519"' in out


def test_json_output(capsys):
    rc = main(["--kid", "json-kid", "--json"])
    assert rc == 0
    body = json.loads(capsys.readouterr().out)
    assert body["kid"] == "json-kid"
    assert body["public_jwk"]["kid"] == "json-kid"
    assert body["public_jwk"]["kty"] == "OKP"
    assert body["public_jwk"]["crv"] == "Ed25519"
    assert "BEGIN PRIVATE KEY" in body["private_pem"]
    assert body["private_pem_path"] is None


def test_out_writes_file_with_mode_0600(tmp_path, capsys):
    target = tmp_path / "subdir" / "hub.pem"
    rc = main(["--out", str(target)])
    assert rc == 0
    assert target.exists()
    assert os.stat(target).st_mode & 0o777 == 0o600
    assert "BEGIN PRIVATE KEY" in target.read_text()
    msg = capsys.readouterr().out
    assert f"wrote private key to {target}" in msg


def test_out_with_json_omits_private_pem_inline(tmp_path, capsys):
    target = tmp_path / "hub.pem"
    rc = main(["--out", str(target), "--json"])
    assert rc == 0
    body = json.loads(capsys.readouterr().out)
    assert body["private_pem"] is None
    assert body["private_pem_path"] == str(target)
    # File still has the key.
    assert "BEGIN PRIVATE KEY" in target.read_text()


def test_output_round_trips_through_signing(tmp_path, capsys):
    """The PEM the CLI produces must load and sign cleanly. Catches
    drift between the CLI's serialization and what sign_manifest
    expects to consume."""
    target = tmp_path / "hub.pem"
    main(["--out", str(target), "--kid", "round-trip"])
    capsys.readouterr()  # discard

    private_key = load_pem_private_key(target.read_bytes(), password=None)
    manifest = build_manifest(
        service_id="https://api.example.com",
        namespace="example",
        categories_url="https://api.example.com/.well-known/agent-id-activity-categories",
        jwks_url="https://api.example.com/.well-known/agent-id-jwks",
    )
    jws = sign_manifest(manifest, private_key=private_key, kid="round-trip")
    # Verify directly with the public key derived from the same PEM.
    claims = pyjwt.decode(
        jws,
        private_key.public_key(),  # type: ignore[union-attr]
        algorithms=["EdDSA"],
        options={"verify_aud": False, "verify_exp": False},
    )
    assert claims["service_id"] == "https://api.example.com"
