"""Tests for IDP URL derivation from agent_id."""

import json
import zipfile
from io import BytesIO

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_id_client_sdk.identity import Identity


class TestIdpUrlFromAgentId:
    def test_https_for_normal_domain(self):
        url = Identity._idp_url_from_agent_id("agentid:example.com:agent_001")
        assert url == "https://example.com"

    def test_http_for_localhost(self):
        url = Identity._idp_url_from_agent_id("agentid:localhost:agent_001")
        assert url == "http://localhost"

    def test_localhost_in_agent_id_always_http(self):
        """Port is not part of agent_id domain — localhost always derives to http."""
        url = Identity._idp_url_from_agent_id("agentid:localhost:agent_001")
        assert url == "http://localhost"

    def test_invalid_agent_id_raises(self):
        with pytest.raises(ValueError, match="Cannot derive IDP URL"):
            Identity._idp_url_from_agent_id("bad_id")

    def test_subdomain(self):
        url = Identity._idp_url_from_agent_id("agentid:idp.corp.example.com:agent_x")
        assert url == "https://idp.corp.example.com"


class TestIdpUrlOptional:
    def _make_identity(self, idp_url=None):
        pk = Ed25519PrivateKey.generate()
        return Identity(
            agent_id="agentid:myidp.example.com:agent_001",
            kid="kid123",
            private_key_bytes=pk.private_bytes_raw(),
            idp_url=idp_url,
        )

    def test_explicit_idp_url(self):
        identity = self._make_identity(idp_url="https://custom.example.com")
        assert identity.idp_url == "https://custom.example.com"

    def test_derived_idp_url(self):
        identity = self._make_identity()
        assert identity.idp_url == "https://myidp.example.com"


class TestFromZipPem:
    def test_from_zip_with_pem_key(self):
        pk = Ed25519PrivateKey.generate()
        pem_bytes = pk.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        config = {
            "agent_id": "agentid:test.example.com:agent_pem",
            "kid": "pemkid",
            "name": "pem-agent",
            "principal_id": "p-001",
        }

        buf = BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("agent.json", json.dumps(config))
            zf.writestr("private_key.pem", pem_bytes)

        identity = Identity.from_zip(BytesIO(buf.getvalue()))
        assert identity.agent_id == config["agent_id"]
        assert identity.kid == "pemkid"
        assert identity.idp_url == "https://test.example.com"
        # Verify signing works
        sig = identity.sign_token_request("https://hub.example.com", 1234567890)
        assert isinstance(sig, str) and len(sig) > 0

    def test_from_zip_without_idp_url(self):
        pk = Ed25519PrivateKey.generate()
        config = {
            "agent_id": "agentid:derived.example.com:agent_no_url",
            "kid": "kid456",
            "name": "no-url-agent",
            "principal_id": "p-002",
        }

        buf = BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("agent.json", json.dumps(config))
            zf.writestr("private_key", pk.private_bytes_raw())

        identity = Identity.from_zip(BytesIO(buf.getvalue()))
        assert identity.idp_url == "https://derived.example.com"

    def test_from_zip_pem_preferred_over_raw(self):
        """When both private_key.pem and private_key exist, PEM is used."""
        pk = Ed25519PrivateKey.generate()
        pem_bytes = pk.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        config = {
            "agent_id": "agentid:test.example.com:agent_both",
            "kid": "bothkid",
            "name": "both-agent",
            "principal_id": "p-003",
        }

        buf = BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("agent.json", json.dumps(config))
            zf.writestr("private_key.pem", pem_bytes)
            zf.writestr("private_key", pk.private_bytes_raw())

        identity = Identity.from_zip(BytesIO(buf.getvalue()))
        assert identity.agent_id == config["agent_id"]
        # Should work regardless of which key was loaded
        sig = identity.sign_token_request("https://hub.example.com", 1234567890)
        assert isinstance(sig, str) and len(sig) > 0
