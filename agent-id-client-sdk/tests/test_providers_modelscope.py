"""Tests for the provider (adapter) layer and the ModelScope provider."""

from __future__ import annotations

import base64
import json

import httpx
import pytest

from agent_id_client_sdk.providers import (
    IdentityProvider,
    ProviderError,
    RegisteredAgent,
    build_public_jwk,
    provision_agent,
)
from agent_id_client_sdk.providers.modelscope import ModelScopeProvider

BASE = "https://www.modelscope.cn/openapi/v1"


def _provider(handler, token: str = "ms-token") -> ModelScopeProvider:
    client = httpx.Client(transport=httpx.MockTransport(handler))
    return ModelScopeProvider(token, base_url=BASE, http=client)


def test_build_public_jwk():
    pub = bytes(range(32))
    jwk = build_public_jwk(pub, "key-1")
    assert jwk["kty"] == "OKP"
    assert jwk["crv"] == "Ed25519"
    assert jwk["kid"] == "key-1"
    # x is base64url (no padding) of the 32-byte key.
    x = jwk["x"]
    assert "=" not in x
    assert base64.urlsafe_b64decode(x + "=" * (-len(x) % 4)) == pub


def test_register_agent():
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["auth"] = request.headers.get("authorization")
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "success": True,
                "request_id": "r1",
                "data": {
                    "agent_id": "aip:identity.modelscope.cn:agent_x",
                    "agent_name": "my-agent",
                    "kid": "key-1",
                    "status": "active",
                    "create_time": "2025-01-15T10:30:00Z",
                },
            },
        )

    provider = _provider(handler)
    jwk = build_public_jwk(bytes(range(32)), "key-1")
    agent = provider.register_agent(
        agent_name="my-agent", public_jwk=jwk, token_expire_time=600
    )

    assert isinstance(agent, RegisteredAgent)
    assert agent.agent_id == "aip:identity.modelscope.cn:agent_x"
    assert agent.kid == "key-1"
    assert agent.status == "active"

    # POSTs to /agent_ids (plural) with the AccessToken bearer + JWK body.
    assert captured["url"].endswith("/agent_ids")
    assert captured["auth"] == "Bearer ms-token"
    body = captured["body"]
    assert body["agent_name"] == "my-agent"
    assert body["public_key"]["kty"] == "OKP"
    assert body["public_key"]["kid"] == "key-1"
    assert body["token_expire_time"] == 600


def test_create_hub_app():
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "success": True,
                "request_id": "r2",
                "data": {
                    "client_id": "hub_4abb08",
                    "app_name": "Dojo",
                    "app_homepage": "https://dojo.example.com",
                    "owner": "myuser",
                    "create_time": "2025-01-15T11:00:00Z",
                },
            },
        )

    provider = _provider(handler)
    hub = provider.create_hub_app(
        app_name="Dojo", app_homepage="https://dojo.example.com"
    )

    assert hub.client_id == "hub_4abb08"
    assert hub.owner == "myuser"
    assert captured["url"].endswith("/hub_apps")
    assert captured["body"]["app_homepage"] == "https://dojo.example.com"


def test_error_envelope_raises_provider_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "success": False,
                "code": "DuplicateEntity",
                "message": "homepage already registered",
                "request_id": "r3",
            },
        )

    provider = _provider(handler)
    with pytest.raises(ProviderError) as exc:
        provider.create_hub_app(app_name="Dojo", app_homepage="https://dup.example.com")
    assert exc.value.code == "DuplicateEntity"
    assert exc.value.request_id == "r3"


def test_http_error_surfaces():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            401, json={"success": False, "code": "InvalidAuthentication"}
        )

    provider = _provider(handler)
    with pytest.raises(httpx.HTTPStatusError):
        provider.register_agent(
            agent_name="x", public_jwk=build_public_jwk(bytes(32), "k")
        )


class _FakeProvider(IdentityProvider):
    """Captures the registration call without any network."""

    idp_url = "https://idp.example/openapi/v1"

    def __init__(self) -> None:
        self.jwk: dict | None = None

    def register_agent(
        self, *, agent_name, public_jwk, description="", token_expire_time=None
    ):
        self.jwk = public_jwk
        return RegisteredAgent(
            agent_id="aip:idp.example:agent_1",
            kid=public_jwk["kid"],
            agent_name=agent_name,
        )

    def create_hub_app(
        self, *, app_name, app_homepage, app_logo=None
    ):  # pragma: no cover
        raise NotImplementedError


def test_provision_agent_orchestration():
    provider = _FakeProvider()
    registered, private_key = provision_agent(provider, "bob", save=False)

    # Registered identity reflects the generated keypair's kid.
    assert registered.agent_id == "aip:idp.example:agent_1"
    assert provider.jwk is not None
    assert provider.jwk["kty"] == "OKP"
    assert registered.kid == provider.jwk["kid"]

    # Raw Ed25519 private seed is 32 bytes; never uploaded.
    assert isinstance(private_key, bytes) and len(private_key) == 32


def test_unwrap_raises_provider_error_on_malformed_200():
    """A 200 with no `data` object yields a ProviderError, not a KeyError."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"success": True, "request_id": "r"})

    provider = _provider(handler)
    with pytest.raises(ProviderError):
        provider.create_hub_app(app_name="x", app_homepage="https://x.example")
