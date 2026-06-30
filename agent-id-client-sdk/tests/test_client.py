"""Tests for the ModelScope Agent IdP token-exchange protocol in Client.

These drive the async ``get_token`` via ``asyncio.run`` so they need no
pytest-asyncio configuration. httpx ``MockTransport`` stands in for the IdP.
"""

from __future__ import annotations

import asyncio
import base64
import json

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_id_client_sdk.client import Client
from agent_id_client_sdk.identity import Identity


def _identity() -> Identity:
    pk = Ed25519PrivateKey.generate()
    return Identity(
        agent_id="aip:identity.modelscope.cn:agent_x",
        kid="key-1",
        private_key_bytes=pk.private_bytes_raw(),
        idp_url="https://idp.example.com/openapi/v1",
    )


def _client_with(handler) -> Client:
    client = Client(_identity(), default_audience="hub_abc123")
    client._http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return client


def _ok_response(_request: httpx.Request) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "success": True,
            "request_id": "r1",
            "data": {
                "access_token": "the.jwt.token",
                "token_type": "Bearer",
                "expires_in": 600,
                "jti": "jti-1",
            },
        },
    )


def test_get_token_modelscope_protocol():
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["body"] = json.loads(request.content)
        return _ok_response(request)

    client = _client_with(handler)
    token = asyncio.run(client.get_token())

    assert token == "the.jwt.token"
    # POSTs to the ModelScope token endpoint (singular agent_id).
    assert captured["url"].endswith("/agent_id/token")

    body = captured["body"]
    # timestamp is an int, not a string.
    assert isinstance(body["timestamp"], int)
    # audience is the hub client_id, passed through verbatim.
    assert body["audience"] == "hub_abc123"
    # signature is base64url (decodes to a 64-byte Ed25519 sig), not hex.
    sig = body["signature"]
    sig_bytes = base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4))
    assert len(sig_bytes) == 64


def test_get_token_caches_until_expiry():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return _ok_response(request)

    client = _client_with(handler)

    async def run_twice():
        await client.get_token()
        await client.get_token()

    asyncio.run(run_twice())
    # Second call served from cache (expires_in 600 >> 60s safety margin).
    assert calls["n"] == 1


def test_get_token_raises_on_success_false():
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "success": False,
                "code": "InvalidAuthentication",
                "message": "bad signature",
                "request_id": "r2",
            },
        )

    client = _client_with(handler)

    try:
        asyncio.run(client.get_token())
    except RuntimeError as exc:
        assert "InvalidAuthentication" in str(exc)
    else:
        raise AssertionError("expected RuntimeError on success=false")


def test_get_token_raises_on_malformed_200():
    """A 200 with no `data` object yields a clear RuntimeError, not a KeyError."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"success": True, "request_id": "r"})

    client = _client_with(handler)
    try:
        asyncio.run(client.get_token())
    except RuntimeError as exc:
        assert "malformed" in str(exc).lower()
    except KeyError:
        raise AssertionError("got raw KeyError instead of a clear RuntimeError")
    else:
        raise AssertionError("expected RuntimeError on malformed response")
