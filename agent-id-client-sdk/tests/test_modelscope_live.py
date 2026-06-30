"""Live control-plane smoke test for the ModelScope provider.

SKIPPED unless ``MODELSCOPE_ACCESS_TOKEN`` is set — it mutates a real ModelScope
environment (registers a throwaway hub + agent, then deletes both). Run on
demand:

    MODELSCOPE_ACCESS_TOKEN=ms-... pytest tests/test_modelscope_live.py

Covers the only path not exercisable offline: ``ModelScopeProvider.create_hub_app``
+ ``provision_agent`` (keygen → register) against the live IdP, then the
provisioned agent issues a token for the new hub and the JWT claims are checked.
Self-contained (no service SDK) — claims are decoded without signature verify.
"""

from __future__ import annotations

import asyncio
import os
import uuid

import httpx
import jwt as pyjwt
import pytest

from agent_id_client_sdk import Client, Identity
from agent_id_client_sdk.providers import provision_agent
from agent_id_client_sdk.providers.modelscope import ModelScopeProvider

_TOKEN = os.environ.get("MODELSCOPE_ACCESS_TOKEN")
_BASE = os.environ.get("MODELSCOPE_BASE", "https://pre.modelscope.cn/openapi/v1")

# Whole module is gated: nothing here runs without an AccessToken.
pytestmark = pytest.mark.skipif(
    not _TOKEN, reason="MODELSCOPE_ACCESS_TOKEN not set (live control-plane test)"
)


def _delete(path: str) -> None:
    """Best-effort cleanup so the live environment isn't left dirty."""
    try:
        httpx.delete(
            f"{_BASE}{path}",
            headers={"Authorization": f"Bearer {_TOKEN}"},
            timeout=20,
        )
    except Exception:  # noqa: BLE001
        pass


def test_provider_live_roundtrip():
    suffix = uuid.uuid4().hex[:8]
    # os.environ[...] is typed ``str`` (the module skips when it's unset).
    provider = ModelScopeProvider(os.environ["MODELSCOPE_ACCESS_TOKEN"], base_url=_BASE)
    hub = agent = None
    try:
        hub = provider.create_hub_app(
            app_name=f"sdk-smoke-{suffix}",
            app_homepage=f"https://sdk-smoke-{suffix}.example.com",
        )
        assert hub.client_id.startswith("hub_")

        agent, private_key = provision_agent(provider, f"smoke-{suffix}", save=False)
        assert agent.agent_id and agent.kid

        identity = Identity(agent.agent_id, agent.kid, private_key, idp_url=_BASE)
        token = asyncio.run(
            Client(identity, default_audience=hub.client_id, dpop=False).get_token()
        )

        claims = pyjwt.decode(token, options={"verify_signature": False})
        assert claims["sub"] == agent.agent_id
        assert claims["aud"] == hub.client_id
        assert "modelscope" in claims["iss"]
    finally:
        if agent is not None:
            _delete(f"/agent_ids/{agent.agent_id}")
        if hub is not None:
            _delete(f"/hub_apps/{hub.client_id}")
