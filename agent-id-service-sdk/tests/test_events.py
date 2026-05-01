"""Tests for Verifier.report_event + the events helper module."""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, patch

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_id_service_sdk.events import (
    ActivityEvent,
    TIER1_CATEGORIES,
    category_tier,
    match_category,
)
from agent_id_service_sdk.verifier import VerifiedAgent, Verifier


PROVIDER_DOMAIN = "idp.example.com"
AUDIENCE = "https://hub.example.com"
KID = "test-key-1"


def _make_agent() -> VerifiedAgent:
    return VerifiedAgent(
        agent_id="agentid:idp.example.com:agent_x",
        agent_name="bot",
        principal={"id": "p1", "name": "alice", "type": "human"},
        capabilities=[],
        scopes={},
        delegation=None,
        model_info=None,
        issuer="https://idp.example.com",
        expires_at=None,  # type: ignore[arg-type]
        raw_claims={"_kid": KID},
    )


def _build_verifier(**kwargs) -> Verifier:
    v = Verifier(
        trusted_providers=[PROVIDER_DOMAIN],
        audience=AUDIENCE,
        **kwargs,
    )
    # Pre-seed activity_endpoint so report_event doesn't fail on lookup.
    v._activity_endpoint_cache[PROVIDER_DOMAIN] = (
        "https://activity.example.com/aip/activity"
    )
    return v


# ---------------------------------------------------------------------------
# match_category
# ---------------------------------------------------------------------------


class TestPatternMatching:
    def test_literal_match(self):
        assert match_category("model.call", "model.call")
        assert not match_category("model.call", "tool.use")

    def test_namespaced_wildcard(self):
        assert match_category("dojozero.*", "dojozero.bet_decision")
        assert match_category("dojozero.*", "dojozero.trial_outcome")
        assert not match_category("dojozero.*", "acme.bet")

    def test_namespace_must_match_exactly(self):
        # `dojozero.*` should not match `dojozeronaut.foo`
        assert not match_category("dojozero.*", "dojozeronaut.foo")

    def test_custom_wildcard(self):
        assert match_category("custom.*", "custom.experiment_42")
        assert not match_category("custom.*", "model.call")

    def test_full_wildcard(self):
        assert match_category("*", "anything.at.all")

    def test_suffix_wildcard(self):
        assert match_category("*.verify", "auth.verify")
        assert not match_category("*.verify", "auth.deny")


# ---------------------------------------------------------------------------
# category_tier
# ---------------------------------------------------------------------------


class TestCategoryTier:
    def test_tier1(self):
        for cat in TIER1_CATEGORIES:
            assert category_tier(cat) == 1

    def test_tier2_namespace_match(self):
        assert category_tier("dojozero.bet", hub_namespace="dojozero") == 2

    def test_tier2_namespace_mismatch_returns_zero(self):
        # SDK refuses to emit another hub's namespace.
        assert category_tier("acme.bet", hub_namespace="dojozero") == 0

    def test_tier2_no_namespace_check(self):
        # When hub_namespace=None, server validates instead.
        assert category_tier("acme.bet") == 2

    def test_tier3(self):
        assert category_tier("custom.experiment") == 3

    def test_invalid(self):
        # No prefix, not Tier 1, not custom → 0
        assert category_tier("foobar") == 0


# ---------------------------------------------------------------------------
# ActivityEvent.build
# ---------------------------------------------------------------------------


class TestActivityEventBuild:
    def test_build_populates_envelope(self):
        evt = ActivityEvent.build(
            category="model.call",
            agent_id="a",
            principal_id="p",
            audience="https://hub",
            issuer="https://idp",
            kid="k",
            service="svc",
            payload={"model": "qwen"},
        )
        assert evt.event_id  # auto-generated
        assert evt.aip_version == "0.1"
        assert evt.category == "model.call"
        assert evt.payload == {"model": "qwen"}
        assert evt.ext is None

    def test_to_dict_omits_ext_when_none(self):
        evt = ActivityEvent.build(
            category="model.call",
            agent_id="a",
            principal_id="p",
            audience="https://hub",
            issuer="https://idp",
            kid="k",
            service="svc",
        )
        d = evt.to_dict()
        assert "ext" not in d


# ---------------------------------------------------------------------------
# Verifier.report_event behavior
# ---------------------------------------------------------------------------


class TestReportEvent:
    @pytest.mark.asyncio
    async def test_silent_drop_outside_allowlist(self):
        verifier = _build_verifier(
            activity_api_key="fake",
            event_categories={"auth.verify"},  # only auth.verify allowed
            service_name="my-hub",
        )
        with patch.object(verifier, "_enqueue_event") as mock_enq:
            await verifier.report_event(
                category="model.call",
                agent=_make_agent(),
                payload={"model": "qwen", "tokens_in": 10, "tokens_out": 1},
            )
        mock_enq.assert_not_called()

    @pytest.mark.asyncio
    async def test_no_report_paths(self):
        verifier = _build_verifier(
            activity_api_key="fake",
            no_report_paths={"/health"},
            service_name="my-hub",
        )
        with patch.object(verifier, "_enqueue_event") as mock_enq:
            await verifier.report_event(
                category="model.call",
                agent=_make_agent(),
                route="/health",
            )
        mock_enq.assert_not_called()

    @pytest.mark.asyncio
    async def test_namespace_must_match_hub_namespace(self):
        # SDK has hub_namespace="dojozero"; refuses to emit acme.*
        verifier = _build_verifier(
            activity_api_key="fake",
            hub_namespace="dojozero",
            service_name="my-hub",
        )
        with patch.object(verifier, "_enqueue_event") as mock_enq:
            await verifier.report_event(
                category="acme.bet",
                agent=_make_agent(),
                payload={"x": 1},
            )
        mock_enq.assert_not_called()

    @pytest.mark.asyncio
    async def test_no_api_key_silent_noop(self):
        verifier = _build_verifier(service_name="my-hub")  # no api key
        with patch.object(verifier, "_enqueue_event") as mock_enq:
            await verifier.report_event(
                category="model.call",
                agent=_make_agent(),
                payload={"model": "x", "tokens_in": 1, "tokens_out": 1},
            )
        mock_enq.assert_not_called()

    @pytest.mark.asyncio
    async def test_emits_to_queue_when_allowlisted(self):
        verifier = _build_verifier(
            activity_api_key="fake",
            event_categories={"model.call", "tool.use"},
            service_name="my-hub",
        )
        with patch.object(verifier, "_enqueue_event") as mock_enq:
            await verifier.report_event(
                category="model.call",
                agent=_make_agent(),
                payload={"model": "qwen", "tokens_in": 1, "tokens_out": 1},
            )
        mock_enq.assert_called_once()
        evt = mock_enq.call_args.args[0]
        assert evt.category == "model.call"
        assert evt.agent_id == "agentid:idp.example.com:agent_x"
        assert evt.audience == AUDIENCE


# ---------------------------------------------------------------------------
# Auto-emit on verify success
# ---------------------------------------------------------------------------


class TestAutoEmitOnVerify:
    @pytest.mark.asyncio
    async def test_auto_emit_when_enabled(self):
        private_key = Ed25519PrivateKey.generate()
        verifier = Verifier(
            trusted_providers=[PROVIDER_DOMAIN],
            audience=AUDIENCE,
            activity_api_key="fake",
            report_auto_verify=True,
            service_name="my-hub",
        )
        verifier._jwks_cache[PROVIDER_DOMAIN] = (
            {KID: private_key.public_key()},
            time.time(),
        )
        verifier._activity_endpoint_cache[PROVIDER_DOMAIN] = (
            "https://activity.example.com/aip/activity"
        )

        token = pyjwt.encode(
            {
                "sub": "agent-001",
                "iss": f"https://{PROVIDER_DOMAIN}",
                "aud": AUDIENCE,
                "exp": int(time.time()) + 3600,
                "principal": {"id": "p1"},
            },
            private_key,
            algorithm="EdDSA",
            headers={"kid": KID},
        )

        with patch.object(verifier, "report_event", new=AsyncMock()) as mock_emit:
            await verifier.verify_token(token, request_context={"route": "/api/foo"})
        mock_emit.assert_called_once()
        kwargs = mock_emit.call_args.kwargs
        assert kwargs["category"] == "auth.verify"
        assert kwargs["payload"]["route"] == "/api/foo"

    @pytest.mark.asyncio
    async def test_no_auto_emit_when_disabled(self):
        private_key = Ed25519PrivateKey.generate()
        verifier = Verifier(
            trusted_providers=[PROVIDER_DOMAIN],
            audience=AUDIENCE,
            activity_api_key="fake",
            report_auto_verify=False,  # default
        )
        verifier._jwks_cache[PROVIDER_DOMAIN] = (
            {KID: private_key.public_key()},
            time.time(),
        )

        token = pyjwt.encode(
            {
                "sub": "agent-001",
                "iss": f"https://{PROVIDER_DOMAIN}",
                "aud": AUDIENCE,
                "exp": int(time.time()) + 3600,
                "principal": {"id": "p1"},
            },
            private_key,
            algorithm="EdDSA",
            headers={"kid": KID},
        )

        with patch.object(verifier, "report_event", new=AsyncMock()) as mock_emit:
            await verifier.verify_token(token)
        mock_emit.assert_not_called()
