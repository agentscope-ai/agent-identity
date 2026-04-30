from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import httpx
import jwt
from jwt import PyJWK

from .errors import (
    AIPProviderUntrusted,
    AIPTokenExpired,
    AIPTokenInvalid,
    AIPSignatureInvalid,
)
from .events import ActivityEvent, category_tier, match_category

logger = logging.getLogger(__name__)

# Bounded outbox so a slow activity service can't push the hub OOM.
_EMIT_QUEUE_MAX = 1024


@dataclass
class AIPAgent:
    """Parsed and verified agent identity from a JWT."""

    agent_id: str
    agent_name: str
    principal: dict
    capabilities: list[str]
    scopes: dict
    delegation: dict | None
    model_info: dict | None
    issuer: str
    expires_at: datetime
    raw_claims: dict


class AIPVerifier:
    """Verifies AIP JWT tokens issued by trusted identity providers."""

    def __init__(
        self,
        trusted_providers: list[str],
        audience: str,
        cache_ttl: int = 3600,
        clock_skew_seconds: int = 30,
        provider_urls: dict[str, str] | None = None,
        # --- activity reporting (all optional; reporting opt-in) ---
        activity_api_key: str | None = None,
        activity_endpoint: str | None = None,
        event_categories: set[str] | None = None,
        no_report_paths: set[str] | None = None,
        service_name: str = "",
        hub_namespace: str | None = None,
        report_auto_verify: bool = False,
        agent_token_for_emit: str | None = None,
    ) -> None:
        self._trusted_providers = [_normalise_domain(p) for p in trusted_providers]
        self._audience = audience
        self._cache_ttl = cache_ttl
        self._clock_skew_seconds = clock_skew_seconds
        # Optional override: provider_domain -> base URL (for local dev / non-https)
        self._provider_urls = provider_urls or {}
        # provider_domain -> (keys_by_kid, fetched_at)
        self._jwks_cache: dict[str, tuple[dict[str, Any], float]] = {}
        # provider_domain -> activity_endpoint URL (refreshed alongside JWKS)
        self._activity_endpoint_cache: dict[str, str] = {}

        # --- activity-reporting state ---
        self._activity_api_key = activity_api_key
        self._activity_endpoint_override = activity_endpoint
        self._event_categories = event_categories  # None = no filter
        self._no_report_paths = no_report_paths or set()
        self._service_name = service_name
        self._hub_namespace = hub_namespace
        self._report_auto_verify = report_auto_verify
        # The hub's own agent token (forwarded as X-AIP-Token); without this,
        # aip-activity will reject events as the principal-policy claim is
        # unverifiable. Optional — emit just logs and drops if missing.
        self._agent_token_for_emit = agent_token_for_emit

        # Lazily-initialized async resources. Created on first emit so the
        # verifier can be constructed outside an event loop.
        # Each queued item is (event, resolved_activity_endpoint_url) — the
        # endpoint is resolved per-issuer at enqueue time and carried alongside
        # the event so the drain task doesn't have to re-resolve it.
        self._emit_client: httpx.AsyncClient | None = None
        self._emit_queue: asyncio.Queue[tuple[ActivityEvent, str]] | None = None
        self._emit_drain_task: asyncio.Task[None] | None = None
        self._emit_overflow_count = 0

    # -- JWKS fetching --------------------------------------------------------

    async def _fetch_jwks(
        self,
        provider_domain: str,
        *,
        force_refresh: bool = False,
    ) -> dict[str, Any]:
        """Fetch and cache public keys from the provider's JWKS.

        Supports EC (P-256) and OKP (Ed25519) key types.

        Args:
            provider_domain: The IDP domain to fetch keys from.
            force_refresh: If True, bypass the cache and refetch from the IDP.
                Used when a token references a kid not in the cached JWKS
                (e.g. after key rotation).

        Discovery flow:
        1. GET https://{provider_domain}/.well-known/agentid-configuration
           (falls back to /.well-known/aip-configuration during the rename
           soft-migration window — Phase 4 of the AgentID rebrand).
        2. Extract ``jwks_uri`` from the response.
        3. GET {jwks_uri} and parse the JWKS key set.
        """
        now = time.time()
        if not force_refresh:
            cached = self._jwks_cache.get(provider_domain)
            if cached is not None:
                keys, fetched_at = cached
                if now - fetched_at < self._cache_ttl:
                    return keys

        async with httpx.AsyncClient() as client:
            base = self._provider_urls.get(
                provider_domain, f"https://{provider_domain}"
            )

            # Step 1: discover JWKS URI (and activity_endpoint while we're here).
            # Prefer the AgentID-named endpoint; fall back to the legacy AIP one
            # for IdPs that haven't migrated yet.
            config_url = f"{base}/.well-known/agentid-configuration"
            config_resp = await client.get(config_url)
            if config_resp.status_code == 404:
                config_url = f"{base}/.well-known/aip-configuration"
                config_resp = await client.get(config_url)
            config_resp.raise_for_status()
            config_data = config_resp.json()
            jwks_uri = config_data["jwks_uri"]
            activity_endpoint = config_data.get("activity_endpoint")
            if activity_endpoint:
                # Apply provider_url override if set (local-dev URL rewriting).
                if provider_domain in self._provider_urls:
                    path = urlparse(activity_endpoint).path or "/aip/activity"
                    activity_endpoint = f"{base}{path}"
                self._activity_endpoint_cache[provider_domain] = activity_endpoint

            # Step 2: fetch JWKS.
            # If a provider_url override is set, resolve jwks_uri relative to
            # the override base (the discovery doc may advertise a production URL
            # that is not reachable in local dev).
            if provider_domain in self._provider_urls:
                path = urlparse(jwks_uri).path
                jwks_uri = f"{base}{path}"

            jwks_resp = await client.get(jwks_uri)
            jwks_resp.raise_for_status()
            jwks_data = jwks_resp.json()

        keys: dict[str, Any] = {}
        for key_data in jwks_data.get("keys", []):
            kty = key_data.get("kty")
            kid = key_data.get("kid")
            if not kid:
                continue
            # Accept EC (P-256) keys — used by production IDPs
            if kty == "EC" and key_data.get("crv") == "P-256":
                jwk = PyJWK(key_data)
                keys[kid] = jwk.key
            # Accept OKP (Ed25519) keys — for backwards compatibility
            elif kty == "OKP" and key_data.get("crv") == "Ed25519":
                jwk = PyJWK(key_data)
                keys[kid] = jwk.key

        self._jwks_cache[provider_domain] = (keys, now)
        return keys

    # -- verification ---------------------------------------------------------

    async def verify(
        self,
        authorization_header: str,
        request_context: dict[str, Any] | None = None,
    ) -> AIPAgent:
        """Verify an ``Authorization: Bearer <token>`` (or legacy
        ``Authorization: AIP <token>``) header and return an `AIPAgent`.

        Convenience wrapper for HTTP handlers. For non-HTTP transports
        (WebSocket, gRPC, MCP), use :meth:`verify_token` directly.

        Both ``Bearer`` (the OAuth 2.0 standard, AgentID's long-term form)
        and ``AIP`` (the legacy custom scheme) are accepted during the
        rename soft-migration window. Phase 9 will drop ``AIP``.

        `request_context` is an optional dict carrying `route` and other
        per-request context. Only used when `report_auto_verify=True`.

        Raises:
            AIPTokenInvalid: header is malformed or audience mismatch.
            AIPProviderUntrusted: issuer is not in trusted_providers.
            AIPTokenExpired: token has expired.
            AIPSignatureInvalid: signature verification failed.
        """
        if not authorization_header:
            raise AIPTokenInvalid("Authorization header is required")

        if authorization_header.startswith("Bearer "):
            token = authorization_header[7:]
        elif authorization_header.startswith("AIP "):
            token = authorization_header[4:]
        else:
            raise AIPTokenInvalid(
                "Authorization header must start with 'Bearer ' or 'AIP '"
            )

        return await self.verify_token(token, request_context=request_context)

    async def verify_token(
        self,
        token: str,
        request_context: dict[str, Any] | None = None,
        audience: str | list[str] | None = None,
    ) -> AIPAgent:
        """Verify a raw AIP JWT string and return an `AIPAgent`.

        Transport-agnostic — use this for WebSocket, gRPC, MCP, or any
        non-HTTP transport where the token isn't in an Authorization header.

        Raises:
            AIPTokenInvalid: token is malformed or audience mismatch.
            AIPProviderUntrusted: issuer is not in trusted_providers.
            AIPTokenExpired: token has expired.
            AIPSignatureInvalid: signature verification failed.
        """
        # Decode header (unverified) to get kid.
        try:
            unverified_header = jwt.get_unverified_header(token)
        except jwt.exceptions.DecodeError as exc:
            raise AIPTokenInvalid(f"Malformed JWT: {exc}") from exc

        kid = unverified_header.get("kid")
        if not kid:
            raise AIPTokenInvalid("JWT header missing 'kid'")

        # Decode payload (unverified) to get iss.
        try:
            unverified_payload = jwt.decode(token, options={"verify_signature": False})
        except jwt.exceptions.DecodeError as exc:
            raise AIPTokenInvalid(f"Malformed JWT payload: {exc}") from exc

        issuer = unverified_payload.get("iss")
        if not issuer:
            raise AIPTokenInvalid("JWT missing 'iss' claim")

        provider_domain = _normalise_domain(issuer)

        # Check trusted providers.
        if provider_domain not in self._trusted_providers:
            raise AIPProviderUntrusted(f"Provider '{provider_domain}' is not trusted")

        # Fetch JWKS and find the key. If the kid is missing, refetch
        # once in case the IDP rotated keys since we last cached.
        keys = await self._fetch_jwks(provider_domain)
        public_key = keys.get(kid)
        if public_key is None:
            keys = await self._fetch_jwks(provider_domain, force_refresh=True)
            public_key = keys.get(kid)
        if public_key is None:
            raise AIPTokenInvalid(
                f"Key '{kid}' not found in JWKS for '{provider_domain}'"
            )

        # Verify signature, audience, and expiration.
        # `audience` arg overrides the constructor default — used by services
        # like aip-activity that verify tokens issued for arbitrary hubs.
        effective_audience = audience if audience is not None else self._audience
        try:
            claims = jwt.decode(
                token,
                public_key,
                algorithms=["ES256", "EdDSA"],
                audience=effective_audience,
                leeway=self._clock_skew_seconds,
                options={"require": ["exp", "iss", "aud"]},
            )
        except jwt.ExpiredSignatureError as exc:
            raise AIPTokenExpired(str(exc)) from exc
        except jwt.InvalidAudienceError as exc:
            raise AIPTokenInvalid(f"Audience mismatch: {exc}") from exc
        except jwt.InvalidSignatureError as exc:
            raise AIPSignatureInvalid(str(exc)) from exc
        except jwt.PyJWTError as exc:
            raise AIPTokenInvalid(str(exc)) from exc

        # Stash kid into raw_claims so report_event can pull it out without
        # re-parsing the JWT header. (kid lives in the header, not the claims.)
        claims_with_kid = dict(claims)
        claims_with_kid["_kid"] = kid

        agent = AIPAgent(
            agent_id=claims.get("sub", ""),
            agent_name=claims.get("agent_name", ""),
            principal=claims.get("principal", {}),
            capabilities=claims.get("capabilities", []),
            scopes=claims.get("scopes", {}),
            delegation=claims.get("delegation"),
            model_info=claims.get("model_info"),
            issuer=issuer,
            expires_at=datetime.fromtimestamp(claims["exp"], tz=timezone.utc),
            raw_claims=claims_with_kid,
        )

        # Auto-emit auth.verify if configured. Best-effort, never raises.
        if self._report_auto_verify and self._activity_api_key:
            route = (request_context or {}).get("route")
            try:
                await self.report_event(
                    category="auth.verify",
                    agent=agent,
                    payload={"route": route or "", "success": True},
                    outcome="success",
                    route=route,
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("auto-emit auth.verify failed: %s", exc)

        return agent

    # -- activity reporting ---------------------------------------------------

    async def report_event(
        self,
        *,
        category: str,
        agent: AIPAgent,
        payload: dict[str, Any] | None = None,
        ext: dict[str, Any] | None = None,
        outcome: str = "n/a",
        session_id: str | None = None,
        route: str | None = None,
        timestamp: datetime | None = None,
    ) -> None:
        """Emit a single activity event to aip-activity. Best-effort, never raises.

        Hub-side gating:
          - Drops if `route` is in `no_report_paths`.
          - Drops if `category` doesn't match any pattern in `event_categories`.
          - Rejects (logs warning, drops) Tier 2 categories whose namespace
            doesn't match this verifier's `hub_namespace`.

        On transport failure, logs at WARNING and drops the event. On overflow
        of the bounded outbox, drops the oldest pending event.
        """
        if route is not None and route in self._no_report_paths:
            return
        if self._event_categories is not None and not any(
            match_category(p, category) for p in self._event_categories
        ):
            return

        tier = category_tier(category, self._hub_namespace)
        if tier == 0:
            logger.warning(
                "report_event: category %r is not Tier 1, allowed Tier 2 namespace, "
                "or custom.* — dropping",
                category,
            )
            return

        if not self._activity_api_key:
            # Reporting not configured; silently no-op.
            return

        kid = agent.raw_claims.get("kid", "")  # tokens carry kid in header, not claims
        if not kid:
            # Fall back to the unverified header; verify_token already validated it.
            kid = agent.raw_claims.get("_kid", "")

        evt = ActivityEvent.build(
            category=category,
            agent_id=agent.agent_id,
            principal_id=agent.principal.get("id", "") if agent.principal else "",
            audience=self._audience,
            issuer=agent.issuer,
            kid=kid,
            service=self._service_name,
            session_id=session_id,
            outcome=outcome,
            payload=payload,
            ext=ext,
            timestamp=timestamp,
        )

        await self._enqueue_event(evt, agent.issuer)

    async def report_session_start(
        self,
        agent: AIPAgent,
        session_id: str,
        **payload_extras: Any,
    ) -> None:
        """Convenience wrapper for emitting a `session.start` event."""
        payload = {"session_id": session_id, **payload_extras}
        await self.report_event(
            category="session.start",
            agent=agent,
            payload=payload,
            session_id=session_id,
            outcome="n/a",
        )

    async def report_session_end(
        self,
        agent: AIPAgent,
        session_id: str,
        duration_ms: int,
        **payload_extras: Any,
    ) -> None:
        """Convenience wrapper for emitting a `session.end` event."""
        payload = {
            "session_id": session_id,
            "duration_ms": duration_ms,
            **payload_extras,
        }
        await self.report_event(
            category="session.end",
            agent=agent,
            payload=payload,
            session_id=session_id,
            outcome="success",
        )

    async def _enqueue_event(self, evt: ActivityEvent, issuer: str) -> None:
        await self._ensure_emitter()
        # Resolve activity endpoint — override > discovery cache > skip.
        endpoint = (
            self._activity_endpoint_override
            or self._activity_endpoint_cache.get(_normalise_domain(issuer))
        )
        if not endpoint:
            logger.warning(
                "report_event: activity_endpoint not in discovery cache yet "
                "for %r and no override set; dropping event %s",
                issuer,
                evt.event_id,
            )
            return

        # _ensure_emitter() above guarantees the queue is initialised.
        assert self._emit_queue is not None
        try:
            self._emit_queue.put_nowait((evt, endpoint))
        except asyncio.QueueFull:
            # Drop oldest, increment counter
            try:
                self._emit_queue.get_nowait()
                self._emit_overflow_count += 1
            except asyncio.QueueEmpty:
                pass
            try:
                self._emit_queue.put_nowait((evt, endpoint))
            except asyncio.QueueFull:
                self._emit_overflow_count += 1

    async def _ensure_emitter(self) -> None:
        if self._emit_client is None:
            self._emit_client = httpx.AsyncClient(timeout=5.0)
        if self._emit_queue is None:
            self._emit_queue = asyncio.Queue(maxsize=_EMIT_QUEUE_MAX)
        if self._emit_drain_task is None or self._emit_drain_task.done():
            self._emit_drain_task = asyncio.create_task(self._drain_emitter())

    async def _drain_emitter(self) -> None:
        """Pull queued events and POST them. Survives transport errors."""
        assert self._emit_queue is not None
        assert self._emit_client is not None
        while True:
            evt, endpoint = await self._emit_queue.get()
            try:
                headers = {
                    "Authorization": f"Bearer {self._activity_api_key}",
                    "Content-Type": "application/json",
                }
                if self._agent_token_for_emit:
                    headers["X-AIP-Token"] = self._agent_token_for_emit
                resp = await self._emit_client.post(
                    endpoint,
                    headers=headers,
                    json={"events": [evt.to_dict()]},
                )
                if resp.status_code >= 400:
                    logger.warning(
                        "activity emit failed: %s %s — %s",
                        resp.status_code,
                        endpoint,
                        resp.text[:200],
                    )
            except Exception as exc:  # noqa: BLE001 — never raise from drain
                logger.warning("activity emit transport error: %s", exc)


def _normalise_domain(value: str) -> str:
    """Extract bare domain from a URL or return as-is if already a domain."""
    if "://" in value:
        return urlparse(value).netloc
    return value
