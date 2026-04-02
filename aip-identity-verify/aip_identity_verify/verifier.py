from __future__ import annotations

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
    ) -> None:
        self._trusted_providers = [_normalise_domain(p) for p in trusted_providers]
        self._audience = audience
        self._cache_ttl = cache_ttl
        self._clock_skew_seconds = clock_skew_seconds
        # Optional override: provider_domain -> base URL (for local dev / non-https)
        self._provider_urls = provider_urls or {}
        # provider_domain -> (keys_by_kid, fetched_at)
        self._jwks_cache: dict[str, tuple[dict[str, Any], float]] = {}

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
        1. GET https://{provider_domain}/.well-known/aip-configuration
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

            # Step 1: discover JWKS URI.
            config_url = f"{base}/.well-known/aip-configuration"
            config_resp = await client.get(config_url)
            config_resp.raise_for_status()
            jwks_uri = config_resp.json()["jwks_uri"]

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

    async def verify(self, authorization_header: str) -> AIPAgent:
        """Verify an ``Authorization: AIP <token>`` header and return an `AIPAgent`.

        Raises:
            AIPTokenInvalid: header is malformed or audience mismatch.
            AIPProviderUntrusted: issuer is not in trusted_providers.
            AIPTokenExpired: token has expired.
            AIPSignatureInvalid: signature verification failed.
        """
        if not authorization_header or not authorization_header.startswith("AIP "):
            raise AIPTokenInvalid("Authorization header must start with 'AIP '")

        token = authorization_header[4:]

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
        try:
            claims = jwt.decode(
                token,
                public_key,
                algorithms=["ES256", "EdDSA"],
                audience=self._audience,
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

        return AIPAgent(
            agent_id=claims.get("sub", ""),
            agent_name=claims.get("agent_name", ""),
            principal=claims.get("principal", {}),
            capabilities=claims.get("capabilities", []),
            scopes=claims.get("scopes", {}),
            delegation=claims.get("delegation"),
            model_info=claims.get("model_info"),
            issuer=issuer,
            expires_at=datetime.fromtimestamp(claims["exp"], tz=timezone.utc),
            raw_claims=claims,
        )


def _normalise_domain(value: str) -> str:
    """Extract bare domain from a URL or return as-is if already a domain."""
    if "://" in value:
        return urlparse(value).netloc
    return value
