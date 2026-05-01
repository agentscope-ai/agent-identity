from __future__ import annotations

import time
from urllib.parse import urlparse

import httpx

from .identity import Identity


class Client:
    """HTTP client that automatically manages AIP token acquisition."""

    def __init__(
        self,
        identity: Identity,
        default_audience: str | None = None,
    ) -> None:
        self._identity = identity
        self._default_audience = default_audience
        self._token_cache: dict[str, tuple[str, float]] = {}
        self._http = httpx.AsyncClient()

    # -- token management -----------------------------------------------------

    async def get_token(self, audience: str | None = None) -> str:
        """Return a valid JWT for *audience*, fetching a new one if needed."""
        audience = audience or self._default_audience
        if audience is None:
            raise ValueError("audience must be provided or set as default")

        now = time.time()
        cached = self._token_cache.get(audience)
        if cached is not None:
            token, expires_at = cached
            if now < expires_at - 60:  # 60-second safety margin
                return token

        # Request a new token from the IdP.
        timestamp = int(now)
        signature = self._identity.sign_token_request(audience, timestamp)

        resp = await self._http.post(
            f"{self._identity.idp_url}/aip/token",
            json={
                "agent_id": self._identity.agent_id,
                "kid": self._identity.kid,
                "audience": audience,
                "timestamp": str(timestamp),
                "signature": signature,
            },
        )
        resp.raise_for_status()
        data = resp.json()

        token = data["token"]
        expires_at = float(data["expires_at"])
        self._token_cache[audience] = (token, expires_at)
        return token

    # -- HTTP helpers ---------------------------------------------------------

    async def request(
        self,
        method: str,
        url: str,
        **kwargs,
    ) -> httpx.Response:
        """Send an HTTP request with an ``Authorization: AIP`` header.

        The audience is derived from the URL origin unless a default was set.
        On a 401 response the token is refreshed and the request retried once.
        """
        audience = self._audience_from_url(url)
        token = await self.get_token(audience)

        headers = kwargs.pop("headers", {}) or {}
        headers["Authorization"] = f"AIP {token}"
        kwargs["headers"] = headers

        resp = await self._http.request(method, url, **kwargs)

        if resp.status_code == 401:
            # Invalidate cache and retry once.
            self._token_cache.pop(audience, None)
            token = await self.get_token(audience)
            kwargs["headers"]["Authorization"] = f"AIP {token}"
            resp = await self._http.request(method, url, **kwargs)

        return resp

    async def get(self, url: str, **kwargs) -> httpx.Response:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> httpx.Response:
        return await self.request("POST", url, **kwargs)

    # -- internals ------------------------------------------------------------

    def _audience_from_url(self, url: str) -> str:
        if self._default_audience:
            return self._default_audience
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"
