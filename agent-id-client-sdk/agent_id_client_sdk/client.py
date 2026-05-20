from __future__ import annotations

import time
from urllib.parse import urlparse

import httpx

from .identity import Identity


class Client:
    """HTTP client that automatically manages AgentID token acquisition.

    Set ``dpop=True`` to attach a per-request DPoP proof (RFC 9449) and
    switch the Authorization scheme from ``Bearer`` to ``DPoP``. The
    identity's private key signs each proof; the verifier on the hub
    side checks the proof against the token's ``cnf.jkt`` binding.

    Hubs running with ``dpop_mode="optional"`` accept either; hubs running
    with ``dpop_mode="required"`` reject Bearer. When the hub returns
    ``401`` for a bearer request that should have been DPoP, set
    ``dpop=True``.
    """

    def __init__(
        self,
        identity: Identity,
        default_audience: str | None = None,
        *,
        dpop: bool = False,
    ) -> None:
        self._identity = identity
        self._default_audience = default_audience
        self._token_cache: dict[str, tuple[str, float]] = {}
        self._http = httpx.AsyncClient()
        self._dpop = dpop

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
            f"{self._identity.idp_url}/agentid/token",
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
        """Send an HTTP request with an Authorization header.

        Uses ``Bearer`` by default; when ``dpop=True`` was passed to the
        ``Client`` constructor, attaches a freshly-signed DPoP proof
        (RFC 9449) and switches the Authorization scheme to ``DPoP``.

        The audience is derived from the URL origin unless a default was set.
        On a 401 response the token is refreshed and the request retried once.
        """
        audience = self._audience_from_url(url)
        token = await self.get_token(audience)

        headers = kwargs.pop("headers", {}) or {}
        self._attach_auth_headers(headers, method=method, url=url, token=token)
        kwargs["headers"] = headers

        resp = await self._http.request(method, url, **kwargs)

        if resp.status_code == 401:
            # Invalidate cache and retry once.
            self._token_cache.pop(audience, None)
            token = await self.get_token(audience)
            self._attach_auth_headers(
                kwargs["headers"], method=method, url=url, token=token
            )
            resp = await self._http.request(method, url, **kwargs)

        return resp

    def _attach_auth_headers(
        self,
        headers: dict,
        *,
        method: str,
        url: str,
        token: str,
    ) -> None:
        """Set Authorization (and DPoP) headers on a request dict in-place."""
        if self._dpop:
            proof = self._identity.sign_dpop_proof(
                htm=method,
                htu=url,
                access_token=token,
            )
            headers["Authorization"] = f"DPoP {token}"
            headers["DPoP"] = proof
        else:
            headers["Authorization"] = f"Bearer {token}"
            # Defensive: remove any DPoP header from a previous attempt.
            headers.pop("DPoP", None)

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
