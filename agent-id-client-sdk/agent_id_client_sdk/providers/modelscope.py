"""ModelScope identity provider — setup-time control plane over OpenAPI.

Wraps ModelScope's ``/openapi/v1`` agent-identity and hub-app endpoints,
authenticated with a ModelScope AccessToken — the user's existing account
token, obtained from their ModelScope account. This module neither mints nor
manages that token; it only presents it as a bearer credential.
"""

from __future__ import annotations

from typing import Any

import httpx

from .base import (
    IdentityProvider,
    ProviderError,
    RegisteredAgent,
    RegisteredHubApp,
)

#: Production OpenAPI base for the live ModelScope IdP.
DEFAULT_BASE_URL = "https://www.modelscope.cn/openapi/v1"


class ModelScopeProvider(IdentityProvider):
    """Register agents and hub apps against ModelScope's Agent IdP.

    Args:
        access_token: ModelScope AccessToken (sent as ``Authorization: Bearer``).
        base_url: OpenAPI base; defaults to production.
        http: optional pre-built ``httpx.Client`` (handy for tests / custom
            transports). A sync client is used on purpose — registration is a
            setup-time operation, kept entirely separate from the async
            runtime token path.
    """

    def __init__(
        self,
        access_token: str,
        *,
        base_url: str = DEFAULT_BASE_URL,
        http: httpx.Client | None = None,
    ) -> None:
        self._token = access_token
        self.idp_url = base_url.rstrip("/")
        self._http = http or httpx.Client(timeout=30.0)

    # -- helpers --------------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
        }

    def _unwrap(self, resp: httpx.Response) -> dict[str, Any]:
        """Raise on HTTP/application failure; return the ``data`` payload."""
        resp.raise_for_status()
        payload = resp.json()
        if payload.get("success") is False:
            raise ProviderError(
                payload.get("code"),
                payload.get("message"),
                payload.get("request_id"),
            )
        data = payload.get("data")
        if not isinstance(data, dict):
            raise ProviderError(
                "MalformedResponse",
                f"response missing 'data' object: {payload!r}",
                payload.get("request_id"),
            )
        return data

    # -- control plane --------------------------------------------------------

    def register_agent(
        self,
        *,
        agent_name: str,
        public_jwk: dict[str, Any],
        description: str = "",
        token_expire_time: int | None = None,
    ) -> RegisteredAgent:
        body: dict[str, Any] = {"agent_name": agent_name, "public_key": public_jwk}
        if description:
            body["description"] = description
        if token_expire_time is not None:
            body["token_expire_time"] = token_expire_time
        data = self._unwrap(
            self._http.post(
                f"{self.idp_url}/agent_ids", json=body, headers=self._headers()
            )
        )
        return RegisteredAgent(
            agent_id=data["agent_id"],
            kid=data["kid"],
            agent_name=data.get("agent_name", agent_name),
            status=data.get("status", "active"),
            public_key=data.get("public_key", public_jwk),
        )

    def create_hub_app(
        self,
        *,
        app_name: str,
        app_homepage: str,
        app_logo: str | None = None,
    ) -> RegisteredHubApp:
        body: dict[str, Any] = {"app_name": app_name, "app_homepage": app_homepage}
        if app_logo:
            body["app_logo"] = app_logo
        data = self._unwrap(
            self._http.post(
                f"{self.idp_url}/hub_apps", json=body, headers=self._headers()
            )
        )
        return RegisteredHubApp(
            client_id=data["client_id"],
            app_name=data.get("app_name", app_name),
            app_homepage=data.get("app_homepage", app_homepage),
            owner=data.get("owner", ""),
            app_logo=data.get("app_logo"),
        )
