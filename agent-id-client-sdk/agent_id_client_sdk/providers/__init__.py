"""Provider (adapter) layer for setup-time identity control-plane operations.

Import a concrete provider explicitly, e.g.::

    from agent_id_client_sdk.providers.modelscope import ModelScopeProvider
    from agent_id_client_sdk.providers import provision_agent

    provider = ModelScopeProvider(access_token, base_url="https://pre.modelscope.cn/openapi/v1")
    agent, _priv = provision_agent(provider, "my-agent")

The runtime token path never imports this package — see
:mod:`agent_id_client_sdk.providers.base` for the rationale.
"""

from __future__ import annotations

from .base import (
    IdentityProvider,
    ProviderError,
    RegisteredAgent,
    RegisteredHubApp,
    build_public_jwk,
)
from .provision import provision_agent

__all__ = [
    "IdentityProvider",
    "ProviderError",
    "RegisteredAgent",
    "RegisteredHubApp",
    "build_public_jwk",
    "provision_agent",
]
