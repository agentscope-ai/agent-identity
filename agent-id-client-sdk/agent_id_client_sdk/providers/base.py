"""Provider (adapter) layer — vendor-specific, setup-time control plane.

The runtime token path (:class:`~agent_id_client_sdk.identity.Identity` +
:class:`~agent_id_client_sdk.client.Client`) is deliberately IdP-neutral: it
speaks the AgentID *protocol* (sign → token endpoint → JWKS) and never touches
a specific vendor's management API or credentials.

Registering an agent identity (and managing hub apps) is the opposite —
vendor-specific, done once at setup, and behind a high-privilege platform
credential (e.g. a ModelScope AccessToken). This package isolates that control
plane behind the small :class:`IdentityProvider` interface so the neutral core
stays clean and portable.

Rules:
  * Concrete providers depend only on the neutral primitives.
  * The runtime path MUST NOT import this package — that keeps the
    control-plane credential out of the agent process.
  * A provider here can be lifted into its own distribution later with
    almost no change (it already depends only on the core).
"""

from __future__ import annotations

import base64
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class RegisteredAgent:
    """An agent identity as returned by a provider's registration call."""

    agent_id: str
    kid: str
    agent_name: str = ""
    status: str = "active"
    public_key: dict[str, Any] = field(default_factory=dict)


@dataclass
class RegisteredHubApp:
    """A hub application (resource server) as returned by a provider."""

    client_id: str
    app_name: str = ""
    app_homepage: str = ""
    owner: str = ""
    app_logo: str | None = None


class ProviderError(Exception):
    """An identity provider returned an application-level failure.

    Distinct from transport/HTTP errors (those surface as the underlying
    client's exceptions, e.g. ``httpx.HTTPStatusError``). This is raised when
    the provider answers with a structured failure (``success: false``).
    """

    def __init__(
        self,
        code: str | None,
        message: str | None,
        request_id: str | None = None,
    ) -> None:
        self.code = code
        self.message = message
        self.request_id = request_id
        super().__init__(f"{code or 'ProviderError'}: {message or ''}".strip())


class IdentityProvider(ABC):
    """Setup-time control plane for a specific AgentID provider.

    Implementations are vendor-specific (endpoint URLs, auth, payload shapes).
    The contract here is what the provisioning helpers and CLIs depend on.
    """

    #: Base URL the runtime token client should use, saved into the agent
    #: profile as ``idp_url``. For ModelScope this is the OpenAPI base, so the
    #: runtime resolves ``{idp_url}/agent_id/token``.
    idp_url: str

    @abstractmethod
    def register_agent(
        self,
        *,
        agent_name: str,
        public_jwk: dict[str, Any],
        description: str = "",
        token_expire_time: int | None = None,
    ) -> RegisteredAgent:
        """Register an agent's public key; return its assigned identity."""

    @abstractmethod
    def create_hub_app(
        self,
        *,
        app_name: str,
        app_homepage: str,
        app_logo: str | None = None,
    ) -> RegisteredHubApp:
        """Register a hub application (resource server); return its client_id."""


def build_public_jwk(public_key_bytes: bytes, kid: str) -> dict[str, Any]:
    """Build an Ed25519 OKP public JWK (with ``kid``) for registration.

    ``public_key_bytes`` is the raw 32-byte Ed25519 public key.
    """
    x = base64.urlsafe_b64encode(public_key_bytes).rstrip(b"=").decode("ascii")
    return {"kty": "OKP", "crv": "Ed25519", "x": x, "kid": kid}
