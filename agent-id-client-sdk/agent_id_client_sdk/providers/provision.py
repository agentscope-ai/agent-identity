"""End-to-end provisioning: keygen → register via a provider → save profile.

This is the nice setup-time DX — one call to go from nothing to a usable
agent profile under ``~/.agentid/agents/{name}/``. It composes the neutral
primitives (keygen / kid / profile store) with a vendor :class:`IdentityProvider`.
"""

from __future__ import annotations

from .base import IdentityProvider, RegisteredAgent, build_public_jwk


def provision_agent(
    provider: IdentityProvider,
    name: str,
    *,
    description: str = "",
    token_expire_time: int | None = None,
    save: bool = True,
) -> tuple[RegisteredAgent, bytes]:
    """Generate an Ed25519 keypair, register it via *provider*, and optionally
    save the agent profile locally.

    Returns ``(RegisteredAgent, private_key_bytes)``. The caller keeps the
    private key; only the public JWK is ever uploaded.
    """
    # Neutral primitives (provider-agnostic). They live in ``manage`` today;
    # importing lazily keeps this module's surface small and avoids pulling
    # the management module unless provisioning is actually used.
    from ..manage import compute_kid, generate_keypair, save_agent

    private_key_bytes, public_key_bytes = generate_keypair()
    kid = compute_kid(public_key_bytes)
    public_jwk = build_public_jwk(public_key_bytes, kid)

    registered = provider.register_agent(
        agent_name=name,
        public_jwk=public_jwk,
        description=description,
        token_expire_time=token_expire_time,
    )

    if save:
        # Persist the kid the provider acknowledged (it echoes ours) and the
        # provider's base URL so the runtime client knows where to get tokens.
        save_agent(
            name=name,
            agent_id=registered.agent_id,
            kid=registered.kid,
            private_key_bytes=private_key_bytes,
            idp_url=provider.idp_url,
        )

    return registered, private_key_bytes
