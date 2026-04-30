from __future__ import annotations

from urllib.parse import urlparse

import httpx


async def discover_hub(hub_url: str) -> dict:
    """Fetch the AIP hub configuration from ``{hub_url}/.well-known/aip-hub``.

    Returns a dict with keys such as ``service_id``,
    ``trusted_providers``, ``local_mode``, and ``aip_version``.
    """
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"{hub_url.rstrip('/')}/.well-known/aip-hub")
        resp.raise_for_status()
        return resp.json()


async def check_compatibility(hub_url: str, idp_domain: str) -> bool:
    """Check whether *idp_domain* is among the hub's trusted providers."""
    config = await discover_hub(hub_url)
    trusted = config.get("trusted_providers", [])

    # Normalise: compare bare domains (strip scheme if present).
    def _domain(value: str) -> str:
        if "://" in value:
            return urlparse(value).netloc
        return value

    idp_norm = _domain(idp_domain)
    return any(_domain(t) == idp_norm for t in trusted)
