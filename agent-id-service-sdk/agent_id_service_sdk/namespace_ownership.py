"""Namespace ownership check (design §6).

A hub MAY claim Tier-2 namespace ``<ns>`` if and only if the registrable
domain (eTLD+1) of its ``service_id`` resolves to ``<ns>``,
case-insensitive, after underscore/hyphen normalization. DNS ownership
is the trust anchor — controlling the cert proves controlling the domain.

Examples:
  service_id=https://api.dojozero.live,     namespace=dojozero  → ok
  service_id=https://api.evil.com,          namespace=dojozero  → reject
  service_id=https://gateway.dojozero.live, namespace=dojozero  → ok

This helper lives in the SDK so every activity-protocol verifier
reproduces the same rule. Hub adopters writing in another language can
consult RFC 7340 + the Public Suffix List spec; the algorithm is purely
DNS — no AgentID-specific encoding.
"""

from __future__ import annotations

# tldextract is a declared runtime dep in pyproject.toml; the per-line
# pyright ignore is only because some pre-commit pyright envs resolve
# imports against a venv that hasn't been re-synced after the dep was
# added. At runtime the import either works or fails fast on first call.
import tldextract  # pyright: ignore[reportMissingImports]

# Single shared extractor; reuses cached PSL across calls. ``cache_dir=None``
# + ``suffix_list_urls=()`` forces use of the snapshot bundled with
# tldextract — no runtime fetch, deterministic across deploys.
_EXTRACTOR = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=())


class NamespaceOwnershipError(Exception):
    """Raised when a manifest's namespace doesn't match its service_id's eTLD+1."""


def _normalize(s: str) -> str:
    return s.lower().replace("_", "-")


def verify_namespace_ownership(service_id: str, namespace: str) -> None:
    """Verify a hub's claimed namespace matches the bare-name label of its
    registrable domain.

    Raises NamespaceOwnershipError on mismatch or on URLs without a
    recognised public suffix (e.g., bare hostnames, IPs, localhost).
    Test/local-dev callers that need to bypass the eTLD+1 rule should do
    so at the dispatch layer, not by mocking this function.
    """
    parts = _EXTRACTOR(service_id)
    if not parts.domain or not parts.suffix:
        raise NamespaceOwnershipError(
            f"could not extract registrable domain from service_id "
            f"{service_id!r} (no public suffix?)"
        )
    if _normalize(parts.domain) != _normalize(namespace):
        raise NamespaceOwnershipError(
            f"namespace {namespace!r} does not match registrable domain "
            f"{parts.domain}.{parts.suffix} of service_id {service_id!r}"
        )


__all__ = ["NamespaceOwnershipError", "verify_namespace_ownership"]
