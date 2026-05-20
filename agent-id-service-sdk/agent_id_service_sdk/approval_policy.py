"""Hub-side evaluator for the JWT ``delegation`` claim.

When a hub receives a request from an agent, it consults the agent's
JWT ``delegation`` claim (composed by the IdP from the hub's own
published policy + the principal's preferences) to decide whether
the action needs human confirmation before proceeding.

This module is the symmetric counterpart of the IdP's
``compose_delegation_claim``: the IdP composes, the hub evaluates.
Both implementations use the same DSL — keeping them in matching
shapes is what makes "most-restrictive wins" composition meaningful.

Evaluation contract::

    evaluate_approval_needed(
        action="transfer.value",
        params={"amount_usd": 1500},
        delegation=<JWT claim>,
    )
    → (approval_needed: bool, reason: str | None)

Order of checks (first match wins):
  1. ``action`` is in ``always_require`` → ``(True, "...")``
  2. ``action`` is in ``never_require``  → ``(False, None)``
  3. Any numeric threshold for ``action`` is exceeded by ``params`` →
     ``(True, "...")``
  4. Default → ``(False, None)``

When ``delegation`` is ``None`` or empty, the function returns
``(False, None)`` — i.e., absent policy means auto-approve. Hubs that
need a fail-closed default should layer their own manifest-published
floor on top via :func:`merge_hub_floor` before calling, or evaluate
twice and OR the results.

The DSL itself is documented in
``app/core/approval_policy.py`` on the IdP side.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def evaluate_approval_needed(
    *,
    action: str,
    params: dict[str, Any] | None = None,
    delegation: dict[str, Any] | None = None,
) -> tuple[bool, str | None]:
    """Decide whether `action` requires human approval under `delegation`.

    Args:
        action: The action being attempted (e.g. ``"transfer.value"``,
            ``"data.delete"``). Match is exact-string against the
            ``always_require`` / ``never_require`` lists and the
            ``thresholds`` map.
        params: Action parameters carrying values to compare against
            numeric thresholds (e.g. ``{"amount_usd": 1500}``). Missing
            keys cause that threshold to be skipped — only declared,
            comparable params drive approval. ``None`` is treated as
            an empty dict.
        delegation: The JWT ``delegation`` claim. ``None`` or empty
            means no policy is in effect → ``(False, None)``.

    Returns:
        ``(approval_needed, reason)``. ``reason`` is a short human-readable
        string suitable for surfacing in the principal's approval prompt
        when ``approval_needed`` is True; ``None`` otherwise.
    """
    if not delegation:
        return False, None

    always = delegation.get("always_require") or []
    never = delegation.get("never_require") or []
    thresholds = delegation.get("thresholds") or {}

    if isinstance(always, list) and action in always:
        return True, f"Hub policy: {action!r} always requires approval"
    if isinstance(never, list) and action in never:
        return False, None

    action_thresholds = thresholds.get(action) if isinstance(thresholds, dict) else None
    if isinstance(action_thresholds, dict):
        params = params or {}
        for key, threshold in action_thresholds.items():
            if not isinstance(threshold, (int, float)) or isinstance(threshold, bool):
                # Non-numeric constraints (currency, region, etc.) are
                # context metadata in v1; they scope when the threshold
                # applies but don't enforce on their own. v2 may make
                # this explicit via per-constraint operators.
                continue
            value = params.get(key)
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                # Param missing or non-comparable → threshold doesn't trip.
                continue
            if value > threshold:
                return (
                    True,
                    f"{action} {key}={value} exceeds threshold {threshold}",
                )

    return False, None


def merge_hub_floor(
    delegation: dict[str, Any] | None,
    hub_floor: dict[str, Any] | None,
) -> dict[str, Any] | None:
    """Defense-in-depth helper: merge a hub's own published floor with the
    JWT delegation claim, taking the most-restrictive of each field.

    Why a hub would call this:
      - The agent's IdP is older and doesn't compose delegation claims
        from hub manifests yet (Phase A back-compat).
      - The hub's published policy has changed since this JWT was
        issued and it wants to apply the new floor immediately.
      - Belt-and-suspenders: the hub doesn't fully trust the IdP's
        composition correctness for high-value actions.

    Composition rule matches the IdP-side composer:
      - ``always_require``: union (preserving order from delegation first)
      - ``thresholds``: per-action min for numeric values; last writer
        wins for non-numeric (hub_floor overrides delegation since it's
        passed second).
      - ``never_require``: hub_floor's ``always_require`` removes any
        matching entries from delegation's ``never_require``.

    Returns the merged claim, or ``None`` when both inputs are empty.
    """
    if not delegation and not hub_floor:
        return None
    if not hub_floor:
        return dict(delegation) if delegation else None
    if not delegation:
        # Hub-floor only; treat as the effective delegation.
        out = dict(hub_floor)
        # Hub's never_require has no special meaning standalone — drop.
        out.pop("never_require", None)
        return out or None

    merged: dict[str, Any] = {}

    d_always = delegation.get("always_require") or []
    f_always = hub_floor.get("always_require") or []
    seen: dict[str, None] = {}
    for entry in d_always + f_always:
        if isinstance(entry, str) and entry and entry not in seen:
            seen[entry] = None
    if seen:
        merged["always_require"] = list(seen)

    d_thresh = delegation.get("thresholds") or {}
    f_thresh = hub_floor.get("thresholds") or {}
    if isinstance(d_thresh, dict) and isinstance(f_thresh, dict):
        merged_thresh: dict[str, dict[str, Any]] = {}
        for src in (d_thresh, f_thresh):
            for action, constraints in src.items():
                if not isinstance(constraints, dict):
                    continue
                bucket = merged_thresh.setdefault(action, {})
                for k, v in constraints.items():
                    if (
                        k in bucket
                        and isinstance(bucket[k], (int, float))
                        and isinstance(v, (int, float))
                    ):
                        bucket[k] = min(bucket[k], v)
                    else:
                        bucket[k] = v
        if merged_thresh:
            merged["thresholds"] = merged_thresh

    # never_require: hub_floor.always_require overrides delegation.never_require.
    d_never = delegation.get("never_require") or []
    if isinstance(d_never, list) and d_never:
        floor_set = set(merged.get("always_require") or [])
        filtered = [n for n in d_never if isinstance(n, str) and n not in floor_set]
        if filtered:
            merged["never_require"] = filtered

    return merged or None


__all__ = ["evaluate_approval_needed", "merge_hub_floor"]
