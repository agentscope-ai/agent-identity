"""Tests for hub-side approval-policy evaluator + hub-floor merge."""

from __future__ import annotations

from agent_id_service_sdk import evaluate_approval_needed, merge_hub_floor


# ---------------------------------------------------------------------------
# evaluate_approval_needed — no delegation
# ---------------------------------------------------------------------------


def test_no_delegation_means_auto_approve():
    needed, reason = evaluate_approval_needed(
        action="transfer.value", params={"amount_usd": 1000000}
    )
    assert needed is False
    assert reason is None


def test_empty_delegation_is_no_delegation():
    needed, _ = evaluate_approval_needed(action="data.delete", delegation={})
    assert needed is False


# ---------------------------------------------------------------------------
# always_require
# ---------------------------------------------------------------------------


def test_always_require_matches_action():
    needed, reason = evaluate_approval_needed(
        action="data.delete",
        delegation={"always_require": ["data.delete"]},
    )
    assert needed is True
    assert reason is not None
    assert "data.delete" in reason
    assert "always" in reason.lower()


def test_always_require_does_not_match_unrelated_action():
    needed, _ = evaluate_approval_needed(
        action="data.read",
        delegation={"always_require": ["data.delete"]},
    )
    assert needed is False


# ---------------------------------------------------------------------------
# never_require
# ---------------------------------------------------------------------------


def test_never_require_bypasses_threshold():
    """Even if a threshold would otherwise fire, never_require wins."""
    needed, _ = evaluate_approval_needed(
        action="data.read",
        params={"size_mb": 999},
        delegation={
            "never_require": ["data.read"],
            "thresholds": {"data.read": {"size_mb": 10}},
        },
    )
    assert needed is False


def test_always_require_beats_never_require_in_same_claim():
    """If a (broken) composer leaves an action in both lists, always wins.
    The IdP composer prevents this case at composition time; the
    evaluator checks always_require first so the protocol stays safe."""
    needed, _ = evaluate_approval_needed(
        action="data.delete",
        delegation={
            "always_require": ["data.delete"],
            "never_require": ["data.delete"],
        },
    )
    assert needed is True


# ---------------------------------------------------------------------------
# thresholds
# ---------------------------------------------------------------------------


def test_numeric_threshold_exceeded_requires_approval():
    needed, reason = evaluate_approval_needed(
        action="transfer.value",
        params={"amount_usd": 1500},
        delegation={"thresholds": {"transfer.value": {"amount_usd": 500}}},
    )
    assert needed is True
    assert reason is not None
    assert "1500" in reason
    assert "500" in reason


def test_threshold_not_exceeded_auto_approves():
    needed, _ = evaluate_approval_needed(
        action="transfer.value",
        params={"amount_usd": 100},
        delegation={"thresholds": {"transfer.value": {"amount_usd": 500}}},
    )
    assert needed is False


def test_param_missing_for_threshold_doesnt_fire():
    """Param not present in request → threshold doesn't apply.
    Hub policy can declare thresholds liberally; if the action's params
    don't expose the key, the check is silently skipped."""
    needed, _ = evaluate_approval_needed(
        action="transfer.value",
        params={"currency": "USD"},  # no amount_usd
        delegation={"thresholds": {"transfer.value": {"amount_usd": 500}}},
    )
    assert needed is False


def test_multiple_thresholds_any_exceeded_fires():
    needed, reason = evaluate_approval_needed(
        action="transfer.value",
        params={"amount_usd": 100, "fee_usd": 50},
        delegation={
            "thresholds": {"transfer.value": {"amount_usd": 500, "fee_usd": 10}}
        },
    )
    assert needed is True
    assert reason is not None
    assert "fee_usd" in reason


def test_non_numeric_threshold_constraint_is_metadata():
    """currency / region / nested hub-extension are context metadata
    in v1, not enforcement triggers."""
    needed, _ = evaluate_approval_needed(
        action="transfer.value",
        params={"amount_usd": 100, "currency": "EUR"},
        delegation={
            "thresholds": {"transfer.value": {"amount_usd": 500, "currency": "USD"}}
        },
    )
    assert needed is False


def test_boolean_param_doesnt_trigger_numeric_threshold():
    """bool is technically numeric in Python; reject to avoid surprises."""
    needed, _ = evaluate_approval_needed(
        action="anything",
        params={"flag": True},
        delegation={"thresholds": {"anything": {"flag": 0}}},
    )
    assert needed is False


# ---------------------------------------------------------------------------
# Malformed claim is tolerated
# ---------------------------------------------------------------------------


def test_malformed_always_require_is_ignored():
    needed, _ = evaluate_approval_needed(
        action="data.delete",
        delegation={"always_require": "data.delete"},  # str, not list
    )
    assert needed is False  # bad shape skipped


def test_malformed_thresholds_is_ignored():
    needed, _ = evaluate_approval_needed(
        action="transfer.value",
        params={"amount_usd": 10000},
        delegation={"thresholds": "not a dict"},
    )
    assert needed is False


# ---------------------------------------------------------------------------
# merge_hub_floor — defense-in-depth merge
# ---------------------------------------------------------------------------


def test_merge_returns_none_when_both_empty():
    assert merge_hub_floor(None, None) is None
    assert merge_hub_floor({}, {}) is None


def test_merge_returns_delegation_when_floor_empty():
    delegation = {"always_require": ["data.delete"]}
    out = merge_hub_floor(delegation, None)
    assert out == delegation


def test_merge_returns_floor_when_delegation_empty():
    """Old IdP didn't compose delegation; hub falls back to its own
    floor as the effective policy."""
    floor = {"always_require": ["data.delete"], "thresholds": {}}
    out = merge_hub_floor(None, floor)
    assert out is not None
    assert out["always_require"] == ["data.delete"]


def test_merge_unions_always_require():
    out = merge_hub_floor(
        {"always_require": ["data.delete"]},
        {"always_require": ["data.delete", "data.write"]},
    )
    assert out is not None
    assert out["always_require"] == ["data.delete", "data.write"]


def test_merge_takes_min_threshold():
    out = merge_hub_floor(
        {"thresholds": {"transfer.value": {"amount_usd": 500}}},
        {"thresholds": {"transfer.value": {"amount_usd": 100}}},
    )
    assert out is not None
    assert out["thresholds"]["transfer.value"]["amount_usd"] == 100


def test_merge_hub_floor_always_strips_delegation_never():
    out = merge_hub_floor(
        {"never_require": ["data.delete", "data.read"]},
        {"always_require": ["data.delete"]},
    )
    assert out is not None
    assert "data.delete" in out["always_require"]
    assert out["never_require"] == ["data.read"]  # delete stripped


def test_merge_then_evaluate_end_to_end():
    """The point of the merge helper: hub trusts the delegation but
    layers its own floor for defense-in-depth, then evaluates."""
    delegation = {"thresholds": {"transfer.value": {"amount_usd": 500}}}
    floor = {"always_require": ["data.delete"]}
    merged = merge_hub_floor(delegation, floor)

    # Floor-mandated action requires approval even though it isn't in delegation.
    needed, _ = evaluate_approval_needed(action="data.delete", delegation=merged)
    assert needed is True
    # Delegation-driven threshold still works.
    needed, _ = evaluate_approval_needed(
        action="transfer.value",
        params={"amount_usd": 1000},
        delegation=merged,
    )
    assert needed is True
