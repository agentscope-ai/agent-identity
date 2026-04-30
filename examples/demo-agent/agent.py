"""
Demo: AIP agent with subcommands that exercise the approval workflow.

Subcommands:
  whoami                             authenticate to the hub and print identity
  book <destination> <amount>        book a flight
  delete <path>                      delete a file (always needs approval)
  trade <pair> <amount> <side>       execute a trade (buy|sell)
  demo                               run a scripted sequence (default)

The agent's approval handling is the same for every command: on 202,
poll the hub, retry with X-AIP-Grant once a grant is issued.

Identity is selected by AIP_IDP (default: "local"); see IDENTITY_PROFILES
below for the available profiles. The hub must be started with the same
AIP_IDP value so it trusts the matching IdP. The repo root Makefile wraps
this:  make agent whoami IDP=pre.

Prerequisites:
  1. An IdP reachable at the URL implied by AIP_IDP (local: ref-idp on :8000)
  2. demo-hub on :8001, started with the same AIP_IDP
  3. An identity loadable by the selected profile (~/.aip/agents/<name>/
     for "profile:" specs, or a zip export for "zip:" specs)
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from typing import Any

from agent_id_sdk import AIPClient, AIPIdentity

HUB_URL = "http://localhost:8001"
POLL_INTERVAL_SECONDS = 2
POLL_TIMEOUT_SECONDS = 300

# Identity source per AIP_IDP profile.
# "profile:<name>" loads ~/.aip/agents/<name>/; "zip:<path>" loads a zip export.
IDENTITY_PROFILES: dict[str, str] = {
    "local": "profile:cli-agent-2",
    "pre": "zip:/Users/yilei.z/Downloads/pre-portal-agent.zip",
    "prod": "zip:/path/to/prod-agent.zip",
}

# Where the principal approves IdP-delegated requests (Model 3) — printed as
# a hint when the hub returns approval_via=idp. Local dev runs the portal on
# Vite's 5173; hosted envs co-serve it with the IdP.
PORTAL_URLS: dict[str, str] = {
    "local": "http://localhost:5173/portal/approvals",
    "pre": "https://pre.agent-id.live/portal/approvals",
    "prod": "https://agent-id.live/portal/approvals",
}


async def execute_action(
    client: AIPClient,
    path: str,
    payload: dict[str, Any],
    *,
    label: str,
) -> dict:
    """Call the hub; transparently handle 202 + poll + retry-with-grant."""
    print(f"\n→ {label}")
    resp = await client.post(f"{HUB_URL}{path}", json=payload)

    if resp.status_code == 200:
        print(f"  completed: {resp.json()}")
        return resp.json()

    if resp.status_code != 202:
        raise RuntimeError(f"unexpected {resp.status_code}: {resp.text}")

    body = resp.json()
    approval_id = body["approval_id"]
    via = body.get("approval_via", "hub")
    note = body.get("threshold_exceeded", "approval required")
    print(f"  {note} (approval via {via})")
    print(f"  approval_id = {approval_id}")
    if via == "idp":
        portal = PORTAL_URLS.get(os.environ.get("AIP_IDP", "local"), "")
        print(
            f"  → approve at {portal}" if portal else "  → approve via the IdP portal"
        )
    else:
        print(
            f"  → principal must approve, e.g.:\n"
            f"    cd examples/demo-hub && python approve.py approve {approval_id}"
        )

    grant_id = await _poll_for_grant(client, approval_id)
    print(f"  grant issued: {grant_id} — retrying {label}")

    retry = await client.post(
        f"{HUB_URL}{path}",
        json=payload,
        headers={"X-AIP-Grant": grant_id},
    )
    if retry.status_code != 200:
        raise RuntimeError(f"retry failed: {retry.status_code} {retry.text}")
    print(f"  completed: {retry.json()}")
    return retry.json()


async def _poll_for_grant(client: AIPClient, approval_id: str) -> str:
    poll_url = f"{HUB_URL}/aip/grants/{approval_id}"
    deadline = asyncio.get_event_loop().time() + POLL_TIMEOUT_SECONDS
    while asyncio.get_event_loop().time() < deadline:
        resp = await client.get(poll_url)
        resp.raise_for_status()
        data = resp.json()
        status = data["status"]
        if status == "approved":
            return data["grant"]["grant_id"]
        if status == "denied":
            raise RuntimeError(f"approval denied: {data.get('reason')}")
        if status == "expired":
            raise RuntimeError("approval expired")
        await asyncio.sleep(POLL_INTERVAL_SECONDS)
    raise TimeoutError(f"gave up waiting for approval {approval_id}")


def _new_identity() -> AIPIdentity:
    profile = os.environ.get("AIP_IDP", "local")
    spec = IDENTITY_PROFILES.get(profile)
    if spec is None:
        raise SystemExit(
            f"AIP_IDP={profile!r} unknown; choose {list(IDENTITY_PROFILES)}"
        )
    kind, _, value = spec.partition(":")
    if kind == "profile":
        return AIPIdentity.from_profile(value)
    if kind == "zip":
        return AIPIdentity.from_zip(value)
    raise SystemExit(f"unknown loader kind {kind!r} in IDENTITY_PROFILES")


def _new_client() -> AIPClient:
    return AIPClient(_new_identity())


async def cmd_whoami(args):
    identity = _new_identity()
    client = AIPClient(identity)

    print("local identity:")
    print(f"  agent_id = {identity.agent_id}")
    print(f"  kid      = {identity.kid}")
    print(f"  idp_url  = {identity.idp_url}")

    print(f"\n→ GET {HUB_URL}/api/whoami")
    resp = await client.get(f"{HUB_URL}/api/whoami")
    resp.raise_for_status()
    print("hub sees:")
    for k, v in resp.json().items():
        print(f"  {k} = {v}")


async def cmd_book(args):
    client = _new_client()
    await execute_action(
        client,
        "/api/book-flight",
        {
            "destination": args.destination,
            "amount": args.amount,
            "refundable": args.refundable,
        },
        label=f"book flight to {args.destination} for ${args.amount:.2f}",
    )


async def cmd_delete(args):
    client = _new_client()
    await execute_action(
        client,
        "/api/delete-file",
        {"path": args.path},
        label=f"delete file {args.path}",
    )


async def cmd_trade(args):
    client = _new_client()
    await execute_action(
        client,
        "/api/trade",
        {"pair": args.pair, "amount": args.amount, "side": args.side},
        label=f"{args.side} ${args.amount:.2f} of {args.pair}",
    )


async def cmd_demo(args):
    client = _new_client()
    whoami = await client.get(f"{HUB_URL}/api/whoami")
    print(f"hub says: {whoami.json()}")

    # Small booking — under threshold, auto-approved.
    await execute_action(
        client,
        "/api/book-flight",
        {"destination": "SFO", "amount": 299.00, "refundable": True},
        label="book flight to SFO for $299.00",
    )
    # Big booking — triggers approval.
    await execute_action(
        client,
        "/api/book-flight",
        {"destination": "NYC", "amount": 1299.00, "refundable": False},
        label="book flight to NYC for $1299.00",
    )
    # File delete — always triggers approval.
    await execute_action(
        client,
        "/api/delete-file",
        {"path": "/data/old-report.csv"},
        label="delete /data/old-report.csv",
    )
    # Trade over threshold — triggers approval.
    await execute_action(
        client,
        "/api/trade",
        {"pair": "BTC/USD", "amount": 2500.00, "side": "buy"},
        label="buy $2500.00 of BTC/USD",
    )


def main():
    parser = argparse.ArgumentParser(description="AIP demo agent")
    subparsers = parser.add_subparsers(dest="cmd")

    p_whoami = subparsers.add_parser(
        "whoami", help="Authenticate to the hub and print identity"
    )
    p_whoami.set_defaults(func=cmd_whoami)

    p_book = subparsers.add_parser("book", help="Book a flight")
    p_book.add_argument("destination")
    p_book.add_argument("amount", type=float)
    p_book.add_argument("--refundable", action="store_true")
    p_book.set_defaults(func=cmd_book)

    p_delete = subparsers.add_parser("delete", help="Delete a file")
    p_delete.add_argument("path")
    p_delete.set_defaults(func=cmd_delete)

    p_trade = subparsers.add_parser("trade", help="Execute a trade")
    p_trade.add_argument("pair", help="e.g. BTC/USD")
    p_trade.add_argument("amount", type=float)
    p_trade.add_argument("side", choices=["buy", "sell"])
    p_trade.set_defaults(func=cmd_trade)

    p_demo = subparsers.add_parser("demo", help="Run a scripted sequence")
    p_demo.set_defaults(func=cmd_demo)

    args = parser.parse_args()
    if not args.cmd:
        args.func = cmd_demo
    try:
        asyncio.run(args.func(args))
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
