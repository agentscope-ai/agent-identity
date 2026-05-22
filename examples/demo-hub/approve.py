"""
Demo: Principal-side CLI for reviewing and approving agent action requests.

Usage:
  python approve.py list
  python approve.py approve <approval_id> [--max-amount N]
  python approve.py deny <approval_id> "reason"

For the demo the /agentid/approvals endpoints are unauthenticated. A real hub would
gate these behind a portal session tied to the principal.
"""

import argparse
import sys

import httpx

HUB_URL = "http://localhost:8001"


def cmd_list(args):
    params = {}
    if args.status:
        params["status"] = args.status
    if args.principal:
        params["principal_id"] = args.principal
    resp = httpx.get(f"{HUB_URL}/agentid/approvals", params=params)
    resp.raise_for_status()
    items = resp.json()["approvals"]
    if not items:
        print("(no approvals)")
        return
    for a in items:
        amount = a["details"].get("amount")
        desc = a["details"].get("description", "")
        print(
            f"{a['approval_id']}  {a['status']:<9}  ${amount:>8.2f}  "
            f"{a['agent_name']}  {desc}"
        )


def cmd_approve(args):
    body = {}
    if args.max_amount is not None:
        body["max_amount"] = args.max_amount
    resp = httpx.post(
        f"{HUB_URL}/agentid/approvals/{args.approval_id}/approve", json=body
    )
    if resp.status_code != 200:
        print(f"error: {resp.status_code} {resp.text}", file=sys.stderr)
        sys.exit(1)
    data = resp.json()
    grant = data["grant"]
    print(f"approved → grant_id={grant['grant_id']} expires={grant['expires_at']}")


def cmd_deny(args):
    resp = httpx.post(
        f"{HUB_URL}/agentid/approvals/{args.approval_id}/deny",
        json={"reason": args.reason},
    )
    if resp.status_code != 200:
        print(f"error: {resp.status_code} {resp.text}", file=sys.stderr)
        sys.exit(1)
    print(f"denied: {args.reason}")


def main():
    parser = argparse.ArgumentParser(description="Approve/deny agent actions")
    subparsers = parser.add_subparsers(dest="cmd", required=True)

    p_list = subparsers.add_parser("list", help="List approvals")
    p_list.add_argument(
        "--status", help="Filter by status (pending/approved/denied/expired)"
    )
    p_list.add_argument("--principal", help="Filter by principal_id")
    p_list.set_defaults(func=cmd_list)

    p_approve = subparsers.add_parser("approve", help="Approve a request")
    p_approve.add_argument("approval_id")
    p_approve.add_argument(
        "--max-amount", type=float, help="Cap the grant to this amount"
    )
    p_approve.set_defaults(func=cmd_approve)

    p_deny = subparsers.add_parser("deny", help="Deny a request")
    p_deny.add_argument("approval_id")
    p_deny.add_argument("reason", nargs="?", default="Denied by principal")
    p_deny.set_defaults(func=cmd_deny)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
