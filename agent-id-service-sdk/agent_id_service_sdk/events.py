"""Activity event schema (mirror of aip-activity's canonical Pydantic model).

The server is the source of truth for validation; this module exists so hubs
can construct events with the right shape and use the helper utilities.

Three-tier category model:
  Tier 1 — Protocol categories (no namespace prefix). See TIER1_CATEGORIES.
  Tier 2 — Hub namespaced (`<hub_namespace>.<verb>`). Schema declared by hub.
  Tier 3 — Free-form (`custom.*`). Opaque payload, dropped if privacy != "full".
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

# Tier 1 — protocol categories. Cross-hub aggregable. Schema enforced
# server-side (`aip-activity/app/schemas/categories.py`). Standardised-
# when-emitted, not emitted-everywhere — a hub without an economy never
# fires `transfer.value`, that's expected.
TIER1_CATEGORIES: frozenset[str] = frozenset(
    {
        # Universal lifecycle — fires on any agent regardless of hub class.
        "auth.verify",
        "auth.deny",
        "session.start",
        "session.end",
        # Domain-flavored — fires only on hubs in the matching domain.
        "model.call",
        "tool.use",
        "data.read",
        "data.write",
        "transfer.value",
        # Approval workflow (see 2026-03-25-agentid.en.md §7.4).
        "approval.requested",
        "approval.granted",
        "approval.denied",
        # Delegation lifecycle (see 2026-03-25-agentid.en.md §4.4 / §7.4).
        "delegation.granted",
        "delegation.revoked",
    }
)


@dataclass
class ActivityEvent:
    """Wire shape for events posted to aip-activity's POST /agentid/activity.

    Matches aip-activity/app/routes/activity.py's Pydantic model. No client-
    side validation; the server is the source of truth.
    """

    # envelope (always required)
    event_id: str
    aip_version: str
    category: str
    agent_id: str
    principal_id: str
    audience: str
    issuer: str
    kid: str
    service: str
    timestamp: datetime
    session_id: str | None = None
    outcome: str = "n/a"
    payload: dict[str, Any] = field(default_factory=dict)
    ext: dict[str, Any] | None = None

    @staticmethod
    def new_event_id() -> str:
        return str(uuid.uuid4())

    @classmethod
    def build(
        cls,
        *,
        category: str,
        agent_id: str,
        principal_id: str,
        audience: str,
        issuer: str,
        kid: str,
        service: str,
        session_id: str | None = None,
        outcome: str = "n/a",
        payload: dict[str, Any] | None = None,
        ext: dict[str, Any] | None = None,
        timestamp: datetime | None = None,
    ) -> "ActivityEvent":
        return cls(
            event_id=cls.new_event_id(),
            aip_version="0.1",
            category=category,
            agent_id=agent_id,
            principal_id=principal_id,
            audience=audience,
            issuer=issuer,
            kid=kid,
            service=service,
            session_id=session_id,
            timestamp=timestamp or datetime.now(tz=timezone.utc),
            outcome=outcome,
            payload=dict(payload) if payload else {},
            ext=dict(ext) if ext else None,
        )

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "event_id": self.event_id,
            "aip_version": self.aip_version,
            "category": self.category,
            "agent_id": self.agent_id,
            "principal_id": self.principal_id,
            "audience": self.audience,
            "issuer": self.issuer,
            "kid": self.kid,
            "service": self.service,
            "session_id": self.session_id,
            "timestamp": self.timestamp.isoformat(),
            "outcome": self.outcome,
            "payload": self.payload,
        }
        if self.ext is not None:
            out["ext"] = self.ext
        return out


def match_category(pattern: str, category: str) -> bool:
    """Match a category against an allow-list pattern.

    Patterns:
      - literal: "model.call" matches only "model.call"
      - prefix wildcard: "dojozero.*" matches "dojozero.<anything>"
      - suffix wildcard: "*.verify" matches "<anything>.verify"
      - full wildcard: "*" matches anything (use with care)
    """
    if pattern == "*":
        return True
    if pattern.endswith(".*"):
        prefix = pattern[:-2]
        return category == prefix or category.startswith(f"{prefix}.")
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return category.endswith(f".{suffix}")
    return pattern == category


def category_tier(category: str, hub_namespace: str | None = None) -> int:
    """Return the tier (1, 2, or 3) for a given category.

    If hub_namespace is given, validates that Tier 2 categories use it.
    Returns 0 for invalid (e.g., emitting another hub's namespace).
    """
    if category in TIER1_CATEGORIES:
        return 1
    if category.startswith("custom."):
        return 3
    # Tier 2: namespaced
    if "." in category:
        ns = category.split(".", 1)[0]
        if hub_namespace is None:
            return 2  # caller will let server validate
        return 2 if ns == hub_namespace else 0
    return 0
