from __future__ import annotations

import json
import uuid
import warnings
from datetime import datetime, timezone
from typing import Any

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_der_private_key,
)


class AIPActivityReporter:
    """Reports agent activity to an AIP activity tracker, signed with Ed25519.

    DEPRECATED: this implements the legacy hub-signed session-attestation flow
    (POST /aip/reports). The new event-roll-up design replaces it with
    `AIPVerifier.report_event` (granular events POSTed to /aip/activity;
    server-side aggregation produces session attestations). Will be removed
    in the next minor release.
    """

    def __init__(
        self,
        service_id: str,
        service_private_key_bytes: bytes,
        activity_tracker_url: str,
    ) -> None:
        warnings.warn(
            "AIPActivityReporter is deprecated and will be removed in the next "
            "minor release. Use AIPVerifier.report_event for the event-roll-up "
            "flow.",
            DeprecationWarning,
            stacklevel=2,
        )
        self._service_id = service_id
        self._activity_tracker_url = activity_tracker_url.rstrip("/")
        self._private_key = _load_private_key(service_private_key_bytes)

    def _sign_report(self, report_body: dict) -> str:
        """JCS-canonicalize *report_body* and return the hex-encoded Ed25519 signature.

        JSON Canonicalization Scheme (RFC 8785): sorted keys, no extra whitespace.
        """
        canonical = _jcs_canonicalize(report_body)
        signature = self._private_key.sign(canonical)
        return signature.hex()

    async def report(
        self,
        agent_id: str,
        session_id: str,
        activity_type: str,
        summary: str,
        outcome: str,
        started_at: str | None = None,
        ended_at: str | None = None,
    ) -> dict:
        """Build, sign, and POST an activity report.

        Returns the parsed JSON response from the activity tracker.
        """
        now = datetime.now(timezone.utc).isoformat()
        report_body: dict[str, Any] = {
            "report_id": str(uuid.uuid4()),
            "service_id": self._service_id,
            "agent_id": agent_id,
            "session_id": session_id,
            "activity_type": activity_type,
            "summary": summary,
            "outcome": outcome,
            "started_at": started_at or now,
            "ended_at": ended_at or now,
            "reported_at": now,
        }

        signature = self._sign_report(report_body)

        payload = {
            "report": report_body,
            "signature": signature,
        }

        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self._activity_tracker_url}/aip/reports",
                json=payload,
            )
            resp.raise_for_status()
            return resp.json()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _jcs_canonicalize(obj: Any) -> bytes:
    """Produce a JCS (RFC 8785) canonical form of a JSON-serialisable object.

    This simplified implementation handles the subset used by AIP reports
    (strings, numbers, booleans, null, dicts, lists).  Keys are sorted
    lexicographically and no extra whitespace is emitted.
    """
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


def _load_private_key(data: bytes) -> Ed25519PrivateKey:
    if data.strip().startswith(b"-----"):
        key = load_pem_private_key(data, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise TypeError("PEM key is not Ed25519")
        return key

    if len(data) == 32:
        return Ed25519PrivateKey.from_private_bytes(data)

    try:
        key = load_der_private_key(data, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise TypeError("DER key is not Ed25519")
        return key
    except Exception:
        pass

    raise ValueError(f"Unable to load Ed25519 private key (length={len(data)})")
