"""Unit tests for the eTLD+1 namespace ownership rule (design §6).

End-to-end tests that exercise this through actual ingest paths live
in the activity service's test suite (`test_activity_tier2.py`).
"""

from __future__ import annotations

import pytest

from agent_id_service_sdk import (
    NamespaceOwnershipError,
    verify_namespace_ownership,
)


class TestHappyPath:
    def test_apex_subdomain(self):
        verify_namespace_ownership("https://api.dojozero.live", "dojozero")

    def test_alternative_subdomain(self):
        # Multiple subdomains of the same registrable domain MAY share namespace.
        verify_namespace_ownership("https://gateway.dojozero.live", "dojozero")
        verify_namespace_ownership("https://canary.dojozero.live", "dojozero")

    def test_apex_only(self):
        verify_namespace_ownership("https://dojozero.live", "dojozero")

    def test_case_insensitive(self):
        verify_namespace_ownership("https://api.DOJOZERO.live", "dojozero")
        verify_namespace_ownership("https://api.dojozero.live", "DojoZero")

    def test_underscore_hyphen_normalization(self):
        # `dojo-zero.live` ↔ namespace `dojo_zero` is the same DNS owner.
        verify_namespace_ownership("https://api.dojo-zero.live", "dojo_zero")
        verify_namespace_ownership("https://api.dojo_zero.live", "dojo-zero")


class TestRejection:
    def test_different_registrable_domain(self):
        with pytest.raises(NamespaceOwnershipError, match="does not match"):
            verify_namespace_ownership("https://api.evil.com", "dojozero")

    def test_namespace_is_subdomain_label_not_etld1(self):
        # The bare-name label of `evil.dojozero.live` is `dojozero` (eTLD+1
        # is `dojozero.live`). That's correctly accepted as the owner of
        # the `dojozero` namespace — same DNS owner as api.dojozero.live.
        # But the analogous `dojozero.evil.com` has eTLD+1 `evil.com` and
        # bare-name `evil`, so claiming `dojozero` is rejected.
        with pytest.raises(NamespaceOwnershipError, match="does not match"):
            verify_namespace_ownership("https://dojozero.evil.com", "dojozero")

    def test_localhost_rejected(self):
        # No public suffix → fail closed. Tests/local dev should mock the
        # fetcher entirely rather than rely on localhost passing.
        with pytest.raises(NamespaceOwnershipError, match="public suffix"):
            verify_namespace_ownership("http://localhost:8000", "dojozero")

    def test_ip_address_rejected(self):
        with pytest.raises(NamespaceOwnershipError, match="public suffix"):
            verify_namespace_ownership("https://10.0.0.1", "dojozero")

    def test_bare_hostname_rejected(self):
        with pytest.raises(NamespaceOwnershipError, match="public suffix"):
            verify_namespace_ownership("https://internal-host", "dojozero")
