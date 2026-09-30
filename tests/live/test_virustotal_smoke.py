"""Controlled opt-in live smoke test for VirusTotal threat intelligence lookup.

NOT part of the default offline test suite.
Run explicitly only when RUN_LIVE_VT_TESTS=1 and VIRUSTOTAL_API_KEY are set
in the environment to verify live connectivity through the bounded ToolRouter.

Usage:
    $env:RUN_LIVE_VT_TESTS="1"
    $env:VIRUSTOTAL_API_KEY="<your_api_key>"
    python -m unittest tests/live/test_virustotal_smoke.py -v
    # or
    python tests/live/test_virustotal_smoke.py

Each test skips automatically if either environment variable is absent.

Operational invariants:
  - Bounded lookup: queries canonical public IP 8.8.8.8 only.
  - Zero authority side effects: does not invoke policy, request approval,
    simulate containment, engage RuntimeGuard, or call Splunk.
  - Secret hygiene: API key is read exclusively from os.environ, immediately
    encapsulated in VirusTotalCredentials, and never printed, logged, or included
    in exception/assertion messages.
"""

from __future__ import annotations

import dataclasses
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import MagicMock

# Ensure repository root is on sys.path
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from investigator.providers.virustotal_provider import (
    VirusTotalCredentials,
    VirusTotalError,
    VirusTotalResponseError,
    VirusTotalThreatIntelClient,
    VirusTotalTransportError,
)
from investigator.threat_intel import (
    ThreatIntelLookupStatus,
    ThreatIntelObservation,
    ThreatIntelRequest,
    ThreatIntelResult,
)
from investigator.tool_router import ToolExecutionError, ToolRouter

# -----------------------------------------------------------------------
# Skip sentinel — evaluated once at import time
# -----------------------------------------------------------------------

_SKIP_REASON: str | None = None
_RUN_LIVE = os.environ.get("RUN_LIVE_VT_TESTS", "").strip() == "1"
_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()

if not _RUN_LIVE:
    _SKIP_REASON = "RUN_LIVE_VT_TESTS=1 environment variable is not set (opt-in guard)"
elif not _API_KEY:
    _SKIP_REASON = "VIRUSTOTAL_API_KEY environment variable is not set or empty"


def _skip_unless_opted_in(test_item):
    """Decorator: skip test cleanly if opt-in guard or credentials are absent."""
    if _SKIP_REASON:
        return unittest.skip(_SKIP_REASON)(test_item)
    return test_item


# -----------------------------------------------------------------------
# Live Smoke Test Suite
# -----------------------------------------------------------------------

class TestVirusTotalLiveSmoke(unittest.TestCase):
    """Live smoke test exercising bounded ToolRouter threat intelligence integration."""

    @_skip_unless_opted_in
    def test_live_bounded_tool_router_lookup(self) -> None:
        """Verify bounded ToolRouter threat_intel_lookup execution against live VirusTotal."""
        raw_key = os.environ["VIRUSTOTAL_API_KEY"].strip()
        credentials = VirusTotalCredentials(api_key=raw_key)

        # 1. Secret hygiene verification on credentials
        self.assertNotIn(raw_key, repr(credentials))
        self.assertNotIn(raw_key, str(credentials))
        self.assertEqual(repr(credentials), "VirusTotalCredentials(api_key='***')")
        self.assertEqual(str(credentials), "VirusTotalCredentials(api_key='***')")

        # 2. Construct bounded tool router with mock Splunk and real live VT client
        mock_splunk = MagicMock()
        client = VirusTotalThreatIntelClient(credentials=credentials)
        router = ToolRouter(splunk_client=mock_splunk, vt_client=client)

        # 3. Dispatch bounded lookup
        try:
            observation = router.execute_tool(
                "threat_intel_lookup",
                {"indicator": "8.8.8.8"},
            )
        except ToolExecutionError as exc:
            # Distinguish legitimate service constraints from regressions
            cause = exc.__cause__
            if isinstance(cause, VirusTotalResponseError):
                cause_code = str(cause)
                if cause_code == "vt_auth_failed":
                    self.fail("Live VirusTotal authentication failed (invalid API key): vt_auth_failed")
                elif cause_code in ("vt_rate_limited", "vt_forbidden", "vt_remote_error"):
                    self.skipTest(f"Live VirusTotal service constraint: {cause_code}")
                else:
                    self.fail(f"Live VirusTotal returned unexpected schema/provider error: {cause_code}")
            elif isinstance(cause, VirusTotalTransportError):
                cause_code = str(cause)
                if cause_code == "vt_transport_error":
                    self.skipTest(f"Live VirusTotal temporary transport failure: {cause_code}")
                else:
                    self.fail(f"Live VirusTotal transport error: {cause_code}")
            else:
                self.fail(f"Live ToolRouter threat_intel_lookup failed: {type(cause).__name__ if cause else 'unknown'}")

        # 4. Assert returned object contract
        self.assertIsInstance(observation, ThreatIntelObservation)
        self.assertEqual(observation.indicator, "8.8.8.8")
        self.assertEqual(observation.indicator_type, "ip")
        self.assertEqual(observation.provider, "virustotal")
        self.assertEqual(observation.source_reference, "virustotal:ip:8.8.8.8")

        # 5. Assert counter invariants (exact int, not bool, non-negative)
        for counter_name in (
            "malicious_count",
            "suspicious_count",
            "harmless_count",
            "undetected_count",
        ):
            val = getattr(observation, counter_name)
            self.assertIs(type(val), int, f"{counter_name} must be exact int type")
            self.assertFalse(isinstance(val, bool), f"{counter_name} must not be a bool")
            self.assertGreaterEqual(val, 0, f"{counter_name} must be non-negative")

        # 6. Assert normalized verdict allowlist
        valid_verdicts = {"malicious", "suspicious", "harmless", "unknown"}
        self.assertIn(
            observation.verdict,
            valid_verdicts,
            f"verdict '{observation.verdict}' must be in allowlisted set {valid_verdicts}",
        )

        # 7. Secret hygiene verification on returned observation
        self.assertNotIn(raw_key, repr(observation))
        self.assertNotIn(raw_key, str(observation))
        self.assertNotIn(raw_key, str(dataclasses.asdict(observation)))

        # 8. Authority boundary verification: zero Splunk queries, zero policy side-effects
        mock_splunk.search_encoded_powershell.assert_not_called()
        mock_splunk.search_powershell_network_retrieval.assert_not_called()

    @_skip_unless_opted_in
    def test_live_direct_client_contract(self) -> None:
        """Verify direct VirusTotalThreatIntelClient lookup returns valid ThreatIntelResult."""
        raw_key = os.environ["VIRUSTOTAL_API_KEY"].strip()
        credentials = VirusTotalCredentials(api_key=raw_key)
        client = VirusTotalThreatIntelClient(credentials=credentials)
        req = ThreatIntelRequest(indicator_value="8.8.8.8")

        try:
            result = client.lookup(req)
        except VirusTotalResponseError as exc:
            cause_code = str(exc)
            if cause_code == "vt_auth_failed":
                self.fail("Live VirusTotal authentication failed (invalid API key): vt_auth_failed")
            elif cause_code in ("vt_rate_limited", "vt_forbidden", "vt_remote_error"):
                self.skipTest(f"Live VirusTotal service constraint: {cause_code}")
            else:
                self.fail(f"Live VirusTotal client returned schema/provider error: {cause_code}")
        except VirusTotalTransportError as exc:
            cause_code = str(exc)
            if cause_code == "vt_transport_error":
                self.skipTest(f"Live VirusTotal temporary transport failure: {cause_code}")
            else:
                self.fail(f"Live VirusTotal transport error: {cause_code}")

        self.assertIsInstance(result, ThreatIntelResult)
        self.assertEqual(result.provider, "virustotal")
        self.assertEqual(result.indicator_type, "ip")
        self.assertEqual(result.indicator_value, "8.8.8.8")
        self.assertIn(
            result.lookup_status,
            (ThreatIntelLookupStatus.FOUND, ThreatIntelLookupStatus.NOT_FOUND),
        )
        self.assertIn(
            result.detail_code,
            ("ip_lookup_found", "ip_lookup_not_found"),
        )

        for counter_name in (
            "malicious_count",
            "suspicious_count",
            "harmless_count",
            "undetected_count",
        ):
            val = getattr(result, counter_name)
            self.assertIs(type(val), int)
            self.assertFalse(isinstance(val, bool))
            self.assertGreaterEqual(val, 0)

        self.assertNotIn(raw_key, repr(result))
        self.assertNotIn(raw_key, str(result))


if __name__ == "__main__":
    unittest.main(verbosity=2)
