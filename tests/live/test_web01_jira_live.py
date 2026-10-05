"""Controlled opt-in live test for WEB01 Jira ticket creation.

NOT part of the default offline test suite.
Run explicitly only when JIRA_BASE_URL, JIRA_USER_EMAIL, and JIRA_API_TOKEN
are configured in the environment (or local .env) to verify live downstream
ticketing in Jira Cloud project KAN with issue type Incident.

Usage:
    python -m unittest tests.live.test_web01_jira_live -v
    # or
    python tests/live/test_web01_jira_live.py

Security invariants:
    - Downstream reporting only: Jira issue creation possesses ZERO authority
      over risk scoring, policy evaluation, approval gates, or response execution.
    - Bounded routing: strictly project KAN and issue type Incident.
    - Sanitized telemetry: structured ModSecurity fields only, zero raw transaction logs (_raw).
    - Deterministic TI status: records SKIPPED_INELIGIBLE without claiming clean or benign verdict.
    - Secret hygiene: API token is never printed, logged, or included in assertions.
    - Single dispatch: exactly one live POST /rest/api/3/issue call with zero automatic retries.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
import sys
from typing import Optional
import unittest

# Ensure repository root is on sys.path
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

# Attempt reading credentials from local .env if not already in os.environ
_ENV_FILE = _REPO_ROOT / ".env"
if _ENV_FILE.exists():
    try:
        with open(_ENV_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    k = k.strip()
                    v = v.strip().strip("'\"")
                    if k in ("JIRA_BASE_URL", "JIRA_USER_EMAIL", "JIRA_API_TOKEN") and k not in os.environ:
                        os.environ[k] = v
    except Exception:
        pass

# -----------------------------------------------------------------------
# Skip sentinel — evaluated once at import time
# -----------------------------------------------------------------------

_SKIP_REASON: Optional[str] = None
_BASE_URL = os.environ.get("JIRA_BASE_URL", "").strip()
_USER_EMAIL = os.environ.get("JIRA_USER_EMAIL", "").strip()
_API_TOKEN = os.environ.get("JIRA_API_TOKEN", "").strip()

if not _BASE_URL:
    _SKIP_REASON = "JIRA_BASE_URL environment variable is not set"
elif not _USER_EMAIL:
    _SKIP_REASON = "JIRA_USER_EMAIL environment variable is not set"
elif not _API_TOKEN:
    _SKIP_REASON = "JIRA_API_TOKEN environment variable is not set"


def _skip_if_no_credentials(test_func):
    """Decorator: skip test cleanly if live Jira credentials are absent."""
    if _SKIP_REASON:
        return unittest.skip(_SKIP_REASON)(test_func)
    return test_func


# -----------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------

from investigator.incident_record import (
    IncidentRecord,
    build_modsecurity_incident_record,
)
from investigator.modsecurity import ModSecuritySqliEvidence
from investigator.modsecurity_enrichment import ModSecurityEnrichmentResult
from investigator.providers.jira_provider import (
    JiraConfigError,
    JiraCredentialError,
    JiraError,
    JiraResponseError,
    JiraTicketClient,
    JiraTransportError,
)
from investigator.threat_intel import IndicatorScope
from investigator.ticketing import (
    ALLOWED_TICKET_LABELS,
    SAFE_TICKET_KEY_PATTERN,
    TicketClientError,
    TicketConfig,
    TicketRequest,
    TicketResult,
    build_ticket_request,
)

# -----------------------------------------------------------------------
# Live-derived sanitized ModSecurity fixtures
# -----------------------------------------------------------------------

_VALID_WEB01_EVIDENCE = ModSecuritySqliEvidence(
    host="web01",
    src_ip="192.168.1.100",
    rule_id=942100,
    rule_msg="SQL Injection Attack Detected via libinjection",
    severity="CRITICAL",
    anomaly_score=8,
    unique_id="ar1Z9uxU-NFJV-LskY52NwAAAEQ",
)

_WEB01_INELIGIBLE_ENRICHMENT = ModSecurityEnrichmentResult(
    evidence=_VALID_WEB01_EVIDENCE,
    scope=IndicatorScope(
        indicator="192.168.1.100",
        scope="private",
        external_ti_eligible=False,
    ),
    enriched=False,
    observation=None,
    skip_reason="ineligible_scope:private",
)


class TestWeb01JiraLiveValidation(unittest.TestCase):
    """Controlled live validation suite for WEB01 Jira ticket creation."""

    @_skip_if_no_credentials
    def test_live_web01_jira_ticket_creation(self) -> None:
        """Create exactly one live Jira incident ticket for a sanitized WEB01 incident."""
        print(f"\n[live-jira-web01] Target base URL: {_BASE_URL}")
        print("[live-jira-web01] Jira credentials present: YES (value masked)")

        # 1. Construct sanitized IncidentRecord via existing builder
        incident_record = build_modsecurity_incident_record(
            evidence=_VALID_WEB01_EVIDENCE,
            enrichment_result=_WEB01_INELIGIBLE_ENRICHMENT,
        )
        self.assertIsInstance(incident_record, IncidentRecord)
        self.assertEqual(incident_record.threat_intel_status, "SKIPPED_INELIGIBLE")
        self.assertEqual(incident_record.threat_intel_skip_reason, "ineligible_scope:private")

        # 2. Build TicketRequest via existing builder with strict bounds
        ticket_config = TicketConfig(
            project_key="KAN",
            issue_type="Incident",
            allowed_labels=tuple(sorted(ALLOWED_TICKET_LABELS)),
        )
        ticket_request = build_ticket_request(incident_record, ticket_config)

        # 3. Pre-flight verification: Bounded routing
        self.assertEqual(ticket_request.project_key, "KAN")
        self.assertEqual(ticket_request.issue_type, "Incident")
        self.assertIn("web-attack", ticket_request.labels)
        self.assertIn("ai-native-soc", ticket_request.labels)

        # 4. Pre-flight verification: Content bounds and deterministic evidence
        desc = ticket_request.description
        summary = ticket_request.summary

        self.assertIn("web01", desc)
        self.assertIn("192.168.1.100", desc)
        self.assertIn("942100", desc)
        self.assertIn("SQL Injection Attack Detected via libinjection", desc)
        self.assertIn("CRITICAL", desc)
        self.assertIn("ar1Z9uxU-NFJV-LskY52NwAAAEQ", desc)
        self.assertIn("SKIPPED_INELIGIBLE", desc)
        self.assertIn("ineligible_scope:private", desc)
        self.assertIn(incident_record.incident_id, desc)

        # Negative assertions: No false benign claims
        combined_text = f"{summary}\n{desc}"
        self.assertNotIn("clean", combined_text.lower())
        self.assertNotIn("benign", combined_text.lower())
        self.assertNotIn("virustotal found zero", combined_text.lower())
        self.assertNotIn("virustotal was queried", combined_text.lower())
        self.assertNotIn("endpoint was isolated", combined_text.lower())
        self.assertNotIn("ip was blocked", combined_text.lower())
        self.assertNotIn("action executed", combined_text.lower())

        # Negative assertions: Data minimization and secret hygiene
        self.assertNotIn("_raw", combined_text)
        self.assertNotIn("--ar1Z9uxU", combined_text)
        self.assertNotIn("HTTP/1.1", combined_text)
        self.assertNotIn("Stopwatch:", combined_text)
        self.assertNotIn(_API_TOKEN, combined_text)
        self.assertNotIn("Bearer", combined_text)
        self.assertNotIn("Authorization", combined_text)
        self.assertNotIn("api_key", combined_text)

        # 5. Construct existing Jira client from environment
        client = JiraTicketClient.from_env()

        # Wrap create_ticket to enforce exact single-call constraint
        real_create_ticket = client.create_ticket
        create_calls = 0

        def instrumented_create_ticket(req: TicketRequest) -> TicketResult:
            nonlocal create_calls
            create_calls += 1
            if create_calls > 1:
                raise RuntimeError("Security invariant violated: more than one live Jira ticket creation attempted!")
            return real_create_ticket(req)

        client.create_ticket = instrumented_create_ticket

        # 6. Dispatch live create ticket request exactly once
        print(f"[live-jira-web01] Dispatching POST /rest/api/3/issue for incident {incident_record.incident_id}...")
        try:
            result = client.create_ticket(ticket_request)
        except JiraResponseError as exc:
            diag_parts = []
            if exc.http_status:
                diag_parts.append(f"HTTP {exc.http_status}")
            if exc.jira_errors:
                diag_parts.append(f"errors={exc.jira_errors}")
            if exc.jira_error_messages:
                diag_parts.append(f"errorMessages={list(exc.jira_error_messages)}")
            diag_str = f" [Diagnostic: {'; '.join(diag_parts)}]" if diag_parts else ""
            self.fail(f"Live Jira API rejected request (HTTP/schema error): {exc}{diag_str}")
        except JiraTransportError as exc:
            self.fail(f"Live Jira network/transport failure: {exc}")
        except JiraError as exc:
            self.fail(f"Live Jira client error: {exc}")

        # 7. Post-creation assertions
        self.assertEqual(create_calls, 1, "Exactly one Jira create-ticket API call must be executed")
        self.assertIsInstance(result, TicketResult)
        self.assertTrue(result.success, "Ticket creation must return success=True")
        self.assertEqual(result.detail_code, "ticket_created_jira")
        self.assertIsNotNone(result.ticket_key)
        self.assertTrue(
            result.ticket_key.startswith("KAN-"),
            f"Returned ticket key '{result.ticket_key}' must belong to project KAN",
        )
        self.assertRegex(result.ticket_key, SAFE_TICKET_KEY_PATTERN)

        print(f"[live-jira-web01] Ticket successfully created!")
        print(f"[live-jira-web01] Ticket Key: {result.ticket_key}")
        print(f"[live-jira-web01] Project: {ticket_request.project_key}")
        print(f"[live-jira-web01] Issue Type: {ticket_request.issue_type}")
        print(f"[live-jira-web01] Summary: {ticket_request.summary}")
        print(f"[live-jira-web01] Labels: {list(ticket_request.labels)}")
        print(f"[live-jira-web01] Created At UTC: {result.created_at_utc}")
        print(f"[live-jira-web01] Detail Code: {result.detail_code}")
        print(f"[live-jira-web01] Live API calls made: {create_calls}")

    def test_web01_workflow_routing_rejects_sec_and_task(self) -> None:
        """Verify WEB01 workflow routing strictly rejects SEC and Task."""
        from investigator.incident_workflow import (
            ALLOWED_WEB01_PROJECT_KEYS,
            ALLOWED_WEB01_ISSUE_TYPES,
        )
        self.assertIn("KAN", ALLOWED_WEB01_PROJECT_KEYS)
        self.assertNotIn("SEC", ALLOWED_WEB01_PROJECT_KEYS)
        self.assertIn("Incident", ALLOWED_WEB01_ISSUE_TYPES)
        self.assertNotIn("Task", ALLOWED_WEB01_ISSUE_TYPES)


if __name__ == "__main__":
    unittest.main()
