"""Controlled opt-in live test for WEB01 public-source threat intelligence enrichment.

NOT part of the default offline test suite.
Run explicitly only when RUN_LIVE_VT_TESTS=1 and VIRUSTOTAL_API_KEY are set in
the environment (or present in local .env) to verify live threat intelligence
enrichment through the full deterministic WEB01 control pipeline.

Usage:
    $env:RUN_LIVE_VT_TESTS="1"
    $env:VIRUSTOTAL_API_KEY="<your_api_key>"
    python -m unittest tests/live/test_web01_threat_intel_live.py -v
    # or
    python tests/live/test_web01_threat_intel_live.py

Security invariants & trust boundaries:
    - Pure advisory evidence: Threat intelligence results possess ZERO authority
      over risk scoring, policy evaluation, approval gates, containment, Jira, or Splunk.
    - Sanitized public-IP test fixture: Uses canonical indicator 8.8.8.8.
      SAFETY NOTICE: This fixture does NOT represent real attack traffic from 8.8.8.8,
      and no claim is made that traffic actually originated from that public IP.
    - Zero network exposure: WEB01 and Juice Shop are never exposed to the Internet.
    - Zero OpenAI calls: Driven by deterministic ScriptedModel; zero OpenAI tokens or keys.
    - Zero Jira writes: ticket_client=None; zero live Jira tickets created.
    - Zero containment actions: Containment simulation/execution is not engaged.
    - Mocked Splunk retrieval: Telemetry is mocked fail-closed; zero live Splunk network calls.
    - Exact single dispatch: Exactly one HTTPS GET dispatch to VirusTotal REST API v3 for 8.8.8.8;
      zero automatic retries.
    - Secret hygiene: API key is read strictly from process environment or .env,
      encapsulated in VirusTotalCredentials, and never printed, logged, or serialized.
"""

from __future__ import annotations

import dataclasses
import os
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional
import unittest
from unittest.mock import MagicMock

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
                    if k in ("VIRUSTOTAL_API_KEY", "RUN_LIVE_VT_TESTS") and k not in os.environ:
                        os.environ[k] = v
    except Exception:
        pass

# -----------------------------------------------------------------------
# Skip sentinel — evaluated once at import time
# -----------------------------------------------------------------------

_SKIP_REASON: Optional[str] = None
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
# Imports
# -----------------------------------------------------------------------

from gateway.splunk_search import SplunkSearchClient
from investigator.audit import AuditEvent, AuditEventType, AuditLog
from investigator.incident_record import (
    IncidentRecord,
    build_modsecurity_incident_record,
)
from investigator.incident_workflow import (
    Web01WorkflowResult,
    run_web01_incident_workflow,
)
from investigator.model import (
    DecisionType,
    ModelDecision,
    ModelRequest,
    ToolRequest,
)
from investigator.modsecurity import ModSecuritySqliEvidence
from investigator.orchestrator import (
    InvestigationOrchestrator,
    OrchestratorError,
)
from investigator.providers.virustotal_provider import (
    VirusTotalApiConfig,
    VirusTotalCredentials,
    VirusTotalError,
    VirusTotalResponseError,
    VirusTotalThreatIntelClient,
    VirusTotalTransportError,
)
from investigator.runtime_guard import RuntimeGuard
from investigator.schemas import (
    Web01InvestigationAssessment,
    Web01InvestigationRequest,
)
from investigator.threat_intel import (
    IndicatorScope,
    ThreatIntelObservation,
    classify_ipv4_scope,
)
from investigator.ticketing import (
    ALLOWED_TICKET_LABELS,
    TicketConfig,
)
from investigator.tool_router import ToolRouter


# -----------------------------------------------------------------------
# Controlled Test Fixtures (Sanitized Public-IP Demonstration Only)
# -----------------------------------------------------------------------
# PROVENANCE & SAFETY NOTICE:
# The indicator 8.8.8.8 is a sanitized public-IP test fixture used exclusively
# to validate the external threat intelligence pipeline under controlled live conditions.
# This fixture does NOT represent real attack traffic from 8.8.8.8, and no claim is made
# that traffic actually originated from that public IP.

CONTROLLED_PUBLIC_IP = "8.8.8.8"

_CONTROLLED_PUBLIC_MODSEC_RAW: Dict[str, Any] = {
    "_raw": (
        "--live-ti-validation-8888-A--\n"
        "[04/Oct/2026:08:15:30 +0000] live-ti-validation-8888 8.8.8.8 45678 192.168.1.102 80\n"
        "--live-ti-validation-8888-B--\n"
        "GET /rest/products/search?q=%27%20OR%201=1-- HTTP/1.1\n"
        "Host: 192.168.1.102\n"
        "User-Agent: sqlmap/1.7#stable\n"
        "--live-ti-validation-8888-H--\n"
        'Message: Warning. Pattern match "(?i:(?:select.*from))" at ARGS:q. [file "..."] [line "12"] [id "942100"] [msg "SQL Injection Attack Detected via libinjection"] [severity "CRITICAL"]\n'
        'Message: Warning. Operator GE reached 5 at TX:inbound_anomaly_score. [file "/etc/modsecurity/owasp-crs/rules/RESPONSE-980-CORRELATION.conf"] [line "91"] [id "980130"] [msg "Inbound Anomaly Score Exceeded (Total Score: 8)"] [severity "CRITICAL"] [ver "OWASP_CRS/3.3.4"]\n'
        "Action: Intercepted (eval score 8)\n"
        "--live-ti-validation-8888-Z--\n"
    ),
    "host": "web01",
    "src_ip": "8.8.8.8",
    "rule_id": "942100",
    "rule_msg": "SQL Injection Attack Detected via libinjection",
    "severity": "CRITICAL",
    "anomaly_score": "8",
    "unique_id": "live-ti-validation-8888",
}

_VALID_WEB01_REQUEST = Web01InvestigationRequest(
    detection_id="DET-WEB-001",
    host="web01",
    detection_type="modsecurity_sqli",
    rule_id=942100,
)

_VALID_WEB01_ASSESSMENT = Web01InvestigationAssessment(
    assessment="SQL injection attempt intercepted by ModSecurity CRS rule 942100.",
    confidence="high",
    evidence_summary="Controlled live TI validation fixture returned 1 matching event from web01.",
    attack_type="sql_injection",
    escalation_recommended=True,
    recommended_next_step="Inspect firewall rules and review TI report for indicator 8.8.8.8.",
)


class ScriptedModel:
    """Deterministic scripted model driving orchestrator decision loop without OpenAI calls."""

    def __init__(self, decisions: List[ModelDecision]) -> None:
        self._decisions = list(decisions)
        self.recorded_requests: List[ModelRequest] = []

    def decide(self, request: ModelRequest) -> ModelDecision:
        self.recorded_requests.append(request)
        if not self._decisions:
            raise RuntimeError("ScriptedModel has no more configured decisions")
        return self._decisions.pop(0)


# -----------------------------------------------------------------------
# Live Test Suite
# -----------------------------------------------------------------------

class TestWeb01ThreatIntelLive(unittest.TestCase):
    """Controlled live validation of WEB01 public-source threat intelligence enrichment."""

    @_skip_unless_opted_in
    def test_live_web01_public_source_ti_enrichment(self) -> None:
        """Verify full deterministic control path for public-source IP enrichment against live VirusTotal."""
        raw_key = os.environ["VIRUSTOTAL_API_KEY"].strip()
        credentials = VirusTotalCredentials(api_key=raw_key)

        # -------------------------------------------------------------------
        # 1. Scope Classification Assertion
        # -------------------------------------------------------------------
        scope = classify_ipv4_scope(CONTROLLED_PUBLIC_IP)
        self.assertEqual(scope.indicator, "8.8.8.8")
        self.assertEqual(scope.scope, "public")
        self.assertTrue(scope.external_ti_eligible)

        # -------------------------------------------------------------------
        # 2. Setup Mocked Splunk Retrieval (Zero live Splunk calls)
        # -------------------------------------------------------------------
        mock_splunk = MagicMock(spec=SplunkSearchClient)
        mock_splunk.search_modsecurity_sqli.return_value = [_CONTROLLED_PUBLIC_MODSEC_RAW]

        # -------------------------------------------------------------------
        # 3. Setup Real VirusTotal Client with Call-Tracking Spy
        # -------------------------------------------------------------------
        vt_client = VirusTotalThreatIntelClient(credentials=credentials)
        real_lookup = vt_client.lookup
        captured_exceptions: List[Exception] = []

        def tracked_lookup(req):
            try:
                return real_lookup(req)
            except Exception as exc:
                captured_exceptions.append(exc)
                raise

        spy_lookup = MagicMock(side_effect=tracked_lookup)
        vt_client.lookup = spy_lookup

        # -------------------------------------------------------------------
        # 4. Setup Deterministic ToolRouter, Guard, AuditLog, and Orchestrator
        # -------------------------------------------------------------------
        router = ToolRouter(splunk_client=mock_splunk, vt_client=vt_client)
        audit_log = AuditLog()
        guard = RuntimeGuard(audit_log=audit_log)

        # Two-turn decision loop:
        # Turn 0: Request bounded Splunk search (orchestrator will intercept and enrich)
        # Turn 1: Emit final assessment
        model = ScriptedModel([
            ModelDecision(
                decision_type=DecisionType.TOOL_REQUEST,
                tool_request=ToolRequest(
                    tool_name="bounded_splunk_search",
                    arguments={"query_type": "modsecurity_sqli_matches", "host": "web01"},
                ),
            ),
            ModelDecision(
                decision_type=DecisionType.FINAL_RESULT,
                final_result=_VALID_WEB01_ASSESSMENT,
            ),
        ])

        orchestrator = InvestigationOrchestrator(
            model=model,
            tool_router=router,
            audit_log=audit_log,
            guard=guard,
        )

        ticket_config = TicketConfig(
            project_key="KAN",
            issue_type="Incident",
            allowed_labels=tuple(sorted(ALLOWED_TICKET_LABELS)),
        )

        # -------------------------------------------------------------------
        # 5. Execute End-to-End Workflow with ticket_client=None (Zero Jira calls)
        # -------------------------------------------------------------------
        try:
            workflow_result: Web01WorkflowResult = run_web01_incident_workflow(
                request=_VALID_WEB01_REQUEST,
                orchestrator=orchestrator,
                ticket_config=ticket_config,
                ticket_client=None,
            )
        except Exception:
            # Check if live VirusTotal raised a legitimate service constraint
            if captured_exceptions:
                exc = captured_exceptions[0]
                if isinstance(exc, VirusTotalResponseError):
                    if str(exc) in ("vt_rate_limited", "vt_forbidden", "vt_remote_error"):
                        self.skipTest(f"Live VirusTotal service constraint: {exc}")
                    elif str(exc) == "vt_auth_failed":
                        self.fail(f"Live VirusTotal authentication failed (invalid API key): {exc}")
                elif isinstance(exc, VirusTotalTransportError):
                    self.skipTest(f"Live VirusTotal temporary transport failure: {exc}")
            raise

        # Check for provider failure that orchestrator caught fail-closed
        if orchestrator.last_web01_ti_status == "LOOKUP_FAILED" and captured_exceptions:
            exc = captured_exceptions[0]
            if isinstance(exc, VirusTotalResponseError) and str(exc) in ("vt_rate_limited", "vt_forbidden", "vt_remote_error"):
                self.skipTest(f"Live VirusTotal service constraint: {exc}")
            elif isinstance(exc, VirusTotalTransportError):
                self.skipTest(f"Live VirusTotal temporary transport failure: {exc}")

        # -------------------------------------------------------------------
        # 6. Verify Single Provider Call (No retry / duplicate)
        # -------------------------------------------------------------------
        self.assertEqual(
            spy_lookup.call_count,
            1,
            f"Expected exactly 1 call to VirusTotal lookup, got {spy_lookup.call_count}",
        )

        # -------------------------------------------------------------------
        # 7. Verify RuntimeGuard Tool Execution Budget & Permits
        # -------------------------------------------------------------------
        # Exactly two backend tool executions permitted:
        # 1. bounded_splunk_search
        # 2. threat_intel_lookup
        self.assertEqual(guard.state.tool_executions_permitted, 2)

        # -------------------------------------------------------------------
        # 8. Verify Normalized ThreatIntelObservation Contract
        # -------------------------------------------------------------------
        observation = orchestrator.last_web01_ti_observation
        self.assertIsInstance(observation, ThreatIntelObservation)
        self.assertEqual(observation.provider, "virustotal")
        self.assertEqual(observation.indicator, "8.8.8.8")
        self.assertEqual(observation.indicator_type, "ip")
        self.assertEqual(observation.source_reference, "virustotal:ip:8.8.8.8")

        valid_verdicts = {"malicious", "suspicious", "harmless", "unknown"}
        self.assertIn(
            observation.verdict,
            valid_verdicts,
            f"Verdict '{observation.verdict}' must be in allowlisted set {valid_verdicts}",
        )

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

        # -------------------------------------------------------------------
        # 9. Verify WEB01 Orchestrator Retained Deterministic State
        # -------------------------------------------------------------------
        self.assertEqual(orchestrator.last_web01_ti_status, "ENRICHED")
        self.assertIsNone(orchestrator.last_web01_ti_skip_reason)
        self.assertIs(orchestrator.last_web01_ti_observation, observation)
        self.assertIsNotNone(orchestrator.last_web01_evidence)
        self.assertEqual(orchestrator.last_web01_evidence.src_ip, "8.8.8.8")

        # -------------------------------------------------------------------
        # 10. Verify Immutable IncidentRecord Integration
        # -------------------------------------------------------------------
        incident_record = workflow_result.incident_record
        self.assertIsInstance(incident_record, IncidentRecord)
        self.assertEqual(incident_record.threat_intel_status, "ENRICHED")
        self.assertIsNone(incident_record.threat_intel_skip_reason)
        self.assertEqual(incident_record.threat_intel_observation, observation)
        self.assertIsNotNone(incident_record.modsecurity_evidence)
        self.assertEqual(incident_record.modsecurity_evidence.src_ip, "8.8.8.8")
        self.assertEqual(incident_record.modsecurity_evidence.rule_id, 942100)
        self.assertEqual(incident_record.modsecurity_evidence.unique_id, "live-ti-validation-8888")

        # -------------------------------------------------------------------
        # 11. Verify Zero Consequential Side Effects & Zero Network Leaks
        # -------------------------------------------------------------------
        # Zero Jira ticket creation
        self.assertIsNone(workflow_result.ticket_result)

        # Zero live Splunk calls beyond the mock
        mock_splunk.search_encoded_powershell.assert_not_called()
        mock_splunk.search_powershell_network_retrieval.assert_not_called()

        # Zero containment or approval side-effects
        self.assertFalse(incident_record.requires_human_approval)
        self.assertEqual(incident_record.approval_status, "NOT_REQUIRED")
        self.assertEqual(incident_record.simulation_status, "NOT_EXECUTED")
        self.assertEqual(incident_record.simulation_detail_code, "simulation_not_required")

        # -------------------------------------------------------------------
        # 12. Secret Hygiene Invariants
        # -------------------------------------------------------------------
        # API key absent from observation repr/str/dict
        self.assertNotIn(raw_key, repr(observation))
        self.assertNotIn(raw_key, str(observation))
        self.assertNotIn(raw_key, str(dataclasses.asdict(observation)))

        # API key absent from credentials repr/str
        self.assertNotIn(raw_key, repr(credentials))
        self.assertNotIn(raw_key, str(credentials))

        # API key absent from IncidentRecord repr/str/dict
        self.assertNotIn(raw_key, repr(incident_record))
        self.assertNotIn(raw_key, str(incident_record))
        self.assertNotIn(raw_key, str(incident_record.to_dict()))

        # API key absent from audit log
        audit_events = orchestrator.audit_log.events()
        for event in audit_events:
            self.assertNotIn(raw_key, repr(event))
            self.assertNotIn(raw_key, event.detail_code)

        # -------------------------------------------------------------------
        # 13. Audit Lifecycle Partial-Order Guarantees
        # -------------------------------------------------------------------
        actual_audit_codes = [event.detail_code for event in audit_events]

        for expected_code in (
            "bounded_splunk_search_requested",
            "bounded_splunk_search_allowed",
            "bounded_splunk_search_ok",
            "threat_intel_lookup_requested",
            "threat_intel_lookup_allowed",
            "threat_intel_lookup_ok",
        ):
            self.assertIn(
                expected_code,
                actual_audit_codes,
                f"Missing expected audit code '{expected_code}' in audit events: {actual_audit_codes}",
            )

        idx_splunk_req = actual_audit_codes.index("bounded_splunk_search_requested")
        idx_splunk_allowed = actual_audit_codes.index("bounded_splunk_search_allowed")
        idx_splunk_ok = actual_audit_codes.index("bounded_splunk_search_ok")

        idx_ti_req = actual_audit_codes.index("threat_intel_lookup_requested")
        idx_ti_allowed = actual_audit_codes.index("threat_intel_lookup_allowed")
        idx_ti_ok = actual_audit_codes.index("threat_intel_lookup_ok")

        # 1. Bounded Splunk search lifecycle ordering: requested < allowed < ok
        self.assertLess(
            idx_splunk_req,
            idx_splunk_allowed,
            "bounded_splunk_search_requested must precede bounded_splunk_search_allowed",
        )
        self.assertLess(
            idx_splunk_allowed,
            idx_splunk_ok,
            "bounded_splunk_search_allowed must precede bounded_splunk_search_ok",
        )

        # 2. Threat intelligence lookup lifecycle ordering: requested < allowed < ok
        self.assertLess(
            idx_ti_req,
            idx_ti_allowed,
            "threat_intel_lookup_requested must precede threat_intel_lookup_allowed",
        )
        self.assertLess(
            idx_ti_allowed,
            idx_ti_ok,
            "threat_intel_lookup_allowed must precede threat_intel_lookup_ok",
        )

        # 3. Nested WEB01 enrichment ordering: bounded_splunk_search_allowed < threat_intel_lookup_requested
        self.assertLess(
            idx_splunk_allowed,
            idx_ti_req,
            "bounded_splunk_search_allowed must precede threat_intel_lookup_requested",
        )

        # 4. TI completes before enclosing bounded search marks complete: threat_intel_lookup_ok < bounded_splunk_search_ok
        self.assertLess(
            idx_ti_ok,
            idx_splunk_ok,
            "threat_intel_lookup_ok must precede bounded_splunk_search_ok",
        )


if __name__ == "__main__":
    unittest.main()
