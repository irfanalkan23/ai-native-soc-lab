"""Controlled opt-in live test for WEB01 investigation path using OpenAIModel.

NOT part of the default offline test suite.
Run explicitly only when OPENAI_API_KEY and OPENAI_MODEL are set in the
environment (or present in local .env) to verify live model decision-making
and assessment production for Web01InvestigationRequest.

Usage:
    python -m unittest tests.live.test_web01_openai_live -v
    # or
    python tests/live/test_web01_openai_live.py

Security invariants:
    - Bounded tool execution: the real OpenAI model may only request bounded_splunk_search.
    - Zero SPL: model never authors SPL queries.
    - Zero action authority: Web01InvestigationAssessment has no containment authority.
    - Sanitized telemetry: evidence passed to model contains normalized fields, never raw Splunk logs.
    - Secret hygiene: OPENAI_API_KEY is read strictly from the process environment or .env,
      never printed, logged, or included in test assertions.
"""

from __future__ import annotations

import os
from pathlib import Path
import sys
import unittest
from typing import Any, Dict
from unittest.mock import MagicMock

# Ensure repository root is on sys.path
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

# Attempt reading credentials from local .env if not already in os.environ
_ENV_FILE = _REPO_ROOT / ".env"
if "OPENAI_API_KEY" not in os.environ and _ENV_FILE.exists():
    try:
        with open(_ENV_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    k = k.strip()
                    v = v.strip().strip("'\"")
                    if k in ("OPENAI_API_KEY", "OPENAI_MODEL") and k not in os.environ:
                        os.environ[k] = v
    except Exception:
        pass

# -----------------------------------------------------------------------
# Skip sentinel — evaluated once at import time
# -----------------------------------------------------------------------

_SKIP_REASON: str | None = None
_API_KEY = os.environ.get("OPENAI_API_KEY", "").strip()
_MODEL_NAME = os.environ.get("OPENAI_MODEL", "").strip()

if not _API_KEY:
    _SKIP_REASON = "OPENAI_API_KEY environment variable is not set"
elif not _MODEL_NAME:
    _SKIP_REASON = "OPENAI_MODEL environment variable is not set"


def _skip_if_no_credentials(test_func):
    """Decorator: skip test cleanly if live credentials are absent."""
    if _SKIP_REASON:
        return unittest.skip(_SKIP_REASON)(test_func)
    return test_func


# -----------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------

from investigator.audit import AuditEventType, AuditLog
from investigator.model import DecisionType, ModelDecision
from investigator.orchestrator import InvestigationOrchestrator
from investigator.providers.openai_provider import (
    OpenAIModel,
    OpenAIRequestError,
    OpenAIResponseError,
)
from investigator.schemas import (
    Web01InvestigationAssessment,
    Web01InvestigationRequest,
)
from gateway.splunk_search import SplunkSearchClient
from investigator.tool_router import ToolRouter

# -----------------------------------------------------------------------
# Live-derived sanitized ModSecurity fixture
# -----------------------------------------------------------------------

_VALID_WEB01_REQUEST = Web01InvestigationRequest(
    detection_id="DET-WEB-001",
    host="web01",
    detection_type="modsecurity_sqli",
    rule_id=942100,
)

_RAW_MODSEC_PRIVATE_TELEMETRY: Dict[str, Any] = {
    "_raw": (
        "--ar1Z9uxU-NFJV-LskY52NwAAAEQ-A--\n"
        "[04/Oct/2026:08:15:30 +0000] ar1Z9uxU-NFJV-LskY52NwAAAEQ 192.168.1.100 45678 192.168.1.102 80\n"
        "--ar1Z9uxU-NFJV-LskY52NwAAAEQ-B--\n"
        "GET /rest/products/search?q=%27%20OR%201=1-- HTTP/1.1\n"
        "Host: 192.168.1.102\n"
        "User-Agent: sqlmap/1.7#stable\n"
        "--ar1Z9uxU-NFJV-LskY52NwAAAEQ-H--\n"
        'Message: Warning. Pattern match "(?i:(?:select.*from))" at ARGS:q. [file "..."] [line "12"] [id "942100"] [msg "SQL Injection Attack Detected via libinjection"] [severity "CRITICAL"]\n'
        'Message: Warning. Operator GE reached 5 at TX:inbound_anomaly_score. [file "/etc/modsecurity/owasp-crs/rules/RESPONSE-980-CORRELATION.conf"] [line "91"] [id "980130"] [msg "Inbound Anomaly Score Exceeded (Total Score: 8)"] [severity "CRITICAL"] [ver "OWASP_CRS/3.3.4"]\n'
        "Action: Intercepted (eval score 8)\n"
        "--ar1Z9uxU-NFJV-LskY52NwAAAEQ-Z--\n"
    ),
    "host": "web01",
    "src_ip": "192.168.1.100",
    "rule_id": "942100",
    "rule_msg": "SQL Injection Attack Detected via libinjection",
    "severity": "CRITICAL",
    "anomaly_score": "8",
    "unique_id": "ar1Z9uxU-NFJV-LskY52NwAAAEQ",
}


class TestWeb01OpenAILiveValidation(unittest.TestCase):
    """Controlled live validation suite for WEB01 investigation via OpenAIModel."""

    @_skip_if_no_credentials
    def test_live_web01_openai_investigation(self) -> None:
        """Run a single controlled live OpenAI investigation for WEB01.

        Verifies:
            1. Model requests bounded_splunk_search with exact query_type and host.
            2. Tool router executes search against mocked Splunk and returns validated ModSecurity evidence.
            3. Deterministic TI scope policy marks private IP 192.168.1.100 as SKIPPED_INELIGIBLE (zero VT calls).
            4. Model returns a valid Web01InvestigationAssessment matching the output contract.
            5. Assessment contains no execution authority fields (isolate_host, block_ip, etc.).
            6. Audit trail logs complete static lifecycle events without leaking keys or raw data.
        """
        print(f"\n[live-openai-web01] Configured model: {_MODEL_NAME}")
        print(f"[live-openai-web01] OPENAI_API_KEY present: YES (value masked)")

        # 1. Bounded Splunk search mock returning sanitized live-derived telemetry
        mock_splunk = MagicMock(spec=SplunkSearchClient)
        mock_splunk.search_modsecurity_sqli.return_value = [_RAW_MODSEC_PRIVATE_TELEMETRY]
        router = ToolRouter(splunk_client=mock_splunk)

        # 2. Live OpenAI model adapter with decision recorder
        live_model = OpenAIModel()
        real_decide = live_model.decide
        call_count = 0
        recorded_decisions: list[ModelDecision] = []

        def instrumented_decide(req):
            nonlocal call_count
            call_count += 1
            decision = real_decide(req)
            recorded_decisions.append(decision)
            print(f"[live-openai-web01] Step {call_count}: decision_type={decision.decision_type}")
            if decision.decision_type == DecisionType.TOOL_REQUEST:
                print(f"  tool_name={decision.tool_request.tool_name} arguments={decision.tool_request.arguments}")
            elif decision.decision_type == DecisionType.FINAL_RESULT:
                print(f"  final_result={type(decision.final_result).__name__}")
            return decision

        live_model.decide = instrumented_decide

        # 3. Investigation orchestrator
        audit_log = AuditLog()
        orchestrator = InvestigationOrchestrator(
            model=live_model,
            tool_router=router,
            audit_log=audit_log,
        )

        # 4. Drive live investigation
        try:
            assessment = orchestrator.investigate(_VALID_WEB01_REQUEST)
        except OpenAIRequestError as exc:
            self.fail(f"Live OpenAI API call failed: {exc}")
        except OpenAIResponseError as exc:
            self.fail(f"Live OpenAI model returned invalid response: {exc}")

        # 5. Assertions on calls and decisions
        print(f"[live-openai-web01] Actual OpenAI API calls made: {call_count}")
        self.assertGreaterEqual(call_count, 2, "Expected at least 1 tool request and 1 final assessment")
        self.assertLessEqual(call_count, 4, "Expected within tool budget (<= 3 tool calls + 1 final result)")
        self.assertEqual(len(recorded_decisions), call_count)

        # Inspect all tool requests prior to final result
        for idx, tool_decision in enumerate(recorded_decisions[:-1], start=1):
            self.assertEqual(tool_decision.decision_type, DecisionType.TOOL_REQUEST)
            tool_req = tool_decision.tool_request
            self.assertIsNotNone(tool_req)
            print(f"[live-openai-web01] Tool request {idx}: {tool_req.tool_name} arguments={tool_req.arguments}")

            self.assertEqual(tool_req.tool_name, "bounded_splunk_search")
            self.assertEqual(tool_req.arguments.get("query_type"), "modsecurity_sqli_matches")
            self.assertEqual(tool_req.arguments.get("host"), "web01")

            # Disallowed tool arguments boundary
            disallowed_args = {"spl", "query", "index", "sourcetype", "rule_id", "indicator"}
            for arg in disallowed_args:
                self.assertNotIn(arg, tool_req.arguments, f"Model must not author or override '{arg}'")

        # Inspect final assessment (last decision)
        final_decision = recorded_decisions[-1]
        self.assertEqual(final_decision.decision_type, DecisionType.FINAL_RESULT)
        self.assertIsInstance(assessment, Web01InvestigationAssessment)

        print(f"[live-openai-web01] Attack type: {assessment.attack_type}")
        print(f"[live-openai-web01] Confidence: {assessment.confidence}")
        print(f"[live-openai-web01] Escalation recommended: {assessment.escalation_recommended}")
        print(f"[live-openai-web01] Recommended next step: {assessment.recommended_next_step}")
        print(f"[live-openai-web01] Assessment text: {assessment.assessment}")
        print(f"[live-openai-web01] Evidence summary: {assessment.evidence_summary}")

        self.assertEqual(assessment.attack_type, "sql_injection")
        self.assertIn(assessment.confidence, ("low", "medium", "high"))
        self.assertTrue(bool(assessment.assessment.strip()))
        self.assertTrue(bool(assessment.evidence_summary.strip()))
        self.assertTrue(bool(assessment.recommended_next_step.strip()))
        self.assertIsInstance(assessment.escalation_recommended, bool)

        # Verify no execution / containment authority leaked into assessment
        forbidden_fields = (
            "isolate_host",
            "block_ip",
            "disable_account",
            "firewall_change",
            "action_executed",
        )
        for field in forbidden_fields:
            self.assertFalse(hasattr(assessment, field), f"Assessment must not contain execution field '{field}'")

        # 6. Verify deterministic Threat Intel policy gating and backend execution accounting
        self.assertEqual(orchestrator.last_web01_ti_status, "SKIPPED_INELIGIBLE")
        self.assertEqual(orchestrator.last_web01_ti_skip_reason, "ineligible_scope:private")
        self.assertIsNone(orchestrator.last_web01_ti_observation)
        # Even if the live model emits identical tool requests, backend executes at most once
        self.assertEqual(
            mock_splunk.search_modsecurity_sqli.call_count,
            1,
            "Backend Splunk search must execute exactly once; identical requests must be deduplicated",
        )
        print("[live-openai-web01] Confirmed: 192.168.1.100 was SKIPPED_INELIGIBLE, zero VirusTotal lookups")
        print(f"[live-openai-web01] Confirmed: Splunk backend execution count = {mock_splunk.search_modsecurity_sqli.call_count}")

        # 7. Audit trail assertions
        events = audit_log.events()
        event_types = [event.event_type for event in events]
        self.assertIn(AuditEventType.MODEL_REQUESTED, event_types)
        self.assertIn(AuditEventType.TOOL_REQUESTED, event_types)
        self.assertIn(AuditEventType.TOOL_ALLOWED, event_types)
        self.assertIn(AuditEventType.TOOL_COMPLETED, event_types)
        self.assertIn(AuditEventType.FINAL_RESULT_ACCEPTED, event_types)

        # Audit events detail code inspection
        for event in events:
            self.assertNotIn(_API_KEY, event.detail_code)
            self.assertNotIn("Bearer", event.detail_code)
            self.assertNotIn("--ar1Z9uxU", event.detail_code)

        print("[live-openai-web01] Audit log lifecycle verified with sanitized static detail codes")
        print("[live-openai-web01] PASS: controlled live OpenAI validation successful")


if __name__ == "__main__":
    unittest.main()
