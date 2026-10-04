"""Unit and integration tests for Milestone 13E: End-to-End Offline WEB01 Incident Workflow.

TDD RED PHASE ONLY.

Architecture Principle:
    AI proposes
    -> deterministic policy evaluates
    -> human approves consequential actions
    -> system executes only permitted/simulated actions
    -> deterministic IncidentRecord generated
    -> downstream bounded Jira ticket created
    -> everything is logged and evaluated

Scope & Trust Boundaries:
1. Fully Offline & Deterministic:
   - Zero live OpenAI, VirusTotal, or Jira network calls.
   - Scripted provider-neutral model, mocked Splunk, FakeTicketClient.
2. Single Pipeline & No Duplication:
   - Reuses existing InvestigationOrchestrator, ToolRouter, RuntimeGuard, AuditLog.
   - Reuses existing IncidentRecord and build_modsecurity_incident_record.
   - Reuses existing build_ticket_request and TicketConfig.
   - Does NOT create a second agent, second orchestrator, or second Jira adapter.
3. Authority Separation:
   - AI assessment remains strictly advisory with zero action or routing authority.
   - Deterministic policy dictates risk, disposition, and TI eligibility.
   - Human approval cannot be bypassed by AI recommendation.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
import unittest
from unittest.mock import MagicMock

from gateway.splunk_search import SplunkSearchClient
from investigator.audit import AuditEvent, AuditEventType, AuditLog
from investigator.incident_record import (
    IncidentApprovalStatus,
    IncidentRecord,
    IncidentRecordError,
    build_modsecurity_incident_record,
)
from investigator.model import (
    DecisionType,
    ModelDecision,
    ModelRequest,
    ToolRequest,
)
from investigator.modsecurity import ModSecuritySqliEvidence
from investigator.modsecurity_enrichment import ModSecurityEnrichmentResult
from investigator.orchestrator import (
    InvestigationOrchestrator,
    OrchestratorError,
)
from investigator.runtime_guard import RuntimeGuard, RuntimeGuardConfig
from investigator.schemas import (
    InvestigationResult,
    Web01InvestigationAssessment,
    Web01InvestigationRequest,
)
from investigator.simulator import SimulationStatus
from investigator.threat_intel import (
    IndicatorScope,
    ThreatIntelLookupStatus,
    ThreatIntelObservation,
    ThreatIntelResult,
)
from investigator.ticketing import (
    ALLOWED_TICKET_LABELS,
    FakeTicketClient,
    TicketClient,
    TicketClientError,
    TicketConfig,
    TicketConfigError,
    TicketPriority,
    TicketRequest,
    TicketResult,
    TicketSchemaError,
    build_ticket_request,
)
from investigator.tool_router import ToolRouter

# Attempt to import workflow coordinator (RED phase: does not exist yet)
try:
    from investigator.incident_workflow import (  # type: ignore[import-not-found]
        Web01WorkflowResult,
        run_web01_incident_workflow,
    )
except ImportError:
    run_web01_incident_workflow = None  # type: ignore[assignment]
    Web01WorkflowResult = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Test Fixtures (Offline & Deterministic)
# ---------------------------------------------------------------------------

_VALID_WEB01_REQUEST = Web01InvestigationRequest(
    detection_id="DET-WEB-001",
    host="web01",
    detection_type="modsecurity_sqli",
    rule_id=942100,
)

_VALID_MODSECURITY_EVIDENCE = ModSecuritySqliEvidence(
    host="web01",
    src_ip="192.168.1.100",
    rule_id=942100,
    rule_msg="SQL Injection Attack Detected via libinjection",
    severity="CRITICAL",
    anomaly_score=8,
    unique_id="ar1Z9uxU-NFJV-LskY52NwAAAEQ",
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

_VALID_WEB01_ASSESSMENT = Web01InvestigationAssessment(
    assessment="SQL injection activity confirmed by validated ModSecurity evidence",
    confidence="high",
    evidence_summary="Rule 942100 triggered with anomaly score 8 from 192.168.1.100",
    attack_type="sql_injection",
    escalation_recommended=True,
    recommended_next_step="Escalate for analyst review",
)

_PUBLIC_MODSECURITY_EVIDENCE = ModSecuritySqliEvidence(
    host="web01",
    src_ip="93.184.216.34",
    rule_id=942100,
    rule_msg="SQL Injection Attack Detected via libinjection",
    severity="CRITICAL",
    anomaly_score=8,
    unique_id="pubZ9uxU-NFJV-LskY52NwAAAEQ",
)

_NORMALIZED_TI_OBSERVATION = ThreatIntelObservation(
    indicator="93.184.216.34",
    indicator_type="ip",
    provider="virustotal",
    verdict="suspicious",
    malicious_count=0,
    suspicious_count=2,
    harmless_count=60,
    undetected_count=18,
    source_reference="virustotal:ip:93.184.216.34",
)

_VALID_TICKET_CONFIG = TicketConfig(
    project_key="SEC",
    issue_type="Incident",
    allowed_labels=tuple(sorted(ALLOWED_TICKET_LABELS)),
)


class ScriptedModel:
    """Deterministic scripted model for offline test execution."""

    def __init__(self, decisions: List[ModelDecision]) -> None:
        self._decisions = list(decisions)
        self._call_count = 0
        self.recorded_requests: List[ModelRequest] = []

    def decide(self, request: ModelRequest) -> ModelDecision:
        self.recorded_requests.append(request)
        if self._call_count >= len(self._decisions):
            raise RuntimeError(f"Unexpected decide() call #{self._call_count + 1}")
        decision = self._decisions[self._call_count]
        self._call_count += 1
        return decision


class TestWeb01IncidentWorkflow(unittest.TestCase):
    """Offline test suite for Milestone 13E WEB01 incident workflow integration."""

    def _run_workflow(
        self,
        request: Web01InvestigationRequest,
        orchestrator: InvestigationOrchestrator,
        ticket_config: TicketConfig,
        ticket_client: Optional[TicketClient] = None,
    ) -> Any:
        """Helper to invoke workflow coordinator or fail if unimplemented (RED phase)."""
        if run_web01_incident_workflow is None:
            self.fail(
                "Milestone 13E RED: run_web01_incident_workflow is not implemented yet. "
                "No complete WEB01 workflow coordinator exists."
            )
        return run_web01_incident_workflow(
            request=request,
            orchestrator=orchestrator,
            ticket_config=ticket_config,
            ticket_client=ticket_client,
        )

    # =========================================================================
    # 1. Core End-to-End Offline Scenario (Section 3)
    # =========================================================================

    def test_web01_offline_incident_workflow_end_to_end(self) -> None:
        """Verify complete offline WEB01 workflow from alert to IncidentRecord and Jira ticket."""
        mock_splunk = MagicMock(spec=SplunkSearchClient)
        mock_splunk.search_modsecurity_sqli.return_value = [_RAW_MODSEC_PRIVATE_TELEMETRY]
        router = ToolRouter(splunk_client=mock_splunk)

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

        audit_log = AuditLog()
        orchestrator = InvestigationOrchestrator(
            model=model,
            tool_router=router,
            audit_log=audit_log,
        )
        fake_ticket_client = FakeTicketClient()

        result = self._run_workflow(
            request=_VALID_WEB01_REQUEST,
            orchestrator=orchestrator,
            ticket_config=_VALID_TICKET_CONFIG,
            ticket_client=fake_ticket_client,
        )

        self.assertIsNotNone(result)
        self.assertIsInstance(result.incident_record, IncidentRecord)
        self.assertIsInstance(result.ticket_request, TicketRequest)
        self.assertIsInstance(result.ticket_result, TicketResult)
        self.assertTrue(result.ticket_result.success)
        self.assertTrue(result.ticket_result.ticket_key.startswith("SEC-"))

    # =========================================================================
    # 2. IncidentRecord Integration (Section 4)
    # =========================================================================

    def test_web01_incident_record_uses_validated_modsecurity_evidence(self) -> None:
        """Verify workflow constructs IncidentRecord with exact validated ModSecurity evidence fields."""
        record = build_modsecurity_incident_record(
            evidence=_VALID_MODSECURITY_EVIDENCE,
            threat_intel_status="SKIPPED_INELIGIBLE",
            threat_intel_skip_reason="ineligible_scope:private",
        )
        self.assertEqual(record.target_host, "web01")
        self.assertEqual(record.modsecurity_evidence.src_ip, "192.168.1.100")
        self.assertEqual(record.modsecurity_evidence.rule_id, 942100)
        self.assertEqual(record.modsecurity_evidence.anomaly_score, 8)
        self.assertEqual(record.modsecurity_evidence.unique_id, "ar1Z9uxU-NFJV-LskY52NwAAAEQ")

    def test_web01_incident_record_uses_deterministic_ti_state(self) -> None:
        """Verify IncidentRecord embeds deterministic TI status rather than model conjecture."""
        record = build_modsecurity_incident_record(
            evidence=_VALID_MODSECURITY_EVIDENCE,
            threat_intel_status="SKIPPED_INELIGIBLE",
            threat_intel_skip_reason="ineligible_scope:private",
        )
        self.assertEqual(record.threat_intel_status, "SKIPPED_INELIGIBLE")
        self.assertEqual(record.threat_intel_skip_reason, "ineligible_scope:private")
        self.assertIsNone(record.threat_intel_observation)

    def test_web01_ai_cannot_override_incident_identity(self) -> None:
        """Verify AI assessment cannot alter detection ID or MITRE technique."""
        record = build_modsecurity_incident_record(
            evidence=_VALID_MODSECURITY_EVIDENCE,
            threat_intel_status="SKIPPED_INELIGIBLE",
            threat_intel_skip_reason="ineligible_scope:private",
        )
        self.assertEqual(record.detection_id, "DET-WEB-001")
        self.assertEqual(record.mitre_technique_id, "T1190")

    def test_web01_ai_cannot_override_ti_status(self) -> None:
        """Verify AI prose claiming clean TI does not alter deterministic skipped TI status."""
        record = build_modsecurity_incident_record(
            evidence=_VALID_MODSECURITY_EVIDENCE,
            threat_intel_status="SKIPPED_INELIGIBLE",
            threat_intel_skip_reason="ineligible_scope:private",
        )
        self.assertNotEqual(record.threat_intel_status, "ENRICHED")
        self.assertEqual(record.threat_intel_status, "SKIPPED_INELIGIBLE")

    def test_web01_ai_cannot_claim_action_executed(self) -> None:
        """Verify AI assessment cannot transition simulation status to executed."""
        record = build_modsecurity_incident_record(
            evidence=_VALID_MODSECURITY_EVIDENCE,
            threat_intel_status="SKIPPED_INELIGIBLE",
            threat_intel_skip_reason="ineligible_scope:private",
        )
        self.assertEqual(record.simulation_status, SimulationStatus.NOT_EXECUTED.value)

    # =========================================================================
    # 3. Identity Semantics (Section 5)
    # =========================================================================

    def test_web01_detection_id_is_not_incident_id(self) -> None:
        """Verify detection rule ID (DET-WEB-001) is strictly distinct from incident ID."""
        record = build_modsecurity_incident_record(
            evidence=_VALID_MODSECURITY_EVIDENCE,
            threat_intel_status="SKIPPED_INELIGIBLE",
            threat_intel_skip_reason="ineligible_scope:private",
        )
        self.assertEqual(record.detection_id, "DET-WEB-001")
        self.assertNotEqual(record.incident_id, record.detection_id)
        self.assertTrue(record.incident_id.startswith("INC-WEB01-"))

    def test_web01_incident_record_uses_unique_modsecurity_incident_identity(self) -> None:
        """Verify incident ID derives deterministically from the ModSecurity unique transaction ID."""
        record = build_modsecurity_incident_record(
            evidence=_VALID_MODSECURITY_EVIDENCE,
            threat_intel_status="SKIPPED_INELIGIBLE",
            threat_intel_skip_reason="ineligible_scope:private",
        )
        self.assertIn("ar1Z9uxU", record.incident_id)

    # =========================================================================
    # 4. Private-IP Workflow (Section 6)
    # =========================================================================

    def test_web01_private_ip_incident_records_skipped_ti(self) -> None:
        """Verify private IP produces SKIPPED_INELIGIBLE state in IncidentRecord."""
        record = build_modsecurity_incident_record(
            evidence=_VALID_MODSECURITY_EVIDENCE,
            threat_intel_status="SKIPPED_INELIGIBLE",
            threat_intel_skip_reason="ineligible_scope:private",
        )
        self.assertEqual(record.threat_intel_status, "SKIPPED_INELIGIBLE")
        self.assertIsNone(record.threat_intel_observation)

    def test_web01_private_ip_ticket_does_not_claim_clean_verdict(self) -> None:
        """Verify private IP ticket description does not describe skipped TI as clean or benign."""
        record = build_modsecurity_incident_record(
            evidence=_VALID_MODSECURITY_EVIDENCE,
            threat_intel_status="SKIPPED_INELIGIBLE",
            threat_intel_skip_reason="ineligible_scope:private",
        )
        ticket_req = build_ticket_request(record, _VALID_TICKET_CONFIG)
        desc_lower = ticket_req.description.lower()
        self.assertIn("skipped_ineligible", desc_lower)
        self.assertNotIn("verdict: clean", desc_lower)
        self.assertNotIn("verdict: benign", desc_lower)

    def test_web01_private_ip_ticket_does_not_claim_ti_lookup_executed(self) -> None:
        """Verify private IP ticket description does not claim VirusTotal was queried."""
        record = build_modsecurity_incident_record(
            evidence=_VALID_MODSECURITY_EVIDENCE,
            threat_intel_status="SKIPPED_INELIGIBLE",
            threat_intel_skip_reason="ineligible_scope:private",
        )
        ticket_req = build_ticket_request(record, _VALID_TICKET_CONFIG)
        self.assertNotIn("Provider: virustotal", ticket_req.description)

    # =========================================================================
    # 5. Public-IP ENRICHED Workflow (Section 7)
    # =========================================================================

    def test_web01_public_ip_incident_records_enriched_ti(self) -> None:
        """Verify eligible public IP produces ENRICHED status with ThreatIntelObservation attached."""
        record = build_modsecurity_incident_record(
            evidence=_PUBLIC_MODSECURITY_EVIDENCE,
            threat_intel_status="ENRICHED",
            threat_intel_observation=_NORMALIZED_TI_OBSERVATION,
        )
        self.assertEqual(record.threat_intel_status, "ENRICHED")
        self.assertIsNotNone(record.threat_intel_observation)
        self.assertEqual(record.threat_intel_observation.indicator, "93.184.216.34")

    def test_web01_public_ip_ticket_contains_normalized_ti_only(self) -> None:
        """Verify public IP ticket description renders normalized counters and verdict."""
        record = build_modsecurity_incident_record(
            evidence=_PUBLIC_MODSECURITY_EVIDENCE,
            threat_intel_status="ENRICHED",
            threat_intel_observation=_NORMALIZED_TI_OBSERVATION,
        )
        ticket_req = build_ticket_request(record, _VALID_TICKET_CONFIG)
        self.assertIn("* Indicator: 93.184.216.34", ticket_req.description)
        self.assertIn("* Provider: virustotal", ticket_req.description)
        self.assertIn("* Verdict: suspicious", ticket_req.description)
        self.assertIn("* Suspicious Count: 2", ticket_req.description)

    def test_web01_public_ip_ticket_excludes_provider_payload(self) -> None:
        """Verify public IP ticket excludes raw provider JSON, API keys, or HTTP headers."""
        record = build_modsecurity_incident_record(
            evidence=_PUBLIC_MODSECURITY_EVIDENCE,
            threat_intel_status="ENRICHED",
            threat_intel_observation=_NORMALIZED_TI_OBSERVATION,
        )
        ticket_req = build_ticket_request(record, _VALID_TICKET_CONFIG)
        self.assertNotIn("Bearer", ticket_req.description)
        self.assertNotIn("api_key", ticket_req.description)
        self.assertNotIn("x-apikey", ticket_req.description)

    # =========================================================================
    # 6. Public-IP LOOKUP_FAILED Workflow (Section 8)
    # =========================================================================

    def test_web01_ti_failure_incident_is_distinct_from_skipped(self) -> None:
        """Verify provider lookup failure is recorded as LOOKUP_FAILED and not SKIPPED."""
        record = build_modsecurity_incident_record(
            evidence=_PUBLIC_MODSECURITY_EVIDENCE,
            enrichment_failure_reason="provider_lookup_failed",
        )
        self.assertEqual(record.threat_intel_status, "LOOKUP_FAILED")
        self.assertNotEqual(record.threat_intel_status, "SKIPPED_INELIGIBLE")

    def test_web01_ti_failure_ticket_reports_lookup_failure(self) -> None:
        """Verify failed lookup ticket description explicitly documents the failure."""
        record = build_modsecurity_incident_record(
            evidence=_PUBLIC_MODSECURITY_EVIDENCE,
            enrichment_failure_reason="provider_lookup_failed",
        )
        ticket_req = build_ticket_request(record, _VALID_TICKET_CONFIG)
        self.assertIn("* Status: LOOKUP_FAILED", ticket_req.description)
        self.assertIn("* Error Detail: provider_lookup_failed", ticket_req.description)

    def test_web01_ti_failure_ticket_does_not_claim_benign(self) -> None:
        """Verify failed lookup ticket does not infer a clean or harmless observation."""
        record = build_modsecurity_incident_record(
            evidence=_PUBLIC_MODSECURITY_EVIDENCE,
            enrichment_failure_reason="provider_lookup_failed",
        )
        ticket_req = build_ticket_request(record, _VALID_TICKET_CONFIG)
        self.assertNotIn("Verdict: clean", ticket_req.description)
        self.assertNotIn("Verdict: harmless", ticket_req.description)

    # =========================================================================
    # 7. Jira Remains Bounded and Offline (Section 9)
    # =========================================================================

    def test_web01_ticket_uses_bounded_project(self) -> None:
        """Verify ticket project key is strictly bound to trusted config (SEC)."""
        record = build_modsecurity_incident_record(
            evidence=_VALID_MODSECURITY_EVIDENCE,
            threat_intel_status="SKIPPED_INELIGIBLE",
            threat_intel_skip_reason="ineligible_scope:private",
        )
        ticket_req = build_ticket_request(record, _VALID_TICKET_CONFIG)
        self.assertEqual(ticket_req.project_key, "SEC")

    def test_web01_ticket_uses_bounded_issue_type(self) -> None:
        """Verify ticket issue type is strictly bound to trusted config (Incident)."""
        record = build_modsecurity_incident_record(
            evidence=_VALID_MODSECURITY_EVIDENCE,
            threat_intel_status="SKIPPED_INELIGIBLE",
            threat_intel_skip_reason="ineligible_scope:private",
        )
        ticket_req = build_ticket_request(record, _VALID_TICKET_CONFIG)
        self.assertEqual(ticket_req.issue_type, "Incident")

    def test_web01_ticket_includes_web_attack_label(self) -> None:
        """Verify ticket contains web-attack label derived from ModSecurity evidence."""
        record = build_modsecurity_incident_record(
            evidence=_VALID_MODSECURITY_EVIDENCE,
            threat_intel_status="SKIPPED_INELIGIBLE",
            threat_intel_skip_reason="ineligible_scope:private",
        )
        ticket_req = build_ticket_request(record, _VALID_TICKET_CONFIG)
        self.assertIn("web-attack", ticket_req.labels)

    def test_web01_ticket_rejects_arbitrary_project_override(self) -> None:
        """Verify unallowlisted project keys are rejected fail-closed by TicketConfig."""
        with self.assertRaises(TicketConfigError):
            TicketConfig(
                project_key="lowercase_project",
                issue_type="Incident",
                allowed_labels=_VALID_TICKET_CONFIG.allowed_labels,
            )

    # =========================================================================
    # 8. AI Assessment Remains Advisory (Section 10)
    # =========================================================================

    def test_web01_ai_assessment_cannot_execute_response(self) -> None:
        """Verify AI assessment cannot trigger host isolation or containment."""
        record = build_modsecurity_incident_record(
            evidence=_VALID_MODSECURITY_EVIDENCE,
            threat_intel_status="SKIPPED_INELIGIBLE",
            threat_intel_skip_reason="ineligible_scope:private",
        )
        self.assertEqual(record.simulation_status, SimulationStatus.NOT_EXECUTED.value)
        self.assertEqual(record.simulation_detail_code, "simulation_not_required")

    def test_web01_ai_assessment_cannot_set_ticket_routing(self) -> None:
        """Verify AI assessment content cannot redirect Jira project or issue type."""
        record = build_modsecurity_incident_record(
            evidence=_VALID_MODSECURITY_EVIDENCE,
            threat_intel_status="SKIPPED_INELIGIBLE",
            threat_intel_skip_reason="ineligible_scope:private",
        )
        ticket_req = build_ticket_request(record, _VALID_TICKET_CONFIG)
        self.assertEqual(ticket_req.project_key, "SEC")
        self.assertEqual(ticket_req.issue_type, "Incident")

    def test_web01_ai_assessment_cannot_override_risk_policy(self) -> None:
        """Verify AI assessment cannot directly set the risk score or disposition."""
        record = build_modsecurity_incident_record(
            evidence=_VALID_MODSECURITY_EVIDENCE,
            threat_intel_status="SKIPPED_INELIGIBLE",
            threat_intel_skip_reason="ineligible_scope:private",
        )
        self.assertEqual(record.risk_score, 80)
        self.assertEqual(record.risk_level, "HIGH")

    # =========================================================================
    # 9. Human Approval Semantics (Section 11)
    # =========================================================================

    def test_web01_escalation_recommendation_does_not_equal_approval(self) -> None:
        """Verify escalation_recommended=True does not constitute human approval."""
        record = build_modsecurity_incident_record(
            evidence=_VALID_MODSECURITY_EVIDENCE,
            threat_intel_status="SKIPPED_INELIGIBLE",
            threat_intel_skip_reason="ineligible_scope:private",
        )
        self.assertEqual(record.approval_status, IncidentApprovalStatus.NOT_REQUIRED.value)
        self.assertNotEqual(record.approval_status, IncidentApprovalStatus.APPROVED.value)

    def test_web01_recommended_isolation_does_not_execute_isolation(self) -> None:
        """Verify recommendation text mentioning isolation does not execute response."""
        record = build_modsecurity_incident_record(
            evidence=_VALID_MODSECURITY_EVIDENCE,
            threat_intel_status="SKIPPED_INELIGIBLE",
            threat_intel_skip_reason="ineligible_scope:private",
        )
        self.assertEqual(record.simulation_status, SimulationStatus.NOT_EXECUTED.value)

    # =========================================================================
    # 10. Sanitization Boundary (Section 12)
    # =========================================================================

    def test_web01_incident_record_contains_no_raw_telemetry(self) -> None:
        """Verify serialized IncidentRecord contains no raw ModSecurity transaction markers or _raw."""
        record = build_modsecurity_incident_record(
            evidence=_VALID_MODSECURITY_EVIDENCE,
            threat_intel_status="SKIPPED_INELIGIBLE",
            threat_intel_skip_reason="ineligible_scope:private",
        )
        record_json = json.dumps(record.to_dict())
        self.assertNotIn("_raw", record_json)
        self.assertNotIn("--ar1Z9uxU", record_json)

    def test_web01_ticket_contains_no_raw_telemetry(self) -> None:
        """Verify ticket description contains no raw Splunk envelope or ModSecurity raw text."""
        record = build_modsecurity_incident_record(
            evidence=_VALID_MODSECURITY_EVIDENCE,
            threat_intel_status="SKIPPED_INELIGIBLE",
            threat_intel_skip_reason="ineligible_scope:private",
        )
        ticket_req = build_ticket_request(record, _VALID_TICKET_CONFIG)
        self.assertNotIn("_raw", ticket_req.description)
        self.assertNotIn("--ar1Z9uxU", ticket_req.description)

    def test_web01_ticket_contains_no_provider_secrets(self) -> None:
        """Verify ticket description contains zero API keys, tokens, or authorization headers."""
        record = build_modsecurity_incident_record(
            evidence=_VALID_MODSECURITY_EVIDENCE,
            threat_intel_status="SKIPPED_INELIGIBLE",
            threat_intel_skip_reason="ineligible_scope:private",
        )
        ticket_req = build_ticket_request(record, _VALID_TICKET_CONFIG)
        self.assertNotIn("Bearer", ticket_req.description)
        self.assertNotIn("api_key", ticket_req.description)
        self.assertNotIn("OPENAI_API_KEY", ticket_req.description)
        self.assertNotIn("VIRUSTOTAL_API_KEY", ticket_req.description)

    # =========================================================================
    # 11. Audit Expectations (Section 13)
    # =========================================================================

    def test_web01_offline_incident_workflow_preserves_existing_audit_log(self) -> None:
        """Verify complete workflow run preserves and appends to the attached AuditLog."""
        mock_splunk = MagicMock(spec=SplunkSearchClient)
        mock_splunk.search_modsecurity_sqli.return_value = [_RAW_MODSEC_PRIVATE_TELEMETRY]
        router = ToolRouter(splunk_client=mock_splunk)

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

        audit_log = AuditLog()
        orchestrator = InvestigationOrchestrator(
            model=model,
            tool_router=router,
            audit_log=audit_log,
        )

        result = self._run_workflow(
            request=_VALID_WEB01_REQUEST,
            orchestrator=orchestrator,
            ticket_config=_VALID_TICKET_CONFIG,
            ticket_client=FakeTicketClient(),
        )

        events = result.audit_log.events()
        event_types = [e.event_type for e in events]
        self.assertIn(AuditEventType.TOOL_REQUESTED, event_types)
        self.assertIn(AuditEventType.TOOL_COMPLETED, event_types)
        self.assertIn(AuditEventType.FINAL_RESULT_ACCEPTED, event_types)

    # =========================================================================
    # 12. Failure Behavior (Section 14)
    # =========================================================================

    def test_web01_workflow_rejects_missing_evidence(self) -> None:
        """Verify workflow fails closed when search returns zero ModSecurity events."""
        mock_splunk = MagicMock(spec=SplunkSearchClient)
        mock_splunk.search_modsecurity_sqli.return_value = []
        router = ToolRouter(splunk_client=mock_splunk)

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

        orchestrator = InvestigationOrchestrator(model=model, tool_router=router)
        with self.assertRaises((OrchestratorError, IncidentRecordError, TicketClientError, TicketSchemaError)):
            self._run_workflow(
                request=_VALID_WEB01_REQUEST,
                orchestrator=orchestrator,
                ticket_config=_VALID_TICKET_CONFIG,
            )

    def test_web01_workflow_rejects_invalid_assessment(self) -> None:
        """Verify workflow fails closed when model returns an invalid assessment type."""
        mock_splunk = MagicMock(spec=SplunkSearchClient)
        mock_splunk.search_modsecurity_sqli.return_value = [_RAW_MODSEC_PRIVATE_TELEMETRY]
        router = ToolRouter(splunk_client=mock_splunk)

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
                final_result=InvestigationResult(
                    summary="DC01 investigation result",
                    observations=["Event 1"],
                    decoded_command=None,
                    mitre_techniques=["T1059.001"],
                    suspicious_indicators=["test"],
                    recommended_next_step="close",
                    confidence_level="high",
                    evidence_refs=["ref1"],
                ),
            ),
        ])

        orchestrator = InvestigationOrchestrator(model=model, tool_router=router)
        with self.assertRaises((OrchestratorError, IncidentRecordError, TicketClientError, TicketSchemaError)):
            self._run_workflow(
                request=_VALID_WEB01_REQUEST,
                orchestrator=orchestrator,
                ticket_config=_VALID_TICKET_CONFIG,
            )

    def test_web01_workflow_rejects_inconsistent_ti_state(self) -> None:
        """Verify workflow rejects contradictory TI state fail-closed."""
        with self.assertRaises(IncidentRecordError):
            build_modsecurity_incident_record(
                evidence=_VALID_MODSECURITY_EVIDENCE,
                threat_intel_status="ENRICHED",
                threat_intel_observation=None,  # Contradictory: ENRICHED without observation
            )

    def test_web01_workflow_does_not_create_ticket_on_invalid_incident(self) -> None:
        """Verify ticketing client is never invoked if investigation fails closed."""
        mock_splunk = MagicMock(spec=SplunkSearchClient)
        mock_splunk.search_modsecurity_sqli.return_value = []
        router = ToolRouter(splunk_client=mock_splunk)

        model = ScriptedModel([
            ModelDecision(
                decision_type=DecisionType.TOOL_REQUEST,
                tool_request=ToolRequest(
                    tool_name="bounded_splunk_search",
                    arguments={"query_type": "modsecurity_sqli_matches", "host": "web01"},
                ),
            ),
        ])

        orchestrator = InvestigationOrchestrator(model=model, tool_router=router)
        mock_client = MagicMock(spec=TicketClient)

        with self.assertRaises((OrchestratorError, IncidentRecordError, TicketClientError, TicketSchemaError)):
            self._run_workflow(
                request=_VALID_WEB01_REQUEST,
                orchestrator=orchestrator,
                ticket_config=_VALID_TICKET_CONFIG,
                ticket_client=mock_client,
            )

        self.assertEqual(mock_client.create_ticket.call_count, 0)

    # =========================================================================
    # 13. State Isolation & Cross-Run Regression Tests
    # =========================================================================

    def test_web01_failed_second_run_cannot_reuse_prior_evidence_or_ti_state(self) -> None:
        """Verify a second failed investigation on same orchestrator instance never reuses run 1 evidence or TI."""
        mock_splunk = MagicMock(spec=SplunkSearchClient)
        mock_splunk.search_modsecurity_sqli.return_value = [_RAW_MODSEC_PRIVATE_TELEMETRY]
        router = ToolRouter(splunk_client=mock_splunk)

        # Run 1: Succeeds
        model_run1 = ScriptedModel([
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

        orchestrator = InvestigationOrchestrator(model=model_run1, tool_router=router)
        result1 = self._run_workflow(
            request=_VALID_WEB01_REQUEST,
            orchestrator=orchestrator,
            ticket_config=_VALID_TICKET_CONFIG,
            ticket_client=FakeTicketClient(),
        )
        self.assertIsNotNone(result1)
        self.assertIsNotNone(orchestrator.last_web01_evidence)
        self.assertEqual(orchestrator.last_web01_ti_status, "SKIPPED_INELIGIBLE")

        # Run 2: Model fails immediately before any tool call
        model_run2 = ScriptedModel([])
        orchestrator._model = model_run2

        with self.assertRaises(OrchestratorError):
            self._run_workflow(
                request=_VALID_WEB01_REQUEST,
                orchestrator=orchestrator,
                ticket_config=_VALID_TICKET_CONFIG,
                ticket_client=FakeTicketClient(),
            )

        # Invariant: orchestrator state must be completely cleared, not holding run 1 values
        self.assertIsNone(orchestrator.last_web01_evidence)
        self.assertIsNone(orchestrator.last_web01_ti_status)
        self.assertIsNone(orchestrator.last_web01_ti_skip_reason)
        self.assertIsNone(orchestrator.last_web01_ti_observation)

    def test_web01_dc01_subsequent_run_clears_web01_retained_state(self) -> None:
        """Verify a DC01 investigation running on the same orchestrator clears all retained WEB01 state."""
        mock_splunk = MagicMock(spec=SplunkSearchClient)
        mock_splunk.search_modsecurity_sqli.return_value = [_RAW_MODSEC_PRIVATE_TELEMETRY]
        router = ToolRouter(splunk_client=mock_splunk)

        # Run 1: WEB01 investigation succeeds
        model_web01 = ScriptedModel([
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

        orchestrator = InvestigationOrchestrator(model=model_web01, tool_router=router)
        self._run_workflow(
            request=_VALID_WEB01_REQUEST,
            orchestrator=orchestrator,
            ticket_config=_VALID_TICKET_CONFIG,
        )
        self.assertIsNotNone(orchestrator.last_web01_evidence)

        # Run 2: DC01 investigation runs on same orchestrator instance
        dc01_res = InvestigationResult(
            summary="DC01 investigation result",
            observations=["Event 1"],
            decoded_command=None,
            mitre_techniques=["T1059.001"],
            suspicious_indicators=["test"],
            recommended_next_step="close",
            confidence_level="high",
            evidence_refs=["ref1"],
        )
        model_dc01 = ScriptedModel([
            ModelDecision(decision_type=DecisionType.FINAL_RESULT, final_result=dc01_res),
        ])
        orchestrator._model = model_dc01

        from investigator.schemas import InvestigationInput
        dc01_input = InvestigationInput(
            incident_id="INC-DC01-999",
            timestamp="2026-10-04T08:00:00Z",
            host="DC01",
            user="SOCLAB\\Administrator",
            image="powershell.exe",
            command_line="powershell.exe",
            parent_image="cmd.exe",
            parent_command_line="cmd.exe",
            detection_name="PowerShell",
            detection_id="det-123",
        )
        dc01_outcome = orchestrator.investigate(dc01_input)
        self.assertIsInstance(dc01_outcome, InvestigationResult)

        # Invariant: WEB01 state must have been completely cleared by the DC01 run
        self.assertIsNone(orchestrator.last_web01_evidence)
        self.assertIsNone(orchestrator.last_web01_ti_status)
        self.assertIsNone(orchestrator.last_web01_ti_skip_reason)
        self.assertIsNone(orchestrator.last_web01_ti_observation)


if __name__ == "__main__":
    unittest.main()
