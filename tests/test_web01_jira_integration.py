"""Unit and security boundary tests for Milestone 12F: WEB01 Jira Ticket Integration.

TDD RED PHASE ONLY.

Proves that a WEB01 ModSecurity IncidentRecord can be converted into the existing
bounded Jira ticket workflow safely, deterministically, and without leaking raw
telemetry, provider payloads, or secrets.

Security & Architectural Guarantees:
1. Data Minimization & Privacy:
   - Structured, validated ModSecurity evidence only.
   - Zero raw ModSecurity audit log transaction text (_raw).
   - Zero raw provider JSON, API keys, tokens, or credentials.
2. Deterministic Threat Intel Representation:
   - SKIPPED_INELIGIBLE preserves the explicit reason ('ineligible_scope:private')
     without conflation with 'clean' or 'harmless'.
   - ENRICHED preserves normalized observation counters and verdict.
   - LOOKUP_FAILED preserves the execution failure reason and is never conflated with skipped.
3. Strict Governance & Bounded Execution:
   - Bounded project keys and issue types enforced.
   - Exact single-POST dispatch through mocked Jira transport; zero live network calls.
   - Human approval and simulation boundaries are preserved without autonomous containment.
"""

from __future__ import annotations

import json
import unittest
from unittest.mock import MagicMock, patch

from investigator.incident_record import (
    IncidentRecord,
    IncidentRecordError,
    build_modsecurity_incident_record,
)
from investigator.modsecurity import ModSecuritySqliEvidence
from investigator.modsecurity_enrichment import ModSecurityEnrichmentResult
from investigator.providers.jira_provider import (
    JiraApiConfig,
    JiraCredentials,
    JiraPayloadMapper,
    JiraResponseError,
    JiraTicketClient,
    JiraTransportError,
)
from investigator.threat_intel import (
    IndicatorScope,
    ThreatIntelObservation,
)
from investigator.ticketing import (
    ALLOWED_TICKET_LABELS,
    TicketClientError,
    TicketConfig,
    TicketConfigError,
    TicketPriority,
    TicketRequest,
    TicketResult,
    TicketSchemaError,
    build_ticket_request,
)


# ---------------------------------------------------------------------------
# Test Fixtures
# ---------------------------------------------------------------------------

LIVE_DERIVED_WEB01_EVIDENCE = ModSecuritySqliEvidence(
    host="web01",
    src_ip="192.168.1.100",
    rule_id=942100,
    rule_msg="SQL Injection Attack Detected via libinjection",
    severity="CRITICAL",
    anomaly_score=8,
    unique_id="ar1Z9uxU-NFJV-LskY52NwAAAEQ",
)

WEB01_INELIGIBLE_ENRICHMENT = ModSecurityEnrichmentResult(
    evidence=LIVE_DERIVED_WEB01_EVIDENCE,
    scope=IndicatorScope(
        indicator="192.168.1.100",
        scope="private",
        external_ti_eligible=False,
    ),
    enriched=False,
    observation=None,
    skip_reason="ineligible_scope:private",
)

CONTROLLED_PUBLIC_EVIDENCE = ModSecuritySqliEvidence(
    host="web01",
    src_ip="8.8.8.8",
    rule_id=942100,
    rule_msg="SQL Injection Attack Detected via libinjection",
    severity="CRITICAL",
    anomaly_score=8,
    unique_id="fixture-public-001",
)

SAMPLE_TI_OBSERVATION = ThreatIntelObservation(
    indicator="8.8.8.8",
    indicator_type="ip",
    provider="virustotal",
    verdict="CLEAN",
    malicious_count=0,
    suspicious_count=0,
    harmless_count=75,
    undetected_count=10,
    source_reference="vt-report-8888",
)

PUBLIC_ENRICHED_RESULT = ModSecurityEnrichmentResult(
    evidence=CONTROLLED_PUBLIC_EVIDENCE,
    scope=IndicatorScope(
        indicator="8.8.8.8",
        scope="public",
        external_ti_eligible=True,
    ),
    enriched=True,
    observation=SAMPLE_TI_OBSERVATION,
    skip_reason=None,
)

LIVE_WEB01_INCIDENT = build_modsecurity_incident_record(
    incident_id="INC-WEB01-001",
    evidence=LIVE_DERIVED_WEB01_EVIDENCE,
    enrichment_result=WEB01_INELIGIBLE_ENRICHMENT,
)

PUBLIC_ENRICHED_INCIDENT = build_modsecurity_incident_record(
    incident_id="INC-WEB01-PUB01",
    evidence=CONTROLLED_PUBLIC_EVIDENCE,
    enrichment_result=PUBLIC_ENRICHED_RESULT,
)

LOOKUP_FAILED_INCIDENT = build_modsecurity_incident_record(
    incident_id="INC-WEB01-FAIL01",
    evidence=CONTROLLED_PUBLIC_EVIDENCE,
    enrichment_failure_reason="VT provider transport failure",
)


class TestWeb01JiraIntegration(unittest.TestCase):
    """RED phase test suite for Milestone 12F: WEB01 Jira Ticket Integration."""

    def setUp(self) -> None:
        self.jira_config = JiraApiConfig(base_url="https://secops.atlassian.net")
        self.jira_creds = JiraCredentials(
            email="soc-bot@secops.atlassian.net",
            api_token="test-api-token-12345",
        )

    def _get_ticket_config(self) -> TicketConfig:
        """Construct ticket config with WEB01 labels after support is verified."""
        return TicketConfig(
            project_key="KAN",
            issue_type="Incident",
            allowed_labels=(
                "ai-native-soc",
                "approval-not-required",
                "action-not-executed",
                "web-attack",
            ),
        )

    def _require_web01_jira_support(self) -> None:
        """Assert RED phase failure if WEB01 Jira ticket integration is not yet implemented."""
        if "web-attack" not in ALLOWED_TICKET_LABELS:
            self.fail(
                "RED PHASE: WEB01 ModSecurity Jira ticket integration or label support is not yet implemented"
            )

    # -------------------------------------------------------------------------
    # 1. BASIC WEB01 TICKET REQUEST
    # -------------------------------------------------------------------------

    def test_build_ticket_request_accepts_web01_incident(self) -> None:
        """build_ticket_request accepts a WEB01 ModSecurity IncidentRecord and preserves core bounds."""
        self._require_web01_jira_support()

        ticket_req = build_ticket_request(LIVE_WEB01_INCIDENT, self._get_ticket_config())

        self.assertIsInstance(ticket_req, TicketRequest)
        self.assertEqual(ticket_req.project_key, "KAN")
        self.assertEqual(ticket_req.issue_type, "Incident")
        self.assertEqual(ticket_req.incident_id, "INC-WEB01-001")
        self.assertEqual(ticket_req.priority, TicketPriority.HIGH)

    def test_summary_clearly_identifies_web01_modsecurity_and_incident_id(self) -> None:
        """Summary clearly identifies host WEB01, ModSecurity/SQLi attack, and incident ID."""
        self._require_web01_jira_support()

        ticket_req = build_ticket_request(LIVE_WEB01_INCIDENT, self._get_ticket_config())

        summary_lower = ticket_req.summary.lower()
        self.assertIn("web01", summary_lower)
        self.assertIn("inc-web01-001", summary_lower)
        self.assertTrue(
            "modsecurity" in summary_lower or "sql" in summary_lower,
            f"Expected ModSecurity or SQL in summary, got: {ticket_req.summary!r}",
        )

    # -------------------------------------------------------------------------
    # 2. DESCRIPTION / BODY STRUCTURE
    # -------------------------------------------------------------------------

    def test_description_contains_structured_modsecurity_evidence(self) -> None:
        """Ticket description contains all 7 validated ModSecurity evidence fields."""
        self._require_web01_jira_support()

        ticket_req = build_ticket_request(LIVE_WEB01_INCIDENT, self._get_ticket_config())
        desc = ticket_req.description

        self.assertIn("INC-WEB01-001", desc)
        self.assertIn("web01", desc)
        self.assertIn("192.168.1.100", desc)
        self.assertIn("942100", desc)
        self.assertIn("SQL Injection Attack Detected via libinjection", desc)
        self.assertIn("CRITICAL", desc)
        self.assertIn("ar1Z9uxU-NFJV-LskY52NwAAAEQ", desc)
        self.assertIn("T1190", desc)

    def test_description_contains_skipped_threat_intel_state(self) -> None:
        """Description accurately records SKIPPED_INELIGIBLE state and explicit reason."""
        self._require_web01_jira_support()

        ticket_req = build_ticket_request(LIVE_WEB01_INCIDENT, self._get_ticket_config())
        desc = ticket_req.description

        self.assertIn("SKIPPED_INELIGIBLE", desc)
        self.assertIn("ineligible_scope:private", desc)
        # Invariant: Must not claim VirusTotal evaluated this private IP
        self.assertNotIn("Verdict: CLEAN", desc)
        self.assertNotIn("Verdict: harmless", desc)
        self.assertNotIn("Verdict: unknown", desc)

    # -------------------------------------------------------------------------
    # 3. SECURITY / DATA MINIMIZATION
    # -------------------------------------------------------------------------

    def test_ticket_request_excludes_raw_telemetry_and_secrets(self) -> None:
        """Neither summary nor description contains raw ModSecurity audit logs or API secrets."""
        self._require_web01_jira_support()

        ticket_req = build_ticket_request(LIVE_WEB01_INCIDENT, self._get_ticket_config())
        combined = f"{ticket_req.summary}\n{ticket_req.description}"

        self.assertNotIn("_raw", combined)
        self.assertNotIn("--ar1Z9uxU", combined)
        self.assertNotIn("HTTP/1.1 403 Forbidden", combined)
        self.assertNotIn("Stopwatch:", combined)
        self.assertNotIn("api_key", combined)
        self.assertNotIn("Authorization", combined)
        self.assertNotIn("Bearer", combined)
        self.assertNotIn("VIRUSTOTAL", combined)
        self.assertNotIn("token", combined.lower())

    # -------------------------------------------------------------------------
    # 4. THREAT INTEL STATE REPRESENTATIONS
    # -------------------------------------------------------------------------

    def test_enriched_ticket_description_preserves_normalized_observation(self) -> None:
        """Enriched public fixture ticket preserves normalized ThreatIntelObservation fields."""
        self._require_web01_jira_support()

        ticket_req = build_ticket_request(PUBLIC_ENRICHED_INCIDENT, self._get_ticket_config())
        desc = ticket_req.description

        self.assertIn("ENRICHED", desc)
        self.assertIn("8.8.8.8", desc)
        self.assertIn("CLEAN", desc)
        self.assertIn("75", desc)
        # Invariant: No raw provider payload or secret
        self.assertNotIn("api_key", desc)
        self.assertNotIn("attributes", desc)

    def test_lookup_failed_ticket_description_distinguishes_failure_from_skip(self) -> None:
        """Lookup failure ticket preserves explicit sanitized failure reason and avoids conflation with skip."""
        self._require_web01_jira_support()

        ticket_req = build_ticket_request(LOOKUP_FAILED_INCIDENT, self._get_ticket_config())
        desc = ticket_req.description

        self.assertIn("LOOKUP_FAILED", desc)
        self.assertIn("VT provider transport failure", desc)
        # Invariant: Must not imply source IP was ineligible
        self.assertNotIn("ineligible_scope", desc)

    # -------------------------------------------------------------------------
    # 5. DETERMINISTIC TICKET REQUEST TESTS
    # -------------------------------------------------------------------------

    def test_repeated_construction_is_strictly_deterministic(self) -> None:
        """Repeated TicketRequest construction yields bit-for-bit identical content."""
        self._require_web01_jira_support()

        req1 = build_ticket_request(LIVE_WEB01_INCIDENT, self._get_ticket_config())
        req2 = build_ticket_request(LIVE_WEB01_INCIDENT, self._get_ticket_config())

        self.assertEqual(req1, req2)
        self.assertEqual(req1.summary, req2.summary)
        self.assertEqual(req1.description, req2.description)
        self.assertEqual(req1.labels, req2.labels)
        self.assertEqual(req1.priority, req2.priority)

    def test_labels_include_web_attack_deterministically(self) -> None:
        """ModSecurity incident derives 'web-attack' label deterministically based on modsecurity_evidence."""
        self._require_web01_jira_support()

        ticket_req = build_ticket_request(LIVE_WEB01_INCIDENT, self._get_ticket_config())

        self.assertIn("ai-native-soc", ticket_req.labels)
        self.assertIn("web-attack", ticket_req.labels)
        self.assertNotIn("powershell", ticket_req.labels)
        self.assertNotIn("network-retrieval", ticket_req.labels)
        self.assertEqual(
            ticket_req.labels,
            ("action-not-executed", "ai-native-soc", "approval-not-required", "web-attack"),
        )

    def test_non_modsecurity_incident_with_t1190_does_not_receive_web_attack(self) -> None:
        """Legacy or non-ModSecurity incident with T1190 does NOT derive 'web-attack' without modsecurity_evidence."""
        self._require_web01_jira_support()

        legacy_t1190_incident = IncidentRecord(
            schema_version="1.0.0",
            incident_id="INC-LEGACY-001",
            created_at_utc="2026-09-18T20:00:00+00:00",
            detection_id="DET-LEGACY-001",
            detection_name="legacy unvalidated detection",
            target_host="web01",
            target_user="www-data",
            evidence_source="Manual Inspection",
            decoded_command=None,
            mitre_technique_id="T1190",
            investigation_summary="Legacy manual report with T1190 mapping.",
            confidence_level="medium",
            suspicious_indicator_count=0,
            recommended_next_step="Review manually.",
            risk_score=50,
            risk_level="MEDIUM",
            disposition="HUMAN_REVIEW",
            proposed_action="request_human_review",
            requires_human_approval=False,
            policy_reason_codes=(),
            approval_status="NOT_REQUIRED",
            approval_reason_code=None,
            simulation_status="NOT_EXECUTED",
            simulation_detail_code="simulation_not_required",
            modsecurity_evidence=None,
        )

        ticket_req = build_ticket_request(legacy_t1190_incident, self._get_ticket_config())

        self.assertIn("ai-native-soc", ticket_req.labels)
        self.assertNotIn("web-attack", ticket_req.labels)
        self.assertNotIn("powershell", ticket_req.labels)
        self.assertNotIn("network-retrieval", ticket_req.labels)
        self.assertEqual(
            ticket_req.labels,
            ("action-not-executed", "ai-native-soc", "approval-not-required"),
        )

    # -------------------------------------------------------------------------
    # 6. ADAPTER / MOCK EXECUTION TESTS
    # -------------------------------------------------------------------------

    @patch("http.client.HTTPSConnection")
    def test_jira_ticket_client_accepts_web01_ticket_request(
        self, mock_conn_cls: MagicMock
    ) -> None:
        """JiraTicketClient accepts a WEB01 TicketRequest and produces a normalized TicketResult."""
        self._require_web01_jira_support()

        mock_conn = MagicMock()
        mock_conn_cls.return_value = mock_conn

        mock_resp = MagicMock()
        mock_resp.status = 201
        mock_resp.read.return_value = json.dumps(
            {"id": "10099", "key": "KAN-0088"}
        ).encode("utf-8")
        mock_conn.getresponse.return_value = mock_resp

        client = JiraTicketClient(config=self.jira_config, credentials=self.jira_creds)
        ticket_req = build_ticket_request(LIVE_WEB01_INCIDENT, self._get_ticket_config())

        result = client.create_ticket(ticket_req)

        self.assertIsInstance(result, TicketResult)
        self.assertTrue(result.success)
        self.assertEqual(result.provider, "jira_cloud")
        self.assertEqual(result.ticket_key, "KAN-0088")
        self.assertEqual(result.detail_code, "ticket_created_jira")

    @patch("http.client.HTTPSConnection")
    def test_jira_adapter_invoked_exactly_once_with_exact_payload(
        self, mock_conn_cls: MagicMock
    ) -> None:
        """Exactly one HTTP POST occurs with exact bounded project key, issue type, and ADF."""
        self._require_web01_jira_support()

        mock_conn = MagicMock()
        mock_conn_cls.return_value = mock_conn

        mock_resp = MagicMock()
        mock_resp.status = 201
        mock_resp.read.return_value = json.dumps(
            {"id": "10099", "key": "KAN-0088"}
        ).encode("utf-8")
        mock_conn.getresponse.return_value = mock_resp

        client = JiraTicketClient(config=self.jira_config, credentials=self.jira_creds)
        ticket_req = build_ticket_request(LIVE_WEB01_INCIDENT, self._get_ticket_config())

        client.create_ticket(ticket_req)

        self.assertEqual(mock_conn.request.call_count, 1)
        args, kwargs = mock_conn.request.call_args
        self.assertEqual(args[0], "POST")
        self.assertEqual(args[1], "/rest/api/3/issue")

        sent_body = json.loads(kwargs["body"].decode("utf-8"))
        fields = sent_body["fields"]
        self.assertEqual(fields["project"]["key"], "KAN")
        self.assertEqual(fields["issuetype"]["name"], "Incident")
        self.assertEqual(fields["summary"], ticket_req.summary)
        self.assertIn("web-attack", fields["labels"])

        # ADF plain text node verification
        adf_text = fields["description"]["content"][0]["content"][0]["text"]
        self.assertEqual(adf_text, ticket_req.description)

    @patch("http.client.HTTPSConnection")
    def test_jira_adapter_failure_propagates_as_execution_failure(
        self, mock_conn_cls: MagicMock
    ) -> None:
        """Remote Jira HTTP 500 error raises JiraResponseError and never reports false success."""
        self._require_web01_jira_support()

        mock_conn = MagicMock()
        mock_conn_cls.return_value = mock_conn

        mock_resp = MagicMock()
        mock_resp.status = 500
        mock_resp.read.return_value = b'{"errorMessages":["Internal server error"]}'
        mock_conn.getresponse.return_value = mock_resp

        client = JiraTicketClient(config=self.jira_config, credentials=self.jira_creds)
        ticket_req = build_ticket_request(LIVE_WEB01_INCIDENT, self._get_ticket_config())

        with self.assertRaises(JiraResponseError):
            client.create_ticket(ticket_req)

    # -------------------------------------------------------------------------
    # 7. INVALID / FAIL-CLOSED TESTS
    # -------------------------------------------------------------------------

    def test_reject_none_incident_record(self) -> None:
        """Passing None as incident_record raises TicketSchemaError."""
        self._require_web01_jira_support()

        with self.assertRaises(TicketSchemaError):
            build_ticket_request(None, self._get_ticket_config())  # type: ignore[arg-type]

    def test_reject_wrong_incident_type(self) -> None:
        """Passing a dictionary or non-IncidentRecord raises TicketSchemaError."""
        self._require_web01_jira_support()

        with self.assertRaises(TicketSchemaError):
            build_ticket_request({"incident_id": "INC-001"}, self._get_ticket_config())  # type: ignore[arg-type]

    def test_reject_unauthorized_project_key(self) -> None:
        """Project keys not adhering to uppercase pattern are rejected by TicketConfig."""
        self._require_web01_jira_support()

        with self.assertRaises(TicketConfigError):
            TicketConfig(
                project_key="lowercase_proj",
                issue_type="Incident",
                allowed_labels=("ai-native-soc",),
            )

    def test_reject_unauthorized_issue_type(self) -> None:
        """Empty or whitespace issue types are rejected by TicketConfig."""
        self._require_web01_jira_support()

        with self.assertRaises(TicketConfigError):
            TicketConfig(
                project_key="KAN",
                issue_type="",
                allowed_labels=("ai-native-soc",),
            )

    def test_contradictory_ti_state_cannot_reach_ticket_generation(self) -> None:
        """Contradictory TI states in IncidentRecord fail closed and cannot generate tickets."""
        self._require_web01_jira_support()

        with self.assertRaises(IncidentRecordError):
            build_modsecurity_incident_record(
                incident_id="INC-WEB01-BAD",
                evidence=LIVE_DERIVED_WEB01_EVIDENCE,
                threat_intel_status="SKIPPED_INELIGIBLE",
                threat_intel_skip_reason="ineligible_scope:private",
                threat_intel_observation=SAMPLE_TI_OBSERVATION,  # Contradictory observation
            )

    def test_jira_payload_mapper_rejects_non_ticket_request(self) -> None:
        """JiraPayloadMapper.build_issue_payload rejects objects that are not TicketRequest."""
        self._require_web01_jira_support()

        with self.assertRaises(TicketClientError):
            JiraPayloadMapper.build_issue_payload({"not": "a_ticket_request"})  # type: ignore[arg-type]

    # -------------------------------------------------------------------------
    # 8. HUMAN-CONTROL BOUNDARY
    # -------------------------------------------------------------------------

    def test_human_control_boundary_preserved_in_web01_ticket(self) -> None:
        """Ticket payload strictly preserves human review and non-execution lifecycle state."""
        self._require_web01_jira_support()

        ticket_req = build_ticket_request(LIVE_WEB01_INCIDENT, self._get_ticket_config())

        self.assertIn("approval-not-required", ticket_req.labels)
        self.assertIn("action-not-executed", ticket_req.labels)
        self.assertNotIn("human-approved", ticket_req.labels)
        self.assertNotIn("simulated-containment", ticket_req.labels)

        desc = ticket_req.description
        self.assertIn("Approval Required: No", desc)
        self.assertIn("Simulation Status: NOT_EXECUTED", desc)
        # Invariant: No destructive or containment action implied
        self.assertNotIn("host isolated", desc.lower())
        self.assertNotIn("account disabled", desc.lower())
        self.assertNotIn("firewall blocked", desc.lower())


if __name__ == "__main__":
    unittest.main()
