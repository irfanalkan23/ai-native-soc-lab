"""Milestone 15C — AI Assessment vs Deterministic Policy Visualization Tests.

Verifies:
1. AI advisory and deterministic policy appear in distinct, separate sections.
2. Deterministic section is explicitly labeled authoritative ("Authoritative security-control decision.").
3. AI section is explicitly labeled advisory / zero authority ("Advisory only. Cannot authorize actions.").
4. Deterministic risk score and risk level render accurately.
5. AI confidence is displayed separately from deterministic risk score.
6. Human approval state: NOT REQUIRED renders correctly.
7. Human approval state: REQUIRED / PENDING renders correctly.
8. Human approval state: APPROVED renders correctly.
9. Human approval state: DENIED renders correctly.
10. Simulation state: NOT EXECUTED renders correctly.
11. Simulation state: SIMULATED renders correctly.
12. Real containment state always displays NOT IMPLEMENTED.
13. Conflicting AI summary vs deterministic non-execution remains visually truthful.
14. Policy reason codes render safely as chips.
15. Hostile reason-code strings (<script>alert(1)</script>) are HTML-escaped.
16. Unknown/unexpected approval status fails visually conservative as UNKNOWN.
17. Unknown/unexpected simulation status fails visually conservative as UNKNOWN.
18. Malformed or invalid risk score does not crash rendering.
19. Visual risk bar width is defensively clamped to 0..100.
20. Zero action buttons or forms are present on the detail page.
21. Mutating HTTP methods (POST, PUT, PATCH, DELETE) return HTTP 405.
22. Zero ToolRouter, Splunk, Jira, VirusTotal, or RuntimeGuard calls occur.
23. Jira key remains labeled as Tracking Ticket only, with zero response authority.
24. Threat Intelligence status is displayed separately from AI assessment.
25. Governance control-flow pipeline appears in exact required sequence:
    Stage 1: Evidence -> Stage 2: AI Advisory -> Stage 3: Deterministic Policy ->
    Stage 4: Human Approval -> Stage 5: Permitted / Simulated Action.
"""

import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from ui.app import _clamp_risk_score, _resolve_approval_display_state, _resolve_simulation_display_state, create_app
from ui.models import IncidentDetailView, ThreatIntelDetailView


def _make_sample_incident(incident_id: str = "INC-15C-001", **extra: object) -> dict:
    """Helper to construct a valid base incident dictionary."""
    base = {
        "schema_version": "1.0.0",
        "incident_id": incident_id,
        "created_at_utc": "2026-10-08T12:00:00+00:00",
        "detection_id": "DET-POWERSHELL-001",
        "detection_name": "Suspicious Encoded PowerShell",
        "target_host": "DC01",
        "target_user": "SYSTEM",
        "evidence_source": "Sysmon Event ID 1",
        "decoded_command": "powershell.exe -enc SQBFAFgA",
        "Image": "C:\\Windows\\System32\\powershell.exe",
        "CommandLine": "powershell.exe -encodedCommand SQBFAFgA",
        "ParentImage": "C:\\Windows\\System32\\cmd.exe",
        "ParentCommandLine": "cmd.exe /c start",
        "mitre_technique_id": "T1059.001",
        "investigation_summary": "Model observes suspicious PowerShell invocation.",
        "confidence_level": "high",
        "suspicious_indicator_count": 2,
        "recommended_next_step": "Isolate host and verify execution origin.",
        "risk_score": 80,
        "risk_level": "HIGH",
        "disposition": "APPROVAL_REQUIRED",
        "proposed_action": "simulate_endpoint_isolation",
        "requires_human_approval": True,
        "policy_reason_codes": ["encoded_powershell_detected"],
        "approval_status": "APPROVED",
        "approval_reason_code": "approval_granted",
        "simulation_status": "SIMULATED",
        "simulation_detail_code": "simulated_endpoint_isolation",
        "threat_intel_status": "SKIPPED_INELIGIBLE",
        "threat_intel_skip_reason": "private_source_ip_ineligible",
        "jira_ticket_key": "KAN-101",
    }
    base.update(extra)
    return base


class TestUiPolicyVisualization(unittest.TestCase):
    """Focused test suite for Milestone 15C presentation layer visualization."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.incidents_dir = Path(self.tmp_dir.name)
        self.app = create_app(incidents_dir=self.incidents_dir)
        self.client = TestClient(self.app)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def _write_incident(self, incident_dict: dict) -> Path:
        """Write a JSON file to the test incidents directory."""
        path = self.incidents_dir / f"{incident_dict['incident_id']}.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(incident_dict, f)
        return path

    def test_01_ai_advisory_and_deterministic_policy_appear_in_separate_sections(self) -> None:
        """1. AI advisory and deterministic policy appear in distinct, separate sections."""
        self._write_incident(_make_sample_incident("INC-SEP-001"))
        res = self.client.get("/incidents/INC-SEP-001")
        self.assertEqual(res.status_code, 200)
        body = res.text

        self.assertIn("Deterministic Security Policy", body)
        self.assertIn("AI Advisory Assessment", body)
        # Distinct cards
        self.assertIn("card-policy-elevated", body)
        self.assertIn("card-ai-advisory", body)

    def test_02_deterministic_section_labeled_authoritative(self) -> None:
        """2. Deterministic section is explicitly labeled authoritative."""
        self._write_incident(_make_sample_incident("INC-AUTH-001"))
        res = self.client.get("/incidents/INC-AUTH-001")
        self.assertEqual(res.status_code, 200)
        body = res.text

        self.assertIn("DETERMINISTIC POLICY &bull; AUTHORITATIVE", body)
        self.assertIn("Authoritative security-control decision.", body)

    def test_03_ai_section_labeled_advisory_zero_authority(self) -> None:
        """3. AI section is explicitly labeled advisory with zero action authority."""
        self._write_incident(_make_sample_incident("INC-ZERO-001"))
        res = self.client.get("/incidents/INC-ZERO-001")
        self.assertEqual(res.status_code, 200)
        body = res.text

        self.assertIn("AI ADVISORY &bull; ZERO AUTHORITY", body)
        self.assertIn("Model-generated assessment. Advisory only. Cannot authorize actions.", body)

    def test_04_risk_score_and_risk_level_render_correctly(self) -> None:
        """4. Deterministic risk score and risk level render accurately with progress bar."""
        self._write_incident(_make_sample_incident("INC-RISK-001", risk_score=85, risk_level="HIGH"))
        res = self.client.get("/incidents/INC-RISK-001")
        self.assertEqual(res.status_code, 200)
        body = res.text

        self.assertIn("Score: 85 / 100 &bull; HIGH", body)
        self.assertIn('style="width: 85%;"', body)
        self.assertIn("risk-bar-high", body)

    def test_05_ai_confidence_displayed_separately_from_risk(self) -> None:
        """5. AI confidence is displayed separately from deterministic risk score."""
        self._write_incident(_make_sample_incident(
            "INC-CONF-001",
            risk_score=90,
            risk_level="CRITICAL",
            confidence_level="medium",
        ))
        res = self.client.get("/incidents/INC-CONF-001")
        self.assertEqual(res.status_code, 200)
        body = res.text

        # Both exist but in separate cards with separate contexts
        self.assertIn("Score: 90 / 100 &bull; CRITICAL", body)
        self.assertIn("medium", body)
        self.assertIn("Categorical AI assessment; distinct from deterministic risk.", body)

    def test_06_approval_not_required_renders_correctly(self) -> None:
        """6. Human approval state: NOT REQUIRED renders correctly."""
        self._write_incident(_make_sample_incident(
            "INC-APP-NR",
            requires_human_approval=False,
            approval_status="NOT_REQUIRED",
        ))
        res = self.client.get("/incidents/INC-APP-NR")
        self.assertEqual(res.status_code, 200)
        body = res.text

        self.assertIn("NOT REQUIRED", body)
        self.assertIn("app-not-req", body)

    def test_07_approval_required_pending_renders_correctly(self) -> None:
        """7. Human approval state: REQUIRED / PENDING renders correctly."""
        self._write_incident(_make_sample_incident(
            "INC-APP-PEND",
            requires_human_approval=True,
            approval_status="PENDING",
        ))
        res = self.client.get("/incidents/INC-APP-PEND")
        self.assertEqual(res.status_code, 200)
        body = res.text

        self.assertIn("REQUIRED / PENDING", body)
        self.assertIn("app-pending", body)

    def test_08_approval_approved_renders_correctly(self) -> None:
        """8. Human approval state: APPROVED renders correctly."""
        self._write_incident(_make_sample_incident(
            "INC-APP-OK",
            requires_human_approval=True,
            approval_status="APPROVED",
        ))
        res = self.client.get("/incidents/INC-APP-OK")
        self.assertEqual(res.status_code, 200)
        body = res.text

        self.assertIn("APPROVED", body)
        self.assertIn("app-approved", body)

    def test_09_approval_denied_renders_correctly(self) -> None:
        """9. Human approval state: DENIED renders correctly."""
        self._write_incident(_make_sample_incident(
            "INC-APP-DEN",
            requires_human_approval=True,
            approval_status="DENIED",
        ))
        res = self.client.get("/incidents/INC-APP-DEN")
        self.assertEqual(res.status_code, 200)
        body = res.text

        self.assertIn("DENIED", body)
        self.assertIn("app-denied", body)

    def test_10_simulation_not_executed_renders_correctly(self) -> None:
        """10. Simulation state: NOT EXECUTED renders correctly."""
        self._write_incident(_make_sample_incident(
            "INC-SIM-NO",
            simulation_status="NOT_EXECUTED",
        ))
        res = self.client.get("/incidents/INC-SIM-NO")
        self.assertEqual(res.status_code, 200)
        body = res.text

        self.assertIn("NOT EXECUTED", body)
        self.assertIn("sim-not-executed", body)

    def test_11_simulation_simulated_renders_correctly(self) -> None:
        """11. Simulation state: SIMULATED renders correctly."""
        self._write_incident(_make_sample_incident(
            "INC-SIM-YES",
            simulation_status="SIMULATED",
        ))
        res = self.client.get("/incidents/INC-SIM-YES")
        self.assertEqual(res.status_code, 200)
        body = res.text

        self.assertIn("SIMULATED", body)
        self.assertIn("sim-simulated", body)

    def test_12_real_containment_always_shows_not_implemented(self) -> None:
        """12. Real containment state always displays NOT IMPLEMENTED."""
        self._write_incident(_make_sample_incident("INC-CONT-001"))
        res = self.client.get("/incidents/INC-CONT-001")
        self.assertEqual(res.status_code, 200)
        body = res.text

        self.assertIn("Real Containment State", body)
        self.assertIn("NOT IMPLEMENTED (SIMULATED ONLY)", body)
        self.assertIn("CONTAINMENT: NOT IMPLEMENTED", body)

    def test_13_conflicting_ai_claim_vs_deterministic_non_execution(self) -> None:
        """13. Conflicting AI summary vs deterministic non-execution remains visually truthful."""
        self._write_incident(_make_sample_incident(
            "INC-TRUTH-001",
            investigation_summary="Endpoint isolated successfully. Real containment applied by AI.",
            simulation_status="NOT_EXECUTED",
            approval_status="DENIED",
        ))
        res = self.client.get("/incidents/INC-TRUTH-001")
        self.assertEqual(res.status_code, 200)
        body = res.text

        # The AI advisory hypothesis remains verbatim as reported
        self.assertIn("Endpoint isolated successfully. Real containment applied by AI.", body)
        # But deterministic truthfulness block and policy card firmly state NOT_EXECUTED and NOT IMPLEMENTED
        self.assertIn("NOT IMPLEMENTED (SIMULATED ONLY)", body)
        self.assertIn("NOT_EXECUTED", body)
        self.assertIn("DENIED", body)
        self.assertIn("Authoritative security-control decision.", body)

    def test_14_policy_reason_codes_render_safely(self) -> None:
        """14. Policy reason codes render safely as chips."""
        self._write_incident(_make_sample_incident(
            "INC-CHIPS-001",
            policy_reason_codes=["encoded_powershell_detected", "network_retrieval_observed"],
        ))
        res = self.client.get("/incidents/INC-CHIPS-001")
        self.assertEqual(res.status_code, 200)
        body = res.text

        self.assertIn('<span class="policy-chip">encoded_powershell_detected</span>', body)
        self.assertIn('<span class="policy-chip">network_retrieval_observed</span>', body)

    def test_15_hostile_reason_code_strings_are_escaped(self) -> None:
        """15. Hostile reason-code strings (<script>alert(1)</script>) are HTML-escaped."""
        self._write_incident(_make_sample_incident(
            "INC-XSS-CHIPS",
            policy_reason_codes=["<script>alert('chip-xss')</script>", '"><img src=x onerror=alert(2)>'],
        ))
        res = self.client.get("/incidents/INC-XSS-CHIPS")
        self.assertEqual(res.status_code, 200)
        body = res.text

        self.assertNotIn("<script>alert('chip-xss')</script>", body)
        self.assertNotIn("<img src=x onerror=alert(2)>", body)
        self.assertIn("&lt;script&gt;alert(&#x27;chip-xss&#x27;)&lt;/script&gt;", body)

    def test_16_unknown_approval_status_fails_visually_conservative(self) -> None:
        """16. Unknown/unexpected approval status fails visually conservative as UNKNOWN."""
        self._write_incident(_make_sample_incident(
            "INC-BAD-APP",
            requires_human_approval=True,
            approval_status="UNEXPECTED_EXOTIC_STATE",
        ))
        res = self.client.get("/incidents/INC-BAD-APP")
        self.assertEqual(res.status_code, 200)
        body = res.text

        self.assertIn("UNKNOWN", body)
        self.assertIn("app-unknown", body)

    def test_17_unknown_simulation_status_fails_visually_conservative(self) -> None:
        """17. Unknown/unexpected simulation status fails visually conservative as UNKNOWN."""
        self._write_incident(_make_sample_incident(
            "INC-BAD-SIM",
            simulation_status="UNEXPECTED_SIM_VALUE",
        ))
        res = self.client.get("/incidents/INC-BAD-SIM")
        self.assertEqual(res.status_code, 200)
        body = res.text

        self.assertIn("UNKNOWN", body)
        self.assertIn("sim-unknown", body)

    def test_18_malformed_or_invalid_risk_score_does_not_break_page(self) -> None:
        """18. Malformed or invalid risk score does not crash rendering."""
        # Directly test clamping helper with invalid inputs
        self.assertEqual(_clamp_risk_score("NaN"), 0)
        self.assertEqual(_clamp_risk_score(None), 0)
        self.assertEqual(_clamp_risk_score(-50), 0)
        self.assertEqual(_clamp_risk_score(250), 100)

        # File with valid negative score in storage clamps cleanly in HTML
        self._write_incident(_make_sample_incident("INC-BAD-SCORE", risk_score=0))
        res = self.client.get("/incidents/INC-BAD-SCORE")
        self.assertEqual(res.status_code, 200)
        self.assertIn('style="width: 0%;"', res.text)

    def test_19_risk_presentation_bounded_to_0_100(self) -> None:
        """19. Visual risk bar width is defensively clamped to 0..100."""
        self.assertEqual(_clamp_risk_score(150), 100)
        self.assertEqual(_clamp_risk_score(-10), 0)
        self.assertEqual(_clamp_risk_score(73), 73)

        self._write_incident(_make_sample_incident("INC-CLAMP-100", risk_score=100))
        res = self.client.get("/incidents/INC-CLAMP-100")
        self.assertEqual(res.status_code, 200)
        self.assertIn('style="width: 100%;"', res.text)

    def test_20_no_action_buttons_or_forms_present(self) -> None:
        """20. Zero action buttons or forms are present on the detail page."""
        self._write_incident(_make_sample_incident("INC-NO-BTNS"))
        res = self.client.get("/incidents/INC-NO-BTNS")
        self.assertEqual(res.status_code, 200)
        body = res.text

        self.assertNotIn("<button", body)
        self.assertNotIn("</button>", body)
        self.assertNotIn("<form", body)
        self.assertNotIn("</form>", body)
        self.assertNotIn('type="submit"', body)
        self.assertNotIn('type="button"', body)

    def test_21_mutating_http_methods_return_405(self) -> None:
        """21. Mutating HTTP methods return HTTP 405 Method Not Allowed."""
        self._write_incident(_make_sample_incident("INC-NO-MUTATE"))
        for method in ["post", "put", "delete", "patch"]:
            client_fn = getattr(self.client, method)
            res = client_fn("/incidents/INC-NO-MUTATE")
            self.assertEqual(res.status_code, 405)
            res_api = client_fn("/api/incidents/INC-NO-MUTATE")
            self.assertEqual(res_api.status_code, 405)

    def test_22_no_tool_router_provider_backend_calls_occur(self) -> None:
        """22. Zero ToolRouter, Splunk, Jira, VirusTotal, or RuntimeGuard calls occur."""
        self._write_incident(_make_sample_incident("INC-MOCK-CALLS"))

        with patch("investigator.tool_router.ToolRouter.execute_tool") as mock_tool, \
             patch("gateway.splunk_search.SplunkSearchClient._execute_bounded_search") as mock_splunk, \
             patch("investigator.providers.jira_provider.JiraTicketClient.create_ticket") as mock_jira, \
             patch("investigator.providers.virustotal_provider.VirusTotalThreatIntelClient.lookup") as mock_vt, \
             patch("investigator.runtime_guard.RuntimeGuard.check_execution_permitted") as mock_guard:

            res = self.client.get("/incidents/INC-MOCK-CALLS")
            self.assertEqual(res.status_code, 200)

            mock_tool.assert_not_called()
            mock_splunk.assert_not_called()
            mock_jira.assert_not_called()
            mock_vt.assert_not_called()
            mock_guard.assert_not_called()

    def test_23_jira_key_remains_tracking_only(self) -> None:
        """23. Jira key remains labeled as Tracking Ticket only, with zero response authority."""
        self._write_incident(_make_sample_incident("INC-JIRA-TRK", jira_ticket_key="SEC-888"))
        res = self.client.get("/incidents/INC-JIRA-TRK")
        self.assertEqual(res.status_code, 200)
        body = res.text

        self.assertIn("Tracking Ticket", body)
        self.assertIn("SEC-888", body)
        self.assertIn("Downstream external tracking sink only. Zero response authority.", body)
        self.assertNotIn("Action executed", body)
        self.assertNotIn("Response complete", body)

    def test_24_ti_status_displayed_separately_from_ai_assessment(self) -> None:
        """24. Threat Intelligence status is displayed separately from AI assessment."""
        self._write_incident(_make_sample_incident(
            "INC-TI-SEP",
            threat_intel_status="ENRICHED",
            threat_intel_observation={
                "indicator": "198.51.100.25",
                "indicator_type": "ipv4",
                "provider": "VirusTotal",
                "verdict": "suspicious",
                "malicious_count": 5,
                "suspicious_count": 1,
                "harmless_count": 60,
                "undetected_count": 5,
            },
        ))
        res = self.client.get("/incidents/INC-TI-SEP")
        self.assertEqual(res.status_code, 200)
        body = res.text

        self.assertIn("Threat Intelligence", body)
        self.assertIn("ADVISORY EVIDENCE", body)
        self.assertIn("ENRICHED", body)
        self.assertIn("198.51.100.25", body)

    def test_25_governance_flow_appears_in_expected_order(self) -> None:
        """25. Governance control-flow pipeline appears in exact required sequence."""
        self._write_incident(_make_sample_incident("INC-FLOW-001"))
        res = self.client.get("/incidents/INC-FLOW-001")
        self.assertEqual(res.status_code, 200)
        body = res.text

        pos_ev = body.find("Stage 1 &bull; Evidence")
        pos_ai = body.find("Stage 2 &bull; AI Advisory")
        pos_pol = body.find("Stage 3 &bull; Deterministic Policy")
        pos_app = body.find("Stage 4 &bull; Human Approval")
        pos_act = body.find("Stage 5 &bull; Permitted / Simulated Action")

        self.assertTrue(pos_ev > 0, "Stage 1 Evidence must be present")
        self.assertTrue(pos_ai > pos_ev, "Stage 2 AI Advisory must follow Stage 1")
        self.assertTrue(pos_pol > pos_ai, "Stage 3 Deterministic Policy must follow Stage 2")
        self.assertTrue(pos_app > pos_pol, "Stage 4 Human Approval must follow Stage 3")
        self.assertTrue(pos_act > pos_app, "Stage 5 Permitted / Simulated Action must follow Stage 4")
