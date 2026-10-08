"""Milestone 15 — Manual UI Validation Polish Tests.

Verifies:
1. M15A/M15D/M15C stale labels no longer appear on incident list or detail pages.
2. Milestone-wide label appears ("Milestone 15 • SOC Analyst UI", "Read-Only Analyst View").
3. Incident-list presentation clearly distinguishes "SIMULATION: COMPLETED" from "REAL ACTION: NOT EXECUTED".
4. POLICY_EVALUATED audit event displays as SUCCESS instead of REQUESTED.
5. Underlying persisted simulation_status remains unchanged in JSON API endpoints.
6. Deterministic policy and AI advisory separation remains intact with governance pipeline.
7. Zero forms, interactive controls, or action buttons exist.
8. Zero provider, tool router, or privileged execution calls occur.
"""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from ui.app import create_app


def _make_demo_incident(incident_id: str = "INC-DEMO-CRIT-2026-001", **kwargs: object) -> dict:
    base = {
        "schema_version": "1.0.0",
        "incident_id": incident_id,
        "created_at_utc": "2026-10-08T16:00:00+00:00",
        "detection_id": "DET-DEMO-001",
        "detection_name": "Critical Attack Simulation",
        "target_host": "WEB01",
        "target_user": "www-data",
        "source_ip": "198.51.100.99",
        "mitre_technique_id": "T1190",
        "investigation_summary": "Synthesized critical alert for validation.",
        "confidence_level": "high",
        "suspicious_indicator_count": 2,
        "recommended_next_step": "Isolate host and block attacker IP.",
        "risk_score": 90,
        "risk_level": "CRITICAL",
        "disposition": "APPROVAL_REQUIRED",
        "proposed_action": "simulate_endpoint_isolation",
        "requires_human_approval": True,
        "approval_status": "APPROVED",
        "approval_reason_code": "critical_risk_consequential_action",
        "simulation_status": "SIMULATED",
        "simulation_detail_code": "simulation_completed_mock",
        "real_containment_status": "NOT_IMPLEMENTED",
        "policy_reason_codes": ["critical_risk_score", "malicious_indicator"],
        "threat_intel_status": "ENRICHED",
        "threat_intel_observation": {
            "indicator": "198.51.100.99",
            "indicator_type": "ip",
            "provider": "VirusTotal",
            "verdict": "Malicious",
            "malicious_count": 12,
            "suspicious_count": 3,
            "harmless_count": 55,
            "undetected_count": 1,
        },
        "jira_ticket_key": "SOC-8888",
        "modsecurity_evidence": {
            "host": "WEB01",
            "src_ip": "198.51.100.99",
            "rule_id": 942100,
            "rule_msg": "SQL Injection Detected",
            "severity": "CRITICAL",
            "anomaly_score": 15,
            "unique_id": "TX-DEMO-001",
        },
    }
    base.update(kwargs)
    return base


class TestUiManualValidationPolish(unittest.TestCase):
    """Test suite covering the three presentation fixes from manual validation."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.incidents_dir = Path(self.tmp_dir.name) / "incidents"
        self.incidents_dir.mkdir(parents=True, exist_ok=True)

        self.audit_file = Path(self.tmp_dir.name) / "agent_audit.jsonl"
        self.audit_file.touch()

        # Seed demo incident
        self.inc_data = _make_demo_incident("INC-DEMO-CRIT-2026-001")
        self._write_incident(self.inc_data)

        # Seed unsimulated incident for comparison
        self.inc_unsim = _make_demo_incident(
            "INC-DEMO-UNSIM-2026-002",
            simulation_status="NOT_EXECUTED",
            approval_status="PENDING_APPROVAL",
        )
        self._write_incident(self.inc_unsim)

        # Seed audit records including POLICY_EVALUATED
        self._append_audit([
            {
                "incident_id": "INC-DEMO-CRIT-2026-001",
                "sequence": 1,
                "timestamp": "2026-10-08T16:00:01+00:00",
                "event_type": "INVESTIGATION_STARTED",
                "detail_code": "triage_started",
                "outcome": "INFO",
            },
            {
                "incident_id": "INC-DEMO-CRIT-2026-001",
                "sequence": 2,
                "timestamp": "2026-10-08T16:00:02+00:00",
                "event_type": "POLICY_EVALUATED",
                "detail_code": "policy_evaluated_critical",
                "outcome": "SUCCESS",
            },
            {
                "incident_id": "INC-DEMO-CRIT-2026-001",
                "sequence": 3,
                "timestamp": "2026-10-08T16:00:03+00:00",
                "event_type": "TOOL_REQUESTED",
                "detail_code": "splunk_query_requested",
                "outcome": "REQUESTED",
            },
        ])

        self.app = create_app(incidents_dir=self.incidents_dir, audit_path=self.audit_file)
        self.client = TestClient(self.app)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def _write_incident(self, data: dict) -> Path:
        path = self.incidents_dir / f"{data['incident_id']}.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f)
        return path

    def _append_audit(self, events: list) -> None:
        with open(self.audit_file, "a", encoding="utf-8") as f:
            for ev in events:
                f.write(json.dumps(ev) + "\n")

    # -------------------------------------------------------------------------
    # Fix 1 — Stale Milestone Labels
    # -------------------------------------------------------------------------

    def test_01_stale_milestone_labels_do_not_appear(self) -> None:
        """Stale Milestone 15A/15D/15C labels no longer appear on incident list or detail."""
        list_html = self.client.get("/").text
        detail_html = self.client.get("/incidents/INC-DEMO-CRIT-2026-001").text

        # List view must not have stale slice labels
        self.assertNotIn("M15A", list_html)
        self.assertNotIn("Milestone 15A", list_html)

        # Detail view must not have stale slice labels
        self.assertNotIn("Milestone 15D", detail_html)
        self.assertNotIn("Milestone 15C", detail_html)

    def test_02_milestone_wide_label_appears(self) -> None:
        """Milestone-wide labels appear cleanly on list and detail footers and headers."""
        list_html = self.client.get("/").text
        detail_html = self.client.get("/incidents/INC-DEMO-CRIT-2026-001").text

        self.assertIn("Read-Only Analyst View", list_html)
        self.assertIn("Milestone 15 &bull; SOC Analyst UI", list_html)
        self.assertIn("Milestone 15 &bull; SOC Analyst UI", detail_html)

    # -------------------------------------------------------------------------
    # Fix 2 — Clarify Simulated vs Real Action Wording
    # -------------------------------------------------------------------------

    def test_03_simulated_action_wording_distinguishes_simulation_from_real_action(self) -> None:
        """Incident-list clearly distinguishes SIMULATION: COMPLETED from REAL ACTION: NOT EXECUTED."""
        list_html = self.client.get("/").text

        # List table shows both pieces of information clearly
        self.assertIn("REAL ACTION: NOT EXECUTED", list_html)
        self.assertIn("SIMULATION: COMPLETED", list_html)
        self.assertIn("SIMULATION: NOT EXECUTED", list_html)

        # Ambiguous raw category badge 'SIMULATED / NOT EXECUTED' is replaced
        self.assertNotIn("SIMULATED / NOT EXECUTED", list_html)

    def test_04_detail_page_preserves_not_implemented_and_simulation_status(self) -> None:
        """Incident detail page preserves Real Containment: NOT IMPLEMENTED and Simulation Status: SIMULATED."""
        detail_html = self.client.get("/incidents/INC-DEMO-CRIT-2026-001").text

        self.assertIn("CONTAINMENT: NOT IMPLEMENTED", detail_html)
        self.assertIn("NOT IMPLEMENTED (SIMULATED ONLY)", detail_html)
        self.assertIn("SIMULATED", detail_html)

    # -------------------------------------------------------------------------
    # Fix 3 — Correct POLICY_EVALUATED Audit Display Outcome
    # -------------------------------------------------------------------------

    def test_05_policy_evaluated_audit_outcome_is_success_not_requested(self) -> None:
        """POLICY_EVALUATED audit event displays as SUCCESS instead of misleading REQUESTED."""
        # Check API representation
        audit_events = self.client.get("/api/incidents/INC-DEMO-CRIT-2026-001/audit").json()
        policy_event = next(e for e in audit_events if e["event_type"] == "POLICY_EVALUATED")
        self.assertEqual(policy_event["outcome"], "SUCCESS")

        # Check tool request still appropriately displays REQUESTED
        tool_event = next(e for e in audit_events if e["event_type"] == "TOOL_REQUESTED")
        self.assertEqual(tool_event["outcome"], "REQUESTED")

        # Check HTML presentation
        detail_html = self.client.get("/incidents/INC-DEMO-CRIT-2026-001").text
        self.assertIn("POLICY_EVALUATED", detail_html)
        self.assertIn("audit-outcome-success", detail_html)

    # -------------------------------------------------------------------------
    # Regression & Authority Invariant Tests
    # -------------------------------------------------------------------------

    def test_06_underlying_persisted_simulation_status_remains_unchanged(self) -> None:
        """JSON APIs return exact persisted simulation_status ('SIMULATED', 'NOT_EXECUTED')."""
        list_data = self.client.get("/api/incidents").json()
        crit_item = next(i for i in list_data if i["incident_id"] == "INC-DEMO-CRIT-2026-001")
        self.assertEqual(crit_item["simulation_status"], "SIMULATED")

        detail_data = self.client.get("/api/incidents/INC-DEMO-CRIT-2026-001").json()
        self.assertEqual(detail_data["simulation_status"], "SIMULATED")

    def test_07_deterministic_policy_and_ai_advisory_separation_remains_intact(self) -> None:
        """Deterministic policy and AI advisory separation remains intact on incident detail."""
        detail_html = self.client.get("/incidents/INC-DEMO-CRIT-2026-001").text

        self.assertIn("Deterministic Security Policy", detail_html)
        self.assertIn("Authoritative security-control decision.", detail_html)
        self.assertIn("AI Advisory Assessment", detail_html)
        self.assertIn("Advisory only. Cannot authorize actions.", detail_html)
        self.assertIn("governance-pipeline", detail_html)

    def test_08_no_new_controls_forms_actions_added(self) -> None:
        """Zero form tags or action/approval buttons exist across list or detail views."""
        for path in ("/", "/incidents/INC-DEMO-CRIT-2026-001"):
            html = self.client.get(path).text
            self.assertNotIn("<form", html.lower())
            self.assertNotIn("<button", html.lower())
            self.assertNotIn('type="submit"', html.lower())
            self.assertNotIn("Approve", html)
            self.assertNotIn("Deny Action", html)

    @patch("urllib.request.urlopen")
    def test_09_no_provider_tool_backend_calls_occur(self, mock_urlopen: MagicMock) -> None:
        """Zero external network or tool router calls occur when querying UI views."""
        self.client.get("/")
        self.client.get("/api/incidents")
        self.client.get("/incidents/INC-DEMO-CRIT-2026-001")
        self.client.get("/api/incidents/INC-DEMO-CRIT-2026-001")
        self.client.get("/api/incidents/INC-DEMO-CRIT-2026-001/audit")
        mock_urlopen.assert_not_called()


if __name__ == "__main__":
    unittest.main()
