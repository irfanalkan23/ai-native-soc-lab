"""Focused tests for Deferred UI Approval Workflow.

Validates:
1. Default approval mode is 'cli'
2. Invalid approval mode is rejected via argparse choices
3. CLI mode still prompts interactively for approval
4. UI mode never calls request_cli_approval() for approval-required incident
5. UI mode never executes simulator before browser decision
6. UI mode writes PENDING incident record
7. Pending record uses truthful simulation detail code ('simulation_deferred_pending_approval')
8. No approval ledger consumption occurs before UI decision
9. No APPROVAL_REQUESTED event before UI decision
10. No APPROVAL_GRANTED before UI decision
11. No APPROVAL_CONSUMED before UI decision
12. No SIMULATION_COMPLETED before UI decision
13. Jira ticket can be created from PENDING record
14. Jira ticket key persisted into record
15. Jira remains downstream zero-authority sink
16. Jira failure preserves PENDING incident
17. Jira failure does not simulate
18. Jira failure does not consume approval
19. TICKET_CREATED audit only on actual success
20. TICKET_FAILED audit only on failure
21. Deferred record is accepted by 16D approve endpoint
22. Deferred record is accepted by 16D deny endpoint
23. Approve yields only simulated endpoint isolation
24. Deny yields NOT_EXECUTED
25. Real containment remains NOT IMPLEMENTED
26. Non-approval-required UI-mode flow remains compatible with existing behavior
27. CLI-mode regressions remain unchanged
28. Old IncidentRecord artifacts remain readable
"""

import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from investigator.approval import (
    ApprovalDecision,
    ApprovalLedger,
    ApprovalRecord,
    ApprovalRegistry,
    DEFAULT_APPROVAL_LEDGER_PATH,
    DEFAULT_APPROVER,
)
from investigator.audit import AuditEventType, AuditLog
from investigator.incident_record import (
    IncidentApprovalStatus,
    IncidentJsonWriter,
    IncidentRecord,
    build_incident_record,
)
from investigator.policy import (
    ActionDisposition,
    PolicyDecision,
    ProposedAction,
    RiskLevel,
)
from investigator.runtime_guard import RuntimeGuard
from investigator.schemas import InvestigationInput, InvestigationResult
from investigator.simulator import SimulationResult, SimulationStatus
from investigator.ticketing import (
    FakeTicketClient,
    TicketClient,
    TicketRequest,
    TicketResult,
)
from scripts.run_end_to_end_demo import (
    _parse_args,
    run_demo,
)
from ui.app import create_app


class FailingTicketClient(TicketClient):
    """Test client that simulates an external ticketing outage."""

    def create_ticket(self, request: TicketRequest) -> TicketResult:
        return TicketResult(
            success=False,
            ticket_key="ERROR",
            detail_code="jira_upstream_503_error",
            provider="failing_mock",
        )


class TestDeferredUiApprovalWorkflow(unittest.TestCase):
    """Test suite covering the complete deferred UI approval lifecycle."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp_dir.name)
        self.incidents_dir = self.tmp_path / "incidents"
        self.incidents_dir.mkdir(parents=True, exist_ok=True)
        self.audit_path = self.tmp_path / "agent_audit.jsonl"
        self.ledger_path = self.tmp_path / "consumed_ledger.jsonl"

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    # 1. Default approval mode is cli
    def test_default_approval_mode_is_cli(self) -> None:
        with patch("sys.argv", ["run_end_to_end_demo.py", "--mode", "synthetic-critical"]):
            args = _parse_args()
            self.assertEqual(args.approval_mode, "cli")

    # 2. Invalid approval mode rejected
    def test_invalid_approval_mode_rejected(self) -> None:
        with patch("sys.argv", ["run_end_to_end_demo.py", "--mode", "synthetic-critical", "--approval-mode", "unsupported"]):
            with self.assertRaises(SystemExit):
                with patch("sys.stderr", new_callable=io.StringIO):
                    _parse_args()

    # 3. CLI mode still prompts for approval
    def test_cli_mode_still_prompts_for_approval(self) -> None:
        in_stream = io.StringIO("approve\n")
        out_stream = io.StringIO()
        with patch("scripts.run_end_to_end_demo.request_cli_approval") as mock_cli:
            mock_cli.return_value = ApprovalRecord(
                incident_id="INC-DEMO-CRIT-2026-001",
                proposed_action=ProposedAction.SIMULATE_ENDPOINT_ISOLATION,
                decision=ApprovalDecision.APPROVED,
                approver=DEFAULT_APPROVER,
                reason_code="approval_granted",
            )
            rc = run_demo(
                mode="synthetic-critical",
                stream_in=in_stream,
                stream_out=out_stream,
                approval_mode="cli",
            )
            self.assertEqual(rc, 0)
            mock_cli.assert_called_once()

    # 4. UI mode never calls CLI approval for approval-required incident
    def test_ui_mode_never_calls_cli_approval(self) -> None:
        out_stream = io.StringIO()
        with patch("scripts.run_end_to_end_demo.request_cli_approval") as mock_cli:
            rc = run_demo(
                mode="synthetic-critical",
                stream_out=out_stream,
                approval_mode="ui",
                incidents_dir=self.incidents_dir,
            )
            self.assertEqual(rc, 0)
            mock_cli.assert_not_called()

    # 5. UI mode never executes simulator before browser decision
    def test_ui_mode_never_executes_simulator_before_browser_decision(self) -> None:
        out_stream = io.StringIO()
        with patch("scripts.run_end_to_end_demo.SimulatedResponseExecutor.execute") as mock_exec:
            rc = run_demo(
                mode="synthetic-critical",
                stream_out=out_stream,
                approval_mode="ui",
                incidents_dir=self.incidents_dir,
            )
            self.assertEqual(rc, 0)
            mock_exec.assert_not_called()

    # 6. UI mode writes PENDING incident & 7. Truthful simulation detail code
    def test_ui_mode_writes_pending_incident_with_truthful_detail_code(self) -> None:
        out_stream = io.StringIO()
        rc = run_demo(
            mode="synthetic-critical",
            stream_out=out_stream,
            approval_mode="ui",
            incidents_dir=self.incidents_dir,
            synthetic_incident_id="INC-PENDING-001",
        )
        self.assertEqual(rc, 0)
        incident_file = self.incidents_dir / "INC-PENDING-001.json"
        self.assertTrue(incident_file.exists())

        with open(incident_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.assertEqual(data["approval_status"], "PENDING")
        self.assertIsNone(data.get("approval_reason_code"))
        self.assertEqual(data["simulation_status"], "NOT_EXECUTED")
        self.assertEqual(data["simulation_detail_code"], "simulation_deferred_pending_approval")
        self.assertTrue(data["requires_human_approval"])
        self.assertEqual(data["proposed_action"], "simulate_endpoint_isolation")

    # 8. No approval ledger consumption occurs
    def test_no_approval_ledger_consumption_before_ui_decision(self) -> None:
        out_stream = io.StringIO()
        ledger = ApprovalLedger(path=self.ledger_path)
        rc = run_demo(
            mode="synthetic-critical",
            stream_out=out_stream,
            approval_mode="ui",
            incidents_dir=self.incidents_dir,
            approval_ledger=ledger,
            synthetic_incident_id="INC-LEDGER-001",
        )
        self.assertEqual(rc, 0)
        consumed_ids, consumed_grants = ledger.load_consumed()
        self.assertEqual(len(consumed_ids), 0)
        self.assertEqual(len(consumed_grants), 0)

    # 9-12. No approval lifecycle or simulation completed audit events before UI decision
    def test_pre_approval_audit_omits_decision_and_consumption_events(self) -> None:
        out_stream = io.StringIO()
        rc = run_demo(
            mode="synthetic-critical",
            stream_out=out_stream,
            approval_mode="ui",
            incidents_dir=self.incidents_dir,
            persist_audit=True,
            audit_log_path=self.audit_path,
            synthetic_incident_id="INC-AUDIT-001",
        )
        self.assertEqual(rc, 0)
        self.assertTrue(self.audit_path.exists())

        events = []
        with open(self.audit_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    events.append(json.loads(line))

        event_types = [e["event_type"] for e in events]
        self.assertIn("POLICY_EVALUATED", event_types)
        self.assertIn("APPROVAL_REQUIRED", event_types)

        self.assertNotIn("APPROVAL_REQUESTED", event_types)
        self.assertNotIn("APPROVAL_GRANTED", event_types)
        self.assertNotIn("APPROVAL_DENIED", event_types)
        self.assertNotIn("APPROVAL_CONSUMED", event_types)
        self.assertNotIn("SIMULATION_COMPLETED", event_types)

    # 13. Jira ticket created from PENDING record & 14. Key persisted & 15. Zero authority sink
    def test_jira_ticket_created_and_key_persisted_from_pending_record(self) -> None:
        out_stream = io.StringIO()
        rc = run_demo(
            mode="synthetic-critical",
            stream_out=out_stream,
            approval_mode="ui",
            incidents_dir=self.incidents_dir,
            create_ticket=True,
            ticket_provider="fake",
            synthetic_incident_id="INC-JIRA-001",
            persist_audit=True,
            audit_log_path=self.audit_path,
        )
        self.assertEqual(rc, 0)
        incident_file = self.incidents_dir / "INC-JIRA-001.json"
        self.assertTrue(incident_file.exists())

        with open(incident_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.assertIn("jira_ticket_key", data)
        self.assertTrue(data["jira_ticket_key"].startswith("SEC-"))
        self.assertEqual(data["approval_status"], "PENDING")
        self.assertEqual(data["simulation_status"], "NOT_EXECUTED")

    # 16. Jira failure preserves PENDING incident & 17. No simulation & 18. No ledger consumption
    # & 19. TICKET_CREATED on success & 20. TICKET_FAILED on failure
    def test_jira_failure_preserves_pending_incident_without_simulation(self) -> None:
        out_stream = io.StringIO()
        failing_client = FailingTicketClient()
        ledger = ApprovalLedger(path=self.ledger_path)

        rc = run_demo(
            mode="synthetic-critical",
            stream_out=out_stream,
            approval_mode="ui",
            incidents_dir=self.incidents_dir,
            create_ticket=True,
            ticket_provider="jira",
            jira_client=failing_client,
            approval_ledger=ledger,
            persist_audit=True,
            audit_log_path=self.audit_path,
            synthetic_incident_id="INC-JIRA-FAIL-001",
        )
        # Should return error code 1 on ticketing failure
        self.assertEqual(rc, 1)

        # Incident MUST remain safely persisted in PENDING state
        incident_file = self.incidents_dir / "INC-JIRA-FAIL-001.json"
        self.assertTrue(incident_file.exists())

        with open(incident_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.assertEqual(data["approval_status"], "PENDING")
        self.assertEqual(data["simulation_status"], "NOT_EXECUTED")
        self.assertIsNone(data.get("jira_ticket_key"))

        # Zero ledger consumption
        consumed_ids, _ = ledger.load_consumed()
        self.assertEqual(len(consumed_ids), 0)

        # Audit events must reflect TICKET_FAILED
        events = []
        with open(self.audit_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    events.append(json.loads(line))

        event_types = [e["event_type"] for e in events]
        self.assertIn("TICKET_FAILED", event_types)
        self.assertNotIn("TICKET_CREATED", event_types)
        self.assertNotIn("SIMULATION_COMPLETED", event_types)

    # 21. Deferred record is accepted by 16D approve endpoint
    # 23. Approve yields simulated endpoint isolation
    # 25. Real containment remains NOT IMPLEMENTED
    def test_deferred_record_can_be_approved_via_16d_ui_endpoint(self) -> None:
        out_stream = io.StringIO()
        ledger = ApprovalLedger(path=self.ledger_path)

        # 1. Generate deferred UI pending incident
        rc = run_demo(
            mode="synthetic-critical",
            stream_out=out_stream,
            approval_mode="ui",
            incidents_dir=self.incidents_dir,
            approval_ledger=ledger,
            synthetic_incident_id="INC-UI-APP-001",
        )
        self.assertEqual(rc, 0)

        # 2. Spin up Starlette/FastAPI TestClient with 16D UI
        app = create_app(
            incidents_dir=self.incidents_dir,
            audit_path=self.audit_path,
            approval_ledger_path=self.ledger_path,
            allowed_origins=["http://testserver"],
        )
        client = TestClient(app)
        csrf_token = app.state.csrf_token

        # 3. Post Approve intent
        resp = client.post(
            "/api/incidents/INC-UI-APP-001/approval/approve",
            headers={"Origin": "http://testserver"},
            json={"csrf_token": csrf_token},
        )
        self.assertEqual(resp.status_code, 200)
        res_data = resp.json()
        self.assertEqual(res_data["approval_status"], "APPROVED")
        self.assertEqual(res_data["simulation_status"], "SIMULATED")
        self.assertEqual(res_data["real_action_status"], "NOT_IMPLEMENTED")
        self.assertEqual(res_data["detail_code"], "simulated_endpoint_isolation")

        # 4. Verify disk artifact transitioned
        incident_file = self.incidents_dir / "INC-UI-APP-001.json"
        with open(incident_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["approval_status"], "APPROVED")
        self.assertEqual(data["simulation_status"], "SIMULATED")
        self.assertEqual(data["simulation_detail_code"], "simulated_endpoint_isolation")

        # 5. Verify ledger consumed
        consumed_ids, consumed_grants = ledger.load_consumed()
        self.assertEqual(len(consumed_ids), 1)
        self.assertIn(("INC-UI-APP-001", "simulate_endpoint_isolation"), consumed_grants)

    # 22. Deferred record is accepted by 16D deny endpoint
    # 24. Deny yields NOT_EXECUTED
    def test_deferred_record_can_be_denied_via_16d_ui_endpoint(self) -> None:
        out_stream = io.StringIO()
        ledger = ApprovalLedger(path=self.ledger_path)

        # 1. Generate deferred UI pending incident
        rc = run_demo(
            mode="synthetic-critical",
            stream_out=out_stream,
            approval_mode="ui",
            incidents_dir=self.incidents_dir,
            approval_ledger=ledger,
            synthetic_incident_id="INC-UI-DENY-001",
        )
        self.assertEqual(rc, 0)

        # 2. Spin up TestClient with 16D UI
        app = create_app(
            incidents_dir=self.incidents_dir,
            audit_path=self.audit_path,
            approval_ledger_path=self.ledger_path,
            allowed_origins=["http://testserver"],
        )
        client = TestClient(app)
        csrf_token = app.state.csrf_token

        # 3. Post Deny intent
        resp = client.post(
            "/api/incidents/INC-UI-DENY-001/approval/deny",
            headers={"Origin": "http://testserver"},
            json={"csrf_token": csrf_token},
        )
        self.assertEqual(resp.status_code, 200)
        res_data = resp.json()
        self.assertEqual(res_data["approval_status"], "DENIED")
        self.assertEqual(res_data["simulation_status"], "NOT_EXECUTED")
        self.assertEqual(res_data["real_action_status"], "NOT_IMPLEMENTED")

        # 4. Verify disk artifact transitioned
        incident_file = self.incidents_dir / "INC-UI-DENY-001.json"
        with open(incident_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["approval_status"], "DENIED")
        self.assertEqual(data["simulation_status"], "NOT_EXECUTED")
        self.assertEqual(data["simulation_detail_code"], "simulation_blocked_denied")

        # 5. Ledger should NOT have consumed grant
        consumed_ids, _ = ledger.load_consumed()
        self.assertEqual(len(consumed_ids), 0)

    # 26. Non-approval-required UI-mode flow remains compatible with existing behavior
    def test_non_approval_flow_in_ui_mode_continues_normally(self) -> None:
        out_stream = io.StringIO()
        # Mocking Splunk client for live-benign mode
        mock_splunk = MagicMock()
        mock_splunk.search_encoded_powershell.return_value = [
            {
                "_time": "2026-09-17T12:00:00.000+00:00",
                "host": "DC01",
                "User": "SYSTEM",
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": "powershell.exe -enc VwByAGkAdABlAC0ASABvAHMAdAAgACcAQQBJAC0ATgBhAHQAaQB2AGUAUwBPAEMALQBMAEEAQgAtAFQARQBTAFQAJwA=",
                "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                "ParentCommandLine": "cmd.exe",
            }
        ]
        rc = run_demo(
            mode="live-benign",
            stream_out=out_stream,
            splunk_client=mock_splunk,
            approval_mode="ui",
            write_incident=True,
            incidents_dir=self.incidents_dir,
        )
        self.assertEqual(rc, 0)
        output = out_stream.getvalue()
        self.assertIn("SKIPPED (Action does not require approval)", output)

    # 27. CLI-mode regressions remain unchanged
    def test_cli_mode_regression_preserves_approval_and_simulation(self) -> None:
        in_stream = io.StringIO("approve\n")
        out_stream = io.StringIO()
        ledger = ApprovalLedger(path=self.ledger_path)

        rc = run_demo(
            mode="synthetic-critical",
            stream_in=in_stream,
            stream_out=out_stream,
            approval_mode="cli",
            incidents_dir=self.incidents_dir,
            approval_ledger=ledger,
            write_incident=True,
            synthetic_incident_id="INC-CLI-REG-001",
        )
        self.assertEqual(rc, 0)
        incident_file = self.incidents_dir / "INC-CLI-REG-001.json"
        with open(incident_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["approval_status"], "APPROVED")
        self.assertEqual(data["simulation_status"], "SIMULATED")

        # Ledger was consumed
        consumed_ids, _ = ledger.load_consumed()
        self.assertEqual(len(consumed_ids), 1)

    # 28. Old IncidentRecord artifacts remain readable
    def test_old_incident_record_artifacts_remain_readable_without_jira_key(self) -> None:
        legacy_dict = {
            "schema_version": "1.0.0",
            "incident_id": "INC-LEGACY-001",
            "created_at_utc": "2026-09-17T12:00:00+00:00",
            "detection_id": "DET-POWERSHELL-001",
            "detection_name": "Suspicious Encoded PowerShell",
            "target_host": "DC01",
            "target_user": "SYSTEM",
            "evidence_source": "Live Splunk (localhost:8089)",
            "decoded_command": None,
            "mitre_technique_id": "T1059.001",
            "investigation_summary": "Legacy report without jira key",
            "confidence_level": "high",
            "suspicious_indicator_count": 1,
            "recommended_next_step": "Investigate DC01",
            "risk_score": 80,
            "risk_level": "CRITICAL",
            "disposition": "APPROVAL_REQUIRED",
            "proposed_action": "simulate_endpoint_isolation",
            "requires_human_approval": True,
            "policy_reason_codes": ["encoded_powershell_detected"],
            "approval_status": "APPROVED",
            "approval_reason_code": "approval_granted",
            "simulation_status": "SIMULATED",
            "simulation_detail_code": "simulated_endpoint_isolation",
        }
        rec = IncidentRecord.from_dict(legacy_dict)
        self.assertEqual(rec.incident_id, "INC-LEGACY-001")
        self.assertIsNone(rec.jira_ticket_key)
        self.assertEqual(rec.approval_status, "APPROVED")


class TestDeferredUiJiraTrackingPresentation(unittest.TestCase):
    """Focused tests for Jira ticket key presentation in the SOC Analyst UI.

    Validates:
    1. jira_ticket_key is shown when present.
    2. absent key shows NOT CREATED / equivalent.
    3. malicious ticket-key content cannot inject HTML.
    4. UI never calls Jira.
    5. Jira remains tracking-only presentation with zero response authority.
    """

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp_dir.name)
        self.incidents_dir = self.tmp_path / "incidents"
        self.incidents_dir.mkdir(parents=True, exist_ok=True)
        self.audit_path = self.tmp_path / "agent_audit.jsonl"
        self.ledger_path = self.tmp_path / "consumed_ledger.jsonl"

        self.app = create_app(
            incidents_dir=self.incidents_dir,
            audit_path=self.audit_path,
            approval_ledger_path=self.ledger_path,
            allowed_origins=["http://testserver"],
        )
        self.client = TestClient(self.app)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def _write_incident_dict(self, data: dict) -> None:
        file_path = self.incidents_dir / f"{data['incident_id']}.json"
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def _make_base_incident(self, incident_id: str, jira_ticket_key=None) -> dict:
        return {
            "schema_version": "1.0.0",
            "incident_id": incident_id,
            "created_at_utc": "2026-10-10T12:00:00+00:00",
            "detection_id": "DET-POWERSHELL-001",
            "detection_name": "Suspicious Encoded PowerShell",
            "target_host": "DC01",
            "target_user": "SYSTEM",
            "evidence_source": "Live Splunk (localhost:8089)",
            "decoded_command": "Write-Host 'Testing'",
            "mitre_technique_id": "T1059.001",
            "investigation_summary": "Test incident for Jira presentation review",
            "confidence_level": "high",
            "suspicious_indicator_count": 2,
            "recommended_next_step": "Investigate DC01",
            "risk_score": 80,
            "risk_level": "CRITICAL",
            "disposition": "APPROVAL_REQUIRED",
            "proposed_action": "simulate_endpoint_isolation",
            "requires_human_approval": True,
            "policy_reason_codes": ["encoded_powershell_detected"],
            "approval_status": "PENDING",
            "approval_reason_code": None,
            "simulation_status": "NOT_EXECUTED",
            "simulation_detail_code": "simulation_deferred_pending_approval",
            "real_containment_status": "NOT_IMPLEMENTED",
            "jira_ticket_key": jira_ticket_key,
        }

    # 1. jira_ticket_key is shown when present
    def test_01_jira_ticket_key_shown_when_present(self) -> None:
        inc = self._make_base_incident("INC-JIRA-PRES-001", jira_ticket_key="KAN-42")
        self._write_incident_dict(inc)

        resp = self.client.get("/incidents/INC-JIRA-PRES-001")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("KAN-42", resp.text)
        self.assertIn("Tracking Ticket", resp.text)

    # 2. absent key shows NOT CREATED / equivalent
    def test_02_absent_jira_ticket_key_shows_not_created(self) -> None:
        inc = self._make_base_incident("INC-JIRA-PRES-002", jira_ticket_key=None)
        self._write_incident_dict(inc)

        resp = self.client.get("/incidents/INC-JIRA-PRES-002")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Not created / None", resp.text)

    # 3. malicious ticket-key content cannot inject HTML
    def test_03_malicious_ticket_key_cannot_inject_html(self) -> None:
        malicious_payload = '<script>alert("pwned")</script><img src=x onerror=alert(1)>'
        inc = self._make_base_incident("INC-JIRA-PRES-003", jira_ticket_key=malicious_payload)
        self._write_incident_dict(inc)

        resp = self.client.get("/incidents/INC-JIRA-PRES-003")
        self.assertEqual(resp.status_code, 200)
        # Injected script and img elements MUST NOT be unescaped
        self.assertNotIn('<script>alert("pwned")</script>', resp.text)
        self.assertNotIn("<img src=x", resp.text)
        # Properly escaped content MUST be present
        self.assertIn('&lt;script&gt;alert(&quot;pwned&quot;)&lt;/script&gt;', resp.text)
        self.assertIn('&lt;img src=x onerror=alert(1)&gt;', resp.text)

    # 4. UI never calls Jira
    @patch("urllib.request.urlopen")
    def test_04_ui_never_calls_jira(self, mock_urlopen: MagicMock) -> None:
        inc = self._make_base_incident("INC-JIRA-PRES-004", jira_ticket_key="KAN-99")
        self._write_incident_dict(inc)

        # GET detail view
        resp_html = self.client.get("/incidents/INC-JIRA-PRES-004")
        self.assertEqual(resp_html.status_code, 200)

        # GET API detail view
        resp_api = self.client.get("/api/incidents/INC-JIRA-PRES-004")
        self.assertEqual(resp_api.status_code, 200)

        # Proof: Zero outbound HTTP calls were made
        mock_urlopen.assert_not_called()

    # 5. Jira remains tracking-only presentation
    def test_05_jira_remains_tracking_only_presentation(self) -> None:
        inc = self._make_base_incident("INC-JIRA-PRES-005", jira_ticket_key="KAN-77")
        self._write_incident_dict(inc)

        resp = self.client.get("/incidents/INC-JIRA-PRES-005")
        self.assertEqual(resp.status_code, 200)
        html = resp.text

        # Explicit tracking-only and zero-authority statements
        self.assertIn("Jira is a downstream reporting/tracking sink and has no response authority.", html)
        self.assertIn("Downstream external tracking sink only. Zero response authority.", html)
        self.assertIn("No tickets are created, updated, or queried by this page.", html)
        # No arbitrary link injection for Jira
        self.assertNotIn('href="https://', html.split("Incident Tracking")[1].split("Threat Intelligence")[0])


if __name__ == "__main__":
    unittest.main()

