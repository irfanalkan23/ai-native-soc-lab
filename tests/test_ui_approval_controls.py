"""Security and functionality tests for Milestone 16D controlled approve/deny UI integration.

Architecture Principle:
    Browser expresses analyst intent only.
    Backend resolves trusted incident + policy + action + approval state.
    RuntimeGuard remains higher authority.
    Only the already-authorized simulated action may execute.
    Everything is audited.
    Zero real containment, OS mutation, socket connections, or external API calls.
"""

import ast
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
from investigator.audit import AuditEvent, AuditEventType, AuditLog
from investigator.audit_writer import JsonlAuditWriter
from investigator.incident_record import (
    IncidentApprovalStatus,
    IncidentJsonWriter,
    IncidentRecord,
)
from investigator.policy import ProposedAction
from investigator.runtime_guard import RuntimeGuard
from ui.app import create_app


def _make_pending_incident_dict(
    incident_id: str = "INC-16D-001",
    proposed_action: str = "simulate_endpoint_isolation",
    requires_human_approval: bool = True,
    approval_status: str = "PENDING",
    simulation_status: str = "NOT_EXECUTED",
    **kwargs: object,
) -> dict:
    """Build a baseline incident dict awaiting human approval."""
    base = {
        "schema_version": "1.0.0",
        "incident_id": incident_id,
        "created_at_utc": "2026-10-10T12:00:00+00:00",
        "detection_id": "DET-16D-001",
        "detection_name": "Suspicious Encoded PowerShell Execution",
        "target_host": "DC01",
        "target_user": "SYSTEM",
        "evidence_source": "Sysmon Telemetry Log",
        "decoded_command": "powershell.exe -enc AAAA",
        "mitre_technique_id": "T1059.001",
        "investigation_summary": "High-risk encoded execution requiring isolation.",
        "confidence_level": "high",
        "suspicious_indicator_count": 2,
        "recommended_next_step": "Isolate host and investigate DC01.",
        "risk_score": 85,
        "risk_level": "HIGH",
        "disposition": "APPROVAL_REQUIRED",
        "proposed_action": proposed_action,
        "requires_human_approval": requires_human_approval,
        "policy_reason_codes": ["encoded_powershell_detected"],
        "approval_status": approval_status,
        "approval_reason_code": None,
        "simulation_status": simulation_status,
        "simulation_detail_code": "simulation_not_required",
        "threat_intel_status": "SKIPPED_INELIGIBLE",
        "threat_intel_skip_reason": "private_source_ip_ineligible",
        "jira_ticket_key": "SEC-1601",
    }
    base.update(kwargs)
    return base


class TestUiApprovalControls(unittest.TestCase):
    """Test suite covering the 40 security checklist requirements of Milestone 16D."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp_dir.name)
        self.incidents_dir = self.tmp_path / "incidents"
        self.incidents_dir.mkdir(parents=True, exist_ok=True)
        self.audit_path = self.tmp_path / "audit" / "agent_audit.jsonl"
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        self.ledger_path = self.tmp_path / "approvals" / "approval_consumption.jsonl"
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)

        self.runtime_guard = RuntimeGuard()
        self.approval_registry = ApprovalRegistry(ledger=ApprovalLedger(path=self.ledger_path))

        self.app = create_app(
            incidents_dir=self.incidents_dir,
            audit_path=self.audit_path,
            approval_registry=self.approval_registry,
            approval_ledger_path=self.ledger_path,
            runtime_guard=self.runtime_guard,
        )
        self.client = TestClient(self.app)
        self.csrf_token = self.app.state.csrf_token

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def _write_incident(self, data: dict) -> Path:
        p = self.incidents_dir / f"{data['incident_id']}.json"
        with open(p, "w", encoding="utf-8") as f:
            json.dump(data, f)
        return p

    def _read_incident(self, incident_id: str) -> dict:
        p = self.incidents_dir / f"{incident_id}.json"
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)

    def _read_audit_events(self) -> list:
        if not self.audit_path.exists():
            return []
        events = []
        with open(self.audit_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    events.append(json.loads(line))
        return events

    # -------------------------------------------------------------------------
    # 1-5: HTTP Methods & Routing Hardening
    # -------------------------------------------------------------------------

    def test_01_approve_endpoint_exists_only_as_post(self) -> None:
        """Approve endpoint allows POST and rejects GET, PUT, PATCH, DELETE."""
        data = _make_pending_incident_dict("INC-RTE-001")
        self._write_incident(data)
        url = "/api/incidents/INC-RTE-001/approval/approve"

        # POST is accepted method (tested below for 200 with token)
        # Non-POST methods must return 405 Method Not Allowed
        self.assertEqual(self.client.get(url).status_code, 405)
        self.assertEqual(self.client.put(url, json={}).status_code, 405)
        self.assertEqual(self.client.patch(url, json={}).status_code, 405)
        self.assertEqual(self.client.delete(url).status_code, 405)

    def test_02_deny_endpoint_exists_only_as_post(self) -> None:
        """Deny endpoint allows POST and rejects GET, PUT, PATCH, DELETE."""
        data = _make_pending_incident_dict("INC-RTE-002")
        self._write_incident(data)
        url = "/api/incidents/INC-RTE-002/approval/deny"

        self.assertEqual(self.client.get(url).status_code, 405)
        self.assertEqual(self.client.put(url, json={}).status_code, 405)
        self.assertEqual(self.client.patch(url, json={}).status_code, 405)
        self.assertEqual(self.client.delete(url).status_code, 405)

    def test_03_get_approve_returns_405(self) -> None:
        """GET on approve route returns 405."""
        resp = self.client.get("/api/incidents/INC-NONEXIST/approval/approve")
        self.assertEqual(resp.status_code, 405)

    def test_04_put_patch_delete_approve_returns_405(self) -> None:
        """PUT, PATCH, DELETE on approve route return 405."""
        url = "/api/incidents/INC-NONEXIST/approval/approve"
        self.assertEqual(self.client.put(url).status_code, 405)
        self.assertEqual(self.client.patch(url).status_code, 405)
        self.assertEqual(self.client.delete(url).status_code, 405)

    def test_05_post_unrelated_ui_route_returns_405(self) -> None:
        """POST to read-only UI routes returns 405."""
        for path in ("/", "/api/incidents", "/incidents/INC-001", "/api/incidents/INC-001", "/api/incidents/INC-001/audit"):
            resp = self.client.post(path, json={"action": "approve"})
            self.assertEqual(resp.status_code, 405)

    # -------------------------------------------------------------------------
    # 6-8: Path Validation & Containment
    # -------------------------------------------------------------------------

    def test_06_invalid_incident_id_rejected(self) -> None:
        """Malformed incident IDs are rejected with 400 Bad Request."""
        for bad_id in ("INC%20001", "INC*001", "INC!001", "a" * 65):
            resp = self.client.post(
                f"/api/incidents/{bad_id}/approval/approve",
                json={"csrf_token": self.csrf_token},
            )
            self.assertEqual(resp.status_code, 400)

    def test_07_traversal_id_rejected(self) -> None:
        """Path traversal identifiers are rejected with 400 or 404."""
        for trav in ("..", "../INC-001", "..%2Ftest", "C:\\Windows"):
            resp = self.client.post(
                f"/api/incidents/{trav}/approval/approve",
                json={"csrf_token": self.csrf_token},
            )
            self.assertIn(resp.status_code, (400, 404))

    def test_08_missing_incident_returns_404(self) -> None:
        """Non-existent incident returns 404 Not Found."""
        resp = self.client.post(
            "/api/incidents/INC-MISSING-999/approval/approve",
            json={"csrf_token": self.csrf_token},
        )
        self.assertEqual(resp.status_code, 404)
        self.assertEqual(resp.json()["detail"], "incident_not_found")

    # -------------------------------------------------------------------------
    # 9-10: Anti-CSRF & Origin Boundary
    # -------------------------------------------------------------------------

    def test_09a_default_localhost_8010_accepted_by_default(self) -> None:
        """Default localhost:8010 origin is accepted by default configuration."""
        data = _make_pending_incident_dict("INC-ORIGIN-001")
        self._write_incident(data)

        resp = self.client.post(
            "/api/incidents/INC-ORIGIN-001/approval/approve",
            headers={"Origin": "http://localhost:8010", "X-CSRF-Token": self.csrf_token},
            json={"csrf_token": self.csrf_token},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["approval_status"], "APPROVED")

    def test_09b_default_127_0_0_1_8010_accepted_by_default(self) -> None:
        """Default 127.0.0.1:8010 origin is accepted by default configuration."""
        data = _make_pending_incident_dict("INC-ORIGIN-002")
        self._write_incident(data)

        resp = self.client.post(
            "/api/incidents/INC-ORIGIN-002/approval/approve",
            headers={"Origin": "http://127.0.0.1:8010", "X-CSRF-Token": self.csrf_token},
            json={"csrf_token": self.csrf_token},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["approval_status"], "APPROVED")

    def test_09c_localhost_8000_rejected_by_default(self) -> None:
        """Splunk Web port http://localhost:8000 is rejected by default."""
        data = _make_pending_incident_dict("INC-ORIGIN-003")
        self._write_incident(data)

        resp = self.client.post(
            "/api/incidents/INC-ORIGIN-003/approval/approve",
            headers={"Origin": "http://localhost:8000", "X-CSRF-Token": self.csrf_token},
            json={"csrf_token": self.csrf_token},
        )
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.json()["detail"], "origin_forbidden")

    def test_09d_127_0_0_1_8000_rejected_by_default(self) -> None:
        """Splunk Web port http://127.0.0.1:8000 is rejected by default."""
        data = _make_pending_incident_dict("INC-ORIGIN-004")
        self._write_incident(data)

        resp = self.client.post(
            "/api/incidents/INC-ORIGIN-004/approval/approve",
            headers={"Origin": "http://127.0.0.1:8000", "X-CSRF-Token": self.csrf_token},
            json={"csrf_token": self.csrf_token},
        )
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.json()["detail"], "origin_forbidden")

    def test_09e_testserver_rejected_by_default_configuration(self) -> None:
        """http://testserver is rejected by production/default configuration."""
        data = _make_pending_incident_dict("INC-ORIGIN-005")
        self._write_incident(data)

        resp = self.client.post(
            "/api/incidents/INC-ORIGIN-005/approval/approve",
            headers={"Origin": "http://testserver", "X-CSRF-Token": self.csrf_token},
            json={"csrf_token": self.csrf_token},
        )
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.json()["detail"], "origin_forbidden")

    def test_09f_testserver_works_only_when_explicitly_injected(self) -> None:
        """http://testserver works only when explicitly injected in test configuration."""
        test_app = create_app(
            incidents_dir=self.incidents_dir,
            audit_path=self.audit_path,
            approval_registry=self.approval_registry,
            approval_ledger_path=self.ledger_path,
            runtime_guard=self.runtime_guard,
            allowed_origins=["http://testserver"],
        )
        client = TestClient(test_app)
        csrf = test_app.state.csrf_token

        data = _make_pending_incident_dict("INC-ORIGIN-006")
        self._write_incident(data)

        resp = client.post(
            "/api/incidents/INC-ORIGIN-006/approval/approve",
            headers={"Origin": "http://testserver", "X-CSRF-Token": csrf},
            json={"csrf_token": csrf},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["approval_status"], "APPROVED")

    def test_09g_configured_lab_origin_accepted(self) -> None:
        """Configured lab origin http://192.168.1.101:8010 is accepted."""
        app = create_app(
            incidents_dir=self.incidents_dir,
            audit_path=self.audit_path,
            approval_registry=self.approval_registry,
            approval_ledger_path=self.ledger_path,
            runtime_guard=self.runtime_guard,
            allowed_origins=["http://192.168.1.101:8010"],
        )
        client = TestClient(app)
        csrf = app.state.csrf_token

        data = _make_pending_incident_dict("INC-ORIGIN-007")
        self._write_incident(data)

        resp = client.post(
            "/api/incidents/INC-ORIGIN-007/approval/approve",
            headers={"Origin": "http://192.168.1.101:8010", "X-CSRF-Token": csrf},
            json={"csrf_token": csrf},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["approval_status"], "APPROVED")

    def test_09h_wrong_port_lookalike_wildcard_null_rejected(self) -> None:
        """Wrong port, lookalike hostname, wildcard, and null origins are rejected."""
        app = create_app(
            incidents_dir=self.incidents_dir,
            audit_path=self.audit_path,
            approval_registry=self.approval_registry,
            approval_ledger_path=self.ledger_path,
            runtime_guard=self.runtime_guard,
            allowed_origins=["http://192.168.1.101:8010"],
        )
        client = TestClient(app)
        csrf = app.state.csrf_token

        data = _make_pending_incident_dict("INC-ORIGIN-008")
        self._write_incident(data)

        bad_origins = [
            "http://192.168.1.101:9999",
            "http://192.168.1.101.evil.com:8010",
            "*",
            "null",
            "http://*",
            "http://attacker.com",
        ]
        for bad_origin in bad_origins:
            resp = client.post(
                "/api/incidents/INC-ORIGIN-008/approval/approve",
                headers={"Origin": bad_origin, "X-CSRF-Token": csrf},
                json={"csrf_token": csrf},
            )
            self.assertEqual(resp.status_code, 403)
            self.assertEqual(resp.json()["detail"], "origin_forbidden")

    def test_09i_csrf_token_required_independently_of_origin(self) -> None:
        """CSRF token is required independently of valid Origin."""
        data = _make_pending_incident_dict("INC-ORIGIN-009")
        self._write_incident(data)

        # Missing token
        resp = self.client.post(
            "/api/incidents/INC-ORIGIN-009/approval/approve",
            headers={"Origin": "http://localhost:8010"},
            json={},
        )
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.json()["detail"], "csrf_token_invalid")

        # Wrong token
        resp = self.client.post(
            "/api/incidents/INC-ORIGIN-009/approval/approve",
            headers={"Origin": "http://localhost:8010", "X-CSRF-Token": "invalid-token"},
            json={"csrf_token": "invalid-token"},
        )
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.json()["detail"], "csrf_token_invalid")

    def test_09j_browser_cannot_modify_allowed_origin_configuration(self) -> None:
        """Browser headers or body parameters cannot alter server app.state.allowed_origins."""
        initial_origins = set(self.app.state.allowed_origins)
        data = _make_pending_incident_dict("INC-ORIGIN-010")
        self._write_incident(data)

        self.client.post(
            "/api/incidents/INC-ORIGIN-010/approval/approve",
            headers={
                "Origin": "http://attacker.com",
                "X-Allowed-Origins": "http://attacker.com",
                "X-CSRF-Token": self.csrf_token,
            },
            json={"csrf_token": self.csrf_token},
        )
        self.assertEqual(self.app.state.allowed_origins, initial_origins)

    def test_10_same_origin_request_accepted(self) -> None:
        """Requests with allowlisted loopback origin and valid token succeed."""
        data = _make_pending_incident_dict("INC-CSRF-002")
        self._write_incident(data)

        resp = self.client.post(
            "/api/incidents/INC-CSRF-002/approval/approve",
            headers={"Origin": "http://localhost:8010", "X-CSRF-Token": self.csrf_token},
            json={"csrf_token": self.csrf_token},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["approval_status"], "APPROVED")

    # -------------------------------------------------------------------------
    # 11-16: Request Body Hardening (Zero Caller-Controlled Parameters)
    # -------------------------------------------------------------------------

    def test_11_malformed_content_type_body_rejected(self) -> None:
        """Unsupported Content-Type and malformed body payloads are rejected with 400."""
        url = "/api/incidents/INC-001/approval/approve"
        # Plain text
        resp = self.client.post(url, content="raw text", headers={"Content-Type": "text/plain"})
        self.assertEqual(resp.status_code, 400)

        # Invalid JSON syntax
        resp = self.client.post(url, content="{bad json", headers={"Content-Type": "application/json"})
        self.assertEqual(resp.status_code, 400)

    def test_12_extra_arbitrary_fields_rejected(self) -> None:
        """Request containing extra arbitrary fields is rejected with 400."""
        data = _make_pending_incident_dict("INC-EXTRA-001")
        self._write_incident(data)

        resp = self.client.post(
            "/api/incidents/INC-EXTRA-001/approval/approve",
            json={"csrf_token": self.csrf_token, "foo": "bar"},
        )
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.json()["detail"], "unexpected_fields")

    def test_13_browser_cannot_supply_proposed_action(self) -> None:
        """Caller attempting to pass proposed_action is rejected with 400."""
        data = _make_pending_incident_dict("INC-FORGE-001")
        self._write_incident(data)

        resp = self.client.post(
            "/api/incidents/INC-FORGE-001/approval/approve",
            json={"csrf_token": self.csrf_token, "proposed_action": "containment"},
        )
        self.assertEqual(resp.status_code, 400)

    def test_14_browser_cannot_supply_approval_id(self) -> None:
        """Caller attempting to pass approval_id is rejected with 400."""
        data = _make_pending_incident_dict("INC-FORGE-002")
        self._write_incident(data)

        resp = self.client.post(
            "/api/incidents/INC-FORGE-002/approval/approve",
            json={"csrf_token": self.csrf_token, "approval_id": "APP-FORGED-001"},
        )
        self.assertEqual(resp.status_code, 400)

    def test_15_browser_cannot_supply_timestamp(self) -> None:
        """Caller attempting to pass timestamp is rejected with 400."""
        data = _make_pending_incident_dict("INC-FORGE-003")
        self._write_incident(data)

        resp = self.client.post(
            "/api/incidents/INC-FORGE-003/approval/approve",
            json={"csrf_token": self.csrf_token, "created_at_utc": "2026-10-10T12:00:00Z"},
        )
        self.assertEqual(resp.status_code, 400)

    def test_16_browser_cannot_supply_ledger_path(self) -> None:
        """Caller attempting to pass ledger_path is rejected with 400."""
        data = _make_pending_incident_dict("INC-FORGE-004")
        self._write_incident(data)

        resp = self.client.post(
            "/api/incidents/INC-FORGE-004/approval/approve",
            json={"csrf_token": self.csrf_token, "ledger_path": "/etc/shadow"},
        )
        self.assertEqual(resp.status_code, 400)

    # -------------------------------------------------------------------------
    # 17-21: Trusted State Resolution & Approve Semantics
    # -------------------------------------------------------------------------

    def test_17_non_approval_required_incident_cannot_be_approved(self) -> None:
        """Incident where requires_human_approval is False fails closed with 409."""
        data = _make_pending_incident_dict(
            "INC-NOAPP-001",
            requires_human_approval=False,
            proposed_action="simulate_endpoint_isolation",
        )
        self._write_incident(data)

        resp = self.client.post(
            "/api/incidents/INC-NOAPP-001/approval/approve",
            json={"csrf_token": self.csrf_token},
        )
        self.assertEqual(resp.status_code, 409)
        self.assertEqual(resp.json()["detail"], "approval_not_required")

    def test_18_wrong_unsupported_proposed_action_fails_closed(self) -> None:
        """Incident with non-allowlisted action fails closed with 409."""
        data = _make_pending_incident_dict(
            "INC-WRONGACT-001",
            proposed_action="monitor",
            requires_human_approval=True,
        )
        self._write_incident(data)

        resp = self.client.post(
            "/api/incidents/INC-WRONGACT-001/approval/approve",
            json={"csrf_token": self.csrf_token},
        )
        self.assertEqual(resp.status_code, 409)
        self.assertEqual(resp.json()["detail"], "unsupported_proposed_action")

    def test_19_pending_valid_approval_required_incident_can_be_approved(self) -> None:
        """Valid pending incident can be approved and returns 200 with bounded outcome."""
        data = _make_pending_incident_dict("INC-OK-001")
        self._write_incident(data)

        resp = self.client.post(
            "/api/incidents/INC-OK-001/approval/approve",
            json={"csrf_token": self.csrf_token},
        )
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["incident_id"], "INC-OK-001")
        self.assertEqual(body["approval_status"], "APPROVED")
        self.assertEqual(body["simulation_status"], "SIMULATED")
        self.assertEqual(body["real_action_status"], "NOT_IMPLEMENTED")
        self.assertEqual(body["detail_code"], "simulated_endpoint_isolation")

    def test_20_approved_flow_results_only_in_simulated_action(self) -> None:
        """Approved flow results solely in simulated action status."""
        data = _make_pending_incident_dict("INC-SIM-001")
        self._write_incident(data)

        resp = self.client.post(
            "/api/incidents/INC-SIM-001/approval/approve",
            json={"csrf_token": self.csrf_token},
        )
        self.assertEqual(resp.json()["simulation_status"], "SIMULATED")

    def test_21_real_action_remains_not_implemented(self) -> None:
        """Response explicitly confirms real containment is NOT_IMPLEMENTED."""
        data = _make_pending_incident_dict("INC-REAL-001")
        self._write_incident(data)

        resp = self.client.post(
            "/api/incidents/INC-REAL-001/approval/approve",
            json={"csrf_token": self.csrf_token},
        )
        self.assertEqual(resp.json()["real_action_status"], "NOT_IMPLEMENTED")

    # -------------------------------------------------------------------------
    # 22-25: Denial & Replay / Conflict Semantics
    # -------------------------------------------------------------------------

    def test_22_deny_blocks_simulation(self) -> None:
        """Deny records denial and explicitly does NOT execute simulation."""
        data = _make_pending_incident_dict("INC-DENY-001")
        self._write_incident(data)

        resp = self.client.post(
            "/api/incidents/INC-DENY-001/approval/deny",
            json={"csrf_token": self.csrf_token},
        )
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["approval_status"], "DENIED")
        self.assertEqual(body["simulation_status"], "NOT_EXECUTED")
        self.assertEqual(body["detail_code"], "simulation_blocked_denied")

        # Verify disk persistence
        persisted = self._read_incident("INC-DENY-001")
        self.assertEqual(persisted["approval_status"], "DENIED")
        self.assertEqual(persisted["simulation_status"], "NOT_EXECUTED")

    def test_23_denied_incident_cannot_then_be_approved_in_same_cycle(self) -> None:
        """Denied incident cannot subsequently be approved (finalized state)."""
        data = _make_pending_incident_dict("INC-DENY-002")
        self._write_incident(data)

        # Deny first
        r_deny = self.client.post(
            "/api/incidents/INC-DENY-002/approval/deny",
            json={"csrf_token": self.csrf_token},
        )
        self.assertEqual(r_deny.status_code, 200)

        # Attempt to approve
        r_app = self.client.post(
            "/api/incidents/INC-DENY-002/approval/approve",
            json={"csrf_token": self.csrf_token},
        )
        self.assertEqual(r_app.status_code, 409)
        self.assertEqual(r_app.json()["detail"], "incident_already_finalized")

    def test_24_already_consumed_approval_cannot_be_replayed(self) -> None:
        """If grant was already consumed in registry, approve fails closed with 409."""
        data = _make_pending_incident_dict("INC-CONSUMED-001")
        self._write_incident(data)

        # Pre-consume in registry ledger
        self.approval_registry._consumed_grant_keys.add(("INC-CONSUMED-001", "simulate_endpoint_isolation"))
        self.approval_registry._consumed_approval_ids.add("APP-INC-CONSUMED-001")

        resp = self.client.post(
            "/api/incidents/INC-CONSUMED-001/approval/approve",
            json={"csrf_token": self.csrf_token},
        )
        self.assertEqual(resp.status_code, 409)
        self.assertEqual(resp.json()["detail"], "approval_already_consumed")

    def test_25_duplicate_approve_fails_closed(self) -> None:
        """Duplicate approve request fails closed with 409 incident_already_finalized."""
        data = _make_pending_incident_dict("INC-DUP-001")
        self._write_incident(data)

        r1 = self.client.post(
            "/api/incidents/INC-DUP-001/approval/approve",
            json={"csrf_token": self.csrf_token},
        )
        self.assertEqual(r1.status_code, 200)

        # Second approve fails closed
        r2 = self.client.post(
            "/api/incidents/INC-DUP-001/approval/approve",
            json={"csrf_token": self.csrf_token},
        )
        self.assertEqual(r2.status_code, 409)
        self.assertEqual(r2.json()["detail"], "incident_already_finalized")

    # -------------------------------------------------------------------------
    # 26-29: RuntimeGuard Precedence & Ledger Integrity
    # -------------------------------------------------------------------------

    def test_26_runtime_guard_halted_blocks_approve(self) -> None:
        """RuntimeGuard in halted state blocks approve with 409."""
        data = _make_pending_incident_dict("INC-HALT-001")
        self._write_incident(data)

        # Halt RuntimeGuard
        self.runtime_guard._halted = True
        self.runtime_guard._halt_reason = "CONTROL_FAILURE"
        self.runtime_guard._halt_detail_code = "TRIPWIRE_TEST"
        self.assertTrue(self.runtime_guard.state.halted)

        resp = self.client.post(
            "/api/incidents/INC-HALT-001/approval/approve",
            json={"csrf_token": self.csrf_token},
        )
        self.assertEqual(resp.status_code, 409)
        self.assertEqual(resp.json()["detail"], "runtime_guard_halted")

    def test_27_runtime_guard_halt_does_not_consume_approval(self) -> None:
        """RuntimeGuard halt aborts before consuming approval in ledger."""
        data = _make_pending_incident_dict("INC-HALT-002")
        self._write_incident(data)

        self.runtime_guard._halted = True
        self.runtime_guard._halt_reason = "CONTROL_FAILURE"
        self.runtime_guard._halt_detail_code = "TRIPWIRE_TEST"

        self.client.post(
            "/api/incidents/INC-HALT-002/approval/approve",
            json={"csrf_token": self.csrf_token},
        )

        # Confirm ledger is empty
        self.assertFalse(self.ledger_path.exists() and self.ledger_path.stat().st_size > 0)
        # Incident record remains PENDING
        persisted = self._read_incident("INC-HALT-002")
        self.assertEqual(persisted["approval_status"], "PENDING")

    def test_28_ledger_failure_blocks_approve(self) -> None:
        """Ledger persistence failure blocks approve and returns 409."""
        data = _make_pending_incident_dict("INC-LEDGER-001")
        self._write_incident(data)

        # Mock ledger append to fail
        with patch.object(self.approval_registry._ledger, "append_consumption", side_effect=OSError("disk failure")):
            resp = self.client.post(
                "/api/incidents/INC-LEDGER-001/approval/approve",
                json={"csrf_token": self.csrf_token},
            )
            self.assertEqual(resp.status_code, 409)
            self.assertEqual(resp.json()["detail"], "approval_ledger_failure")

    def test_29_corrupt_ledger_blocks_approve(self) -> None:
        """Corrupt JSON lines in ledger causes approval registry check to fail closed."""
        data = _make_pending_incident_dict("INC-LEDGER-CORRUPT")
        self._write_incident(data)

        with patch.object(self.approval_registry, "is_grant_consumed", side_effect=Exception("corrupt")):
            resp = self.client.post(
                "/api/incidents/INC-LEDGER-CORRUPT/approval/approve",
                json={"csrf_token": self.csrf_token},
            )
            self.assertEqual(resp.status_code, 409)
            self.assertEqual(resp.json()["detail"], "approval_ledger_corrupt")

    # -------------------------------------------------------------------------
    # 30-34: Audit Singularity, Persistence & Isolation
    # -------------------------------------------------------------------------

    def test_30_audit_events_appear_exactly_once(self) -> None:
        """Authoritative lifecycle events appear exactly once in persisted audit log."""
        data = _make_pending_incident_dict("INC-AUDIT-001")
        self._write_incident(data)

        resp = self.client.post(
            "/api/incidents/INC-AUDIT-001/approval/approve",
            json={"csrf_token": self.csrf_token},
        )
        self.assertEqual(resp.status_code, 200)

        events = self._read_audit_events()
        event_types = [e["event_type"] for e in events if e.get("incident_id") == "INC-AUDIT-001"]
        self.assertEqual(
            event_types,
            [
                "APPROVAL_REQUESTED",
                "APPROVAL_GRANTED",
                "APPROVAL_CONSUMED",
                "SIMULATION_COMPLETED",
            ],
        )

    def test_31_incident_state_persisted_after_approve(self) -> None:
        """Updated IncidentRecord is persisted with APPROVED and SIMULATED state."""
        data = _make_pending_incident_dict("INC-PERSIST-001")
        self._write_incident(data)

        self.client.post(
            "/api/incidents/INC-PERSIST-001/approval/approve",
            json={"csrf_token": self.csrf_token},
        )
        persisted = self._read_incident("INC-PERSIST-001")
        self.assertEqual(persisted["approval_status"], "APPROVED")
        self.assertEqual(persisted["approval_reason_code"], "approval_granted")
        self.assertEqual(persisted["simulation_status"], "SIMULATED")
        self.assertEqual(persisted["simulation_detail_code"], "simulated_endpoint_isolation")

    def test_31b_incident_persistence_failure_after_approval_consumption(self) -> None:
        """Forced IncidentRecord write failure fails closed, preserves consumed ledger, and blocks replay.

        The consumed grant remains durably recorded in the local approval ledger
        and is rejected on subsequent registry reloads under the tested local filesystem model.
        """
        data = _make_pending_incident_dict("INC-FAIL-PERSIST-001")
        self._write_incident(data)

        # Force IncidentJsonWriter.write_record to fail with OSError
        with patch("investigator.incident_record.IncidentJsonWriter.write_record", side_effect=OSError("disk failure simulation")):
            resp = self.client.post(
                "/api/incidents/INC-FAIL-PERSIST-001/approval/approve",
                json={"csrf_token": self.csrf_token},
            )
            # 4. HTTP response fails closed with 500 and sanitized persistence_error
            self.assertEqual(resp.status_code, 500)
            self.assertEqual(resp.json()["detail"], "persistence_error")
            # 8. Internal filesystem path and exception text are not leaked
            self.assertNotIn("disk failure simulation", resp.text)
            self.assertNotIn(str(self.incidents_dir), resp.text)

        # 1. Approval consumption succeeded in persistent ledger
        self.assertTrue(self.ledger_path.exists())
        with open(self.ledger_path, "r", encoding="utf-8") as f:
            ledger_lines = [json.loads(line.strip()) for line in f if line.strip()]
        self.assertTrue(any(e.get("incident_id") == "INC-FAIL-PERSIST-001" for e in ledger_lines))

        # 2. Simulation completed and audit events were persisted
        events = self._read_audit_events()
        event_types = [e["event_type"] for e in events if e.get("incident_id") == "INC-FAIL-PERSIST-001"]
        self.assertIn("APPROVAL_CONSUMED", event_types)
        self.assertIn("SIMULATION_COMPLETED", event_types)

        # 5. Consumed grant remains consumed in registry
        self.assertTrue(
            self.approval_registry.is_grant_consumed(
                "INC-FAIL-PERSIST-001", ProposedAction.SIMULATE_ENDPOINT_ISOLATION
            )
        )

        # 6. Second POST cannot simulate again (re-checks ledger and fails closed with 409)
        resp_retry = self.client.post(
            "/api/incidents/INC-FAIL-PERSIST-001/approval/approve",
            json={"csrf_token": self.csrf_token},
        )
        self.assertEqual(resp_retry.status_code, 409)
        self.assertEqual(resp_retry.json()["detail"], "approval_already_consumed")

        # 7. Ledger is not rolled back (still contains consumption entry)
        with open(self.ledger_path, "r", encoding="utf-8") as f:
            ledger_lines_after = [json.loads(line.strip()) for line in f if line.strip()]
        self.assertEqual(len(ledger_lines), len(ledger_lines_after))

        # Exactly 1 SIMULATION_COMPLETED event in entire audit trail
        sim_events = [e for e in self._read_audit_events() if e.get("incident_id") == "INC-FAIL-PERSIST-001" and e.get("event_type") == "SIMULATION_COMPLETED"]
        self.assertEqual(len(sim_events), 1)

    def test_32_incident_state_persisted_after_deny(self) -> None:
        """Updated IncidentRecord is persisted with DENIED and NOT_EXECUTED state."""
        data = _make_pending_incident_dict("INC-PERSIST-002")
        self._write_incident(data)

        self.client.post(
            "/api/incidents/INC-PERSIST-002/approval/deny",
            json={"csrf_token": self.csrf_token},
        )
        persisted = self._read_incident("INC-PERSIST-002")
        self.assertEqual(persisted["approval_status"], "DENIED")
        self.assertEqual(persisted["approval_reason_code"], "approval_denied")
        self.assertEqual(persisted["simulation_status"], "NOT_EXECUTED")
        self.assertEqual(persisted["simulation_detail_code"], "simulation_blocked_denied")

    def test_33_cross_incident_isolation_preserved(self) -> None:
        """Approving INC-A does not alter or approve INC-B."""
        inc_a = _make_pending_incident_dict("INC-ISO-A")
        inc_b = _make_pending_incident_dict("INC-ISO-B")
        self._write_incident(inc_a)
        self._write_incident(inc_b)

        self.client.post(
            "/api/incidents/INC-ISO-A/approval/approve",
            json={"csrf_token": self.csrf_token},
        )

        res_a = self._read_incident("INC-ISO-A")
        res_b = self._read_incident("INC-ISO-B")

        self.assertEqual(res_a["approval_status"], "APPROVED")
        self.assertEqual(res_b["approval_status"], "PENDING")

    def test_34_xss_prompt_injection_content_remains_inert(self) -> None:
        """XSS payloads in incident fields are escaped and never executed."""
        xss_payload = "<script>alert('xss')</script>"
        data = _make_pending_incident_dict(
            "INC-XSS-001",
            investigation_summary=xss_payload,
        )
        self._write_incident(data)

        resp = self.client.get("/incidents/INC-XSS-001")
        self.assertEqual(resp.status_code, 200)
        self.assertNotIn("<script>alert('xss')</script>", resp.text)
        self.assertIn("&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;", resp.text)

    # -------------------------------------------------------------------------
    # 35-40: Defense-in-Depth, Error Sanitization & Environment Invariants
    # -------------------------------------------------------------------------

    def test_35_error_response_does_not_leak_filesystem_path(self) -> None:
        """Error responses do not leak local filesystem paths."""
        resp = self.client.post(
            "/api/incidents/INC-MISSING-999/approval/approve",
            json={"csrf_token": self.csrf_token},
        )
        self.assertEqual(resp.status_code, 404)
        for leak in (str(self.incidents_dir), "C:\\", "/tmp", "/etc"):
            self.assertNotIn(leak.lower(), resp.text.lower())

    def test_36_error_response_does_not_leak_exception_text(self) -> None:
        """Error responses do not leak raw Python tracebacks or internal exception types."""
        resp = self.client.post(
            "/api/incidents/INC-MISSING-999/approval/approve",
            json={"csrf_token": self.csrf_token},
        )
        for leak in ("traceback", "exception", "file \""):
            self.assertNotIn(leak, resp.text.lower())

    def test_37_openapi_docs_remain_unavailable(self) -> None:
        """OpenAPI, Swagger, and ReDoc documentation routes remain disabled."""
        for path in ("/docs", "/redoc", "/openapi.json"):
            self.assertEqual(self.client.get(path).status_code, 404)

    def test_38_no_toolrouter_provider_external_api_imports_in_ui(self) -> None:
        """AST inspection confirms no UI module imports ToolRouter or external API clients."""
        ui_app = Path("ui/app.py")
        tree = ast.parse(ui_app.read_text(encoding="utf-8"), filename=str(ui_app))
        banned = {"toolrouter", "openai", "jira", "virustotal", "splunk"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertFalse(any(b in alias.name.lower() for b in banned))
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    self.assertFalse(any(b in node.module.lower() for b in banned))

    @patch("urllib.request.urlopen")
    @patch("http.client.HTTPConnection")
    def test_39_zero_network_calls_occur(self, mock_conn: MagicMock, mock_urlopen: MagicMock) -> None:
        """Zero outbound network connections occur during approval mutations."""
        data = _make_pending_incident_dict("INC-NET-001")
        self._write_incident(data)

        self.client.post(
            "/api/incidents/INC-NET-001/approval/approve",
            json={"csrf_token": self.csrf_token},
        )
        mock_urlopen.assert_not_called()
        mock_conn.assert_not_called()

    @patch("subprocess.run")
    @patch("os.system")
    def test_40_zero_real_os_endpoint_action_occurs(self, mock_os_system: MagicMock, mock_sub: MagicMock) -> None:
        """Zero OS commands or subprocesses are executed during approval mutations."""
        data = _make_pending_incident_dict("INC-OS-001")
        self._write_incident(data)

        self.client.post(
            "/api/incidents/INC-OS-001/approval/approve",
            json={"csrf_token": self.csrf_token},
        )
        mock_sub.assert_not_called()
        mock_os_system.assert_not_called()


if __name__ == "__main__":
    unittest.main()
