"""Unit and integration tests for Milestone 5B-1 Ticketing module.

Verifies:
1. Provider-neutral TicketPriority enum (LOW, MEDIUM, HIGH, CRITICAL).
2. Hardened TicketConfig validation (exact tuple, max count, no duplicates, allowlisted labels, default include_decoded_command=False).
3. TicketRequest schema bounds, immutability, single-line summary, and label filtering.
4. TicketResult strict consistency validation (success/failure coupling, ticket_key presence, exact UTC offset zero).
5. FakeTicketClient determinism, thread safety, and key derivation strictly from request.project_key.
6. Deterministic builder invariants (priority mapping, tightened label derivation, inert evidence framing).
7. Security boundaries: zero network, socket, subprocess, or credential access.
"""

from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
import sys
import threading
import unittest
from unittest.mock import patch

from investigator.incident_record import (
    IncidentApprovalStatus,
    IncidentRecord,
)
from investigator.policy import (
    ActionDisposition,
    PolicyDecision,
    ProposedAction,
    RiskLevel,
)
from investigator.schemas import (
    InvestigationInput,
    InvestigationResult,
)
from investigator.simulator import (
    SimulationResult,
    SimulationStatus,
)
from investigator.ticketing import (
    ALLOWED_TICKET_LABELS,
    FakeTicketClient,
    TicketClientError,
    TicketConfig,
    TicketConfigError,
    TicketPriority,
    TicketRequest,
    TicketResult,
    TicketSchemaError,
    build_ticket_request,
)


def _make_valid_incident_record(
    incident_id: str = "INC-TEST-001",
    risk_level: str = "LOW",
    risk_score: int = 0,
    mitre_technique_id: str = "T1059.001",
    policy_reason_codes: tuple = ("benign_lab_fixture_matched",),
    approval_status: str = IncidentApprovalStatus.NOT_REQUIRED.value,
    approval_reason_code: str = None,
    simulation_status: str = SimulationStatus.NOT_EXECUTED.value,
    simulation_detail_code: str = "simulation_not_required",
    decoded_command: str = "Write-Host 'AI-NativeSOC-LAB-TEST'",
    detection_name: str = "suspicious encoded powershell execution",
) -> IncidentRecord:
    """Helper to construct a valid IncidentRecord fixture for ticketing tests."""
    return IncidentRecord(
        schema_version="1.0.0",
        incident_id=incident_id,
        created_at_utc="2026-09-20T12:00:00Z",
        detection_id="DET-001",
        detection_name=detection_name,
        target_host="DC01",
        target_user="SYSTEM",
        evidence_source="Live Splunk",
        decoded_command=decoded_command,
        mitre_technique_id=mitre_technique_id,
        investigation_summary="Advisory investigation completed.",
        confidence_level="high",
        suspicious_indicator_count=0,
        recommended_next_step="No action required.",
        risk_score=risk_score,
        risk_level=risk_level,
        disposition="NO_ACTION",
        proposed_action="no_action",
        requires_human_approval=False,
        policy_reason_codes=policy_reason_codes,
        approval_status=approval_status,
        approval_reason_code=approval_reason_code,
        simulation_status=simulation_status,
        simulation_detail_code=simulation_detail_code,
    )


class TestTicketConfig(unittest.TestCase):
    """Verify TicketConfig validation, immutability, and defaults."""

    def test_default_config_valid(self) -> None:
        config = TicketConfig(
            project_key="SEC",
            issue_type="Incident",
            allowed_labels=tuple(sorted(ALLOWED_TICKET_LABELS)),
        )
        self.assertEqual(config.project_key, "SEC")
        self.assertEqual(config.issue_type, "Incident")
        self.assertFalse(config.include_decoded_command)
        self.assertEqual(len(config.allowed_labels), len(ALLOWED_TICKET_LABELS))

    def test_immutability(self) -> None:
        config = TicketConfig(
            project_key="SEC",
            issue_type="Incident",
            allowed_labels=("ai-native-soc",),
        )
        with self.assertRaises(FrozenInstanceError):
            config.project_key = "OTHER"

    def test_project_key_validation(self) -> None:
        with self.assertRaises(TicketConfigError):
            TicketConfig(project_key="sec", issue_type="Incident", allowed_labels=())
        with self.assertRaises(TicketConfigError):
            TicketConfig(project_key="S", issue_type="Incident", allowed_labels=())
        with self.assertRaises(TicketConfigError):
            TicketConfig(project_key="SEC-INVALID", issue_type="Incident", allowed_labels=())

    def test_issue_type_validation(self) -> None:
        with self.assertRaises(TicketConfigError):
            TicketConfig(project_key="SEC", issue_type="", allowed_labels=())
        with self.assertRaises(TicketConfigError):
            TicketConfig(project_key="SEC", issue_type="Invalid/Type!", allowed_labels=())

    def test_allowed_labels_must_be_exact_tuple(self) -> None:
        with self.assertRaises(TicketConfigError):
            TicketConfig(project_key="SEC", issue_type="Incident", allowed_labels=["ai-native-soc"])

    def test_allowed_labels_elements_must_be_str(self) -> None:
        with self.assertRaises(TicketConfigError):
            TicketConfig(project_key="SEC", issue_type="Incident", allowed_labels=(123,))

    def test_allowed_labels_unknown_value_rejected(self) -> None:
        with self.assertRaises(TicketConfigError):
            TicketConfig(project_key="SEC", issue_type="Incident", allowed_labels=("ai-native-soc", "unauthorized-label"))

    def test_allowed_labels_duplicates_rejected(self) -> None:
        with self.assertRaises(TicketConfigError):
            TicketConfig(project_key="SEC", issue_type="Incident", allowed_labels=("ai-native-soc", "ai-native-soc"))

    def test_allowed_labels_max_count_exceeded_rejected(self) -> None:
        labels = ("ai-native-soc", "powershell", "benign-test", "human-approved",
                  "human-denied", "approval-not-required", "simulated-containment",
                  "action-not-executed", "extra-label")
        with self.assertRaises(TicketConfigError):
            TicketConfig(project_key="SEC", issue_type="Incident", allowed_labels=labels)

    def test_include_decoded_command_must_be_bool(self) -> None:
        with self.assertRaises(TicketConfigError):
            TicketConfig(project_key="SEC", issue_type="Incident", allowed_labels=(), include_decoded_command="yes")


class TestTicketRequestSchema(unittest.TestCase):
    """Verify TicketRequest schema constraints, immutability, and bounds."""

    def test_valid_request_creation(self) -> None:
        req = TicketRequest(
            incident_id="INC-001",
            project_key="SEC",
            issue_type="Incident",
            summary="[LOW] suspicious powershell on DC01 (INC-001)",
            description="Incident details...",
            priority=TicketPriority.LOW,
            labels=("ai-native-soc",),
            external_reference="DET-001",
        )
        self.assertEqual(req.incident_id, "INC-001")
        self.assertEqual(req.priority, TicketPriority.LOW)
        self.assertEqual(req.labels, ("ai-native-soc",))

    def test_immutability(self) -> None:
        req = TicketRequest(
            incident_id="INC-001",
            project_key="SEC",
            issue_type="Incident",
            summary="Summary",
            description="Description",
            priority=TicketPriority.LOW,
            labels=(),
            external_reference="DET-001",
        )
        with self.assertRaises(FrozenInstanceError):
            req.summary = "New Summary"

    def test_summary_cannot_contain_newlines(self) -> None:
        with self.assertRaises(TicketSchemaError):
            TicketRequest(
                incident_id="INC-001",
                project_key="SEC",
                issue_type="Incident",
                summary="Multi\nLine\nSummary",
                description="Description",
                priority=TicketPriority.LOW,
                labels=(),
                external_reference="DET-001",
            )

    def test_summary_cannot_exceed_max_length(self) -> None:
        with self.assertRaises(TicketSchemaError):
            TicketRequest(
                incident_id="INC-001",
                project_key="SEC",
                issue_type="Incident",
                summary="A" * 256,
                description="Description",
                priority=TicketPriority.LOW,
                labels=(),
                external_reference="DET-001",
            )

    def test_description_cannot_exceed_max_length(self) -> None:
        with self.assertRaises(TicketSchemaError):
            TicketRequest(
                incident_id="INC-001",
                project_key="SEC",
                issue_type="Incident",
                summary="Summary",
                description="A" * 4097,
                priority=TicketPriority.LOW,
                labels=(),
                external_reference="DET-001",
            )

    def test_invalid_priority_type_rejected(self) -> None:
        with self.assertRaises(TicketSchemaError):
            TicketRequest(
                incident_id="INC-001",
                project_key="SEC",
                issue_type="Incident",
                summary="Summary",
                description="Description",
                priority="LOW",  # string instead of TicketPriority
                labels=(),
                external_reference="DET-001",
            )

    def test_labels_validation(self) -> None:
        with self.assertRaises(TicketSchemaError):
            TicketRequest(
                incident_id="INC-001",
                project_key="SEC",
                issue_type="Incident",
                summary="Summary",
                description="Description",
                priority=TicketPriority.LOW,
                labels=("invalid-label",),
                external_reference="DET-001",
            )


class TestTicketResultConsistency(unittest.TestCase):
    """Verify TicketResult strict consistency validation and UTC zero offset enforcement."""

    def test_valid_success_result_z(self) -> None:
        result = TicketResult(
            success=True,
            provider="fake_ticket_client",
            ticket_key="SEC-0001",
            detail_code="ticket_created_fake",
            created_at_utc="2026-09-20T12:00:00Z",
        )
        self.assertTrue(result.success)
        self.assertEqual(result.ticket_key, "SEC-0001")
        self.assertEqual(result.detail_code, "ticket_created_fake")

    def test_valid_success_result_plus_zero(self) -> None:
        result = TicketResult(
            success=True,
            provider="fake_ticket_client",
            ticket_key="SEC-0001",
            detail_code="ticket_created_fake",
            created_at_utc="2026-09-20T12:00:00+00:00",
        )
        self.assertTrue(result.success)

    def test_valid_failure_result(self) -> None:
        result = TicketResult(
            success=False,
            provider="fake_ticket_client",
            ticket_key=None,
            detail_code="ticket_creation_failed",
            created_at_utc="2026-09-20T12:00:00Z",
        )
        self.assertFalse(result.success)
        self.assertIsNone(result.ticket_key)

    def test_success_true_missing_ticket_key_fails_closed(self) -> None:
        with self.assertRaises(TicketSchemaError):
            TicketResult(
                success=True,
                provider="fake_ticket_client",
                ticket_key=None,
                detail_code="ticket_created_fake",
                created_at_utc="2026-09-20T12:00:00Z",
            )

    def test_success_true_wrong_detail_code_fails_closed(self) -> None:
        with self.assertRaises(TicketSchemaError):
            TicketResult(
                success=True,
                provider="fake_ticket_client",
                ticket_key="SEC-0001",
                detail_code="ticket_creation_failed",
                created_at_utc="2026-09-20T12:00:00Z",
            )

    def test_success_false_with_ticket_key_fails_closed(self) -> None:
        with self.assertRaises(TicketSchemaError):
            TicketResult(
                success=False,
                provider="fake_ticket_client",
                ticket_key="SEC-0001",
                detail_code="ticket_creation_failed",
                created_at_utc="2026-09-20T12:00:00Z",
            )

    def test_success_false_with_success_detail_code_fails_closed(self) -> None:
        with self.assertRaises(TicketSchemaError):
            TicketResult(
                success=False,
                provider="fake_ticket_client",
                ticket_key=None,
                detail_code="ticket_created_fake",
                created_at_utc="2026-09-20T12:00:00Z",
            )

    def test_created_at_utc_non_zero_offset_rejected(self) -> None:
        with self.assertRaises(TicketSchemaError):
            TicketResult(
                success=True,
                provider="fake_ticket_client",
                ticket_key="SEC-0001",
                detail_code="ticket_created_fake",
                created_at_utc="2026-09-20T17:00:00+05:00",
            )

    def test_created_at_utc_naive_timestamp_rejected(self) -> None:
        with self.assertRaises(TicketSchemaError):
            TicketResult(
                success=True,
                provider="fake_ticket_client",
                ticket_key="SEC-0001",
                detail_code="ticket_created_fake",
                created_at_utc="2026-09-20T12:00:00",
            )

    def test_malformed_timestamp_error_remains_sanitized(self) -> None:
        with self.assertRaises(TicketSchemaError) as ctx:
            TicketResult(
                success=True,
                provider="fake_ticket_client",
                ticket_key="SEC-0001",
                detail_code="ticket_created_fake",
                created_at_utc="not-a-timestamp",
            )
        self.assertEqual(str(ctx.exception), "created_at_utc must be a valid ISO 8601 timestamp")


class TestFakeTicketClient(unittest.TestCase):
    """Verify FakeTicketClient protocol conformance, key derivation, and thread safety."""

    def test_create_ticket_sequential_keys_from_project_key(self) -> None:
        client = FakeTicketClient()
        req1 = TicketRequest(
            incident_id="INC-001",
            project_key="SEC",
            issue_type="Incident",
            summary="Summary 1",
            description="Description 1",
            priority=TicketPriority.LOW,
            labels=(),
            external_reference="DET-001",
        )
        req2 = TicketRequest(
            incident_id="INC-002",
            project_key="SEC",
            issue_type="Incident",
            summary="Summary 2",
            description="Description 2",
            priority=TicketPriority.HIGH,
            labels=(),
            external_reference="DET-002",
        )
        res1 = client.create_ticket(req1)
        res2 = client.create_ticket(req2)

        self.assertEqual(res1.ticket_key, "SEC-0001")
        self.assertEqual(res2.ticket_key, "SEC-0002")
        self.assertEqual(res1.provider, "fake_ticket_client")
        self.assertTrue(res1.success)

    def test_project_key_governs_ticket_key_prefix(self) -> None:
        client = FakeTicketClient()
        req = TicketRequest(
            incident_id="INC-001",
            project_key="LAB",
            issue_type="Task",
            summary="Summary",
            description="Description",
            priority=TicketPriority.LOW,
            labels=(),
            external_reference="DET-001",
        )
        res = client.create_ticket(req)
        self.assertEqual(res.ticket_key, "LAB-0001")

    def test_client_rejects_non_ticket_request(self) -> None:
        client = FakeTicketClient()
        with self.assertRaises(TicketClientError):
            client.create_ticket({"summary": "invalid"} )

    def test_thread_safe_counter(self) -> None:
        client = FakeTicketClient()
        req = TicketRequest(
            incident_id="INC-001",
            project_key="SEC",
            issue_type="Incident",
            summary="Summary",
            description="Description",
            priority=TicketPriority.LOW,
            labels=(),
            external_reference="DET-001",
        )
        keys = []
        def worker() -> None:
            res = client.create_ticket(req)
            keys.append(res.ticket_key)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(keys), 10)
        self.assertEqual(len(set(keys)), 10)  # All 10 keys must be unique


class TestBuildTicketRequest(unittest.TestCase):
    """Verify deterministic build_ticket_request mappings and boundary enforcement."""

    def setUp(self) -> None:
        self.config_default = TicketConfig(
            project_key="SEC",
            issue_type="Incident",
            allowed_labels=tuple(sorted(ALLOWED_TICKET_LABELS)),
            include_decoded_command=False,
        )
        self.config_with_evidence = TicketConfig(
            project_key="SEC",
            issue_type="Incident",
            allowed_labels=tuple(sorted(ALLOWED_TICKET_LABELS)),
            include_decoded_command=True,
        )

    def test_provider_neutral_priority_mapping(self) -> None:
        rec_low = _make_valid_incident_record(risk_level="LOW", risk_score=10)
        rec_med = _make_valid_incident_record(risk_level="MEDIUM", risk_score=50)
        rec_high = _make_valid_incident_record(risk_level="HIGH", risk_score=70)
        rec_crit = _make_valid_incident_record(risk_level="CRITICAL", risk_score=90)

        self.assertEqual(build_ticket_request(rec_low, self.config_default).priority, TicketPriority.LOW)
        self.assertEqual(build_ticket_request(rec_med, self.config_default).priority, TicketPriority.MEDIUM)
        self.assertEqual(build_ticket_request(rec_high, self.config_default).priority, TicketPriority.HIGH)
        self.assertEqual(build_ticket_request(rec_crit, self.config_default).priority, TicketPriority.CRITICAL)

    def test_detection_name_containing_powershell_does_not_create_powershell_label(self) -> None:
        """Untrusted detection_name containing 'powershell' cannot independently create the powershell label."""
        rec = _make_valid_incident_record(
            detection_name="malicious powershell invocation",
            mitre_technique_id="T1003.001",  # NOT T1059.001
        )
        req = build_ticket_request(rec, self.config_default)
        self.assertNotIn("powershell", req.labels)

    def test_mitre_technique_t1059_001_creates_powershell_label(self) -> None:
        """T1059.001 does create the powershell label."""
        rec = _make_valid_incident_record(
            detection_name="Generic Script Execution",
            mitre_technique_id="T1059.001",
        )
        req = build_ticket_request(rec, self.config_default)
        self.assertIn("powershell", req.labels)

    def test_risk_score_zero_without_policy_reason_does_not_create_benign_test_label(self) -> None:
        """risk_score 0 without benign_lab_fixture_matched cannot independently create benign-test label."""
        rec = _make_valid_incident_record(
            risk_score=0,
            policy_reason_codes=("encoded_powershell_detected",),  # NO benign_lab_fixture_matched
        )
        req = build_ticket_request(rec, self.config_default)
        self.assertNotIn("benign-test", req.labels)

    def test_benign_lab_fixture_matched_creates_benign_test_label(self) -> None:
        """benign_lab_fixture_matched in policy_reason_codes does create benign-test label."""
        rec = _make_valid_incident_record(
            risk_score=0,
            policy_reason_codes=("benign_lab_fixture_matched",),
        )
        req = build_ticket_request(rec, self.config_default)
        self.assertIn("benign-test", req.labels)

    def test_approval_and_simulation_labels_derived_deterministically(self) -> None:
        # Critical approved simulated record
        rec_approved = _make_valid_incident_record(
            risk_level="CRITICAL",
            approval_status=IncidentApprovalStatus.APPROVED.value,
            simulation_status=SimulationStatus.SIMULATED.value,
        )
        req_approved = build_ticket_request(rec_approved, self.config_default)
        self.assertIn("human-approved", req_approved.labels)
        self.assertIn("simulated-containment", req_approved.labels)
        self.assertNotIn("human-denied", req_approved.labels)
        self.assertNotIn("action-not-executed", req_approved.labels)

        # Critical denied not-executed record
        rec_denied = _make_valid_incident_record(
            risk_level="CRITICAL",
            approval_status=IncidentApprovalStatus.DENIED.value,
            simulation_status=SimulationStatus.NOT_EXECUTED.value,
        )
        req_denied = build_ticket_request(rec_denied, self.config_default)
        self.assertIn("human-denied", req_denied.labels)
        self.assertIn("action-not-executed", req_denied.labels)
        self.assertNotIn("human-approved", req_denied.labels)
        self.assertNotIn("simulated-containment", req_denied.labels)

    def test_decoded_command_excluded_by_default(self) -> None:
        rec = _make_valid_incident_record(
            decoded_command="Write-Host 'SECRET_OR_PAYLOAD'",
        )
        req = build_ticket_request(rec, self.config_default)
        self.assertNotIn("Write-Host 'SECRET_OR_PAYLOAD'", req.description)
        self.assertNotIn("BEGIN UNTRUSTED EVIDENCE", req.description)

    def test_decoded_command_included_only_when_explicitly_enabled(self) -> None:
        rec = _make_valid_incident_record(
            decoded_command="Write-Host 'SECRET_OR_PAYLOAD'",
        )
        req = build_ticket_request(rec, self.config_with_evidence)
        self.assertIn("--- BEGIN UNTRUSTED EVIDENCE (INERT TEXT ONLY) ---", req.description)
        self.assertIn("Write-Host 'SECRET_OR_PAYLOAD'", req.description)
        self.assertIn("--- END UNTRUSTED EVIDENCE ---", req.description)

    def test_max_size_decoded_command_preserves_boundary_markers_and_stays_bounded(self) -> None:
        """Near/max-size decoded command is truncated within evidence budget, preserving BEGIN and END markers."""
        large_command = "A" * 4096  # MAX_DECODED_COMMAND_LENGTH in IncidentRecord
        rec = _make_valid_incident_record(
            decoded_command=large_command,
        )
        req = build_ticket_request(rec, self.config_with_evidence)

        self.assertLessEqual(len(req.description), 4096)
        self.assertIn("--- BEGIN UNTRUSTED EVIDENCE (INERT TEXT ONLY) ---", req.description)
        self.assertIn("--- END UNTRUSTED EVIDENCE ---", req.description)
        self.assertIn("[EVIDENCE TRUNCATED]", req.description)
        self.assertTrue(req.description.rstrip().endswith("--- END UNTRUSTED EVIDENCE ---"))

    def test_max_size_decoded_command_excluded_by_default(self) -> None:
        """Default config with max-size decoded command excludes evidence completely and remains within 4096."""
        large_command = "A" * 4096
        rec = _make_valid_incident_record(
            decoded_command=large_command,
        )
        req = build_ticket_request(rec, self.config_default)

        self.assertLessEqual(len(req.description), 4096)
        self.assertNotIn("--- BEGIN UNTRUSTED EVIDENCE", req.description)
        self.assertNotIn("--- END UNTRUSTED EVIDENCE", req.description)
        self.assertNotIn("[EVIDENCE TRUNCATED]", req.description)

    def test_insufficient_budget_omits_evidence_block_entirely(self) -> None:
        """If there is insufficient budget even for the structural evidence block, omit evidence block entirely."""
        with patch("investigator.ticketing.MAX_DESCRIPTION_LENGTH", 300):
            rec = _make_valid_incident_record(
                decoded_command="Write-Host 'OMITTED_DUE_TO_BUDGET'",
            )
            req = build_ticket_request(rec, self.config_with_evidence)
            self.assertLessEqual(len(req.description), 300)
            self.assertNotIn("--- BEGIN UNTRUSTED EVIDENCE", req.description)
            self.assertNotIn("--- END UNTRUSTED EVIDENCE", req.description)
            self.assertNotIn("OMITTED_DUE_TO_BUDGET", req.description)

    def test_positive_budget_smaller_than_truncation_marker_omits_evidence_block(self) -> None:
        """When 0 < available_budget < len(EVIDENCE_TRUNCATION_MARKER), evidence block is omitted entirely."""
        rec = _make_valid_incident_record(
            decoded_command="Write-Host 'SHOULD_BE_OMITTED_DUE_TO_MARKER_BUDGET'",
        )
        base_req = build_ticket_request(rec, self.config_default)
        base_len = len(base_req.description)
        overhead = 113  # len(evidence_prefix) + len(evidence_suffix)
        budget = 8      # 0 < 8 < len(EVIDENCE_TRUNCATION_MARKER) (21)
        test_max_len = base_len + overhead + budget

        with patch("investigator.ticketing.MAX_DESCRIPTION_LENGTH", test_max_len):
            req = build_ticket_request(rec, self.config_with_evidence)
            self.assertLessEqual(len(req.description), test_max_len)
            self.assertNotIn("--- BEGIN UNTRUSTED EVIDENCE", req.description)
            self.assertNotIn("--- END UNTRUSTED EVIDENCE", req.description)
            self.assertNotIn("SHOULD_BE_OMITTED_DUE_TO_MARKER_BUDGET", req.description)





class TestTicketingSecurityBoundaries(unittest.TestCase):
    """Verify security isolation: zero subprocess, socket, network, or secrets."""

    def test_no_forbidden_modules_imported(self) -> None:
        from pathlib import Path
        import investigator.ticketing as ticketing_module
        module_text = Path(ticketing_module.__file__).read_text(encoding="utf-8")

        self.assertNotIn("import subprocess", module_text)
        self.assertNotIn("from subprocess import", module_text)
        self.assertNotIn("os.system", module_text)
        self.assertNotIn("import socket", module_text)
        self.assertNotIn("from socket import", module_text)
        self.assertNotIn("import urllib", module_text)
        self.assertNotIn("import requests", module_text)
        self.assertNotIn("import http", module_text)
        self.assertNotIn("import aiohttp", module_text)
        self.assertNotIn("eval(", module_text)
        self.assertNotIn("exec(", module_text)


if __name__ == "__main__":
    unittest.main()
