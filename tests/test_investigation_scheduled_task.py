"""Focused offline unit and integration tests for DET-TASK-001.

Milestone 18B-3: Scheduled Task Investigation & Policy Integration.

Security Invariants Tested:
1. InvestigationInput: Generic process telemetry schema accepts scheduled-task evidence.
2. MITRE Authority: DET-TASK-001 maps deterministically to T1053.005; untrusted model text
   cannot override or forge authoritative MITRE technique mapping.
3. Deterministic Policy:
   - Canonical scheduled-task evidence evaluates deterministically according to predefined weights.
   - Base detection (+25) and authoritative MITRE (+10) produce raw score 35 (MEDIUM / REQUEST_HUMAN_REVIEW)
     without model advisory.
   - With high-confidence advisory model (indicators >= 1 (+20), indicators > 1 (+5), high confidence (+10)),
     produces raw score 70 (HIGH / CREATE_INCIDENT_RECORD / HUMAN_REVIEW).
   - Approval is NOT required (requires_human_approval=False).
   - Benign model narrative claiming "safe admin task" cannot force NO_ACTION or lower score.
   - Model recommended action cannot dictate proposed action.
4. IncidentRecord:
   - Persists DET-TASK-001, DC01, T1053.005, policy reasons, and approval/simulation statuses.
   - Zero containment authority is claimed.
5. Audit Trail:
   - Standard investigation lifecycle events are recorded.
   - No approval events or simulated containment events appear when not required.
6. Ticketing:
   - Generic ticket request builds cleanly with priority HIGH, appropriate labels, and zero containment.
7. ToolRouter:
   - bounded_splunk_search supports scheduled_task_creation_matches.
8. Regressions:
   - DET-POWERSHELL-001 and DET-POWERSHELL-002 policy evaluation behaviors remain identical.
"""

from datetime import datetime, timezone
import io
import json
from pathlib import Path
import tempfile
from typing import Dict, List, Optional
import unittest

from investigator.audit import AuditEvent, AuditEventType, AuditLog
from investigator.incident_record import (
    IncidentApprovalStatus,
    IncidentJsonWriter,
    IncidentRecord,
    build_incident_record,
)
from investigator.model import (
    DecisionType,
    ModelDecision,
    ToolRequest,
)
from investigator.orchestrator import InvestigationOrchestrator
from investigator.policy import (
    BENIGN_LAB_DETECTION_ID,
    DET_POWERSHELL_002,
    DET_TASK_001,
    EXACT_BENIGN_COMMAND,
    ActionDisposition,
    PolicyContext,
    PolicyDecision,
    PolicyEngineError,
    ProposedAction,
    RiskLevel,
    RiskPolicyEngine,
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
    TicketConfig,
    TicketPriority,
    build_ticket_request,
)
from investigator.tool_router import (
    ALLOWED_SPLUNK_QUERY_TYPES,
    ToolRouter,
    ToolValidationError,
)
from investigator.tools.mitre_mapper import map_detection_to_mitre
from scripts.run_end_to_end_demo import (
    generate_synthetic_incident_id,
    run_demo,
)


class FakeScriptedModel:
    """Deterministic scripted model returning a sequence of decisions."""

    def __init__(self, decisions: List[ModelDecision]) -> None:
        self._decisions = list(decisions)
        self._index = 0

    def decide(self, request) -> ModelDecision:
        if self._index >= len(self._decisions):
            raise RuntimeError("Model decisions exhausted")
        decision = self._decisions[self._index]
        self._index += 1
        return decision


def _make_scheduled_task_alert(
    incident_id: str = "INC-TASK-TEST-001",
    detection_id: str = DET_TASK_001,
    detection_name: str = "suspicious scheduled task creation",
    command_line: str = (
        "schtasks.exe /create /tn SecurityHealthFix /tr C:\\Windows\\Temp\\update.bat "
        "/sc daily /st 09:00 /f"
    ),
    host: str = "DC01",
    user: str = "SYSTEM",
) -> InvestigationInput:
    """Helper creating a canonical scheduled-task alert."""
    return InvestigationInput(
        incident_id=incident_id,
        timestamp="2026-10-15T10:00:00Z",
        host=host,
        user=user,
        image="C:\\Windows\\System32\\schtasks.exe",
        command_line=command_line,
        parent_image="C:\\Windows\\System32\\cmd.exe",
        parent_command_line="cmd.exe /c update.bat",
        detection_name=detection_name,
        detection_id=detection_id,
    )


def _make_scheduled_task_advisory_result(
    incident_id: str = "INC-TASK-TEST-001",
    confidence: str = "high",
    indicators: tuple = ("scheduled_task_persistence", "temp_directory_target"),
    recommended_step: str = "Review scheduled task properties and verify binary integrity.",
    summary: str = "Scheduled task creation observed targeting temporary batch file.",
) -> InvestigationResult:
    """Helper creating an advisory model result for scheduled tasks."""
    return InvestigationResult(
        summary=summary,
        observations=(
            "schtasks.exe /create executed on DC01",
            "Target program is in C:\\Windows\\Temp\\",
        ),
        decoded_command=None,
        mitre_techniques=("T1053.005",),
        suspicious_indicators=indicators,
        recommended_next_step=recommended_step,
        confidence_level=confidence,
        evidence_refs=(incident_id,),
    )


class TestInvestigationScheduledTaskInput(unittest.TestCase):
    """A. Investigation input schema tests for scheduled tasks."""

    def test_scheduled_task_telemetry_accepted_without_schema_modification(self) -> None:
        alert = _make_scheduled_task_alert()
        self.assertEqual(alert.detection_id, "DET-TASK-001")
        self.assertEqual(alert.host, "DC01")
        self.assertEqual(alert.user, "SYSTEM")
        self.assertEqual(alert.image, "C:\\Windows\\System32\\schtasks.exe")
        self.assertIn("/create", alert.command_line)
        self.assertEqual(alert.parent_image, "C:\\Windows\\System32\\cmd.exe")

    def test_empty_or_whitespace_scheduled_task_fields_fail_validation(self) -> None:
        with self.assertRaises(ValueError):
            _make_scheduled_task_alert(command_line="   ")


class TestScheduledTaskMitreAuthority(unittest.TestCase):
    """B. MITRE mapping authority tests."""

    def test_det_task_001_authoritative_mapping_to_t1053_005(self) -> None:
        mapping = map_detection_to_mitre("suspicious scheduled task creation", fail_closed=True)
        self.assertTrue(mapping.mapped)
        self.assertEqual(mapping.technique_id, "T1053.005")
        self.assertEqual(mapping.technique_name, "Scheduled Task/Job: Scheduled Task")
        self.assertEqual(mapping.tactic_id, "TA0003")
        self.assertEqual(mapping.tactic_name, "Persistence")

    def test_untrusted_model_cannot_replace_authoritative_mitre_mapping(self) -> None:
        engine = RiskPolicyEngine()
        alert = _make_scheduled_task_alert()
        context = PolicyContext(
            alert=alert,
            verified_detection_id=DET_TASK_001,
            deterministic_decoded_command=None,
            mitre_technique_id="T1053.005",
            tool_failure_or_incomplete_evidence=False,
        )
        # Model claims an unrelated or fabricated MITRE technique
        model_result = _make_scheduled_task_advisory_result()
        object.__setattr__(model_result, "mitre_techniques", ("T1059.001", "T9999"))

        decision = engine.evaluate(context, model_result)
        # Policy evaluates ONLY the trusted context.mitre_technique_id ("T1053.005")
        self.assertIn("mitre_t1053_005", decision.reasons)
        self.assertNotIn("mitre_t1059_001", decision.reasons)


class TestScheduledTaskPolicy(unittest.TestCase):
    """C. Deterministic policy scoring and governance tests."""

    def setUp(self) -> None:
        self.engine = RiskPolicyEngine()
        self.alert = _make_scheduled_task_alert()

    def test_canonical_scheduled_task_policy_outcome_with_advisory_model(self) -> None:
        """Canonical outcome: Base (25) + MITRE (10) + ind>=1 (20) + ind>1 (5) + conf-high (10) = 70.

        Risk Level: HIGH (50-74)
        Action Disposition: HUMAN_REVIEW
        Proposed Action: CREATE_INCIDENT_RECORD
        Approval Required: False (no consequential containment)
        """
        context = PolicyContext(
            alert=self.alert,
            verified_detection_id=DET_TASK_001,
            deterministic_decoded_command=None,
            mitre_technique_id="T1053.005",
            tool_failure_or_incomplete_evidence=False,
        )
        model_result = _make_scheduled_task_advisory_result(
            confidence="high",
            indicators=("scheduled_task_persistence", "temp_directory_target"),
        )
        decision = self.engine.evaluate(context, model_result)

        self.assertEqual(decision.risk_score, 70)
        self.assertEqual(decision.risk_level, RiskLevel.HIGH)
        self.assertEqual(decision.action_disposition, ActionDisposition.HUMAN_REVIEW)
        self.assertEqual(decision.proposed_action, ProposedAction.CREATE_INCIDENT_RECORD)
        self.assertFalse(decision.requires_human_approval)
        self.assertEqual(
            decision.reasons,
            (
                "scheduled_task_creation_detected",
                "mitre_t1053_005",
                "suspicious_indicators_present",
                "multiple_suspicious_indicators",
                "model_confidence_high",
            ),
        )

    def test_canonical_scheduled_task_policy_outcome_without_advisory_model(self) -> None:
        """Raw outcome: Base (25) + MITRE (10) = 35.

        Risk Level: MEDIUM (25-49)
        Action Disposition: HUMAN_REVIEW
        Proposed Action: REQUEST_HUMAN_REVIEW
        Approval Required: False
        """
        context = PolicyContext(
            alert=self.alert,
            verified_detection_id=DET_TASK_001,
            deterministic_decoded_command=None,
            mitre_technique_id="T1053.005",
            tool_failure_or_incomplete_evidence=False,
        )
        decision = self.engine.evaluate(context, None)

        self.assertEqual(decision.risk_score, 35)
        self.assertEqual(decision.risk_level, RiskLevel.MEDIUM)
        self.assertEqual(decision.action_disposition, ActionDisposition.HUMAN_REVIEW)
        self.assertEqual(decision.proposed_action, ProposedAction.REQUEST_HUMAN_REVIEW)
        self.assertFalse(decision.requires_human_approval)
        self.assertEqual(
            decision.reasons,
            ("scheduled_task_creation_detected", "mitre_t1053_005"),
        )

    def test_benign_model_narrative_cannot_force_no_action(self) -> None:
        """Advisory model narrative claiming 'benign administrative script' cannot zero out score."""
        context = PolicyContext(
            alert=self.alert,
            verified_detection_id=DET_TASK_001,
            deterministic_decoded_command=None,
            mitre_technique_id="T1053.005",
            tool_failure_or_incomplete_evidence=False,
        )
        # Model gives 0 indicators, low confidence, claims benign
        benign_result = _make_scheduled_task_advisory_result(
            confidence="low",
            indicators=(),
            recommended_step="no_action - benign routine maintenance",
            summary="Routine IT maintenance scheduled task.",
        )
        decision = self.engine.evaluate(context, benign_result)

        # Base detection (25) and MITRE (10) remain strictly additive
        self.assertEqual(decision.risk_score, 35)
        self.assertEqual(decision.risk_level, RiskLevel.MEDIUM)
        self.assertEqual(decision.proposed_action, ProposedAction.REQUEST_HUMAN_REVIEW)
        self.assertNotIn("benign_lab_fixture_matched", decision.reasons)

    def test_model_recommended_action_cannot_override_proposed_action(self) -> None:
        """Model recommending isolate_endpoint cannot force SIMULATE_ENDPOINT_ISOLATION or approval."""
        context = PolicyContext(
            alert=self.alert,
            verified_detection_id=DET_TASK_001,
            deterministic_decoded_command=None,
            mitre_technique_id="T1053.005",
            tool_failure_or_incomplete_evidence=False,
        )
        model_result = _make_scheduled_task_advisory_result(
            confidence="high",
            indicators=("scheduled_task_persistence", "temp_directory_target"),
            recommended_step="simulate_endpoint_isolation immediately!",
        )
        decision = self.engine.evaluate(context, model_result)

        # Score is 70 (HIGH), which maps deterministically to CREATE_INCIDENT_RECORD
        self.assertEqual(decision.proposed_action, ProposedAction.CREATE_INCIDENT_RECORD)
        self.assertEqual(decision.action_disposition, ActionDisposition.HUMAN_REVIEW)
        self.assertFalse(decision.requires_human_approval)


    def test_incomplete_evidence_uncertainty_escalates_score_by_15(self) -> None:
        """If tool_failure_or_incomplete_evidence is True, score adds 15."""
        context = PolicyContext(
            alert=self.alert,
            verified_detection_id=DET_TASK_001,
            deterministic_decoded_command=None,
            mitre_technique_id="T1053.005",
            tool_failure_or_incomplete_evidence=True,
        )
        decision = self.engine.evaluate(context, None)
        # Base (25) + MITRE (10) + Incomplete (15) = 50 -> HIGH
        self.assertEqual(decision.risk_score, 50)
        self.assertEqual(decision.risk_level, RiskLevel.HIGH)
        self.assertIn("incomplete_evidence_uncertainty", decision.reasons)
        self.assertIn("fail_closed_incomplete_evidence", decision.reasons)


class TestScheduledTaskIncidentRecord(unittest.TestCase):
    """D. IncidentRecord integration tests."""

    def test_incident_record_builds_and_serializes_successfully(self) -> None:
        alert = _make_scheduled_task_alert()
        inv_result = _make_scheduled_task_advisory_result()
        policy_decision = PolicyDecision(
            risk_score=70,
            risk_level=RiskLevel.HIGH,
            action_disposition=ActionDisposition.HUMAN_REVIEW,
            proposed_action=ProposedAction.CREATE_INCIDENT_RECORD,
            reasons=(
                "scheduled_task_creation_detected",
                "mitre_t1053_005",
                "suspicious_indicators_present",
                "multiple_suspicious_indicators",
                "model_confidence_high",
            ),
            requires_human_approval=False,
        )
        sim_result = SimulationResult(
            incident_id=alert.incident_id,
            status=SimulationStatus.NOT_EXECUTED,
            proposed_action=ProposedAction.CREATE_INCIDENT_RECORD,
            detail_code="incident_record_deferred",
        )

        record = build_incident_record(
            investigation_input=alert,
            investigation_result=inv_result,
            policy_decision=policy_decision,
            simulation_result=sim_result,
            approval_record=None,
            evidence_source="Sanitized Local Synthetic Fixture",
            deterministic_decoded_command=None,
            mitre_technique_id="T1053.005",
        )

        self.assertEqual(record.detection_id, "DET-TASK-001")
        self.assertEqual(record.target_host, "DC01")
        self.assertEqual(record.target_user, "SYSTEM")
        self.assertEqual(record.mitre_technique_id, "T1053.005")
        self.assertEqual(record.risk_score, 70)
        self.assertEqual(record.risk_level, "HIGH")
        self.assertEqual(record.disposition, "HUMAN_REVIEW")
        self.assertEqual(record.proposed_action, "create_incident_record")
        self.assertFalse(record.requires_human_approval)
        self.assertEqual(record.approval_status, IncidentApprovalStatus.NOT_REQUIRED.value)
        self.assertEqual(record.simulation_status, SimulationStatus.NOT_EXECUTED.value)

        # Atomic persistence test
        with tempfile.TemporaryDirectory() as tmpdir:
            writer = IncidentJsonWriter(Path(tmpdir))
            filepath = writer.write_record(record, overwrite=False)
            self.assertTrue(filepath.exists())
            content = json.loads(filepath.read_text(encoding="utf-8"))
            self.assertEqual(content["detection_id"], "DET-TASK-001")
            self.assertEqual(content["mitre_technique_id"], "T1053.005")
            self.assertIn("scheduled_task_creation_detected", content["policy_reason_codes"])
            loaded = IncidentRecord.from_dict(content)
            self.assertEqual(loaded.detection_id, "DET-TASK-001")
            self.assertEqual(loaded.mitre_technique_id, "T1053.005")


class TestScheduledTaskAuditAndTicketing(unittest.TestCase):
    """E & F. Audit and Ticketing integration tests."""

    def test_audit_lifecycle_records_expected_events_without_approval(self) -> None:
        audit_log = AuditLog()
        alert = _make_scheduled_task_alert()
        engine = RiskPolicyEngine()
        context = PolicyContext(
            alert=alert,
            verified_detection_id=DET_TASK_001,
            deterministic_decoded_command=None,
            mitre_technique_id="T1053.005",
            tool_failure_or_incomplete_evidence=False,
        )
        inv_result = _make_scheduled_task_advisory_result()
        decision = engine.evaluate(context, inv_result, audit_log=audit_log)

        events = audit_log.events()
        # Should record POLICY_EVALUATED
        self.assertTrue(any(e.event_type == AuditEventType.POLICY_EVALUATED for e in events))
        # Should NOT record APPROVAL_REQUIRED because decision does not require approval
        self.assertFalse(any(e.event_type == AuditEventType.APPROVAL_REQUIRED for e in events))
        self.assertFalse(decision.requires_human_approval)

    def test_ticketing_payload_accepts_det_task_001_cleanly(self) -> None:
        alert = _make_scheduled_task_alert()
        inv_result = _make_scheduled_task_advisory_result()
        policy_decision = PolicyDecision(
            risk_score=70,
            risk_level=RiskLevel.HIGH,
            action_disposition=ActionDisposition.HUMAN_REVIEW,
            proposed_action=ProposedAction.CREATE_INCIDENT_RECORD,
            reasons=(
                "scheduled_task_creation_detected",
                "mitre_t1053_005",
                "suspicious_indicators_present",
                "multiple_suspicious_indicators",
                "model_confidence_high",
            ),
            requires_human_approval=False,
        )
        sim_result = SimulationResult(
            incident_id=alert.incident_id,
            status=SimulationStatus.NOT_EXECUTED,
            proposed_action=ProposedAction.CREATE_INCIDENT_RECORD,
            detail_code="incident_record_deferred",
        )
        record = build_incident_record(
            investigation_input=alert,
            investigation_result=inv_result,
            policy_decision=policy_decision,
            simulation_result=sim_result,
            mitre_technique_id="T1053.005",
        )

        config = TicketConfig(
            project_key="SEC",
            issue_type="Incident",
            allowed_labels=tuple(sorted(ALLOWED_TICKET_LABELS)),
            include_decoded_command=False,
        )
        ticket_req = build_ticket_request(record, config)

        self.assertEqual(ticket_req.priority, TicketPriority.HIGH)
        self.assertIn("suspicious scheduled task creation", ticket_req.summary)
        self.assertIn("DC01", ticket_req.summary)
        self.assertIn("DET-TASK-001", ticket_req.description)
        self.assertIn("ai-native-soc", ticket_req.labels)
        self.assertIn("approval-not-required", ticket_req.labels)
        self.assertIn("action-not-executed", ticket_req.labels)

        # Dispatch with FakeTicketClient
        client = FakeTicketClient()
        res = client.create_ticket(ticket_req)
        self.assertTrue(res.success)
        self.assertEqual(res.ticket_key, "SEC-0001")


class TestScheduledTaskToolRouter(unittest.TestCase):
    """ToolRouter support for scheduled task creation queries."""

    def test_query_types_allowlist_contains_scheduled_task(self) -> None:
        self.assertIn("scheduled_task_creation_matches", ALLOWED_SPLUNK_QUERY_TYPES)

    def test_tool_router_dispatches_scheduled_task_query_to_client(self) -> None:
        class FakeSplunkSearchClient:
            def search_scheduled_task_creation(self, host: str, minutes: int, limit: int):
                return [{"_time": "2026-10-15T10:00:00Z", "host": host, "Image": "schtasks.exe"}]

        router = ToolRouter(splunk_client=FakeSplunkSearchClient())
        result = router.execute_tool(
            "bounded_splunk_search",
            {"query_type": "scheduled_task_creation_matches", "host": "DC01", "minutes": 15, "limit": 5},
        )
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["Image"], "schtasks.exe")


class TestEndToEndDemoSyntheticScheduledTaskMode(unittest.TestCase):
    """Integration test for scripts/run_end_to_end_demo.py --mode synthetic-scheduled-task."""

    def test_demo_harness_synthetic_scheduled_task_mode_executes_successfully(self) -> None:
        out_stream = io.StringIO()
        in_stream = io.StringIO()

        with tempfile.TemporaryDirectory() as tmpdir:
            incidents_dir = Path(tmpdir) / "incidents"
            audit_path = Path(tmpdir) / "audit.jsonl"

            ret = run_demo(
                mode="synthetic-scheduled-task",
                provider=None,
                minutes=15,
                persist_audit=True,
                write_incident=True,
                create_ticket=True,
                ticket_provider="fake",
                kill_switch=False,
                enrich_threat_intel=False,
                synthetic_incident_id="INC-TASK-DEMO-001",
                approval_mode="cli",
                audit_log_path=audit_path,
                incidents_dir=incidents_dir,
                stream_in=in_stream,
                stream_out=out_stream,
            )

            output = out_stream.getvalue()
            self.assertEqual(ret, 0, f"run_demo failed with output:\n{output}")
            self.assertIn("Detection ID:      DET-TASK-001", output)
            self.assertIn("MITRE Technique:   T1053.005", output)
            self.assertIn("Risk Score:        70 / 100", output)
            self.assertIn("Risk Level:        HIGH", output)
            self.assertIn("Proposed Action:   create_incident_record", output)
            self.assertIn("Disposition:       HUMAN_REVIEW", output)
            self.assertIn("Approval Required: no", output)
            self.assertIn("Ticket Key:        SEC-0001", output)

            # Verify persisted incident record
            incident_file = incidents_dir / "INC-TASK-DEMO-001.json"
            self.assertTrue(incident_file.exists())
            content = json.loads(incident_file.read_text(encoding="utf-8"))
            self.assertEqual(content["detection_id"], "DET-TASK-001")
            self.assertEqual(content["mitre_technique_id"], "T1053.005")
            self.assertEqual(content["risk_score"], 70)
            self.assertEqual(content["risk_level"], "HIGH")
            self.assertEqual(content["approval_status"], "NOT_REQUIRED")


class TestRegressionSafety(unittest.TestCase):
    """G. Regression safety tests for existing detections."""

    def setUp(self) -> None:
        self.engine = RiskPolicyEngine()

    def test_det_powershell_001_exact_benign_suppression_unchanged(self) -> None:
        alert = InvestigationInput(
            incident_id="INC-REG-001",
            timestamp="2026-09-17T12:00:00Z",
            host="DC01",
            user="SYSTEM",
            image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            command_line="powershell.exe -enc V3JpdGUtSG9zdCAnQUktTmF0aXZlU09DLUxBQi1URVNURCc=",
            parent_image="C:\\Windows\\System32\\cmd.exe",
            parent_command_line="cmd.exe /c test",
            detection_name="suspicious encoded powershell execution",
            detection_id=BENIGN_LAB_DETECTION_ID,
        )
        ctx = PolicyContext(
            alert=alert,
            verified_detection_id=BENIGN_LAB_DETECTION_ID,
            deterministic_decoded_command=EXACT_BENIGN_COMMAND,
            mitre_technique_id="T1059.001",
            tool_failure_or_incomplete_evidence=False,
        )
        decision = self.engine.evaluate(ctx)
        self.assertEqual(decision.risk_score, 0)
        self.assertEqual(decision.risk_level, RiskLevel.LOW)
        self.assertEqual(decision.action_disposition, ActionDisposition.NO_ACTION)
        self.assertEqual(decision.proposed_action, ProposedAction.NO_ACTION)
        self.assertIn("benign_lab_fixture_matched", decision.reasons)

    def test_det_powershell_002_scoring_unchanged(self) -> None:
        alert = InvestigationInput(
            incident_id="INC-REG-002",
            timestamp="2026-09-17T12:00:00Z",
            host="DC01",
            user="SYSTEM",
            image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            command_line="powershell.exe -c Invoke-WebRequest http://127.0.0.1:65535/AI-NativeSOC-LAB-TEST",
            parent_image="C:\\Windows\\System32\\cmd.exe",
            parent_command_line="cmd.exe /c test",
            detection_name="suspicious_powershell_network_retrieval",
            detection_id=DET_POWERSHELL_002,
        )
        ctx = PolicyContext(
            alert=alert,
            verified_detection_id=DET_POWERSHELL_002,
            deterministic_decoded_command=None,
            mitre_technique_id="T1105",
            tool_failure_or_incomplete_evidence=False,
        )
        decision = self.engine.evaluate(ctx)
        # Base (25) + MITRE (10) = 35 -> MEDIUM
        self.assertEqual(decision.risk_score, 35)
        self.assertEqual(decision.risk_level, RiskLevel.MEDIUM)
        self.assertEqual(decision.action_disposition, ActionDisposition.HUMAN_REVIEW)
        self.assertEqual(decision.proposed_action, ProposedAction.REQUEST_HUMAN_REVIEW)
        self.assertIn("powershell_network_retrieval_detected", decision.reasons)
        self.assertIn("mitre_t1105", decision.reasons)


class TestSyntheticIncidentIdCompatibility(unittest.TestCase):
    """Compatibility tests for generate_synthetic_incident_id."""

    def test_zero_argument_call_preserves_default_crit_prefix(self) -> None:
        """1. Zero-argument call maintains INC-DEMO-CRIT-... prefix."""
        incident_id = generate_synthetic_incident_id()
        self.assertTrue(incident_id.startswith("INC-DEMO-CRIT-"))
        self.assertLessEqual(len(incident_id), 64)

    def test_clock_injection_positional_preserves_semantics(self) -> None:
        """2. Existing positional clock argument preserves timestamp injection."""
        fixed_time = datetime(2026, 9, 20, 14, 30, 45, 123456, tzinfo=timezone.utc)
        incident_id = generate_synthetic_incident_id(lambda: fixed_time)
        self.assertEqual(incident_id, "INC-DEMO-CRIT-20260920T143045123456Z")

    def test_clock_injection_keyword_preserves_semantics(self) -> None:
        """2b. Existing keyword clock argument preserves timestamp injection."""
        fixed_time = datetime(2026, 9, 20, 14, 30, 45, 123456, tzinfo=timezone.utc)
        incident_id = generate_synthetic_incident_id(clock=lambda: fixed_time)
        self.assertEqual(incident_id, "INC-DEMO-CRIT-20260920T143045123456Z")

    def test_scheduled_task_prefix_generates_expected_prefix(self) -> None:
        """3. Scheduled-task prefix generates INC-DEMO-TASK-... format."""
        fixed_time = datetime(2026, 10, 15, 10, 0, 0, 0, tzinfo=timezone.utc)
        incident_id = generate_synthetic_incident_id(
            clock=lambda: fixed_time,
            prefix="INC-DEMO-TASK",
        )
        self.assertEqual(incident_id, "INC-DEMO-TASK-20261015T100000000000Z")

    def test_id_length_bounded_within_64_characters(self) -> None:
        """4. Generated incident ID strictly satisfies length bound <= 64."""
        fixed_time = datetime(2026, 12, 31, 23, 59, 59, 999999, tzinfo=timezone.utc)
        id_crit = generate_synthetic_incident_id(clock=lambda: fixed_time)
        id_task = generate_synthetic_incident_id(clock=lambda: fixed_time, prefix="INC-DEMO-TASK")
        self.assertLessEqual(len(id_crit), 64)
        self.assertLessEqual(len(id_task), 64)
        import re
        safe_pattern = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
        self.assertTrue(safe_pattern.match(id_crit))
        self.assertTrue(safe_pattern.match(id_task))


if __name__ == "__main__":
    unittest.main()
