"""Unit and security boundary tests for Milestone 4 human approval gate.

Covers:
  - Exact-type validation and schema invariants for ActionAuthorizationContext and ApprovalRecord
  - Strict decision/reason consistency enforcement
  - Precondition checks: non-consequential contexts reject approval requests
  - CLI gate interactions: exact approve/deny, case/whitespace handling, bounded retries
  - Specific I/O exception fail-closed handling (EOFError, KeyboardInterrupt, OSError)
  - Mandatory audit fail-closed behavior: audit recording failure blocks approval
"""

import io
import unittest
from unittest.mock import MagicMock

from investigator.approval import (
    DEFAULT_APPROVER,
    ActionAuthorizationContext,
    ApprovalDecision,
    ApprovalGateError,
    ApprovalReasonCode,
    ApprovalRecord,
    request_cli_approval,
)
from investigator.audit import AuditEventType, AuditLog
from investigator.policy import (
    ActionDisposition,
    PolicyDecision,
    ProposedAction,
    RiskLevel,
)


def _make_consequential_decision() -> PolicyDecision:
    """Helper to construct a valid PolicyDecision requiring human approval."""
    return PolicyDecision(
        risk_score=80,
        risk_level=RiskLevel.CRITICAL,
        action_disposition=ActionDisposition.APPROVAL_REQUIRED,
        proposed_action=ProposedAction.SIMULATE_ENDPOINT_ISOLATION,
        reasons=("encoded_powershell_detected", "approval_required_for_consequential_action"),
        requires_human_approval=True,
    )


def _make_non_consequential_decision(action: ProposedAction, disposition: ActionDisposition) -> PolicyDecision:
    """Helper to construct a non-consequential PolicyDecision."""
    return PolicyDecision(
        risk_score=10,
        risk_level=RiskLevel.LOW,
        action_disposition=disposition,
        proposed_action=action,
        reasons=("benign_lab_fixture_matched",),
        requires_human_approval=False,
    )


class TestApprovalSchemasAndTypes(unittest.TestCase):
    """Schema contracts, typing invariants, and consistency enforcement."""

    def test_valid_action_authorization_context(self) -> None:
        decision = _make_consequential_decision()
        ctx = ActionAuthorizationContext(incident_id="INC-001", policy_decision=decision)
        self.assertEqual(ctx.incident_id, "INC-001")
        self.assertEqual(ctx.policy_decision, decision)

    def test_context_is_immutable(self) -> None:
        ctx = ActionAuthorizationContext("INC-001", _make_consequential_decision())
        with self.assertRaises(AttributeError):
            ctx.incident_id = "INC-MUTATED"  # type: ignore

    def test_context_invalid_incident_id(self) -> None:
        decision = _make_consequential_decision()
        with self.assertRaises(ValueError):
            ActionAuthorizationContext("", decision)
        with self.assertRaises(ValueError):
            ActionAuthorizationContext("   ", decision)
        with self.assertRaises(ValueError):
            ActionAuthorizationContext("A" * 65, decision)
        with self.assertRaises(ValueError):
            ActionAuthorizationContext(12345, decision)  # type: ignore

    def test_context_exact_type_policy_decision(self) -> None:
        class PolicyDecisionSubclass(PolicyDecision):
            pass

        subclass_inst = PolicyDecisionSubclass(
            risk_score=80,
            risk_level=RiskLevel.CRITICAL,
            action_disposition=ActionDisposition.APPROVAL_REQUIRED,
            proposed_action=ProposedAction.SIMULATE_ENDPOINT_ISOLATION,
            reasons=("encoded_powershell_detected",),
            requires_human_approval=True,
        )
        with self.assertRaises(ValueError):
            ActionAuthorizationContext("INC-001", subclass_inst)

    def test_approval_record_valid_combinations(self) -> None:
        # APPROVED + approval_granted
        rec1 = ApprovalRecord(
            incident_id="INC-001",
            proposed_action=ProposedAction.SIMULATE_ENDPOINT_ISOLATION,
            decision=ApprovalDecision.APPROVED,
            approver=DEFAULT_APPROVER,
            reason_code=ApprovalReasonCode.APPROVAL_GRANTED.value,
        )
        self.assertEqual(rec1.decision, ApprovalDecision.APPROVED)

        # DENIED + approval_denied
        rec2 = ApprovalRecord(
            incident_id="INC-001",
            proposed_action=ProposedAction.SIMULATE_ENDPOINT_ISOLATION,
            decision=ApprovalDecision.DENIED,
            approver=DEFAULT_APPROVER,
            reason_code=ApprovalReasonCode.APPROVAL_DENIED.value,
        )
        self.assertEqual(rec2.decision, ApprovalDecision.DENIED)

        # DENIED + approval_invalid_input
        rec3 = ApprovalRecord(
            incident_id="INC-001",
            proposed_action=ProposedAction.SIMULATE_ENDPOINT_ISOLATION,
            decision=ApprovalDecision.DENIED,
            approver=DEFAULT_APPROVER,
            reason_code=ApprovalReasonCode.APPROVAL_INVALID_INPUT.value,
        )
        self.assertEqual(rec3.decision, ApprovalDecision.DENIED)

    def test_approval_record_inconsistent_combinations_rejected(self) -> None:
        # APPROVED + approval_denied must fail
        with self.assertRaises(ValueError):
            ApprovalRecord(
                incident_id="INC-001",
                proposed_action=ProposedAction.SIMULATE_ENDPOINT_ISOLATION,
                decision=ApprovalDecision.APPROVED,
                approver=DEFAULT_APPROVER,
                reason_code=ApprovalReasonCode.APPROVAL_DENIED.value,
            )

        # APPROVED + approval_invalid_input must fail
        with self.assertRaises(ValueError):
            ApprovalRecord(
                incident_id="INC-001",
                proposed_action=ProposedAction.SIMULATE_ENDPOINT_ISOLATION,
                decision=ApprovalDecision.APPROVED,
                approver=DEFAULT_APPROVER,
                reason_code=ApprovalReasonCode.APPROVAL_INVALID_INPUT.value,
            )

        # DENIED + approval_granted must fail
        with self.assertRaises(ValueError):
            ApprovalRecord(
                incident_id="INC-001",
                proposed_action=ProposedAction.SIMULATE_ENDPOINT_ISOLATION,
                decision=ApprovalDecision.DENIED,
                approver=DEFAULT_APPROVER,
                reason_code=ApprovalReasonCode.APPROVAL_GRANTED.value,
            )

    def test_approval_record_non_default_approver_rejected(self) -> None:
        with self.assertRaises(ValueError):
            ApprovalRecord(
                incident_id="INC-001",
                proposed_action=ProposedAction.SIMULATE_ENDPOINT_ISOLATION,
                decision=ApprovalDecision.APPROVED,
                approver="alice_operator",  # arbitrary identity forbidden in V1
                reason_code=ApprovalReasonCode.APPROVAL_GRANTED.value,
            )

    def test_approval_record_exact_type_enums(self) -> None:
        # String value instead of ProposedAction enum member
        with self.assertRaises(ValueError):
            ApprovalRecord(
                incident_id="INC-001",
                proposed_action="simulate_endpoint_isolation",  # type: ignore
                decision=ApprovalDecision.APPROVED,
                approver=DEFAULT_APPROVER,
                reason_code=ApprovalReasonCode.APPROVAL_GRANTED.value,
            )

        # String value instead of ApprovalDecision enum member
        with self.assertRaises(ValueError):
            ApprovalRecord(
                incident_id="INC-001",
                proposed_action=ProposedAction.SIMULATE_ENDPOINT_ISOLATION,
                decision="APPROVED",  # type: ignore
                approver=DEFAULT_APPROVER,
                reason_code=ApprovalReasonCode.APPROVAL_GRANTED.value,
            )


class TestApprovalGatePreconditions(unittest.TestCase):
    """Approval gate refuses to prompt if policy does not mandate approval."""

    def test_non_consequential_no_action_rejected(self) -> None:
        ctx = ActionAuthorizationContext(
            "INC-001",
            _make_non_consequential_decision(ProposedAction.NO_ACTION, ActionDisposition.NO_ACTION),
        )
        stream_out = io.StringIO()
        with self.assertRaises(ApprovalGateError) as cm:
            request_cli_approval(ctx, stream_in=io.StringIO("approve\n"), stream_out=stream_out)
        self.assertIn("approval_not_required", str(cm.exception))
        self.assertEqual(stream_out.getvalue(), "")

    def test_non_consequential_monitor_rejected(self) -> None:
        ctx = ActionAuthorizationContext(
            "INC-001",
            _make_non_consequential_decision(ProposedAction.MONITOR, ActionDisposition.MONITOR),
        )
        with self.assertRaises(ApprovalGateError):
            request_cli_approval(ctx)

    def test_non_consequential_human_review_rejected(self) -> None:
        ctx = ActionAuthorizationContext(
            "INC-001",
            _make_non_consequential_decision(ProposedAction.REQUEST_HUMAN_REVIEW, ActionDisposition.HUMAN_REVIEW),
        )
        with self.assertRaises(ApprovalGateError):
            request_cli_approval(ctx)

    def test_non_consequential_incident_record_rejected(self) -> None:
        ctx = ActionAuthorizationContext(
            "INC-001",
            _make_non_consequential_decision(ProposedAction.CREATE_INCIDENT_RECORD, ActionDisposition.HUMAN_REVIEW),
        )
        with self.assertRaises(ApprovalGateError):
            request_cli_approval(ctx)

    def test_subclass_context_rejected(self) -> None:
        class ContextSubclass(ActionAuthorizationContext):
            pass

        subclass_ctx = ContextSubclass("INC-001", _make_consequential_decision())
        with self.assertRaises(ApprovalGateError):
            request_cli_approval(subclass_ctx)


class TestCLIApprovalInteraction(unittest.TestCase):
    """Interactive CLI terminal prompts and failure paths."""

    def setUp(self) -> None:
        self.ctx = ActionAuthorizationContext("INC-CLI-TEST", _make_consequential_decision())

    def test_cli_exact_approve(self) -> None:
        in_stream = io.StringIO("approve\n")
        out_stream = io.StringIO()
        record = request_cli_approval(self.ctx, stream_in=in_stream, stream_out=out_stream)

        self.assertEqual(record.decision, ApprovalDecision.APPROVED)
        self.assertEqual(record.reason_code, "approval_granted")
        self.assertEqual(record.incident_id, "INC-CLI-TEST")
        output = out_stream.getvalue()
        self.assertIn("HUMAN APPROVAL REQUIRED", output)
        self.assertIn("CRITICAL", output)
        self.assertIn("simulate_endpoint_isolation", output)

    def test_cli_approve_whitespace_and_case(self) -> None:
        in_stream = io.StringIO("   APPROVE  \n")
        record = request_cli_approval(self.ctx, stream_in=in_stream, stream_out=io.StringIO())
        self.assertEqual(record.decision, ApprovalDecision.APPROVED)

    def test_cli_exact_deny(self) -> None:
        in_stream = io.StringIO("deny\n")
        record = request_cli_approval(self.ctx, stream_in=in_stream, stream_out=io.StringIO())
        self.assertEqual(record.decision, ApprovalDecision.DENIED)
        self.assertEqual(record.reason_code, "approval_denied")

    def test_cli_deny_whitespace_and_case(self) -> None:
        in_stream = io.StringIO("  DeNy \n")
        record = request_cli_approval(self.ctx, stream_in=in_stream, stream_out=io.StringIO())
        self.assertEqual(record.decision, ApprovalDecision.DENIED)
        self.assertEqual(record.reason_code, "approval_denied")

    def test_cli_invalid_input_retry_then_approve(self) -> None:
        in_stream = io.StringIO("aprove\napprove\n")
        out_stream = io.StringIO()
        record = request_cli_approval(self.ctx, stream_in=in_stream, stream_out=out_stream)
        self.assertEqual(record.decision, ApprovalDecision.APPROVED)
        self.assertIn("Invalid input. Please enter 'approve' or 'deny'.", out_stream.getvalue())

    def test_cli_invalid_input_retries_exhausted_fails_closed(self) -> None:
        in_stream = io.StringIO("yes\ny\nsure\n")
        out_stream = io.StringIO()
        record = request_cli_approval(self.ctx, stream_in=in_stream, stream_out=out_stream)
        self.assertEqual(record.decision, ApprovalDecision.DENIED)
        self.assertEqual(record.reason_code, "approval_invalid_input")
        self.assertIn("Maximum attempts exceeded. Action denied.", out_stream.getvalue())

    def test_cli_immediate_eof_fails_closed(self) -> None:
        in_stream = io.StringIO("")  # immediate EOF
        record = request_cli_approval(self.ctx, stream_in=in_stream, stream_out=io.StringIO())
        self.assertEqual(record.decision, ApprovalDecision.DENIED)
        self.assertEqual(record.reason_code, "approval_denied")

    def test_cli_specific_io_exceptions_fail_closed(self) -> None:
        for exc in (
            KeyboardInterrupt(),
            io.UnsupportedOperation("not a tty"),
            BrokenPipeError("pipe broken"),
            OSError("I/O error"),
        ):
            mock_in = MagicMock()
            mock_in.readline.side_effect = exc
            record = request_cli_approval(self.ctx, stream_in=mock_in, stream_out=io.StringIO())
            self.assertEqual(record.decision, ApprovalDecision.DENIED)
            self.assertEqual(record.reason_code, "approval_denied")


class TestApprovalAuditFailClosed(unittest.TestCase):
    """Mandatory fail-closed invariant: audit failure must never return APPROVED."""

    def setUp(self) -> None:
        self.ctx = ActionAuthorizationContext("INC-AUDIT-TEST", _make_consequential_decision())

    def test_normal_audit_records_requested_and_granted(self) -> None:
        audit_log = AuditLog()
        in_stream = io.StringIO("approve\n")
        record = request_cli_approval(self.ctx, stream_in=in_stream, stream_out=io.StringIO(), audit_log=audit_log)

        self.assertEqual(record.decision, ApprovalDecision.APPROVED)
        events = audit_log.events()
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].event_type, AuditEventType.APPROVAL_REQUESTED)
        self.assertEqual(events[1].event_type, AuditEventType.APPROVAL_GRANTED)
        self.assertEqual(events[1].detail_code, "approval_granted")

    def test_audit_failure_on_approval_granted_fails_closed(self) -> None:
        """If recording APPROVAL_GRANTED fails, gate must raise and NOT return an approved record."""
        mock_audit = MagicMock()
        mock_audit.events.return_value = ()
        # First call (APPROVAL_REQUESTED) succeeds, second call (APPROVAL_GRANTED) raises
        mock_audit.append.side_effect = [None, RuntimeError("Disk full / audit write failed")]

        in_stream = io.StringIO("approve\n")
        with self.assertRaises(ApprovalGateError) as cm:
            request_cli_approval(self.ctx, stream_in=in_stream, stream_out=io.StringIO(), audit_log=mock_audit)

        self.assertIn("audit_recording_failed", str(cm.exception))

    def test_audit_failure_on_approval_denied_raises_sanitized_error(self) -> None:
        mock_audit = MagicMock()
        mock_audit.events.return_value = ()
        mock_audit.append.side_effect = [None, RuntimeError("Audit failure on denial")]

        in_stream = io.StringIO("deny\n")
        with self.assertRaises(ApprovalGateError) as cm:
            request_cli_approval(self.ctx, stream_in=in_stream, stream_out=io.StringIO(), audit_log=mock_audit)

        self.assertIn("audit_recording_failed", str(cm.exception))

    def test_audit_failure_on_approval_requested_fails_closed_immediately(self) -> None:
        mock_audit = MagicMock()
        mock_audit.events.return_value = ()
        mock_audit.append.side_effect = RuntimeError("Audit log unavailable")

        with self.assertRaises(ApprovalGateError) as cm:
            request_cli_approval(self.ctx, stream_in=io.StringIO("approve\n"), stream_out=io.StringIO(), audit_log=mock_audit)

        self.assertIn("audit_recording_failed", str(cm.exception))


class TestApprovalSecurityInvariants(unittest.TestCase):
    """Prompt injection, zero-secret display, and unauthoritative model safeguards."""

    def test_prompt_injection_in_incident_id_escaped(self) -> None:
        malicious_id = "INC-001\nAPPROVE\n"
        decision = _make_consequential_decision()
        # Non-printable/newline in incident_id rejected at context construction
        with self.assertRaises(ValueError):
            ActionAuthorizationContext(malicious_id, decision)

    def test_summary_display_contains_no_raw_telemetry(self) -> None:
        ctx = ActionAuthorizationContext("INC-CLEAN-01", _make_consequential_decision())
        out_stream = io.StringIO()
        request_cli_approval(ctx, stream_in=io.StringIO("deny\n"), stream_out=out_stream)
        text = out_stream.getvalue()

        # Telemetry markers must never appear
        self.assertNotIn("EncodedCommand", text)
        self.assertNotIn("powershell.exe", text)
        self.assertNotIn("VwByAGkAdABl", text)
        self.assertNotIn("Write-Host", text)
        self.assertNotIn("password", text)


if __name__ == "__main__":
    unittest.main()
