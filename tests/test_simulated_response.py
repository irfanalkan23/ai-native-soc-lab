"""Unit and security boundary tests for Milestone 4 simulated response execution.

Covers:
  - Exact-type validation and schema invariants for SimulationResult
  - Authorization binding: incident ID match, action match, cross-incident reuse prevention
  - Consequential execution: approved -> SIMULATED; denied/missing/mismatched -> NOT_EXECUTED
  - Non-consequential actions: NO_ACTION, MONITOR, HUMAN_REVIEW, CREATE_INCIDENT_RECORD
  - Audit logging integration and fail-closed audit error handling
  - Security isolation: proof that approval and simulator modules import zero network/execution libraries
"""

import sys
import unittest
from unittest.mock import MagicMock

from investigator.approval import (
    DEFAULT_APPROVER,
    ActionAuthorizationContext,
    ApprovalDecision,
    ApprovalReasonCode,
    ApprovalRecord,
)
from investigator.audit import AuditEventType, AuditLog
from investigator.policy import (
    ActionDisposition,
    PolicyDecision,
    ProposedAction,
    RiskLevel,
)
from investigator.simulator import (
    SimulatedResponseExecutor,
    SimulationError,
    SimulationResult,
    SimulationStatus,
)


def _make_context(
    incident_id: str = "INC-SIM-001",
    action: ProposedAction = ProposedAction.SIMULATE_ENDPOINT_ISOLATION,
    disposition: ActionDisposition = ActionDisposition.APPROVAL_REQUIRED,
    requires_approval: bool = True,
) -> ActionAuthorizationContext:
    """Helper to construct ActionAuthorizationContext."""
    decision = PolicyDecision(
        risk_score=80 if requires_approval else 10,
        risk_level=RiskLevel.CRITICAL if requires_approval else RiskLevel.LOW,
        action_disposition=disposition,
        proposed_action=action,
        reasons=("encoded_powershell_detected",),
        requires_human_approval=requires_approval,
    )
    return ActionAuthorizationContext(incident_id=incident_id, policy_decision=decision)


def _make_approval(
    incident_id: str = "INC-SIM-001",
    action: ProposedAction = ProposedAction.SIMULATE_ENDPOINT_ISOLATION,
    decision: ApprovalDecision = ApprovalDecision.APPROVED,
    reason_code: str = ApprovalReasonCode.APPROVAL_GRANTED.value,
) -> ApprovalRecord:
    """Helper to construct ApprovalRecord."""
    return ApprovalRecord(
        incident_id=incident_id,
        proposed_action=action,
        decision=decision,
        approver=DEFAULT_APPROVER,
        reason_code=reason_code,
    )


class TestSimulationSchemasAndTypes(unittest.TestCase):
    """Schema validation, immutability, and exact typing for SimulationResult."""

    def test_valid_simulation_result(self) -> None:
        res = SimulationResult(
            incident_id="INC-001",
            proposed_action=ProposedAction.SIMULATE_ENDPOINT_ISOLATION,
            status=SimulationStatus.SIMULATED,
            detail_code="simulated_endpoint_isolation",
        )
        self.assertEqual(res.incident_id, "INC-001")
        self.assertEqual(res.status, SimulationStatus.SIMULATED)

    def test_simulation_result_is_immutable(self) -> None:
        res = SimulationResult(
            incident_id="INC-001",
            proposed_action=ProposedAction.SIMULATE_ENDPOINT_ISOLATION,
            status=SimulationStatus.SIMULATED,
            detail_code="simulated_endpoint_isolation",
        )
        with self.assertRaises(AttributeError):
            res.status = SimulationStatus.NOT_EXECUTED  # type: ignore

    def test_simulation_result_invalid_incident_id(self) -> None:
        with self.assertRaises(ValueError):
            SimulationResult(
                incident_id="",
                proposed_action=ProposedAction.SIMULATE_ENDPOINT_ISOLATION,
                status=SimulationStatus.SIMULATED,
                detail_code="simulated_endpoint_isolation",
            )

    def test_simulation_result_exact_types(self) -> None:
        # String instead of ProposedAction enum member
        with self.assertRaises(ValueError):
            SimulationResult(
                incident_id="INC-001",
                proposed_action="simulate_endpoint_isolation",  # type: ignore
                status=SimulationStatus.SIMULATED,
                detail_code="simulated_endpoint_isolation",
            )

        # String instead of SimulationStatus enum member
        with self.assertRaises(ValueError):
            SimulationResult(
                incident_id="INC-001",
                proposed_action=ProposedAction.SIMULATE_ENDPOINT_ISOLATION,
                status="SIMULATED",  # type: ignore
                detail_code="simulated_endpoint_isolation",
            )

    def test_simulation_result_disallowed_detail_code(self) -> None:
        with self.assertRaises(ValueError):
            SimulationResult(
                incident_id="INC-001",
                proposed_action=ProposedAction.SIMULATE_ENDPOINT_ISOLATION,
                status=SimulationStatus.SIMULATED,
                detail_code="arbitrary_unallowlisted_detail",
            )


class TestSimulationAuthorizationBinding(unittest.TestCase):
    """Deterministic binding between ActionAuthorizationContext and ApprovalRecord."""

    def setUp(self) -> None:
        self.executor = SimulatedResponseExecutor()

    def test_incident_id_mismatch_blocks_simulation(self) -> None:
        ctx = _make_context(incident_id="INC-CONTEXT-001")
        app = _make_approval(incident_id="INC-APPROVAL-DIFFERENT")

        res = self.executor.execute(ctx, app)
        self.assertEqual(res.status, SimulationStatus.NOT_EXECUTED)
        self.assertEqual(res.detail_code, "simulation_blocked_mismatched_approval")

    def test_action_mismatch_blocks_simulation(self) -> None:
        ctx = _make_context(action=ProposedAction.SIMULATE_ENDPOINT_ISOLATION)
        # Approval was granted for MONITOR instead of isolation
        app = _make_approval(
            action=ProposedAction.MONITOR,
            decision=ApprovalDecision.APPROVED,
            reason_code=ApprovalReasonCode.APPROVAL_GRANTED.value,
        )

        res = self.executor.execute(ctx, app)
        self.assertEqual(res.status, SimulationStatus.NOT_EXECUTED)
        self.assertEqual(res.detail_code, "simulation_blocked_mismatched_approval")

    def test_subclass_context_rejected(self) -> None:
        class ContextSubclass(ActionAuthorizationContext):
            pass

        ctx = ContextSubclass("INC-001", _make_context().policy_decision)
        with self.assertRaises(SimulationError):
            self.executor.execute(ctx, _make_approval())

    def test_subclass_approval_rejected(self) -> None:
        class ApprovalSubclass(ApprovalRecord):
            pass

        app = ApprovalSubclass(
            incident_id="INC-001",
            proposed_action=ProposedAction.SIMULATE_ENDPOINT_ISOLATION,
            decision=ApprovalDecision.APPROVED,
            approver=DEFAULT_APPROVER,
            reason_code=ApprovalReasonCode.APPROVAL_GRANTED.value,
        )
        with self.assertRaises(SimulationError):
            self.executor.execute(_make_context(), app)


class TestConsequentialSimulationOutcomes(unittest.TestCase):
    """Simulated execution for SIMULATE_ENDPOINT_ISOLATION."""

    def setUp(self) -> None:
        self.executor = SimulatedResponseExecutor()
        self.ctx = _make_context()

    def test_approved_executes_simulation(self) -> None:
        app = _make_approval(decision=ApprovalDecision.APPROVED)
        res = self.executor.execute(self.ctx, app)

        self.assertEqual(res.status, SimulationStatus.SIMULATED)
        self.assertEqual(res.detail_code, "simulated_endpoint_isolation")
        self.assertEqual(res.proposed_action, ProposedAction.SIMULATE_ENDPOINT_ISOLATION)
        self.assertEqual(res.incident_id, self.ctx.incident_id)

    def test_missing_approval_blocks_simulation(self) -> None:
        res = self.executor.execute(self.ctx, approval_record=None)
        self.assertEqual(res.status, SimulationStatus.NOT_EXECUTED)
        self.assertEqual(res.detail_code, "simulation_blocked_missing_approval")

    def test_denied_approval_blocks_simulation(self) -> None:
        app = _make_approval(
            decision=ApprovalDecision.DENIED,
            reason_code=ApprovalReasonCode.APPROVAL_DENIED.value,
        )
        res = self.executor.execute(self.ctx, app)
        self.assertEqual(res.status, SimulationStatus.NOT_EXECUTED)
        self.assertEqual(res.detail_code, "simulation_blocked_denied")


class TestNonConsequentialSimulationOutcomes(unittest.TestCase):
    """Non-consequential policy outcomes never execute simulation machinery."""

    def setUp(self) -> None:
        self.executor = SimulatedResponseExecutor()

    def test_no_action_returns_not_executed(self) -> None:
        ctx = _make_context(action=ProposedAction.NO_ACTION, disposition=ActionDisposition.NO_ACTION, requires_approval=False)
        res = self.executor.execute(ctx)
        self.assertEqual(res.status, SimulationStatus.NOT_EXECUTED)
        self.assertEqual(res.detail_code, "simulation_not_required")

    def test_monitor_returns_not_executed(self) -> None:
        ctx = _make_context(action=ProposedAction.MONITOR, disposition=ActionDisposition.MONITOR, requires_approval=False)
        res = self.executor.execute(ctx)
        self.assertEqual(res.status, SimulationStatus.NOT_EXECUTED)
        self.assertEqual(res.detail_code, "simulation_not_required")

    def test_human_review_returns_not_executed(self) -> None:
        ctx = _make_context(action=ProposedAction.REQUEST_HUMAN_REVIEW, disposition=ActionDisposition.HUMAN_REVIEW, requires_approval=False)
        res = self.executor.execute(ctx)
        self.assertEqual(res.status, SimulationStatus.NOT_EXECUTED)
        self.assertEqual(res.detail_code, "human_review_required")

    def test_incident_record_returns_not_executed(self) -> None:
        ctx = _make_context(action=ProposedAction.CREATE_INCIDENT_RECORD, disposition=ActionDisposition.HUMAN_REVIEW, requires_approval=False)
        res = self.executor.execute(ctx)
        self.assertEqual(res.status, SimulationStatus.NOT_EXECUTED)
        self.assertEqual(res.detail_code, "incident_record_deferred")


class TestSimulationAuditIntegration(unittest.TestCase):
    """Audit event emission and mandatory fail-closed audit error handling."""

    def setUp(self) -> None:
        self.executor = SimulatedResponseExecutor()
        self.ctx = _make_context()

    def test_successful_simulation_records_completed_audit(self) -> None:
        audit_log = AuditLog()
        app = _make_approval()
        res = self.executor.execute(self.ctx, app, audit_log=audit_log)

        self.assertEqual(res.status, SimulationStatus.SIMULATED)
        events = audit_log.events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].event_type, AuditEventType.SIMULATION_COMPLETED)
        self.assertEqual(events[0].detail_code, "simulated_endpoint_isolation")

    def test_blocked_simulation_records_not_executed_audit(self) -> None:
        audit_log = AuditLog()
        res = self.executor.execute(self.ctx, approval_record=None, audit_log=audit_log)

        self.assertEqual(res.status, SimulationStatus.NOT_EXECUTED)
        events = audit_log.events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].event_type, AuditEventType.SIMULATION_NOT_EXECUTED)
        self.assertEqual(events[0].detail_code, "simulation_blocked_missing_approval")

    def test_audit_failure_on_consequential_simulation_fails_closed(self) -> None:
        """If recording SIMULATION_COMPLETED fails, executor must raise and NOT return SIMULATED."""
        mock_audit = MagicMock()
        mock_audit.events.return_value = ()
        mock_audit.append.side_effect = RuntimeError("Audit disk full")

        app = _make_approval()
        with self.assertRaises(SimulationError) as cm:
            self.executor.execute(self.ctx, app, audit_log=mock_audit)

        self.assertIn("audit_recording_failed", str(cm.exception))

    def test_audit_failure_on_blocked_simulation_fails_closed(self) -> None:
        mock_audit = MagicMock()
        mock_audit.events.return_value = ()
        mock_audit.append.side_effect = RuntimeError("Audit failure on block")

        with self.assertRaises(SimulationError) as cm:
            self.executor.execute(self.ctx, approval_record=None, audit_log=mock_audit)

        self.assertIn("audit_recording_failed", str(cm.exception))


class TestSimulationSecurityBoundaries(unittest.TestCase):
    """Proof of isolation: approval and simulator modules do not import execution libraries."""

    def test_no_subprocess_imported(self) -> None:
        import investigator.approval as app_mod
        import investigator.simulator as sim_mod

        self.assertNotIn("subprocess", dir(app_mod))
        self.assertNotIn("subprocess", dir(sim_mod))

    def test_no_socket_imported(self) -> None:
        import investigator.approval as app_mod
        import investigator.simulator as sim_mod

        self.assertNotIn("socket", dir(app_mod))
        self.assertNotIn("socket", dir(sim_mod))

    def test_no_remote_execution_tools_imported(self) -> None:
        import investigator.approval as app_mod
        import investigator.simulator as sim_mod

        for forbidden in ("winrm", "paramiko", "fabric", "ansible", "shutil", "requests", "urllib"):
            self.assertNotIn(forbidden, dir(app_mod))
            self.assertNotIn(forbidden, dir(sim_mod))


if __name__ == "__main__":
    unittest.main()
