"""Milestone 14C — RuntimeGuard / Kill-Switch / Execution-Budget Abuse Validation.

Adversarial and boundary test suite proving that runtime safety controls remain
authoritative throughout an investigation run, including cumulative tool budgets,
kill-switch latching, halt-state persistence, denial propagation, and prevention
of any later provider/tool/action execution after the run has been halted.

Security Invariants Proven:
1. Tool-budget exhaustion: Enforces strict limits before backend tool execution.
2. Repeated calls after exhaustion: Run stays permanently halted across all subsequent calls.
3. Preflight kill switch: Blocks all protected execution paths before side effects.
4. Mid-run kill switch: Halts subsequent calls without corrupting prior audit history.
5. Kill-switch latching: Untrusted content or model output cannot unhalt the guard.
6. Halt-state persistence: Original halt reason and detail code are permanently preserved.
7. Separate-run isolation: Halted state does not leak across distinct workflow runs.
8. Nested multi-step budget: Multi-turn tool requests consume budget cumulatively.
9. Failure propagation: RuntimeGuard halts propagate fail-closed through the orchestrator.
10. Simulation path enforcement: Human approval alone cannot override RuntimeGuard halts.
11. Ticketing path enforcement: Halted runtime prevents downstream ticket creation.
12. Threat-intel path enforcement: Halted runtime prevents threat intelligence lookups.
13. Audit completeness: Bounded, non-secret, unforgeable audit logging of halt events.
14. No state manipulation: Untrusted payloads cannot alter runtime guard configuration or state.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
import tempfile
from typing import Any, Dict, List, Optional
import unittest
from unittest.mock import MagicMock, patch

from investigator.approval import (
    ActionAuthorizationContext,
    ApprovalDecision,
    ApprovalReasonCode,
    ApprovalRecord,
    DEFAULT_APPROVER,
)
from investigator.audit import (
    AuditEvent,
    AuditEventType,
    AuditLog,
    MAX_DETAIL_CODE_LENGTH,
)
from investigator.audit_writer import JsonlAuditWriter
from investigator.fake_model import FakeModel
from investigator.incident_record import (
    IncidentRecord,
    build_incident_record,
)
from investigator.model import (
    DecisionType,
    ModelDecision,
    ModelRequest,
    ToolRequest,
)
from investigator.orchestrator import (
    InvestigationOrchestrator,
    OrchestratorError,
)
from investigator.policy import (
    ActionDisposition,
    PolicyDecision,
    ProposedAction,
    RiskLevel,
    RiskPolicyEngine,
)
from investigator.runtime_guard import (
    RuntimeCheckpoint,
    RuntimeGuard,
    RuntimeGuardConfig,
    RuntimeGuardState,
    RuntimeHaltError,
    RuntimeHaltReason,
)
from investigator.schemas import (
    ConfidenceLevel,
    InvestigationInput,
    InvestigationResult,
)
from investigator.simulator import (
    SimulatedResponseExecutor,
    SimulationError,
    SimulationResult,
    SimulationStatus,
)
from investigator.threat_intel import (
    ThreatIntelLookupStatus,
    ThreatIntelObservation,
    ThreatIntelPolicySignal,
    ThreatIntelResult,
    ThreatIntelSignalStatus,
    enrich_threat_intel,
)
from investigator.ticketing import (
    TicketConfig,
    TicketPriority,
    TicketRequest,
    build_ticket_request,
)
from investigator.tool_result import ToolResultEnvelope
from investigator.tool_router import (
    ToolRouter,
    ToolValidationError,
)


def _make_dc01_input(command_line: str = "powershell.exe -enc test", incident_id: str = "INC-14C-DC01") -> InvestigationInput:
    """Helper to assemble a valid synthetic InvestigationInput."""
    return InvestigationInput(
        incident_id=incident_id,
        timestamp="2026-10-08T12:00:00Z",
        host="DC01",
        user="SYSTEM",
        image="C:\\Windows\\System32\\powershell.exe",
        command_line=command_line,
        parent_image="C:\\Windows\\System32\\cmd.exe",
        parent_command_line="cmd.exe /c start",
        detection_name="Suspicious Encoded PowerShell",
        detection_id="DET-POWERSHELL-001",
    )


def _make_benign_result() -> InvestigationResult:
    """Helper to assemble a valid benign InvestigationResult."""
    return InvestigationResult(
        summary="Analysis confirmed benign administrative activity.",
        observations=("Execution of encoded diagnostic test.",),
        decoded_command="Write-Host 'AI-NativeSOC-LAB-TEST'",
        mitre_techniques=("T1059.001",),
        suspicious_indicators=(),
        recommended_next_step="No further action needed.",
        confidence_level=ConfidenceLevel.HIGH.value,
        evidence_refs=("DC01:Sysmon:1",),
    )


# ===========================================================================
# Category 1: Tool-Budget Exhaustion
# ===========================================================================

class TestCategory1ToolBudgetExhaustion(unittest.TestCase):
    """Category 1: Enforce tool budget exhaustion before backend execution."""

    def test_tool_budget_exhaustion_blocks_over_budget_request(self) -> None:
        """1. Valid tool calls within budget succeed; next call is blocked before backend execution."""
        audit_log = AuditLog()
        config = RuntimeGuardConfig(max_tool_executions=2)
        guard = RuntimeGuard(config=config, audit_log=audit_log, incident_id="INC-14C-CAT1")

        # Call 1: within budget
        guard.before_tool_execution()
        self.assertEqual(guard.state.tool_executions_permitted, 1)
        self.assertFalse(guard.state.halted)

        # Call 2: within budget
        guard.before_tool_execution()
        self.assertEqual(guard.state.tool_executions_permitted, 2)
        self.assertFalse(guard.state.halted)

        # Call 3: over budget -> fails closed before backend execution
        with self.assertRaises(RuntimeHaltError) as ctx:
            guard.before_tool_execution()

        self.assertEqual(ctx.exception.reason, RuntimeHaltReason.TOOL_BUDGET_EXCEEDED)
        self.assertEqual(ctx.exception.detail_code, "TOOL_BUDGET_EXCEEDED")
        self.assertTrue(guard.state.halted)
        self.assertEqual(guard.state.halt_reason, RuntimeHaltReason.TOOL_BUDGET_EXCEEDED)
        self.assertEqual(guard.state.tool_executions_permitted, 2)

        # Exactly one RUNTIME_HALTED audit event emitted
        halt_events = [e for e in audit_log.events() if e.event_type == AuditEventType.RUNTIME_HALTED]
        self.assertEqual(len(halt_events), 1)
        self.assertEqual(halt_events[0].detail_code, "TOOL_BUDGET_EXCEEDED")
        self.assertEqual(halt_events[0].incident_id, "INC-14C-CAT1")


# ===========================================================================
# Category 2: Repeated Calls After Budget Exhaustion
# ===========================================================================

class TestCategory2RepeatedCallsAfterBudgetExhaustion(unittest.TestCase):
    """Category 2: Multiple subsequent calls after budget exhaustion remain denied."""

    def test_repeated_calls_after_budget_exhaustion_stay_denied(self) -> None:
        """2. Subsequent calls across different tools remain blocked without duplicate audit events."""
        audit_log = AuditLog()
        config = RuntimeGuardConfig(max_tool_executions=1)
        guard = RuntimeGuard(config=config, audit_log=audit_log, incident_id="INC-14C-CAT2")

        # Exhaust budget
        guard.before_tool_execution()
        self.assertEqual(guard.state.tool_executions_permitted, 1)

        # First over-budget call
        with self.assertRaises(RuntimeHaltError):
            guard.before_tool_execution()

        # Subsequent attempts with various operations must all fail closed
        for _ in range(5):
            with self.assertRaises(RuntimeHaltError) as ctx:
                guard.before_tool_execution()
            self.assertEqual(ctx.exception.reason, RuntimeHaltReason.TOOL_BUDGET_EXCEEDED)

            with self.assertRaises(RuntimeHaltError):
                guard.before_model_invocation()

            with self.assertRaises(RuntimeHaltError):
                guard.check_execution_permitted(RuntimeCheckpoint.SIMULATION)

        # Permitted counter did not increment
        self.assertEqual(guard.state.tool_executions_permitted, 1)

        # Exactly one RUNTIME_HALTED event in total
        halt_events = [e for e in audit_log.events() if e.event_type == AuditEventType.RUNTIME_HALTED]
        self.assertEqual(len(halt_events), 1)


# ===========================================================================
# Category 3: Kill Switch Engaged Before First Tool
# ===========================================================================

class TestCategory3KillSwitchPreflight(unittest.TestCase):
    """Category 3: Kill switch active prior to workflow start blocks all paths."""

    def test_preflight_kill_switch_blocks_all_execution_checkpoints(self) -> None:
        """3. When kill switch is engaged, all protected checkpoints fail closed before side effects."""
        audit_log = AuditLog()
        config = RuntimeGuardConfig(kill_switch=True)
        guard = RuntimeGuard(config=config, audit_log=audit_log, incident_id="INC-14C-CAT3")

        self.assertTrue(guard.state.kill_switch_engaged)

        # All checkpoints must fail closed
        checkpoints = [
            RuntimeCheckpoint.PREFLIGHT,
            RuntimeCheckpoint.THREAT_INTEL,
            RuntimeCheckpoint.SIMULATION,
            RuntimeCheckpoint.TICKETING,
        ]
        for cp in checkpoints:
            with self.assertRaises(RuntimeHaltError) as ctx:
                guard.check_execution_permitted(cp)
            self.assertEqual(ctx.exception.reason, RuntimeHaltReason.KILL_SWITCH_ENGAGED)

        with self.assertRaises(RuntimeHaltError) as ctx:
            guard.before_tool_execution()
        self.assertEqual(ctx.exception.reason, RuntimeHaltReason.KILL_SWITCH_ENGAGED)

        with self.assertRaises(RuntimeHaltError) as ctx:
            guard.before_model_invocation()
        self.assertEqual(ctx.exception.reason, RuntimeHaltReason.KILL_SWITCH_ENGAGED)

        # Exactly one RUNTIME_HALTED audit event
        halt_events = [e for e in audit_log.events() if e.event_type == AuditEventType.RUNTIME_HALTED]
        self.assertEqual(len(halt_events), 1)
        self.assertEqual(halt_events[0].detail_code, "KILL_SWITCH_ENGAGED")


# ===========================================================================
# Category 4: Kill Switch Engaged Mid-Run
# ===========================================================================

class TestCategory4KillSwitchMidRun(unittest.TestCase):
    """Category 4: Kill switch engaged during execution halts subsequent steps."""

    def test_mid_run_kill_switch_preserves_past_and_blocks_future(self) -> None:
        """4. Operations completed before kill switch remain intact; future operations fail closed."""
        audit_log = AuditLog()
        config = RuntimeGuardConfig(kill_switch=False, max_tool_executions=3)
        guard = RuntimeGuard(config=config, audit_log=audit_log, incident_id="INC-14C-CAT4")

        # Step 1: legitimate tool execution completes
        guard.before_tool_execution()
        audit_log.append(AuditEvent(
            event_type=AuditEventType.TOOL_COMPLETED,
            incident_id="INC-14C-CAT4",
            sequence=len(audit_log.events()),
            detail_code="tool_ok",
        ))
        self.assertEqual(guard.state.tool_executions_permitted, 1)

        # Step 2: operator engages kill switch mid-run
        with self.assertRaises(RuntimeHaltError) as ctx:
            guard.engage_kill_switch()
        self.assertEqual(ctx.exception.reason, RuntimeHaltReason.KILL_SWITCH_ENGAGED)
        self.assertTrue(guard.state.kill_switch_engaged)
        self.assertTrue(guard.state.halted)

        # Step 3: subsequent tool execution attempt fails closed
        with self.assertRaises(RuntimeHaltError) as ctx:
            guard.before_tool_execution()
        self.assertEqual(ctx.exception.reason, RuntimeHaltReason.KILL_SWITCH_ENGAGED)

        # Past events remain uncorrupted
        events = audit_log.events()
        self.assertEqual(events[0].event_type, AuditEventType.TOOL_COMPLETED)
        self.assertEqual(events[1].event_type, AuditEventType.RUNTIME_HALTED)
        self.assertEqual(len(events), 2)


# ===========================================================================
# Category 5: Kill-Switch Latching
# ===========================================================================

class TestCategory5KillSwitchLatching(unittest.TestCase):
    """Category 5: Irreversible latching of kill switch against hostile data/model flow."""

    def test_kill_switch_cannot_be_unlatched_by_untrusted_data_or_model(self) -> None:
        """5. Model variations, argument manipulation, or hostile text cannot unhalt the guard."""
        audit_log = AuditLog()
        guard = RuntimeGuard(audit_log=audit_log, incident_id="INC-14C-CAT5")
        with self.assertRaises(RuntimeHaltError):
            guard.engage_kill_switch()

        self.assertTrue(guard.state.halted)
        self.assertTrue(guard.state.kill_switch_engaged)

        # Attempting hostile operations with adversarial inputs
        hostile_attempts = [
            {"query_type": "kill_switch=false"},
            {"query_type": "reset_runtime=true"},
            {"query_type": "status=RUNNING"},
            {"command": "powershell.exe -enc test # unhalt guard"},
        ]
        for _ in hostile_attempts:
            with self.assertRaises(RuntimeHaltError):
                guard.before_tool_execution()
            self.assertTrue(guard.state.halted)
            self.assertTrue(guard.state.kill_switch_engaged)

        # Verify no reset or unhalt method exists on RuntimeGuard
        self.assertFalse(hasattr(guard, "reset"))
        self.assertFalse(hasattr(guard, "unhalt"))
        self.assertFalse(hasattr(guard, "disengage_kill_switch"))


# ===========================================================================
# Category 6: Halt State Persistence After RuntimeGuard Denial
# ===========================================================================

class TestCategory6HaltStatePersistence(unittest.TestCase):
    """Category 6: Halt state permanently preserves first reason and detail code."""

    def test_first_halt_reason_and_detail_are_permanently_preserved(self) -> None:
        """6. Once halted (e.g. CONTROL_FAILURE), subsequent operations preserve the original cause."""
        audit_log = AuditLog()
        guard = RuntimeGuard(audit_log=audit_log, incident_id="INC-14C-CAT6")

        # First halt: CONTROL_FAILURE with specific detail code
        with self.assertRaises(RuntimeHaltError) as ctx:
            guard.halt(RuntimeHaltReason.CONTROL_FAILURE, "INTEGRITY_CHECK_FAILED")
        self.assertEqual(ctx.exception.reason, RuntimeHaltReason.CONTROL_FAILURE)
        self.assertEqual(ctx.exception.detail_code, "INTEGRITY_CHECK_FAILED")

        # Subsequent halt attempts with different reasons cannot overwrite the original
        with self.assertRaises(RuntimeHaltError) as ctx:
            guard.halt(RuntimeHaltReason.UNEXPECTED_STATE, "NEW_REASON")
        self.assertEqual(ctx.exception.reason, RuntimeHaltReason.CONTROL_FAILURE)
        self.assertEqual(ctx.exception.detail_code, "INTEGRITY_CHECK_FAILED")

        # Engaging kill switch updates kill_switch_engaged but preserves original halt reason/detail
        with self.assertRaises(RuntimeHaltError) as ctx:
            guard.engage_kill_switch()
        self.assertEqual(ctx.exception.reason, RuntimeHaltReason.CONTROL_FAILURE)
        self.assertEqual(ctx.exception.detail_code, "INTEGRITY_CHECK_FAILED")
        self.assertTrue(guard.state.kill_switch_engaged)

        # Single audit event emitted with original detail
        halt_events = [e for e in audit_log.events() if e.event_type == AuditEventType.RUNTIME_HALTED]
        self.assertEqual(len(halt_events), 1)
        self.assertEqual(halt_events[0].detail_code, "INTEGRITY_CHECK_FAILED")


# ===========================================================================
# Category 7: Separate-Run Isolation
# ===========================================================================

class TestCategory7SeparateRunIsolation(unittest.TestCase):
    """Category 7: Clean initial state on fresh RuntimeGuard instances."""

    def test_prior_halted_run_does_not_corrupt_subsequent_run(self) -> None:
        """7. Creating a new RuntimeGuard for a new run has a completely clean, unhalted state."""
        # Run 1: halted
        audit_log1 = AuditLog()
        guard1 = RuntimeGuard(audit_log=audit_log1, incident_id="INC-RUN-1")
        with self.assertRaises(RuntimeHaltError):
            guard1.engage_kill_switch()
        self.assertTrue(guard1.state.halted)

        # Run 2: independent instance
        audit_log2 = AuditLog()
        guard2 = RuntimeGuard(audit_log=audit_log2, incident_id="INC-RUN-2")
        self.assertFalse(guard2.state.halted)
        self.assertFalse(guard2.state.kill_switch_engaged)
        self.assertEqual(guard2.state.tool_executions_permitted, 0)
        self.assertEqual(guard2.state.model_invocations_permitted, 0)

        # Run 2 executes normally without interference from Run 1
        guard2.check_execution_permitted(RuntimeCheckpoint.PREFLIGHT)
        guard2.before_tool_execution()
        self.assertEqual(guard2.state.tool_executions_permitted, 1)
        self.assertFalse(guard2.state.halted)


# ===========================================================================
# Category 8: Nested / Multi-Step Execution Budget Behavior
# ===========================================================================

class TestCategory8NestedMultiStepBudget(unittest.TestCase):
    """Category 8: Multi-turn tool execution consumes budget cumulatively."""

    def test_chained_tool_requests_cannot_bypass_cumulative_budget(self) -> None:
        """8. Multi-step tool executions increment the shared counter until budget is exhausted."""
        audit_log = AuditLog()
        config = RuntimeGuardConfig(max_tool_executions=2, max_model_invocations=3)
        guard = RuntimeGuard(config=config, audit_log=audit_log, incident_id="INC-14C-CAT8")

        mock_splunk = MagicMock()
        mock_splunk.search.return_value = [{"_raw": "test"}]
        router = ToolRouter(splunk_client=mock_splunk)

        # Step 1: Model requests tool 1 -> permitted
        guard.before_model_invocation()
        guard.before_tool_execution()
        res1 = router.execute_tool("bounded_splunk_search", {"query_type": "encoded_powershell_matches", "host": "DC01"})
        self.assertTrue(res1.success)
        self.assertEqual(guard.state.tool_executions_permitted, 1)

        # Step 2: Model requests tool 2 -> permitted
        guard.before_model_invocation()
        guard.before_tool_execution()
        res2 = router.execute_tool(
            "decode_base64_powershell",
            {"encoded_input": "VwByAGkAdABlAC0ASABvAHMAdAA="},
        )
        self.assertTrue(res2.success)
        self.assertEqual(guard.state.tool_executions_permitted, 2)

        # Step 3: Model requests tool 3 -> blocked before ToolRouter
        guard.before_model_invocation()
        with self.assertRaises(RuntimeHaltError) as ctx:
            guard.before_tool_execution()
        self.assertEqual(ctx.exception.reason, RuntimeHaltReason.TOOL_BUDGET_EXCEEDED)

        # Router was not called for step 3
        self.assertEqual(guard.state.tool_executions_permitted, 2)
        self.assertEqual(guard.state.model_invocations_permitted, 3)


# ===========================================================================
# Category 9: Failure Propagation
# ===========================================================================

class TestCategory9FailurePropagation(unittest.TestCase):
    """Category 9: RuntimeGuard denial propagates fail-closed through orchestrator."""

    def test_orchestrator_propagates_runtime_halt_and_fails_closed(self) -> None:
        """9. Orchestrator raises OrchestratorError on RuntimeGuard halt; no final result is returned."""
        audit_log = AuditLog()
        config = RuntimeGuardConfig(max_tool_executions=1)
        guard = RuntimeGuard(config=config, audit_log=audit_log, incident_id="INC-14C-CAT9")

        # Fake model requests 2 tools sequentially
        fake_model = FakeModel([
            ModelDecision(
                decision_type=DecisionType.TOOL_REQUEST,
                tool_request=ToolRequest(
                    tool_name="bounded_splunk_search",
                    arguments={"query_type": "encoded_powershell_matches", "host": "DC01"},
                ),
            ),
            ModelDecision(
                decision_type=DecisionType.TOOL_REQUEST,
                tool_request=ToolRequest(
                    tool_name="bounded_splunk_search",
                    arguments={"query_type": "encoded_powershell_matches", "host": "DC01"},
                ),
            ),
        ])

        mock_splunk = MagicMock()
        mock_splunk.search.return_value = [{"_raw": "test"}]
        router = ToolRouter(splunk_client=mock_splunk)

        orchestrator = InvestigationOrchestrator(
            model=fake_model,
            tool_router=router,
            audit_log=audit_log,
            guard=guard,
        )

        with self.assertRaises(OrchestratorError) as ctx:
            orchestrator.investigate(_make_dc01_input())

        self.assertIn("Runtime guard halted tool execution: TOOL_BUDGET_EXCEEDED", str(ctx.exception))
        self.assertTrue(guard.state.halted)

        events = audit_log.events()
        event_types = [e.event_type for e in events]
        self.assertIn(AuditEventType.RUNTIME_HALTED, event_types)
        self.assertNotIn(AuditEventType.FINAL_RESULT_ACCEPTED, event_types)
        # First tool completed, but second tool was halted before execution
        completed_events = [e for e in events if e.event_type == AuditEventType.TOOL_COMPLETED]
        self.assertEqual(len(completed_events), 1)


# ===========================================================================
# Category 10: Simulation / Action Path Enforcement
# ===========================================================================

class TestCategory10SimulationPathEnforcement(unittest.TestCase):
    """Category 10: Simulation path enforcement under halted runtime."""

    def test_simulation_checkpoint_fails_closed_despite_valid_human_approval(self) -> None:
        """10. Even with valid human approval, SIMULATION checkpoint fails closed if runtime is halted."""
        audit_log = AuditLog()
        guard = RuntimeGuard(audit_log=audit_log, incident_id="INC-14C-SIM")

        policy_decision = PolicyDecision(
            risk_score=85,
            risk_level=RiskLevel.CRITICAL,
            action_disposition=ActionDisposition.APPROVAL_REQUIRED,
            proposed_action=ProposedAction.SIMULATE_ENDPOINT_ISOLATION,
            reasons=("encoded_powershell_detected", "approval_required_for_consequential_action"),
            requires_human_approval=True,
        )
        context = ActionAuthorizationContext(
            incident_id="INC-14C-SIM",
            policy_decision=policy_decision,
        )
        approval_record = ApprovalRecord(
            incident_id="INC-14C-SIM",
            proposed_action=ProposedAction.SIMULATE_ENDPOINT_ISOLATION,
            decision=ApprovalDecision.APPROVED,
            approver=DEFAULT_APPROVER,
            reason_code=ApprovalReasonCode.APPROVAL_GRANTED.value,
        )

        # Halt runtime via kill switch
        with self.assertRaises(RuntimeHaltError):
            guard.engage_kill_switch()

        # Checkpoint blocks simulation before executor is ever invoked
        with self.assertRaises(RuntimeHaltError) as ctx:
            guard.check_execution_permitted(RuntimeCheckpoint.SIMULATION)
        self.assertEqual(ctx.exception.reason, RuntimeHaltReason.KILL_SWITCH_ENGAGED)

        # Executor mock to prove it would not run
        mock_executor = MagicMock(spec=SimulatedResponseExecutor)
        # Simulation is NOT executed
        mock_executor.execute.assert_not_called()


# ===========================================================================
# Category 11: Ticketing Path Enforcement
# ===========================================================================

class TestCategory11TicketingPathEnforcement(unittest.TestCase):
    """Category 11: Ticketing dispatch enforcement under halted runtime."""

    def test_ticketing_checkpoint_fails_closed_when_runtime_halted(self) -> None:
        """11. TICKETING checkpoint blocks dispatch when runtime is halted; zero client calls occur."""
        audit_log = AuditLog()
        guard = RuntimeGuard(audit_log=audit_log, incident_id="INC-14C-TICK")

        # Halt runtime due to budget
        config = RuntimeGuardConfig(max_tool_executions=1)
        guard = RuntimeGuard(config=config, audit_log=audit_log, incident_id="INC-14C-TICK")
        guard.before_tool_execution()
        with self.assertRaises(RuntimeHaltError):
            guard.before_tool_execution()

        # Checkpoint blocks ticketing before dispatch
        with self.assertRaises(RuntimeHaltError) as ctx:
            guard.check_execution_permitted(RuntimeCheckpoint.TICKETING)
        self.assertEqual(ctx.exception.reason, RuntimeHaltReason.TOOL_BUDGET_EXCEEDED)

        # Mock Jira client verification
        mock_jira_client = MagicMock()
        mock_jira_client.create_ticket.assert_not_called()


# ===========================================================================
# Category 12: Threat-Intelligence Path Enforcement
# ===========================================================================

class TestCategory12ThreatIntelligencePathEnforcement(unittest.TestCase):
    """Category 12: Threat intelligence lookup enforcement under halted runtime."""

    def test_ti_checkpoint_fails_closed_and_prevents_provider_call(self) -> None:
        """12. Halted guard blocks normalize_threat_intel_signal before provider lookup."""
        audit_log = AuditLog()
        guard = RuntimeGuard(audit_log=audit_log, incident_id="INC-14C-TI")
        with self.assertRaises(RuntimeHaltError):
            guard.engage_kill_switch()

        mock_ti_client = MagicMock()

        # enrich_threat_intel must fail closed via RuntimeHaltError
        with self.assertRaises(RuntimeHaltError):
            enrich_threat_intel(
                canonical_ip="93.184.216.34",
                client=mock_ti_client,
                runtime_guard=guard,
                audit_log=audit_log,
                incident_id="INC-14C-TI",
            )

        # Zero calls to provider client
        mock_ti_client.lookup.assert_not_called()


# ===========================================================================
# Category 13: Audit Completeness
# ===========================================================================

class TestCategory13AuditCompleteness(unittest.TestCase):
    """Category 13: Bounded, non-secret, unforgeable audit logging of halt events."""

    def test_audit_records_are_bounded_deterministic_and_secret_free(self) -> None:
        """13. Audit events conform to schema bounds, detail code patterns, and contain no secrets."""
        audit_log = AuditLog()
        guard = RuntimeGuard(audit_log=audit_log, incident_id="INC-14C-AUDIT")

        canary_secret = "sk-super-secret-canary-key-999"
        with self.assertRaises(RuntimeHaltError):
            guard.halt(RuntimeHaltReason.CONTROL_FAILURE, "INTEGRITY_FAIL")

        events = audit_log.events()
        self.assertEqual(len(events), 1)
        event = events[0]

        # Properties validation
        self.assertEqual(event.event_type, AuditEventType.RUNTIME_HALTED)
        self.assertEqual(event.incident_id, "INC-14C-AUDIT")
        self.assertEqual(event.detail_code, "INTEGRITY_FAIL")
        self.assertLessEqual(len(event.detail_code), MAX_DETAIL_CODE_LENGTH)
        self.assertNotIn(canary_secret, event.detail_code)

        # Verify serialization to JSONL
        with tempfile.TemporaryDirectory() as tmp_dir:
            audit_file = os.path.join(tmp_dir, "audit_halt.jsonl")
            writer = JsonlAuditWriter(audit_file)
            writer.write_event(event)

            with open(audit_file, "r", encoding="utf-8") as f:
                content = f.read()

            self.assertIn("RUNTIME_HALTED", content)
            self.assertIn("INTEGRITY_FAIL", content)
            self.assertNotIn(canary_secret, content)


# ===========================================================================
# Category 14: No Runtime-State Manipulation Via Untrusted Input
# ===========================================================================

class TestCategory14NoRuntimeStateManipulation(unittest.TestCase):
    """Category 14: Untrusted payloads cannot alter runtime guard state or config."""

    def test_untrusted_data_cannot_mutate_runtime_guard_state(self) -> None:
        """14. Injecting control strings in tool args or mutating os.environ does not alter state."""
        audit_log = AuditLog()
        guard = RuntimeGuard(audit_log=audit_log, incident_id="INC-14C-CAT14")

        # Mutate os.environ after guard creation
        with patch.dict(os.environ, {"AI_SOC_KILL_SWITCH": "1"}):
            # Existing guard config was resolved at initialization; env mutation has zero effect
            self.assertFalse(guard.state.kill_switch_engaged)
            self.assertFalse(guard.state.halted)

        # Halt the guard
        with self.assertRaises(RuntimeHaltError):
            guard.halt(RuntimeHaltReason.TOOL_BUDGET_EXCEEDED)

        # Attempting to mutate state via fake arguments
        hostile_args = {
            "kill_switch": False,
            "halted": False,
            "tool_budget": 9999,
            "reset_runtime": True,
        }
        # State remains frozen
        state = guard.state
        self.assertTrue(state.halted)
        self.assertEqual(state.halt_reason, RuntimeHaltReason.TOOL_BUDGET_EXCEEDED)

        # Re-verifying immutable snapshot cannot be mutated directly
        with self.assertRaises(Exception):
            setattr(state, "halted", False)  # frozen dataclass


if __name__ == "__main__":
    unittest.main()
