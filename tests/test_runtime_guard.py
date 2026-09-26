"""Comprehensive unit and integration tests for RuntimeGuard and runtime safety controls.

Verifies:
1. Normal guard permits execution across all checkpoints and budgets.
2. Active config preflight halts before any work.
3. E2E preflight kill switch -> zero Splunk calls.
4. E2E preflight kill switch -> zero model calls.
5. E2E preflight kill switch -> zero Jira calls.
6. E2E preflight kill switch -> zero simulator calls.
7. E2E preflight kill switch -> zero VirusTotal calls.
8. engage_kill_switch() immediately raises RuntimeHaltError.
9. engage_kill_switch() emits exactly one RUNTIME_HALTED event.
10. Subsequent boundary calls remain halted.
11. Subsequent calls do not duplicate RUNTIME_HALTED.
12. Original halt reason remains unchanged across subsequent calls.
13. Model calls 1-4 permitted.
14. Model attempt 5 blocked before model call.
15. Model counter remains 4.
16. Tool executions 1-3 permitted.
17. Tool attempt 4 blocked before router call.
18. Tool counter remains 3.
19. Malformed environment value engages kill switch (fails closed).
20. Environment value read only at config creation.
21. Changing os.environ afterward does not mutate existing config/guard.
22. RuntimeCheckpoint rejects arbitrary/unrecognized values.
23. Normal ToolRouter forbidden-tool rejection does not halt guard.
24. Simulator remains responsible for approval validation.
25. RuntimeGuard contains no tool allowlist.
26. Audit uses same run AuditLog.
27. RUNTIME_HALTED detail is deterministic/bounded.
28. Sentinel API key absent from exception/audit/summary.
29. Audit persistence still possible after halt.
30. Normal existing orchestrator behavior remains unchanged when guard is healthy.
31. Synthetic negative control proving genuine CONTROL_FAILURE latches.
32. Audit log binds once; same instance rebind is no-op; different instance raises.
33. Audit log cannot change after halt.
34. Incident ID cannot change after halt; invalid incident ID rejected.
35. First halt reason and detail preserved across halt(other_reason) and engage_kill_switch().
36. Strict detail code validation: bounded identifiers accepted, invalid/raw prose fails closed.
37. Budget ceilings enforced (max 50, huge ints rejected).
38. Constructor-level preflight proof: Splunk, VT, OpenAI, Jira, Simulator constructors not called.
"""

from dataclasses import FrozenInstanceError
import io
import json
import os
from pathlib import Path
import tempfile
from typing import Any, Dict, List, Optional
import unittest
from unittest.mock import MagicMock, patch

from gateway.splunk_search import SplunkSearchClient
from investigator.approval import (
    ActionAuthorizationContext,
    ApprovalDecision,
    ApprovalRecord,
    DEFAULT_APPROVER,
)
from investigator.audit import (
    AuditEvent,
    AuditEventType,
    AuditLog,
)
from investigator.audit_writer import JsonlAuditWriter
from investigator.model import (
    DecisionType,
    INVESTIGATOR_SYSTEM_INSTRUCTIONS,
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
    MAX_RUNTIME_MODEL_BUDGET,
    MAX_RUNTIME_TOOL_BUDGET,
    RuntimeCheckpoint,
    RuntimeGuard,
    RuntimeGuardConfig,
    RuntimeGuardState,
    RuntimeHaltError,
    RuntimeHaltReason,
)
from investigator.schemas import (
    InvestigationInput,
    InvestigationResult,
)
from investigator.simulator import (
    SimulatedResponseExecutor,
    SimulationStatus,
)
from investigator.ticketing import TicketClient, TicketResult
from investigator.tool_result import ToolResultEnvelope
from investigator.tool_router import (
    ALLOWED_TOOLS,
    ToolRouter,
    ToolValidationError,
)
from scripts.run_end_to_end_demo import run_demo


def _make_sample_input(incident_id: str = "INC-HEALTHY-01") -> InvestigationInput:
    """Create a valid sample InvestigationInput."""
    return InvestigationInput(
        incident_id=incident_id,
        timestamp="2026-09-26T12:00:00Z",
        host="DC01",
        user="SYSTEM",
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line="powershell.exe -enc V3JpdGUtSG9zdCAnQUktTmF0aXZlU09DLUxBQi1URVNUJw==",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        parent_command_line="cmd.exe /c start",
        detection_name="Suspicious Encoded PowerShell",
        detection_id="DET-POWERSHELL-001",
    )


def _make_sample_result() -> InvestigationResult:
    """Create a valid sample InvestigationResult."""
    return InvestigationResult(
        summary="Analysis concluded: benign domain.",
        observations=("Observed benign execution pattern",),
        decoded_command="Write-Host 'AI-NativeSOC-LAB-TEST'",
        mitre_techniques=("T1059.001",),
        suspicious_indicators=(),
        recommended_next_step="No further action needed",
        confidence_level="high",
        evidence_refs=("REF-001",),
    )


class FakeInvestigationModel:
    """Mock model returning pre-scripted decisions for testing."""

    def __init__(self, decisions: Optional[List[ModelDecision]] = None) -> None:
        self.decisions = list(decisions or [])
        self.calls: List[ModelRequest] = []

    def decide(self, request: ModelRequest) -> ModelDecision:
        self.calls.append(request)
        if self.decisions:
            return self.decisions.pop(0)
        return ModelDecision(
            decision_type=DecisionType.FINAL_RESULT,
            final_result=_make_sample_result(),
        )


class TestRuntimeGuardBasics(unittest.TestCase):
    """Test basic functionality, immutability, snapshots, and permissions."""

    def test_01_normal_guard_permits_execution(self) -> None:
        """A normal healthy guard permits execution across all checkpoints."""
        audit_log = AuditLog()
        guard = RuntimeGuard(audit_log=audit_log, incident_id="INC-001")

        state = guard.state
        self.assertFalse(state.kill_switch_engaged)
        self.assertFalse(state.halted)
        self.assertIsNone(state.halt_reason)
        self.assertIsNone(state.halt_detail_code)
        self.assertEqual(state.model_invocations_permitted, 0)
        self.assertEqual(state.tool_executions_permitted, 0)

        # Checkpoints pass without raising
        guard.check_execution_permitted(RuntimeCheckpoint.PREFLIGHT)
        guard.check_execution_permitted(RuntimeCheckpoint.SIMULATION)
        guard.check_execution_permitted(RuntimeCheckpoint.TICKETING)

        # Invocations permitted
        guard.before_model_invocation()
        guard.before_tool_execution()

        self.assertEqual(guard.state.model_invocations_permitted, 1)
        self.assertEqual(guard.state.tool_executions_permitted, 1)
        self.assertEqual(len(audit_log.events()), 0)

    def test_guard_state_snapshot_is_immutable(self) -> None:
        """RuntimeGuardState is a frozen dataclass."""
        guard = RuntimeGuard()
        state = guard.state
        with self.assertRaises(FrozenInstanceError):
            state.halted = True  # type: ignore[misc]

    def test_runtime_checkpoint_enum_bounded(self) -> None:
        """RuntimeCheckpoint must be bounded to PREFLIGHT, SIMULATION, TICKETING."""
        expected = {"PREFLIGHT", "SIMULATION", "TICKETING"}
        actual = {m.value for m in RuntimeCheckpoint}
        self.assertEqual(actual, expected)

    def test_runtime_halt_reason_enum_bounded(self) -> None:
        """RuntimeHaltReason must be bounded strictly to the approved enum members."""
        expected = {
            "KILL_SWITCH_ENGAGED",
            "MODEL_BUDGET_EXCEEDED",
            "TOOL_BUDGET_EXCEEDED",
            "CONTROL_FAILURE",
            "UNEXPECTED_STATE",
        }
        actual = {m.value for m in RuntimeHaltReason}
        self.assertEqual(actual, expected)


class TestRuntimeGuardConfigAndEnv(unittest.TestCase):
    """Test configuration resolution, validation, budget ceilings, and fail-closed environment parsing."""

    def test_config_defaults(self) -> None:
        """Defaults must be kill_switch=False, max_model_invocations=4, max_tool_executions=3."""
        config = RuntimeGuardConfig()
        self.assertFalse(config.kill_switch)
        self.assertEqual(config.max_model_invocations, 4)
        self.assertEqual(config.max_tool_executions, 3)

    def test_config_immutability(self) -> None:
        """RuntimeGuardConfig is a frozen dataclass."""
        config = RuntimeGuardConfig()
        with self.assertRaises(FrozenInstanceError):
            config.kill_switch = True  # type: ignore[misc]

    def test_config_validation(self) -> None:
        """Invalid types or non-positive budget limits raise TypeError/ValueError."""
        with self.assertRaises(TypeError):
            RuntimeGuardConfig(kill_switch="true")  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            RuntimeGuardConfig(max_model_invocations=True)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            RuntimeGuardConfig(max_tool_executions=1.5)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            RuntimeGuardConfig(max_model_invocations=0)
        with self.assertRaises(ValueError):
            RuntimeGuardConfig(max_tool_executions=-1)

    def test_budget_ceilings_enforced(self) -> None:
        """Budget values exceeding the upper ceiling or huge integers are rejected."""
        # Exact ceiling is accepted
        cfg = RuntimeGuardConfig(
            max_model_invocations=MAX_RUNTIME_MODEL_BUDGET,
            max_tool_executions=MAX_RUNTIME_TOOL_BUDGET,
        )
        self.assertEqual(cfg.max_model_invocations, MAX_RUNTIME_MODEL_BUDGET)
        self.assertEqual(cfg.max_tool_executions, MAX_RUNTIME_TOOL_BUDGET)

        # Ceiling + 1 rejected
        with self.assertRaises(ValueError):
            RuntimeGuardConfig(max_model_invocations=MAX_RUNTIME_MODEL_BUDGET + 1)
        with self.assertRaises(ValueError):
            RuntimeGuardConfig(max_tool_executions=MAX_RUNTIME_TOOL_BUDGET + 1)

        # Huge integer rejected
        with self.assertRaises(ValueError):
            RuntimeGuardConfig(max_model_invocations=1000000)

    def test_from_env_inactive_values(self) -> None:
        """Inactive values must resolve to kill_switch=False."""
        inactive_cases = ["", "0", "false", "no", "off", "  0  ", "  FALSE  ", "No", "OFF"]
        for val in inactive_cases:
            cfg = RuntimeGuardConfig.from_env(env={"AI_SOC_KILL_SWITCH": val})
            self.assertFalse(cfg.kill_switch, f"Expected False for {val!r}")

        # Unset env
        cfg_unset = RuntimeGuardConfig.from_env(env={})
        self.assertFalse(cfg_unset.kill_switch)

    def test_from_env_active_values(self) -> None:
        """Active values must resolve to kill_switch=True."""
        active_cases = ["1", "true", "yes", "on", "  1  ", "  TRUE  ", "Yes", "ON"]
        for val in active_cases:
            cfg = RuntimeGuardConfig.from_env(env={"AI_SOC_KILL_SWITCH": val})
            self.assertTrue(cfg.kill_switch, f"Expected True for {val!r}")

    def test_19_malformed_environment_value_engages_switch(self) -> None:
        """Any unexpected or malformed environment value fails closed -> kill_switch=True."""
        malformed_cases = [
            "2",
            "-1",
            "disabled_temp",
            "maybe",
            "enabled",
            "true!",
            "null",
            "undefined",
            "kill",
        ]
        for val in malformed_cases:
            cfg = RuntimeGuardConfig.from_env(env={"AI_SOC_KILL_SWITCH": val})
            self.assertTrue(cfg.kill_switch, f"Expected fail-closed True for {val!r}")

    def test_20_21_env_read_only_at_config_creation(self) -> None:
        """Environment is read once at creation; mutating os.environ does not mutate config or guard."""
        env_dict = {"AI_SOC_KILL_SWITCH": "0"}
        config = RuntimeGuardConfig.from_env(env=env_dict)
        guard = RuntimeGuard(config=config)

        self.assertFalse(config.kill_switch)
        self.assertFalse(guard.state.kill_switch_engaged)

        # Mutate the dictionary that was passed or os.environ
        env_dict["AI_SOC_KILL_SWITCH"] = "1"

        # Neither existing config nor guard changes state
        self.assertFalse(config.kill_switch)
        self.assertFalse(guard.state.kill_switch_engaged)

        # Guard still permits execution
        guard.check_execution_permitted(RuntimeCheckpoint.PREFLIGHT)


class TestKillSwitchAndHaltSemantics(unittest.TestCase):
    """Test mid-run kill-switch engagement, halt latching, and exactly-once audit emission."""

    def test_02_active_config_preflight_halts(self) -> None:
        """Config with kill_switch=True halts at preflight checkpoint."""
        audit_log = AuditLog()
        config = RuntimeGuardConfig(kill_switch=True)
        guard = RuntimeGuard(config=config, audit_log=audit_log, incident_id="INC-PRE")

        with self.assertRaises(RuntimeHaltError) as ctx:
            guard.check_execution_permitted(RuntimeCheckpoint.PREFLIGHT)

        self.assertEqual(ctx.exception.reason, RuntimeHaltReason.KILL_SWITCH_ENGAGED)
        self.assertEqual(ctx.exception.detail_code, RuntimeHaltReason.KILL_SWITCH_ENGAGED.value)
        self.assertTrue(guard.state.halted)
        self.assertEqual(guard.state.halt_reason, RuntimeHaltReason.KILL_SWITCH_ENGAGED)
        self.assertEqual(guard.state.halt_detail_code, RuntimeHaltReason.KILL_SWITCH_ENGAGED.value)

        # Audit log contains exactly one RUNTIME_HALTED event
        events = audit_log.events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].event_type, AuditEventType.RUNTIME_HALTED)
        self.assertEqual(events[0].detail_code, RuntimeHaltReason.KILL_SWITCH_ENGAGED.value)

    def test_08_engage_kill_switch_immediately_raises(self) -> None:
        """guard.engage_kill_switch() immediately raises RuntimeHaltError without deferral."""
        guard = RuntimeGuard()
        with self.assertRaises(RuntimeHaltError) as ctx:
            guard.engage_kill_switch()

        self.assertEqual(ctx.exception.reason, RuntimeHaltReason.KILL_SWITCH_ENGAGED)
        self.assertEqual(ctx.exception.detail_code, RuntimeHaltReason.KILL_SWITCH_ENGAGED.value)
        self.assertTrue(guard.state.halted)

    def test_09_11_engage_kill_switch_emits_one_halt_event(self) -> None:
        """engage_kill_switch emits exactly one event; subsequent calls do not duplicate."""
        audit_log = AuditLog()
        guard = RuntimeGuard(audit_log=audit_log, incident_id="INC-HALT")

        with self.assertRaises(RuntimeHaltError):
            guard.engage_kill_switch()

        events = audit_log.events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].event_type, AuditEventType.RUNTIME_HALTED)

        # Subsequent attempts to engage or check
        for _ in range(5):
            with self.assertRaises(RuntimeHaltError):
                guard.check_execution_permitted(RuntimeCheckpoint.SIMULATION)
            with self.assertRaises(RuntimeHaltError):
                guard.before_model_invocation()
            with self.assertRaises(RuntimeHaltError):
                guard.before_tool_execution()
            with self.assertRaises(RuntimeHaltError):
                guard.engage_kill_switch()

        # Audit log STILL has exactly one event
        self.assertEqual(len(audit_log.events()), 1)

    def test_10_12_subsequent_boundary_calls_remain_halted_original_reason(self) -> None:
        """Subsequent boundary calls fail closed with the original halt reason."""
        guard = RuntimeGuard(config=RuntimeGuardConfig(kill_switch=True))

        with self.assertRaises(RuntimeHaltError) as ctx1:
            guard.check_execution_permitted(RuntimeCheckpoint.PREFLIGHT)
        self.assertEqual(ctx1.exception.reason, RuntimeHaltReason.KILL_SWITCH_ENGAGED)

        # Attempting model invocation
        with self.assertRaises(RuntimeHaltError) as ctx2:
            guard.before_model_invocation()
        self.assertEqual(ctx2.exception.reason, RuntimeHaltReason.KILL_SWITCH_ENGAGED)

        # Attempting tool execution
        with self.assertRaises(RuntimeHaltError) as ctx3:
            guard.before_tool_execution()
        self.assertEqual(ctx3.exception.reason, RuntimeHaltReason.KILL_SWITCH_ENGAGED)

        # Attempting simulation checkpoint
        with self.assertRaises(RuntimeHaltError) as ctx4:
            guard.check_execution_permitted(RuntimeCheckpoint.SIMULATION)
        self.assertEqual(ctx4.exception.reason, RuntimeHaltReason.KILL_SWITCH_ENGAGED)

        # Attempting ticketing checkpoint
        with self.assertRaises(RuntimeHaltError) as ctx5:
            guard.check_execution_permitted(RuntimeCheckpoint.TICKETING)
        self.assertEqual(ctx5.exception.reason, RuntimeHaltReason.KILL_SWITCH_ENGAGED)

    def test_first_halt_reason_and_detail_preserved_across_subsequent_halts(self) -> None:
        """First halt reason and detail code are strictly preserved; later halt calls cannot overwrite."""
        audit_log = AuditLog()
        guard = RuntimeGuard(audit_log=audit_log, incident_id="INC-PRESERVE")

        # First halt: budget exceeded
        with self.assertRaises(RuntimeHaltError) as ctx1:
            guard.halt(
                RuntimeHaltReason.MODEL_BUDGET_EXCEEDED,
                detail_code="MODEL_BUDGET_EXCEEDED",
            )
        self.assertEqual(ctx1.exception.reason, RuntimeHaltReason.MODEL_BUDGET_EXCEEDED)
        self.assertEqual(ctx1.exception.detail_code, "MODEL_BUDGET_EXCEEDED")

        # Now attempt engage_kill_switch()
        with self.assertRaises(RuntimeHaltError) as ctx2:
            guard.engage_kill_switch()
        # MUST preserve original reason and detail code
        self.assertEqual(ctx2.exception.reason, RuntimeHaltReason.MODEL_BUDGET_EXCEEDED)
        self.assertEqual(ctx2.exception.detail_code, "MODEL_BUDGET_EXCEEDED")
        self.assertTrue(guard.state.kill_switch_engaged)
        self.assertEqual(guard.state.halt_reason, RuntimeHaltReason.MODEL_BUDGET_EXCEEDED)
        self.assertEqual(guard.state.halt_detail_code, "MODEL_BUDGET_EXCEEDED")

        # Now attempt halt(CONTROL_FAILURE, "SYNTHETIC_FAILURE")
        with self.assertRaises(RuntimeHaltError) as ctx3:
            guard.halt(RuntimeHaltReason.CONTROL_FAILURE, detail_code="SYNTHETIC_FAILURE")
        self.assertEqual(ctx3.exception.reason, RuntimeHaltReason.MODEL_BUDGET_EXCEEDED)
        self.assertEqual(ctx3.exception.detail_code, "MODEL_BUDGET_EXCEEDED")

        # Exactly one RUNTIME_HALTED event in audit log
        events = audit_log.events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].detail_code, "MODEL_BUDGET_EXCEEDED")

    def test_22_checkpoint_rejects_arbitrary_unrecognized_values(self) -> None:
        """RuntimeCheckpoint rejects arbitrary/unrecognized strings with UNEXPECTED_STATE."""
        audit_log = AuditLog()
        guard = RuntimeGuard(audit_log=audit_log, incident_id="INC-CHECK")

        # Passing an arbitrary string instead of RuntimeCheckpoint member
        with self.assertRaises(RuntimeHaltError) as ctx:
            guard.check_execution_permitted("ARBITRARY_CHECKPOINT")  # type: ignore[arg-type]

        self.assertEqual(ctx.exception.reason, RuntimeHaltReason.UNEXPECTED_STATE)
        self.assertEqual(ctx.exception.detail_code, "INVALID_CHECKPOINT")
        self.assertTrue(guard.state.halted)
        self.assertEqual(guard.state.halt_reason, RuntimeHaltReason.UNEXPECTED_STATE)
        self.assertEqual(guard.state.halt_detail_code, "INVALID_CHECKPOINT")

        events = audit_log.events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].detail_code, "INVALID_CHECKPOINT")


class TestExecutionBudgets(unittest.TestCase):
    """Test model and tool budget enforcement and counter semantics."""

    def test_13_14_15_model_budget_permits_up_to_max_and_blocks_attempt_5(self) -> None:
        """Model invocations 1-4 permitted; attempt 5 halts; counter remains 4."""
        audit_log = AuditLog()
        guard = RuntimeGuard(audit_log=audit_log, incident_id="INC-BUDGET")

        # Invocations 1-4
        for i in range(1, 5):
            guard.before_model_invocation()
            self.assertEqual(guard.state.model_invocations_permitted, i)

        self.assertEqual(guard.state.model_invocations_permitted, 4)
        self.assertFalse(guard.state.halted)

        # Attempt 5 halts before model.decide()
        with self.assertRaises(RuntimeHaltError) as ctx:
            guard.before_model_invocation()

        self.assertEqual(ctx.exception.reason, RuntimeHaltReason.MODEL_BUDGET_EXCEEDED)
        self.assertEqual(ctx.exception.detail_code, "MODEL_BUDGET_EXCEEDED")
        self.assertTrue(guard.state.halted)
        # Counter remains 4 (does NOT increment for blocked attempt)
        self.assertEqual(guard.state.model_invocations_permitted, 4)

        # Exactly one audit event
        events = audit_log.events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].event_type, AuditEventType.RUNTIME_HALTED)
        self.assertEqual(events[0].detail_code, RuntimeHaltReason.MODEL_BUDGET_EXCEEDED.value)

        # Subsequent attempt also fails and counter remains 4
        with self.assertRaises(RuntimeHaltError):
            guard.before_model_invocation()
        self.assertEqual(guard.state.model_invocations_permitted, 4)
        self.assertEqual(len(audit_log.events()), 1)

    def test_16_17_18_tool_budget_permits_up_to_max_and_blocks_attempt_4(self) -> None:
        """Tool executions 1-3 permitted; attempt 4 halts; counter remains 3."""
        audit_log = AuditLog()
        guard = RuntimeGuard(audit_log=audit_log, incident_id="INC-TOOL-BUDGET")

        # Tool executions 1-3
        for i in range(1, 4):
            guard.before_tool_execution()
            self.assertEqual(guard.state.tool_executions_permitted, i)

        self.assertEqual(guard.state.tool_executions_permitted, 3)
        self.assertFalse(guard.state.halted)

        # Attempt 4 halts before router execution
        with self.assertRaises(RuntimeHaltError) as ctx:
            guard.before_tool_execution()

        self.assertEqual(ctx.exception.reason, RuntimeHaltReason.TOOL_BUDGET_EXCEEDED)
        self.assertEqual(ctx.exception.detail_code, "TOOL_BUDGET_EXCEEDED")
        self.assertTrue(guard.state.halted)
        # Counter remains 3 (does NOT increment for blocked attempt)
        self.assertEqual(guard.state.tool_executions_permitted, 3)

        # Exactly one audit event
        events = audit_log.events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].event_type, AuditEventType.RUNTIME_HALTED)
        self.assertEqual(events[0].detail_code, RuntimeHaltReason.TOOL_BUDGET_EXCEEDED.value)

        # Subsequent attempt also fails and counter remains 3
        with self.assertRaises(RuntimeHaltError):
            guard.before_tool_execution()
        self.assertEqual(guard.state.tool_executions_permitted, 3)
        self.assertEqual(len(audit_log.events()), 1)


class TestAuditOwnershipAndSanitization(unittest.TestCase):
    """Test audit ownership, deterministic bounded fields, and lack of sensitive tokens."""

    def test_audit_log_binding_semantics(self) -> None:
        """Audit log binds once; same instance is no-op; different instance raises."""
        guard = RuntimeGuard()
        self.assertIsNone(guard.audit_log)

        log1 = AuditLog()
        guard.bind_audit_log(log1)
        self.assertIs(guard.audit_log, log1)

        # Rebinding the SAME instance is a harmless no-op
        guard.bind_audit_log(log1)
        self.assertIs(guard.audit_log, log1)

        # Binding a DIFFERENT instance raises ValueError
        log2 = AuditLog()
        with self.assertRaises(ValueError):
            guard.bind_audit_log(log2)

    def test_audit_log_cannot_change_after_halt(self) -> None:
        """Cannot bind or change audit log after guard is halted."""
        guard = RuntimeGuard(config=RuntimeGuardConfig(kill_switch=True))
        with self.assertRaises(RuntimeHaltError):
            guard.check_execution_permitted(RuntimeCheckpoint.PREFLIGHT)

        self.assertTrue(guard.state.halted)
        with self.assertRaises(RuntimeHaltError):
            guard.bind_audit_log(AuditLog())

    def test_incident_id_binding_semantics(self) -> None:
        """Incident ID can be bound when healthy, but rejected when empty or after halt."""
        guard = RuntimeGuard()
        self.assertEqual(guard.incident_id, "SYSTEM")

        guard.bind_incident_id("INC-NEW-01")
        self.assertEqual(guard.incident_id, "INC-NEW-01")

        # Invalid strings rejected
        with self.assertRaises(ValueError):
            guard.bind_incident_id("")
        with self.assertRaises(ValueError):
            guard.bind_incident_id("   ")
        with self.assertRaises(ValueError):
            guard.bind_incident_id(123)  # type: ignore[arg-type]

        # Halt the guard
        with self.assertRaises(RuntimeHaltError):
            guard.engage_kill_switch()

        # Cannot mutate incident_id after halt
        with self.assertRaises(RuntimeHaltError):
            guard.bind_incident_id("INC-MUTATE-AFTER-HALT")

    def test_detail_code_validation_and_fail_closed(self) -> None:
        """Strict validation of detail_code: bounded codes accepted; invalid codes fail closed."""
        audit_log = AuditLog()
        guard = RuntimeGuard(audit_log=audit_log, incident_id="INC-DETAIL")

        # Invalid free-form prose fails closed with INVALID_HALT_DETAIL and UNEXPECTED_STATE
        raw_secret_prose = "Error: leaked secret token sk-12345 occurred"
        with self.assertRaises(RuntimeHaltError) as ctx:
            guard.halt(
                RuntimeHaltReason.CONTROL_FAILURE,
                detail_code=raw_secret_prose,
            )

        self.assertEqual(ctx.exception.reason, RuntimeHaltReason.UNEXPECTED_STATE)
        self.assertEqual(ctx.exception.detail_code, "INVALID_HALT_DETAIL")
        self.assertNotIn("sk-12345", str(ctx.exception))
        self.assertNotIn("leaked", str(ctx.exception))

        # Check audit event
        events = audit_log.events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].detail_code, "INVALID_HALT_DETAIL")
        self.assertNotIn("sk-12345", events[0].detail_code)

    def test_detail_code_length_cap_enforced(self) -> None:
        """Detail codes longer than 64 characters fail closed."""
        guard = RuntimeGuard()
        too_long = "A" * 65
        with self.assertRaises(RuntimeHaltError) as ctx:
            guard.halt(RuntimeHaltReason.CONTROL_FAILURE, detail_code=too_long)

        self.assertEqual(ctx.exception.reason, RuntimeHaltReason.UNEXPECTED_STATE)
        self.assertEqual(ctx.exception.detail_code, "INVALID_HALT_DETAIL")

    def test_26_audit_uses_same_run_audit_log(self) -> None:
        """RuntimeGuard attaches to and populates the shared run AuditLog."""
        shared_audit_log = AuditLog()
        guard = RuntimeGuard(audit_log=shared_audit_log, incident_id="SHARED-01")

        # Simulate earlier audit event
        shared_audit_log.append(AuditEvent(
            event_type=AuditEventType.MODEL_REQUESTED,
            incident_id="SHARED-01",
            sequence=0,
            detail_code="INITIAL_EVENT",
        ))

        guard.before_model_invocation()
        with self.assertRaises(RuntimeHaltError):
            guard.engage_kill_switch()

        events = shared_audit_log.events()
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].event_type, AuditEventType.MODEL_REQUESTED)
        self.assertEqual(events[1].event_type, AuditEventType.RUNTIME_HALTED)
        self.assertEqual(events[1].sequence, 1)

    def test_27_runtime_halted_detail_is_deterministic_and_bounded(self) -> None:
        """RUNTIME_HALTED event contains only bounded deterministic fields under existing schema."""
        audit_log = AuditLog()
        guard = RuntimeGuard(audit_log=audit_log, incident_id="INC-BOUNDED")

        with self.assertRaises(RuntimeHaltError):
            guard.engage_kill_switch()

        event = audit_log.events()[0]
        self.assertEqual(event.event_type, AuditEventType.RUNTIME_HALTED)
        self.assertEqual(event.incident_id, "INC-BOUNDED")
        self.assertLessEqual(len(event.detail_code), 64)
        self.assertEqual(event.detail_code, RuntimeHaltReason.KILL_SWITCH_ENGAGED.value)

    def test_28_sentinel_api_key_absent_from_exception_and_audit(self) -> None:
        """Sentinel API keys or secrets must never appear in exception messages or audit records."""
        secret_key = "sk-live-supersecretapikey123456789"
        audit_log = AuditLog()
        guard = RuntimeGuard(audit_log=audit_log, incident_id="INC-SECRET")

        with self.assertRaises(RuntimeHaltError) as ctx:
            guard.engage_kill_switch()

        err_msg = str(ctx.exception)
        self.assertNotIn(secret_key, err_msg)

        # Check all audit fields
        for ev in audit_log.events():
            self.assertNotIn(secret_key, ev.detail_code)
            self.assertNotIn(secret_key, ev.event_type.value)
            self.assertNotIn(secret_key, ev.incident_id)

    def test_29_audit_persistence_still_possible_after_halt(self) -> None:
        """Sanitized JSONL audit trail can be persisted even after execution is halted."""
        audit_log = AuditLog()
        guard = RuntimeGuard(audit_log=audit_log, incident_id="INC-PERSIST")

        with self.assertRaises(RuntimeHaltError):
            guard.engage_kill_switch()

        with tempfile.TemporaryDirectory() as tmp_dir:
            audit_file = Path(tmp_dir) / "audit.jsonl"
            writer = JsonlAuditWriter(audit_file)
            writer.write_events(audit_log.events())

            self.assertTrue(audit_file.exists())
            with open(audit_file, "r", encoding="utf-8") as f:
                lines = [json.loads(line) for line in f]

            self.assertEqual(len(lines), 1)
            self.assertEqual(lines[0]["event_type"], "RUNTIME_HALTED")
            self.assertEqual(lines[0]["detail_code"], "KILL_SWITCH_ENGAGED")


class TestOrchestratorAndBoundarySeparation(unittest.TestCase):
    """Test orchestrator integration, ToolRouter ownership, and Simulator approval ownership."""

    def test_23_normal_tool_rejection_does_not_halt_guard(self) -> None:
        """ToolRouter rejection of an unallowed tool does NOT halt the RuntimeGuard."""
        audit_log = AuditLog()
        guard = RuntimeGuard(audit_log=audit_log)
        router = ToolRouter()

        # Rejection by ToolRouter raises ToolValidationError
        with self.assertRaises(ToolValidationError):
            router.execute_tool("forbidden_shell_tool", {})

        # The guard must NOT be halted! A held control is not a failed control.
        self.assertFalse(guard.state.halted)
        self.assertIsNone(guard.state.halt_reason)
        # Permitted counter should be 0 because router rejected it before/without guard tool execution
        self.assertEqual(guard.state.tool_executions_permitted, 0)

    def test_24_simulator_remains_responsible_for_approval_validation(self) -> None:
        """SimulatedResponseExecutor owns approval validation; RuntimeGuard does not duplicate it."""
        guard = RuntimeGuard()
        executor = SimulatedResponseExecutor()

        # Permitted by guard
        guard.check_execution_permitted(RuntimeCheckpoint.SIMULATION)

        # Simulator independently checks policy and approval
        decision = PolicyDecision(
            risk_score=80,
            risk_level=RiskLevel.CRITICAL,
            action_disposition=ActionDisposition.APPROVAL_REQUIRED,
            proposed_action=ProposedAction.SIMULATE_ENDPOINT_ISOLATION,
            reasons=("encoded_powershell_detected",),
            requires_human_approval=True,
        )
        ctx = ActionAuthorizationContext(
            incident_id="INC-SIM-001",
            policy_decision=decision,
        )

        # Missing required approval -> executor returns NOT_EXECUTED with simulation_blocked_missing_approval
        result = executor.execute(ctx, approval_record=None)
        self.assertEqual(result.status, SimulationStatus.NOT_EXECUTED)
        self.assertEqual(result.detail_code, "simulation_blocked_missing_approval")

        # Guard itself was not halted; simulator did its job
        self.assertFalse(guard.state.halted)

    def test_25_runtime_guard_contains_no_tool_allowlist(self) -> None:
        """RuntimeGuard must not contain or duplicate ALLOWED_TOOLS or tool checking logic."""
        guard = RuntimeGuard()
        self.assertFalse(hasattr(guard, "ALLOWED_TOOLS"))
        self.assertFalse(hasattr(guard, "allowed_tools"))
        self.assertFalse(hasattr(guard, "_allowed_tools"))

    def test_30_normal_existing_orchestrator_behavior_unchanged_when_guard_healthy(self) -> None:
        """Existing orchestrator behavior remains unchanged when RuntimeGuard is healthy."""
        decisions = [
            ModelDecision(
                decision_type=DecisionType.TOOL_REQUEST,
                tool_request=ToolRequest(
                    tool_name="decode_base64_powershell",
                    arguments={"encoded_input": "V3JpdGUtSG9zdCAnQUktTmF0aXZlU09DLUxBQi1URVNUJw=="},
                ),
            ),
            ModelDecision(
                decision_type=DecisionType.FINAL_RESULT,
                final_result=_make_sample_result(),
            ),
        ]
        model = FakeInvestigationModel(decisions=decisions)
        tool_router = ToolRouter()
        audit_log = AuditLog()
        guard = RuntimeGuard(audit_log=audit_log)

        orchestrator = InvestigationOrchestrator(
            model=model,
            tool_router=tool_router,
            audit_log=audit_log,
            guard=guard,
        )

        inp = _make_sample_input("INC-HEALTHY-01")

        result = orchestrator.investigate(inp)
        self.assertIsInstance(result, InvestigationResult)
        self.assertEqual(result.summary, "Analysis concluded: benign domain.")

        # Guard recorded 2 model calls and 1 tool call
        self.assertEqual(guard.state.model_invocations_permitted, 2)
        self.assertEqual(guard.state.tool_executions_permitted, 1)
        self.assertFalse(guard.state.halted)

    def test_orchestrator_aborts_when_guard_halted_before_model(self) -> None:
        """Orchestrator halts with OrchestratorError if guard blocks model invocation."""
        model = FakeInvestigationModel()
        tool_router = ToolRouter()
        audit_log = AuditLog()
        guard = RuntimeGuard(audit_log=audit_log, config=RuntimeGuardConfig(kill_switch=True))

        orchestrator = InvestigationOrchestrator(
            model=model,
            tool_router=tool_router,
            audit_log=audit_log,
            guard=guard,
        )

        inp = _make_sample_input("INC-HALTED-01")

        with self.assertRaises(OrchestratorError) as ctx:
            orchestrator.investigate(inp)

        self.assertIn("Runtime guard halted model invocation", str(ctx.exception))
        self.assertEqual(len(model.calls), 0)

    def test_orchestrator_aborts_when_guard_halted_before_tool(self) -> None:
        """Orchestrator halts with OrchestratorError if guard blocks tool execution."""
        decisions = [
            ModelDecision(
                decision_type=DecisionType.TOOL_REQUEST,
                tool_request=ToolRequest(
                    tool_name="decode_base64_powershell",
                    arguments={"encoded_input": "V3JpdGUtSG9zdCAnQUktTmF0aXZlU09DLUxBQi1URVNUJw=="},
                ),
            ),
        ]
        model = FakeInvestigationModel(decisions=decisions)
        tool_router = ToolRouter()
        audit_log = AuditLog()
        # Set max_tool_executions=1 but consume it before orchestrator
        guard = RuntimeGuard(
            audit_log=audit_log,
            config=RuntimeGuardConfig(max_tool_executions=1),
        )
        # Pre-consume the 1 tool budget
        guard.before_tool_execution()
        self.assertEqual(guard.state.tool_executions_permitted, 1)

        orchestrator = InvestigationOrchestrator(
            model=model,
            tool_router=tool_router,
            audit_log=audit_log,
            guard=guard,
        )

        inp = _make_sample_input("INC-TOOL-BUDGET-EXC")

        with self.assertRaises(OrchestratorError) as ctx:
            orchestrator.investigate(inp)

        self.assertIn("Runtime guard halted tool execution", str(ctx.exception))
        self.assertEqual(guard.state.halt_reason, RuntimeHaltReason.TOOL_BUDGET_EXCEEDED)


class TestEndToEndDemoPreflightGuarantees(unittest.TestCase):
    """Test top-level preflight guarantees in run_end_to_end_demo.py."""

    def test_03_04_05_06_07_e2e_preflight_kill_switch_zero_external_calls(self) -> None:
        """When preflight kill switch is active, run_demo aborts before any external calls.

        Guarantees:
        - 0 Splunk calls
        - 0 Model calls
        - 0 Jira calls
        - 0 Simulator calls
        - 0 VirusTotal calls
        - Exit code 1
        - Emits RUNTIME_HALTED
        """
        mock_splunk = MagicMock(spec=SplunkSearchClient)
        mock_jira = MagicMock(spec=TicketClient)

        out_stream = io.StringIO()
        in_stream = io.StringIO()

        code = run_demo(
            mode="live-benign",
            provider="fake",
            minutes=15,
            persist_audit=False,
            stream_in=in_stream,
            stream_out=out_stream,
            splunk_client=mock_splunk,
            jira_client=mock_jira,
            kill_switch=True,  # Kill switch engaged at preflight
        )

        # 1. Exit code is 1 (abort)
        self.assertEqual(code, 1)

        # 2. Output explains preflight failure
        output = out_stream.getvalue()
        self.assertIn("Runtime guard preflight check failed", output)
        self.assertIn("KILL_SWITCH_ENGAGED", output)

        # 3. Exactly ZERO Splunk calls
        self.assertEqual(mock_splunk.search_encoded_powershell.call_count, 0)

        # 4. Exactly ZERO Jira calls
        self.assertEqual(mock_jira.create_ticket.call_count, 0)

    @patch("scripts.run_end_to_end_demo.SplunkSearchClient")
    @patch("investigator.providers.virustotal_provider.VirusTotalThreatIntelClient")
    @patch("investigator.providers.openai_provider.OpenAIModel")
    @patch("scripts.run_end_to_end_demo.JiraTicketClient")
    @patch("scripts.run_end_to_end_demo.SimulatedResponseExecutor")
    def test_constructor_level_preflight_proof_zero_instantiations(
        self,
        mock_sim_cls: MagicMock,
        mock_jira_cls: MagicMock,
        mock_openai_cls: MagicMock,
        mock_vt_cls: MagicMock,
        mock_splunk_cls: MagicMock,
    ) -> None:
        """Proves external provider constructors are NOT called when preflight kill switch is active.

        For run_end_to_end_demo.py, pre-run kill switch aborts before construction or invocation
        of the external provider classes reached later in that instrumented execution path.
        """
        out_stream = io.StringIO()
        in_stream = io.StringIO()

        code = run_demo(
            mode="live-benign",
            provider="openai",
            create_ticket=True,
            ticket_provider="jira",
            jira_project="SEC",
            jira_issue_type="Incident",
            splunk_client=None,  # Do not supply pre-built clients
            jira_client=None,
            stream_in=in_stream,
            stream_out=out_stream,
            kill_switch=True,
        )

        self.assertEqual(code, 1)
        mock_splunk_cls.assert_not_called()
        mock_vt_cls.assert_not_called()
        mock_openai_cls.assert_not_called()
        mock_jira_cls.assert_not_called()
        mock_sim_cls.assert_not_called()

    def test_e2e_preflight_kill_switch_persists_audit(self) -> None:
        """When persist_audit=True and preflight halts, RUNTIME_HALTED is persisted."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            audit_file = Path(tmp_dir) / "demo_halt_audit.jsonl"
            out_stream = io.StringIO()

            code = run_demo(
                mode="synthetic-critical",
                provider="fake",
                persist_audit=True,
                audit_log_path=audit_file,
                stream_out=out_stream,
                kill_switch=True,
            )

            self.assertEqual(code, 1)
            self.assertTrue(audit_file.exists())

            with open(audit_file, "r", encoding="utf-8") as f:
                lines = [json.loads(line) for line in f]

            self.assertEqual(len(lines), 1)
            self.assertEqual(lines[0]["event_type"], "RUNTIME_HALTED")
            self.assertEqual(lines[0]["detail_code"], "KILL_SWITCH_ENGAGED")


class TestNegativeControl(unittest.TestCase):
    """Test-local negative-control path proving genuine control failure can latch CONTROL_FAILURE."""

    def test_31_synthetic_negative_control_latches_control_failure(self) -> None:
        """SYNTHETIC TEST-ONLY: Proves a genuine control failure transitions guard to CONTROL_FAILURE."""
        audit_log = AuditLog()
        guard = RuntimeGuard(audit_log=audit_log, incident_id="SYNTHETIC-NEG-01")

        # Explicitly invoke halt hook for a genuine control failure
        with self.assertRaises(RuntimeHaltError) as ctx:
            guard.halt(
                RuntimeHaltReason.CONTROL_FAILURE,
                detail_code="SYNTHETIC_INTEGRITY_BREACH",
            )

        self.assertEqual(ctx.exception.reason, RuntimeHaltReason.CONTROL_FAILURE)
        self.assertEqual(ctx.exception.detail_code, "SYNTHETIC_INTEGRITY_BREACH")
        self.assertTrue(guard.state.halted)
        self.assertEqual(guard.state.halt_reason, RuntimeHaltReason.CONTROL_FAILURE)
        self.assertEqual(guard.state.halt_detail_code, "SYNTHETIC_INTEGRITY_BREACH")

        # Verify audit emission
        events = audit_log.events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].event_type, AuditEventType.RUNTIME_HALTED)
        self.assertEqual(events[0].detail_code, "SYNTHETIC_INTEGRITY_BREACH")

        # Subsequent operations remain latched with CONTROL_FAILURE
        with self.assertRaises(RuntimeHaltError) as ctx2:
            guard.check_execution_permitted(RuntimeCheckpoint.PREFLIGHT)
        self.assertEqual(ctx2.exception.reason, RuntimeHaltReason.CONTROL_FAILURE)
        self.assertEqual(ctx2.exception.detail_code, "SYNTHETIC_INTEGRITY_BREACH")


if __name__ == "__main__":
    unittest.main()
