"""Deterministic Runtime Monitoring and Kill-Switch / Execution-Abort Controls.

Architecture Guarantees:
  1. Orthogonal Execution Supervision: RuntimeGuard operates outside model-controlled
     data, prompts, and tool results. Untrusted text cannot disable or alter the guard.
  2. Irreversible Latch: Once transitioned from RUNNING to HALTED, the guard remains
     permanently halted for that instance, preserving the first halt reason and detail.
  3. Single-Owner Audit: Exactly one RUNTIME_HALTED event is emitted upon latching.
     Subsequent blocked calls fail closed with the original reason and detail, and
     do not emit duplicate audit events.
  4. Separation of Concerns:
     - RuntimeGuard owns: kill switch, halted latch, execution budgets, global abort.
     - ToolRouter owns: allowed tool set, argument validation, tool dispatch.
     - RiskPolicyEngine owns: risk scoring, determining if approval is required.
     - ApprovalGate owns: capturing operator approval/denial.
     - SimulatedResponseExecutor owns: approval invariant validation and response simulation.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import os
import re
from typing import Mapping, Optional, Tuple

from investigator.audit import AuditEvent, AuditEventType, AuditLog


# Strict upper ceilings for runtime budgets
MAX_RUNTIME_MODEL_BUDGET: int = 50
MAX_RUNTIME_TOOL_BUDGET: int = 50

# Strict deterministic identifier format for halt detail codes
_DETAIL_CODE_PATTERN = re.compile(r"^[A-Z0-9_]{1,64}$")


class RuntimeCheckpoint(str, Enum):
    """Bounded, validated checkpoints for top-level lifecycle inspection."""
    PREFLIGHT = "PREFLIGHT"
    SIMULATION = "SIMULATION"
    TICKETING = "TICKETING"


class RuntimeHaltReason(str, Enum):
    """Deterministic, bounded machine-readable halt reasons."""
    KILL_SWITCH_ENGAGED = "KILL_SWITCH_ENGAGED"
    MODEL_BUDGET_EXCEEDED = "MODEL_BUDGET_EXCEEDED"
    TOOL_BUDGET_EXCEEDED = "TOOL_BUDGET_EXCEEDED"
    CONTROL_FAILURE = "CONTROL_FAILURE"
    UNEXPECTED_STATE = "UNEXPECTED_STATE"


class RuntimeHaltError(Exception):
    """Raised when runtime guard halts execution or blocks an operation."""

    def __init__(self, reason: RuntimeHaltReason, detail_code: Optional[str] = None) -> None:
        self.reason = reason
        self.detail_code = detail_code or reason.value
        super().__init__(f"Runtime execution halted: {self.detail_code}")


@dataclass(frozen=True)
class RuntimeGuardConfig:
    """Immutable resolved configuration for the runtime safety guard."""
    kill_switch: bool = False
    max_model_invocations: int = 4
    max_tool_executions: int = 3

    def __post_init__(self) -> None:
        if type(self.kill_switch) is not bool:
            raise TypeError("kill_switch must be a bool")
        if type(self.max_model_invocations) is not int:
            raise TypeError("max_model_invocations must be an int")
        if not (1 <= self.max_model_invocations <= MAX_RUNTIME_MODEL_BUDGET):
            raise ValueError(
                f"max_model_invocations must be between 1 and {MAX_RUNTIME_MODEL_BUDGET}"
            )
        if type(self.max_tool_executions) is not int:
            raise TypeError("max_tool_executions must be an int")
        if not (1 <= self.max_tool_executions <= MAX_RUNTIME_TOOL_BUDGET):
            raise ValueError(
                f"max_tool_executions must be between 1 and {MAX_RUNTIME_TOOL_BUDGET}"
            )

    @classmethod
    def from_env(
        cls,
        env: Optional[Mapping[str, str]] = None,
        max_model_invocations: int = 4,
        max_tool_executions: int = 3,
    ) -> RuntimeGuardConfig:
        """Resolve config once from environment with strict fail-closed parsing.

        Accepted Inactive: "", "0", "false", "no", "off" (or unset) -> kill_switch=False
        Accepted Active:   "1", "true", "yes", "on"                 -> kill_switch=True
        Any other string:  FAIL CLOSED                              -> kill_switch=True
        """
        active_env = env if env is not None else os.environ
        raw = active_env.get("AI_SOC_KILL_SWITCH")

        if raw is None:
            kill_switch = False
        else:
            cleaned = raw.strip().lower()
            if cleaned in {"", "0", "false", "no", "off"}:
                kill_switch = False
            elif cleaned in {"1", "true", "yes", "on"}:
                kill_switch = True
            else:
                # Malformed or unexpected value fails closed
                kill_switch = True

        return cls(
            kill_switch=kill_switch,
            max_model_invocations=max_model_invocations,
            max_tool_executions=max_tool_executions,
        )


@dataclass(frozen=True)
class RuntimeGuardState:
    """Immutable state snapshot of the runtime guard."""
    kill_switch_engaged: bool
    halted: bool
    halt_reason: Optional[RuntimeHaltReason]
    halt_detail_code: Optional[str]
    model_invocations_permitted: int
    tool_executions_permitted: int


def _validate_detail_code(
    reason: RuntimeHaltReason,
    detail_code: Optional[str],
) -> Tuple[RuntimeHaltReason, str]:
    """Validate or derive machine-readable detail_code.

    If detail_code is None: returns (reason, reason.value).
    If detail_code matches ^[A-Z0-9_]{1,64}$: returns (reason, detail_code).
    Otherwise: fails closed to (RuntimeHaltReason.UNEXPECTED_STATE, "INVALID_HALT_DETAIL").
    """
    if detail_code is None:
        return reason, reason.value
    if isinstance(detail_code, str) and _DETAIL_CODE_PATTERN.match(detail_code):
        return reason, detail_code
    return RuntimeHaltReason.UNEXPECTED_STATE, "INVALID_HALT_DETAIL"


class RuntimeGuard:
    """Stateful, deterministic runtime safety guard."""

    def __init__(
        self,
        config: Optional[RuntimeGuardConfig] = None,
        audit_log: Optional[AuditLog] = None,
        incident_id: str = "SYSTEM",
    ) -> None:
        self._config = config or RuntimeGuardConfig()
        self._audit_log = audit_log
        self._incident_id = incident_id.strip() if isinstance(incident_id, str) and incident_id.strip() else "SYSTEM"
        self._kill_switch_engaged = self._config.kill_switch
        self._halted: bool = False
        self._halt_reason: Optional[RuntimeHaltReason] = None
        self._halt_detail_code: Optional[str] = None
        self._model_invocations_permitted: int = 0
        self._tool_executions_permitted: int = 0

    @property
    def state(self) -> RuntimeGuardState:
        """Return an immutable snapshot of current guard state."""
        return RuntimeGuardState(
            kill_switch_engaged=self._kill_switch_engaged,
            halted=self._halted,
            halt_reason=self._halt_reason,
            halt_detail_code=self._halt_detail_code,
            model_invocations_permitted=self._model_invocations_permitted,
            tool_executions_permitted=self._tool_executions_permitted,
        )

    @property
    def audit_log(self) -> Optional[AuditLog]:
        """Return the attached AuditLog instance, or None if unattached."""
        return self._audit_log

    @property
    def incident_id(self) -> str:
        """Return the bound incident identifier."""
        return self._incident_id

    def bind_audit_log(self, audit_log: AuditLog) -> None:
        """Attach shared AuditLog instance exactly once.

        Raises:
            RuntimeHaltError: If guard is already halted.
            TypeError: If audit_log is not an AuditLog instance.
            ValueError: If attempting to bind a different AuditLog than the currently bound instance.
        """
        if self._halted:
            self._raise_halted()

        if not isinstance(audit_log, AuditLog):
            raise TypeError("audit_log must be an AuditLog instance")

        if self._audit_log is audit_log:
            return

        if self._audit_log is not None:
            raise ValueError("RuntimeGuard already bound to a different AuditLog instance")

        self._audit_log = audit_log

    def set_audit_log(self, audit_log: AuditLog) -> None:
        """Compatibility wrapper for bind_audit_log."""
        self.bind_audit_log(audit_log)

    def bind_incident_id(self, incident_id: str) -> None:
        """Bind active incident identifier while guard is running/healthy.

        Raises:
            RuntimeHaltError: If guard is already halted.
            ValueError: If incident_id is not a non-empty string.
        """
        if self._halted:
            self._raise_halted()

        if type(incident_id) is not str or not incident_id.strip():
            raise ValueError("incident_id must be a non-empty str")

        self._incident_id = incident_id.strip()

    def set_incident_id(self, incident_id: str) -> None:
        """Compatibility wrapper for bind_incident_id."""
        self.bind_incident_id(incident_id)

    def _raise_halted(self) -> None:
        """Raise RuntimeHaltError preserving the original halt reason and detail code."""
        assert self._halt_reason is not None
        assert self._halt_detail_code is not None
        raise RuntimeHaltError(self._halt_reason, self._halt_detail_code)

    def _transition_to_halt(
        self,
        reason: RuntimeHaltReason,
        detail_code: Optional[str] = None,
    ) -> None:
        """Irreversible one-way transition from RUNNING to HALTED.

        Guarantees:
          - Emits exactly one RUNTIME_HALTED event on the first transition.
          - Subsequent calls preserve original halt_reason and halt_detail_code,
            and do not duplicate audit events.
        """
        if self._halted:
            return

        effective_reason, effective_code = _validate_detail_code(reason, detail_code)

        self._halted = True
        self._halt_reason = effective_reason
        self._halt_detail_code = effective_code

        if self._audit_log is not None:
            seq = len(self._audit_log.events())
            self._audit_log.append(
                AuditEvent(
                    event_type=AuditEventType.RUNTIME_HALTED,
                    incident_id=self._incident_id,
                    sequence=seq,
                    detail_code=self._halt_detail_code,
                )
            )

    def check_execution_permitted(self, checkpoint: RuntimeCheckpoint) -> None:
        """Check top-level execution boundary (PREFLIGHT, SIMULATION, TICKETING).

        Raises:
            RuntimeHaltError: If halted, invalid checkpoint, or kill switch is engaged.
        """
        if self._halted:
            self._raise_halted()

        if not isinstance(checkpoint, RuntimeCheckpoint):
            self._transition_to_halt(RuntimeHaltReason.UNEXPECTED_STATE, "INVALID_CHECKPOINT")
            self._raise_halted()

        if self._kill_switch_engaged:
            self._transition_to_halt(RuntimeHaltReason.KILL_SWITCH_ENGAGED)
            self._raise_halted()

    def before_model_invocation(self) -> None:
        """Hook evaluated before each model.decide() invocation.

        Increments model_invocations_permitted only when permitted.
        Raises:
            RuntimeHaltError: If halted, kill switch active, or model budget exceeded.
        """
        if self._halted:
            self._raise_halted()

        if self._kill_switch_engaged:
            self._transition_to_halt(RuntimeHaltReason.KILL_SWITCH_ENGAGED)
            self._raise_halted()

        if self._model_invocations_permitted >= self._config.max_model_invocations:
            self._transition_to_halt(RuntimeHaltReason.MODEL_BUDGET_EXCEEDED)
            self._raise_halted()

        self._model_invocations_permitted += 1

    def before_tool_execution(self) -> None:
        """Hook evaluated before each ToolRouter.execute_tool() call.

        Increments tool_executions_permitted only when permitted.
        Raises:
            RuntimeHaltError: If halted, kill switch active, or tool budget exceeded.
        """
        if self._halted:
            self._raise_halted()

        if self._kill_switch_engaged:
            self._transition_to_halt(RuntimeHaltReason.KILL_SWITCH_ENGAGED)
            self._raise_halted()

        if self._tool_executions_permitted >= self._config.max_tool_executions:
            self._transition_to_halt(RuntimeHaltReason.TOOL_BUDGET_EXCEEDED)
            self._raise_halted()

        self._tool_executions_permitted += 1

    def halt(self, reason: RuntimeHaltReason, detail_code: Optional[str] = None) -> None:
        """Explicitly transition runtime guard to HALTED state.

        Used for genuine externally detected control failures or manual emergency halts.
        If already halted, preserves original reason and detail code.
        """
        if not self._halted:
            self._transition_to_halt(reason, detail_code)
        self._raise_halted()

    def engage_kill_switch(self) -> None:
        """In-process operator/test method to immediately engage kill switch and halt.

        If already halted by another cause, preserves original halt cause while setting
        kill_switch_engaged=True.
        """
        self._kill_switch_engaged = True
        if not self._halted:
            self._transition_to_halt(RuntimeHaltReason.KILL_SWITCH_ENGAGED)
        self._raise_halted()
