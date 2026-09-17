"""Deterministic simulated response action executor.

Architecture Principle:
    AI proposes -> deterministic evidence/risk evaluation ->
    deterministic action policy -> human explicitly approves consequential actions ->
    deterministic simulator executes only simulated actions -> everything logged.

Trust & Scope Boundaries:
    - This module contains NO subprocess, shell, or OS execution capabilities.
    - This module creates NO network or socket connections.
    - This module calls NO WinRM, SSH, EDR, firewall, or cloud-control APIs.
    - This module NEVER mutates endpoint, network, or system state.
    - Execution of SIMULATE_ENDPOINT_ISOLATION records solely that endpoint isolation
      would have been requested in a real deployment; zero actual containment occurs.
    - Derives target action strictly from PolicyDecision inside ActionAuthorizationContext.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from investigator.approval import (
    ActionAuthorizationContext,
    ApprovalDecision,
    ApprovalRecord,
)
from investigator.audit import AuditEvent, AuditEventType, AuditLog
from investigator.policy import ProposedAction


class SimulationError(ValueError):
    """Raised when simulation parameters or invariants are violated, or audit fails."""
    pass


class SimulationStatus(str, Enum):
    """Status outcome of the simulated response executor."""
    SIMULATED = "SIMULATED"
    NOT_EXECUTED = "NOT_EXECUTED"


SIMULATION_DETAIL_CODES = frozenset({
    "simulated_endpoint_isolation",
    "simulation_blocked_missing_approval",
    "simulation_blocked_mismatched_approval",
    "simulation_blocked_denied",
    "simulation_not_required",
    "human_review_required",
    "incident_record_deferred",
})


@dataclass(frozen=True)
class SimulationResult:
    """Immutable result of deterministic response simulation."""
    incident_id: str
    proposed_action: ProposedAction
    status: SimulationStatus
    detail_code: str

    def __post_init__(self) -> None:
        # Exact-type validation
        if type(self.incident_id) is not str or not self.incident_id.strip():
            raise ValueError("incident_id must be a non-empty str")
        if type(self.proposed_action) is not ProposedAction:
            raise ValueError(
                f"proposed_action must be exact ProposedAction, got {type(self.proposed_action).__name__}"
            )
        if type(self.status) is not SimulationStatus:
            raise ValueError(
                f"status must be exact SimulationStatus, got {type(self.status).__name__}"
            )
        if self.detail_code not in SIMULATION_DETAIL_CODES:
            raise ValueError(f"detail_code '{self.detail_code}' not in allowlist")


class SimulatedResponseExecutor:
    """Deterministic executor for simulated response actions."""

    def execute(
        self,
        authorization_context: ActionAuthorizationContext,
        approval_record: Optional[ApprovalRecord] = None,
        audit_log: Optional[AuditLog] = None,
    ) -> SimulationResult:
        """Simulate execution of an authorized policy action.

        Args:
            authorization_context: Immutable context binding incident ID and evaluated PolicyDecision.
            approval_record: Optional human approval record required for consequential actions.
            audit_log: Optional audit log for recording simulation lifecycle events.

        Returns:
            SimulationResult indicating SIMULATED or NOT_EXECUTED.

        Raises:
            SimulationError: If context/approval types are invalid, or if audit recording fails.
        """
        # Exact-type validation at the security boundary
        if type(authorization_context) is not ActionAuthorizationContext:
            raise SimulationError(
                f"authorization_context must be exact ActionAuthorizationContext, "
                f"got {type(authorization_context).__name__}"
            )
        if approval_record is not None and type(approval_record) is not ApprovalRecord:
            raise SimulationError(
                f"approval_record must be exact ApprovalRecord or None, "
                f"got {type(approval_record).__name__}"
            )

        incident_id = authorization_context.incident_id
        target_action = authorization_context.policy_decision.proposed_action

        # -------------------------------------------------------------------
        # Non-Consequential Policy Outcomes (Zero Simulation Machinery)
        # -------------------------------------------------------------------
        if target_action is ProposedAction.NO_ACTION:
            return self._record_and_return(
                incident_id, target_action, SimulationStatus.NOT_EXECUTED, "simulation_not_required", audit_log
            )
        if target_action is ProposedAction.MONITOR:
            return self._record_and_return(
                incident_id, target_action, SimulationStatus.NOT_EXECUTED, "simulation_not_required", audit_log
            )
        if target_action is ProposedAction.REQUEST_HUMAN_REVIEW:
            return self._record_and_return(
                incident_id, target_action, SimulationStatus.NOT_EXECUTED, "human_review_required", audit_log
            )
        if target_action is ProposedAction.CREATE_INCIDENT_RECORD:
            return self._record_and_return(
                incident_id, target_action, SimulationStatus.NOT_EXECUTED, "incident_record_deferred", audit_log
            )

        # -------------------------------------------------------------------
        # Consequential Action: SIMULATE_ENDPOINT_ISOLATION
        # -------------------------------------------------------------------
        if target_action is ProposedAction.SIMULATE_ENDPOINT_ISOLATION:
            # 1. Missing approval
            if approval_record is None:
                return self._record_and_return(
                    incident_id,
                    target_action,
                    SimulationStatus.NOT_EXECUTED,
                    "simulation_blocked_missing_approval",
                    audit_log,
                )

            # 2. Mismatched incident ID binding
            if approval_record.incident_id != incident_id:
                return self._record_and_return(
                    incident_id,
                    target_action,
                    SimulationStatus.NOT_EXECUTED,
                    "simulation_blocked_mismatched_approval",
                    audit_log,
                )

            # 3. Mismatched action binding
            if approval_record.proposed_action != target_action:
                return self._record_and_return(
                    incident_id,
                    target_action,
                    SimulationStatus.NOT_EXECUTED,
                    "simulation_blocked_mismatched_approval",
                    audit_log,
                )

            # 4. Explicitly denied approval
            if approval_record.decision is ApprovalDecision.DENIED:
                return self._record_and_return(
                    incident_id,
                    target_action,
                    SimulationStatus.NOT_EXECUTED,
                    "simulation_blocked_denied",
                    audit_log,
                )

            # 5. Approved and verified
            if approval_record.decision is ApprovalDecision.APPROVED:
                detail_code = "simulated_endpoint_isolation"
                if audit_log is not None:
                    try:
                        seq = len(audit_log.events())
                        audit_log.append(AuditEvent(
                            event_type=AuditEventType.SIMULATION_COMPLETED,
                            incident_id=incident_id,
                            sequence=seq,
                            detail_code=detail_code,
                        ))
                    except Exception as exc:
                        raise SimulationError("audit_recording_failed") from exc

                return SimulationResult(
                    incident_id=incident_id,
                    proposed_action=target_action,
                    status=SimulationStatus.SIMULATED,
                    detail_code=detail_code,
                )

            # Unknown/unsupported decision state fails closed
            raise SimulationError(f"unsupported_approval_decision: {approval_record.decision}")

        # Unknown/unsupported proposed action fails closed
        raise SimulationError(f"unsupported_proposed_action: {target_action}")

    def _record_and_return(
        self,
        incident_id: str,
        proposed_action: ProposedAction,
        status: SimulationStatus,
        detail_code: str,
        audit_log: Optional[AuditLog],
    ) -> SimulationResult:
        """Record simulation outcome event and return immutable result."""
        if audit_log is not None:
            try:
                seq = len(audit_log.events())
                audit_log.append(AuditEvent(
                    event_type=AuditEventType.SIMULATION_NOT_EXECUTED,
                    incident_id=incident_id,
                    sequence=seq,
                    detail_code=detail_code,
                ))
            except Exception as exc:
                raise SimulationError("audit_recording_failed") from exc

        return SimulationResult(
            incident_id=incident_id,
            proposed_action=proposed_action,
            status=status,
            detail_code=detail_code,
        )
