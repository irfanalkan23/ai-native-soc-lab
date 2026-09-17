"""Human-in-the-loop authorization gate for consequential response actions.

Architecture Principle:
    AI proposes -> deterministic evidence/risk evaluation ->
    deterministic action policy -> human explicitly approves consequential actions ->
    deterministic simulator executes only simulated actions -> everything logged.

Trust & Scope Boundaries:
    - This module contains NO subprocess, shell, or OS execution capabilities.
    - This module creates NO network or socket connections.
    - This module calls NO WinRM, SSH, EDR, firewall, or cloud-control APIs.
    - This module NEVER mutates endpoint, network, or system state.
    - Approval provenance is deterministic application metadata binding, NOT cryptography.
    - Approver is a bounded local label ('human_operator'), NOT an authenticated identity.
"""

import io
import sys
from dataclasses import dataclass
from enum import Enum
from typing import Optional, TextIO

from investigator.audit import AuditEvent, AuditEventType, AuditLog
from investigator.policy import ActionDisposition, PolicyDecision, ProposedAction


class ApprovalGateError(ValueError):
    """Raised when the approval gate is misused, preconditions fail, or audit recording fails."""
    pass


DEFAULT_APPROVER = "human_operator"
MAX_APPROVER_LENGTH = 64
MAX_INCIDENT_ID_LENGTH = 64
MAX_CLI_RETRIES = 2  # Total attempts: 3


@dataclass(frozen=True)
class ActionAuthorizationContext:
    """Immutable context binding an incident to its evaluated PolicyDecision.

    Carries the incident identity and exact policy decision together, serving as
    the single authorization context for human approval and simulated execution.
    """
    incident_id: str
    policy_decision: PolicyDecision

    def __post_init__(self) -> None:
        if type(self.incident_id) is not str or not self.incident_id.strip():
            raise ValueError("incident_id must be a non-empty str")
        if len(self.incident_id) > MAX_INCIDENT_ID_LENGTH:
            raise ValueError(f"incident_id exceeds {MAX_INCIDENT_ID_LENGTH} characters")
        if any(ord(c) < 32 or ord(c) > 126 for c in self.incident_id):
            raise ValueError(
                "incident_id must contain only printable ASCII characters without control characters or newlines"
            )
        if type(self.policy_decision) is not PolicyDecision:
            raise ValueError(
                f"policy_decision must be exact PolicyDecision, got {type(self.policy_decision).__name__}"
            )


class ApprovalDecision(str, Enum):
    """Explicit human approval decision."""
    APPROVED = "APPROVED"
    DENIED = "DENIED"


class ApprovalReasonCode(str, Enum):
    """Allowlisted machine-readable approval reason codes."""
    APPROVAL_GRANTED = "approval_granted"
    APPROVAL_DENIED = "approval_denied"
    APPROVAL_INVALID_INPUT = "approval_invalid_input"


APPROVAL_REASON_CODES = frozenset({
    ApprovalReasonCode.APPROVAL_GRANTED.value,
    ApprovalReasonCode.APPROVAL_DENIED.value,
    ApprovalReasonCode.APPROVAL_INVALID_INPUT.value,
})


@dataclass(frozen=True)
class ApprovalRecord:
    """Immutable record of an explicit human authorization decision."""
    incident_id: str
    proposed_action: ProposedAction
    decision: ApprovalDecision
    approver: str
    reason_code: str

    def __post_init__(self) -> None:
        # 1. Exact-type validation (subclasses rejected)
        if type(self.incident_id) is not str or not self.incident_id.strip():
            raise ValueError("incident_id must be a non-empty str")
        if len(self.incident_id) > MAX_INCIDENT_ID_LENGTH:
            raise ValueError(f"incident_id exceeds {MAX_INCIDENT_ID_LENGTH} characters")
        if any(ord(c) < 32 or ord(c) > 126 for c in self.incident_id):
            raise ValueError(
                "incident_id must contain only printable ASCII characters without control characters or newlines"
            )
        if type(self.proposed_action) is not ProposedAction:
            raise ValueError(
                f"proposed_action must be exact ProposedAction, got {type(self.proposed_action).__name__}"
            )
        if type(self.decision) is not ApprovalDecision:
            raise ValueError(
                f"decision must be exact ApprovalDecision, got {type(self.decision).__name__}"
            )

        # 2. Fixed approver label validation (V1 requires exact default label)
        if type(self.approver) is not str or self.approver != DEFAULT_APPROVER:
            raise ValueError(f"approver must be '{DEFAULT_APPROVER}', got '{self.approver}'")

        # 3. Allowlisted reason code validation
        if self.reason_code not in APPROVAL_REASON_CODES:
            raise ValueError(f"reason_code '{self.reason_code}' not in allowlist")

        # 4. Strict Decision / Reason Code Consistency
        if self.decision is ApprovalDecision.APPROVED:
            if self.reason_code != ApprovalReasonCode.APPROVAL_GRANTED.value:
                raise ValueError(
                    f"decision APPROVED requires reason_code '{ApprovalReasonCode.APPROVAL_GRANTED.value}', "
                    f"got '{self.reason_code}'"
                )
        elif self.decision is ApprovalDecision.DENIED:
            if self.reason_code not in {
                ApprovalReasonCode.APPROVAL_DENIED.value,
                ApprovalReasonCode.APPROVAL_INVALID_INPUT.value,
            }:
                raise ValueError(
                    f"decision DENIED requires reason_code in "
                    f"{APPROVAL_REASON_CODES - {ApprovalReasonCode.APPROVAL_GRANTED.value}}, "
                    f"got '{self.reason_code}'"
                )


def _validate_approval_required(context: ActionAuthorizationContext) -> None:
    """Verify that the policy context strictly satisfies the consequential approval contract."""
    if type(context) is not ActionAuthorizationContext:
        raise ApprovalGateError("context must be exact ActionAuthorizationContext")

    decision = context.policy_decision
    if not (
        decision.proposed_action is ProposedAction.SIMULATE_ENDPOINT_ISOLATION
        and decision.action_disposition is ActionDisposition.APPROVAL_REQUIRED
        and decision.requires_human_approval is True
    ):
        raise ApprovalGateError("approval_not_required")


def _append_audit_event(
    audit_log: Optional[AuditLog],
    event_type: AuditEventType,
    incident_id: str,
    detail_code: str,
) -> None:
    """Helper to append an audit event with fail-closed error handling."""
    if audit_log is None:
        return
    try:
        seq = len(audit_log.events())
        audit_log.append(AuditEvent(
            event_type=event_type,
            incident_id=incident_id,
            sequence=seq,
            detail_code=detail_code,
        ))
    except Exception as exc:
        raise ApprovalGateError("audit_recording_failed") from exc


def request_cli_approval(
    context: ActionAuthorizationContext,
    stream_in: Optional[TextIO] = None,
    stream_out: Optional[TextIO] = None,
    audit_log: Optional[AuditLog] = None,
) -> ApprovalRecord:
    """Interactively request human authorization for a consequential action via CLI.

    Preconditions:
        - context.policy_decision must mandate human approval for SIMULATE_ENDPOINT_ISOLATION.
          Non-consequential policy outcomes fail deterministically with ApprovalGateError.

    Fail-Closed Rules:
        - Human must explicitly enter 'approve' or 'deny'.
        - Up to MAX_CLI_RETRIES retries for invalid input before failing closed to DENIED.
        - Abrupt I/O failure (EOF, KeyboardInterrupt, broken pipe) immediately fails closed to DENIED.
        - If 'approve' is entered, APPROVAL_GRANTED must be recorded to audit_log BEFORE
          returning the approved record. If recording fails, raises ApprovalGateError.

    Returns:
        Validated immutable ApprovalRecord.
    """
    _validate_approval_required(context)

    in_stream = stream_in if stream_in is not None else sys.stdin
    out_stream = stream_out if stream_out is not None else sys.stdout

    # Record prompt presentation in audit trail
    _append_audit_event(
        audit_log,
        AuditEventType.APPROVAL_REQUESTED,
        context.incident_id,
        "approval_requested",
    )

    # Render safe summary metadata (zero telemetry, command lines, or secrets)
    decision = context.policy_decision
    out_stream.write("\n" + "=" * 60 + "\n")
    out_stream.write("              HUMAN APPROVAL REQUIRED\n")
    out_stream.write("=" * 60 + "\n")
    out_stream.write(f"  Incident ID:       {context.incident_id}\n")
    out_stream.write(f"  Risk Level:        {decision.risk_level.value}\n")
    out_stream.write(f"  Proposed Action:   {decision.proposed_action.value}\n")
    out_stream.write(f"  Approval Required: yes\n")
    out_stream.write("=" * 60 + "\n")
    out_stream.flush()

    attempts_left = MAX_CLI_RETRIES + 1

    while attempts_left > 0:
        attempts_left -= 1
        out_stream.write("Approve simulated action? [approve/deny]: ")
        out_stream.flush()

        try:
            line = in_stream.readline()
            if not line:
                # EOF reached on input stream
                return _record_denial(
                    context.incident_id,
                    decision.proposed_action,
                    ApprovalReasonCode.APPROVAL_DENIED.value,
                    audit_log,
                )
        except (EOFError, KeyboardInterrupt, io.UnsupportedOperation, OSError, BrokenPipeError):
            return _record_denial(
                context.incident_id,
                decision.proposed_action,
                ApprovalReasonCode.APPROVAL_DENIED.value,
                audit_log,
            )

        val = line.strip().lower()

        if val == "approve":
            record = ApprovalRecord(
                incident_id=context.incident_id,
                proposed_action=decision.proposed_action,
                decision=ApprovalDecision.APPROVED,
                approver=DEFAULT_APPROVER,
                reason_code=ApprovalReasonCode.APPROVAL_GRANTED.value,
            )
            # Mandatory audit fail-closed check BEFORE returning approved record
            _append_audit_event(
                audit_log,
                AuditEventType.APPROVAL_GRANTED,
                context.incident_id,
                "approval_granted",
            )
            return record

        if val == "deny":
            return _record_denial(
                context.incident_id,
                decision.proposed_action,
                ApprovalReasonCode.APPROVAL_DENIED.value,
                audit_log,
            )

        # Invalid input
        if attempts_left > 0:
            out_stream.write("Invalid input. Please enter 'approve' or 'deny'.\n")
            out_stream.flush()

    # Retries exhausted -> fail closed to denial
    out_stream.write("Maximum attempts exceeded. Action denied.\n")
    out_stream.flush()
    return _record_denial(
        context.incident_id,
        decision.proposed_action,
        ApprovalReasonCode.APPROVAL_INVALID_INPUT.value,
        audit_log,
    )


def _record_denial(
    incident_id: str,
    proposed_action: ProposedAction,
    reason_code: str,
    audit_log: Optional[AuditLog],
) -> ApprovalRecord:
    """Helper to record denial in audit trail and return validated denial record."""
    record = ApprovalRecord(
        incident_id=incident_id,
        proposed_action=proposed_action,
        decision=ApprovalDecision.DENIED,
        approver=DEFAULT_APPROVER,
        reason_code=reason_code,
    )
    _append_audit_event(
        audit_log,
        AuditEventType.APPROVAL_DENIED,
        incident_id,
        reason_code,
    )
    return record
