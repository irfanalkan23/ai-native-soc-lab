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
import re
import sys
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional, TextIO

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


class ApprovalValidationCode(str, Enum):
    """Deterministic validation codes for approval binding and consumption."""
    APPROVAL_VALID = "approval_valid"
    APPROVAL_MISSING = "approval_missing"
    APPROVAL_INCIDENT_MISMATCH = "approval_incident_mismatch"
    APPROVAL_ACTION_MISMATCH = "approval_action_mismatch"
    APPROVAL_POLICY_MISMATCH = "approval_policy_mismatch"
    APPROVAL_DENIED = "approval_denied"
    APPROVAL_ALREADY_CONSUMED = "approval_already_consumed"
    APPROVAL_MALFORMED = "approval_malformed"
    RUNTIME_HALTED = "runtime_halted"


APPROVAL_VALIDATION_CODES = frozenset({
    ApprovalValidationCode.APPROVAL_VALID.value,
    ApprovalValidationCode.APPROVAL_MISSING.value,
    ApprovalValidationCode.APPROVAL_INCIDENT_MISMATCH.value,
    ApprovalValidationCode.APPROVAL_ACTION_MISMATCH.value,
    ApprovalValidationCode.APPROVAL_POLICY_MISMATCH.value,
    ApprovalValidationCode.APPROVAL_DENIED.value,
    ApprovalValidationCode.APPROVAL_ALREADY_CONSUMED.value,
    ApprovalValidationCode.APPROVAL_MALFORMED.value,
    ApprovalValidationCode.RUNTIME_HALTED.value,
})

MAX_APPROVAL_ID_LENGTH = 64
SAFE_APPROVAL_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


@dataclass(frozen=True)
class ApprovalRecord:
    """Immutable record of an explicit human authorization decision."""
    incident_id: str
    proposed_action: ProposedAction
    decision: ApprovalDecision
    approver: str
    reason_code: str
    approval_id: str = ""

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

        # 5. approval_id validation or deterministic generation
        if not self.approval_id:
            raw_act = self.proposed_action.value.upper()
            clean_act = "".join(c for c in raw_act if c.isalnum() or c in ("_", "-"))[:24]
            generated_id = f"APP-{self.incident_id}-{clean_act}"
            if len(generated_id) > MAX_APPROVAL_ID_LENGTH:
                generated_id = generated_id[:MAX_APPROVAL_ID_LENGTH]
            object.__setattr__(self, "approval_id", generated_id)
        else:
            if type(self.approval_id) is not str or not self.approval_id.strip():
                raise ValueError("approval_id must be a non-empty str")
            if len(self.approval_id) > MAX_APPROVAL_ID_LENGTH:
                raise ValueError(f"approval_id exceeds {MAX_APPROVAL_ID_LENGTH} characters")
            if not SAFE_APPROVAL_ID_PATTERN.match(self.approval_id):
                raise ValueError(
                    "approval_id must be alphanumeric with underscores or dashes, no spaces or special characters"
                )


class ApprovalRegistry:
    """Stateful, in-memory replay-resistance registry for one-time approval consumption.

    Guarantees:
      - Validates approval binding (incident, proposed action, policy match, non-denial).
      - Tracks consumed authorizations both by explicit approval_id AND by the exact
        authorization grant identity: (incident_id, proposed_action).
      - A caller cannot manufacture a new approval authorization merely by changing or
        supplying an alternate approval_id for the same incident and action.
      - Enforces consume-before-execute one-time enforcement within the current trusted
        single-process lab execution model.
      - Checks RuntimeGuard precedence: if RuntimeGuard is provided and halted, validation fails closed.
      - Audits consumption and replay attempts deterministically.

    Lifetime Scope & Concurrency:
      - Approval consumption is enforced for the lifetime of the shared ApprovalRegistry instance.
      - Concurrent multi-threaded consumption is not currently claimed.
      - Persistent cross-restart replay hardening is scheduled for Milestone 16B.
    """

    def __init__(self) -> None:
        self._consumed_approval_ids: set[str] = set()
        self._consumed_grant_keys: set[tuple[str, str]] = set()

    def is_consumed(self, approval_id: str) -> bool:
        """Check whether an approval_id has already been consumed."""
        if not isinstance(approval_id, str) or not approval_id.strip():
            return False
        return approval_id in self._consumed_approval_ids

    def is_grant_consumed(self, incident_id: str, proposed_action: ProposedAction) -> bool:
        """Check whether the authorization grant for (incident_id, action) has been consumed."""
        if not isinstance(incident_id, str) or not incident_id.strip():
            return False
        if not isinstance(proposed_action, ProposedAction):
            return False
        return (incident_id, proposed_action.value) in self._consumed_grant_keys

    def validate(
        self,
        authorization_context: ActionAuthorizationContext,
        approval_record: Optional[ApprovalRecord],
        runtime_guard: Optional[Any] = None,
    ) -> ApprovalValidationCode:
        """Validate whether an approval record satisfies all binding and safety invariants."""
        # 1. RuntimeGuard precedence check
        if runtime_guard is not None:
            if hasattr(runtime_guard, "state") and getattr(runtime_guard.state, "halted", False):
                return ApprovalValidationCode.RUNTIME_HALTED

        # 2. Context verification
        if type(authorization_context) is not ActionAuthorizationContext:
            return ApprovalValidationCode.APPROVAL_MALFORMED

        # 3. Missing approval check
        if approval_record is None:
            return ApprovalValidationCode.APPROVAL_MISSING

        # 4. Malformed approval check
        if type(approval_record) is not ApprovalRecord:
            return ApprovalValidationCode.APPROVAL_MALFORMED

        # 5. Incident binding check
        if approval_record.incident_id != authorization_context.incident_id:
            return ApprovalValidationCode.APPROVAL_INCIDENT_MISMATCH

        # 6. Policy action binding check
        target_action = authorization_context.policy_decision.proposed_action
        if approval_record.proposed_action != target_action:
            return ApprovalValidationCode.APPROVAL_ACTION_MISMATCH

        # 7. Policy requirement check
        if not authorization_context.policy_decision.requires_human_approval:
            return ApprovalValidationCode.APPROVAL_POLICY_MISMATCH

        # 8. Denial check
        if approval_record.decision is ApprovalDecision.DENIED:
            return ApprovalValidationCode.APPROVAL_DENIED
        if approval_record.decision is not ApprovalDecision.APPROVED:
            return ApprovalValidationCode.APPROVAL_MALFORMED

        # 9. Replay resistance check: both by approval_id AND by semantic grant (incident_id, action)
        if self.is_consumed(approval_record.approval_id) or self.is_grant_consumed(
            approval_record.incident_id, approval_record.proposed_action
        ):
            return ApprovalValidationCode.APPROVAL_ALREADY_CONSUMED

        return ApprovalValidationCode.APPROVAL_VALID

    def validate_and_consume(
        self,
        authorization_context: ActionAuthorizationContext,
        approval_record: Optional[ApprovalRecord],
        runtime_guard: Optional[Any] = None,
        audit_log: Optional[AuditLog] = None,
    ) -> ApprovalValidationCode:
        """Validate and mark an approval authorization consumed before execution.

        Enforces consume-before-execute one-time semantics within the single-process model.

        Authority Sequence:
          1. RuntimeGuard check
          2. Approval binding validation
          3. One-time approval consumption (marked consumed immediately)
          4. Emits APPROVAL_CONSUMED (or APPROVAL_REPLAY_REJECTED / APPROVAL_VALIDATION_FAILED)
        """
        code = self.validate(authorization_context, approval_record, runtime_guard=runtime_guard)

        incident_id = (
            authorization_context.incident_id
            if isinstance(authorization_context, ActionAuthorizationContext)
            else "SYSTEM"
        )

        if code is ApprovalValidationCode.APPROVAL_ALREADY_CONSUMED:
            _append_audit_event(
                audit_log,
                AuditEventType.APPROVAL_REPLAY_REJECTED,
                incident_id,
                "approval_already_consumed",
            )
            return code

        if code is not ApprovalValidationCode.APPROVAL_VALID:
            _append_audit_event(
                audit_log,
                AuditEventType.APPROVAL_VALIDATION_FAILED,
                incident_id,
                code.value,
            )
            return code

        assert approval_record is not None
        # Atomic registration of consumed tokens
        self._consumed_approval_ids.add(approval_record.approval_id)
        self._consumed_grant_keys.add((approval_record.incident_id, approval_record.proposed_action.value))

        _append_audit_event(
            audit_log,
            AuditEventType.APPROVAL_CONSUMED,
            incident_id,
            "approval_consumed",
        )
        return ApprovalValidationCode.APPROVAL_VALID

    def consume(
        self,
        authorization_context: ActionAuthorizationContext,
        approval_record: Optional[ApprovalRecord],
        runtime_guard: Optional[Any] = None,
        audit_log: Optional[AuditLog] = None,
    ) -> ApprovalValidationCode:
        """Compatibility alias for validate_and_consume."""
        return self.validate_and_consume(
            authorization_context,
            approval_record,
            runtime_guard=runtime_guard,
            audit_log=audit_log,
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
