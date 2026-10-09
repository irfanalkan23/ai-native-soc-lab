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
import json
import os
from pathlib import Path
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Optional, TextIO, Union

from investigator.audit import AuditEvent, AuditEventType, AuditLog
from investigator.policy import ActionDisposition, PolicyDecision, ProposedAction


class ApprovalGateError(ValueError):
    """Raised when the approval gate is misused, preconditions fail, or audit recording fails."""
    pass


class ApprovalLedgerError(Exception):
    """Raised when persistent approval ledger operations fail or ledger is corrupt."""
    pass


DEFAULT_APPROVER = "human_operator"
MAX_APPROVER_LENGTH = 64
MAX_INCIDENT_ID_LENGTH = 64
MAX_TIMESTAMP_LENGTH = 35
MAX_CLI_RETRIES = 2  # Total attempts: 3

DEFAULT_APPROVAL_TTL_SECONDS: int = 600  # 10 minutes lab-appropriate default TTL
DEFAULT_CLOCK_SKEW_SECONDS: int = 30     # 30 seconds future-skew tolerance
DEFAULT_APPROVAL_LEDGER_PATH = Path("artifacts/approvals/approval_consumption.jsonl")


def _now_utc_iso() -> str:
    """Return the current time formatted as an ISO 8601 UTC string."""
    return datetime.now(timezone.utc).isoformat()


def _parse_utc_iso(ts_str: str) -> datetime:
    """Parse an ISO 8601 UTC timestamp strictly, requiring timezone offset of zero."""
    if type(ts_str) is not str or not ts_str.strip():
        raise ValueError("Timestamp must be a non-empty string")
    if len(ts_str) > MAX_TIMESTAMP_LENGTH:
        raise ValueError(f"Timestamp exceeds max length {MAX_TIMESTAMP_LENGTH}")
    cleaned = ts_str.replace("Z", "+00:00")
    dt = datetime.fromisoformat(cleaned)
    if dt.tzinfo is None:
        raise ValueError("Timestamp must be timezone-aware")
    if dt.utcoffset() != timezone.utc.utcoffset(dt):
        raise ValueError("Timestamp must have a UTC offset of zero")
    return dt


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
    """Deterministic validation codes for approval binding, freshness, and consumption."""
    APPROVAL_VALID = "approval_valid"
    APPROVAL_MISSING = "approval_missing"
    APPROVAL_INCIDENT_MISMATCH = "approval_incident_mismatch"
    APPROVAL_ACTION_MISMATCH = "approval_action_mismatch"
    APPROVAL_POLICY_MISMATCH = "approval_policy_mismatch"
    APPROVAL_DENIED = "approval_denied"
    APPROVAL_ALREADY_CONSUMED = "approval_already_consumed"
    APPROVAL_MALFORMED = "approval_malformed"
    APPROVAL_EXPIRED = "approval_expired"
    APPROVAL_TIMESTAMP_INVALID = "approval_timestamp_invalid"
    APPROVAL_TIMESTAMP_FUTURE = "approval_timestamp_future"
    APPROVAL_LEDGER_UNAVAILABLE = "approval_ledger_unavailable"
    APPROVAL_LEDGER_CORRUPT = "approval_ledger_corrupt"
    APPROVAL_PERSISTENCE_FAILED = "approval_persistence_failed"
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
    ApprovalValidationCode.APPROVAL_EXPIRED.value,
    ApprovalValidationCode.APPROVAL_TIMESTAMP_INVALID.value,
    ApprovalValidationCode.APPROVAL_TIMESTAMP_FUTURE.value,
    ApprovalValidationCode.APPROVAL_LEDGER_UNAVAILABLE.value,
    ApprovalValidationCode.APPROVAL_LEDGER_CORRUPT.value,
    ApprovalValidationCode.APPROVAL_PERSISTENCE_FAILED.value,
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
    created_at_utc: str = field(init=False, default="")

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

        # 6. created_at_utc: strictly generated by trusted runtime boundary; caller-cannot-pass
        object.__setattr__(self, "created_at_utc", _now_utc_iso())

    @classmethod
    def _issue_for_testing(
        cls,
        incident_id: str,
        proposed_action: ProposedAction,
        decision: ApprovalDecision,
        approver: str = DEFAULT_APPROVER,
        reason_code: str = ApprovalReasonCode.APPROVAL_GRANTED.value,
        approval_id: str = "",
        created_at_utc: Optional[str] = None,
    ) -> "ApprovalRecord":
        """Trusted internal test/bootstrap issuance boundary for deterministic tests.

        Production callers cannot pass created_at_utc to ApprovalRecord.__init__.
        """
        record = cls(
            incident_id=incident_id,
            proposed_action=proposed_action,
            decision=decision,
            approver=approver,
            reason_code=reason_code,
            approval_id=approval_id,
        )
        if created_at_utc is not None:
            if type(created_at_utc) is not str or not created_at_utc.strip():
                raise ValueError("created_at_utc must be a non-empty str")
            _parse_utc_iso(created_at_utc)
            object.__setattr__(record, "created_at_utc", created_at_utc)
        return record

    @classmethod
    def _issue_malformed_timestamp_for_testing(
        cls,
        incident_id: str,
        proposed_action: ProposedAction,
        decision: ApprovalDecision,
        approver: str = DEFAULT_APPROVER,
        reason_code: str = ApprovalReasonCode.APPROVAL_GRANTED.value,
        approval_id: str = "",
        malformed_timestamp: str = "",
    ) -> "ApprovalRecord":
        """Dedicated test helper for testing registry handling of malformed timestamp records."""
        record = cls(
            incident_id=incident_id,
            proposed_action=proposed_action,
            decision=decision,
            approver=approver,
            reason_code=reason_code,
            approval_id=approval_id,
        )
        object.__setattr__(record, "created_at_utc", malformed_timestamp)
        return record


class ApprovalLedger:
    """Persistent, append-only JSONL storage for consumed approval authorizations.

    Security & Boundary Guarantees:
      - Fixed default destination under artifacts/approvals/approval_consumption.jsonl.
      - Never accepts browser or model-controlled paths.
      - Optional dependency-injected path accepted only for trusted test isolation.
      - Persists only bounded metadata: approval_id, incident_id, proposed_action, consumed_at_utc.
      - Zero raw model text, prompts, tool outputs, secrets, or arbitrary text persisted.
      - Fail-closed on file corruption: if any JSON line is corrupt, loading fails closed
        to prevent replaying previously consumed records.
      - Uses flush and os.fsync to improve local durability; does not claim crash-proof
        or filesystem-independent durability.
    """

    def __init__(self, path: Union[Path, str] = DEFAULT_APPROVAL_LEDGER_PATH) -> None:
        if isinstance(path, Path):
            target = path
        elif isinstance(path, str):
            if not path.strip() or path.endswith(("/", "\\")):
                raise ApprovalLedgerError("Invalid approval ledger path")
            target = Path(path)
        else:
            raise ApprovalLedgerError("Invalid approval ledger path type")

        if target.is_dir():
            raise ApprovalLedgerError("Approval ledger path cannot be a directory")
        if not target.name or target.name in (".", ".."):
            raise ApprovalLedgerError("Invalid approval ledger filename")

        self._path: Path = target

    @property
    def path(self) -> Path:
        return self._path

    def _ensure_parent_dir(self) -> None:
        try:
            parent = self._path.parent
            if parent and not parent.exists():
                parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise ApprovalLedgerError("approval_ledger_unavailable") from exc

    def load_consumed(self) -> tuple[set[str], set[tuple[str, str]]]:
        """Load previously consumed approval IDs and grant keys from the ledger.

        Fails closed with ApprovalLedgerError if any row is corrupt or malformed.
        """
        if not self._path.exists():
            return set(), set()

        consumed_ids: set[str] = set()
        consumed_grants: set[tuple[str, str]] = set()

        try:
            with self._path.open("r", encoding="utf-8") as f:
                for line_num, line in enumerate(f, start=1):
                    raw = line.strip()
                    if not raw:
                        continue
                    try:
                        record = json.loads(raw)
                    except Exception as exc:
                        raise ApprovalLedgerError(f"approval_ledger_corrupt: line {line_num}") from exc

                    if not isinstance(record, dict):
                        raise ApprovalLedgerError(f"approval_ledger_corrupt: line {line_num} not dict")

                    app_id = record.get("approval_id")
                    inc_id = record.get("incident_id")
                    action = record.get("proposed_action")

                    if not (isinstance(app_id, str) and app_id.strip()):
                        raise ApprovalLedgerError(f"approval_ledger_corrupt: missing approval_id line {line_num}")
                    if not (isinstance(inc_id, str) and inc_id.strip()):
                        raise ApprovalLedgerError(f"approval_ledger_corrupt: missing incident_id line {line_num}")
                    if not (isinstance(action, str) and action.strip()):
                        raise ApprovalLedgerError(f"approval_ledger_corrupt: missing proposed_action line {line_num}")

                    consumed_ids.add(app_id)
                    consumed_grants.add((inc_id, action))
        except ApprovalLedgerError:
            raise
        except OSError as exc:
            raise ApprovalLedgerError("approval_ledger_unavailable") from exc

        return consumed_ids, consumed_grants

    def append_consumption(
        self,
        approval_record: ApprovalRecord,
        consumed_at_utc: Optional[str] = None,
    ) -> None:
        """Atomically append a consumed approval entry with flush and fsync."""
        if type(approval_record) is not ApprovalRecord:
            raise ApprovalLedgerError("Invalid approval_record type")

        self._ensure_parent_dir()
        timestamp = consumed_at_utc or _now_utc_iso()

        payload = {
            "schema_version": "1.0.0",
            "approval_id": approval_record.approval_id,
            "incident_id": approval_record.incident_id,
            "proposed_action": approval_record.proposed_action.value,
            "consumed_at_utc": timestamp,
        }
        line = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)

        try:
            with self._path.open("a", encoding="utf-8", newline="\n") as f:
                f.write(line + "\n")
                f.flush()
                try:
                    os.fsync(f.fileno())
                except (OSError, AttributeError):
                    pass
        except OSError as exc:
            raise ApprovalLedgerError("approval_persistence_failed") from exc


class ApprovalRegistry:
    """Stateful replay-resistance registry for one-time approval consumption.

    Guarantees:
      - Validates approval binding (incident, proposed action, policy match, non-denial).
      - Enforces bounded freshness (rejection if expired or skewed into the future).
      - Tracks consumed authorizations by explicit approval_id AND by the exact
        authorization grant identity: (incident_id, proposed_action).
      - Survives process restarts when backed by ApprovalLedger (loads historical grants at startup).
      - Enforces consume-before-execute one-time semantics within the trusted execution model.
      - Checks RuntimeGuard precedence: if RuntimeGuard is provided and halted, validation fails closed.
      - Audits consumption, replay, and expiry attempts deterministically.

    Lifetime Scope & Concurrency:
      - When backed by ApprovalLedger, replay protection survives process restart.
      - Concurrent multi-threaded consumption is not claimed.
    """

    def __init__(
        self,
        ledger: Optional[ApprovalLedger] = None,
        clock: Optional[Callable[[], datetime]] = None,
        ttl_seconds: int = DEFAULT_APPROVAL_TTL_SECONDS,
        skew_tolerance_seconds: int = DEFAULT_CLOCK_SKEW_SECONDS,
    ) -> None:
        self._ledger = ledger
        self._clock = clock
        self._ttl_seconds = ttl_seconds
        self._skew_tolerance_seconds = skew_tolerance_seconds

        self._consumed_approval_ids: set[str] = set()
        self._consumed_grant_keys: set[tuple[str, str]] = set()

        if self._ledger is not None:
            loaded_ids, loaded_grants = self._ledger.load_consumed()
            self._consumed_approval_ids.update(loaded_ids)
            self._consumed_grant_keys.update(loaded_grants)

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

    def validate_freshness(self, approval_record: ApprovalRecord) -> ApprovalValidationCode:
        """Validate whether an approval record was created within the permitted TTL window."""
        if type(approval_record) is not ApprovalRecord:
            return ApprovalValidationCode.APPROVAL_MALFORMED

        if not approval_record.created_at_utc:
            return ApprovalValidationCode.APPROVAL_TIMESTAMP_INVALID

        try:
            created_dt = _parse_utc_iso(approval_record.created_at_utc)
        except Exception:
            return ApprovalValidationCode.APPROVAL_TIMESTAMP_INVALID

        now_dt = self._clock() if self._clock is not None else datetime.now(timezone.utc)
        if now_dt.tzinfo is None:
            now_dt = now_dt.replace(tzinfo=timezone.utc)

        age_seconds = (now_dt - created_dt).total_seconds()

        # Check future timestamp beyond allowed skew tolerance
        if age_seconds < -self._skew_tolerance_seconds:
            return ApprovalValidationCode.APPROVAL_TIMESTAMP_FUTURE

        # Check expired beyond TTL
        if age_seconds > self._ttl_seconds:
            return ApprovalValidationCode.APPROVAL_EXPIRED

        return ApprovalValidationCode.APPROVAL_VALID

    def validate(
        self,
        authorization_context: ActionAuthorizationContext,
        approval_record: Optional[ApprovalRecord],
        runtime_guard: Optional[Any] = None,
    ) -> ApprovalValidationCode:
        """Validate whether an approval record satisfies all binding, freshness, and replay invariants."""
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

        # 9. Freshness check (TTL & Clock Skew)
        freshness_code = self.validate_freshness(approval_record)
        if freshness_code is not ApprovalValidationCode.APPROVAL_VALID:
            return freshness_code

        # 10. Replay resistance check: both by approval_id AND by semantic grant (incident_id, action)
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

        Authority Sequence:
          1. RuntimeGuard check
          2. Approval binding validation
          3. Freshness validation
          4. Replay check (in-memory and persistent)
          5. Persistent ledger append (fail-closed if append fails)
          6. In-memory registration
          7. Emits APPROVAL_CONSUMED (or APPROVAL_EXPIRED / APPROVAL_REPLAY_REJECTED / APPROVAL_VALIDATION_FAILED)
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

        if code is ApprovalValidationCode.APPROVAL_EXPIRED:
            _append_audit_event(
                audit_log,
                AuditEventType.APPROVAL_EXPIRED,
                incident_id,
                "approval_expired",
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

        # Fail-closed persistent write before in-memory consumption and before simulation execution
        if self._ledger is not None:
            try:
                self._ledger.append_consumption(approval_record)
            except Exception:
                _append_audit_event(
                    audit_log,
                    AuditEventType.APPROVAL_VALIDATION_FAILED,
                    incident_id,
                    "approval_persistence_failed",
                )
                raise ApprovalLedgerError("approval_persistence_failed")

        # In-memory registration of consumed tokens
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
