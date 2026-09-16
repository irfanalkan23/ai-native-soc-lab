"""In-memory structured audit event scaffolding for the AI investigator.

Security Notes:
  - Audit events must NOT contain raw telemetry, decoded scripts, or secrets.
  - detail_code is a short machine-readable code only (no free-form text).
  - Persistent JSONL logging is deferred to a future milestone.
"""

from dataclasses import dataclass
from enum import Enum
from typing import List, Tuple


class AuditEventType(str, Enum):
    """Discriminated audit event types for investigation lifecycle tracking."""
    MODEL_REQUESTED = "MODEL_REQUESTED"
    TOOL_REQUESTED = "TOOL_REQUESTED"
    TOOL_ALLOWED = "TOOL_ALLOWED"
    TOOL_REJECTED = "TOOL_REJECTED"
    TOOL_COMPLETED = "TOOL_COMPLETED"
    FINAL_RESULT_ACCEPTED = "FINAL_RESULT_ACCEPTED"
    INVESTIGATION_FAILED = "INVESTIGATION_FAILED"


# Maximum length of a detail_code value.
# detail_code is a short machine-readable code, not a telemetry carrier or
# exception message. Anything longer indicates misuse.
MAX_DETAIL_CODE_LENGTH = 64


@dataclass(frozen=True)
class AuditEvent:
    """Immutable structured audit record for a single investigation lifecycle event.

    Fields:
        event_type:  Lifecycle stage identifier.
        incident_id: Incident identifier (not raw telemetry).
        sequence:    Monotonically increasing position within one investigation.
        detail_code: Short machine-readable code describing the event.
                     Must not contain raw exception text, secrets, telemetry,
                     control characters, or newlines.
    """
    event_type: AuditEventType
    incident_id: str
    sequence: int
    detail_code: str

    def __post_init__(self) -> None:
        # event_type must be a proper AuditEventType member
        if not isinstance(self.event_type, AuditEventType):
            raise ValueError(
                f"event_type must be AuditEventType, got {type(self.event_type).__name__}"
            )
        # incident_id must be a non-empty str
        if type(self.incident_id) is not str or not self.incident_id.strip():
            raise ValueError("incident_id must be a non-empty str")
        # sequence must be a plain int >= 0; bool is explicitly excluded
        if type(self.sequence) is bool or type(self.sequence) is not int:
            raise ValueError(
                f"sequence must be int, got {type(self.sequence).__name__}"
            )
        if self.sequence < 0:
            raise ValueError(
                f"sequence must be >= 0, got {self.sequence}"
            )
        # detail_code must be a non-empty str within bounds and without control chars
        if type(self.detail_code) is not str or not self.detail_code.strip():
            raise ValueError("detail_code must be a non-empty str")
        if len(self.detail_code) > MAX_DETAIL_CODE_LENGTH:
            raise ValueError(
                f"detail_code length {len(self.detail_code)} exceeds maximum {MAX_DETAIL_CODE_LENGTH}"
            )
        if any(ord(c) < 32 for c in self.detail_code):
            raise ValueError(
                "detail_code must not contain control characters or newlines"
            )


class AuditLog:
    """In-memory append-only audit log for one investigation session.

    Thread safety: not required for the current single-threaded V1 orchestrator.
    Persistent storage is deferred to a future milestone.
    """

    def __init__(self) -> None:
        self._events: List[AuditEvent] = []

    def append(self, event: AuditEvent) -> None:
        """Append an AuditEvent to the in-memory log."""
        if not isinstance(event, AuditEvent):
            raise TypeError(
                f"Expected AuditEvent, got {type(event).__name__}"
            )
        self._events.append(event)

    def events(self) -> Tuple[AuditEvent, ...]:
        """Return an immutable snapshot of all recorded events in order."""
        return tuple(self._events)
