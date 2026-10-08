"""Deterministic, read-only audit log reader for investigation timelines.

Architecture Principle:
    Reads persisted JSONL audit event logs and produces allowlisted AuditEventView models.
    Holds zero action authority: cannot mutate logs, invoke tools, or call external services.
    Enforces strict incident isolation, fail-safe parsing, bounded event counts,
    and deterministic ordering.
"""

import json
import logging
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Union

from ui.models import AuditEventView

logger = logging.getLogger(__name__)

DEFAULT_AUDIT_LOG_PATH = Path("artifacts/audit/agent_audit.jsonl")
MIN_AUDIT_LIMIT = 1
MAX_AUDIT_LIMIT = 200
DEFAULT_AUDIT_LIMIT = 100

SAFE_INCIDENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

_EVENT_CATEGORY_MAP: Dict[str, str] = {
    "MODEL_REQUESTED": "INVESTIGATION",
    "INVESTIGATION_FAILED": "INVESTIGATION",
    "TOOL_REQUESTED": "TOOL REQUEST",
    "TOOL_ALLOWED": "TOOL ALLOWED",
    "TOOL_REJECTED": "TOOL DENIED",
    "TOOL_COMPLETED": "TOOL COMPLETED",
    "POLICY_EVALUATED": "POLICY",
    "APPROVAL_REQUIRED": "APPROVAL",
    "APPROVAL_REQUESTED": "APPROVAL",
    "APPROVAL_GRANTED": "APPROVAL",
    "APPROVAL_DENIED": "APPROVAL",
    "SIMULATION_COMPLETED": "SIMULATION",
    "SIMULATION_NOT_EXECUTED": "SIMULATION",
    "TICKET_REQUESTED": "TICKETING",
    "TICKET_CREATED": "TICKETING",
    "TICKET_FAILED": "TICKETING",
    "THREAT_INTEL_REQUESTED": "THREAT INTEL",
    "THREAT_INTEL_COMPLETED": "THREAT INTEL",
    "RUNTIME_HALTED": "RUNTIME HALT",
    "FINAL_RESULT_ACCEPTED": "FINAL RESULT",
}


def _resolve_audit_category(event_type: str) -> str:
    """Map raw event type to high-level visual category; unknown types map to UNKNOWN / OTHER."""
    return _EVENT_CATEGORY_MAP.get(event_type.strip().upper(), "UNKNOWN / OTHER")


def _resolve_audit_outcome(event_type: str, detail_code: str) -> str:
    """Map event type and detail code to concise outcome badge label."""
    et = event_type.strip().upper()
    dt = detail_code.strip().lower()

    if "DENIED" in et or "REJECT" in et:
        return "DENIED"
    if "FAILED" in et or "HALT" in et:
        return "FAILED"
    if "ALLOWED" in et or "GRANTED" in et or "COMPLETED" in et or "ACCEPTED" in et or "CREATED" in et or "EVALUATED" in et:
        return "SUCCESS"
    if "REQUEST" in et:
        return "REQUESTED"
    if dt in ("ok", "success", "granted", "allowed"):
        return "SUCCESS"
    if dt in ("denied", "rejected", "failed"):
        return "FAILED"
    return "INFO"


class AuditReader:
    """Read-only parser and filter for persisted JSONL audit event logs."""

    def __init__(self, audit_path: Union[Path, str] = DEFAULT_AUDIT_LOG_PATH) -> None:
        """Initialize with target audit log path."""
        if isinstance(audit_path, str):
            if not audit_path.strip():
                raise ValueError("audit_path cannot be empty")
            self._path = Path(audit_path)
        elif isinstance(audit_path, Path):
            self._path = audit_path
        else:
            raise TypeError(f"audit_path must be Path or str, got {type(audit_path).__name__}")

    @property
    def path(self) -> Path:
        """Return configured audit log path."""
        return self._path

    def get_incident_events(self, incident_id: str, limit: int = DEFAULT_AUDIT_LIMIT) -> List[AuditEventView]:
        """Read, correlate, and return deterministically ordered audit events for an incident.

        Security Boundaries:
            - Validates incident_id against strict alphanumeric regex.
            - Restricts results to records where record['incident_id'] == incident_id exactly.
            - Excludes raw model prompts, tool arguments, credentials, and telemetry.
            - Bounded count (1..200).
            - Tolerates malformed lines safely without raising exceptions or leaking paths.
        """
        if not isinstance(incident_id, str) or not SAFE_INCIDENT_ID_PATTERN.match(incident_id.strip()):
            logger.warning("Rejected invalid or traversal incident_id for audit lookup: %r", incident_id)
            return []

        clean_id = incident_id.strip()

        # Enforce bounds on limit
        try:
            clamped_limit = max(MIN_AUDIT_LIMIT, min(MAX_AUDIT_LIMIT, int(limit)))
        except (ValueError, TypeError):
            clamped_limit = DEFAULT_AUDIT_LIMIT

        if not self._path.exists() or not self._path.is_file():
            return []

        matched_events: List[AuditEventView] = []

        try:
            with open(self._path, "r", encoding="utf-8") as f:
                for line in f:
                    line_str = line.strip()
                    if not line_str:
                        continue
                    try:
                        record = json.loads(line_str)
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        continue

                    if not isinstance(record, dict):
                        continue

                    # Exact correlation check
                    rec_inc_id = record.get("incident_id")
                    if not isinstance(rec_inc_id, str) or rec_inc_id.strip() != clean_id:
                        continue

                    event_view = self._parse_event_record(record, clean_id)
                    if event_view is not None:
                        matched_events.append(event_view)

        except OSError as exc:
            logger.warning("Failed to read audit log from %s: %s", self._path.name, exc)
            return []

        # Deterministic ordering: sequence number ascending, timestamp ascending, detail_code tie-breaker
        matched_events.sort(key=lambda ev: (ev.sequence, ev.timestamp or "", ev.detail_code))

        return matched_events[:clamped_limit]

    def _parse_event_record(self, record: Dict[str, Any], expected_id: str) -> Optional[AuditEventView]:
        """Safely extract allowlisted fields into an immutable AuditEventView."""
        raw_event_type = record.get("event_type")
        if not isinstance(raw_event_type, str) or not raw_event_type.strip():
            return None

        event_type = raw_event_type.strip()[:64]

        # Extract sequence
        raw_seq = record.get("sequence")
        if isinstance(raw_seq, bool) or not isinstance(raw_seq, (int, float)):
            sequence = 0
        else:
            sequence = int(raw_seq)

        # Extract detail_code (bounded to 64 chars)
        raw_detail = record.get("detail_code")
        if isinstance(raw_detail, str) and raw_detail.strip():
            detail_code = raw_detail.strip()[:64]
        else:
            detail_code = "ok"

        # Optional timestamp
        raw_ts = record.get("timestamp") or record.get("created_at_utc")
        timestamp = raw_ts.strip()[:35] if isinstance(raw_ts, str) and raw_ts.strip() else None

        category = _resolve_audit_category(event_type)
        outcome = _resolve_audit_outcome(event_type, detail_code)

        return AuditEventView(
            sequence=sequence,
            event_type=event_type,
            incident_id=expected_id,
            detail_code=detail_code,
            category=category,
            outcome=outcome,
            timestamp=timestamp,
        )
