"""Persistent JSONL audit logging for the AI-Native SOC investigator.

Architecture Principle:
    AI proposes -> deterministic orchestration/tool controls ->
    audit events generated -> sanitized structured events persisted.

Security Guarantees:
    1. Consumes strictly validated AuditEvent instances (exact-type check:
       `type(event) is AuditEvent`). Arbitrary subclasses, dicts, strings,
       or raw telemetry are rejected (fail closed).
    2. Explicit allowlisted serialization: only sequence, event_type,
       incident_id, and detail_code are persisted.
    3. No raw model text, tool arguments, telemetry, decoded commands,
       or secrets may ever enter the persistent audit stream.
    4. Deterministic JSON formatting: UTF-8, compact separators, sorted keys.
    5. Append-only semantics: existing records are never truncated or overwritten.
    6. Sanitized exception messages: no system paths or raw OS error text exposed.
    7. Durability: V1 closes the file after each append operation, providing
       simple local durability appropriate for this lab. Crash-proof journaling
       is not claimed.
"""

import json
from pathlib import Path
from typing import Any, Iterable, List, Union

from investigator.audit import AuditEvent


DEFAULT_AUDIT_LOG_PATH = Path("artifacts/audit/agent_audit.jsonl")

# Explicit field allowlist for persistent serialization
_ALLOWLISTED_FIELDS = ("detail_code", "event_type", "incident_id", "sequence")


class AuditWriterError(Exception):
    """Base exception for audit writer failures."""
    pass


class AuditPathError(AuditWriterError):
    """Raised when the audit log destination path is invalid."""
    pass


class AuditWriteError(AuditWriterError):
    """Raised when persisting audit events to storage fails."""
    pass


def _serialize_audit_event(event: AuditEvent) -> str:
    """Serialize an AuditEvent using an explicit field allowlist.

    Uses exact-type validation. Produces deterministic, compact, one-line JSON.
    """
    if type(event) is not AuditEvent:
        raise AuditWriterError("audit_invalid_event")

    record = {
        "sequence": event.sequence,
        "event_type": event.event_type.value,
        "incident_id": event.incident_id,
        "detail_code": event.detail_code,
    }
    return json.dumps(record, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


class JsonlAuditWriter:
    """Persistent, append-only JSONL audit event sink.

    Accepts only validated AuditEvent instances and writes them to a local
    JSONL file using deterministic formatting.
    """

    def __init__(self, path: Union[Path, str] = DEFAULT_AUDIT_LOG_PATH) -> None:
        """Initialize the writer with a destination file path.

        Args:
            path: Destination file path (Path or non-empty string).

        Raises:
            AuditPathError: If path is empty, invalid type, points to a directory,
                            or has an empty filename.
        """
        if isinstance(path, Path):
            target = path
        elif isinstance(path, str):
            if not path.strip():
                raise AuditPathError("audit_invalid_path")
            if path.endswith(("/", "\\")):
                raise AuditPathError("audit_invalid_path")
            target = Path(path)
        else:
            raise AuditPathError("audit_invalid_path")

        # Reject if target path points to an existing directory
        if target.is_dir():
            raise AuditPathError("audit_invalid_path")

        # Reject empty or relative-directory filename
        if not target.name or target.name in (".", ".."):
            raise AuditPathError("audit_invalid_path")

        self._path: Path = target

    @property
    def path(self) -> Path:
        """Return the destination Path."""
        return self._path

    def _ensure_parent_dir(self) -> None:
        """Ensure the parent directory of the target path exists."""
        try:
            if self._path.is_dir():
                raise AuditPathError("audit_invalid_path")
            parent = self._path.parent
            if parent and not parent.exists():
                parent.mkdir(parents=True, exist_ok=True)
        except AuditPathError:
            raise
        except OSError:
            raise AuditPathError("audit_invalid_path")

    def write_event(self, event: AuditEvent) -> None:
        """Persist a single AuditEvent to the append-only JSONL file.

        Args:
            event: Validated AuditEvent instance.

        Raises:
            AuditWriterError: If event is not an AuditEvent instance.
            AuditPathError: If destination directory cannot be created.
            AuditWriteError: If file write/append fails.
        """
        if type(event) is not AuditEvent:
            raise AuditWriterError("audit_invalid_event")

        line = _serialize_audit_event(event)
        self._ensure_parent_dir()

        try:
            with self._path.open("a", encoding="utf-8", newline="\n") as f:
                f.write(line + "\n")
        except OSError:
            raise AuditWriteError("audit_write_failed")

    def write_events(self, events: Iterable[AuditEvent]) -> None:
        """Persist multiple AuditEvents to the append-only JSONL file.

        All items in `events` are validated and serialized before opening the file
        to prevent partial writes if an invalid item is encountered.

        Args:
            events: Iterable of validated AuditEvent instances.

        Raises:
            AuditWriterError: If any item is not an AuditEvent instance.
            AuditPathError: If destination directory cannot be created.
            AuditWriteError: If file write/append fails.
        """
        if not hasattr(events, "__iter__") or isinstance(events, (str, bytes, dict)):
            raise AuditWriterError("audit_invalid_event")

        # Materialize and validate all items before opening the file
        try:
            event_list = list(events)
        except Exception:
            raise AuditWriterError("audit_invalid_event")

        lines: List[str] = []
        for item in event_list:
            if type(item) is not AuditEvent:
                raise AuditWriterError("audit_invalid_event")
            lines.append(_serialize_audit_event(item))

        if not lines:
            return

        self._ensure_parent_dir()

        try:
            with self._path.open("a", encoding="utf-8", newline="\n") as f:
                for line in lines:
                    f.write(line + "\n")
        except OSError:
            raise AuditWriteError("audit_write_failed")
