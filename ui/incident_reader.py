"""Deterministic, read-only incident presentation reader.

Architecture Principle:
    Existing persisted incident artifacts are consumed through a read-only UI path
    and mapped to allowlisted IncidentSummaryView models.
    Does NOT invoke ToolRouter, RuntimeGuard, policy engines, or provider clients.
    Fails safely on malformed files without leaking tracebacks.
"""

from datetime import datetime, timezone
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from ui.models import IncidentSummaryView

logger = logging.getLogger(__name__)

DEFAULT_INCIDENTS_DIR = Path("artifacts/incidents")
MIN_LIMIT = 1
MAX_LIMIT = 100
DEFAULT_LIMIT = 50


def _safe_timestamp(ts_str: str) -> float:
    """Parse an ISO 8601 UTC timestamp to float seconds for sorting; fallback to 0.0."""
    try:
        cleaned = ts_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except (ValueError, TypeError, AttributeError):
        return 0.0


class IncidentReader:
    """Read-only presentation reader for persisted incident artifacts."""

    def __init__(self, incidents_dir: Union[Path, str] = DEFAULT_INCIDENTS_DIR) -> None:
        """Initialize the reader with a target directory."""
        if isinstance(incidents_dir, str):
            if not incidents_dir.strip():
                raise ValueError("incidents_dir cannot be empty")
            self._incidents_dir = Path(incidents_dir)
        elif isinstance(incidents_dir, Path):
            self._incidents_dir = incidents_dir
        else:
            raise TypeError(f"incidents_dir must be Path or str, got {type(incidents_dir).__name__}")

    @property
    def incidents_dir(self) -> Path:
        """Return the configured incident artifacts directory."""
        return self._incidents_dir

    def list_incidents(self, limit: int = DEFAULT_LIMIT) -> List[IncidentSummaryView]:
        """Read and return a deterministically sorted list of incident summaries.

        Args:
            limit: Maximum number of incidents to return (bounded to 1..100).

        Returns:
            List of allowlisted IncidentSummaryView records sorted descending by
            created_at_utc, with incident_id as deterministic tie-breaker.

        Raises:
            ValueError: If limit is outside [1, 100].
        """
        if not isinstance(limit, int) or isinstance(limit, bool):
            raise ValueError(f"limit must be an integer, got {type(limit).__name__}")
        if limit < MIN_LIMIT or limit > MAX_LIMIT:
            raise ValueError(f"limit must be between {MIN_LIMIT} and {MAX_LIMIT}, got {limit}")

        if not self._incidents_dir.exists() or not self._incidents_dir.is_dir():
            return []

        results: List[IncidentSummaryView] = []

        try:
            entries = sorted(self._incidents_dir.iterdir(), key=lambda p: p.name)
        except OSError as exc:
            logger.warning("Failed to list incidents directory %s: %s", self._incidents_dir, exc)
            return []

        for entry in entries:
            if not entry.is_file() or not entry.name.endswith(".json") or entry.name.endswith(".tmp"):
                continue

            try:
                summary = self._parse_incident_file(entry)
                if summary is not None:
                    results.append(summary)
            except Exception as exc:
                # Catch-all to guarantee that a corrupt or hostile file never crashes the listing
                logger.warning("Skipping unparseable incident file %s: %s", entry.name, exc)
                continue

        # Deterministic ordering: most recent first, then incident_id ascending
        results.sort(key=lambda item: (-_safe_timestamp(item.created_at_utc), item.incident_id))

        return results[:limit]

    def _parse_incident_file(self, file_path: Path) -> Optional[IncidentSummaryView]:
        """Parse a single JSON artifact into an allowlisted IncidentSummaryView.

        Returns None if file is malformed, missing required fields, or has corrupt types.
        """
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError, UnicodeDecodeError) as exc:
            logger.warning("Failed to decode JSON from %s: %s", file_path.name, exc)
            return None

        if not isinstance(data, dict):
            logger.warning("Incident JSON root in %s is not an object", file_path.name)
            return None

        # Validate required fields
        required_str_fields = [
            "incident_id",
            "detection_id",
            "detection_name",
            "target_host",
            "risk_level",
            "confidence_level",
            "proposed_action",
            "approval_status",
            "simulation_status",
            "created_at_utc",
        ]
        for field in required_str_fields:
            val = data.get(field)
            if not isinstance(val, str) or not val.strip():
                logger.warning("Missing or non-string required field '%s' in %s", field, file_path.name)
                return None

        # Validate risk_score
        risk_score = data.get("risk_score")
        if not isinstance(risk_score, int) or isinstance(risk_score, bool):
            logger.warning("Invalid or missing risk_score in %s", file_path.name)
            return None

        # Validate requires_human_approval
        requires_approval = data.get("requires_human_approval")
        if not isinstance(requires_approval, bool):
            logger.warning("Invalid or missing requires_human_approval in %s", file_path.name)
            return None

        # Extract optional fields
        # 1. source_ip (from modsecurity_evidence or direct source_ip)
        source_ip: Optional[str] = None
        modsec = data.get("modsecurity_evidence")
        if isinstance(modsec, dict) and isinstance(modsec.get("src_ip"), str):
            source_ip = modsec["src_ip"].strip() or None
        elif isinstance(data.get("source_ip"), str):
            source_ip = str(data["source_ip"]).strip() or None

        # 2. mitre_technique_id
        mitre_id = data.get("mitre_technique_id")
        mitre_technique_id = str(mitre_id).strip() if isinstance(mitre_id, str) and mitre_id.strip() else None

        # 3. threat_intel_status
        ti_status = data.get("threat_intel_status")
        threat_intel_status = str(ti_status).strip() if isinstance(ti_status, str) and ti_status.strip() else None

        # 4. jira_ticket_key
        jira_key = data.get("jira_ticket_key") or data.get("ticket_key")
        jira_ticket_key = str(jira_key).strip() if isinstance(jira_key, str) and jira_key.strip() else None

        return IncidentSummaryView(
            incident_id=str(data["incident_id"]).strip(),
            detection_id=str(data["detection_id"]).strip(),
            detection_name=str(data["detection_name"]).strip(),
            target_host=str(data["target_host"]).strip(),
            source_ip=source_ip,
            risk_level=str(data["risk_level"]).strip(),
            risk_score=risk_score,
            mitre_technique_id=mitre_technique_id,
            confidence_level=str(data["confidence_level"]).strip(),
            proposed_action=str(data["proposed_action"]).strip(),
            requires_human_approval=requires_approval,
            approval_status=str(data["approval_status"]).strip(),
            simulation_status=str(data["simulation_status"]).strip(),
            threat_intel_status=threat_intel_status,
            jira_ticket_key=jira_ticket_key,
            created_at_utc=str(data["created_at_utc"]).strip(),
        )
