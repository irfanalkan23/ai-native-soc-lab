"""Deterministic, read-only incident presentation reader.

Architecture Principle:
    Existing persisted incident artifacts are consumed through a read-only UI path
    and mapped to allowlisted IncidentSummaryView and IncidentDetailView models.
    Does NOT invoke ToolRouter, RuntimeGuard, policy engines, or provider clients.
    Fails safely on malformed files without leaking tracebacks.
"""

from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Union

from ui.models import (
    IncidentDetailView,
    IncidentSummaryView,
    ModSecurityEvidenceView,
    SysmonEvidenceView,
    ThreatIntelDetailView,
)

logger = logging.getLogger(__name__)

DEFAULT_INCIDENTS_DIR = Path("artifacts/incidents")
MIN_LIMIT = 1
MAX_LIMIT = 100
DEFAULT_LIMIT = 50

# Strict alphanumeric identifier pattern (prevents path traversal, path separators, traversal dots)
SAFE_INCIDENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


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
                summary = self._parse_incident_summary_file(entry)
                if summary is not None:
                    results.append(summary)
            except Exception as exc:
                # Catch-all to guarantee that a corrupt or hostile file never crashes the listing
                logger.warning("Skipping unparseable incident file %s: %s", entry.name, exc)
                continue

        # Deterministic ordering: most recent first, then incident_id ascending
        results.sort(key=lambda item: (-_safe_timestamp(item.created_at_utc), item.incident_id))

        return results[:limit]

    def get_incident(self, incident_id: str) -> Optional[IncidentDetailView]:
        """Retrieve and parse a single incident artifact by exact identifier.

        Security Boundaries:
            - Validates incident_id against strict alphanumeric pattern.
            - Blocks all directory traversal tokens (../, slashes, backslashes, colons).
            - Enforces parent directory boundary verification on resolved target path.
            - Returns None on missing, invalid, or malformed artifacts without leaking tracebacks.
        """
        if not isinstance(incident_id, str) or not incident_id.strip():
            return None

        # 1. Strict regex validation for identifier format
        if not SAFE_INCIDENT_ID_PATTERN.match(incident_id):
            logger.warning("Rejected unsafe or malformed incident_id identifier: %r", incident_id)
            return None

        if not self._incidents_dir.exists() or not self._incidents_dir.is_dir():
            return None

        # 2. Strict path resolution & traversal guard
        try:
            resolved_dir = self._incidents_dir.resolve()
            target_path = (self._incidents_dir / f"{incident_id}.json").resolve()
        except OSError:
            return None

        if target_path.parent != resolved_dir:
            logger.warning("Path traversal attempt blocked for identifier: %r", incident_id)
            return None

        if not target_path.is_file():
            return None

        # 3. Parse detail view model
        try:
            return self._parse_incident_detail_file(target_path)
        except Exception as exc:
            logger.warning("Failed to parse incident detail from %s: %s", target_path.name, exc)
            return None

    def _parse_incident_summary_file(self, file_path: Path) -> Optional[IncidentSummaryView]:
        """Parse a single JSON artifact into an allowlisted IncidentSummaryView.

        Returns None if file is malformed, missing required fields, or has corrupt types.
        """
        data = self._read_json_file(file_path)
        if data is None:
            return None

        # Validate required fields
        if not self._validate_base_fields(data, file_path.name):
            return None

        # Extract optional summary fields
        source_ip = self._extract_source_ip(data)
        mitre_technique_id = self._extract_optional_str(data.get("mitre_technique_id"))
        threat_intel_status = self._extract_optional_str(data.get("threat_intel_status"))
        jira_ticket_key = self._extract_optional_str(data.get("jira_ticket_key") or data.get("ticket_key"))

        return IncidentSummaryView(
            incident_id=str(data["incident_id"]).strip(),
            detection_id=str(data["detection_id"]).strip(),
            detection_name=str(data["detection_name"]).strip(),
            target_host=str(data["target_host"]).strip(),
            source_ip=source_ip,
            risk_level=str(data["risk_level"]).strip(),
            risk_score=data["risk_score"],
            mitre_technique_id=mitre_technique_id,
            confidence_level=str(data["confidence_level"]).strip(),
            proposed_action=str(data["proposed_action"]).strip(),
            requires_human_approval=data["requires_human_approval"],
            approval_status=str(data["approval_status"]).strip(),
            simulation_status=str(data["simulation_status"]).strip(),
            threat_intel_status=threat_intel_status,
            jira_ticket_key=jira_ticket_key,
            created_at_utc=str(data["created_at_utc"]).strip(),
        )

    def _parse_incident_detail_file(self, file_path: Path) -> Optional[IncidentDetailView]:
        """Parse a single JSON artifact into an allowlisted IncidentDetailView."""
        data = self._read_json_file(file_path)
        if data is None:
            return None

        if not self._validate_base_fields(data, file_path.name):
            return None

        source_ip = self._extract_source_ip(data)
        mitre_technique_id = self._extract_optional_str(data.get("mitre_technique_id"))
        jira_ticket_key = self._extract_optional_str(data.get("jira_ticket_key") or data.get("ticket_key"))

        # Policy reasons
        raw_reasons = data.get("policy_reason_codes", [])
        policy_reason_codes = [str(r).strip() for r in raw_reasons if isinstance(r, str)] if isinstance(raw_reasons, (list, tuple)) else []

        # Parse Threat Intelligence Detail
        threat_intel = self._extract_threat_intel_detail(data)

        # Parse Evidence Models
        modsec_ev = self._extract_modsecurity_evidence(data)
        sysmon_ev = self._extract_sysmon_evidence(data)

        if modsec_ev is not None:
            evidence_type = "web01_modsecurity"
        elif sysmon_ev is not None and (sysmon_ev.decoded_command or "sysmon" in str(sysmon_ev.evidence_source).lower()):
            evidence_type = "dc01_sysmon"
        else:
            evidence_type = "generic"

        return IncidentDetailView(
            incident_id=str(data["incident_id"]).strip(),
            created_at_utc=str(data["created_at_utc"]).strip(),
            detection_id=str(data["detection_id"]).strip(),
            detection_name=str(data["detection_name"]).strip(),
            target_host=str(data["target_host"]).strip(),
            source_ip=source_ip,
            risk_score=data["risk_score"],
            risk_level=str(data["risk_level"]).strip(),
            disposition=str(data.get("disposition", "UNKNOWN")).strip(),
            proposed_action=str(data["proposed_action"]).strip(),
            requires_human_approval=data["requires_human_approval"],
            policy_reason_codes=policy_reason_codes,
            approval_status=str(data["approval_status"]).strip(),
            approval_reason_code=self._extract_optional_str(data.get("approval_reason_code")),
            simulation_status=str(data["simulation_status"]).strip(),
            simulation_detail_code=str(data.get("simulation_detail_code", "simulation_not_required")).strip(),
            real_containment_status="NOT_IMPLEMENTED",
            investigation_summary=str(data.get("investigation_summary", "")).strip(),
            confidence_level=str(data["confidence_level"]).strip(),
            suspicious_indicator_count=int(data.get("suspicious_indicator_count", 0)),
            recommended_next_step=str(data.get("recommended_next_step", "")).strip(),
            mitre_technique_id=mitre_technique_id,
            threat_intel=threat_intel,
            jira_ticket_key=jira_ticket_key,
            evidence_type=evidence_type,
            modsecurity_evidence=modsec_ev,
            sysmon_evidence=sysmon_ev,
        )

    def _read_json_file(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """Read and decode JSON from file safely."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                return data
            logger.warning("Incident JSON root in %s is not an object", file_path.name)
            return None
        except (json.JSONDecodeError, OSError, UnicodeDecodeError) as exc:
            logger.warning("Failed to decode JSON from %s: %s", file_path.name, exc)
            return None

    def _validate_base_fields(self, data: Dict[str, Any], filename: str) -> bool:
        """Validate presence and basic types of common required fields."""
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
                logger.warning("Missing or non-string required field '%s' in %s", field, filename)
                return False

        risk_score = data.get("risk_score")
        if not isinstance(risk_score, int) or isinstance(risk_score, bool):
            logger.warning("Invalid or missing risk_score in %s", filename)
            return False

        requires_approval = data.get("requires_human_approval")
        if not isinstance(requires_approval, bool):
            logger.warning("Invalid or missing requires_human_approval in %s", filename)
            return False

        return True

    def _extract_source_ip(self, data: Dict[str, Any]) -> Optional[str]:
        """Extract source IP from modsecurity evidence or top-level source_ip."""
        modsec = data.get("modsecurity_evidence")
        if isinstance(modsec, dict) and isinstance(modsec.get("src_ip"), str):
            val = modsec["src_ip"].strip()
            if val:
                return val
        if isinstance(data.get("source_ip"), str):
            val = str(data["source_ip"]).strip()
            if val:
                return val
        return None

    def _extract_optional_str(self, val: Any) -> Optional[str]:
        """Return non-empty stripped string or None."""
        if isinstance(val, str) and val.strip():
            return val.strip()
        return None

    def _extract_threat_intel_detail(self, data: Dict[str, Any]) -> ThreatIntelDetailView:
        """Extract and normalize threat intelligence state."""
        status = self._extract_optional_str(data.get("threat_intel_status"))
        skip_reason = self._extract_optional_str(data.get("threat_intel_skip_reason"))

        obs = data.get("threat_intel_observation")
        if isinstance(obs, dict):
            return ThreatIntelDetailView(
                status=status,
                skip_reason=skip_reason,
                indicator=self._extract_optional_str(obs.get("indicator")),
                indicator_type=self._extract_optional_str(obs.get("indicator_type")),
                provider=self._extract_optional_str(obs.get("provider")),
                verdict=self._extract_optional_str(obs.get("verdict")),
                malicious_count=obs.get("malicious_count") if isinstance(obs.get("malicious_count"), int) else None,
                suspicious_count=obs.get("suspicious_count") if isinstance(obs.get("suspicious_count"), int) else None,
                harmless_count=obs.get("harmless_count") if isinstance(obs.get("harmless_count"), int) else None,
                undetected_count=obs.get("undetected_count") if isinstance(obs.get("undetected_count"), int) else None,
            )

        return ThreatIntelDetailView(
            status=status,
            skip_reason=skip_reason,
            indicator=None,
            indicator_type=None,
            provider=None,
            verdict=None,
            malicious_count=None,
            suspicious_count=None,
            harmless_count=None,
            undetected_count=None,
        )

    def _extract_modsecurity_evidence(self, data: Dict[str, Any]) -> Optional[ModSecurityEvidenceView]:
        """Extract strict 7-field ModSecurity evidence if present."""
        modsec = data.get("modsecurity_evidence")
        if not isinstance(modsec, dict):
            return None

        try:
            return ModSecurityEvidenceView(
                host=str(modsec.get("host", "")).strip(),
                src_ip=str(modsec.get("src_ip", "")).strip(),
                rule_id=int(modsec.get("rule_id", 0)),
                rule_msg=str(modsec.get("rule_msg", "")).strip(),
                severity=str(modsec.get("severity", "")).strip(),
                anomaly_score=int(modsec.get("anomaly_score", 0)),
                unique_id=str(modsec.get("unique_id", "")).strip(),
            )
        except (ValueError, TypeError):
            return None

    def _extract_sysmon_evidence(self, data: Dict[str, Any]) -> Optional[SysmonEvidenceView]:
        """Extract bounded Sysmon endpoint evidence if present."""
        def _cap(s: Optional[str], max_len: int = 4096) -> Optional[str]:
            if s and len(s) > max_len:
                return s[:max_len] + "... [truncated]"
            return s

        host = self._extract_optional_str(data.get("target_host") or data.get("host")) or "Unknown"
        user = self._extract_optional_str(data.get("target_user") or data.get("User") or data.get("user")) or "Unknown"
        source = self._extract_optional_str(data.get("evidence_source")) or "Unknown"
        decoded = self._extract_optional_str(data.get("decoded_command"))
        image = self._extract_optional_str(data.get("Image") or data.get("image"))
        cmd = self._extract_optional_str(data.get("CommandLine") or data.get("command_line"))
        parent_img = self._extract_optional_str(data.get("ParentImage") or data.get("parent_image"))
        parent_cmd = self._extract_optional_str(data.get("ParentCommandLine") or data.get("parent_command_line"))

        nested_sysmon = data.get("sysmon_evidence")
        if isinstance(nested_sysmon, dict):
            host = self._extract_optional_str(nested_sysmon.get("target_host") or nested_sysmon.get("host")) or host
            user = self._extract_optional_str(nested_sysmon.get("target_user") or nested_sysmon.get("User") or nested_sysmon.get("user")) or user
            source = self._extract_optional_str(nested_sysmon.get("evidence_source")) or source
            decoded = self._extract_optional_str(nested_sysmon.get("decoded_command")) or decoded
            image = self._extract_optional_str(nested_sysmon.get("Image") or nested_sysmon.get("image")) or image
            cmd = self._extract_optional_str(nested_sysmon.get("CommandLine") or nested_sysmon.get("command_line")) or cmd
            parent_img = self._extract_optional_str(nested_sysmon.get("ParentImage") or nested_sysmon.get("parent_image")) or parent_img
            parent_cmd = self._extract_optional_str(nested_sysmon.get("ParentCommandLine") or nested_sysmon.get("parent_command_line")) or parent_cmd

        return SysmonEvidenceView(
            target_host=_cap(host, 64) or "Unknown",
            target_user=_cap(user, 64) or "Unknown",
            evidence_source=_cap(source, 128) or "Unknown",
            decoded_command=_cap(decoded, 4096),
            image=_cap(image, 256),
            command_line=_cap(cmd, 4096),
            parent_image=_cap(parent_img, 256),
            parent_command_line=_cap(parent_cmd, 4096),
        )
