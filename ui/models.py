"""Read-only view models for the SOC Analyst UI presentation layer.

Architecture Principle:
    The UI presentation layer consumes dedicated read-only summary view models.
    Raw internal models, provider credentials, and raw telemetry are never exposed.
"""

from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional, Set


ALLOWLISTED_SUMMARY_FIELDS: Set[str] = frozenset({
    "incident_id",
    "detection_id",
    "detection_name",
    "target_host",
    "source_ip",
    "risk_level",
    "risk_score",
    "mitre_technique_id",
    "confidence_level",
    "proposed_action",
    "requires_human_approval",
    "approval_status",
    "simulation_status",
    "threat_intel_status",
    "jira_ticket_key",
    "created_at_utc",
})


@dataclass(frozen=True)
class IncidentSummaryView:
    """Allowlisted, frozen summary view model for incident list presentation.

    Contains exclusively presentation-safe fields. Holds zero action authority.
    Does NOT contain `_raw` telemetry, API keys, credentials, or provider configuration.
    """
    incident_id: str
    detection_id: str
    detection_name: str
    target_host: str
    source_ip: Optional[str]
    risk_level: str
    risk_score: int
    mitre_technique_id: Optional[str]
    confidence_level: str
    proposed_action: str
    requires_human_approval: bool
    approval_status: str
    simulation_status: str
    threat_intel_status: Optional[str]
    jira_ticket_key: Optional[str]
    created_at_utc: str

    def to_dict(self) -> Dict[str, Any]:
        """Return a dictionary strictly bounded to allowlisted presentation fields."""
        data = asdict(self)
        # Ensure only allowlisted fields are returned
        return {k: v for k, v in data.items() if k in ALLOWLISTED_SUMMARY_FIELDS}
