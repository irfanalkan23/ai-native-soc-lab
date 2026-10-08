"""Read-only view models for the SOC Analyst UI presentation layer.

Architecture Principle:
    The UI presentation layer consumes dedicated read-only summary and detail view models.
    Raw internal models, provider credentials, and raw telemetry are never exposed.
"""

from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Set


ALLOWLISTED_AUDIT_FIELDS: Set[str] = frozenset({
    "sequence",
    "event_type",
    "incident_id",
    "detail_code",
    "timestamp",
    "category",
    "outcome",
})


@dataclass(frozen=True)
class AuditEventView:
    """Allowlisted, frozen presentation view model for an audit timeline event.

    Holds zero execution authority. Strictly excludes raw prompts, tool arguments,
    untrusted payloads, provider credentials, and raw telemetry.
    """
    sequence: int
    event_type: str
    incident_id: str
    detail_code: str
    category: str = "OTHER"
    outcome: str = "INFO"
    timestamp: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Return a structured dictionary with allowlisted audit fields only."""
        data = asdict(self)
        return {k: v for k, v in data.items() if k in ALLOWLISTED_AUDIT_FIELDS}


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
        return {k: v for k, v in data.items() if k in ALLOWLISTED_SUMMARY_FIELDS}


@dataclass(frozen=True)
class ModSecurityEvidenceView:
    """Strict 7-field normalized ModSecurity evidence presentation view."""
    host: str
    src_ip: str
    rule_id: int
    rule_msg: str
    severity: str
    anomaly_score: int
    unique_id: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SysmonEvidenceView:
    """Bounded presentation view for endpoint Sysmon evidence."""
    target_host: str
    target_user: str
    evidence_source: str
    decoded_command: Optional[str]
    image: Optional[str] = None
    command_line: Optional[str] = None
    parent_image: Optional[str] = None
    parent_command_line: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ThreatIntelDetailView:
    """Normalized advisory threat intelligence presentation view."""
    status: Optional[str]
    skip_reason: Optional[str]
    indicator: Optional[str]
    indicator_type: Optional[str]
    provider: Optional[str]
    verdict: Optional[str]
    malicious_count: Optional[int]
    suspicious_count: Optional[int]
    harmless_count: Optional[int]
    undetected_count: Optional[int]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class IncidentDetailView:
    """Allowlisted, frozen view model for deep incident inspection.

    Separates authoritative deterministic policy state from advisory AI assessment.
    Contains strictly allowlisted evidence. Excludes `_raw`, tokens, and internal secrets.
    """
    # Overview
    incident_id: str
    created_at_utc: str
    detection_id: str
    detection_name: str
    target_host: str
    source_ip: Optional[str]

    # Deterministic Policy (Authoritative)
    risk_score: int
    risk_level: str
    disposition: str
    proposed_action: str
    requires_human_approval: bool
    policy_reason_codes: List[str]
    approval_status: str
    approval_reason_code: Optional[str]
    simulation_status: str
    simulation_detail_code: str
    real_containment_status: str  # Always "NOT_IMPLEMENTED"

    # AI Advisory Assessment (Zero Authority)
    investigation_summary: str
    confidence_level: str
    suspicious_indicator_count: int
    recommended_next_step: str

    # MITRE ATT&CK
    mitre_technique_id: Optional[str]

    # Threat Intelligence
    threat_intel: ThreatIntelDetailView

    # Ticketing / Jira
    jira_ticket_key: Optional[str]

    # Evidence (Bounded)
    evidence_type: str  # "web01_modsecurity" | "dc01_sysmon" | "generic"
    modsecurity_evidence: Optional[ModSecurityEvidenceView]
    sysmon_evidence: Optional[SysmonEvidenceView]

    def to_dict(self) -> Dict[str, Any]:
        """Return a structured dictionary with allowlisted detail fields only."""
        res: Dict[str, Any] = {
            "incident_id": self.incident_id,
            "created_at_utc": self.created_at_utc,
            "detection_id": self.detection_id,
            "detection_name": self.detection_name,
            "target_host": self.target_host,
            "source_ip": self.source_ip,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "disposition": self.disposition,
            "proposed_action": self.proposed_action,
            "requires_human_approval": self.requires_human_approval,
            "policy_reason_codes": list(self.policy_reason_codes),
            "approval_status": self.approval_status,
            "approval_reason_code": self.approval_reason_code,
            "simulation_status": self.simulation_status,
            "simulation_detail_code": self.simulation_detail_code,
            "real_containment_status": self.real_containment_status,
            "investigation_summary": self.investigation_summary,
            "confidence_level": self.confidence_level,
            "suspicious_indicator_count": self.suspicious_indicator_count,
            "recommended_next_step": self.recommended_next_step,
            "mitre_technique_id": self.mitre_technique_id,
            "threat_intel": self.threat_intel.to_dict(),
            "jira_ticket_key": self.jira_ticket_key,
            "evidence_type": self.evidence_type,
            "modsecurity_evidence": (
                self.modsecurity_evidence.to_dict() if self.modsecurity_evidence else None
            ),
            "sysmon_evidence": (
                self.sysmon_evidence.to_dict() if self.sysmon_evidence else None
            ),
        }
        return res
