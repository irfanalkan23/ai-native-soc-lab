"""Deterministic Ticketing Contract and Local Fake Ticket Workflow (Milestone 5B-1).

Architecture Principle:
    AI proposes
    -> deterministic policy evaluates
    -> human approves consequential actions
    -> simulated response executes
    -> IncidentRecord is generated (reporting artifact)
    -> ticketing / reporting occurs downstream

Trust & Scope Boundaries:
    - Downstream Reporting Only: Tickets are strictly downstream reporting artifacts.
      They possess ZERO action, policy, approval, or execution authority.
    - Zero External Network / Zero Credentials: This module makes no network calls,
      connects to no remote APIs, uses no API tokens, and imports no HTTP/socket libraries.
      (Live Jira Cloud integration is deferred to Milestone 5B-2).
    - Inert Evidence Demarcation: Decoded commands or evidence included in tickets are
      labeled with explicit trust boundaries and remain inert text data with zero execution capability.
    - Trusted Configuration: Project keys, issue types, and allowed labels originate
      exclusively from trusted application configuration, never from untrusted alert data or model output.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import re
import threading
from typing import Optional, Protocol, Tuple

from investigator.incident_record import IncidentApprovalStatus, IncidentRecord
from investigator.simulator import SimulationStatus


# ---------------------------------------------------------------------------
# Schema Bounds & Patterns
# ---------------------------------------------------------------------------

MAX_INCIDENT_ID_LENGTH = 64
MAX_PROJECT_KEY_LENGTH = 32
MAX_ISSUE_TYPE_LENGTH = 32
MAX_SUMMARY_LENGTH = 255
MAX_DESCRIPTION_LENGTH = 4096
MAX_LABEL_LENGTH = 64
MAX_LABELS_COUNT = 8
MAX_EXTERNAL_REF_LENGTH = 64
MAX_PROVIDER_LENGTH = 32
MAX_TICKET_KEY_LENGTH = 64
MAX_TIMESTAMP_LENGTH = 35

SAFE_INCIDENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
PROJECT_KEY_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]{1,31}$")
ISSUE_TYPE_PATTERN = re.compile(r"^[A-Za-z0-9 _-]{1,32}$")
SAFE_LABEL_PATTERN = re.compile(r"^[a-z0-9_-]{1,64}$")
SAFE_PROVIDER_PATTERN = re.compile(r"^[a-z0-9_-]{1,32}$")
SAFE_TICKET_KEY_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]{1,31}-[0-9]{1,10}$")

ALLOWED_TICKET_LABELS = frozenset({
    "ai-native-soc",
    "powershell",
    "benign-test",
    "human-approved",
    "human-denied",
    "approval-not-required",
    "simulated-containment",
    "action-not-executed",
})

TICKET_DETAIL_CODES = frozenset({
    "ticket_created_fake",
    "ticket_creation_failed",
    "ticket_payload_invalid",
    "ticket_client_error",
})


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class TicketingError(ValueError):
    """Base exception for all ticketing boundary and schema errors."""
    pass


class TicketSchemaError(TicketingError):
    """Raised when TicketRequest or TicketResult violates schema bounds or invariants."""
    pass


class TicketConfigError(TicketingError):
    """Raised when TicketConfig contains invalid or unallowlisted settings."""
    pass


class TicketClientError(TicketingError):
    """Raised when a ticket client fails or receives an invalid request."""
    pass


# ---------------------------------------------------------------------------
# Priority Enum (Provider-Neutral)
# ---------------------------------------------------------------------------

class TicketPriority(str, Enum):
    """Provider-neutral ticket priority classification."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# ---------------------------------------------------------------------------
# Trusted Application Configuration
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TicketConfig:
    """Trusted static operational configuration for ticket generation.

    Fields:
        project_key: Target project key (e.g. 'SEC'). Must be uppercase alphanumeric.
        issue_type: Target issue type (e.g. 'Incident').
        allowed_labels: Tuple of allowlisted label strings.
        include_decoded_command: Whether to include bounded decoded command evidence.
            Defaults strictly to False for least-privilege evidence exposure.
    """
    project_key: str
    issue_type: str
    allowed_labels: Tuple[str, ...]
    include_decoded_command: bool = False

    def __post_init__(self) -> None:
        if type(self.project_key) is not str or not PROJECT_KEY_PATTERN.match(self.project_key):
            raise TicketConfigError("project_key must be uppercase alphanumeric (e.g. 'SEC')")
        if len(self.project_key) > MAX_PROJECT_KEY_LENGTH:
            raise TicketConfigError(f"project_key exceeds maximum length {MAX_PROJECT_KEY_LENGTH}")

        if type(self.issue_type) is not str or not ISSUE_TYPE_PATTERN.match(self.issue_type):
            raise TicketConfigError("issue_type must be a valid alphanumeric string (e.g. 'Incident')")
        if len(self.issue_type) > MAX_ISSUE_TYPE_LENGTH:
            raise TicketConfigError(f"issue_type exceeds maximum length {MAX_ISSUE_TYPE_LENGTH}")

        if type(self.allowed_labels) is not tuple:
            raise TicketConfigError("allowed_labels must be an exact tuple")
        if len(self.allowed_labels) > MAX_LABELS_COUNT:
            raise TicketConfigError(f"allowed_labels count cannot exceed {MAX_LABELS_COUNT}")
        if len(self.allowed_labels) != len(set(self.allowed_labels)):
            raise TicketConfigError("allowed_labels cannot contain duplicate items")
        for lbl in self.allowed_labels:
            if type(lbl) is not str:
                raise TicketConfigError("allowed_labels elements must be strings")
            if lbl not in ALLOWED_TICKET_LABELS:
                raise TicketConfigError(f"allowed_labels contains unauthorized label: {lbl}")

        if type(self.include_decoded_command) is not bool:
            raise TicketConfigError("include_decoded_command must be a bool")


# ---------------------------------------------------------------------------
# Ticket Request & Result Schemas
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TicketRequest:
    """Immutable, bounded ticket creation payload."""
    incident_id: str
    project_key: str
    issue_type: str
    summary: str
    description: str
    priority: TicketPriority
    labels: Tuple[str, ...]
    external_reference: str

    def __post_init__(self) -> None:
        # 1. incident_id
        if type(self.incident_id) is not str or not SAFE_INCIDENT_ID_PATTERN.match(self.incident_id):
            raise TicketSchemaError("incident_id must be safe alphanumeric with dashes or underscores")
        if len(self.incident_id) > MAX_INCIDENT_ID_LENGTH:
            raise TicketSchemaError(f"incident_id exceeds maximum length {MAX_INCIDENT_ID_LENGTH}")

        # 2. project_key
        if type(self.project_key) is not str or not PROJECT_KEY_PATTERN.match(self.project_key):
            raise TicketSchemaError("project_key must be uppercase alphanumeric")
        if len(self.project_key) > MAX_PROJECT_KEY_LENGTH:
            raise TicketSchemaError(f"project_key exceeds maximum length {MAX_PROJECT_KEY_LENGTH}")

        # 3. issue_type
        if type(self.issue_type) is not str or not ISSUE_TYPE_PATTERN.match(self.issue_type):
            raise TicketSchemaError("issue_type must be a valid alphanumeric string")
        if len(self.issue_type) > MAX_ISSUE_TYPE_LENGTH:
            raise TicketSchemaError(f"issue_type exceeds maximum length {MAX_ISSUE_TYPE_LENGTH}")

        # 4. summary (single-line, non-empty, bounded)
        if type(self.summary) is not str or not self.summary.strip():
            raise TicketSchemaError("summary must be a non-empty string")
        if len(self.summary) > MAX_SUMMARY_LENGTH:
            raise TicketSchemaError(f"summary exceeds maximum length {MAX_SUMMARY_LENGTH}")
        if "\n" in self.summary or "\r" in self.summary:
            raise TicketSchemaError("summary must be a single line without newline characters")

        # 5. description
        if type(self.description) is not str or not self.description.strip():
            raise TicketSchemaError("description must be a non-empty string")
        if len(self.description) > MAX_DESCRIPTION_LENGTH:
            raise TicketSchemaError(f"description exceeds maximum length {MAX_DESCRIPTION_LENGTH}")

        # 6. priority
        if not isinstance(self.priority, TicketPriority):
            raise TicketSchemaError(f"priority must be an instance of TicketPriority, got {type(self.priority).__name__}")

        # 7. labels
        if type(self.labels) is not tuple:
            raise TicketSchemaError("labels must be an exact tuple")
        if len(self.labels) > MAX_LABELS_COUNT:
            raise TicketSchemaError(f"labels count cannot exceed {MAX_LABELS_COUNT}")
        if len(self.labels) != len(set(self.labels)):
            raise TicketSchemaError("labels cannot contain duplicate items")
        for lbl in self.labels:
            if type(lbl) is not str or lbl not in ALLOWED_TICKET_LABELS:
                raise TicketSchemaError(f"labels contains unauthorized label: {lbl}")

        # 8. external_reference
        if type(self.external_reference) is not str or not self.external_reference.strip():
            raise TicketSchemaError("external_reference must be a non-empty string")
        if len(self.external_reference) > MAX_EXTERNAL_REF_LENGTH:
            raise TicketSchemaError(f"external_reference exceeds maximum length {MAX_EXTERNAL_REF_LENGTH}")


@dataclass(frozen=True)
class TicketResult:
    """Immutable outcome of a ticket creation operation.

    Enforces strict consistency:
    - success=True requires a non-empty, valid ticket_key and success detail code.
    - success=False requires ticket_key=None and an allowlisted failure detail code.
    - created_at_utc requires exact UTC zero offset (+00:00 or Z).
    """
    success: bool
    provider: str
    ticket_key: Optional[str]
    detail_code: str
    created_at_utc: str

    def __post_init__(self) -> None:
        if type(self.success) is not bool:
            raise TicketSchemaError("success must be a bool")

        if type(self.provider) is not str or not SAFE_PROVIDER_PATTERN.match(self.provider):
            raise TicketSchemaError("provider must be a safe alphanumeric string")
        if len(self.provider) > MAX_PROVIDER_LENGTH:
            raise TicketSchemaError(f"provider exceeds maximum length {MAX_PROVIDER_LENGTH}")

        if type(self.detail_code) is not str or self.detail_code not in TICKET_DETAIL_CODES:
            raise TicketSchemaError("detail_code must be one of allowlisted codes")

        if type(self.created_at_utc) is not str or not self.created_at_utc.strip():
            raise TicketSchemaError("created_at_utc must be a non-empty string")
        if len(self.created_at_utc) > MAX_TIMESTAMP_LENGTH:
            raise TicketSchemaError(f"created_at_utc exceeds maximum length {MAX_TIMESTAMP_LENGTH}")

        cleaned_ts = self.created_at_utc.replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(cleaned_ts)
        except (ValueError, TypeError):
            raise TicketSchemaError("created_at_utc must be a valid ISO 8601 timestamp")
        if dt.tzinfo is None or dt.utcoffset() != timezone.utc.utcoffset(dt):
            raise TicketSchemaError("created_at_utc must have UTC offset exactly zero (+00:00 or Z)")

        # Consistency coupling between success, ticket_key, and detail_code
        if self.success:
            if type(self.ticket_key) is not str or not SAFE_TICKET_KEY_PATTERN.match(self.ticket_key):
                raise TicketSchemaError("success=True requires a valid ticket_key (e.g. 'SEC-0001')")
            if len(self.ticket_key) > MAX_TICKET_KEY_LENGTH:
                raise TicketSchemaError(f"ticket_key exceeds maximum length {MAX_TICKET_KEY_LENGTH}")
            if self.detail_code != "ticket_created_fake":
                raise TicketSchemaError("success=True requires detail_code 'ticket_created_fake'")
        else:
            if self.ticket_key is not None:
                raise TicketSchemaError("success=False requires ticket_key=None")
            if self.detail_code == "ticket_created_fake":
                raise TicketSchemaError("success=False cannot have success detail_code")


# ---------------------------------------------------------------------------
# Ticket Client Protocol & Local Fake Client
# ---------------------------------------------------------------------------

class TicketClient(Protocol):
    """Clean protocol for ticket provider implementations."""
    def create_ticket(self, request: TicketRequest) -> TicketResult:
        """Create a ticket given a validated TicketRequest."""
        ...


class FakeTicketClient:
    """Deterministic local fake ticket client for testing and offline simulation.

    Generates sequential, predictable ticket keys derived exclusively from
    TicketRequest.project_key (e.g. SEC-0001). Zero network, zero subprocess,
    and zero credentials.
    """
    def __init__(self) -> None:
        self._counter = 0
        self._lock = threading.Lock()

    def create_ticket(self, request: TicketRequest) -> TicketResult:
        if type(request) is not TicketRequest:
            raise TicketClientError("request must be exact TicketRequest")

        with self._lock:
            self._counter += 1
            seq = self._counter

        ticket_key = f"{request.project_key}-{seq:04d}"

        return TicketResult(
            success=True,
            provider="fake_ticket_client",
            ticket_key=ticket_key,
            detail_code="ticket_created_fake",
            created_at_utc=datetime.now(timezone.utc).isoformat(),
        )


# ---------------------------------------------------------------------------
# Trust Boundary Evidence Markers
# ---------------------------------------------------------------------------
UNTRUSTED_EVIDENCE_BEGIN = "--- BEGIN UNTRUSTED EVIDENCE (INERT TEXT ONLY) ---"
UNTRUSTED_EVIDENCE_END = "--- END UNTRUSTED EVIDENCE ---"
EVIDENCE_TRUNCATION_MARKER = "\n[EVIDENCE TRUNCATED]"


def build_ticket_request(
    incident_record: IncidentRecord,
    ticket_config: TicketConfig,
) -> TicketRequest:
    """Build an immutable, bounded TicketRequest from a validated IncidentRecord.

    Enforces deterministic mapping:
    - Risk level maps strictly to TicketPriority (LOW, MEDIUM, HIGH, CRITICAL).
    - Labels are derived from verified attributes and filtered against allowed_labels.
    - Decoded-evidence exact invariants:
      * include_decoded_command=False: no evidence block is included.
      * include_decoded_command=True AND evidence block is included:
        BEGIN marker must be present, END marker must be present, and
        final description <= MAX_DESCRIPTION_LENGTH.
      * If there is insufficient budget even for the structural evidence block:
        omit the evidence block entirely rather than emitting malformed or
        partially bounded evidence.
    """
    if type(incident_record) is not IncidentRecord:
        raise TicketSchemaError("incident_record must be exact IncidentRecord")
    if type(ticket_config) is not TicketConfig:
        raise TicketConfigError("ticket_config must be exact TicketConfig")

    # 1. Deterministic Priority Mapping
    if incident_record.risk_level == "LOW":
        priority = TicketPriority.LOW
    elif incident_record.risk_level == "MEDIUM":
        priority = TicketPriority.MEDIUM
    elif incident_record.risk_level == "HIGH":
        priority = TicketPriority.HIGH
    elif incident_record.risk_level == "CRITICAL":
        priority = TicketPriority.CRITICAL
    else:
        raise TicketSchemaError(f"Unknown incident risk_level: {incident_record.risk_level}")

    # 2. Deterministic Label Derivation
    derived_labels = ["ai-native-soc"]

    # "powershell" label is derived ONLY from validated MITRE technique ID,
    # NOT from untrusted detection_name substring.
    if incident_record.mitre_technique_id == "T1059.001":
        derived_labels.append("powershell")

    # "benign-test" label is derived ONLY from validated policy reason code,
    # NOT solely from risk_score == 0.
    if "benign_lab_fixture_matched" in incident_record.policy_reason_codes:
        derived_labels.append("benign-test")

    # Approval labels
    if incident_record.approval_status == IncidentApprovalStatus.APPROVED.value:
        derived_labels.append("human-approved")
    elif incident_record.approval_status == IncidentApprovalStatus.DENIED.value:
        derived_labels.append("human-denied")
    elif incident_record.approval_status == IncidentApprovalStatus.NOT_REQUIRED.value:
        derived_labels.append("approval-not-required")

    # Simulation labels
    if incident_record.simulation_status == SimulationStatus.SIMULATED.value:
        derived_labels.append("simulated-containment")
    elif incident_record.simulation_status == SimulationStatus.NOT_EXECUTED.value:
        derived_labels.append("action-not-executed")

    # Filter against trusted allowed_labels and sort
    final_labels = tuple(sorted(lbl for lbl in derived_labels if lbl in ticket_config.allowed_labels))

    # 3. Summary Construction (bounded to 255 chars)
    raw_summary = f"[{incident_record.risk_level}] {incident_record.detection_name} on {incident_record.target_host} ({incident_record.incident_id})"
    summary = raw_summary[:MAX_SUMMARY_LENGTH]

    # 4. Description Construction (bounded to 4096 chars)
    desc_lines = [
        f"h2. Incident Overview: {incident_record.incident_id}",
        f"* Detection Name: {incident_record.detection_name}",
        f"* Detection ID: {incident_record.detection_id}",
        f"* Target Host: {incident_record.target_host}",
        f"* Target User: {incident_record.target_user}",
        f"* Evidence Source: {incident_record.evidence_source}",
        f"* MITRE Technique: {incident_record.mitre_technique_id or '<none>'}",
        "",
        "h2. Advisory AI Investigation",
        f"* Summary: {incident_record.investigation_summary}",
        f"* Confidence: {incident_record.confidence_level}",
        f"* Suspicious Indicators: {incident_record.suspicious_indicator_count}",
        f"* Recommended Next Step: {incident_record.recommended_next_step}",
        "",
        "h2. Deterministic Policy Evaluation",
        f"* Risk Score: {incident_record.risk_score} / 100",
        f"* Risk Level: {incident_record.risk_level}",
        f"* Disposition: {incident_record.disposition}",
        f"* Proposed Action: {incident_record.proposed_action}",
        f"* Approval Required: {'Yes' if incident_record.requires_human_approval else 'No'}",
        f"* Policy Reasons: {', '.join(incident_record.policy_reason_codes)}",
        "",
        "h2. Governance & Simulation Outcome",
        f"* Approval Status: {incident_record.approval_status}",
        f"* Approval Reason: {incident_record.approval_reason_code or '<none>'}",
        f"* Simulation Status: {incident_record.simulation_status}",
        f"* Simulation Detail: {incident_record.simulation_detail_code}",
    ]

    base_desc_text = "\n".join(desc_lines)
    if len(base_desc_text) > MAX_DESCRIPTION_LENGTH:
        base_desc_text = base_desc_text[:MAX_DESCRIPTION_LENGTH - 3] + "..."

    # Include decoded command evidence only if explicitly enabled by trusted config
    if ticket_config.include_decoded_command and incident_record.decoded_command:
        evidence_prefix = f"\n\nh2. Decoded Command Evidence\n{UNTRUSTED_EVIDENCE_BEGIN}\n"
        evidence_suffix = f"\n{UNTRUSTED_EVIDENCE_END}"
        overhead = len(evidence_prefix) + len(evidence_suffix)
        available_budget = MAX_DESCRIPTION_LENGTH - len(base_desc_text) - overhead

        if available_budget >= len(incident_record.decoded_command):
            evidence_body = incident_record.decoded_command
            desc_text = f"{base_desc_text}{evidence_prefix}{evidence_body}{evidence_suffix}"
        elif available_budget >= len(EVIDENCE_TRUNCATION_MARKER):
            body_budget = available_budget - len(EVIDENCE_TRUNCATION_MARKER)
            evidence_body = incident_record.decoded_command[:body_budget] + EVIDENCE_TRUNCATION_MARKER
            desc_text = f"{base_desc_text}{evidence_prefix}{evidence_body}{evidence_suffix}"
        else:
            desc_text = base_desc_text
    else:
        desc_text = base_desc_text

    return TicketRequest(
        incident_id=incident_record.incident_id,
        project_key=ticket_config.project_key,
        issue_type=ticket_config.issue_type,
        summary=summary,
        description=desc_text,
        priority=priority,
        labels=final_labels,
        external_reference=incident_record.detection_id,
    )
