"""Deterministic, bounded, local structured incident-record reporting artifact.

Architecture Principle:
    AI proposes -> deterministic policy evaluates ->
    human approves consequential actions -> system executes only simulated behavior ->
    incident record generated as a REPORTING ARTIFACT ONLY.

Security & Trust Model:
    1. Reporting Artifact Only: The incident record has ZERO action authority.
       It is an output/reporting record and is never evaluated by executor or policy
       as a source of action authority.
    2. No Secrets / Bounded Telemetry Evidence: Never contains API keys, environment variables,
       raw model responses, prompts, system instructions, raw Splunk JSON, raw Sysmon XML,
       or full telemetry dumps. No separate arbitrary URL field is accepted; decoded_command
       persists bounded untrusted evidence which may contain URL text (e.g. download cradles),
       where any URL text is strictly inert data with zero execution authority.
    3. Strict Consistency & Fail-Closed: Input objects (InvestigationInput,
       InvestigationResult, PolicyDecision, SimulationResult, ApprovalRecord)
       must mutually agree on incident_id, proposed_action, approval_status,
       and simulation_status. Any inconsistency raises IncidentConsistencyError.
    4. Bounded Data: All fields have strict length and count limits.
       Policy reason codes are allowlisted. Collections are deeply immutable tuples.
    5. Local JSON Persistence: Deterministic serialization, atomic write with
       tempfile, flushing and fsync before commit to improve local durability
       (no crash-proof, filesystem-independent, forensic-grade, or cryptographic
       durability guarantee claimed), path traversal protection, sanitized exceptions.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any, Dict, List, Optional, Tuple, Union

from investigator.approval import (
    ApprovalDecision,
    ApprovalReasonCode,
    ApprovalRecord,
)
from investigator.policy import (
    MAX_POLICY_REASONS,
    POLICY_REASON_CODES,
    ActionDisposition,
    PolicyDecision,
    ProposedAction,
    RiskLevel,
)
from investigator.schemas import (
    ALLOWED_CONFIDENCE_LEVELS,
    MAX_RECOMMENDED_STEP_LENGTH,
    MAX_SUMMARY_LENGTH,
    InvestigationInput,
    InvestigationResult,
)
from investigator.simulator import (
    SIMULATION_DETAIL_CODES,
    SimulationResult,
    SimulationStatus,
)


SCHEMA_VERSION = "1.0.0"
DEFAULT_INCIDENTS_DIR = Path("artifacts/incidents")

# Maximum string lengths for incident record fields
MAX_INCIDENT_ID_LENGTH = 64
MAX_DETECTION_ID_LENGTH = 64
MAX_DETECTION_NAME_LENGTH = 128
MAX_TARGET_HOST_LENGTH = 64
MAX_TARGET_USER_LENGTH = 64
MAX_EVIDENCE_SOURCE_LENGTH = 128
MAX_DECODED_COMMAND_LENGTH = 4096
MAX_MITRE_TECHNIQUE_LENGTH = 32
MAX_TIMESTAMP_LENGTH = 35

SAFE_INCIDENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


class IncidentRecordError(ValueError):
    """Base exception for incident record schema or invariant violations."""
    pass


class IncidentConsistencyError(IncidentRecordError):
    """Raised when pipeline output objects contain contradictory or inconsistent facts."""
    pass


class IncidentWriterError(Exception):
    """Base exception for incident record persistence failures."""
    pass


class IncidentFileExistsError(IncidentWriterError):
    """Raised when the incident file already exists and overwrite is False."""
    pass


class IncidentPathError(IncidentWriterError):
    """Raised when destination directory or incident filename is invalid."""
    pass


class IncidentWriteError(IncidentWriterError):
    """Raised when writing the incident file fails."""
    pass


class IncidentApprovalStatus(str, Enum):
    """Deterministic human approval status for reporting."""
    NOT_REQUIRED = "NOT_REQUIRED"
    APPROVED = "APPROVED"
    DENIED = "DENIED"


ALLOWED_APPROVAL_STATUSES = frozenset({
    IncidentApprovalStatus.NOT_REQUIRED.value,
    IncidentApprovalStatus.APPROVED.value,
    IncidentApprovalStatus.DENIED.value,
})

ALLOWED_APPROVAL_REASON_CODES = frozenset({
    ApprovalReasonCode.APPROVAL_GRANTED.value,
    ApprovalReasonCode.APPROVAL_DENIED.value,
    ApprovalReasonCode.APPROVAL_INVALID_INPUT.value,
})

ALLOWED_RISK_LEVELS = frozenset({
    RiskLevel.LOW.value,
    RiskLevel.MEDIUM.value,
    RiskLevel.HIGH.value,
    RiskLevel.CRITICAL.value,
})

ALLOWED_DISPOSITIONS = frozenset({
    ActionDisposition.NO_ACTION.value,
    ActionDisposition.MONITOR.value,
    ActionDisposition.HUMAN_REVIEW.value,
    ActionDisposition.APPROVAL_REQUIRED.value,
    ActionDisposition.BLOCKED.value,
})

ALLOWED_PROPOSED_ACTIONS = frozenset({
    ProposedAction.NO_ACTION.value,
    ProposedAction.MONITOR.value,
    ProposedAction.CREATE_INCIDENT_RECORD.value,
    ProposedAction.REQUEST_HUMAN_REVIEW.value,
    ProposedAction.SIMULATE_ENDPOINT_ISOLATION.value,
})

ALLOWED_SIMULATION_STATUSES = frozenset({
    SimulationStatus.SIMULATED.value,
    SimulationStatus.NOT_EXECUTED.value,
})


@dataclass(frozen=True)
class IncidentRecord:
    """Immutable, bounded structured reporting artifact representing an investigated incident.

    This record contains allowlisted summary metadata only. It holds zero action authority.
    """
    schema_version: str
    incident_id: str
    created_at_utc: str
    detection_id: str
    detection_name: str
    target_host: str
    target_user: str
    evidence_source: str
    decoded_command: Optional[str]
    mitre_technique_id: Optional[str]
    investigation_summary: str
    confidence_level: str
    suspicious_indicator_count: int
    recommended_next_step: str
    risk_score: int
    risk_level: str
    disposition: str
    proposed_action: str
    requires_human_approval: bool
    policy_reason_codes: Tuple[str, ...]
    approval_status: str
    approval_reason_code: Optional[str]
    simulation_status: str
    simulation_detail_code: str

    def __post_init__(self) -> None:
        """Validate all field types, bounds, and allowlisted enums."""
        # 1. schema_version
        if type(self.schema_version) is not str or self.schema_version != SCHEMA_VERSION:
            raise IncidentRecordError(f"schema_version must be '{SCHEMA_VERSION}', got {self.schema_version!r}")

        # 2. incident_id
        if type(self.incident_id) is not str or not self.incident_id.strip():
            raise IncidentRecordError("incident_id must be a non-empty str")
        if len(self.incident_id) > MAX_INCIDENT_ID_LENGTH:
            raise IncidentRecordError(f"incident_id exceeds max length {MAX_INCIDENT_ID_LENGTH}")
        if not SAFE_INCIDENT_ID_PATTERN.match(self.incident_id):
            raise IncidentRecordError(
                "incident_id must be alphanumeric with underscores or dashes, no path traversal or spaces"
            )

        # 3. created_at_utc
        if type(self.created_at_utc) is not str or not self.created_at_utc.strip():
            raise IncidentRecordError("created_at_utc must be a non-empty str")
        if len(self.created_at_utc) > MAX_TIMESTAMP_LENGTH:
            raise IncidentRecordError(f"created_at_utc exceeds max length {MAX_TIMESTAMP_LENGTH}")
        try:
            # Validate ISO timestamp parseability and exact UTC zero offset
            cleaned_ts = self.created_at_utc.replace("Z", "+00:00")
            dt = datetime.fromisoformat(cleaned_ts)
            if dt.tzinfo is None:
                raise IncidentRecordError("created_at_utc must be a timezone-aware ISO timestamp")
            if dt.utcoffset() != timezone.utc.utcoffset(dt):
                raise IncidentRecordError("created_at_utc must have a UTC offset of exactly zero (+00:00 or Z)")
        except (ValueError, TypeError) as exc:
            raise IncidentRecordError(f"created_at_utc must be a valid ISO 8601 UTC timestamp: {exc}") from exc

        # 4. detection_id & detection_name
        if type(self.detection_id) is not str or not self.detection_id.strip():
            raise IncidentRecordError("detection_id must be a non-empty str")
        if len(self.detection_id) > MAX_DETECTION_ID_LENGTH:
            raise IncidentRecordError(f"detection_id exceeds max length {MAX_DETECTION_ID_LENGTH}")

        if type(self.detection_name) is not str or not self.detection_name.strip():
            raise IncidentRecordError("detection_name must be a non-empty str")
        if len(self.detection_name) > MAX_DETECTION_NAME_LENGTH:
            raise IncidentRecordError(f"detection_name exceeds max length {MAX_DETECTION_NAME_LENGTH}")

        # 5. target_host & target_user
        if type(self.target_host) is not str or not self.target_host.strip():
            raise IncidentRecordError("target_host must be a non-empty str")
        if len(self.target_host) > MAX_TARGET_HOST_LENGTH:
            raise IncidentRecordError(f"target_host exceeds max length {MAX_TARGET_HOST_LENGTH}")

        if type(self.target_user) is not str or not self.target_user.strip():
            raise IncidentRecordError("target_user must be a non-empty str")
        if len(self.target_user) > MAX_TARGET_USER_LENGTH:
            raise IncidentRecordError(f"target_user exceeds max length {MAX_TARGET_USER_LENGTH}")

        # 6. evidence_source
        if type(self.evidence_source) is not str or not self.evidence_source.strip():
            raise IncidentRecordError("evidence_source must be a non-empty str")
        if len(self.evidence_source) > MAX_EVIDENCE_SOURCE_LENGTH:
            raise IncidentRecordError(f"evidence_source exceeds max length {MAX_EVIDENCE_SOURCE_LENGTH}")

        # 7. decoded_command & mitre_technique_id (Optional)
        if self.decoded_command is not None:
            if type(self.decoded_command) is not str:
                raise IncidentRecordError("decoded_command must be a str or None")
            if len(self.decoded_command) > MAX_DECODED_COMMAND_LENGTH:
                raise IncidentRecordError(f"decoded_command exceeds max length {MAX_DECODED_COMMAND_LENGTH}")

        if self.mitre_technique_id is not None:
            if type(self.mitre_technique_id) is not str or not self.mitre_technique_id.strip():
                raise IncidentRecordError("mitre_technique_id must be a non-empty str or None")
            if len(self.mitre_technique_id) > MAX_MITRE_TECHNIQUE_LENGTH:
                raise IncidentRecordError(f"mitre_technique_id exceeds max length {MAX_MITRE_TECHNIQUE_LENGTH}")

        # 8. investigation_summary & recommended_next_step
        if type(self.investigation_summary) is not str or not self.investigation_summary.strip():
            raise IncidentRecordError("investigation_summary must be a non-empty str")
        if len(self.investigation_summary) > MAX_SUMMARY_LENGTH:
            raise IncidentRecordError(f"investigation_summary exceeds max length {MAX_SUMMARY_LENGTH}")

        if type(self.recommended_next_step) is not str or not self.recommended_next_step.strip():
            raise IncidentRecordError("recommended_next_step must be a non-empty str")
        if len(self.recommended_next_step) > MAX_RECOMMENDED_STEP_LENGTH:
            raise IncidentRecordError(f"recommended_next_step exceeds max length {MAX_RECOMMENDED_STEP_LENGTH}")

        # 9. confidence_level
        if type(self.confidence_level) is not str or self.confidence_level not in ALLOWED_CONFIDENCE_LEVELS:
            raise IncidentRecordError(
                f"confidence_level must be one of {sorted(ALLOWED_CONFIDENCE_LEVELS)}, got {self.confidence_level!r}"
            )

        # 10. suspicious_indicator_count
        if type(self.suspicious_indicator_count) is not int or type(self.suspicious_indicator_count) is bool:
            raise IncidentRecordError("suspicious_indicator_count must be an int")
        if self.suspicious_indicator_count < 0:
            raise IncidentRecordError("suspicious_indicator_count must be non-negative")

        # 11. risk_score & risk_level
        if type(self.risk_score) is not int or type(self.risk_score) is bool:
            raise IncidentRecordError("risk_score must be an int")
        if not (0 <= self.risk_score <= 100):
            raise IncidentRecordError(f"risk_score must be between 0 and 100, got {self.risk_score}")

        if type(self.risk_level) is not str or self.risk_level not in ALLOWED_RISK_LEVELS:
            raise IncidentRecordError(f"risk_level must be one of {sorted(ALLOWED_RISK_LEVELS)}, got {self.risk_level!r}")

        # 12. disposition & proposed_action
        if type(self.disposition) is not str or self.disposition not in ALLOWED_DISPOSITIONS:
            raise IncidentRecordError(f"disposition must be one of {sorted(ALLOWED_DISPOSITIONS)}, got {self.disposition!r}")

        if type(self.proposed_action) is not str or self.proposed_action not in ALLOWED_PROPOSED_ACTIONS:
            raise IncidentRecordError(f"proposed_action must be one of {sorted(ALLOWED_PROPOSED_ACTIONS)}, got {self.proposed_action!r}")

        # 13. requires_human_approval
        if type(self.requires_human_approval) is not bool:
            raise IncidentRecordError("requires_human_approval must be a bool")

        # 14. policy_reason_codes
        if not isinstance(self.policy_reason_codes, (tuple, list)):
            raise IncidentRecordError("policy_reason_codes must be a tuple or list of strings")
        if len(self.policy_reason_codes) > MAX_POLICY_REASONS:
            raise IncidentRecordError(f"policy_reason_codes exceeds max count {MAX_POLICY_REASONS}")

        normalized_reasons = []
        for r in self.policy_reason_codes:
            if type(r) is not str:
                raise IncidentRecordError("Each policy reason code must be str")
            if r not in POLICY_REASON_CODES:
                raise IncidentRecordError(f"Unknown policy reason code: {r!r}")
            normalized_reasons.append(r)
        object.__setattr__(self, "policy_reason_codes", tuple(normalized_reasons))

        # 15. approval_status & approval_reason_code
        if type(self.approval_status) is not str or self.approval_status not in ALLOWED_APPROVAL_STATUSES:
            raise IncidentRecordError(f"approval_status must be one of {sorted(ALLOWED_APPROVAL_STATUSES)}, got {self.approval_status!r}")

        if self.approval_reason_code is not None:
            if type(self.approval_reason_code) is not str or self.approval_reason_code not in ALLOWED_APPROVAL_REASON_CODES:
                raise IncidentRecordError(
                    f"approval_reason_code must be None or one of {sorted(ALLOWED_APPROVAL_REASON_CODES)}, got {self.approval_reason_code!r}"
                )

        # 16. simulation_status & simulation_detail_code
        if type(self.simulation_status) is not str or self.simulation_status not in ALLOWED_SIMULATION_STATUSES:
            raise IncidentRecordError(f"simulation_status must be one of {sorted(ALLOWED_SIMULATION_STATUSES)}, got {self.simulation_status!r}")

        if type(self.simulation_detail_code) is not str or self.simulation_detail_code not in SIMULATION_DETAIL_CODES:
            raise IncidentRecordError(
                f"simulation_detail_code must be one of {sorted(SIMULATION_DETAIL_CODES)}, got {self.simulation_detail_code!r}"
            )

    def to_dict(self) -> Dict[str, Any]:
        """Return a structured dictionary representation with allowlisted fields only."""
        return {
            "schema_version": self.schema_version,
            "incident_id": self.incident_id,
            "created_at_utc": self.created_at_utc,
            "detection_id": self.detection_id,
            "detection_name": self.detection_name,
            "target_host": self.target_host,
            "target_user": self.target_user,
            "evidence_source": self.evidence_source,
            "decoded_command": self.decoded_command,
            "mitre_technique_id": self.mitre_technique_id,
            "investigation_summary": self.investigation_summary,
            "confidence_level": self.confidence_level,
            "suspicious_indicator_count": self.suspicious_indicator_count,
            "recommended_next_step": self.recommended_next_step,
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
        }

    def to_json(self, indent: int = 2) -> str:
        """Return deterministic JSON string formatted with sorted keys and indentation."""
        return json.dumps(
            self.to_dict(),
            ensure_ascii=False,
            sort_keys=True,
            indent=indent,
        )


def build_incident_record(
    investigation_input: InvestigationInput,
    investigation_result: InvestigationResult,
    policy_decision: PolicyDecision,
    simulation_result: SimulationResult,
    approval_record: Optional[ApprovalRecord] = None,
    evidence_source: str = "Unknown",
    deterministic_decoded_command: Optional[str] = None,
    mitre_technique_id: Optional[str] = None,
    created_at_utc: Optional[str] = None,
) -> IncidentRecord:
    """Build and validate an immutable IncidentRecord from verified pipeline outputs.

    Enforces strict consistency across all input objects:
    - Fails closed on any identity or proposed action discrepancy.
    - Fails closed if approval requirements and simulation outcomes disagree.
    - Authoritative values are extracted solely from the trusted policy, approval,
      and simulation objects (the AI model has zero authority).

    Raises:
        IncidentConsistencyError: If any cross-object consistency rule is violated.
        IncidentRecordError: If schema validation fails.
    """
    # 1. Exact-type checks on inputs
    if type(investigation_input) is not InvestigationInput:
        raise IncidentConsistencyError(
            f"investigation_input must be InvestigationInput, got {type(investigation_input).__name__}"
        )
    if type(investigation_result) is not InvestigationResult:
        raise IncidentConsistencyError(
            f"investigation_result must be InvestigationResult, got {type(investigation_result).__name__}"
        )
    if type(policy_decision) is not PolicyDecision:
        raise IncidentConsistencyError(
            f"policy_decision must be PolicyDecision, got {type(policy_decision).__name__}"
        )
    if type(simulation_result) is not SimulationResult:
        raise IncidentConsistencyError(
            f"simulation_result must be SimulationResult, got {type(simulation_result).__name__}"
        )
    if approval_record is not None and type(approval_record) is not ApprovalRecord:
        raise IncidentConsistencyError(
            f"approval_record must be ApprovalRecord or None, got {type(approval_record).__name__}"
        )
    if type(evidence_source) is not str:
        raise IncidentConsistencyError(f"evidence_source must be str, got {type(evidence_source).__name__}")
    if deterministic_decoded_command is not None and type(deterministic_decoded_command) is not str:
        raise IncidentConsistencyError("deterministic_decoded_command must be str or None")
    if mitre_technique_id is not None and type(mitre_technique_id) is not str:
        raise IncidentConsistencyError("mitre_technique_id must be str or None")
    if created_at_utc is not None and type(created_at_utc) is not str:
        raise IncidentConsistencyError("created_at_utc must be str or None")

    # 2. Incident ID consistency
    incident_id = investigation_input.incident_id
    if simulation_result.incident_id != incident_id:
        raise IncidentConsistencyError(
            f"Simulation result incident_id ({simulation_result.incident_id!r}) does not match alert incident_id ({incident_id!r})"
        )
    if approval_record is not None and approval_record.incident_id != incident_id:
        raise IncidentConsistencyError(
            f"Approval record incident_id ({approval_record.incident_id!r}) does not match alert incident_id ({incident_id!r})"
        )

    # 3. Action consistency
    if simulation_result.proposed_action != policy_decision.proposed_action:
        raise IncidentConsistencyError(
            f"Simulation result proposed_action ({simulation_result.proposed_action.value!r}) does not match policy decision proposed_action ({policy_decision.proposed_action.value!r})"
        )
    if approval_record is not None and approval_record.proposed_action != policy_decision.proposed_action:
        raise IncidentConsistencyError(
            f"Approval record proposed_action ({approval_record.proposed_action.value!r}) does not match policy decision proposed_action ({policy_decision.proposed_action.value!r})"
        )

    # 4. Human Approval and Simulation Consistency
    if policy_decision.requires_human_approval:
        if approval_record is None:
            raise IncidentConsistencyError("Consequential policy decision mandates approval_record, but None was provided")
        if policy_decision.proposed_action is not ProposedAction.SIMULATE_ENDPOINT_ISOLATION:
            raise IncidentConsistencyError("Consequential approval strictly required only for SIMULATE_ENDPOINT_ISOLATION")

        if approval_record.decision is ApprovalDecision.APPROVED:
            approval_status = IncidentApprovalStatus.APPROVED.value
            approval_reason_code = approval_record.reason_code
            if (
                simulation_result.status is not SimulationStatus.SIMULATED
                or simulation_result.detail_code != "simulated_endpoint_isolation"
            ):
                raise IncidentConsistencyError(
                    "Approved SIMULATE_ENDPOINT_ISOLATION must have status=SIMULATED and detail_code='simulated_endpoint_isolation'"
                )
        elif approval_record.decision is ApprovalDecision.DENIED:
            approval_status = IncidentApprovalStatus.DENIED.value
            approval_reason_code = approval_record.reason_code
            if (
                simulation_result.status is not SimulationStatus.NOT_EXECUTED
                or simulation_result.detail_code != "simulation_blocked_denied"
            ):
                raise IncidentConsistencyError(
                    "Denied SIMULATE_ENDPOINT_ISOLATION must have status=NOT_EXECUTED and detail_code='simulation_blocked_denied'"
                )
        else:
            raise IncidentConsistencyError(f"Unexpected approval decision: {approval_record.decision}")
    else:
        # Non-consequential action: approval was not required
        if approval_record is not None:
            raise IncidentConsistencyError(
                "approval_record cannot be provided for non-consequential actions that do not require human approval"
            )
        approval_status = IncidentApprovalStatus.NOT_REQUIRED.value
        approval_reason_code = None

        if simulation_result.status is not SimulationStatus.NOT_EXECUTED:
            raise IncidentConsistencyError(
                f"Non-consequential action ({policy_decision.proposed_action.value}) cannot produce SimulationStatus.SIMULATED"
            )

        if policy_decision.proposed_action in (ProposedAction.NO_ACTION, ProposedAction.MONITOR):
            if simulation_result.detail_code != "simulation_not_required":
                raise IncidentConsistencyError(
                    f"{policy_decision.proposed_action.value} requires status=NOT_EXECUTED and detail_code='simulation_not_required'"
                )
        elif policy_decision.proposed_action is ProposedAction.REQUEST_HUMAN_REVIEW:
            if simulation_result.detail_code != "human_review_required":
                raise IncidentConsistencyError(
                    "REQUEST_HUMAN_REVIEW requires status=NOT_EXECUTED and detail_code='human_review_required'"
                )
        elif policy_decision.proposed_action is ProposedAction.CREATE_INCIDENT_RECORD:
            if simulation_result.detail_code != "incident_record_deferred":
                raise IncidentConsistencyError(
                    "CREATE_INCIDENT_RECORD requires status=NOT_EXECUTED and detail_code='incident_record_deferred'"
                )
        else:
            raise IncidentConsistencyError(
                f"Unsupported action/status/detail combination: {policy_decision.proposed_action.value}"
            )

    # 5. Timestamp generation
    timestamp = created_at_utc or datetime.now(timezone.utc).isoformat()

    return IncidentRecord(
        schema_version=SCHEMA_VERSION,
        incident_id=incident_id,
        created_at_utc=timestamp,
        detection_id=investigation_input.detection_id,
        detection_name=investigation_input.detection_name,
        target_host=investigation_input.host,
        target_user=investigation_input.user,
        evidence_source=evidence_source,
        decoded_command=deterministic_decoded_command,
        mitre_technique_id=mitre_technique_id,
        investigation_summary=investigation_result.summary,
        confidence_level=investigation_result.confidence_level,
        suspicious_indicator_count=len(investigation_result.suspicious_indicators),
        recommended_next_step=investigation_result.recommended_next_step,
        risk_score=policy_decision.risk_score,
        risk_level=policy_decision.risk_level.value,
        disposition=policy_decision.action_disposition.value,
        proposed_action=policy_decision.proposed_action.value,
        requires_human_approval=policy_decision.requires_human_approval,
        policy_reason_codes=policy_decision.reasons,
        approval_status=approval_status,
        approval_reason_code=approval_reason_code,
        simulation_status=simulation_result.status.value,
        simulation_detail_code=simulation_result.detail_code,
    )


class IncidentJsonWriter:
    """Local, atomic JSON persistence writer for validated IncidentRecord artifacts.

    Trust Boundary & Path Safety:
    - Fixed Default: The normal runtime destination directory is fixed to DEFAULT_INCIDENTS_DIR ('artifacts/incidents/').
    - Caller / Model Isolation: Neither the AI model nor incident contents can choose or override output paths.
    - Dependency Injection: The incidents_dir parameter exists solely for trusted application bootstrap and test isolation. Untrusted or model-controlled values must never be passed into it.
    - Path Validation: Target filename is strictly bound to <incident_id>.json and verified against path traversal attempts.
    """

    def __init__(self, incidents_dir: Union[Path, str] = DEFAULT_INCIDENTS_DIR) -> None:
        """Initialize the writer with an immutable target directory."""
        if isinstance(incidents_dir, Path):
            target = incidents_dir
        elif isinstance(incidents_dir, str):
            if not incidents_dir.strip():
                raise IncidentPathError("incidents_dir cannot be empty")
            target = Path(incidents_dir)
        else:
            raise IncidentPathError(f"incidents_dir must be Path or str, got {type(incidents_dir).__name__}")

        if target.is_file():
            raise IncidentPathError(f"incidents_dir cannot be an existing file: {target}")

        self._directory = target

    @property
    def directory(self) -> Path:
        """Return the destination directory path."""
        return self._directory

    def write_record(self, record: IncidentRecord, overwrite: bool = False) -> Path:
        """Write an IncidentRecord to disk as a JSON artifact atomically.

        Writes to a temporary file in the destination directory, flushes and calls
        os.fsync before commit to improve local durability. When overwrite is False
        (default), relies on standard-library hard-link creation (os.link) where supported
        to enforce atomic create-if-absent semantics without check-then-replace (TOCTOU)
        races. If atomic linking is unavailable or unsupported, incident persistence fails
        closed rather than weakening no-overwrite semantics. When overwrite is True,
        explicit atomic replacement via os.replace is permitted.

        Note: Improves local durability; no crash-proof, filesystem-independent,
        forensic-grade, or cryptographic durability guarantee is claimed.

        Args:
            record: Validated IncidentRecord instance.
            overwrite: If False (default), fails closed if the file already exists.

        Returns:
            Resolved Path to the written incident JSON file.

        Raises:
            IncidentPathError: If incident_id is unsafe or attempts path traversal.
            IncidentFileExistsError: If target file exists and overwrite is False.
            IncidentWriteError: If file writing or atomic replacement fails.
        """
        if type(record) is not IncidentRecord:
            raise IncidentWriterError(f"record must be IncidentRecord, got {type(record).__name__}")

        # Path safety check
        if not SAFE_INCIDENT_ID_PATTERN.match(record.incident_id):
            raise IncidentPathError("incident_id contains illegal filename characters or traversal elements")

        filename = f"{record.incident_id}.json"

        try:
            self._directory.mkdir(parents=True, exist_ok=True)
            resolved_dir = self._directory.resolve()
            target_path = (self._directory / filename).resolve()
        except OSError as exc:
            raise IncidentPathError("failed_to_resolve_incident_directory") from exc

        # Ensure no traversal escaped directory
        if target_path.parent != resolved_dir:
            raise IncidentPathError("Path traversal detected in incident artifact target")

        # Fast-path existence check before serialization
        if target_path.exists() and not overwrite:
            raise IncidentFileExistsError(f"Incident file already exists: {target_path.name}")

        json_text = record.to_json(indent=2)

        # Atomic-style write: write to tempfile in the same directory, flush and fsync, then commit
        temp_file = None
        try:
            temp_file = tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=self._directory,
                delete=False,
                suffix=".tmp",
            )
            temp_file.write(json_text + "\n")
            temp_file.flush()
            # Flush and fsync improve local durability before commit; no forensic or crash-proof guarantee claimed
            os.fsync(temp_file.fileno())
            temp_file.close()

            if overwrite:
                os.replace(temp_file.name, str(target_path))
            else:
                # Kernel-level atomic link enforces create-if-absent without TOCTOU race
                try:
                    os.link(temp_file.name, str(target_path))
                    os.unlink(temp_file.name)
                except FileExistsError as exc:
                    raise IncidentFileExistsError(f"Incident file already exists: {target_path.name}") from exc
                except OSError as exc:
                    # Fail closed if atomic linking is unsupported or fails; do not fall back to os.replace
                    raise IncidentWriteError("incident_write_failed_linking_unavailable") from exc

            return target_path
        except (IncidentFileExistsError, IncidentPathError, IncidentWriteError):
            if temp_file is not None and os.path.exists(temp_file.name):
                try:
                    os.remove(temp_file.name)
                except OSError:
                    pass
            raise
        except Exception as exc:
            if temp_file is not None and os.path.exists(temp_file.name):
                try:
                    os.remove(temp_file.name)
                except OSError:
                    pass
            raise IncidentWriteError("incident_write_failed") from exc
