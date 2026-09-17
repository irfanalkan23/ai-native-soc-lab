"""Deterministic risk evaluation and action recommendation policy engine.

Architecture Principle:
    AI proposes -> deterministic evidence/risk evaluation ->
    deterministic action policy -> human approval for consequential actions ->
    system executes only allowed/simulated actions -> everything logged.

Trust Model:
    STRUCTURALLY VALIDATED BUT UNTRUSTED:
      - InvestigationInput: telemetry strings, user, host, command line, alert fields.
      - InvestigationResult: model hypotheses, confidence_level, suspicious_indicators,
        decoded_command. Model text can NEVER activate suppression or lower risk.

    TRUSTED DETERMINISTIC POLICY FACTS:
      - verified_detection_id: established by deterministic detector/bootstrap.
      - deterministic_decoded_command: output of deterministic Base64 decoder tool.
      - mitre_technique_id: output of deterministic MITRE mapping rule.
      - tool_failure_or_incomplete_evidence: deterministic tool-success/failure state.
"""

from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Sequence, Tuple, Union

from investigator.audit import AuditEvent, AuditEventType, AuditLog
from investigator.schemas import InvestigationInput, InvestigationResult


# Canonical lab detection ID for controlled encoded-PowerShell testing
BENIGN_LAB_DETECTION_ID = "DET-POWERSHELL-001"
EXACT_BENIGN_COMMAND = "Write-Host 'AI-NativeSOC-LAB-TEST'"


class PolicyEngineError(ValueError):
    """Raised when policy inputs or invariants are malformed (fails closed)."""
    pass


class RiskLevel(str, Enum):
    """Deterministic severity classification based on calculated risk score."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ActionDisposition(str, Enum):
    """Deterministic governance disposition for investigation outcomes."""
    NO_ACTION = "NO_ACTION"
    MONITOR = "MONITOR"
    HUMAN_REVIEW = "HUMAN_REVIEW"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    BLOCKED = "BLOCKED"


class ProposedAction(str, Enum):
    """Allowlisted proposed actions recommended by the policy engine."""
    NO_ACTION = "no_action"
    MONITOR = "monitor"
    CREATE_INCIDENT_RECORD = "create_incident_record"
    REQUEST_HUMAN_REVIEW = "request_human_review"
    SIMULATE_ENDPOINT_ISOLATION = "simulate_endpoint_isolation"


# Actions that represent containment and strictly mandate human approval
CONSEQUENTIAL_ACTIONS = frozenset({
    ProposedAction.SIMULATE_ENDPOINT_ISOLATION,
})

# Allowlisted deterministic machine-readable policy reason codes
POLICY_REASON_CODES = frozenset({
    "benign_lab_fixture_matched",
    "encoded_powershell_detected",
    "decoded_command_present",
    "mitre_t1059_001",
    "incomplete_evidence_uncertainty",
    "suspicious_indicators_present",
    "multiple_suspicious_indicators",
    "model_confidence_high",
    "model_confidence_medium",
    "approval_required_for_consequential_action",
    "fail_closed_incomplete_evidence",
})

MAX_POLICY_REASONS = 16


@dataclass(frozen=True)
class PolicyContext:
    """Policy context separating untrusted alert evidence from trusted deterministic facts.

    Trust Boundary:
        alert: Structurally validated but UNTRUSTED incident evidence.
               Cannot be used to activate suppression or satisfy trusted checks.
        verified_detection_id: TRUSTED detection identity established by
               deterministic detection/bootstrap logic.
        deterministic_decoded_command: TRUSTED output produced directly by
               the deterministic Base64 decoder tool (None if failed/unexecuted).
        mitre_technique_id: TRUSTED technique identifier from deterministic
               rule mapping (None if unmapped).
        tool_failure_or_incomplete_evidence: TRUSTED boolean flag indicating
               whether required tools failed or evidence is incomplete.
    """
    alert: InvestigationInput
    verified_detection_id: str
    deterministic_decoded_command: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    tool_failure_or_incomplete_evidence: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.alert, InvestigationInput):
            raise PolicyEngineError(
                f"alert must be InvestigationInput, got {type(self.alert).__name__}"
            )
        if type(self.verified_detection_id) is not str or not self.verified_detection_id.strip():
            raise PolicyEngineError("verified_detection_id must be a non-empty str")
        if (
            self.deterministic_decoded_command is not None
            and type(self.deterministic_decoded_command) is not str
        ):
            raise PolicyEngineError("deterministic_decoded_command must be str or None")
        if (
            self.mitre_technique_id is not None
            and type(self.mitre_technique_id) is not str
        ):
            raise PolicyEngineError("mitre_technique_id must be str or None")
        if type(self.tool_failure_or_incomplete_evidence) is not bool:
            raise PolicyEngineError(
                f"tool_failure_or_incomplete_evidence must be bool, "
                f"got {type(self.tool_failure_or_incomplete_evidence).__name__}"
            )


@dataclass(frozen=True)
class PolicyDecision:
    """Immutable, validated output of deterministic risk and policy evaluation.

    The LLM has zero authority over this structure. All fields are verified.
    """
    risk_score: int
    risk_level: RiskLevel
    action_disposition: ActionDisposition
    proposed_action: ProposedAction
    reasons: Tuple[str, ...]
    requires_human_approval: bool

    def __post_init__(self) -> None:
        if type(self.risk_score) is bool or type(self.risk_score) is not int:
            raise PolicyEngineError(
                f"risk_score must be int, got {type(self.risk_score).__name__}"
            )
        if not (0 <= self.risk_score <= 100):
            raise PolicyEngineError(
                f"risk_score must be between 0 and 100, got {self.risk_score}"
            )
        if not isinstance(self.risk_level, RiskLevel):
            raise PolicyEngineError(
                f"risk_level must be RiskLevel, got {type(self.risk_level).__name__}"
            )
        if not isinstance(self.action_disposition, ActionDisposition):
            raise PolicyEngineError(
                f"action_disposition must be ActionDisposition, "
                f"got {type(self.action_disposition).__name__}"
            )
        if not isinstance(self.proposed_action, ProposedAction):
            raise PolicyEngineError(
                f"proposed_action must be ProposedAction, "
                f"got {type(self.proposed_action).__name__}"
            )
        if type(self.requires_human_approval) is not bool:
            raise PolicyEngineError(
                f"requires_human_approval must be bool, "
                f"got {type(self.requires_human_approval).__name__}"
            )

        # Normalize and validate reasons
        if not isinstance(self.reasons, (tuple, list)):
            raise PolicyEngineError("reasons must be a sequence of strings")
        if len(self.reasons) > MAX_POLICY_REASONS:
            raise PolicyEngineError(
                f"reasons count {len(self.reasons)} exceeds maximum {MAX_POLICY_REASONS}"
            )
        normalized: List[str] = []
        for r in self.reasons:
            if type(r) is not str or not r.strip():
                raise PolicyEngineError("Each reason must be a non-empty string")
            if any(ord(c) < 32 for c in r):
                raise PolicyEngineError("Reasons must not contain control characters")
            if r not in POLICY_REASON_CODES:
                raise PolicyEngineError(
                    f"Unknown policy reason code '{r}'. Must be one of allowlisted codes."
                )
            normalized.append(r)
        object.__setattr__(self, "reasons", tuple(normalized))

        # Enforce consequential action invariant
        if self.proposed_action in CONSEQUENTIAL_ACTIONS:
            if not self.requires_human_approval:
                raise PolicyEngineError(
                    f"Action '{self.proposed_action.value}' is consequential and "
                    f"must require human approval"
                )
            if self.action_disposition != ActionDisposition.APPROVAL_REQUIRED:
                raise PolicyEngineError(
                    f"Action '{self.proposed_action.value}' must have "
                    f"APPROVAL_REQUIRED disposition"
                )


class RiskPolicyEngine:
    """Deterministic policy engine for calculating risk scores and recommending actions."""

    def evaluate(
        self,
        context: PolicyContext,
        investigation_result: Optional[InvestigationResult] = None,
        audit_log: Optional[AuditLog] = None,
    ) -> PolicyDecision:
        """Evaluate deterministic policy rules on the provided context and advisory result.

        Args:
            context: Policy context containing untrusted alert evidence and
                     trusted deterministic policy facts.
            investigation_result: Optional advisory findings from AI investigation.
            audit_log: Optional in-memory audit log for recording policy decisions.

        Returns:
            Validated PolicyDecision.

        Raises:
            PolicyEngineError: If context or result is malformed.
        """
        if not isinstance(context, PolicyContext):
            raise PolicyEngineError(
                f"context must be PolicyContext, got {type(context).__name__}"
            )
        if investigation_result is not None and not isinstance(investigation_result, InvestigationResult):
            raise PolicyEngineError(
                f"investigation_result must be InvestigationResult or None, "
                f"got {type(investigation_result).__name__}"
            )

        # -------------------------------------------------------------------
        # Exact Benign Lab Fixture Rule (Strict Conjunction of Trusted Facts)
        # -------------------------------------------------------------------
        is_trusted_benign_lab = (
            context.verified_detection_id == BENIGN_LAB_DETECTION_ID
            and context.deterministic_decoded_command == EXACT_BENIGN_COMMAND
            and not context.tool_failure_or_incomplete_evidence
        )

        if is_trusted_benign_lab:
            decision = PolicyDecision(
                risk_score=0,
                risk_level=RiskLevel.LOW,
                action_disposition=ActionDisposition.NO_ACTION,
                proposed_action=ProposedAction.NO_ACTION,
                reasons=("benign_lab_fixture_matched",),
                requires_human_approval=False,
            )
            self._record_audit(audit_log, context.alert.incident_id, decision, is_benign=True)
            return decision

        # -------------------------------------------------------------------
        # Deterministic Scoring (Non-Benign)
        # -------------------------------------------------------------------
        raw_score = 0
        reasons: List[str] = []

        # 1. Trusted deterministic signals
        if context.verified_detection_id == BENIGN_LAB_DETECTION_ID:
            raw_score += 25
            reasons.append("encoded_powershell_detected")

        if context.deterministic_decoded_command is not None and context.deterministic_decoded_command.strip():
            raw_score += 10
            reasons.append("decoded_command_present")

        if context.mitre_technique_id == "T1059.001":
            raw_score += 10
            reasons.append("mitre_t1059_001")

        if context.tool_failure_or_incomplete_evidence:
            raw_score += 15
            reasons.append("incomplete_evidence_uncertainty")

        # 2. Model-derived advisory signals (strictly additive, escalating only)
        if investigation_result is not None:
            if len(investigation_result.suspicious_indicators) >= 1:
                raw_score += 20
                reasons.append("suspicious_indicators_present")
            if len(investigation_result.suspicious_indicators) > 1:
                raw_score += 5
                reasons.append("multiple_suspicious_indicators")

            if investigation_result.confidence_level == "high":
                raw_score += 10
                reasons.append("model_confidence_high")
            elif investigation_result.confidence_level == "medium":
                raw_score += 5
                reasons.append("model_confidence_medium")

        risk_score = min(raw_score, 100)

        # -------------------------------------------------------------------
        # Risk Level Classification
        # -------------------------------------------------------------------
        if risk_score <= 24:
            risk_level = RiskLevel.LOW
        elif risk_score <= 49:
            risk_level = RiskLevel.MEDIUM
        elif risk_score <= 74:
            risk_level = RiskLevel.HIGH
        else:
            risk_level = RiskLevel.CRITICAL

        # -------------------------------------------------------------------
        # Action Mapping
        # -------------------------------------------------------------------
        if risk_level == RiskLevel.LOW:
            proposed_action = ProposedAction.MONITOR
            action_disposition = ActionDisposition.MONITOR
            requires_human_approval = False
        elif risk_level == RiskLevel.MEDIUM:
            proposed_action = ProposedAction.REQUEST_HUMAN_REVIEW
            action_disposition = ActionDisposition.HUMAN_REVIEW
            requires_human_approval = False
        elif risk_level == RiskLevel.HIGH:
            proposed_action = ProposedAction.CREATE_INCIDENT_RECORD
            action_disposition = ActionDisposition.HUMAN_REVIEW
            requires_human_approval = False
        else:  # CRITICAL
            proposed_action = ProposedAction.SIMULATE_ENDPOINT_ISOLATION
            action_disposition = ActionDisposition.APPROVAL_REQUIRED
            requires_human_approval = True
            reasons.append("approval_required_for_consequential_action")

        # -------------------------------------------------------------------
        # Fail-Closed Incomplete-Evidence Rule
        # -------------------------------------------------------------------
        if context.tool_failure_or_incomplete_evidence:
            reasons.append("fail_closed_incomplete_evidence")
            if risk_level == RiskLevel.LOW:
                proposed_action = ProposedAction.REQUEST_HUMAN_REVIEW
                action_disposition = ActionDisposition.HUMAN_REVIEW
                requires_human_approval = False

        decision = PolicyDecision(
            risk_score=risk_score,
            risk_level=risk_level,
            action_disposition=action_disposition,
            proposed_action=proposed_action,
            reasons=tuple(reasons),
            requires_human_approval=requires_human_approval,
        )
        self._record_audit(audit_log, context.alert.incident_id, decision, is_benign=False)
        return decision

    def _record_audit(
        self,
        audit_log: Optional[AuditLog],
        incident_id: str,
        decision: PolicyDecision,
        is_benign: bool,
    ) -> None:
        """Record policy decision to audit log if provided."""
        if audit_log is None:
            return

        detail_code = "benign_lab_rule_applied" if is_benign else f"risk_{decision.risk_level.value.lower()}"
        seq = len(audit_log.events())
        audit_log.append(AuditEvent(
            event_type=AuditEventType.POLICY_EVALUATED,
            incident_id=incident_id,
            sequence=seq,
            detail_code=detail_code,
        ))

        if decision.requires_human_approval:
            audit_log.append(AuditEvent(
                event_type=AuditEventType.APPROVAL_REQUIRED,
                incident_id=incident_id,
                sequence=seq + 1,
                detail_code="approval_required",
            ))
