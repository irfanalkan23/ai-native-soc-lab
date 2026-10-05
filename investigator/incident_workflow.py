"""Deterministic End-to-End WEB01 Incident Workflow Coordinator.

Architecture Principle:
    AI proposes
    -> deterministic policy evaluates
    -> human approves consequential actions
    -> system executes only permitted/simulated actions
    -> IncidentRecord generated as a reporting artifact
    -> downstream bounded ticketing occurs
    -> everything is logged and evaluated

Scope & Trust Boundaries:
    1. Downstream Reporting Composition:
       Coordinates the offline lifecycle from alert context through investigation,
       structured incident-record generation, and bounded ticket formatting.
    2. Authority Separation:
       Web01InvestigationAssessment remains strictly advisory.
       It cannot dictate detection identity, source IP, risk scores, approval status,
       or Jira routing.
    3. Strict Provenance:
       IncidentRecord is constructed exclusively from validated ModSecuritySqliEvidence
       and deterministic threat intelligence outcome captured by the orchestrator.
    4. Bounded & Offline:
       Uses existing ticket configurations and offline ticket clients. Zero live
       OpenAI, VirusTotal, or Jira network calls.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from investigator.audit import AuditLog
from investigator.incident_record import (
    IncidentRecord,
    build_modsecurity_incident_record,
)
from investigator.orchestrator import (
    InvestigationOrchestrator,
    OrchestratorError,
)
from investigator.schemas import (
    Web01InvestigationAssessment,
    Web01InvestigationRequest,
)
from investigator.ticketing import (
    TicketClient,
    TicketConfig,
    TicketRequest,
    TicketResult,
    build_ticket_request,
)


# ---------------------------------------------------------------------------
# Bounded Ticket Routing Configuration
# ---------------------------------------------------------------------------
ALLOWED_WEB01_PROJECT_KEYS = frozenset({"KAN"})
ALLOWED_WEB01_ISSUE_TYPES = frozenset({"Incident"})


@dataclass(frozen=True)
class Web01WorkflowResult:
    """Immutable, validated output artifact of the complete WEB01 incident workflow."""

    assessment: Web01InvestigationAssessment
    incident_record: IncidentRecord
    ticket_request: TicketRequest
    ticket_result: Optional[TicketResult] = None
    audit_log: Optional[AuditLog] = None


def run_web01_incident_workflow(
    request: Web01InvestigationRequest,
    orchestrator: InvestigationOrchestrator,
    ticket_config: TicketConfig,
    ticket_client: Optional[TicketClient] = None,
) -> Web01WorkflowResult:
    """Execute the end-to-end offline WEB01 incident investigation and ticketing workflow.

    Workflow Sequence:
        1. Validate caller parameters fail-closed.
        2. Execute bounded investigation via InvestigationOrchestrator.
        3. Verify that validated ModSecuritySqliEvidence was captured during investigation.
        4. Verify that deterministic TI state was evaluated.
        5. Build immutable IncidentRecord using build_modsecurity_incident_record.
        6. Build bounded TicketRequest using build_ticket_request.
        7. If ticket_client is provided, dispatch create_ticket offline.
        8. Return immutable Web01WorkflowResult.
    """
    if not isinstance(request, Web01InvestigationRequest):
        raise OrchestratorError(
            f"request must be Web01InvestigationRequest, got {type(request).__name__}"
        )
    if not isinstance(orchestrator, InvestigationOrchestrator):
        raise OrchestratorError(
            f"orchestrator must be InvestigationOrchestrator, got {type(orchestrator).__name__}"
        )
    if not isinstance(ticket_config, TicketConfig):
        raise OrchestratorError(
            f"ticket_config must be TicketConfig, got {type(ticket_config).__name__}"
        )
    if ticket_config.project_key not in ALLOWED_WEB01_PROJECT_KEYS:
        raise OrchestratorError(
            f"Unauthorized project_key '{ticket_config.project_key}' for WEB01 incident workflow. "
            f"Allowed project keys: {sorted(ALLOWED_WEB01_PROJECT_KEYS)}"
        )
    if ticket_config.issue_type not in ALLOWED_WEB01_ISSUE_TYPES:
        raise OrchestratorError(
            f"Unauthorized issue_type '{ticket_config.issue_type}' for WEB01 incident workflow. "
            f"Allowed issue types: {sorted(ALLOWED_WEB01_ISSUE_TYPES)}"
        )

    # 1. Execute bounded investigation (orchestrator handles guard, budget, audit, model loop)
    assessment = orchestrator.investigate(request)

    if not isinstance(assessment, Web01InvestigationAssessment):
        raise OrchestratorError(
            f"Expected Web01InvestigationAssessment from orchestrator, got {type(assessment).__name__}"
        )

    # 2. Extract validated evidence captured by orchestrator
    evidence = orchestrator.last_web01_evidence
    if evidence is None:
        raise OrchestratorError(
            "Investigation failed to capture validated ModSecuritySqliEvidence. Cannot create incident record."
        )

    # 3. Extract deterministic TI state captured by orchestrator
    ti_status = orchestrator.last_web01_ti_status
    if ti_status is None:
        raise OrchestratorError(
            "Investigation failed to capture deterministic threat intelligence state. Cannot create incident record."
        )

    ti_skip_reason = orchestrator.last_web01_ti_skip_reason
    ti_observation = orchestrator.last_web01_ti_observation

    # 4. Construct deterministic IncidentRecord
    incident_record = build_modsecurity_incident_record(
        evidence=evidence,
        threat_intel_status=ti_status,
        threat_intel_skip_reason=ti_skip_reason,
        threat_intel_observation=ti_observation,
    )

    # 5. Build bounded TicketRequest
    ticket_request = build_ticket_request(
        incident_record=incident_record,
        ticket_config=ticket_config,
    )

    # 6. Optional offline ticket client execution
    ticket_result: Optional[TicketResult] = None
    if ticket_client is not None:
        ticket_result = ticket_client.create_ticket(ticket_request)

    return Web01WorkflowResult(
        assessment=assessment,
        incident_record=incident_record,
        ticket_request=ticket_request,
        ticket_result=ticket_result,
        audit_log=orchestrator.audit_log,
    )
