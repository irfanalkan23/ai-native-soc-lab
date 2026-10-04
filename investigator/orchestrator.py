"""Bounded investigation orchestrator for AI-assisted SOC triage.

Architecture Guarantees:
  1. The model is never given Python callables, Splunk clients, or secrets.
  2. All model decisions are validated before any tool is invoked.
  3. Tools are invoked exclusively through the deterministic ToolRouter.
  4. Invalid or forbidden tool requests (unknown tool, arbitrary SPL/URL, bad args)
     terminate the investigation immediately (fail-closed).
  5. Allowed-tool execution failures produce a success=False ToolResultEnvelope
     and allow the model to continue within its remaining budget.
  6. The tool-call count and model-decision count are tracked independently:
       MAX_TOOL_CALLS = 3   (maximum ToolRouter calls per investigation)
       MAX_MODEL_DECISIONS = 4 = MAX_TOOL_CALLS + 1
     A legitimate investigation can issue 3 tools then 1 FINAL_RESULT.
  7. No recursion; uses an explicit deterministic for-loop.
  8. All tool outputs are UNTRUSTED DATA serialized to bounded JSON strings.
  9. Size-bound violations on serialized results produce a sanitized error envelope.
"""

import json
from typing import Any, Dict, List, Optional, Union

from investigator.audit import AuditEvent, AuditEventType, AuditLog
from investigator.model import (
    INVESTIGATOR_SYSTEM_INSTRUCTIONS,
    WEB01_INVESTIGATOR_SYSTEM_INSTRUCTIONS,
    DecisionType,
    ModelDecision,
    ModelRequest,
    ToolRequest,
)
from investigator.runtime_guard import RuntimeGuard, RuntimeHaltError
from investigator.schemas import (
    InvestigationInput,
    InvestigationResult,
    Web01InvestigationAssessment,
    Web01InvestigationRequest,
)
from investigator.tool_result import MAX_RESULT_TEXT_LENGTH, ToolResultEnvelope
from investigator.tool_router import ToolRouter, ToolValidationError, ToolExecutionError


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_TOOL_CALLS: int = 3
MAX_MODEL_DECISIONS: int = MAX_TOOL_CALLS + 1  # 4 — last slot is reserved for FINAL_RESULT


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class OrchestratorError(Exception):
    """Raised when the investigation orchestrator fails closed."""
    pass


# ---------------------------------------------------------------------------
# Tool Audit Mapping & Helper (Milestone 8K)
# ---------------------------------------------------------------------------

_TOOL_AUDIT_PREFIX: Dict[str, str] = {
    "bounded_splunk_search": "bounded_splunk_search",
    "decode_base64_powershell": "decode_base64_powershell",
    "map_mitre_technique": "map_mitre_technique",
    "threat_intel_lookup": "threat_intel_lookup",
}

_ALLOWED_AUDIT_SUFFIXES = frozenset({
    "requested",
    "allowed",
    "ok",
    "execution_failed",
    "result_too_large",
})


def _tool_audit_code(tool_name: str, suffix: str) -> str:
    """Derive a fixed machine-readable audit detail code for an allowlisted tool.

    Security Guarantees:
      - Accepts only the 4 strictly allowlisted tool names.
      - Accepts only fixed internal lifecycle suffixes.
      - Never interpolates arbitrary strings or model inputs into audit.
      - Fails closed for unknown tool names or unknown suffixes.
    """
    if tool_name not in _TOOL_AUDIT_PREFIX or suffix not in _ALLOWED_AUDIT_SUFFIXES:
        raise ValueError(
            f"Invalid tool audit mapping: tool_name={tool_name!r}, suffix={suffix!r}"
        )
    return f"{_TOOL_AUDIT_PREFIX[tool_name]}_{suffix}"


# ---------------------------------------------------------------------------
# Result serialization helpers
# ---------------------------------------------------------------------------

def _serialize_tool_result(tool_name: str, raw_result: Any) -> str:
    """Serialize a ToolRouter result into a bounded JSON string for the model.

    Returns a JSON string. Raises ValueError if the result cannot be serialized
    or if the serialized text exceeds MAX_RESULT_TEXT_LENGTH.
    """
    try:
        if tool_name == "decode_base64_powershell":
            # DecodeResult dataclass
            payload: Dict[str, Any] = {
                "decoded_text": raw_result.decoded_text,
                "encoding": raw_result.encoding,
                "byte_count": raw_result.byte_count,
            }
        elif tool_name == "map_mitre_technique":
            # MitreMapping dataclass
            payload = {
                "mapped": raw_result.mapped,
                "technique_id": raw_result.technique_id,
                "technique_name": raw_result.technique_name,
                "tactic_id": raw_result.tactic_id,
                "tactic_name": raw_result.tactic_name,
                "detection_ref": raw_result.detection_ref,
            }
        elif tool_name == "bounded_splunk_search":
            # List[Dict[str, Any]]
            payload = {"events": raw_result, "event_count": len(raw_result)}
        elif tool_name == "threat_intel_lookup":
            # ThreatIntelObservation dataclass
            if hasattr(raw_result, "to_dict"):
                payload = raw_result.to_dict()
            else:
                payload = {
                    "indicator": raw_result.indicator,
                    "indicator_type": raw_result.indicator_type,
                    "provider": raw_result.provider,
                    "verdict": raw_result.verdict,
                    "malicious_count": raw_result.malicious_count,
                    "suspicious_count": raw_result.suspicious_count,
                    "harmless_count": raw_result.harmless_count,
                    "undetected_count": raw_result.undetected_count,
                    "source_reference": raw_result.source_reference,
                }
        else:
            raise ValueError(f"Unknown tool_name for serialization: {tool_name}")

        result_text = json.dumps(payload, default=str)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Serialization failed for {tool_name}: {exc}") from exc

    if len(result_text) > MAX_RESULT_TEXT_LENGTH:
        raise ValueError(
            f"Serialized result for '{tool_name}' ({len(result_text)} chars) "
            f"exceeds MAX_RESULT_TEXT_LENGTH ({MAX_RESULT_TEXT_LENGTH})"
        )
    return result_text


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class InvestigationOrchestrator:
    """Bounded, deterministic investigation orchestrator.

    Accepts a model interface and a ToolRouter. Drives the investigation loop
    without exposing internals to the model and without recursion.
    """

    def __init__(
        self,
        model: Any,
        tool_router: ToolRouter,
        audit_log: Optional[AuditLog] = None,
        guard: Optional[RuntimeGuard] = None,
    ) -> None:
        self._model = model
        self._tool_router = tool_router
        self._audit_log = audit_log or AuditLog()
        if guard is not None:
            self._guard = guard
            if self._guard.audit_log is None:
                self._guard.bind_audit_log(self._audit_log)
            elif self._guard.audit_log is not self._audit_log:
                raise OrchestratorError("RuntimeGuard already bound to a different AuditLog")
        else:
            self._guard = RuntimeGuard(audit_log=self._audit_log)

    @property
    def audit_log(self) -> AuditLog:
        """Return the audit log for this orchestrator instance."""
        return self._audit_log

    @property
    def guard(self) -> RuntimeGuard:
        """Return the runtime guard attached to this orchestrator instance."""
        return self._guard

    def investigate(
        self,
        investigation_input: Union[InvestigationInput, Web01InvestigationRequest],
    ) -> Union[InvestigationResult, Web01InvestigationAssessment]:
        """Drive one investigation session to a validated result.

        Supports both DC01 endpoint detections (InvestigationInput -> InvestigationResult)
        and WEB01 web application detections (Web01InvestigationRequest -> Web01InvestigationAssessment).

        Args:
            investigation_input: Validated alert context (InvestigationInput or Web01InvestigationRequest).

        Returns:
            A validated InvestigationResult (for DC01) or Web01InvestigationAssessment (for WEB01).

        Raises:
            OrchestratorError: On any policy violation, budget exhaustion, invalid
                              model decision, or failure to produce a final result.
        """
        if isinstance(investigation_input, InvestigationInput):
            incident_id = investigation_input.incident_id
            is_web01 = False
            system_instructions = INVESTIGATOR_SYSTEM_INSTRUCTIONS
        elif isinstance(investigation_input, Web01InvestigationRequest):
            # For WEB01, Milestone 13A establishes the bounded input contract containing
            # detection_id ("DET-WEB-001") without an arbitrary caller-controlled incident ID.
            # We bind detection_id as the correlation scope for RuntimeGuard and AuditLog
            # for this investigation session. It represents the detection alert context,
            # not a globally unique incident UUID. End-to-end incident lifecycle correlation
            # is reserved for subsequent milestones.
            incident_id = investigation_input.detection_id
            is_web01 = True
            system_instructions = WEB01_INVESTIGATOR_SYSTEM_INSTRUCTIONS
        else:
            raise OrchestratorError(
                f"investigation_input must be InvestigationInput or Web01InvestigationRequest, "
                f"got {type(investigation_input).__name__}"
            )

        self._guard.bind_incident_id(incident_id)
        tool_calls_used: int = 0
        prior_tool_results: List[ToolResultEnvelope] = []
        audit_seq: int = 0

        def _audit(event_type: AuditEventType, detail_code: str) -> None:
            nonlocal audit_seq
            self._audit_log.append(AuditEvent(
                event_type=event_type,
                incident_id=incident_id,
                sequence=audit_seq,
                detail_code=detail_code,
            ))
            audit_seq += 1

        for _decision_idx in range(MAX_MODEL_DECISIONS):
            # Check runtime guard before model invocation
            try:
                self._guard.before_model_invocation()
            except RuntimeHaltError as exc:
                raise OrchestratorError(
                    f"Runtime guard halted model invocation: {exc.detail_code}"
                ) from exc

            # --- Build ModelRequest ---
            request = ModelRequest(
                system_instructions=system_instructions,
                investigation_input=investigation_input,
                prior_tool_results=tuple(prior_tool_results),
                remaining_tool_budget=MAX_TOOL_CALLS - tool_calls_used,
            )

            # --- Call model ---
            _audit(AuditEventType.MODEL_REQUESTED, f"decision_idx={_decision_idx}")
            try:
                decision: ModelDecision = self._model.decide(request)
            except Exception as exc:
                _audit(AuditEventType.INVESTIGATION_FAILED, "MODEL_ERROR")
                raise OrchestratorError(
                    f"Model raised an unexpected error: {type(exc).__name__}"
                ) from exc

            # --- Validate model return type before accessing any attribute ---
            if not isinstance(decision, ModelDecision):
                _audit(AuditEventType.INVESTIGATION_FAILED, "INVALID_MODEL_DECISION")
                raise OrchestratorError(
                    f"Model returned invalid type: expected ModelDecision, "
                    f"got {type(decision).__name__}"
                )

            # --- Branch: FINAL_RESULT ---
            if decision.decision_type == DecisionType.FINAL_RESULT:
                result = decision.final_result
                if is_web01:
                    if not isinstance(result, Web01InvestigationAssessment):
                        _audit(AuditEventType.INVESTIGATION_FAILED, "INVALID_FINAL_RESULT_TYPE")
                        raise OrchestratorError(
                            f"Expected Web01InvestigationAssessment for WEB01 investigation, "
                            f"got {type(result).__name__}"
                        )
                else:
                    if not isinstance(result, InvestigationResult):
                        _audit(AuditEventType.INVESTIGATION_FAILED, "INVALID_FINAL_RESULT_TYPE")
                        raise OrchestratorError(
                            f"Expected InvestigationResult for DC01 investigation, "
                            f"got {type(result).__name__}"
                        )
                _audit(AuditEventType.FINAL_RESULT_ACCEPTED, "ok")
                return result

            # --- Branch: TOOL_REQUEST ---
            if decision.decision_type == DecisionType.TOOL_REQUEST:
                tool_req: ToolRequest = decision.tool_request

                # WEB01 workflow tool restriction: bounded_splunk_search only
                if is_web01:
                    if tool_req.tool_name != "bounded_splunk_search":
                        _audit(AuditEventType.INVESTIGATION_FAILED, "UNAUTHORIZED_TOOL")
                        raise OrchestratorError(
                            f"Unauthorized tool '{tool_req.tool_name}' for WEB01 investigation. "
                            f"Only 'bounded_splunk_search' is permitted."
                        )
                    raw_args = tool_req.arguments
                    if raw_args.get("query_type") != "modsecurity_sqli_matches":
                        _audit(AuditEventType.INVESTIGATION_FAILED, "INVALID_TOOL_REQUEST")
                        raise OrchestratorError(
                            f"Unauthorized query_type '{raw_args.get('query_type')}' for WEB01 investigation"
                        )
                    if raw_args.get("host") != "web01":
                        _audit(AuditEventType.INVESTIGATION_FAILED, "INVALID_TOOL_REQUEST")
                        raise OrchestratorError(
                            f"Unauthorized host '{raw_args.get('host')}' for WEB01 investigation"
                        )

                is_allowlisted_tool = tool_req.tool_name in _TOOL_AUDIT_PREFIX

                # Use a static detail code — never place model-supplied arbitrary tool name
                # directly into audit. If allowlisted, derive fixed code; otherwise use generic.
                req_audit_code = (
                    _tool_audit_code(tool_req.tool_name, "requested")
                    if is_allowlisted_tool
                    else "tool_requested"
                )
                _audit(AuditEventType.TOOL_REQUESTED, req_audit_code)

                # Budget check — reject 4th tool call
                if tool_calls_used >= MAX_TOOL_CALLS:
                    _audit(AuditEventType.TOOL_REJECTED, "BUDGET_EXHAUSTED")
                    raise OrchestratorError(
                        f"Tool budget exhausted: {MAX_TOOL_CALLS} tool calls already used. "
                        f"Model must emit FINAL_RESULT."
                    )

                allowed_audit_code = (
                    _tool_audit_code(tool_req.tool_name, "allowed")
                    if is_allowlisted_tool
                    else "tool_allowed"
                )
                _audit(AuditEventType.TOOL_ALLOWED, allowed_audit_code)

                # Check runtime guard before tool execution
                try:
                    self._guard.before_tool_execution()
                except RuntimeHaltError as exc:
                    raise OrchestratorError(
                        f"Runtime guard halted tool execution: {exc.detail_code}"
                    ) from exc

                # Execute via ToolRouter only
                try:
                    raw_result = self._tool_router.execute_tool(
                        tool_req.tool_name,
                        tool_req.arguments_as_dict(),
                    )
                except ToolValidationError as exc:
                    # Invalid/forbidden request (unknown tool, arbitrary SPL, bad args)
                    # → fail-closed immediately; do not continue investigation
                    _audit(AuditEventType.INVESTIGATION_FAILED, "INVALID_TOOL_REQUEST")
                    raise OrchestratorError(
                        f"Invalid or forbidden tool request '{tool_req.tool_name}': "
                        f"{type(exc).__name__}"
                    ) from exc
                except ToolExecutionError as exc:
                    # Allowed tool ran but failed at execution
                    # → produce success=False envelope; model may still recover
                    envelope = ToolResultEnvelope(
                        tool_name=tool_req.tool_name,
                        success=False,
                        result_text=json.dumps({"error": "tool_execution_failed"}),
                        error_code="TOOL_EXECUTION_FAILED",
                    )
                    prior_tool_results.append(envelope)
                    tool_calls_used += 1
                    exec_failed_audit_code = (
                        _tool_audit_code(tool_req.tool_name, "execution_failed")
                        if is_allowlisted_tool
                        else "execution_failed"
                    )
                    _audit(AuditEventType.TOOL_COMPLETED, exec_failed_audit_code)
                    continue

                # Serialize result to bounded JSON string
                try:
                    result_text = _serialize_tool_result(tool_req.tool_name, raw_result)
                    envelope = ToolResultEnvelope(
                        tool_name=tool_req.tool_name,
                        success=True,
                        result_text=result_text,
                        error_code=None,
                    )
                    audit_detail = (
                        _tool_audit_code(tool_req.tool_name, "ok")
                        if is_allowlisted_tool
                        else "ok"
                    )
                except ValueError:
                    # Result was too large or could not be serialized → fail closed with code
                    envelope = ToolResultEnvelope(
                        tool_name=tool_req.tool_name,
                        success=False,
                        result_text=json.dumps({"error": "result_too_large"}),
                        error_code="RESULT_TOO_LARGE",
                    )
                    audit_detail = (
                        _tool_audit_code(tool_req.tool_name, "result_too_large")
                        if is_allowlisted_tool
                        else "result_too_large"
                    )

                prior_tool_results.append(envelope)
                tool_calls_used += 1
                _audit(AuditEventType.TOOL_COMPLETED, audit_detail)
                continue

            # --- Unknown decision type (defensive; ModelDecision validates at construction) ---
            _audit(AuditEventType.INVESTIGATION_FAILED, "UNKNOWN_DECISION_TYPE")
            raise OrchestratorError(
                f"Unexpected decision_type from model: {decision.decision_type!r}"
            )

        # Loop exhausted without FINAL_RESULT
        _audit(AuditEventType.INVESTIGATION_FAILED, "NO_FINAL_RESULT")
        raise OrchestratorError(
            f"Investigation produced no FINAL_RESULT within {MAX_MODEL_DECISIONS} model decisions."
        )
