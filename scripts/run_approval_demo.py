"""Interactive CLI demonstration of Milestone 4 Human Approval and Simulated Response Execution.

Security & Safety Rules:
  - SIMULATED ONLY -- NO ENDPOINT ACTION PERFORMED.
  - Zero subprocess, shell, socket, or network execution.
  - Zero WinRM, SSH, EDR, firewall, or cloud API calls.
  - Displays safe incident context and interactively requests operator approval.
  - Demonstrates deterministic authorization binding and simulated execution.
"""

import sys
from pathlib import Path

# Ensure repository root is on sys.path
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from investigator.approval import (
    ActionAuthorizationContext,
    request_cli_approval,
)
from investigator.audit import AuditEventType, AuditLog
from investigator.policy import (
    ActionDisposition,
    PolicyDecision,
    ProposedAction,
    RiskLevel,
)
from investigator.simulator import (
    SimulatedResponseExecutor,
    SimulationStatus,
)


def run_demo() -> int:
    print("=" * 64)
    print("  AI-Native SOC Lab -- Milestone 4 Human Approval & Simulation Demo")
    print("  SIMULATED ONLY -- NO ENDPOINT ACTION PERFORMED")
    print("=" * 64)

    incident_id = "INC-DEMO-2026-001"

    # Construct a high-risk policy decision requiring human approval
    decision = PolicyDecision(
        risk_score=85,
        risk_level=RiskLevel.CRITICAL,
        action_disposition=ActionDisposition.APPROVAL_REQUIRED,
        proposed_action=ProposedAction.SIMULATE_ENDPOINT_ISOLATION,
        reasons=(
            "encoded_powershell_detected",
            "decoded_command_present",
            "suspicious_indicators_present",
            "approval_required_for_consequential_action",
        ),
        requires_human_approval=True,
    )

    context = ActionAuthorizationContext(
        incident_id=incident_id,
        policy_decision=decision,
    )

    audit_log = AuditLog()

    print("\n[Stage 1: Presentation & Human Approval Gate]")
    approval_record = request_cli_approval(
        context=context,
        stream_in=sys.stdin,
        stream_out=sys.stdout,
        audit_log=audit_log,
    )

    print("\n[Stage 2: Authorization Binding & Simulated Execution]")
    executor = SimulatedResponseExecutor()
    simulation_result = executor.execute(
        authorization_context=context,
        approval_record=approval_record,
        audit_log=audit_log,
    )

    print("\n" + "=" * 64)
    print("  EXECUTION OUTCOME")
    print("=" * 64)
    print(f"  Incident ID:       {simulation_result.incident_id}")
    print(f"  Target Action:     {simulation_result.proposed_action.value}")
    print(f"  Approval Decision: {approval_record.decision.value} ({approval_record.reason_code})")
    print(f"  Approver Label:    {approval_record.approver}")
    print(f"  Simulation Status: {simulation_result.status.value}")
    print(f"  Detail Code:       {simulation_result.detail_code}")

    if simulation_result.status is SimulationStatus.SIMULATED:
        print("\n  [SIMULATED CONTAINMENT RECORDED]")
        print("  The security platform records that endpoint isolation would")
        print("  have been requested in production.")
        print("  SIMULATED ONLY -- NO ENDPOINT ACTION PERFORMED")
    else:
        print("\n  [ACTION BLOCKED / NOT EXECUTED]")
        print("  Containment action was not approved or authorized.")
        print("  No changes made to endpoint or system.")

    print("\n[Stage 3: Audit Trail Logged]")
    for event in audit_log.events():
        print(f"  Seq {event.sequence}: {event.event_type.value:25} (detail={event.detail_code})")

    print("=" * 64 + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(run_demo())
