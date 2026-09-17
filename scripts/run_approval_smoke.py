"""Standalone offline smoke test for Milestone 4 human approval and simulated response execution.

Security Rules:
  - Non-interactive: uses programmatic approval decision injection (zero stdin blocking).
  - Offline: zero live network or endpoint calls.
  - Clearly banners: SIMULATED ONLY — NO ENDPOINT ACTION PERFORMED.
  - Prints ONLY safe summary metadata (zero telemetry, command lines, or secrets).
  - Evaluates:
      Scenario A: CRITICAL incident, human DENIED -> NOT_EXECUTED
      Scenario B: CRITICAL incident, human APPROVED -> SIMULATED
"""

import sys
from pathlib import Path

# Ensure repository root is on sys.path
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import io
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


def _make_smoke_context(incident_id: str) -> ActionAuthorizationContext:
    """Construct a CRITICAL ActionAuthorizationContext requiring human approval."""
    decision = PolicyDecision(
        risk_score=80,
        risk_level=RiskLevel.CRITICAL,
        action_disposition=ActionDisposition.APPROVAL_REQUIRED,
        proposed_action=ProposedAction.SIMULATE_ENDPOINT_ISOLATION,
        reasons=("encoded_powershell_detected", "approval_required_for_consequential_action"),
        requires_human_approval=True,
    )
    return ActionAuthorizationContext(incident_id=incident_id, policy_decision=decision)


def run_scenario_a() -> bool:
    """Scenario A: Consequential action with explicit human DENIAL -> NOT_EXECUTED."""
    print("\n" + "-" * 60)
    print("Scenario A: CRITICAL Alert with Explicit Human Denial")
    print("-" * 60)

    ctx = _make_smoke_context("INC-SMOKE-4A-DENY")
    audit_log = AuditLog()

    # Programmatically inject 'deny' via stream_in
    in_stream = io.StringIO("deny\n")
    out_stream = io.StringIO()
    approval = request_cli_approval(ctx, stream_in=in_stream, stream_out=out_stream, audit_log=audit_log)

    executor = SimulatedResponseExecutor()
    sim_result = executor.execute(ctx, approval, audit_log=audit_log)

    print(f"  Incident ID:       {sim_result.incident_id}")
    print(f"  Proposed Action:   {sim_result.proposed_action.value}")
    print(f"  Approval Decision: {approval.decision.value} ({approval.reason_code})")
    print(f"  Simulation Status: {sim_result.status.value}")
    print(f"  Detail Code:       {sim_result.detail_code}")

    # Verify invariants
    events = audit_log.events()
    event_types = [e.event_type for e in events]
    assert sim_result.status is SimulationStatus.NOT_EXECUTED, "Scenario A must NOT be executed"
    assert sim_result.detail_code == "simulation_blocked_denied", "Expected simulation_blocked_denied"
    assert AuditEventType.APPROVAL_REQUESTED in event_types, "Missing APPROVAL_REQUESTED event"
    assert AuditEventType.APPROVAL_DENIED in event_types, "Missing APPROVAL_DENIED event"
    assert AuditEventType.SIMULATION_NOT_EXECUTED in event_types, "Missing SIMULATION_NOT_EXECUTED event"
    assert AuditEventType.SIMULATION_COMPLETED not in event_types, "SIMULATION_COMPLETED must not be emitted"

    print("  Scenario A Result: PASS (Correctly blocked without execution)")
    return True


def run_scenario_b() -> bool:
    """Scenario B: Consequential action with explicit human APPROVAL -> SIMULATED."""
    print("\n" + "-" * 60)
    print("Scenario B: CRITICAL Alert with Explicit Human Approval")
    print("-" * 60)

    ctx = _make_smoke_context("INC-SMOKE-4B-APPROVE")
    audit_log = AuditLog()

    # Programmatically inject 'approve' via stream_in
    in_stream = io.StringIO("approve\n")
    out_stream = io.StringIO()
    approval = request_cli_approval(ctx, stream_in=in_stream, stream_out=out_stream, audit_log=audit_log)

    executor = SimulatedResponseExecutor()
    sim_result = executor.execute(ctx, approval, audit_log=audit_log)

    print(f"  Incident ID:       {sim_result.incident_id}")
    print(f"  Proposed Action:   {sim_result.proposed_action.value}")
    print(f"  Approval Decision: {approval.decision.value} ({approval.reason_code})")
    print(f"  Simulation Status: {sim_result.status.value}")
    print(f"  Detail Code:       {sim_result.detail_code}")

    # Verify invariants
    events = audit_log.events()
    event_types = [e.event_type for e in events]
    assert sim_result.status is SimulationStatus.SIMULATED, "Scenario B must be SIMULATED"
    assert sim_result.detail_code == "simulated_endpoint_isolation", "Expected simulated_endpoint_isolation"
    assert AuditEventType.APPROVAL_REQUESTED in event_types, "Missing APPROVAL_REQUESTED event"
    assert AuditEventType.APPROVAL_GRANTED in event_types, "Missing APPROVAL_GRANTED event"
    assert AuditEventType.SIMULATION_COMPLETED in event_types, "Missing SIMULATION_COMPLETED event"
    assert AuditEventType.SIMULATION_NOT_EXECUTED not in event_types, "SIMULATION_NOT_EXECUTED must not be emitted"

    print("  Scenario B Result: PASS (Recorded that isolation would have been requested)")
    return True


def main() -> int:
    print("=" * 60)
    print("  AI-Native SOC Lab -- Milestone 4 Approval & Simulation Smoke")
    print("  SIMULATED ONLY -- NO ENDPOINT ACTION PERFORMED")
    print("=" * 60)

    ok_a = run_scenario_a()
    ok_b = run_scenario_b()

    print("\n" + "=" * 60)
    if ok_a and ok_b:
        print("  Milestone 4 Smoke Status: ALL TESTS PASSED")
        print("  Containment Guarantee: Zero actual endpoint or system mutations.")
        print("=" * 60)
        return 0
    else:
        print("  Milestone 4 Smoke Status: FAILED")
        print("=" * 60)
        return 1


if __name__ == "__main__":
    sys.exit(main())
