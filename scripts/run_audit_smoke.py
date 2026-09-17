"""Standalone offline smoke test for Milestone 3C persistent JSONL audit logging.

Security Rules:
  - Uses FakeModel ONLY (zero live model calls, zero secrets).
  - Uses local ToolRouter with deterministic tools (zero network calls).
  - Persists audit events to the configured local runtime path: artifacts/audit/agent_audit.jsonl.
  - Prints ONLY:
      - Number of audit events written
      - Destination relative path
      - Success/failure status
  - Never prints full audit content, raw telemetry, or secrets.
"""

import sys
from pathlib import Path

# Ensure repository root is on sys.path
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from investigator.audit import AuditLog
from investigator.audit_writer import DEFAULT_AUDIT_LOG_PATH, JsonlAuditWriter
from investigator.fake_model import FakeModel
from investigator.model import DecisionType, ModelDecision, ToolRequest
from investigator.orchestrator import InvestigationOrchestrator
from investigator.schemas import ConfidenceLevel, InvestigationInput, InvestigationResult
from investigator.tool_router import ToolRouter


def main() -> int:
    try:
        # 1. Setup deterministic FakeModel for a benign investigation
        final_res = InvestigationResult(
            summary="All evidence indicates controlled benign testing.",
            observations=("Decoded benign Write-Host payload",),
            decoded_command="Write-Host",
            mitre_techniques=("T1059.001",),
            suspicious_indicators=(),
            recommended_next_step="Close incident as benign test.",
            confidence_level=ConfidenceLevel.LOW.value,
            evidence_refs=("DC01 Sysmon Event 1",),
        )
        fake_model = FakeModel(
            decisions=[
                ModelDecision(
                    decision_type=DecisionType.TOOL_REQUEST,
                    tool_request=ToolRequest(
                        tool_name="decode_base64_powershell",
                        arguments={"encoded_input": "VwByAGkAdABlAC0ASABvAHMAdAA="},
                    ),
                ),
                ModelDecision(
                    decision_type=DecisionType.FINAL_RESULT,
                    final_result=final_res,
                ),
            ]
        )

        # 2. Configure deterministic orchestrator with in-memory AuditLog
        router = ToolRouter()
        audit_log = AuditLog()
        orchestrator = InvestigationOrchestrator(
            model=fake_model,
            tool_router=router,
            audit_log=audit_log,
        )

        # 3. Controlled benign alert context
        input_data = InvestigationInput(
            incident_id="INC-SMOKE-3C",
            timestamp="2026-09-17T08:00:00Z",
            host="DC01",
            user="SOCLAB\\Administrator",
            image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            command_line="powershell.exe -NoProfile -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAA=",
            parent_image="C:\\Windows\\System32\\cmd.exe",
            parent_command_line="cmd.exe",
            detection_name="Suspicious Encoded PowerShell",
            detection_id="DET-001",
        )

        # 4. Execute investigation
        orchestrator.investigate(input_data)

        # 5. Persist audit events to configured runtime path
        events = audit_log.events()
        dest_path = _REPO_ROOT / DEFAULT_AUDIT_LOG_PATH
        writer = JsonlAuditWriter(dest_path)
        writer.write_events(events)

        # 6. Report summary only (no raw audit content, no secrets)
        rel_dest = dest_path.relative_to(_REPO_ROOT)
        print(f"Events written: {len(events)}")
        print(f"Destination: {rel_dest}")
        print("Status: SUCCESS")
        return 0

    except Exception:
        print("Status: FAILURE", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
