"""Unit tests for sanitized tool-aware audit observability in InvestigationOrchestrator (Milestone 8K).

TDD RED Phase:
Verifies that:
1. Each allowlisted tool (bounded_splunk_search, decode_base64_powershell, map_mitre_technique)
   produces expected static detail codes for:
   - TOOL_REQUESTED: <tool>_requested
   - TOOL_ALLOWED:   <tool>_allowed
   - TOOL_COMPLETED: <tool>_ok
2. Tool execution failure preserves only sanitized static tool identity:
   - TOOL_COMPLETED: <tool>_execution_failed
3. Serialization / result-size failure produces:
   - TOOL_COMPLETED: <tool>_result_too_large
4. No raw arguments appear anywhere in audit detail codes.
5. No raw exception messages appear in audit detail codes.
6. Unknown/unallowlisted tool names are never interpolated into audit detail codes.
"""

import unittest
from unittest.mock import MagicMock

from investigator.audit import (
    AuditEventType,
    AuditLog,
    MAX_DETAIL_CODE_LENGTH,
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
from investigator.schemas import (
    ConfidenceLevel,
    InvestigationInput,
    InvestigationResult,
)
from investigator.tool_router import (
    ALLOWED_TOOLS,
    ToolExecutionError,
    ToolRouter,
)
from investigator.tools.base64_decoder import DecodeResult
from investigator.tools.mitre_mapper import MitreMapping


_VALID_INPUT = InvestigationInput(
    incident_id="INC-8K-TEST",
    timestamp="2026-09-28T22:00:00Z",
    host="DC01",
    user="SOCLAB\\Administrator",
    image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    command_line="powershell.exe -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAA=",
    parent_image="C:\\Windows\\System32\\cmd.exe",
    parent_command_line="cmd.exe",
    detection_name="Suspicious Encoded PowerShell",
    detection_id="DET-POWERSHELL-001",
)

_FINAL_RESULT = InvestigationResult(
    summary="Benign PowerShell test.",
    observations=("Benign observation",),
    decoded_command="Write-Host",
    mitre_techniques=("T1059.001",),
    suspicious_indicators=(),
    recommended_next_step="Close incident",
    confidence_level=ConfidenceLevel.LOW.value,
    evidence_refs=("DC01:Sysmon:1",),
)


def _make_orchestrator(decisions, router=None, audit_log=None):
    model = FakeModel(decisions)
    audit = audit_log if audit_log is not None else AuditLog()
    if router is None:
        mock_splunk = MagicMock()
        mock_splunk.search_encoded_powershell.return_value = []
        mock_splunk.search_powershell_network_retrieval.return_value = []
        router = ToolRouter(splunk_client=mock_splunk)
    orch = InvestigationOrchestrator(model=model, tool_router=router, audit_log=audit)
    return orch, audit


class TestSanitizedToolAwareAuditObservability(unittest.TestCase):
    """Test suite verifying sanitized tool-aware audit detail codes."""

    # -----------------------------------------------------------------------
    # Requirement 1: Each allowlisted tool gets expected static codes
    # -----------------------------------------------------------------------

    def test_bounded_splunk_search_success_detail_codes(self) -> None:
        """Proof: bounded_splunk_search emits static requested/allowed/ok detail codes."""
        decisions = [
            ModelDecision(
                decision_type=DecisionType.TOOL_REQUEST,
                tool_request=ToolRequest(
                    tool_name="bounded_splunk_search",
                    arguments={
                        "query_type": "encoded_powershell_matches",
                        "host": "DC01",
                    },
                ),
            ),
            ModelDecision(
                decision_type=DecisionType.FINAL_RESULT,
                final_result=_FINAL_RESULT,
            ),
        ]
        orch, audit_log = _make_orchestrator(decisions)
        orch.investigate(_VALID_INPUT)

        events = audit_log.events()
        event_map = {e.event_type: e.detail_code for e in events}

        self.assertEqual(
            event_map.get(AuditEventType.TOOL_REQUESTED),
            "bounded_splunk_search_requested",
            msg="TOOL_REQUESTED must record bounded_splunk_search_requested",
        )
        self.assertEqual(
            event_map.get(AuditEventType.TOOL_ALLOWED),
            "bounded_splunk_search_allowed",
            msg="TOOL_ALLOWED must record bounded_splunk_search_allowed",
        )
        self.assertEqual(
            event_map.get(AuditEventType.TOOL_COMPLETED),
            "bounded_splunk_search_ok",
            msg="Successful TOOL_COMPLETED must record bounded_splunk_search_ok",
        )

    def test_decode_base64_powershell_success_detail_codes(self) -> None:
        """Proof: decode_base64_powershell emits static requested/allowed/ok detail codes."""
        decisions = [
            ModelDecision(
                decision_type=DecisionType.TOOL_REQUEST,
                tool_request=ToolRequest(
                    tool_name="decode_base64_powershell",
                    arguments={
                        "encoded_input": "VwByAGkAdABlAC0ASABvAHMAdAA=",
                    },
                ),
            ),
            ModelDecision(
                decision_type=DecisionType.FINAL_RESULT,
                final_result=_FINAL_RESULT,
            ),
        ]
        orch, audit_log = _make_orchestrator(decisions)
        orch.investigate(_VALID_INPUT)

        events = audit_log.events()
        event_map = {e.event_type: e.detail_code for e in events}

        self.assertEqual(
            event_map.get(AuditEventType.TOOL_REQUESTED),
            "decode_base64_powershell_requested",
            msg="TOOL_REQUESTED must record decode_base64_powershell_requested",
        )
        self.assertEqual(
            event_map.get(AuditEventType.TOOL_ALLOWED),
            "decode_base64_powershell_allowed",
            msg="TOOL_ALLOWED must record decode_base64_powershell_allowed",
        )
        self.assertEqual(
            event_map.get(AuditEventType.TOOL_COMPLETED),
            "decode_base64_powershell_ok",
            msg="Successful TOOL_COMPLETED must record decode_base64_powershell_ok",
        )

    def test_map_mitre_technique_success_detail_codes(self) -> None:
        """Proof: map_mitre_technique emits static requested/allowed/ok detail codes."""
        decisions = [
            ModelDecision(
                decision_type=DecisionType.TOOL_REQUEST,
                tool_request=ToolRequest(
                    tool_name="map_mitre_technique",
                    arguments={
                        "detection_ref": "encoded_powershell_matches",
                        "fail_closed": True,
                    },
                ),
            ),
            ModelDecision(
                decision_type=DecisionType.FINAL_RESULT,
                final_result=_FINAL_RESULT,
            ),
        ]
        orch, audit_log = _make_orchestrator(decisions)
        orch.investigate(_VALID_INPUT)

        events = audit_log.events()
        event_map = {e.event_type: e.detail_code for e in events}

        self.assertEqual(
            event_map.get(AuditEventType.TOOL_REQUESTED),
            "map_mitre_technique_requested",
            msg="TOOL_REQUESTED must record map_mitre_technique_requested",
        )
        self.assertEqual(
            event_map.get(AuditEventType.TOOL_ALLOWED),
            "map_mitre_technique_allowed",
            msg="TOOL_ALLOWED must record map_mitre_technique_allowed",
        )
        self.assertEqual(
            event_map.get(AuditEventType.TOOL_COMPLETED),
            "map_mitre_technique_ok",
            msg="Successful TOOL_COMPLETED must record map_mitre_technique_ok",
        )

    # -----------------------------------------------------------------------
    # Requirement 2: ToolExecutionError preserves sanitized static tool identity
    # -----------------------------------------------------------------------

    def test_tool_execution_error_detail_codes(self) -> None:
        """Proof: ToolExecutionError audits <tool>_execution_failed for each allowlisted tool."""
        test_cases = [
            (
                "bounded_splunk_search",
                {
                    "query_type": "encoded_powershell_matches",
                    "host": "DC01",
                },
                "bounded_splunk_search_execution_failed",
            ),
            (
                "decode_base64_powershell",
                {"encoded_input": "VwByAGkAdABlAC0ASABvAHMAdAA="},
                "decode_base64_powershell_execution_failed",
            ),
            (
                "map_mitre_technique",
                {"detection_ref": "encoded_powershell_matches", "fail_closed": True},
                "map_mitre_technique_execution_failed",
            ),
        ]

        for tool_name, tool_args, expected_failure_code in test_cases:
            with self.subTest(tool=tool_name):
                decisions = [
                    ModelDecision(
                        decision_type=DecisionType.TOOL_REQUEST,
                        tool_request=ToolRequest(
                            tool_name=tool_name,
                            arguments=tool_args,
                        ),
                    ),
                    ModelDecision(
                        decision_type=DecisionType.FINAL_RESULT,
                        final_result=_FINAL_RESULT,
                    ),
                ]
                mock_router = MagicMock(spec=ToolRouter)
                mock_router.execute_tool.side_effect = ToolExecutionError(
                    "Simulated execution crash"
                )

                orch, audit_log = _make_orchestrator(decisions, router=mock_router)
                orch.investigate(_VALID_INPUT)

                completed_events = [
                    e for e in audit_log.events()
                    if e.event_type == AuditEventType.TOOL_COMPLETED
                ]
                self.assertEqual(len(completed_events), 1)
                self.assertEqual(
                    completed_events[0].detail_code,
                    expected_failure_code,
                    msg=f"Execution error for {tool_name} must audit {expected_failure_code}",
                )

    # -----------------------------------------------------------------------
    # Requirement 2 (cont): Result size / serialization failure
    # -----------------------------------------------------------------------

    def test_result_too_large_detail_codes(self) -> None:
        """Proof: Result too large audits <tool>_result_too_large for each allowlisted tool."""
        oversized_splunk = [{"event": "X" * 10000} for _ in range(10)]
        oversized_decoder = DecodeResult(
            success=True,
            decoded_text="X" * 65536,
            encoding="utf-16le",
            byte_count=131072,
        )
        oversized_mitre = MitreMapping(
            mapped=True,
            technique_id="T" * 32768,
            technique_name="Huge Technique Name " * 1000,
            tactic_id="TA0002",
            tactic_name="Execution",
            detection_ref="ref",
        )

        test_cases = [
            (
                "bounded_splunk_search",
                {
                    "query_type": "encoded_powershell_matches",
                    "host": "DC01",
                },
                oversized_splunk,
                "bounded_splunk_search_result_too_large",
            ),
            (
                "decode_base64_powershell",
                {"encoded_input": "VwByAGkAdABlAC0ASABvAHMAdAA="},
                oversized_decoder,
                "decode_base64_powershell_result_too_large",
            ),
            (
                "map_mitre_technique",
                {"detection_ref": "encoded_powershell_matches", "fail_closed": True},
                oversized_mitre,
                "map_mitre_technique_result_too_large",
            ),
        ]

        for tool_name, tool_args, oversized_obj, expected_large_code in test_cases:
            with self.subTest(tool=tool_name):
                decisions = [
                    ModelDecision(
                        decision_type=DecisionType.TOOL_REQUEST,
                        tool_request=ToolRequest(
                            tool_name=tool_name,
                            arguments=tool_args,
                        ),
                    ),
                    ModelDecision(
                        decision_type=DecisionType.FINAL_RESULT,
                        final_result=_FINAL_RESULT,
                    ),
                ]
                mock_router = MagicMock(spec=ToolRouter)
                mock_router.execute_tool.return_value = oversized_obj

                orch, audit_log = _make_orchestrator(decisions, router=mock_router)
                orch.investigate(_VALID_INPUT)

                completed_events = [
                    e for e in audit_log.events()
                    if e.event_type == AuditEventType.TOOL_COMPLETED
                ]
                self.assertEqual(len(completed_events), 1)
                self.assertEqual(
                    completed_events[0].detail_code,
                    expected_large_code,
                    msg=f"Oversized result for {tool_name} must audit {expected_large_code}",
                )

    # -----------------------------------------------------------------------
    # Requirement 3: No raw arguments appear in audit
    # -----------------------------------------------------------------------

    def test_no_raw_arguments_in_audit_detail_codes(self) -> None:
        """Proof: Sensitive tool arguments never appear in any audit detail_code."""
        sensitive_payload = "SUPER_SECRET_PAYLOAD_DO_NOT_LOG_INTO_AUDIT_12345"
        decisions = [
            ModelDecision(
                decision_type=DecisionType.TOOL_REQUEST,
                tool_request=ToolRequest(
                    tool_name="decode_base64_powershell",
                    arguments={
                        "encoded_input": sensitive_payload,
                    },
                ),
            ),
            ModelDecision(
                decision_type=DecisionType.FINAL_RESULT,
                final_result=_FINAL_RESULT,
            ),
        ]
        mock_router = MagicMock(spec=ToolRouter)
        mock_router.execute_tool.return_value = DecodeResult(
            success=True,
            decoded_text="safe_decoded_output",
            encoding="utf-16le",
            byte_count=38,
        )

        orch, audit_log = _make_orchestrator(decisions, router=mock_router)
        orch.investigate(_VALID_INPUT)

        for event in audit_log.events():
            self.assertNotIn(
                sensitive_payload,
                event.detail_code,
                msg=f"Sensitive payload must not appear in detail_code ({event.event_type})",
            )
            self.assertNotIn(
                "encoded_input",
                event.detail_code,
                msg=f"Argument keys must not appear in detail_code ({event.event_type})",
            )

    # -----------------------------------------------------------------------
    # Requirement 4: No raw exception messages appear in audit
    # -----------------------------------------------------------------------

    def test_no_raw_exception_messages_in_audit(self) -> None:
        """Proof: Raw exception strings never leak into audit detail_code."""
        secret_exception = "FATAL_CRASH_SECRET_POSTGRES_PASSWORD_xyz999"
        decisions = [
            ModelDecision(
                decision_type=DecisionType.TOOL_REQUEST,
                tool_request=ToolRequest(
                    tool_name="bounded_splunk_search",
                    arguments={
                        "query_type": "encoded_powershell_matches",
                        "host": "DC01",
                    },
                ),
            ),
            ModelDecision(
                decision_type=DecisionType.FINAL_RESULT,
                final_result=_FINAL_RESULT,
            ),
        ]
        mock_router = MagicMock(spec=ToolRouter)
        mock_router.execute_tool.side_effect = ToolExecutionError(secret_exception)

        orch, audit_log = _make_orchestrator(decisions, router=mock_router)
        orch.investigate(_VALID_INPUT)

        for event in audit_log.events():
            self.assertNotIn(
                secret_exception,
                event.detail_code,
                msg=f"Raw exception message must not leak into detail_code ({event.event_type})",
            )
            self.assertNotIn(
                "POSTGRES",
                event.detail_code,
            )

    # -----------------------------------------------------------------------
    # Requirement 5: Unknown/unallowlisted tool name is NOT interpolated into detail_code
    # -----------------------------------------------------------------------

    def test_unallowlisted_tool_name_not_interpolated_into_audit(self) -> None:
        """Proof: Arbitrary or malicious tool names are rejected and never interpolated into detail_code."""
        untrusted_names = [
            "untrusted_dangerous_tool",
            "eval_arbitrary_python",
            "X" * 100,
        ]

        for untrusted_tool in untrusted_names:
            with self.subTest(untrusted_tool=untrusted_tool):
                decisions = [
                    ModelDecision(
                        decision_type=DecisionType.TOOL_REQUEST,
                        tool_request=ToolRequest(
                            tool_name=untrusted_tool,
                            arguments={"any_arg": "value"},
                        ),
                    ),
                ]
                orch, audit_log = _make_orchestrator(decisions)

                with self.assertRaises(OrchestratorError):
                    orch.investigate(_VALID_INPUT)

                for event in audit_log.events():
                    self.assertNotIn(
                        untrusted_tool,
                        event.detail_code,
                        msg=f"Untrusted tool name '{untrusted_tool}' must not appear in detail_code ({event.event_type})",
                    )
                    self.assertLessEqual(
                        len(event.detail_code),
                        MAX_DETAIL_CODE_LENGTH,
                        msg=f"detail_code '{event.detail_code}' exceeds MAX_DETAIL_CODE_LENGTH",
                    )


if __name__ == "__main__":
    unittest.main()
