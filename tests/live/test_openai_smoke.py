"""Live smoke tests for the OpenAI provider adapter.

NOT part of the default offline test suite.
Run explicitly only when OPENAI_API_KEY and OPENAI_MODEL are set
in the environment and you want to verify live connectivity.

Usage:
    python -m pytest tests/live/test_openai_smoke.py -v
    # or
    python tests/live/test_openai_smoke.py

Each test skips automatically if environment variables are absent.

Cost control:
  These tests make minimal real API calls. Do not run in loops or CI
  without explicit intent and a capped billing alert in place.

Security:
  - API key is read from os.environ only.
  - API key is never printed, logged, or included in assertions.
  - Raw response headers and bodies are never printed.
"""

import json
import os
import sys
import unittest

# -----------------------------------------------------------------------
# Skip sentinel — evaluated once at import time
# -----------------------------------------------------------------------

_SKIP_REASON = None
_API_KEY = os.environ.get("OPENAI_API_KEY", "")
_MODEL_NAME = os.environ.get("OPENAI_MODEL", "")

if not _API_KEY or not _API_KEY.strip():
    _SKIP_REASON = "OPENAI_API_KEY environment variable is not set"
elif not _MODEL_NAME or not _MODEL_NAME.strip():
    _SKIP_REASON = "OPENAI_MODEL environment variable is not set"


def _skip_if_no_credentials(test_func):
    """Decorator: skip test cleanly if live credentials are absent."""
    if _SKIP_REASON:
        return unittest.skip(_SKIP_REASON)(test_func)
    return test_func


# -----------------------------------------------------------------------
# Fixtures
# -----------------------------------------------------------------------

from investigator.model import (
    INVESTIGATOR_SYSTEM_INSTRUCTIONS,
    ModelDecision,
    ModelRequest,
)
from investigator.schemas import InvestigationInput, InvestigationResult
from investigator.providers.openai_provider import (
    OpenAIModel,
    OpenAIRequestError,
    OpenAIResponseError,
)


_SMOKE_INPUT = InvestigationInput(
    incident_id="INC-SMOKE-001",
    timestamp="2026-09-16T10:00:00Z",
    host="DC01",
    user="SOCLAB\\Administrator",
    image="powershell.exe",
    command_line=(
        "powershell.exe -NoProfile -NonInteractive "
        "-EncodedCommand dABlAHMAdAA="
    ),
    parent_image="cmd.exe",
    parent_command_line="cmd.exe /c powershell",
    detection_name="Suspicious Encoded PowerShell - Smoke Test",
    detection_id="det-smoke-001",
)

_SMOKE_REQUEST = ModelRequest(
    system_instructions=INVESTIGATOR_SYSTEM_INSTRUCTIONS,
    investigation_input=_SMOKE_INPUT,
    prior_tool_results=(),
    remaining_tool_budget=3,
)


# -----------------------------------------------------------------------
# Tests
# -----------------------------------------------------------------------

class TestOpenAIConnectivitySmoke(unittest.TestCase):
    """Minimal live smoke tests — skipped automatically without credentials."""

    @_skip_if_no_credentials
    def test_api_connectivity_and_model_decision_returned(self) -> None:
        """Verify live Responses API connectivity and a valid ModelDecision response.

        Records:
          - configured model name (no key value)
          - decision type returned
          - no raw headers or response body printed
        """
        print(f"\n[smoke] Configured model: {_MODEL_NAME}")
        print(f"[smoke] API key present: YES (value not printed)")

        model = OpenAIModel()

        try:
            decision = model.decide(_SMOKE_REQUEST)
        except OpenAIRequestError as exc:
            self.fail(f"Live API call failed with sanitized error: {exc}")
        except OpenAIResponseError as exc:
            self.fail(f"Provider returned unparseable response: {exc}")

        self.assertIsInstance(decision, ModelDecision)
        print(f"[smoke] Decision type returned: {decision.decision_type}")

        if decision.decision_type.value == "tool_request":
            print(f"[smoke] Tool requested: {decision.tool_request.tool_name}")
            print(f"[smoke] Arguments: {dict(decision.tool_request.arguments)}")
        elif decision.decision_type.value == "final_result":
            print(f"[smoke] Confidence: {decision.final_result.confidence_level}")
            print(f"[smoke] Summary (first 120 chars): {decision.final_result.summary[:120]}")

        print("[smoke] PASS: live connectivity confirmed")


class TestOpenAILiveOrchestration(unittest.TestCase):
    """Live orchestrated investigation test — skipped without credentials.

    Uses FakeModel path through ToolRouter for decode_base64_powershell and
    map_mitre_technique (no Splunk required), then calls the live OpenAI model
    for the investigation loop.
    """

    @_skip_if_no_credentials
    def test_live_orchestrated_investigation_no_splunk(self) -> None:
        """Run a live investigation using real local tools and a live OpenAI model.

        Splunk connectivity:
          bounded_splunk_search is served by a MagicMock returning an empty list [].
          This is NOT a test of real Splunk connectivity.
          The mock means bounded_splunk_search always succeeds and returns no events.

        Real local tools used:
          decode_base64_powershell — real local UTF-16LE decoder
          map_mitre_technique      — real local MITRE mapper

        If the model requests map_mitre_technique with an unrecognised detection_ref
        and fail_closed=True (the default), the real mapper raises MitreMappingError,
        which ToolRouter converts to ToolExecutionError → audit TOOL_COMPLETED:execution_failed.
        This is correct fail-closed behaviour from a real local tool, not Splunk.
        """
        from investigator.audit import AuditLog, AuditEventType
        from investigator.orchestrator import InvestigationOrchestrator
        from investigator.tool_router import ToolRouter
        from unittest.mock import MagicMock

        # bounded_splunk_search is MOCKED — not a real Splunk connection.
        # The mock always succeeds and returns an empty event list.
        mock_splunk = MagicMock()
        mock_splunk.search_encoded_powershell.return_value = []

        router = ToolRouter(splunk_client=mock_splunk)
        audit_log = AuditLog()
        live_model = OpenAIModel()

        print(f"\n[live-orch] Model: {_MODEL_NAME}")
        print(f"[live-orch] Starting orchestrated investigation for {_SMOKE_INPUT.incident_id}")
        print(f"[live-orch] NOTE: bounded_splunk_search is MOCKED (returns empty list)")

        result = None
        try:
            result = InvestigationOrchestrator(
                model=live_model,
                tool_router=router,
                audit_log=audit_log,
            ).investigate(_SMOKE_INPUT)
        except Exception as exc:
            self.fail(
                f"Live orchestrated investigation failed: {type(exc).__name__}: {exc}"
            )

        self.assertIsInstance(result, InvestigationResult)
        print(f"[live-orch] Confidence: {result.confidence_level}")
        print(f"[live-orch] Summary (first 150 chars): {result.summary[:150]}")

        # Print sanitized audit event sequence.
        # TOOL_COMPLETED:execution_failed events arise from real local tools
        # (decode_base64_powershell or map_mitre_technique) failing for
        # content/argument reasons, NOT from Splunk unavailability.
        events = audit_log.events()
        splunk_mock_calls = mock_splunk.search_encoded_powershell.call_count
        print(f"\n[live-orch] bounded_splunk_search mock call count: {splunk_mock_calls}")
        print(f"[live-orch] Sanitized audit trail ({len(events)} events):")
        for evt in events:
            print(
                f"  seq={evt.sequence:02d}  {evt.event_type.value:<28}  {evt.detail_code}"
            )

        print("[live-orch] PASS: live orchestrated investigation complete")


if __name__ == "__main__":
    unittest.main(verbosity=2)
