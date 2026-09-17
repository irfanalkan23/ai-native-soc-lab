"""Unit and integration tests for JsonlAuditWriter (Milestone 3C).

Covers:
  - Basic: Single event write, multiple events write, append-only preservation,
    valid JSON per line, allowlisted fields only, event_type serialized as string value,
    sequence and ordering preservation.
  - Validation: Reject dict, None, arbitrary object, str, non-iterable; exact-type
    rejection of AuditEvent subclasses; write_events atomicity (all-or-nothing validation);
    empty path rejection; directory path rejection.
  - Security: No __dict__ leakage, no raw model text/arguments/telemetry,
    no env secrets accessed, OPENAI_API_KEY never accessed, subprocess/shell not used.
  - Failure Handling: Sanitized AuditWriteError on I/O failure without OS error leakage.
  - Determinism: Stable sorted keys, compact separators, one line per record.
  - Integration: Offline end-to-end investigation with FakeModel + InvestigationOrchestrator
    persisted to JSONL and verified against in-memory AuditLog.
"""

import inspect
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from investigator.audit import AuditEvent, AuditEventType, AuditLog
from investigator.audit_writer import (
    DEFAULT_AUDIT_LOG_PATH,
    AuditPathError,
    AuditWriteError,
    AuditWriterError,
    JsonlAuditWriter,
)
from investigator.fake_model import FakeModel
from investigator.model import DecisionType, ModelDecision, ToolRequest
from investigator.orchestrator import InvestigationOrchestrator
from investigator.schemas import ConfidenceLevel, InvestigationInput, InvestigationResult
from investigator.tool_router import ToolRouter


class SubclassedAuditEvent(AuditEvent):
    """Subclass used to test exact-type enforcement."""
    pass


def _make_event(
    sequence: int = 0,
    event_type: AuditEventType = AuditEventType.MODEL_REQUESTED,
    incident_id: str = "INC-3C-TEST",
    detail_code: str = "ok",
) -> AuditEvent:
    return AuditEvent(
        event_type=event_type,
        incident_id=incident_id,
        sequence=sequence,
        detail_code=detail_code,
    )


class TestJsonlAuditWriterBasic(unittest.TestCase):
    """Basic persistence functionality tests."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.log_path = Path(self.temp_dir.name) / "test_audit.jsonl"
        self.writer = JsonlAuditWriter(self.log_path)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_valid_single_event_writes_one_line(self) -> None:
        event = _make_event(sequence=0, detail_code="step_0")
        self.writer.write_event(event)

        self.assertTrue(self.log_path.exists())
        lines = self.log_path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 1)

        record = json.loads(lines[0])
        self.assertEqual(record["sequence"], 0)
        self.assertEqual(record["event_type"], "MODEL_REQUESTED")
        self.assertEqual(record["incident_id"], "INC-3C-TEST")
        self.assertEqual(record["detail_code"], "step_0")

    def test_valid_multiple_events_write_multiple_lines(self) -> None:
        events = [
            _make_event(sequence=0, event_type=AuditEventType.MODEL_REQUESTED, detail_code="step_0"),
            _make_event(sequence=1, event_type=AuditEventType.TOOL_REQUESTED, detail_code="tool_req"),
            _make_event(sequence=2, event_type=AuditEventType.FINAL_RESULT_ACCEPTED, detail_code="ok"),
        ]
        self.writer.write_events(events)

        lines = self.log_path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 3)

        records = [json.loads(line) for line in lines]
        self.assertEqual([r["sequence"] for r in records], [0, 1, 2])
        self.assertEqual(
            [r["event_type"] for r in records],
            ["MODEL_REQUESTED", "TOOL_REQUESTED", "FINAL_RESULT_ACCEPTED"],
        )

    def test_append_preserves_existing_records(self) -> None:
        event1 = _make_event(sequence=0, detail_code="first")
        event2 = _make_event(sequence=1, detail_code="second")

        self.writer.write_event(event1)
        self.writer.write_event(event2)

        lines = self.log_path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 2)
        records = [json.loads(l) for l in lines]
        self.assertEqual(records[0]["detail_code"], "first")
        self.assertEqual(records[1]["detail_code"], "second")

    def test_output_is_valid_json_per_line(self) -> None:
        events = [_make_event(sequence=i) for i in range(5)]
        self.writer.write_events(events)

        lines = self.log_path.read_text(encoding="utf-8").splitlines()
        for idx, line in enumerate(lines):
            parsed = json.loads(line)
            self.assertIsInstance(parsed, dict)
            self.assertEqual(parsed["sequence"], idx)

    def test_output_uses_allowlisted_fields_only(self) -> None:
        event = _make_event(sequence=0)
        self.writer.write_event(event)

        line = self.log_path.read_text(encoding="utf-8").strip()
        record = json.loads(line)
        expected_keys = {"detail_code", "event_type", "incident_id", "sequence"}
        self.assertEqual(set(record.keys()), expected_keys)

    def test_event_type_serialized_as_string_value(self) -> None:
        for et in AuditEventType:
            temp_path = Path(self.temp_dir.name) / f"test_{et.value}.jsonl"
            writer = JsonlAuditWriter(temp_path)
            writer.write_event(_make_event(event_type=et))
            line = temp_path.read_text(encoding="utf-8").strip()
            record = json.loads(line)
            self.assertEqual(record["event_type"], et.value)
            self.assertIsInstance(record["event_type"], str)

    def test_sequence_order_preserved_exactly(self) -> None:
        # Deliberately non-sorted sequences to prove order matches input
        events = [
            _make_event(sequence=10, detail_code="ten"),
            _make_event(sequence=2, detail_code="two"),
            _make_event(sequence=42, detail_code="forty-two"),
        ]
        self.writer.write_events(events)

        lines = self.log_path.read_text(encoding="utf-8").splitlines()
        records = [json.loads(l) for l in lines]
        self.assertEqual([r["sequence"] for r in records], [10, 2, 42])
        self.assertEqual([r["detail_code"] for r in records], ["ten", "two", "forty-two"])

    def test_empty_iterable_in_write_events_is_noop(self) -> None:
        self.writer.write_events([])
        self.assertFalse(self.log_path.exists())


class TestJsonlAuditWriterValidation(unittest.TestCase):
    """Validation and type safety tests."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.log_path = Path(self.temp_dir.name) / "val_audit.jsonl"
        self.writer = JsonlAuditWriter(self.log_path)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_dict_rejected_fails_closed(self) -> None:
        with self.assertRaises(AuditWriterError) as ctx:
            self.writer.write_event({"sequence": 0, "event_type": "MODEL_REQUESTED"})  # type: ignore
        self.assertEqual(str(ctx.exception), "audit_invalid_event")

    def test_none_rejected_fails_closed(self) -> None:
        with self.assertRaises(AuditWriterError) as ctx:
            self.writer.write_event(None)  # type: ignore
        self.assertEqual(str(ctx.exception), "audit_invalid_event")

    def test_arbitrary_object_rejected_fails_closed(self) -> None:
        class Dummy:
            pass
        with self.assertRaises(AuditWriterError) as ctx:
            self.writer.write_event(Dummy())  # type: ignore
        self.assertEqual(str(ctx.exception), "audit_invalid_event")

    def test_string_rejected_fails_closed(self) -> None:
        with self.assertRaises(AuditWriterError) as ctx:
            self.writer.write_event('{"sequence": 0}')  # type: ignore
        self.assertEqual(str(ctx.exception), "audit_invalid_event")

    def test_subclass_of_audit_event_rejected_exact_type_check(self) -> None:
        """Regression test: type(event) is AuditEvent must reject subclasses."""
        subclassed = SubclassedAuditEvent(
            event_type=AuditEventType.MODEL_REQUESTED,
            incident_id="INC-3C",
            sequence=0,
            detail_code="subclass_attempt",
        )
        with self.assertRaises(AuditWriterError) as ctx:
            self.writer.write_event(subclassed)
        self.assertEqual(str(ctx.exception), "audit_invalid_event")

    def test_write_events_rejects_subclass_in_iterable(self) -> None:
        """Regression test: write_events must reject subclasses in batch."""
        events = [
            _make_event(sequence=0),
            SubclassedAuditEvent(
                event_type=AuditEventType.TOOL_REQUESTED,
                incident_id="INC-3C",
                sequence=1,
                detail_code="subclass",
            ),
        ]
        with self.assertRaises(AuditWriterError) as ctx:
            self.writer.write_events(events)
        self.assertEqual(str(ctx.exception), "audit_invalid_event")
        # Fail closed: nothing should have been written to file
        self.assertFalse(self.log_path.exists())

    def test_write_events_validates_all_before_writing_fails_closed(self) -> None:
        """Atomicity test: 2 valid items followed by 1 invalid must write nothing."""
        events = [
            _make_event(sequence=0),
            _make_event(sequence=1),
            {"invalid": "not_an_event"},  # type: ignore
        ]
        with self.assertRaises(AuditWriterError) as ctx:
            self.writer.write_events(events)
        self.assertEqual(str(ctx.exception), "audit_invalid_event")
        self.assertFalse(self.log_path.exists())

    def test_write_events_rejects_non_iterable(self) -> None:
        with self.assertRaises(AuditWriterError) as ctx:
            self.writer.write_events(None)  # type: ignore
        self.assertEqual(str(ctx.exception), "audit_invalid_event")

        with self.assertRaises(AuditWriterError) as ctx:
            self.writer.write_events(12345)  # type: ignore
        self.assertEqual(str(ctx.exception), "audit_invalid_event")

        with self.assertRaises(AuditWriterError) as ctx:
            self.writer.write_events("not_a_list")  # type: ignore
        self.assertEqual(str(ctx.exception), "audit_invalid_event")

    def test_empty_path_rejected(self) -> None:
        with self.assertRaises(AuditPathError) as ctx:
            JsonlAuditWriter("")
        self.assertEqual(str(ctx.exception), "audit_invalid_path")

        with self.assertRaises(AuditPathError) as ctx:
            JsonlAuditWriter("   ")
        self.assertEqual(str(ctx.exception), "audit_invalid_path")

    def test_directory_path_rejected(self) -> None:
        # Existing directory
        with self.assertRaises(AuditPathError) as ctx:
            JsonlAuditWriter(self.temp_dir.name)
        self.assertEqual(str(ctx.exception), "audit_invalid_path")

        # Path ending in trailing slash
        with self.assertRaises(AuditPathError) as ctx:
            JsonlAuditWriter("some/directory/path/")
        self.assertEqual(str(ctx.exception), "audit_invalid_path")

        with self.assertRaises(AuditPathError) as ctx:
            JsonlAuditWriter("some\\directory\\path\\")
        self.assertEqual(str(ctx.exception), "audit_invalid_path")

    def test_invalid_path_types_rejected(self) -> None:
        with self.assertRaises(AuditPathError) as ctx:
            JsonlAuditWriter(123)  # type: ignore
        self.assertEqual(str(ctx.exception), "audit_invalid_path")

        with self.assertRaises(AuditPathError) as ctx:
            JsonlAuditWriter(None)  # type: ignore
        self.assertEqual(str(ctx.exception), "audit_invalid_path")


class TestJsonlAuditWriterSecurity(unittest.TestCase):
    """Security boundary and isolation verification."""

    def test_no_dict_or_accidental_fields_serialized(self) -> None:
        temp_dir = tempfile.TemporaryDirectory()
        try:
            path = Path(temp_dir.name) / "sec.jsonl"
            writer = JsonlAuditWriter(path)
            event = _make_event(sequence=0)
            writer.write_event(event)

            line = path.read_text(encoding="utf-8").strip()
            record = json.loads(line)

            # AuditEvent has 4 approved fields
            self.assertEqual(len(record), 4)
            self.assertEqual(
                sorted(record.keys()),
                ["detail_code", "event_type", "incident_id", "sequence"],
            )
        finally:
            temp_dir.cleanup()

    def test_raw_model_text_or_telemetry_not_in_output(self) -> None:
        """Verify that only AuditEvent data enters the file."""
        temp_dir = tempfile.TemporaryDirectory()
        try:
            path = Path(temp_dir.name) / "sec_data.jsonl"
            writer = JsonlAuditWriter(path)
            event = _make_event(sequence=0, detail_code="ok")
            writer.write_event(event)

            raw_content = path.read_text(encoding="utf-8")
            # None of these raw indicators should appear
            self.assertNotIn("powershell", raw_content.lower())
            self.assertNotIn("encodedcommand", raw_content.lower())
            self.assertNotIn("select", raw_content.lower())
            self.assertNotIn("http", raw_content.lower())
        finally:
            temp_dir.cleanup()

    def test_openai_api_key_not_accessed_by_audit_writer(self) -> None:
        """Verify audit_writer module never accesses OPENAI_API_KEY."""
        import investigator.audit_writer as mod
        source = inspect.getsource(mod)
        self.assertNotIn("OPENAI_API_KEY", source)
        self.assertNotIn("OPENAI_MODEL", source)

    def test_subprocess_and_shell_not_imported_or_used(self) -> None:
        """Verify audit_writer does not import subprocess or shell execution."""
        import investigator.audit_writer as mod
        source = inspect.getsource(mod)
        self.assertNotIn("subprocess", source)
        self.assertNotIn("os.system", source)
        self.assertNotIn("os.popen", source)
        self.assertNotIn("import commands", source)

    def test_gateway_not_imported(self) -> None:
        """Verify audit_writer does not import gateway modules."""
        import investigator.audit_writer as mod
        source = inspect.getsource(mod)
        self.assertNotIn("gateway", source)


class TestJsonlAuditWriterFailureHandling(unittest.TestCase):
    """Failure handling and exception sanitization."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.log_path = Path(self.temp_dir.name) / "fail_audit.jsonl"
        self.writer = JsonlAuditWriter(self.log_path)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_open_failure_raises_sanitized_audit_write_error(self) -> None:
        event = _make_event()
        with patch.object(Path, "open", side_effect=OSError("OS Disk I/O Error: /secret/path/info")):
            with self.assertRaises(AuditWriteError) as ctx:
                self.writer.write_event(event)

        # Exception message must be static and sanitized
        self.assertEqual(str(ctx.exception), "audit_write_failed")
        # Underlying error details must not leak
        self.assertNotIn("secret", str(ctx.exception))
        self.assertNotIn("Disk", str(ctx.exception))

    def test_batch_open_failure_raises_sanitized_audit_write_error(self) -> None:
        events = [_make_event(sequence=i) for i in range(2)]
        with patch.object(Path, "open", side_effect=OSError("Permission denied")):
            with self.assertRaises(AuditWriteError) as ctx:
                self.writer.write_events(events)

        self.assertEqual(str(ctx.exception), "audit_write_failed")
        self.assertNotIn("Permission", str(ctx.exception))


class TestJsonlAuditWriterDeterminism(unittest.TestCase):
    """Determinism and formatting tests."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.log_path = Path(self.temp_dir.name) / "det_audit.jsonl"
        self.writer = JsonlAuditWriter(self.log_path)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_stable_sorted_keys_compact_separators(self) -> None:
        event = AuditEvent(
            event_type=AuditEventType.MODEL_REQUESTED,
            incident_id="INC-DET",
            sequence=1,
            detail_code="test_code",
        )
        self.writer.write_event(event)

        line = self.log_path.read_text(encoding="utf-8").strip()
        expected = '{"detail_code":"test_code","event_type":"MODEL_REQUESTED","incident_id":"INC-DET","sequence":1}'
        self.assertEqual(line, expected)


class TestJsonlAuditWriterIntegration(unittest.TestCase):
    """Offline integration test with FakeModel + InvestigationOrchestrator."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.log_path = Path(self.temp_dir.name) / "integ_audit.jsonl"
        self.writer = JsonlAuditWriter(self.log_path)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_end_to_end_orchestration_audit_persistence(self) -> None:
        """Run benign investigation with FakeModel, persist audit, verify 1-to-1 match."""
        # 1. Setup deterministic FakeModel
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

        # 2. Run orchestrator
        router = ToolRouter()
        audit_log = AuditLog()
        orchestrator = InvestigationOrchestrator(
            model=fake_model,
            tool_router=router,
            audit_log=audit_log,
        )

        input_data = InvestigationInput(
            incident_id="INC-3C-INTEG",
            timestamp="2026-09-17T08:00:00Z",
            host="DC01",
            user="SOCLAB\\Administrator",
            image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            command_line="powershell.exe -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAA=",
            parent_image="C:\\Windows\\System32\\cmd.exe",
            parent_command_line="cmd.exe",
            detection_name="Suspicious Encoded PowerShell",
            detection_id="DET-001",
        )

        result = orchestrator.investigate(input_data)
        self.assertEqual(result.confidence_level, ConfidenceLevel.LOW.value)
        self.assertEqual(result.summary, "All evidence indicates controlled benign testing.")

        # 3. Persist audit events using JsonlAuditWriter
        in_memory_events = audit_log.events()
        self.assertGreater(len(in_memory_events), 0)
        self.writer.write_events(in_memory_events)

        # 4. Reopen JSONL file and verify every line matches in-memory AuditEvent
        self.assertTrue(self.log_path.exists())
        lines = self.log_path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), len(in_memory_events))

        for idx, (line, event) in enumerate(zip(lines, in_memory_events)):
            record = json.loads(line)
            self.assertEqual(record["sequence"], event.sequence)
            self.assertEqual(record["event_type"], event.event_type.value)
            self.assertEqual(record["incident_id"], event.incident_id)
            self.assertEqual(record["detail_code"], event.detail_code)
            self.assertEqual(record["sequence"], idx)


if __name__ == "__main__":
    unittest.main()
