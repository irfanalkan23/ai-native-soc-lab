"""Tests for AuditEvent schema immutability and tool-aware detail-code constraints (Milestone 8K).

Verifies:
1. AuditEvent schema remains strictly unchanged:
   (event_type, incident_id, sequence, detail_code).
2. Existing audit writer schema remains exactly unchanged:
   only allowlisted fields persisted, exact 4 keys in JSON output.
3. All static tool-aware detail codes for allowlisted tools satisfy
   MAX_DETAIL_CODE_LENGTH and contain no control characters or newlines.
"""

import json
import tempfile
import unittest
from dataclasses import fields
from pathlib import Path

from investigator.audit import (
    AuditEvent,
    AuditEventType,
    AuditLog,
    MAX_DETAIL_CODE_LENGTH,
)
from investigator.audit_writer import (
    JsonlAuditWriter,
    _ALLOWLISTED_FIELDS,
)
from investigator.tool_router import ALLOWED_TOOLS


class TestAuditSchemaUnchanged(unittest.TestCase):
    """Verify AuditEvent and JsonlAuditWriter schema stability."""

    def test_audit_event_fields_strictly_unchanged(self) -> None:
        """Proof: AuditEvent dataclass schema has exactly the 4 required fields."""
        field_names = tuple(f.name for f in fields(AuditEvent))
        expected_fields = ("event_type", "incident_id", "sequence", "detail_code")
        self.assertEqual(
            field_names,
            expected_fields,
            msg="AuditEvent schema must not be modified or extended with new fields.",
        )

    def test_audit_event_is_frozen(self) -> None:
        """Proof: AuditEvent is immutable once instantiated."""
        event = AuditEvent(
            event_type=AuditEventType.TOOL_REQUESTED,
            incident_id="INC-TEST-001",
            sequence=0,
            detail_code="tool_requested",
        )
        with self.assertRaises(Exception):
            event.detail_code = "modified"  # type: ignore[misc]

    def test_audit_writer_allowlisted_fields_unchanged(self) -> None:
        """Proof: JsonlAuditWriter field allowlist has exactly the 4 expected fields."""
        self.assertEqual(
            sorted(_ALLOWLISTED_FIELDS),
            ["detail_code", "event_type", "incident_id", "sequence"],
            msg="JsonlAuditWriter field allowlist must remain strictly unchanged.",
        )

    def test_audit_writer_output_keys_exactly_match_schema(self) -> None:
        """Proof: Serialized JSON line contains only sequence, event_type, incident_id, detail_code."""
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "test_audit.jsonl"
            writer = JsonlAuditWriter(log_path)
            event = AuditEvent(
                event_type=AuditEventType.TOOL_COMPLETED,
                incident_id="INC-TEST-001",
                sequence=1,
                detail_code="decode_base64_powershell_ok",
            )
            writer.write_event(event)

            lines = log_path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 1)
            record = json.loads(lines[0])
            self.assertEqual(
                sorted(record.keys()),
                ["detail_code", "event_type", "incident_id", "sequence"],
                msg="Serialized audit record must contain exactly the 4 allowlisted keys.",
            )
            self.assertEqual(record["detail_code"], "decode_base64_powershell_ok")


class TestToolAwareDetailCodeConstraints(unittest.TestCase):
    """Verify that all proposed tool-aware detail codes satisfy AuditEvent validation rules."""

    def test_all_allowlisted_tool_detail_codes_fit_bounds(self) -> None:
        """Proof: All tool-aware detail codes fit within MAX_DETAIL_CODE_LENGTH."""
        suffixes = (
            "_requested",
            "_allowed",
            "_ok",
            "_execution_failed",
            "_result_too_large",
        )
        self.assertEqual(
            ALLOWED_TOOLS,
            frozenset({
                "bounded_splunk_search",
                "decode_base64_powershell",
                "map_mitre_technique",
                "threat_intel_lookup",
            }),
        )

        for tool_name in ALLOWED_TOOLS:
            for suffix in suffixes:
                detail_code = f"{tool_name}{suffix}"
                self.assertLessEqual(
                    len(detail_code),
                    MAX_DETAIL_CODE_LENGTH,
                    msg=f"Detail code '{detail_code}' exceeds MAX_DETAIL_CODE_LENGTH ({MAX_DETAIL_CODE_LENGTH})",
                )
                self.assertFalse(
                    any(ord(c) < 32 for c in detail_code),
                    msg=f"Detail code '{detail_code}' contains control characters",
                )
                # Ensure it instantiates a valid AuditEvent without error
                event = AuditEvent(
                    event_type=AuditEventType.TOOL_COMPLETED,
                    incident_id="INC-TEST-001",
                    sequence=0,
                    detail_code=detail_code,
                )
                self.assertEqual(event.detail_code, detail_code)


if __name__ == "__main__":
    unittest.main()
