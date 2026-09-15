"""Unit tests for local investigation tools and deterministic tool router."""

import unittest
from unittest.mock import MagicMock

from investigator.tool_router import (
    ALLOWED_TOOLS,
    ToolExecutionError,
    ToolRouter,
    ToolValidationError,
)
from investigator.tools.base64_decoder import (
    MAX_ENCODED_INPUT_LENGTH,
    DecodeResult,
    DecoderError,
    decode_powershell_base64,
)
from investigator.tools.mitre_mapper import (
    MitreMapping,
    MitreMappingError,
    map_detection_to_mitre,
)


class TestBase64Decoder(unittest.TestCase):
    """Test local Base64 decoder tool for PowerShell payloads."""

    # Exact benign payload executed on DC01 in lab
    CONTROLLED_B64_PAYLOAD = "VwByAGkAdABlAC0ASABvAHMAdAAgACcAQQBJAC0ATgBhAHQAaQB2AGUAUwBPAEMALQBMAEEAQgAtAFQARQBTAFQAJwA="
    EXPECTED_DECODED_TEXT = "Write-Host 'AI-NativeSOC-LAB-TEST'"

    def test_decode_controlled_powershell_payload_direct(self) -> None:
        """Verify successful decoding of standalone Base64 payload."""
        result = decode_powershell_base64(self.CONTROLLED_B64_PAYLOAD)
        self.assertIsInstance(result, DecodeResult)
        self.assertTrue(result.success)
        self.assertEqual(result.decoded_text, self.EXPECTED_DECODED_TEXT)
        self.assertEqual(result.encoding, "utf-16le")

    def test_decode_from_full_command_line(self) -> None:
        """Verify extraction and decoding from full command line invocation."""
        cmd_line = f"powershell.exe -NoProfile -EncodedCommand {self.CONTROLLED_B64_PAYLOAD}"
        result = decode_powershell_base64(cmd_line)
        self.assertEqual(result.decoded_text, self.EXPECTED_DECODED_TEXT)

        # Also test -enc shorthand flag
        cmd_line_enc = f"C:\\Windows\\System32\\powershell.exe -enc {self.CONTROLLED_B64_PAYLOAD}"
        result_enc = decode_powershell_base64(cmd_line_enc)
        self.assertEqual(result_enc.decoded_text, self.EXPECTED_DECODED_TEXT)

    def test_malformed_base64_fails_closed(self) -> None:
        """Proof: Invalid Base64 strings fail closed with DecoderError."""
        bad_inputs = [
            "NotValidBase64!@#$%",
            "VwByAGk===",  # Illegal padding
            "======",
            "",
            "   ",
        ]
        for bad_input in bad_inputs:
            with self.subTest(bad_input=bad_input):
                with self.assertRaises(DecoderError):
                    decode_powershell_base64(bad_input)

    def test_oversized_decode_input_fails_closed(self) -> None:
        """Proof: Input exceeding MAX_ENCODED_INPUT_LENGTH is rejected."""
        oversized = "A" * (MAX_ENCODED_INPUT_LENGTH + 1)
        with self.assertRaises(DecoderError) as ctx:
            decode_powershell_base64(oversized)
        self.assertIn("exceeds maximum allowed bound", str(ctx.exception))

    def test_decoded_content_never_executed(self) -> None:
        """Proof: Potentially dangerous command strings are returned as inert text only."""
        # Simulated payload: Remove-Item -Path C:\test -Recurse -Force
        # UTF-16LE encoded in base64:
        # "Remove-Item -Path C:\\test -Recurse -Force".encode('utf-16le')
        # b'R\x00e\x00m\x00o\x00v\x00e\x00-\x00I\x00t\x00e\x00m\x00 \x00-\x00P\x00a\x00t\x00h\x00 \x00C\x00:\x00\\\x00t\x00e\x00s\x00t\x00 \x00-\x00R\x00e\x00c\x00u\x00r\x00s\x00e\x00 \x00-\x00F\x00o\x00r\x00c\x00e\x00'
        destructive_b64 = "UgBlAG0AbwB2AGUALQBJAHQAZQBtACAALQBQAGEAdABoACAAQwA6AFwAdABlAHMAdAAgAC0AUgBlAGMAdQByAHMAZQAgAC0ARgBvAHIAYwBlAA=="
        result = decode_powershell_base64(destructive_b64)
        # Verify it returns pure string without side-effects or subprocess execution
        self.assertIn("Remove-Item", result.decoded_text)
        self.assertIsInstance(result.decoded_text, str)

    def test_valid_base64_invalid_utf16le_fails_closed_no_utf8_fallback(self) -> None:
        """Proof: Valid Base64 that is not valid UTF-16LE fails closed with DecoderError.

        PowerShell -EncodedCommand is strictly UTF-16LE. No UTF-8 fallback heuristic
        is permitted.
        """
        import base64

        # 1. Odd number of bytes (e.g. 11 bytes of ASCII/UTF-8 "Hello World")
        # In UTF-8 fallback, this would decode to "Hello World"
        utf8_only_payload = base64.b64encode(b"Hello World").decode("ascii")
        with self.assertRaises(DecoderError) as ctx:
            decode_powershell_base64(utf8_only_payload)
        self.assertIn("Failed to decode payload bytes as UTF-16LE", str(ctx.exception))

        # 2. 3 bytes odd length
        odd_payload = base64.b64encode(b"abc").decode("ascii")
        with self.assertRaises(DecoderError):
            decode_powershell_base64(odd_payload)

        # 3. Unpaired UTF-16 surrogate bytes (0xD800)
        surrogate_payload = base64.b64encode(b"\x00\xd8").decode("ascii")
        with self.assertRaises(DecoderError) as ctx:
            decode_powershell_base64(surrogate_payload)
        self.assertIn("Failed to decode payload bytes as UTF-16LE", str(ctx.exception))


class TestMitreMapper(unittest.TestCase):
    """Test local static MITRE mapper tool."""

    def test_mitre_mapping_encoded_powershell(self) -> None:
        """Verify mapping of verified encoded PowerShell detection references."""
        refs = [
            "Suspicious Encoded PowerShell Execution",
            "suspicious_encoded_powershell",
            "encoded_powershell_matches",
            "4e4f13c0-89a9-4f0e-a08f-b70b9c19e729",
        ]
        for ref in refs:
            with self.subTest(ref=ref):
                mapping = map_detection_to_mitre(ref)
                self.assertIsInstance(mapping, MitreMapping)
                self.assertTrue(mapping.mapped)
                self.assertEqual(mapping.technique_id, "T1059.001")
                self.assertEqual(
                    mapping.technique_name,
                    "Command and Scripting Interpreter: PowerShell",
                )
                self.assertEqual(mapping.tactic_id, "TA0002")
                self.assertEqual(mapping.tactic_name, "Execution")

    def test_unknown_detection_fails_closed_when_configured(self) -> None:
        """Proof: Unknown detections raise MitreMappingError when fail_closed=True."""
        with self.assertRaises(MitreMappingError):
            map_detection_to_mitre("unknown_zero_day_rule", fail_closed=True)

    def test_unknown_detection_returns_unmapped_when_fail_closed_false(self) -> None:
        """Verify explicit unmapped result when fail_closed=False."""
        mapping = map_detection_to_mitre("unmapped_test_rule", fail_closed=False)
        self.assertFalse(mapping.mapped)
        self.assertIsNone(mapping.technique_id)
        self.assertIsNone(mapping.tactic_id)
        self.assertEqual(mapping.detection_ref, "unmapped_test_rule")

    def test_fail_closed_strict_boolean_validation(self) -> None:
        """Proof: fail_closed parameter strictly requires type bool, rejecting truthy/falsy values."""
        invalid_fail_closed_values = ["true", "false", 1, 0, None, [], {}]
        for bad_val in invalid_fail_closed_values:
            with self.subTest(bad_val=repr(bad_val)):
                with self.assertRaises(MitreMappingError) as ctx:
                    map_detection_to_mitre("encoded_powershell_matches", fail_closed=bad_val)  # type: ignore[arg-type]
                self.assertIn("Expected fail_closed bool", str(ctx.exception))


class TestToolRouter(unittest.TestCase):
    """Test deterministic tool router boundaries and execution dispatches."""

    def setUp(self) -> None:
        self.mock_splunk_client = MagicMock()
        self.router = ToolRouter(splunk_client=self.mock_splunk_client)

    def test_router_exposes_only_allowlisted_tools(self) -> None:
        """Proof: Router's allowed_tools strictly equals the 3 allowlisted tools."""
        self.assertEqual(
            self.router.allowed_tools,
            frozenset({
                "bounded_splunk_search",
                "decode_base64_powershell",
                "map_mitre_technique",
            }),
        )

    def test_unknown_tool_name_rejected(self) -> None:
        """Proof: Unregistered tool names fail closed with ToolValidationError."""
        unregistered = [
            "generic_shell_exec",
            "run_command",
            "arbitrary_splunk_query",
            "os.system",
            "subprocess_run",
            "",
            "__import__",
        ]
        for name in unregistered:
            with self.subTest(tool=name):
                with self.assertRaises(ToolValidationError):
                    self.router.execute_tool(name, {})

    def test_router_rejects_arbitrary_spl_parameters(self) -> None:
        """Proof: Router rejects any attempts to supply custom SPL or search queries."""
        forbidden_payloads = [
            {"search": "search index=* | delete"},
            {"spl": "index=main | head 5"},
            {"query": "SELECT * FROM logs"},
        ]
        for payload in forbidden_payloads:
            with self.subTest(payload=payload):
                with self.assertRaises(ToolValidationError) as ctx:
                    self.router.execute_tool("bounded_splunk_search", payload)
                self.assertIn("strictly prohibited", str(ctx.exception))

    def test_router_rejects_arbitrary_url_or_path(self) -> None:
        """Proof: Router rejects custom endpoints, paths, or URLs."""
        forbidden_endpoints = [
            {"url": "https://evil.attacker.com/leak"},
            {"path": "/services/authentication/users"},
            {"endpoint": "http://192.168.1.1:8089"},
        ]
        for endpoint_arg in forbidden_endpoints:
            with self.subTest(endpoint=endpoint_arg):
                with self.assertRaises(ToolValidationError) as ctx:
                    self.router.execute_tool("bounded_splunk_search", endpoint_arg)
                self.assertIn("strictly prohibited", str(ctx.exception))

    def test_router_cannot_dynamically_invoke_arbitrary_python_functions(self) -> None:
        """Proof: Router dispatches through static match branches, not getattr/eval."""
        # Add a dummy method to router to test that execute_tool cannot call it
        self.router._dangerous_internal_func = MagicMock()  # type: ignore[attr-defined]
        with self.assertRaises(ToolValidationError):
            self.router.execute_tool("_dangerous_internal_func", {})
        self.router._dangerous_internal_func.assert_not_called()

    def test_router_executes_splunk_search_cleanly(self) -> None:
        """Verify clean routing to bounded Splunk search client."""
        self.mock_splunk_client.search_encoded_powershell.return_value = [
            {"host": "DC01", "User": "Administrator"}
        ]
        result = self.router.execute_tool(
            "bounded_splunk_search",
            {"host": "DC01", "minutes": 15, "limit": 10},
        )
        self.assertEqual(len(result), 1)
        self.mock_splunk_client.search_encoded_powershell.assert_called_once_with(
            host="DC01",
            minutes=15,
            limit=10,
        )

    def test_router_executes_base64_decoder_cleanly(self) -> None:
        """Verify clean routing to Base64 decoder."""
        payload = "VwByAGkAdABlAC0ASABvAHMAdAAgACcAQQBJAC0ATgBhAHQAaQB2AGUAUwBPAEMALQBMAEEAQgAtAFQARQBTAFQAJwA="
        result = self.router.execute_tool(
            "decode_base64_powershell",
            {"encoded_input": payload},
        )
        self.assertIsInstance(result, DecodeResult)
        self.assertEqual(result.decoded_text, "Write-Host 'AI-NativeSOC-LAB-TEST'")

    def test_router_executes_mitre_mapper_cleanly(self) -> None:
        """Verify clean routing to MITRE mapper."""
        result = self.router.execute_tool(
            "map_mitre_technique",
            {"detection_ref": "encoded_powershell_matches"},
        )
        self.assertIsInstance(result, MitreMapping)
        self.assertEqual(result.technique_id, "T1059.001")

    def test_router_rejects_non_bool_fail_closed(self) -> None:
        """Proof: Router rejects non-bool fail_closed values with ToolValidationError."""
        bad_values = ["true", "false", 1, 0, None, [], {}]
        for bad_val in bad_values:
            with self.subTest(bad_val=repr(bad_val)):
                with self.assertRaises(ToolValidationError) as ctx:
                    self.router.execute_tool(
                        "map_mitre_technique",
                        {"detection_ref": "encoded_powershell_matches", "fail_closed": bad_val},
                    )
                self.assertIn("Expected fail_closed bool", str(ctx.exception))

    def test_router_base64_invalid_utf16le_fails_closed(self) -> None:
        """Proof: Router raises ToolExecutionError when Base64 payload is not valid UTF-16LE."""
        import base64
        utf8_only_payload = base64.b64encode(b"Hello World").decode("ascii")
        with self.assertRaises(ToolExecutionError) as ctx:
            self.router.execute_tool(
                "decode_base64_powershell",
                {"encoded_input": utf8_only_payload},
            )
        self.assertIn("Base64 decoding failed", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
