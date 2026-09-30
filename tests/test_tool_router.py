"""Adversarial regression tests for ToolRouter SPL injection and query-type abuse prevention (Milestone 9B)."""

import unittest
from unittest.mock import MagicMock

from investigator.providers.virustotal_provider import (
    VirusTotalResponseError,
    VirusTotalThreatIntelClient,
    VirusTotalTransportError,
)
from investigator.threat_intel import (
    ThreatIntelLookupStatus,
    ThreatIntelObservation,
    ThreatIntelRequest,
    ThreatIntelResult,
)
from investigator.tool_router import (
    ALLOWED_SPLUNK_QUERY_TYPES,
    ALLOWED_TOOLS,
    ToolExecutionError,
    ToolRouter,
    ToolValidationError,
)


class TestToolRouterSplInjectionDefense(unittest.TestCase):
    """Prove that ToolRouter prevents bounded_splunk_search from becoming an arbitrary SPL primitive."""

    def setUp(self) -> None:
        self.mock_splunk = MagicMock()
        self.router = ToolRouter(splunk_client=self.mock_splunk)

    def test_invalid_query_type_values_fail_closed(self) -> None:
        """1. Invalid query_type values are rejected before Splunk execution with zero calls."""
        invalid_query_types = [
            "index=*",
            "search index=*",
            "search index=* | delete",
            "powershell_network_retrieval_matches | stats count",
        ]
        for bad_query_type in invalid_query_types:
            with self.subTest(query_type=bad_query_type):
                self.mock_splunk.reset_mock()
                with self.assertRaises(ToolValidationError) as ctx:
                    self.router.execute_tool(
                        "bounded_splunk_search",
                        {
                            "query_type": bad_query_type,
                            "host": "DC01",
                            "minutes": 15,
                            "limit": 10,
                        },
                    )
                self.assertIn("Unauthorized query_type", str(ctx.exception))
                self.mock_splunk.search_encoded_powershell.assert_not_called()
                self.mock_splunk.search_powershell_network_retrieval.assert_not_called()
                self.assertEqual(self.mock_splunk.method_calls, [])

    def test_forbidden_additional_arguments_fail_closed(self) -> None:
        """2. Forbidden additional arguments are rejected as invalid tool requests with zero calls."""
        forbidden_payloads = [
            {"query": "search index=*"},
            {"spl": "search index=*"},
            {"search": "index=*"},
            {"url": "https://example.com"},
            {"index": "*"},
        ]
        for payload in forbidden_payloads:
            with self.subTest(forbidden_payload=payload):
                self.mock_splunk.reset_mock()
                full_args = {
                    "host": "DC01",
                    "minutes": 15,
                    "limit": 10,
                    **payload,
                }
                with self.assertRaises(ToolValidationError):
                    self.router.execute_tool("bounded_splunk_search", full_args)
                self.mock_splunk.search_encoded_powershell.assert_not_called()
                self.mock_splunk.search_powershell_network_retrieval.assert_not_called()
                self.assertEqual(self.mock_splunk.method_calls, [])

    def test_valid_query_type_control_cases_dispatch_only_to_fixed_methods(self) -> None:
        """3. Valid query_type control cases pass validation and dispatch only to fixed gateway methods."""
        # 3a. encoded_powershell_matches -> search_encoded_powershell
        self.mock_splunk.reset_mock()
        self.mock_splunk.search_encoded_powershell.return_value = [{"event": "encoded"}]
        result_encoded = self.router.execute_tool(
            "bounded_splunk_search",
            {
                "query_type": "encoded_powershell_matches",
                "host": "DC01",
                "minutes": 15,
                "limit": 10,
            },
        )
        self.mock_splunk.search_encoded_powershell.assert_called_once_with(
            host="DC01",
            minutes=15,
            limit=10,
        )
        self.mock_splunk.search_powershell_network_retrieval.assert_not_called()
        self.assertEqual(result_encoded, [{"event": "encoded"}])

        # 3b. powershell_network_retrieval_matches -> search_powershell_network_retrieval
        self.mock_splunk.reset_mock()
        self.mock_splunk.search_powershell_network_retrieval.return_value = [{"event": "retrieval"}]
        result_retrieval = self.router.execute_tool(
            "bounded_splunk_search",
            {
                "query_type": "powershell_network_retrieval_matches",
                "host": "DC01",
                "minutes": 30,
                "limit": 5,
            },
        )
        self.mock_splunk.search_powershell_network_retrieval.assert_called_once_with(
            host="DC01",
            minutes=30,
            limit=5,
        )
        self.mock_splunk.search_encoded_powershell.assert_not_called()
        self.assertEqual(result_retrieval, [{"event": "retrieval"}])


class TestToolRouterArgumentSmugglingAndTypeConfusion(unittest.TestCase):
    """Milestone 9C: Prove malformed or type-confused arguments fail closed without execution."""

    def setUp(self) -> None:
        from gateway.splunk_search import SplunkSearchClient
        self.mock_splunk = SplunkSearchClient()
        self.mock_splunk._execute_bounded_search = MagicMock(return_value=[])
        self.router = ToolRouter(splunk_client=self.mock_splunk)

    def test_bounded_splunk_search_type_confusion(self) -> None:
        """1. bounded_splunk_search type confusion fails closed before gateway execution."""
        invalid_cases = [
            ("host", ["DC01"]),
            ("host", {"value": "DC01"}),
            ("minutes", "60"),
            ("minutes", 1.5),
            ("minutes", True),
            ("limit", "5"),
            ("limit", 5.0),
            ("limit", False),
            ("query_type", None),
            ("query_type", 123),
            ("query_type", ["encoded_powershell_matches"]),
        ]
        for field, bad_val in invalid_cases:
            with self.subTest(field=field, bad_val=bad_val):
                self.mock_splunk._execute_bounded_search.reset_mock()
                args = {"host": "DC01", "minutes": 15, "limit": 10}
                args[field] = bad_val
                with self.assertRaises(ToolValidationError):
                    self.router.execute_tool("bounded_splunk_search", args)
                self.mock_splunk._execute_bounded_search.assert_not_called()

    def test_map_mitre_technique_type_confusion(self) -> None:
        """2. map_mitre_technique type confusion fails closed with no truthy/falsy coercion."""
        # fail_closed type confusion (rejected by router argument validation)
        invalid_fail_closed = [
            "false",
            0,
            None,
            {"value": False},
        ]
        for bad_fc in invalid_fail_closed:
            with self.subTest(fail_closed=bad_fc):
                with self.assertRaises(ToolValidationError):
                    self.router.execute_tool(
                        "map_mitre_technique",
                        {
                            "detection_ref": "suspicious_powershell_network_retrieval",
                            "fail_closed": bad_fc,
                        },
                    )

        # detection_ref non-string type confusion (fails closed before database lookup)
        from investigator.tools.mitre_mapper import MitreMappingError, map_detection_to_mitre
        invalid_detection_refs = [
            None,
            123,
            ["suspicious_powershell_network_retrieval"],
        ]
        for bad_ref in invalid_detection_refs:
            with self.subTest(detection_ref=bad_ref):
                with self.assertRaises(MitreMappingError):
                    map_detection_to_mitre(bad_ref)  # type: ignore[arg-type]

    def test_decode_base64_powershell_type_confusion(self) -> None:
        """3. decode_base64_powershell type confusion fails closed with zero decoder execution."""
        from investigator.tools.base64_decoder import DecoderError, decode_powershell_base64
        invalid_inputs = [
            None,
            123,
            True,
            ["QQ=="],
            {"value": "QQ=="},
        ]
        for bad_input in invalid_inputs:
            with self.subTest(encoded_input=bad_input):
                with self.assertRaises(DecoderError):
                    decode_powershell_base64(bad_input)  # type: ignore[arg-type]

    def test_argument_smuggling_and_nested_payloads_rejected(self) -> None:
        """4. Argument smuggling / nested payloads are rejected without flattening or normalization."""
        # 4a. bounded_splunk_search nested dictionary
        with self.assertRaises(ToolValidationError):
            self.router.execute_tool(
                "bounded_splunk_search",
                {"host": "DC01", "minutes": {"value": 15}, "limit": 5},
            )
        self.mock_splunk._execute_bounded_search.assert_not_called()

        # 4b. map_mitre_technique nested dictionary
        with self.assertRaises(ToolValidationError):
            self.router.execute_tool(
                "map_mitre_technique",
                {
                    "detection_ref": "suspicious_powershell_network_retrieval",
                    "fail_closed": {"value": False},
                },
            )

        # 4c. decode_base64_powershell nested dictionary
        from investigator.tool_router import ToolExecutionError
        with self.assertRaises(ToolExecutionError):
            self.router.execute_tool(
                "decode_base64_powershell",
                {"encoded_input": {"payload": "QQ=="}},
            )

    def test_boolean_edge_cases_rejected_for_integer_arguments(self) -> None:
        """5. Explicitly verify Python bool values are not accepted where integer arguments are required."""
        bool_cases = [
            {"host": "DC01", "minutes": True, "limit": 10},
            {"host": "DC01", "minutes": False, "limit": 10},
            {"host": "DC01", "minutes": 15, "limit": True},
            {"host": "DC01", "minutes": 15, "limit": False},
        ]
        for args in bool_cases:
            with self.subTest(args=args):
                self.mock_splunk._execute_bounded_search.reset_mock()
                with self.assertRaises(ToolValidationError):
                    self.router.execute_tool("bounded_splunk_search", args)
                self.mock_splunk._execute_bounded_search.assert_not_called()

    def test_valid_controls_exact_types(self) -> None:
        """6. Confirm valid exact types pass validation and execute cleanly."""
        # 6a. bounded_splunk_search
        self.mock_splunk._execute_bounded_search.reset_mock()
        self.mock_splunk._execute_bounded_search.return_value = [{"host": "DC01"}]
        result = self.router.execute_tool(
            "bounded_splunk_search",
            {
                "host": "DC01",
                "minutes": 15,
                "limit": 5,
                "query_type": "encoded_powershell_matches",
            },
        )
        self.assertEqual(len(result), 1)
        self.mock_splunk._execute_bounded_search.assert_called_once()

        # 6b. map_mitre_technique
        mitre_result = self.router.execute_tool(
            "map_mitre_technique",
            {
                "detection_ref": "suspicious_powershell_network_retrieval",
                "fail_closed": False,
            },
        )
        self.assertEqual(mitre_result.technique_id, "T1105")

        # 6c. decode_base64_powershell
        valid_b64 = "VwByAGkAdABlAC0ASABvAHMAdAAgACcAQQBJAC0ATgBhAHQAaQB2AGUAUwBPAEMALQBMAEEAQgAtAFQARQBTAFQAJwA="
        decode_result = self.router.execute_tool(
            "decode_base64_powershell",
            {"encoded_input": valid_b64},
        )
        self.assertIn("AI-NativeSOC-LAB-TEST", decode_result.decoded_text)


class TestToolRouterThreatIntelLookup(unittest.TestCase):
    """Milestone 11C: Tests for bounded threat_intel_lookup tool contract and VirusTotal integration."""

    def setUp(self) -> None:
        self.mock_splunk = MagicMock()
        self.mock_vt = MagicMock(spec=VirusTotalThreatIntelClient)
        # Pass mock_vt if ToolRouter supports it, or instantiate standard router
        try:
            self.router = ToolRouter(splunk_client=self.mock_splunk, vt_client=self.mock_vt)
        except TypeError:
            self.router = ToolRouter(splunk_client=self.mock_splunk)

    def test_allowed_tools_contains_exactly_four_tools(self) -> None:
        """1. ALLOWED_TOOLS contains exactly the 4 audited tools including threat_intel_lookup."""
        self.assertEqual(
            ALLOWED_TOOLS,
            frozenset({
                "bounded_splunk_search",
                "decode_base64_powershell",
                "map_mitre_technique",
                "threat_intel_lookup",
            }),
        )
        # Router with vt_client exposes all 4 tools
        self.assertIn("threat_intel_lookup", self.router.allowed_tools)
        self.assertEqual(self.router.allowed_tools, ALLOWED_TOOLS)

        # Router without vt_client exposes only the 3 base tools
        router_no_vt = ToolRouter(splunk_client=self.mock_splunk)
        self.assertEqual(
            router_no_vt.allowed_tools,
            frozenset({
                "bounded_splunk_search",
                "decode_base64_powershell",
                "map_mitre_technique",
            }),
        )

    def test_threat_intel_lookup_valid_public_ip_dispatches_and_normalizes(self) -> None:
        """2. Valid public IP dispatches to VirusTotal client and returns normalized ThreatIntelObservation."""
        expected_result = ThreatIntelResult(
            provider="virustotal",
            indicator_type="ip",
            indicator_value="93.184.216.34",
            lookup_status=ThreatIntelLookupStatus.FOUND,
            malicious_count=10,
            suspicious_count=2,
            harmless_count=70,
            undetected_count=5,
            detail_code="ip_lookup_found",
            last_analysis_utc="2026-09-30T10:00:00Z",
        )
        self.mock_vt.lookup.return_value = expected_result

        obs = self.router.execute_tool("threat_intel_lookup", {"indicator": "93.184.216.34"})

        self.assertIsInstance(obs, ThreatIntelObservation)
        self.assertEqual(obs.indicator, "93.184.216.34")
        self.assertEqual(obs.indicator_type, "ip")
        self.assertEqual(obs.provider, "virustotal")
        self.assertEqual(obs.verdict, "malicious")
        self.assertEqual(obs.malicious_count, 10)
        self.assertEqual(obs.suspicious_count, 2)
        self.assertEqual(obs.harmless_count, 70)
        self.assertEqual(obs.undetected_count, 5)
        self.assertEqual(obs.source_reference, "virustotal:ip:93.184.216.34")

        # Must have dispatched via ThreatIntelRequest
        self.mock_vt.lookup.assert_called_once()
        req = self.mock_vt.lookup.call_args[0][0]
        self.assertIsInstance(req, ThreatIntelRequest)
        self.assertEqual(req.indicator_value, "93.184.216.34")
        self.assertEqual(req.indicator_type, "ip")

    def test_threat_intel_lookup_rejects_invalid_and_private_indicators(self) -> None:
        """3. Private, loopback, multicast, domain, and malformed indicators are rejected fail-closed."""
        invalid_indicators = [
            "127.0.0.1",
            "10.0.0.1",
            "192.168.1.10",
            "169.254.1.1",
            "0.0.0.0",
            "224.0.0.1",
            "example.com",
            "https://8.8.8.8",
            "not-an-ip",
            "",
            None,
            123,
            True,
        ]
        for bad_indicator in invalid_indicators:
            with self.subTest(indicator=bad_indicator):
                self.mock_vt.reset_mock()
                with self.assertRaises(ToolValidationError):
                    self.router.execute_tool("threat_intel_lookup", {"indicator": bad_indicator})
                self.mock_vt.lookup.assert_not_called()

    def test_threat_intel_lookup_rejects_additional_argument_smuggling(self) -> None:
        """4. Extra arguments like url, provider, api_key, headers are rejected before provider execution."""
        smuggled_payloads = [
            {"indicator": "8.8.8.8", "url": "https://evil.example"},
            {"indicator": "8.8.8.8", "provider": "custom"},
            {"indicator": "8.8.8.8", "api_key": "SECRET_KEY_123"},
            {"indicator": "8.8.8.8", "headers": {"Authorization": "Bearer token"}},
            {"indicator": "8.8.8.8", "endpoint": "/api/v3/ip_addresses/8.8.8.8"},
            {"indicator": "8.8.8.8", "extra": "forbidden"},
        ]
        for payload in smuggled_payloads:
            with self.subTest(payload=payload):
                self.mock_vt.reset_mock()
                with self.assertRaises(ToolValidationError):
                    self.router.execute_tool("threat_intel_lookup", payload)
                self.mock_vt.lookup.assert_not_called()

    def test_threat_intel_lookup_missing_indicator_fails_closed(self) -> None:
        """5. Invoking threat_intel_lookup without indicator argument raises ToolValidationError."""
        with self.assertRaises(ToolValidationError):
            self.router.execute_tool("threat_intel_lookup", {})
        self.mock_vt.lookup.assert_not_called()

    def test_threat_intel_lookup_provider_failures_map_to_tool_execution_error(self) -> None:
        """6. Provider transport or response errors fail closed as sanitized ToolExecutionError."""
        self.mock_vt.lookup.side_effect = VirusTotalTransportError("vt_transport_error")
        with self.assertRaises(ToolExecutionError):
            self.router.execute_tool("threat_intel_lookup", {"indicator": "8.8.8.8"})


if __name__ == "__main__":
    unittest.main()
