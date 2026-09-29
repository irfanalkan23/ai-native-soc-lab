"""Adversarial regression tests for ToolRouter SPL injection and query-type abuse prevention (Milestone 9B)."""

import unittest
from unittest.mock import MagicMock

from investigator.tool_router import (
    ALLOWED_SPLUNK_QUERY_TYPES,
    ALLOWED_TOOLS,
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


if __name__ == "__main__":
    unittest.main()
