"""Unit tests for gateway policy engine and validation boundaries."""

import unittest

from gateway.policy import (
    ALLOWED_FIELDS,
    ALLOWED_HOSTS,
    ALLOWED_QUERY_TYPES,
    PolicyValidationError,
    SearchRequest,
    build_allowlisted_spl,
    validate_search_request,
)


class TestGatewayPolicy(unittest.TestCase):
    """Test policy boundary enforcement and input sanitization."""

    def test_valid_request(self) -> None:
        """Verify that compliant parameters create a valid SearchRequest."""
        req = validate_search_request(
            query_type="encoded_powershell_matches",
            host="DC01",
            minutes=15,
            limit=10,
        )
        self.assertIsInstance(req, SearchRequest)
        self.assertEqual(req.query_type, "encoded_powershell_matches")
        self.assertEqual(req.host, "DC01")
        self.assertEqual(req.minutes, 15)
        self.assertEqual(req.limit, 10)

    def test_direct_search_request_instantiation_validation(self) -> None:
        """Proof: Direct SearchRequest construction enforces policy invariants."""
        # Invalid query_type
        with self.assertRaises(PolicyValidationError):
            SearchRequest(
                query_type="unauthorized_type",
                host="DC01",
                minutes=15,
                limit=10,
            )
        # Invalid host
        with self.assertRaises(PolicyValidationError):
            SearchRequest(
                query_type="encoded_powershell_matches",
                host="WORKSTATION1",
                minutes=15,
                limit=10,
            )
        # Invalid minutes
        with self.assertRaises(PolicyValidationError):
            SearchRequest(
                query_type="encoded_powershell_matches",
                host="DC01",
                minutes=0,
                limit=10,
            )
        # Invalid limit
        with self.assertRaises(PolicyValidationError):
            SearchRequest(
                query_type="encoded_powershell_matches",
                host="DC01",
                minutes=15,
                limit=99,
            )

    def test_build_allowlisted_spl_defense_in_depth(self) -> None:
        """Proof: build_allowlisted_spl cannot be used to inject an unchecked host/minutes/limit."""
        # Non-SearchRequest object rejected
        with self.assertRaises(PolicyValidationError):
            build_allowlisted_spl("search index=*")  # type: ignore[arg-type]

        # Valid SearchRequest succeeds
        valid_req = SearchRequest(
            query_type="encoded_powershell_matches",
            host="DC01",
            minutes=15,
            limit=10,
        )
        spl = build_allowlisted_spl(valid_req)
        self.assertTrue(spl.startswith("search index=main"))

        # Even if object.__setattr__ is abused to mutate a frozen dataclass, re-validation catches it
        object.__setattr__(valid_req, "host", 'DC01" OR index=* |')
        with self.assertRaises(PolicyValidationError):
            build_allowlisted_spl(valid_req)

    def test_regression_boolean_coercion_cannot_succeed_through_builder(self) -> None:
        """Regression test: minutes=True and limit=True cannot succeed through builder or validation."""
        # Case 1: Caller attempts to create request with minutes=True
        with self.assertRaises(PolicyValidationError):
            validate_search_request(
                query_type="encoded_powershell_matches",
                host="DC01",
                minutes=True,  # type: ignore[arg-type]
                limit=10,
            )

        # Case 2: Caller attempts to create request with limit=True
        with self.assertRaises(PolicyValidationError):
            validate_search_request(
                query_type="encoded_powershell_matches",
                host="DC01",
                minutes=15,
                limit=True,  # type: ignore[arg-type]
            )

        # Case 3: Direct instantiation of SearchRequest with booleans
        with self.assertRaises(PolicyValidationError):
            SearchRequest(
                query_type="encoded_powershell_matches",
                host="DC01",
                minutes=True,  # type: ignore[arg-type]
                limit=10,
            )
        with self.assertRaises(PolicyValidationError):
            SearchRequest(
                query_type="encoded_powershell_matches",
                host="DC01",
                minutes=15,
                limit=True,  # type: ignore[arg-type]
            )

        # Case 4: Passing a tampered request with booleans to build_allowlisted_spl
        req = SearchRequest(
            query_type="encoded_powershell_matches",
            host="DC01",
            minutes=15,
            limit=10,
        )
        object.__setattr__(req, "minutes", True)
        with self.assertRaises(PolicyValidationError):
            build_allowlisted_spl(req)

        object.__setattr__(req, "minutes", 15)
        object.__setattr__(req, "limit", True)
        with self.assertRaises(PolicyValidationError):
            build_allowlisted_spl(req)

    def test_invalid_host(self) -> None:
        """Verify that unallowlisted hosts are rejected."""
        invalid_hosts = ["DC02", "WORKSTATION01", "dc01", "", "192.168.1.100", "localhost"]
        for host in invalid_hosts:
            with self.subTest(host=host):
                with self.assertRaises(PolicyValidationError):
                    validate_search_request(
                        query_type="encoded_powershell_matches",
                        host=host,
                        minutes=15,
                        limit=10,
                    )

    def test_minutes_zero(self) -> None:
        """Verify that minutes=0 is rejected (minimum is 1)."""
        with self.assertRaises(PolicyValidationError):
            validate_search_request(
                query_type="encoded_powershell_matches",
                host="DC01",
                minutes=0,
                limit=10,
            )

    def test_minutes_greater_than_sixty(self) -> None:
        """Verify that minutes>60 is rejected (maximum is 60)."""
        with self.assertRaises(PolicyValidationError):
            validate_search_request(
                query_type="encoded_powershell_matches",
                host="DC01",
                minutes=61,
                limit=10,
            )

    def test_limit_zero(self) -> None:
        """Verify that limit=0 is rejected (minimum is 1)."""
        with self.assertRaises(PolicyValidationError):
            validate_search_request(
                query_type="encoded_powershell_matches",
                host="DC01",
                minutes=15,
                limit=0,
            )

    def test_limit_greater_than_fifty(self) -> None:
        """Verify that limit>50 is rejected (maximum is 50)."""
        with self.assertRaises(PolicyValidationError):
            validate_search_request(
                query_type="encoded_powershell_matches",
                host="DC01",
                minutes=15,
                limit=51,
            )

    def test_unknown_query_type(self) -> None:
        """Verify that arbitrary or unknown query types are rejected."""
        unauthorized_types = ["arbitrary_spl", "process_create", "", "encoded_powershell", None]
        for qtype in unauthorized_types:
            with self.subTest(query_type=qtype):
                with self.assertRaises(PolicyValidationError):
                    validate_search_request(
                        query_type=qtype,  # type: ignore[arg-type]
                        host="DC01",
                        minutes=15,
                        limit=10,
                    )

    def test_arbitrary_spl_injection_prevention_via_host(self) -> None:
        """Proof: Caller cannot inject SPL syntax through the host parameter."""
        injection_payloads = [
            'DC01" OR index=* |',
            'DC01 | delete',
            'DC01" index=secrets | eval leaked=1 | ',
            'DC01; eval x=1',
            'DC01\n| table *',
        ]
        for payload in injection_payloads:
            with self.subTest(payload=payload):
                with self.assertRaises(PolicyValidationError):
                    validate_search_request(
                        query_type="encoded_powershell_matches",
                        host=payload,
                        minutes=15,
                        limit=10,
                    )

    def test_arbitrary_spl_injection_prevention_via_numeric_params(self) -> None:
        """Proof: String payloads cannot be passed to minutes or limit."""
        with self.assertRaises(PolicyValidationError):
            validate_search_request(
                query_type="encoded_powershell_matches",
                host="DC01",
                minutes="15 | eval injected=1",  # type: ignore[arg-type]
                limit=10,
            )
        with self.assertRaises(PolicyValidationError):
            validate_search_request(
                query_type="encoded_powershell_matches",
                host="DC01",
                minutes=15,
                limit="10 | head 999",  # type: ignore[arg-type]
            )

    def test_boolean_coercion_prevention(self) -> None:
        """Proof: Python boolean types are not coerced into integers."""
        with self.assertRaises(PolicyValidationError):
            validate_search_request(
                query_type="encoded_powershell_matches",
                host="DC01",
                minutes=True,  # type: ignore[arg-type]
                limit=10,
            )
        with self.assertRaises(PolicyValidationError):
            validate_search_request(
                query_type="encoded_powershell_matches",
                host="DC01",
                minutes=15,
                limit=False,  # type: ignore[arg-type]
            )

    def test_caller_cannot_change_index(self) -> None:
        """Proof: Caller cannot supply an index parameter or redirect search index."""
        # validate_search_request does not accept index parameter
        with self.assertRaises(TypeError):
            validate_search_request(
                query_type="encoded_powershell_matches",
                host="DC01",
                minutes=15,
                limit=10,
                index="other_index",  # type: ignore[call-arg]
            )

        req = validate_search_request(
            query_type="encoded_powershell_matches",
            host="DC01",
            minutes=15,
            limit=10,
        )
        spl = build_allowlisted_spl(req)
        # Verify generated SPL strictly anchors to index=main and sourcetype
        self.assertIn("index=main", spl)
        self.assertIn('sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"', spl)

    def test_spl_construction_correctness(self) -> None:
        """Verify that the generated SPL matches the verified detection template."""
        req = SearchRequest(
            query_type="encoded_powershell_matches",
            host="DC01",
            minutes=30,
            limit=25,
        )
        spl = build_allowlisted_spl(req)
        self.assertTrue(spl.startswith("search index=main"))
        self.assertIn('host="DC01"', spl)
        self.assertIn('earliest="-30m"', spl)
        self.assertIn("<EventID>1</EventID>", spl)
        self.assertIn(r"\\\\powershell\.exe$", spl)
        self.assertIn(r"-(encodedcommand|enc)\\b", spl)
        self.assertIn("| head 25", spl)
        self.assertIn("| table _time host User Image CommandLine ParentImage ParentCommandLine", spl)


if __name__ == "__main__":
    unittest.main()
