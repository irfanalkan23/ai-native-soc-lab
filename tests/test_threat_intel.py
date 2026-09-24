"""Unit tests and security boundary verification for threat intelligence contract.

Verifies:
- Public IP canonicalization and validation (rejecting multicast, private, loopback, etc.)
- ThreatIntelRequest schema invariants and strict type enforcement
- ThreatIntelResult schema invariants, detail-code coupling, and timestamp validation
- FakeThreatIntelClient construction validation and deterministic lookup
- Request-result indicator binding
- AST boundary verification (zero network or subprocess imports)
"""

import ast
from dataclasses import FrozenInstanceError
import inspect
from pathlib import Path
import unittest

from investigator.threat_intel import (
    ALLOWED_TI_DETAIL_CODES,
    ALLOWED_TI_PROVIDERS,
    _canonicalize_public_ip,
    FakeThreatIntelClient,
    ThreatIntelClient,
    ThreatIntelClientError,
    ThreatIntelError,
    ThreatIntelLookupStatus,
    ThreatIntelRequest,
    ThreatIntelRequestError,
    ThreatIntelResult,
    ThreatIntelResultError,
)


class TestPublicIpCanonicalization(unittest.TestCase):
    """Test public IP validation helper and edge case filtering."""

    def test_valid_public_ipv4(self) -> None:
        """Valid public IPv4 addresses canonicalize cleanly."""
        self.assertEqual(_canonicalize_public_ip("8.8.8.8"), "8.8.8.8")
        self.assertEqual(_canonicalize_public_ip("1.1.1.1"), "1.1.1.1")
        self.assertEqual(_canonicalize_public_ip("93.184.216.34"), "93.184.216.34")

    def test_valid_public_ipv6(self) -> None:
        """Valid public IPv6 addresses canonicalize to compressed lowercase."""
        self.assertEqual(
            _canonicalize_public_ip("2606:4700:4700::1111"),
            "2606:4700:4700::1111",
        )
        # Uncompressed input canonicalizes to compressed
        self.assertEqual(
            _canonicalize_public_ip("2001:4860:4860:0000:0000:0000:0000:8888"),
            "2001:4860:4860::8888",
        )

    def test_ipv6_scope_zone_identifier_rejection(self) -> None:
        """IPv6 scope or zone identifiers are strictly rejected."""
        scoped_ips = [
            "fe80::1%eth0",
            "2606:4700:4700::1111%eth0",
            "2001:4860:4860::8888%zone1",
        ]
        for ip in scoped_ips:
            with self.subTest(ip=ip):
                with self.assertRaises(ValueError) as ctx:
                    _canonicalize_public_ip(ip)
                self.assertEqual(
                    str(ctx.exception),
                    "IPv6 scope or zone identifiers are not allowed",
                )

    def test_multicast_rejection(self) -> None:
        """Multicast addresses are explicitly rejected even if Python reports is_global."""
        multicast_ips = [
            "224.0.0.1",
            "239.255.255.250",
            "ff02::1",
            "ff00::1",
            "ff0e::1",
        ]
        for ip in multicast_ips:
            with self.subTest(ip=ip):
                with self.assertRaises(ValueError) as ctx:
                    _canonicalize_public_ip(ip)
                self.assertIn("not a globally routable public IP", str(ctx.exception))

    def test_private_rfc1918_rejection(self) -> None:
        """RFC 1918 private IPv4 addresses are rejected."""
        private_ips = ["10.0.0.1", "172.16.0.1", "192.168.1.1", "192.168.0.254"]
        for ip in private_ips:
            with self.subTest(ip=ip):
                with self.assertRaises(ValueError):
                    _canonicalize_public_ip(ip)

    def test_loopback_rejection(self) -> None:
        """Loopback addresses for IPv4 and IPv6 are rejected."""
        for ip in ["127.0.0.1", "127.0.0.254", "::1"]:
            with self.subTest(ip=ip):
                with self.assertRaises(ValueError):
                    _canonicalize_public_ip(ip)

    def test_link_local_rejection(self) -> None:
        """Link-local addresses are rejected."""
        for ip in ["169.254.1.1", "fe80::1"]:
            with self.subTest(ip=ip):
                with self.assertRaises(ValueError):
                    _canonicalize_public_ip(ip)

    def test_unspecified_and_reserved_rejection(self) -> None:
        """Unspecified (0.0.0.0, ::) and reserved/broadcast addresses are rejected."""
        for ip in ["0.0.0.0", "::", "240.0.0.1", "255.255.255.255"]:
            with self.subTest(ip=ip):
                with self.assertRaises(ValueError):
                    _canonicalize_public_ip(ip)

    def test_documentation_test_net_rejection(self) -> None:
        """RFC 5737 and RFC 3849 documentation IPs are rejected under public IP policy."""
        doc_ips = ["192.0.2.1", "198.51.100.1", "203.0.113.1", "2001:db8::1"]
        for ip in doc_ips:
            with self.subTest(ip=ip):
                with self.assertRaises(ValueError):
                    _canonicalize_public_ip(ip)

    def test_syntax_disallowlist_rejection(self) -> None:
        """Whitespace, CIDR, URLs, host:port, and lists are rejected."""
        invalid_inputs = [
            " 8.8.8.8",
            "8.8.8.8 ",
            "8.8.8.8\n",
            "\t8.8.8.8",
            "8.8.8.0/24",
            "2606:4700::/32",
            "http://8.8.8.8",
            "https://8.8.8.8/foo",
            "8.8.8.8:443",
            "[2606:4700::1]:80",
            "8.8.8.8,1.1.1.1",
            "",
            "not-an-ip",
        ]
        for val in invalid_inputs:
            with self.subTest(val=val):
                with self.assertRaises(ValueError):
                    _canonicalize_public_ip(val)

    def test_invalid_type_rejection(self) -> None:
        """Non-string types are rejected with ValueError."""
        for val in [None, 123, True, False, ["8.8.8.8"], {"ip": "8.8.8.8"}]:
            with self.subTest(val=val):
                with self.assertRaises(ValueError):
                    _canonicalize_public_ip(val)  # type: ignore[arg-type]


class TestThreatIntelRequestSchema(unittest.TestCase):
    """Test ThreatIntelRequest construction and validation."""

    def test_valid_request_construction(self) -> None:
        """Valid public IP constructs ThreatIntelRequest with default indicator_type."""
        req = ThreatIntelRequest(indicator_value="8.8.8.8")
        self.assertEqual(req.indicator_value, "8.8.8.8")
        self.assertEqual(req.indicator_type, "ip")

    def test_request_normalizes_canonical_ipv6(self) -> None:
        """Uncompressed IPv6 is normalized to canonical form in request."""
        req = ThreatIntelRequest(indicator_value="2001:4860:4860:0000:0000:0000:0000:8888")
        self.assertEqual(req.indicator_value, "2001:4860:4860::8888")

    def test_invalid_ip_raises_threat_intel_request_error(self) -> None:
        """Invalid or non-public IP raises ThreatIntelRequestError (not ValueError directly)."""
        invalid_ips = ["192.168.1.1", "224.0.0.1", "127.0.0.1", "invalid_text", ""]
        for ip in invalid_ips:
            with self.subTest(ip=ip):
                with self.assertRaises(ThreatIntelRequestError):
                    ThreatIntelRequest(indicator_value=ip)

    def test_unsupported_indicator_type_rejected(self) -> None:
        """Only indicator_type='ip' is supported in V1."""
        for bad_type in ["domain", "url", "hash", "", None, 123]:
            with self.subTest(bad_type=bad_type):
                with self.assertRaises(ThreatIntelRequestError):
                    ThreatIntelRequest(indicator_value="8.8.8.8", indicator_type=bad_type)  # type: ignore[arg-type]

    def test_immutability(self) -> None:
        """ThreatIntelRequest is frozen."""
        req = ThreatIntelRequest(indicator_value="8.8.8.8")
        with self.assertRaises(FrozenInstanceError):
            req.indicator_value = "1.1.1.1"  # type: ignore[misc]


class TestThreatIntelResultSchema(unittest.TestCase):
    """Test ThreatIntelResult construction, bounds, and coupling invariants."""

    def test_valid_found_result_with_timestamp(self) -> None:
        """Valid FOUND result with ISO 8601 UTC timestamp constructs cleanly."""
        res = ThreatIntelResult(
            provider="fake_threat_intel",
            indicator_type="ip",
            indicator_value="8.8.8.8",
            lookup_status=ThreatIntelLookupStatus.FOUND,
            malicious_count=0,
            suspicious_count=0,
            harmless_count=85,
            undetected_count=5,
            detail_code="ip_lookup_found",
            last_analysis_utc="2026-09-24T12:00:00Z",
        )
        self.assertEqual(res.provider, "fake_threat_intel")
        self.assertEqual(res.lookup_status, ThreatIntelLookupStatus.FOUND)
        self.assertEqual(res.harmless_count, 85)
        self.assertEqual(res.detail_code, "ip_lookup_found")
        self.assertEqual(res.last_analysis_utc, "2026-09-24T12:00:00Z")

    def test_valid_found_result_with_none_timestamp(self) -> None:
        """Valid FOUND result with last_analysis_utc=None is permitted."""
        res = ThreatIntelResult(
            provider="fake_threat_intel",
            indicator_type="ip",
            indicator_value="8.8.8.8",
            lookup_status=ThreatIntelLookupStatus.FOUND,
            malicious_count=1,
            suspicious_count=0,
            harmless_count=80,
            undetected_count=9,
            detail_code="ip_lookup_found",
            last_analysis_utc=None,
        )
        self.assertIsNone(res.last_analysis_utc)

    def test_valid_not_found_result(self) -> None:
        """Valid NOT_FOUND result has all zero counters and None timestamp."""
        res = ThreatIntelResult(
            provider="fake_threat_intel",
            indicator_type="ip",
            indicator_value="8.8.8.8",
            lookup_status=ThreatIntelLookupStatus.NOT_FOUND,
            malicious_count=0,
            suspicious_count=0,
            harmless_count=0,
            undetected_count=0,
            detail_code="ip_lookup_not_found",
            last_analysis_utc=None,
        )
        self.assertEqual(res.lookup_status, ThreatIntelLookupStatus.NOT_FOUND)
        self.assertEqual(res.detail_code, "ip_lookup_not_found")
        self.assertEqual(res.malicious_count, 0)

    def test_not_found_with_nonzero_counters_fails(self) -> None:
        """NOT_FOUND result with any non-zero counter raises ThreatIntelResultError."""
        with self.assertRaises(ThreatIntelResultError):
            ThreatIntelResult(
                provider="fake_threat_intel",
                indicator_type="ip",
                indicator_value="8.8.8.8",
                lookup_status=ThreatIntelLookupStatus.NOT_FOUND,
                malicious_count=1,  # Non-zero counter forbidden for NOT_FOUND
                suspicious_count=0,
                harmless_count=0,
                undetected_count=0,
                detail_code="ip_lookup_not_found",
            )

    def test_not_found_with_timestamp_fails(self) -> None:
        """NOT_FOUND result with a timestamp raises ThreatIntelResultError."""
        with self.assertRaises(ThreatIntelResultError):
            ThreatIntelResult(
                provider="fake_threat_intel",
                indicator_type="ip",
                indicator_value="8.8.8.8",
                lookup_status=ThreatIntelLookupStatus.NOT_FOUND,
                malicious_count=0,
                suspicious_count=0,
                harmless_count=0,
                undetected_count=0,
                detail_code="ip_lookup_not_found",
                last_analysis_utc="2026-09-24T12:00:00Z",
            )

    def test_found_with_naive_timestamp_fails(self) -> None:
        """FOUND result with naive timestamp raises ThreatIntelResultError."""
        with self.assertRaises(ThreatIntelResultError):
            ThreatIntelResult(
                provider="fake_threat_intel",
                indicator_type="ip",
                indicator_value="8.8.8.8",
                lookup_status=ThreatIntelLookupStatus.FOUND,
                malicious_count=0,
                suspicious_count=0,
                harmless_count=0,
                undetected_count=0,
                detail_code="ip_lookup_found",
                last_analysis_utc="2026-09-24T12:00:00",  # No offset
            )

    def test_found_with_nonzero_utc_offset_fails(self) -> None:
        """FOUND result with non-zero offset raises ThreatIntelResultError."""
        with self.assertRaises(ThreatIntelResultError):
            ThreatIntelResult(
                provider="fake_threat_intel",
                indicator_type="ip",
                indicator_value="8.8.8.8",
                lookup_status=ThreatIntelLookupStatus.FOUND,
                malicious_count=0,
                suspicious_count=0,
                harmless_count=0,
                undetected_count=0,
                detail_code="ip_lookup_found",
                last_analysis_utc="2026-09-24T12:00:00+03:00",
            )

    def test_provider_allowlist_enforced(self) -> None:
        """Only exact members of ALLOWED_TI_PROVIDERS are accepted."""
        # Unregistered provider matching regex fails
        with self.assertRaises(ThreatIntelResultError):
            ThreatIntelResult(
                provider="unknown_provider",
                indicator_type="ip",
                indicator_value="8.8.8.8",
                lookup_status=ThreatIntelLookupStatus.FOUND,
                malicious_count=0,
                suspicious_count=0,
                harmless_count=0,
                undetected_count=0,
                detail_code="ip_lookup_found",
            )
        # virustotal is rejected in 5C-1 (deferred to 5C-2)
        with self.assertRaises(ThreatIntelResultError):
            ThreatIntelResult(
                provider="virustotal",
                indicator_type="ip",
                indicator_value="8.8.8.8",
                lookup_status=ThreatIntelLookupStatus.FOUND,
                malicious_count=0,
                suspicious_count=0,
                harmless_count=0,
                undetected_count=0,
                detail_code="ip_lookup_found",
            )

    def test_detail_code_coupling(self) -> None:
        """detail_code must match lookup_status."""
        # FOUND with ip_lookup_not_found raises
        with self.assertRaises(ThreatIntelResultError):
            ThreatIntelResult(
                provider="fake_threat_intel",
                indicator_type="ip",
                indicator_value="8.8.8.8",
                lookup_status=ThreatIntelLookupStatus.FOUND,
                malicious_count=0,
                suspicious_count=0,
                harmless_count=0,
                undetected_count=0,
                detail_code="ip_lookup_not_found",
            )
        # NOT_FOUND with ip_lookup_found raises
        with self.assertRaises(ThreatIntelResultError):
            ThreatIntelResult(
                provider="fake_threat_intel",
                indicator_type="ip",
                indicator_value="8.8.8.8",
                lookup_status=ThreatIntelLookupStatus.NOT_FOUND,
                malicious_count=0,
                suspicious_count=0,
                harmless_count=0,
                undetected_count=0,
                detail_code="ip_lookup_found",
            )

    def test_negative_or_oversized_counters_fail(self) -> None:
        """Counters must be exact int between 0 and 256."""
        for bad_count in [-1, 257, 1000]:
            with self.subTest(bad_count=bad_count):
                with self.assertRaises(ThreatIntelResultError):
                    ThreatIntelResult(
                        provider="fake_threat_intel",
                        indicator_type="ip",
                        indicator_value="8.8.8.8",
                        lookup_status=ThreatIntelLookupStatus.FOUND,
                        malicious_count=bad_count,
                        suspicious_count=0,
                        harmless_count=0,
                        undetected_count=0,
                        detail_code="ip_lookup_found",
                    )

    def test_exact_int_counter_enforcement(self) -> None:
        """Counters strictly require exact int type, rejecting bool, float, and str."""
        counter_fields = (
            "malicious_count",
            "suspicious_count",
            "harmless_count",
            "undetected_count",
        )
        rejected_values = [True, False, 1.0, "1"]
        for field in counter_fields:
            for bad_val in rejected_values:
                with self.subTest(field=field, bad_val=bad_val):
                    kwargs = {
                        "provider": "fake_threat_intel",
                        "indicator_type": "ip",
                        "indicator_value": "8.8.8.8",
                        "lookup_status": ThreatIntelLookupStatus.FOUND,
                        "malicious_count": 0,
                        "suspicious_count": 0,
                        "harmless_count": 0,
                        "undetected_count": 0,
                        "detail_code": "ip_lookup_found",
                    }
                    kwargs[field] = bad_val
                    with self.assertRaises(ThreatIntelResultError):
                        ThreatIntelResult(**kwargs)  # type: ignore[arg-type]

    def test_non_canonical_or_private_ip_in_result_fails(self) -> None:
        """indicator_value in result must be canonical public IP."""
        # Non-canonical IPv6 in result raises ThreatIntelResultError
        with self.assertRaises(ThreatIntelResultError):
            ThreatIntelResult(
                provider="fake_threat_intel",
                indicator_type="ip",
                indicator_value="2001:4860:4860:0000:0000:0000:0000:8888",
                lookup_status=ThreatIntelLookupStatus.FOUND,
                malicious_count=0,
                suspicious_count=0,
                harmless_count=0,
                undetected_count=0,
                detail_code="ip_lookup_found",
            )
        # Private IP in result raises ThreatIntelResultError
        with self.assertRaises(ThreatIntelResultError):
            ThreatIntelResult(
                provider="fake_threat_intel",
                indicator_type="ip",
                indicator_value="192.168.1.1",
                lookup_status=ThreatIntelLookupStatus.FOUND,
                malicious_count=0,
                suspicious_count=0,
                harmless_count=0,
                undetected_count=0,
                detail_code="ip_lookup_found",
            )


class TestFakeThreatIntelClient(unittest.TestCase):
    """Test FakeThreatIntelClient constructor validation and lookup behavior."""

    def setUp(self) -> None:
        self.fixture_a = ThreatIntelResult(
            provider="fake_threat_intel",
            indicator_type="ip",
            indicator_value="8.8.8.8",
            lookup_status=ThreatIntelLookupStatus.FOUND,
            malicious_count=0,
            suspicious_count=0,
            harmless_count=85,
            undetected_count=5,
            detail_code="ip_lookup_found",
            last_analysis_utc="2026-09-24T12:00:00Z",
        )
        self.fixture_b = ThreatIntelResult(
            provider="fake_threat_intel",
            indicator_type="ip",
            indicator_value="93.184.216.34",
            lookup_status=ThreatIntelLookupStatus.FOUND,
            malicious_count=42,
            suspicious_count=3,
            harmless_count=0,
            undetected_count=10,
            detail_code="ip_lookup_found",
            last_analysis_utc="2026-09-24T12:05:00Z",
        )

    def test_default_constructor_empty_fixtures(self) -> None:
        """Client constructs with default empty fixtures."""
        client = FakeThreatIntelClient()
        req = ThreatIntelRequest(indicator_value="1.1.1.1")
        res = client.lookup(req)
        self.assertEqual(res.lookup_status, ThreatIntelLookupStatus.NOT_FOUND)
        self.assertEqual(res.indicator_value, "1.1.1.1")
        self.assertEqual(res.detail_code, "ip_lookup_not_found")
        self.assertEqual(res.malicious_count, 0)

    def test_injected_fixtures_lookup_success(self) -> None:
        """Registered fixtures are returned accurately on lookup."""
        client = FakeThreatIntelClient(
            fixtures={
                "8.8.8.8": self.fixture_a,
                "93.184.216.34": self.fixture_b,
            }
        )
        # Fixture A lookup
        res1 = client.lookup(ThreatIntelRequest(indicator_value="8.8.8.8"))
        self.assertEqual(res1.lookup_status, ThreatIntelLookupStatus.FOUND)
        self.assertEqual(res1.harmless_count, 85)

        # Fixture B lookup
        res2 = client.lookup(ThreatIntelRequest(indicator_value="93.184.216.34"))
        self.assertEqual(res2.lookup_status, ThreatIntelLookupStatus.FOUND)
        self.assertEqual(res2.malicious_count, 42)

        # Unregistered public IP returns NOT_FOUND
        res3 = client.lookup(ThreatIntelRequest(indicator_value="1.1.1.1"))
        self.assertEqual(res3.lookup_status, ThreatIntelLookupStatus.NOT_FOUND)

    def test_fixture_dict_ownership_is_copied(self) -> None:
        """Client must copy incoming fixtures into a private dict, not retain caller reference."""
        mutable_fixtures = {
            "8.8.8.8": self.fixture_a,
        }
        client = FakeThreatIntelClient(fixtures=mutable_fixtures)
        mutable_fixtures.clear()
        req = ThreatIntelRequest(indicator_value="8.8.8.8")
        res = client.lookup(req)
        self.assertEqual(res.lookup_status, ThreatIntelLookupStatus.FOUND)
        self.assertEqual(res.indicator_value, "8.8.8.8")
        self.assertEqual(res.harmless_count, 85)

    def test_constructor_mismatched_key_fails(self) -> None:
        """Constructor raises ThreatIntelClientError if fixture key != result.indicator_value."""
        with self.assertRaises(ThreatIntelClientError) as ctx:
            FakeThreatIntelClient(
                fixtures={
                    "1.1.1.1": self.fixture_a,  # fixture_a is for 8.8.8.8
                }
            )
        self.assertIn("does not match result indicator_value", str(ctx.exception))

    def test_constructor_invalid_ip_key_fails(self) -> None:
        """Constructor raises ThreatIntelClientError if fixture key is not a valid public IP."""
        with self.assertRaises(ThreatIntelClientError):
            FakeThreatIntelClient(
                fixtures={
                    "192.168.1.1": self.fixture_a,  # Private IP key
                }
            )

    def test_constructor_invalid_fixture_value_fails(self) -> None:
        """Constructor raises ThreatIntelClientError if fixture value is not ThreatIntelResult."""
        with self.assertRaises(ThreatIntelClientError):
            FakeThreatIntelClient(
                fixtures={
                    "8.8.8.8": {"status": "FOUND"},  # type: ignore[dict-item]
                }
            )

    def test_lookup_rejects_non_request(self) -> None:
        """lookup() raises ThreatIntelClientError if argument is not ThreatIntelRequest."""
        client = FakeThreatIntelClient()
        with self.assertRaises(ThreatIntelClientError):
            client.lookup("8.8.8.8")  # type: ignore[arg-type]

    def test_defensive_request_result_binding_check(self) -> None:
        """Client defensive binding check raises ThreatIntelClientError if indicator mismatches."""
        client = FakeThreatIntelClient()
        # Tamper the internal fixtures dict to test defensive binding check
        client._fixtures["8.8.8.8"] = self.fixture_b  # Indicator is 93.184.216.34
        req = ThreatIntelRequest(indicator_value="8.8.8.8")
        with self.assertRaises(ThreatIntelClientError) as ctx:
            client.lookup(req)
        self.assertIn("indicator_mismatch", str(ctx.exception))

    def test_protocol_conformance(self) -> None:
        """FakeThreatIntelClient conforms to ThreatIntelClient protocol."""
        client = FakeThreatIntelClient()
        self.assertIsInstance(client, ThreatIntelClient)


class TestThreatIntelSecurityBoundaries(unittest.TestCase):
    """Verify security isolation and AST module boundaries."""

    def test_no_forbidden_network_or_system_modules(self) -> None:
        """investigator/threat_intel.py must import zero socket, HTTP, or subprocess libraries."""
        module_path = Path(__file__).resolve().parent.parent / "investigator" / "threat_intel.py"
        self.assertTrue(module_path.exists(), f"Module {module_path} not found")

        source = module_path.read_text(encoding="utf-8")
        tree = ast.parse(source)

        forbidden_modules = {
            "urllib",
            "urllib.request",
            "urllib.parse",
            "http",
            "http.client",
            "requests",
            "httpx",
            "socket",
            "subprocess",
            "os.system",
        }

        imported_modules: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported_modules.add(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imported_modules.add(node.module)

        for forbidden in forbidden_modules:
            self.assertNotIn(
                forbidden,
                imported_modules,
                f"Forbidden module '{forbidden}' imported in {module_path.name}",
            )

    def test_no_os_environ_access(self) -> None:
        """FakeThreatIntelClient must not access os.environ or load credentials."""
        module_path = Path(__file__).resolve().parent.parent / "investigator" / "threat_intel.py"
        source = module_path.read_text(encoding="utf-8")
        self.assertNotIn("os.environ", source)
        self.assertNotIn("getenv", source)

    def test_no_forbidden_function_calls(self) -> None:
        """investigator/threat_intel.py must not call eval, exec, or os.system."""
        module_path = Path(__file__).resolve().parent.parent / "investigator" / "threat_intel.py"
        source = module_path.read_text(encoding="utf-8")
        tree = ast.parse(source)

        forbidden_calls: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # Detect direct calls to eval(...) or exec(...)
                if isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
                    forbidden_calls.append(node.func.id)
                # Detect calls to os.system(...)
                elif (
                    isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "os"
                    and node.func.attr == "system"
                ):
                    forbidden_calls.append("os.system")

        self.assertEqual(
            forbidden_calls,
            [],
            f"Forbidden function calls detected in {module_path.name}: {forbidden_calls}",
        )


if __name__ == "__main__":
    unittest.main()
