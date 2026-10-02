"""Unit tests for Milestone 12C: Deterministic Source-IP Scope Classification.

TDD RED PHASE ONLY.

Establishes the deterministic classification contract between validated
telemetry evidence (such as ModSecurity WEB01 SQLi detection) and threat intelligence
lookup tools.

Scope & Architecture Invariants:
1. Deterministic Scope Partitioning:
   - "public" (globally routable IPv4) -> external_ti_eligible = True
   - "private", "loopback", "link_local", "multicast", "reserved",
     "unspecified", "non_global" -> external_ti_eligible = False
2. Deterministic Precedence for overlapping Python ipaddress properties:
   - unspecified (0.0.0.0)
   - loopback (127.0.0.0/8)
   - link_local (169.254.0.0/16)
   - multicast (224.0.0.0/4)
   - reserved (240.0.0.0/4)
   - private (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
   - non_global (100.64.0.0/10 CGNAT, etc.)
   - public (globally routable)
3. Strict Fail-Closed Input Validation:
   - Rejects None, bool, non-string, empty string, whitespace, malformed IPv4,
     IPv6, CIDR, URLs, host:port.
4. Pure Offline Evaluation:
   - Zero network, zero external API calls (no VirusTotal, no Splunk, no LLM).
5. Immutable Contract:
   - Frozen dataclass IndicatorScope with deterministic to_dict().
"""

from typing import Any, Dict
import unittest
from unittest.mock import patch

from investigator.modsecurity import ModSecuritySqliEvidence

try:
    from investigator.threat_intel import (  # type: ignore
        IndicatorScope,
        classify_ipv4_scope,
    )
except ImportError:
    IndicatorScope = None  # type: ignore
    classify_ipv4_scope = None  # type: ignore


class TestDeterministicSourceIPScopeClassification(unittest.TestCase):
    """TDD test suite specifying the deterministic source IPv4 scope classification contract."""

    def _require_classifier(self) -> None:
        """Assert RED failure if classification production API is not yet implemented."""
        if classify_ipv4_scope is None or IndicatorScope is None:
            self.fail(
                "RED PHASE: classify_ipv4_scope or IndicatorScope is not yet implemented "
                "in investigator.threat_intel"
            )

    # -------------------------------------------------------------------------
    # 1. POSITIVE CLASSIFICATION: PUBLIC / GLOBALLY ROUTABLE
    # -------------------------------------------------------------------------

    def test_public_ip_8_8_8_8_is_eligible(self) -> None:
        """8.8.8.8 is classified as public and eligible for external threat intelligence."""
        self._require_classifier()

        res = classify_ipv4_scope("8.8.8.8")
        self.assertEqual(res.indicator, "8.8.8.8")
        self.assertEqual(res.scope, "public")
        self.assertTrue(res.external_ti_eligible)

    def test_public_ip_1_1_1_1_is_eligible(self) -> None:
        """1.1.1.1 is classified as public and eligible for external threat intelligence."""
        self._require_classifier()

        res = classify_ipv4_scope("1.1.1.1")
        self.assertEqual(res.indicator, "1.1.1.1")
        self.assertEqual(res.scope, "public")
        self.assertTrue(res.external_ti_eligible)

    # -------------------------------------------------------------------------
    # 2. POSITIVE CLASSIFICATION: PRIVATE (RFC 1918)
    # -------------------------------------------------------------------------

    def test_private_ip_10_0_0_1_is_ineligible(self) -> None:
        """10.0.0.1 is classified as private and ineligible for external TI."""
        self._require_classifier()

        res = classify_ipv4_scope("10.0.0.1")
        self.assertEqual(res.indicator, "10.0.0.1")
        self.assertEqual(res.scope, "private")
        self.assertFalse(res.external_ti_eligible)

    def test_private_ip_172_16_0_1_is_ineligible(self) -> None:
        """172.16.0.1 is classified as private and ineligible for external TI."""
        self._require_classifier()

        res = classify_ipv4_scope("172.16.0.1")
        self.assertEqual(res.indicator, "172.16.0.1")
        self.assertEqual(res.scope, "private")
        self.assertFalse(res.external_ti_eligible)

    def test_private_ip_192_168_1_100_is_ineligible(self) -> None:
        """192.168.1.100 is classified as private and ineligible for external TI."""
        self._require_classifier()

        res = classify_ipv4_scope("192.168.1.100")
        self.assertEqual(res.indicator, "192.168.1.100")
        self.assertEqual(res.scope, "private")
        self.assertFalse(res.external_ti_eligible)

    # -------------------------------------------------------------------------
    # 3. DETERMINISTIC PRECEDENCE FOR SPECIAL-USE RANGES
    # -------------------------------------------------------------------------

    def test_unspecified_0_0_0_0_precedence(self) -> None:
        """0.0.0.0 is classified as unspecified (taking precedence over generic private)."""
        self._require_classifier()

        res = classify_ipv4_scope("0.0.0.0")
        self.assertEqual(res.indicator, "0.0.0.0")
        self.assertEqual(res.scope, "unspecified")
        self.assertFalse(res.external_ti_eligible)

    def test_loopback_127_0_0_1_precedence(self) -> None:
        """127.0.0.1 is classified as loopback (taking precedence over generic private)."""
        self._require_classifier()

        res = classify_ipv4_scope("127.0.0.1")
        self.assertEqual(res.indicator, "127.0.0.1")
        self.assertEqual(res.scope, "loopback")
        self.assertFalse(res.external_ti_eligible)

    def test_link_local_169_254_1_1_precedence(self) -> None:
        """169.254.1.1 is classified as link_local (taking precedence over generic private)."""
        self._require_classifier()

        res = classify_ipv4_scope("169.254.1.1")
        self.assertEqual(res.indicator, "169.254.1.1")
        self.assertEqual(res.scope, "link_local")
        self.assertFalse(res.external_ti_eligible)

    def test_multicast_224_0_0_1_precedence(self) -> None:
        """224.0.0.1 is classified as multicast (taking precedence over generic global)."""
        self._require_classifier()

        res = classify_ipv4_scope("224.0.0.1")
        self.assertEqual(res.indicator, "224.0.0.1")
        self.assertEqual(res.scope, "multicast")
        self.assertFalse(res.external_ti_eligible)

    def test_reserved_240_0_0_1_precedence(self) -> None:
        """240.0.0.1 is classified as reserved."""
        self._require_classifier()

        res = classify_ipv4_scope("240.0.0.1")
        self.assertEqual(res.indicator, "240.0.0.1")
        self.assertEqual(res.scope, "reserved")
        self.assertFalse(res.external_ti_eligible)

    def test_non_global_cgnat_100_64_0_1(self) -> None:
        """100.64.0.1 (Carrier-Grade NAT RFC 6598) is classified as non_global."""
        self._require_classifier()

        res = classify_ipv4_scope("100.64.0.1")
        self.assertEqual(res.indicator, "100.64.0.1")
        self.assertEqual(res.scope, "non_global")
        self.assertFalse(res.external_ti_eligible)

    # -------------------------------------------------------------------------
    # 4. FAIL-CLOSED INPUT VALIDATION
    # -------------------------------------------------------------------------

    def test_reject_none(self) -> None:
        """None value raises ValueError."""
        self._require_classifier()

        with self.assertRaises(ValueError):
            classify_ipv4_scope(None)  # type: ignore[arg-type]

    def test_reject_bool(self) -> None:
        """Booleans True and False raise ValueError."""
        self._require_classifier()

        with self.assertRaises(ValueError):
            classify_ipv4_scope(True)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            classify_ipv4_scope(False)  # type: ignore[arg-type]

    def test_reject_non_string_types(self) -> None:
        """Non-string types (int, list, dict) raise ValueError."""
        self._require_classifier()

        bad_types = [123456, ["8.8.8.8"], {"ip": "8.8.8.8"}]
        for bad in bad_types:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    classify_ipv4_scope(bad)  # type: ignore[arg-type]

    def test_reject_empty_string(self) -> None:
        """Empty string raises ValueError."""
        self._require_classifier()

        with self.assertRaises(ValueError):
            classify_ipv4_scope("")

    def test_reject_whitespace_and_padded_inputs(self) -> None:
        """Whitespace-only and padded IP strings raise ValueError."""
        self._require_classifier()

        bad_inputs = ["   ", "\t", "\n", " 8.8.8.8", "8.8.8.8 ", " 8.8.8.8 "]
        for bad in bad_inputs:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    classify_ipv4_scope(bad)

    def test_reject_malformed_ipv4(self) -> None:
        """Malformed IP octets or non-numeric literals raise ValueError."""
        self._require_classifier()

        bad_ips = [
            "999.999.999.999",
            "256.1.1.1",
            "1.2.3",
            "1.2.3.4.5",
            "abc.def.ghi.jkl",
            "192.168.1.100.bad",
        ]
        for bad in bad_ips:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    classify_ipv4_scope(bad)

    def test_reject_ipv6(self) -> None:
        """Syntactically valid IPv6 addresses raise ValueError (IPv4-only milestone)."""
        self._require_classifier()

        ipv6_addresses = [
            "::1",
            "2001:db8::1",
            "fe80::1",
            "::ffff:192.168.1.1",
        ]
        for ip6 in ipv6_addresses:
            with self.subTest(ip6=ip6):
                with self.assertRaises(ValueError):
                    classify_ipv4_scope(ip6)

    def test_reject_cidr_notation(self) -> None:
        """CIDR subnet notations raise ValueError."""
        self._require_classifier()

        cidr_inputs = ["192.168.1.0/24", "8.8.8.8/32", "10.0.0.0/8"]
        for cidr in cidr_inputs:
            with self.subTest(cidr=cidr):
                with self.assertRaises(ValueError):
                    classify_ipv4_scope(cidr)

    def test_reject_url(self) -> None:
        """URL strings with schemes raise ValueError."""
        self._require_classifier()

        url_inputs = [
            "http://8.8.8.8",
            "https://192.168.1.100",
            "http://8.8.8.8:8080/path",
        ]
        for url in url_inputs:
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    classify_ipv4_scope(url)

    def test_reject_host_port(self) -> None:
        """host:port notation raises ValueError."""
        self._require_classifier()

        host_port_inputs = ["192.168.1.100:80", "8.8.8.8:443", "10.0.0.1:8080"]
        for hp in host_port_inputs:
            with self.subTest(hp=hp):
                with self.assertRaises(ValueError):
                    classify_ipv4_scope(hp)

    # -------------------------------------------------------------------------
    # 5. INVARIANTS & IMMUTABILITY
    # -------------------------------------------------------------------------

    def test_external_ti_eligible_strictly_correlated_with_public_scope(self) -> None:
        """external_ti_eligible is True ONLY for public scope, and False for all other scopes."""
        self._require_classifier()

        test_cases = [
            ("8.8.8.8", "public", True),
            ("1.1.1.1", "public", True),
            ("10.0.0.1", "private", False),
            ("172.16.0.1", "private", False),
            ("192.168.1.100", "private", False),
            ("127.0.0.1", "loopback", False),
            ("169.254.1.1", "link_local", False),
            ("224.0.0.1", "multicast", False),
            ("0.0.0.0", "unspecified", False),
            ("240.0.0.1", "reserved", False),
            ("100.64.0.1", "non_global", False),
        ]
        for ip, expected_scope, expected_ti_eligibility in test_cases:
            with self.subTest(ip=ip):
                classification = classify_ipv4_scope(ip)
                self.assertEqual(classification.scope, expected_scope)
                self.assertEqual(classification.external_ti_eligible, expected_ti_eligibility)

    def test_indicator_scope_immutability(self) -> None:
        """IndicatorScope is frozen and cannot be modified after creation."""
        self._require_classifier()

        res = classify_ipv4_scope("8.8.8.8")
        with self.assertRaises(Exception):
            res.scope = "private"  # type: ignore[misc]

    def test_deterministic_to_dict_serialization(self) -> None:
        """IndicatorScope exposes deterministic dictionary serialization."""
        self._require_classifier()

        res = classify_ipv4_scope("8.8.8.8")
        expected_dict = {
            "indicator": "8.8.8.8",
            "scope": "public",
            "external_ti_eligible": True,
        }
        self.assertEqual(res.to_dict(), expected_dict)

    def test_classification_does_not_invoke_external_subsystems(self) -> None:
        """Classification is purely offline and performs zero subprocess or external calls."""
        self._require_classifier()

        with patch("subprocess.run") as mock_subproc, \
             patch("urllib.request.urlopen") as mock_url:
            res = classify_ipv4_scope("8.8.8.8")
            self.assertEqual(res.scope, "public")
            mock_subproc.assert_not_called()
            mock_url.assert_not_called()

    # -------------------------------------------------------------------------
    # 6. LIVE-DERIVED WEB01 MODSECURITY EVIDENCE CASE
    # -------------------------------------------------------------------------

    def test_live_derived_web01_evidence_source_ip_classified_as_private_and_ineligible(self) -> None:
        """WEB01 ModSecurity SQLi evidence source IP (192.168.1.100) classifies as private and ineligible."""
        self._require_classifier()

        # Construct validated ModSecurity evidence matching live WEB01
        evidence = ModSecuritySqliEvidence(
            host="web01",
            src_ip="192.168.1.100",
            rule_id=942100,
            rule_msg="SQL Injection Attack Detected via libinjection",
            severity="CRITICAL",
            anomaly_score=8,
            unique_id="ar1Z9uxU-NFJV-LskY52NwAAAEQ",
        )

        classification = classify_ipv4_scope(evidence.src_ip)

        self.assertEqual(classification.indicator, "192.168.1.100")
        self.assertEqual(classification.scope, "private")
        self.assertFalse(classification.external_ti_eligible)

        # Confirm evidence itself is unmodified
        self.assertEqual(evidence.src_ip, "192.168.1.100")
        self.assertEqual(evidence.host, "web01")

    def test_web01_modsecurity_evidence_composes_with_scope_classifier(self) -> None:
        """WEB01 evidence source IP safely feeds into scope classifier without external calls or mutation."""
        self._require_classifier()

        evidence = ModSecuritySqliEvidence(
            host="web01",
            src_ip="192.168.1.100",
            rule_id=942100,
            rule_msg="SQL Injection Attack Detected via libinjection",
            severity="CRITICAL",
            anomaly_score=8,
            unique_id="ar1Z9uxU-NFJV-LskY52NwAAAEQ",
        )

        initial_evidence_dict = evidence.to_dict()

        with patch("investigator.providers.virustotal_provider.VirusTotalThreatIntelClient") as mock_vt, \
             patch("gateway.splunk_search.SplunkSearchClient") as mock_splunk, \
             patch("investigator.tool_router.ToolRouter") as mock_router, \
             patch("urllib.request.urlopen") as mock_url, \
             patch("http.client.HTTPSConnection") as mock_https, \
             patch("subprocess.run") as mock_subproc:

            result = classify_ipv4_scope(evidence.src_ip)

            # Assert expected classification fields
            self.assertEqual(result.indicator, "192.168.1.100")
            self.assertEqual(result.scope, "private")
            self.assertFalse(result.external_ti_eligible)

            # Assert evidence is unchanged
            self.assertEqual(evidence.to_dict(), initial_evidence_dict)

            # Assert no external subsystems, network, or tools invoked
            mock_vt.assert_not_called()
            mock_splunk.assert_not_called()
            mock_router.assert_not_called()
            mock_url.assert_not_called()
            mock_https.assert_not_called()
            mock_subproc.assert_not_called()


if __name__ == "__main__":
    unittest.main()
