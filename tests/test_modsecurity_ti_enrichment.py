"""Unit tests for Milestone 12D: Eligibility-Gated Threat Intelligence Integration.

TDD RED PHASE ONLY.

Establishes the deterministic enrichment orchestration contract connecting validated
ModSecurity SQLi evidence to the bounded threat intelligence lookup path.

Security & Architectural Guarantees:
1. Deterministic Scope Gating:
   - classify_ipv4_scope(evidence.src_ip) MUST execute before any external lookup.
   - If external_ti_eligible is False:
     * VirusTotal / external TI lookup MUST NOT be called.
     * Enrichment is recorded as skipped with a deterministic reason.
   - If external_ti_eligible is True:
     * Bounded threat_intel_lookup is called with the canonical indicator.
     * Normalized ThreatIntelObservation is returned.
2. AI-Bypass Prohibition:
   - Eligibility is decided strictly by deterministic code, not LLM reasoning.
3. Fail-Closed Boundaries:
   - Invalid evidence types, missing lookups, or provider exceptions fail closed.
   - No silent fallback to "unknown" or "skipped" on transport/provider execution errors.
4. Telemetry Integrity:
   - ModSecuritySqliEvidence is frozen and never mutated during enrichment.
"""

from typing import Any, Dict
import unittest
from unittest.mock import MagicMock, patch

from investigator.modsecurity import ModSecuritySqliEvidence
from investigator.threat_intel import (
    IndicatorScope,
    ThreatIntelError,
    ThreatIntelObservation,
    classify_ipv4_scope,
)
from investigator.tool_router import ToolExecutionError, ToolRouter

try:
    from investigator.modsecurity_enrichment import (  # type: ignore
        ModSecurityEnrichmentResult,
        enrich_modsecurity_source_ip,
    )
except ImportError:
    try:
        from investigator.threat_intel import (  # type: ignore
            ModSecurityEnrichmentResult,
            enrich_modsecurity_source_ip,
        )
    except ImportError:
        try:
            from investigator.modsecurity import (  # type: ignore
                ModSecurityEnrichmentResult,
                enrich_modsecurity_source_ip,
            )
        except ImportError:
            ModSecurityEnrichmentResult = None  # type: ignore
            enrich_modsecurity_source_ip = None  # type: ignore


# ---------------------------------------------------------------------------
# Test Fixtures
# ---------------------------------------------------------------------------

LIVE_DERIVED_WEB01_EVIDENCE = ModSecuritySqliEvidence(
    host="web01",
    src_ip="192.168.1.100",
    rule_id=942100,
    rule_msg="SQL Injection Attack Detected via libinjection",
    severity="CRITICAL",
    anomaly_score=8,
    unique_id="ar1Z9uxU-NFJV-LskY52NwAAAEQ",
)

CONTROLLED_PUBLIC_EVIDENCE = ModSecuritySqliEvidence(
    host="web01",
    src_ip="8.8.8.8",
    rule_id=942100,
    rule_msg="SQL Injection Attack Detected via libinjection",
    severity="CRITICAL",
    anomaly_score=8,
    unique_id="fixture-public-001",
)

SAMPLE_TI_OBSERVATION = ThreatIntelObservation(
    indicator="8.8.8.8",
    indicator_type="ip",
    provider="virustotal",
    verdict="CLEAN",
    malicious_count=0,
    suspicious_count=0,
    harmless_count=75,
    undetected_count=10,
    source_reference="vt-report-8888",
)


class TestModSecurityThreatIntelEnrichment(unittest.TestCase):
    """Tests establishing the eligibility-gated threat intelligence enrichment contract."""

    def _require_enricher(self) -> None:
        """Assert RED phase failure if enrichment contract is not yet implemented."""
        if enrich_modsecurity_source_ip is None or ModSecurityEnrichmentResult is None:
            self.fail(
                "RED PHASE: enrich_modsecurity_source_ip or ModSecurityEnrichmentResult "
                "is not yet implemented"
            )

    # -------------------------------------------------------------------------
    # 1. LIVE-DERIVED WEB01 PRIVATE IP BEHAVIOR
    # -------------------------------------------------------------------------

    def test_live_derived_web01_private_ip_skips_threat_intel(self) -> None:
        """Real live WEB01 evidence with private IP (192.168.1.100) deterministically skips TI."""
        self._require_enricher()

        mock_lookup = MagicMock()

        result = enrich_modsecurity_source_ip(
            evidence=LIVE_DERIVED_WEB01_EVIDENCE,
            threat_intel_lookup=mock_lookup,
        )

        # Lookup must NOT be called
        mock_lookup.assert_not_called()

        # Scope classification verified
        self.assertEqual(result.scope.indicator, "192.168.1.100")
        self.assertEqual(result.scope.scope, "private")
        self.assertFalse(result.scope.external_ti_eligible)

        # Enrichment status verified
        self.assertFalse(result.enriched)
        self.assertIsNone(result.observation)
        self.assertIsNotNone(result.skip_reason)
        self.assertIn("ineligible", result.skip_reason.lower())

        # Evidence unchanged
        self.assertEqual(result.evidence, LIVE_DERIVED_WEB01_EVIDENCE)
        self.assertEqual(LIVE_DERIVED_WEB01_EVIDENCE.src_ip, "192.168.1.100")

    # -------------------------------------------------------------------------
    # 2. CONTROLLED PUBLIC IP TEST FIXTURE BEHAVIOR
    # -------------------------------------------------------------------------

    def test_offline_fixture_public_ip_triggers_threat_intel(self) -> None:
        """Controlled public IP fixture (8.8.8.8) is eligible and triggers bounded TI lookup."""
        self._require_enricher()

        mock_lookup = MagicMock(return_value=SAMPLE_TI_OBSERVATION)

        result = enrich_modsecurity_source_ip(
            evidence=CONTROLLED_PUBLIC_EVIDENCE,
            threat_intel_lookup=mock_lookup,
        )

        # Lookup must be called exactly once with canonical IP
        mock_lookup.assert_called_once_with("8.8.8.8")

        # Scope verified
        self.assertEqual(result.scope.indicator, "8.8.8.8")
        self.assertEqual(result.scope.scope, "public")
        self.assertTrue(result.scope.external_ti_eligible)

        # Result verified
        self.assertTrue(result.enriched)
        self.assertEqual(result.observation, SAMPLE_TI_OBSERVATION)
        self.assertIsNone(result.skip_reason)

    # -------------------------------------------------------------------------
    # 3. NON-PUBLIC SCOPES ALWAYS SKIP TI
    # -------------------------------------------------------------------------

    def test_loopback_ip_ineligible_and_skips_threat_intel(self) -> None:
        """Loopback IP (127.0.0.1) skips threat intel without invoking lookup."""
        self._require_enricher()

        loopback_ev = ModSecuritySqliEvidence(
            host="web01",
            src_ip="127.0.0.1",
            rule_id=942100,
            rule_msg="SQL Injection Attack Detected via libinjection",
            severity="CRITICAL",
            anomaly_score=8,
            unique_id="fixture-loopback-001",
        )
        mock_lookup = MagicMock()

        result = enrich_modsecurity_source_ip(loopback_ev, mock_lookup)
        mock_lookup.assert_not_called()
        self.assertEqual(result.scope.scope, "loopback")
        self.assertFalse(result.enriched)
        self.assertIsNone(result.observation)
        self.assertIsNotNone(result.skip_reason)

    def test_link_local_ip_ineligible_and_skips_threat_intel(self) -> None:
        """Link-local IP (169.254.1.1) skips threat intel."""
        self._require_enricher()

        link_local_ev = ModSecuritySqliEvidence(
            host="web01",
            src_ip="169.254.1.1",
            rule_id=942100,
            rule_msg="SQL Injection Attack Detected via libinjection",
            severity="CRITICAL",
            anomaly_score=8,
            unique_id="fixture-linklocal-001",
        )
        mock_lookup = MagicMock()

        result = enrich_modsecurity_source_ip(link_local_ev, mock_lookup)
        mock_lookup.assert_not_called()
        self.assertEqual(result.scope.scope, "link_local")
        self.assertFalse(result.enriched)

    def test_multicast_ip_ineligible_and_skips_threat_intel(self) -> None:
        """Multicast IP (224.0.0.1) skips threat intel."""
        self._require_enricher()

        multicast_ev = ModSecuritySqliEvidence(
            host="web01",
            src_ip="224.0.0.1",
            rule_id=942100,
            rule_msg="SQL Injection Attack Detected via libinjection",
            severity="CRITICAL",
            anomaly_score=8,
            unique_id="fixture-multicast-001",
        )
        mock_lookup = MagicMock()

        result = enrich_modsecurity_source_ip(multicast_ev, mock_lookup)
        mock_lookup.assert_not_called()
        self.assertEqual(result.scope.scope, "multicast")
        self.assertFalse(result.enriched)

    def test_reserved_ip_ineligible_and_skips_threat_intel(self) -> None:
        """Reserved IP (240.0.0.1) skips threat intel."""
        self._require_enricher()

        reserved_ev = ModSecuritySqliEvidence(
            host="web01",
            src_ip="240.0.0.1",
            rule_id=942100,
            rule_msg="SQL Injection Attack Detected via libinjection",
            severity="CRITICAL",
            anomaly_score=8,
            unique_id="fixture-reserved-001",
        )
        mock_lookup = MagicMock()

        result = enrich_modsecurity_source_ip(reserved_ev, mock_lookup)
        mock_lookup.assert_not_called()
        self.assertEqual(result.scope.scope, "reserved")
        self.assertFalse(result.enriched)

    def test_unspecified_ip_ineligible_and_skips_threat_intel(self) -> None:
        """Unspecified IP (0.0.0.0) skips threat intel."""
        self._require_enricher()

        unspecified_ev = ModSecuritySqliEvidence(
            host="web01",
            src_ip="0.0.0.0",
            rule_id=942100,
            rule_msg="SQL Injection Attack Detected via libinjection",
            severity="CRITICAL",
            anomaly_score=8,
            unique_id="fixture-unspec-001",
        )
        mock_lookup = MagicMock()

        result = enrich_modsecurity_source_ip(unspecified_ev, mock_lookup)
        mock_lookup.assert_not_called()
        self.assertEqual(result.scope.scope, "unspecified")
        self.assertFalse(result.enriched)

    def test_non_global_cgnat_ineligible_and_skips_threat_intel(self) -> None:
        """CGNAT non-global IP (100.64.0.1) skips threat intel."""
        self._require_enricher()

        cgnat_ev = ModSecuritySqliEvidence(
            host="web01",
            src_ip="100.64.0.1",
            rule_id=942100,
            rule_msg="SQL Injection Attack Detected via libinjection",
            severity="CRITICAL",
            anomaly_score=8,
            unique_id="fixture-cgnat-001",
        )
        mock_lookup = MagicMock()

        result = enrich_modsecurity_source_ip(cgnat_ev, mock_lookup)
        mock_lookup.assert_not_called()
        self.assertEqual(result.scope.scope, "non_global")
        self.assertFalse(result.enriched)

    # -------------------------------------------------------------------------
    # 4. FAIL-CLOSED INPUT AND EXECUTION BOUNDARIES
    # -------------------------------------------------------------------------

    def test_evidence_none_rejected(self) -> None:
        """None passed as evidence raises ValueError or TypeError."""
        self._require_enricher()

        with self.assertRaises((ValueError, TypeError)):
            enrich_modsecurity_source_ip(None, MagicMock())  # type: ignore[arg-type]

    def test_evidence_wrong_type_rejected(self) -> None:
        """Non-ModSecuritySqliEvidence argument raises ValueError or TypeError."""
        self._require_enricher()

        bad_evidences = [
            {"src_ip": "8.8.8.8"},
            "8.8.8.8",
            12345,
        ]
        for bad in bad_evidences:
            with self.subTest(bad=bad):
                with self.assertRaises((ValueError, TypeError)):
                    enrich_modsecurity_source_ip(bad, MagicMock())  # type: ignore[arg-type]

    def test_threat_intel_lookup_not_callable_rejected(self) -> None:
        """Non-callable threat_intel_lookup dependency raises ValueError or TypeError."""
        self._require_enricher()

        bad_lookups = [None, "not_a_callable", 12345, {}]
        for bad in bad_lookups:
            with self.subTest(bad=bad):
                with self.assertRaises((ValueError, TypeError)):
                    enrich_modsecurity_source_ip(CONTROLLED_PUBLIC_EVIDENCE, bad)  # type: ignore[arg-type]

    def test_provider_error_propagates_fail_closed(self) -> None:
        """Eligible public IP encountering provider failure fails closed without falling back to skipped."""
        self._require_enricher()

        mock_lookup = MagicMock(side_effect=ThreatIntelError("VT provider transport failure"))

        with self.assertRaises(ThreatIntelError):
            enrich_modsecurity_source_ip(CONTROLLED_PUBLIC_EVIDENCE, mock_lookup)

    def test_tool_execution_error_propagates_fail_closed(self) -> None:
        """Eligible public IP encountering ToolExecutionError fails closed without swallowing error."""
        self._require_enricher()

        mock_lookup = MagicMock(side_effect=ToolExecutionError("TI lookup execution failed"))

        with self.assertRaises(ToolExecutionError):
            enrich_modsecurity_source_ip(CONTROLLED_PUBLIC_EVIDENCE, mock_lookup)

    def test_lookup_returning_non_observation_rejected(self) -> None:
        """Lookup returning non-ThreatIntelObservation raises error fail-closed."""
        self._require_enricher()

        mock_lookup = MagicMock(return_value={"raw": "payload"})

        with self.assertRaises((ValueError, TypeError, ThreatIntelError)):
            enrich_modsecurity_source_ip(CONTROLLED_PUBLIC_EVIDENCE, mock_lookup)

    def test_lookup_returning_none_for_public_ip_rejected(self) -> None:
        """Lookup returning None for eligible public IP raises error fail-closed."""
        self._require_enricher()

        mock_lookup = MagicMock(return_value=None)

        with self.assertRaises((ValueError, TypeError, ThreatIntelError)):
            enrich_modsecurity_source_ip(CONTROLLED_PUBLIC_EVIDENCE, mock_lookup)

    # -------------------------------------------------------------------------
    # 5. SECURITY INVARIANTS & IMMUTABILITY
    # -------------------------------------------------------------------------

    def test_classification_precedes_lookup(self) -> None:
        """Proves scope classification strictly precedes any threat intelligence lookup."""
        self._require_enricher()

        events = []

        def tracked_classifier(ip: str) -> IndicatorScope:
            events.append("classify")
            return classify_ipv4_scope(ip)

        def tracked_lookup(ip: str) -> ThreatIntelObservation:
            events.append("lookup")
            return SAMPLE_TI_OBSERVATION

        with patch("investigator.threat_intel.classify_ipv4_scope", side_effect=tracked_classifier):
            enrich_modsecurity_source_ip(CONTROLLED_PUBLIC_EVIDENCE, tracked_lookup)

        self.assertEqual(events, ["classify", "lookup"])

    def test_evidence_immutability_preserved(self) -> None:
        """ModSecuritySqliEvidence is frozen and completely unchanged by enrichment."""
        self._require_enricher()

        initial_dict = LIVE_DERIVED_WEB01_EVIDENCE.to_dict()

        res = enrich_modsecurity_source_ip(LIVE_DERIVED_WEB01_EVIDENCE, MagicMock())

        self.assertEqual(res.evidence.to_dict(), initial_dict)
        self.assertEqual(LIVE_DERIVED_WEB01_EVIDENCE.to_dict(), initial_dict)

    def test_result_immutability_and_to_dict(self) -> None:
        """ModSecurityEnrichmentResult is frozen and supports deterministic to_dict()."""
        self._require_enricher()

        mock_lookup = MagicMock(return_value=SAMPLE_TI_OBSERVATION)
        res = enrich_modsecurity_source_ip(CONTROLLED_PUBLIC_EVIDENCE, mock_lookup)

        # Immutability
        with self.assertRaises(Exception):
            res.enriched = False  # type: ignore[misc]

        # Serialization
        as_dict = res.to_dict()
        self.assertIsInstance(as_dict, dict)
        self.assertEqual(as_dict["enriched"], True)
        self.assertEqual(as_dict["evidence"]["src_ip"], "8.8.8.8")
        self.assertEqual(as_dict["scope"]["scope"], "public")
        self.assertEqual(as_dict["observation"]["indicator"], "8.8.8.8")
        self.assertIsNone(as_dict["skip_reason"])

    # -------------------------------------------------------------------------
    # 6. TOOLROUTER INTEGRATION COMPATIBILITY
    # -------------------------------------------------------------------------

    def test_tool_router_dispatch_compatibility_for_public_ip(self) -> None:
        """Proves compatibility when threat_intel_lookup is provided via ToolRouter dispatch."""
        self._require_enricher()

        mock_router = MagicMock()
        mock_router.execute_tool.return_value = SAMPLE_TI_OBSERVATION

        def router_ti_dispatch(indicator: str) -> ThreatIntelObservation:
            return mock_router.execute_tool("threat_intel_lookup", {"indicator": indicator})

        result = enrich_modsecurity_source_ip(
            evidence=CONTROLLED_PUBLIC_EVIDENCE,
            threat_intel_lookup=router_ti_dispatch,
        )

        mock_router.execute_tool.assert_called_once_with(
            "threat_intel_lookup",
            {"indicator": "8.8.8.8"},
        )
        self.assertTrue(result.enriched)
        self.assertEqual(result.observation, SAMPLE_TI_OBSERVATION)

    def test_tool_router_dispatch_compatibility_for_private_web01(self) -> None:
        """Proves ToolRouter threat_intel_lookup is NEVER called for private WEB01 evidence."""
        self._require_enricher()

        mock_router = MagicMock()

        def router_ti_dispatch(indicator: str) -> ThreatIntelObservation:
            return mock_router.execute_tool("threat_intel_lookup", {"indicator": indicator})

        result = enrich_modsecurity_source_ip(
            evidence=LIVE_DERIVED_WEB01_EVIDENCE,
            threat_intel_lookup=router_ti_dispatch,
        )

        mock_router.execute_tool.assert_not_called()
        self.assertFalse(result.enriched)
        self.assertIsNone(result.observation)


if __name__ == "__main__":
    unittest.main()
