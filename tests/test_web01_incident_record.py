"""Unit and integration tests for Milestone 12E: WEB01 Incident Record Integration.

TDD RED PHASE ONLY.

Establishes the contract for representing Apache ModSecurity / OWASP CRS SQLi
incidents from WEB01 within the immutable IncidentRecord reporting artifact,
including deterministic threat intelligence eligibility state.

Security & Architectural Guarantees:
1. Telemetry Integrity:
   - Preserves validated ModSecurity evidence: host, src_ip, rule_id, rule_msg,
     severity, anomaly_score, unique_id.
   - Zero raw ModSecurity transaction text (_raw) in incident record serialization.
2. Threat Intelligence State Coupling:
   - Three distinct deterministic states:
     a. SKIPPED_INELIGIBLE: Ineligible private/local scope; zero observation; explicit reason.
     b. ENRICHED: Public IP; normalized ThreatIntelObservation preserved; no secrets.
     c. LOOKUP_FAILED: Eligible public IP but provider/lookup failed; explicit error reason.
   - Contradictory states strictly fail closed (e.g. skipped with observation,
     enriched without observation, lookup failure masquerading as ineligible skip).
3. Non-Regression & Domain Boundaries:
   - Backward-compatible optional fields preserve existing DC01/PowerShell incidents.
   - Downstream ticketing (Jira) continues to function safely with WEB01 records.
"""

from typing import Any, Dict
import unittest

from investigator.incident_record import (
    SCHEMA_VERSION,
    IncidentRecord,
    IncidentRecordError,
)
from investigator.modsecurity import ModSecuritySqliEvidence
from investigator.modsecurity_enrichment import ModSecurityEnrichmentResult
from investigator.threat_intel import (
    IndicatorScope,
    ThreatIntelObservation,
)
from investigator.ticketing import (
    TicketConfig,
    build_ticket_request,
)

try:
    from investigator.incident_record import (  # type: ignore
        build_modsecurity_incident_record,
    )
except ImportError:
    try:
        from investigator.modsecurity_enrichment import (  # type: ignore
            build_modsecurity_incident_record,
        )
    except ImportError:
        build_modsecurity_incident_record = None  # type: ignore


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

WEB01_INELIGIBLE_ENRICHMENT = ModSecurityEnrichmentResult(
    evidence=LIVE_DERIVED_WEB01_EVIDENCE,
    scope=IndicatorScope(
        indicator="192.168.1.100",
        scope="private",
        external_ti_eligible=False,
    ),
    enriched=False,
    observation=None,
    skip_reason="ineligible_scope:private",
)

PUBLIC_ENRICHED_RESULT = ModSecurityEnrichmentResult(
    evidence=CONTROLLED_PUBLIC_EVIDENCE,
    scope=IndicatorScope(
        indicator="8.8.8.8",
        scope="public",
        external_ti_eligible=True,
    ),
    enriched=True,
    observation=SAMPLE_TI_OBSERVATION,
    skip_reason=None,
)


class TestWeb01IncidentRecordIntegration(unittest.TestCase):
    """Tests establishing the WEB01 ModSecurity incident record integration contract."""

    def _require_web01_incident_support(self) -> None:
        """Assert RED phase failure if WEB01 incident integration is not yet implemented."""
        if (
            build_modsecurity_incident_record is None
            or "modsecurity_evidence" not in getattr(IncidentRecord, "__dataclass_fields__", {})
        ):
            self.fail(
                "RED PHASE: build_modsecurity_incident_record or ModSecurity IncidentRecord "
                "extensions are not yet implemented"
            )

    # -------------------------------------------------------------------------
    # 1. LIVE-DERIVED OFFLINE WEB01 INCIDENT FIXTURE
    # -------------------------------------------------------------------------

    def test_live_derived_web01_incident_preserves_modsecurity_evidence(self) -> None:
        """WEB01 incident record preserves all 7 validated ModSecurity evidence fields."""
        self._require_web01_incident_support()

        record = build_modsecurity_incident_record(
            incident_id="INC-WEB01-001",
            evidence=LIVE_DERIVED_WEB01_EVIDENCE,
            enrichment=WEB01_INELIGIBLE_ENRICHMENT,
        )

        self.assertEqual(record.incident_id, "INC-WEB01-001")
        self.assertEqual(record.target_host, "web01")
        self.assertIsNotNone(record.modsecurity_evidence)
        ev = record.modsecurity_evidence
        self.assertEqual(ev.host, "web01")
        self.assertEqual(ev.src_ip, "192.168.1.100")
        self.assertEqual(ev.rule_id, 942100)
        self.assertEqual(ev.rule_msg, "SQL Injection Attack Detected via libinjection")
        self.assertEqual(ev.severity, "CRITICAL")
        self.assertEqual(ev.anomaly_score, 8)
        self.assertEqual(ev.unique_id, "ar1Z9uxU-NFJV-LskY52NwAAAEQ")

    def test_live_derived_web01_incident_threat_intel_state_is_skipped(self) -> None:
        """WEB01 private IP produces deterministic SKIPPED_INELIGIBLE threat intel state."""
        self._require_web01_incident_support()

        record = build_modsecurity_incident_record(
            incident_id="INC-WEB01-001",
            evidence=LIVE_DERIVED_WEB01_EVIDENCE,
            enrichment=WEB01_INELIGIBLE_ENRICHMENT,
        )

        self.assertEqual(record.threat_intel_status, "SKIPPED_INELIGIBLE")
        self.assertEqual(record.threat_intel_skip_reason, "ineligible_scope:private")
        self.assertIsNone(record.threat_intel_observation)

    # -------------------------------------------------------------------------
    # 2. CONTROLLED PUBLIC-IP FIXTURE (OFFLINE TEST FIXTURE)
    # -------------------------------------------------------------------------

    def test_offline_public_fixture_incident_preserves_enriched_observation(self) -> None:
        """Controlled public IP fixture produces ENRICHED state and preserves observation."""
        self._require_web01_incident_support()

        record = build_modsecurity_incident_record(
            incident_id="INC-WEB01-PUB01",
            evidence=CONTROLLED_PUBLIC_EVIDENCE,
            enrichment=PUBLIC_ENRICHED_RESULT,
        )

        self.assertEqual(record.modsecurity_evidence.src_ip, "8.8.8.8")
        self.assertEqual(record.threat_intel_status, "ENRICHED")
        self.assertIsNone(record.threat_intel_skip_reason)
        self.assertEqual(record.threat_intel_observation, SAMPLE_TI_OBSERVATION)
        self.assertEqual(record.threat_intel_observation.indicator, "8.8.8.8")
        self.assertEqual(record.threat_intel_observation.verdict, "CLEAN")

    # -------------------------------------------------------------------------
    # 3. SEMANTIC DISTINCTION FOR ENRICHMENT FAILURE
    # -------------------------------------------------------------------------

    def test_enrichment_failure_distinguished_from_skipped(self) -> None:
        """Provider lookup failure on eligible public IP produces LOOKUP_FAILED, not skipped."""
        self._require_web01_incident_support()

        record = build_modsecurity_incident_record(
            incident_id="INC-WEB01-FAIL01",
            evidence=CONTROLLED_PUBLIC_EVIDENCE,
            enrichment_failure_reason="VT provider transport failure",
        )

        self.assertEqual(record.threat_intel_status, "LOOKUP_FAILED")
        self.assertEqual(record.threat_intel_skip_reason, "VT provider transport failure")
        self.assertIsNone(record.threat_intel_observation)
        # Invariant: Must not be conflated with SKIPPED_INELIGIBLE
        self.assertNotEqual(record.threat_intel_status, "SKIPPED_INELIGIBLE")

    def test_lookup_failure_cannot_masquerade_as_ineligible_skip(self) -> None:
        """Fails closed if caller attempts to record a lookup failure with an ineligible reason."""
        self._require_web01_incident_support()

        with self.assertRaises(IncidentRecordError):
            build_modsecurity_incident_record(
                incident_id="INC-WEB01-BAD01",
                evidence=CONTROLLED_PUBLIC_EVIDENCE,
                threat_intel_status="SKIPPED_INELIGIBLE",
                threat_intel_skip_reason="lookup_failed:network error",
            )

    def test_rejects_both_enrichment_result_and_failure_reason(self) -> None:
        """Contradictory call with both enrichment_result and failure reason raises IncidentRecordError."""
        self._require_web01_incident_support()

        with self.assertRaises(IncidentRecordError):
            build_modsecurity_incident_record(
                incident_id="INC-WEB01-BAD08",
                evidence=CONTROLLED_PUBLIC_EVIDENCE,
                enrichment_result=PUBLIC_ENRICHED_RESULT,
                enrichment_failure_reason="VT provider transport failure",
            )

    def test_rejects_neither_enrichment_result_nor_failure_reason(self) -> None:
        """Call with neither enrichment_result nor failure reason raises IncidentRecordError."""
        self._require_web01_incident_support()

        with self.assertRaises(IncidentRecordError):
            build_modsecurity_incident_record(
                incident_id="INC-WEB01-BAD09",
                evidence=CONTROLLED_PUBLIC_EVIDENCE,
            )

    def test_rejects_invalid_enrichment_result_type(self) -> None:
        """Non-ModSecurityEnrichmentResult objects passed as enrichment_result raise IncidentRecordError."""
        self._require_web01_incident_support()

        with self.assertRaises((IncidentRecordError, TypeError)):
            build_modsecurity_incident_record(
                incident_id="INC-WEB01-BAD10",
                evidence=LIVE_DERIVED_WEB01_EVIDENCE,
                enrichment_result="invalid_enrichment_result",  # type: ignore[arg-type]
            )


    # -------------------------------------------------------------------------
    # 4. MODSECURITY ENRICHMENT RESULT BUILDER INTEGRATION
    # -------------------------------------------------------------------------

    def test_build_from_enrichment_result_ineligible_private(self) -> None:
        """Builder automatically derives SKIPPED_INELIGIBLE state from ModSecurityEnrichmentResult."""
        self._require_web01_incident_support()

        record = build_modsecurity_incident_record(
            incident_id="INC-WEB01-002",
            enrichment=WEB01_INELIGIBLE_ENRICHMENT,
        )

        self.assertEqual(record.target_host, "web01")
        self.assertEqual(record.threat_intel_status, "SKIPPED_INELIGIBLE")
        self.assertEqual(record.threat_intel_skip_reason, "ineligible_scope:private")
        self.assertIsNone(record.threat_intel_observation)

    def test_build_from_enrichment_result_enriched_public(self) -> None:
        """Builder automatically derives ENRICHED state from public ModSecurityEnrichmentResult."""
        self._require_web01_incident_support()

        record = build_modsecurity_incident_record(
            incident_id="INC-WEB01-003",
            enrichment=PUBLIC_ENRICHED_RESULT,
        )

        self.assertEqual(record.target_host, "web01")
        self.assertEqual(record.threat_intel_status, "ENRICHED")
        self.assertIsNone(record.threat_intel_skip_reason)
        self.assertIsNotNone(record.threat_intel_observation)
        self.assertEqual(record.threat_intel_observation.indicator, "8.8.8.8")

    # -------------------------------------------------------------------------
    # 5. SECURITY INVARIANTS & CONTRADICTORY STATE REJECTION
    # -------------------------------------------------------------------------

    def test_no_raw_modsecurity_text_in_serialized_incident(self) -> None:
        """Neither to_dict() nor to_json() contains raw ModSecurity audit log text."""
        self._require_web01_incident_support()

        record = build_modsecurity_incident_record(
            incident_id="INC-WEB01-SEC01",
            evidence=LIVE_DERIVED_WEB01_EVIDENCE,
            enrichment=WEB01_INELIGIBLE_ENRICHMENT,
        )

        dict_repr = record.to_dict()
        json_repr = record.to_json()

        self.assertNotIn("_raw", dict_repr)
        self.assertNotIn("--ar1Z9uxU", json_repr)
        self.assertNotIn("HTTP/1.1 403 Forbidden", json_repr)
        self.assertNotIn("Stopwatch:", json_repr)

    def test_no_raw_provider_json_or_secrets_in_serialized_incident(self) -> None:
        """Neither to_dict() nor to_json() contains raw provider JSON, tokens, or credentials."""
        self._require_web01_incident_support()

        record = build_modsecurity_incident_record(
            incident_id="INC-WEB01-SEC02",
            evidence=CONTROLLED_PUBLIC_EVIDENCE,
            enrichment=PUBLIC_ENRICHED_RESULT,
        )

        dict_repr = record.to_dict()
        json_repr = record.to_json()

        self.assertNotIn("api_key", json_repr)
        self.assertNotIn("VIRUSTOTAL", json_repr)
        self.assertNotIn("attributes", dict_repr)

    def test_rejects_contradictory_ti_state_skipped_with_observation(self) -> None:
        """Contradictory state (SKIPPED_INELIGIBLE with observation present) raises IncidentRecordError."""
        self._require_web01_incident_support()

        with self.assertRaises(IncidentRecordError):
            build_modsecurity_incident_record(
                incident_id="INC-WEB01-BAD02",
                evidence=LIVE_DERIVED_WEB01_EVIDENCE,
                threat_intel_status="SKIPPED_INELIGIBLE",
                threat_intel_skip_reason="ineligible_scope:private",
                threat_intel_observation=SAMPLE_TI_OBSERVATION,
            )

    def test_rejects_contradictory_ti_state_enriched_without_observation(self) -> None:
        """Contradictory state (ENRICHED but observation is None) raises IncidentRecordError."""
        self._require_web01_incident_support()

        with self.assertRaises(IncidentRecordError):
            build_modsecurity_incident_record(
                incident_id="INC-WEB01-BAD03",
                evidence=CONTROLLED_PUBLIC_EVIDENCE,
                threat_intel_status="ENRICHED",
                threat_intel_skip_reason=None,
                threat_intel_observation=None,
            )

    def test_rejects_contradictory_ti_state_enriched_with_skip_reason(self) -> None:
        """Contradictory state (ENRICHED with skip_reason present) raises IncidentRecordError."""
        self._require_web01_incident_support()

        with self.assertRaises(IncidentRecordError):
            build_modsecurity_incident_record(
                incident_id="INC-WEB01-BAD04",
                evidence=CONTROLLED_PUBLIC_EVIDENCE,
                threat_intel_status="ENRICHED",
                threat_intel_skip_reason="ineligible_scope:private",
                threat_intel_observation=SAMPLE_TI_OBSERVATION,
            )

    def test_rejects_contradictory_ti_state_skipped_without_reason(self) -> None:
        """Contradictory state (SKIPPED_INELIGIBLE without skip_reason) raises IncidentRecordError."""
        self._require_web01_incident_support()

        with self.assertRaises(IncidentRecordError):
            build_modsecurity_incident_record(
                incident_id="INC-WEB01-BAD05",
                evidence=LIVE_DERIVED_WEB01_EVIDENCE,
                threat_intel_status="SKIPPED_INELIGIBLE",
                threat_intel_skip_reason=None,
                threat_intel_observation=None,
            )

    def test_rejects_unauthorized_threat_intel_status(self) -> None:
        """Unauthorized threat_intel_status values fail closed."""
        self._require_web01_incident_support()

        with self.assertRaises(IncidentRecordError):
            build_modsecurity_incident_record(
                incident_id="INC-WEB01-BAD06",
                evidence=LIVE_DERIVED_WEB01_EVIDENCE,
                threat_intel_status="UNKNOWN_STATUS",
                threat_intel_skip_reason=None,
            )

    def test_rejects_invalid_modsecurity_evidence_type(self) -> None:
        """Non-ModSecuritySqliEvidence objects passed as evidence raise IncidentRecordError or TypeError."""
        self._require_web01_incident_support()

        bad_evidences = [
            {"src_ip": "192.168.1.100"},
            "raw_log_string",
            12345,
        ]
        for bad in bad_evidences:
            with self.subTest(bad=bad):
                with self.assertRaises((IncidentRecordError, TypeError)):
                    build_modsecurity_incident_record(
                        incident_id="INC-WEB01-BAD07",
                        evidence=bad,  # type: ignore[arg-type]
                    )

    def test_web01_attack_path_unambiguously_identified(self) -> None:
        """evidence_source identifies WEB01 ModSecurity without ambiguity."""
        self._require_web01_incident_support()

        record = build_modsecurity_incident_record(
            incident_id="INC-WEB01-004",
            evidence=LIVE_DERIVED_WEB01_EVIDENCE,
            enrichment=WEB01_INELIGIBLE_ENRICHMENT,
        )

        self.assertIn("ModSecurity", record.evidence_source)
        self.assertIn("WEB01", record.evidence_source.upper())

    def test_incident_record_immutability_with_modsecurity(self) -> None:
        """IncidentRecord is frozen and raises exception on attribute mutation."""
        self._require_web01_incident_support()

        record = build_modsecurity_incident_record(
            incident_id="INC-WEB01-005",
            evidence=LIVE_DERIVED_WEB01_EVIDENCE,
            enrichment=WEB01_INELIGIBLE_ENRICHMENT,
        )

        with self.assertRaises(Exception):
            record.threat_intel_status = "ENRICHED"  # type: ignore[misc]

    # -------------------------------------------------------------------------
    # 6. PRESERVATION OF EXISTING POWERSHELL & TICKETING BEHAVIOR
    # -------------------------------------------------------------------------

    def test_existing_powershell_incident_remains_valid_without_modsecurity(self) -> None:
        """Standard DC01/PowerShell incident without ModSecurity fields validates cleanly."""
        self._require_web01_incident_support()

        # Existing 24-field dictionary as tested in Milestone 5A
        ps_dict = {
            "schema_version": SCHEMA_VERSION,
            "incident_id": "INC-PS-001",
            "created_at_utc": "2026-09-18T20:00:00+00:00",
            "detection_id": "DET-POWERSHELL-001",
            "detection_name": "suspicious encoded powershell execution",
            "target_host": "DC01",
            "target_user": "SYSTEM",
            "evidence_source": "Live Splunk (localhost:8089)",
            "decoded_command": "Write-Host 'AI-NativeSOC-LAB-TEST'",
            "mitre_technique_id": "T1059.001",
            "investigation_summary": "Controlled benign lab administrative test script executed on DC01.",
            "confidence_level": "high",
            "suspicious_indicator_count": 0,
            "recommended_next_step": "No further action needed; benign verification confirmed.",
            "risk_score": 0,
            "risk_level": "LOW",
            "disposition": "NO_ACTION",
            "proposed_action": "no_action",
            "requires_human_approval": False,
            "policy_reason_codes": ("benign_lab_fixture_matched",),
            "approval_status": "NOT_REQUIRED",
            "approval_reason_code": None,
            "simulation_status": "NOT_EXECUTED",
            "simulation_detail_code": "simulation_not_required",
        }
        record = IncidentRecord(**ps_dict)
        self.assertIsNone(record.modsecurity_evidence)
        self.assertIsNone(record.threat_intel_status)
        self.assertIsNone(record.threat_intel_skip_reason)
        self.assertIsNone(record.threat_intel_observation)

    def test_ticket_request_generation_from_web01_incident(self) -> None:
        """Jira TicketRequest generates cleanly from a WEB01 ModSecurity incident record."""
        self._require_web01_incident_support()

        record = build_modsecurity_incident_record(
            incident_id="INC-WEB01-TKT01",
            evidence=LIVE_DERIVED_WEB01_EVIDENCE,
            enrichment=WEB01_INELIGIBLE_ENRICHMENT,
        )

        ticket_config = TicketConfig(
            project_key="SEC",
            issue_type="Incident",
            allowed_labels=("ai-native-soc", "approval-not-required", "action-not-executed"),
        )
        ticket_req = build_ticket_request(record, ticket_config)

        self.assertEqual(ticket_req.project_key, "SEC")
        self.assertIn("web01", ticket_req.summary.lower())
        self.assertIn("INC-WEB01-TKT01", ticket_req.summary)
        self.assertIn("ModSecurity", ticket_req.description)


if __name__ == "__main__":
    unittest.main()
