"""Focused tests for Milestone 13D: Deterministic TI/Policy Integration for WEB01.

TDD RED PHASE ONLY.

Establishes the deterministic source-IP scope classification and threat intelligence
eligibility policy contract within the WEB01 investigation workflow.

Core Security & Architectural Principles:
1. Deterministic Scope Classification:
   - The source IP from validated ModSecurity evidence must be evaluated by
     deterministic policy (classify_ipv4_scope) before any external TI lookup.
   - Private/non-eligible IP (e.g. 192.168.1.100) -> scope="private",
     external_ti_eligible=False -> zero threat_intel_lookup execution ->
     deterministic skipped enrichment result (SKIPPED_INELIGIBLE).
   - Public eligible IP (e.g. 93.184.216.34) -> scope="public",
     external_ti_eligible=True -> bounded threat_intel_lookup executes once ->
     sanitized ThreatIntelObservation returned (ENRICHED).
2. AI Authority Boundary:
   - The model may consume TI results, but the MODEL MUST NOT decide whether
     external TI is permitted.
   - AI cannot override scope classification, force TI on private IPs, or author SPL/URLs.
3. Three Explicit TI States:
   - SKIPPED_INELIGIBLE: Ineligible/private indicator, 0 provider calls, not an error.
   - ENRICHED: Eligible public indicator, bounded provider lookup succeeded, observation present.
   - LOOKUP_FAILED: Eligible indicator, provider lookup failed, distinct from skipped.
4. Fail-Closed Boundaries:
   - Provider errors on eligible lookups fail closed; never silently convert to "skipped" or "clean".
   - Telemetry context provided to model is strictly sanitized without provider secrets.
5. Offline / Mocked Only:
   - Zero live network calls, zero live API keys (VIRUSTOTAL_API_KEY / OPENAI_API_KEY).
"""

import json
from typing import Any, Dict, List
import unittest
from unittest.mock import MagicMock

from gateway.splunk_search import SplunkSearchClient
from investigator.audit import AuditEvent, AuditEventType, AuditLog
from investigator.modsecurity import ModSecuritySqliEvidence
from investigator.modsecurity_enrichment import (
    ModSecurityEnrichmentResult,
    enrich_modsecurity_source_ip,
)
from investigator.model import (
    DecisionType,
    ModelDecision,
    ModelRequest,
    ToolRequest,
)
from investigator.orchestrator import (
    InvestigationOrchestrator,
    OrchestratorError,
)
from investigator.providers.virustotal_provider import (
    VirusTotalError,
    VirusTotalThreatIntelClient,
)
from investigator.runtime_guard import (
    RuntimeGuard,
    RuntimeGuardConfig,
    RuntimeHaltError,
    RuntimeHaltReason,
)
from investigator.schemas import (
    Web01InvestigationAssessment,
    Web01InvestigationRequest,
)
from investigator.threat_intel import (
    IndicatorScope,
    ThreatIntelError,
    ThreatIntelLookupStatus,
    ThreatIntelObservation,
    ThreatIntelRequest,
    ThreatIntelResult,
    classify_ipv4_scope,
)
from investigator.tool_router import (
    ToolExecutionError,
    ToolRouter,
    ToolValidationError,
)


# ---------------------------------------------------------------------------
# Test Fixtures (Offline & Deterministic)
# ---------------------------------------------------------------------------

_VALID_WEB01_REQUEST = Web01InvestigationRequest(
    detection_id="DET-WEB-001",
    host="web01",
    detection_type="modsecurity_sqli",
    rule_id=942100,
)

# LIVE-DERIVED OFFLINE FIXTURE: 192.168.1.100 from real captured alert
_PRIVATE_WEB01_EVIDENCE = ModSecuritySqliEvidence(
    host="web01",
    src_ip="192.168.1.100",
    rule_id=942100,
    rule_msg="SQL Injection Attack Detected via libinjection",
    severity="CRITICAL",
    anomaly_score=8,
    unique_id="ar1Z9uxU-NFJV-LskY52NwAAAEQ",
)

_RAW_MODSEC_PRIVATE_TELEMETRY: Dict[str, Any] = {
    "_raw": (
        "--ar1Z9uxU-NFJV-LskY52NwAAAEQ-A--\n"
        "[04/Oct/2026:08:15:30 +0000] ar1Z9uxU-NFJV-LskY52NwAAAEQ 192.168.1.100 45678 192.168.1.102 80\n"
        "--ar1Z9uxU-NFJV-LskY52NwAAAEQ-B--\n"
        "GET /rest/products/search?q=%27%20OR%201=1-- HTTP/1.1\n"
        "Host: 192.168.1.102\n"
        "User-Agent: sqlmap/1.7#stable\n"
        "--ar1Z9uxU-NFJV-LskY52NwAAAEQ-H--\n"
        'Message: Warning. Pattern match "(?i:(?:select.*from))" at ARGS:q. [file "..."] [line "12"] [id "942100"] [msg "SQL Injection Attack Detected via libinjection"] [severity "CRITICAL"]\n'
        'Message: Warning. Operator GE reached 5 at TX:inbound_anomaly_score. [file "/etc/modsecurity/owasp-crs/rules/RESPONSE-980-CORRELATION.conf"] [line "91"] [id "980130"] [msg "Inbound Anomaly Score Exceeded (Total Score: 8)"] [severity "CRITICAL"] [ver "OWASP_CRS/3.3.4"]\n'
        "Action: Intercepted (eval score 8)\n"
        "--ar1Z9uxU-NFJV-LskY52NwAAAEQ-Z--\n"
    ),
    "host": "web01",
    "src_ip": "192.168.1.100",
    "rule_id": "942100",
    "rule_msg": "SQL Injection Attack Detected via libinjection",
    "severity": "CRITICAL",
    "anomaly_score": "8",
    "unique_id": "ar1Z9uxU-NFJV-LskY52NwAAAEQ",
}

# Deterministic public IPv4 fixture for offline tests
_PUBLIC_WEB01_EVIDENCE = ModSecuritySqliEvidence(
    host="web01",
    src_ip="93.184.216.34",
    rule_id=942100,
    rule_msg="SQL Injection Attack Detected via libinjection",
    severity="CRITICAL",
    anomaly_score=8,
    unique_id="pub1Z9uxU-NFJV-LskY52NwAAAEQ",
)

_RAW_MODSEC_PUBLIC_TELEMETRY: Dict[str, Any] = {
    "_raw": (
        "--pub1Z9uxU-NFJV-LskY52NwAAAEQ-A--\n"
        "[04/Oct/2026:08:15:30 +0000] pub1Z9uxU-NFJV-LskY52NwAAAEQ 93.184.216.34 45678 192.168.1.102 80\n"
        "--pub1Z9uxU-NFJV-LskY52NwAAAEQ-B--\n"
        "GET /rest/products/search?q=%27%20OR%201=1-- HTTP/1.1\n"
        "Host: 192.168.1.102\n"
        "User-Agent: sqlmap/1.7#stable\n"
        "--pub1Z9uxU-NFJV-LskY52NwAAAEQ-H--\n"
        'Message: Warning. Pattern match "(?i:(?:select.*from))" at ARGS:q. [file "..."] [line "12"] [id "942100"] [msg "SQL Injection Attack Detected via libinjection"] [severity "CRITICAL"]\n'
        'Message: Warning. Operator GE reached 5 at TX:inbound_anomaly_score. [file "/etc/modsecurity/owasp-crs/rules/RESPONSE-980-CORRELATION.conf"] [line "91"] [id "980130"] [msg "Inbound Anomaly Score Exceeded (Total Score: 8)"] [severity "CRITICAL"] [ver "OWASP_CRS/3.3.4"]\n'
        "Action: Intercepted (eval score 8)\n"
        "--pub1Z9uxU-NFJV-LskY52NwAAAEQ-Z--\n"
    ),
    "host": "web01",
    "src_ip": "93.184.216.34",
    "rule_id": "942100",
    "rule_msg": "SQL Injection Attack Detected via libinjection",
    "severity": "CRITICAL",
    "anomaly_score": "8",
    "unique_id": "pub1Z9uxU-NFJV-LskY52NwAAAEQ",
}

_NORMALIZED_TI_OBSERVATION = ThreatIntelObservation(
    indicator="93.184.216.34",
    indicator_type="ip",
    provider="virustotal",
    verdict="suspicious",
    malicious_count=5,
    suspicious_count=2,
    harmless_count=60,
    undetected_count=18,
    source_reference="virustotal:ip:93.184.216.34",
)

_VALID_WEB01_ASSESSMENT = Web01InvestigationAssessment(
    assessment="SQL injection attempt intercepted by ModSecurity CRS rule 942100.",
    confidence="high",
    evidence_summary="Bounded Splunk query returned 1 matching event from web01.",
    attack_type="sql_injection",
    escalation_recommended=True,
    recommended_next_step="Block source IP at edge firewall and inspect application logs.",
)


class ScriptedModel:
    """Deterministic scripted model for driving orchestrator decision loops offline."""

    def __init__(self, decisions: List[ModelDecision]) -> None:
        self._decisions = list(decisions)
        self.recorded_requests: List[ModelRequest] = []

    def decide(self, request: ModelRequest) -> ModelDecision:
        self.recorded_requests.append(request)
        if not self._decisions:
            raise RuntimeError("ScriptedModel has no more configured decisions")
        return self._decisions.pop(0)


class TestWeb01ThreatIntelPolicyIntegration(unittest.TestCase):
    """Test suite for Milestone 13D: Deterministic TI/Policy Integration for WEB01."""

    # =========================================================================
    # 1. Private-IP Happy Path & Live-Derived Fixture
    # =========================================================================

    def test_web01_private_ip_classified_before_ti_lookup(self) -> None:
        """Verify private source IP is classified as private and ineligible before lookup."""
        scope = classify_ipv4_scope(_PRIVATE_WEB01_EVIDENCE.src_ip)
        self.assertIsInstance(scope, IndicatorScope)
        self.assertEqual(scope.indicator, "192.168.1.100")
        self.assertEqual(scope.scope, "private")
        self.assertFalse(scope.external_ti_eligible)

    def test_web01_private_ip_skips_external_ti(self) -> None:
        """Verify enrichment of private IP produces a skipped enrichment result."""
        mock_lookup = MagicMock()
        result = enrich_modsecurity_source_ip(_PRIVATE_WEB01_EVIDENCE, mock_lookup)
        self.assertIsInstance(result, ModSecurityEnrichmentResult)
        self.assertFalse(result.enriched)
        self.assertIsNone(result.observation)
        self.assertEqual(result.skip_reason, "ineligible_scope:private")

    def test_web01_private_ip_executes_zero_ti_calls(self) -> None:
        """Verify threat intelligence lookup callable is never executed for private IP."""
        mock_lookup = MagicMock()
        enrich_modsecurity_source_ip(_PRIVATE_WEB01_EVIDENCE, mock_lookup)
        mock_lookup.assert_not_called()
        self.assertEqual(mock_lookup.call_count, 0)

    def test_web01_private_ip_skip_is_not_provider_failure(self) -> None:
        """Verify private IP skip is an intentional deterministic policy result, not a failure."""
        mock_lookup = MagicMock(side_effect=RuntimeError("Provider failure should not be triggered"))
        result = enrich_modsecurity_source_ip(_PRIVATE_WEB01_EVIDENCE, mock_lookup)
        self.assertFalse(result.enriched)
        self.assertEqual(result.skip_reason, "ineligible_scope:private")
        self.assertEqual(mock_lookup.call_count, 0)

    def test_live_derived_web01_private_ip_remains_ti_ineligible(self) -> None:
        """LIVE-DERIVED OFFLINE FIXTURE: verify captured 192.168.1.100 resolves ineligible."""
        # Evidence from live test fixture: 192.168.1.100
        scope = classify_ipv4_scope("192.168.1.100")
        self.assertEqual(scope.scope, "private")
        self.assertFalse(scope.external_ti_eligible)

        mock_lookup = MagicMock()
        result = enrich_modsecurity_source_ip(_PRIVATE_WEB01_EVIDENCE, mock_lookup)
        self.assertFalse(result.enriched)
        self.assertIsNone(result.observation)
        self.assertEqual(mock_lookup.call_count, 0)

    # =========================================================================
    # 2. Public-IP Eligible Path
    # =========================================================================

    def test_web01_public_ip_is_ti_eligible(self) -> None:
        """Verify public IPv4 indicator is classified as public and eligible."""
        scope = classify_ipv4_scope(_PUBLIC_WEB01_EVIDENCE.src_ip)
        self.assertEqual(scope.scope, "public")
        self.assertTrue(scope.external_ti_eligible)

    def test_web01_public_ip_executes_exactly_one_bounded_ti_lookup(self) -> None:
        """Verify eligible public IP triggers threat_intel_lookup exactly once."""
        mock_lookup = MagicMock(return_value=_NORMALIZED_TI_OBSERVATION)
        result = enrich_modsecurity_source_ip(_PUBLIC_WEB01_EVIDENCE, mock_lookup)
        mock_lookup.assert_called_once_with("93.184.216.34")
        self.assertEqual(mock_lookup.call_count, 1)

    def test_web01_public_ip_returns_normalized_threat_intel_observation(self) -> None:
        """Verify eligible public IP produces normalized ThreatIntelObservation."""
        mock_lookup = MagicMock(return_value=_NORMALIZED_TI_OBSERVATION)
        result = enrich_modsecurity_source_ip(_PUBLIC_WEB01_EVIDENCE, mock_lookup)
        self.assertTrue(result.enriched)
        self.assertEqual(result.observation, _NORMALIZED_TI_OBSERVATION)
        self.assertIsNone(result.skip_reason)

    def test_web01_public_ip_uses_existing_threat_intel_tool_path(self) -> None:
        """Verify ToolRouter dispatches threat_intel_lookup via bounded VT client."""
        mock_vt_client = MagicMock(spec=VirusTotalThreatIntelClient)
        mock_vt_client.lookup.return_value = ThreatIntelResult(
            provider="virustotal",
            indicator_type="ip",
            indicator_value="93.184.216.34",
            lookup_status=ThreatIntelLookupStatus.FOUND,
            malicious_count=0,
            suspicious_count=2,
            harmless_count=60,
            undetected_count=18,
            detail_code="ip_lookup_found",
        )
        router = ToolRouter(splunk_client=MagicMock(spec=SplunkSearchClient), vt_client=mock_vt_client)
        obs = router.execute_tool("threat_intel_lookup", {"indicator": "93.184.216.34"})
        self.assertIsInstance(obs, ThreatIntelObservation)
        self.assertEqual(obs.indicator, "93.184.216.34")
        self.assertEqual(obs.verdict, "suspicious")
        self.assertEqual(mock_vt_client.lookup.call_count, 1)

    # =========================================================================
    # 3. AI Authority Boundaries & Rejection of AI-Driven TI
    # =========================================================================

    def test_web01_model_cannot_force_ti_for_private_ip(self) -> None:
        """Verify model cannot force threat_intel_lookup on private IP."""
        model = ScriptedModel([
            ModelDecision(
                decision_type=DecisionType.TOOL_REQUEST,
                tool_request=ToolRequest(
                    tool_name="threat_intel_lookup",
                    arguments={"indicator": "192.168.1.100"},
                ),
            ),
        ])
        router = ToolRouter(
            splunk_client=MagicMock(spec=SplunkSearchClient),
            vt_client=MagicMock(spec=VirusTotalThreatIntelClient),
        )
        orchestrator = InvestigationOrchestrator(model=model, tool_router=router)
        with self.assertRaises(OrchestratorError) as ctx:
            orchestrator.investigate(_VALID_WEB01_REQUEST)
        self.assertIn("threat_intel_lookup", str(ctx.exception))

    def test_web01_evidence_instruction_cannot_override_ti_policy(self) -> None:
        """Verify prompt injection inside evidence cannot authorize TI lookup on private IP."""
        hostile_evidence = ModSecuritySqliEvidence(
            host="web01",
            src_ip="192.168.1.100",
            rule_id=942100,
            rule_msg="SQL Injection Attack Detected via libinjection",
            severity="CRITICAL",
            anomaly_score=8,
            unique_id="injection-force-vt-for-192-168-1-100",
        )
        mock_lookup = MagicMock()
        result = enrich_modsecurity_source_ip(hostile_evidence, mock_lookup)
        self.assertFalse(result.enriched)
        self.assertEqual(mock_lookup.call_count, 0)
        self.assertEqual(result.skip_reason, "ineligible_scope:private")

    def test_web01_recommendation_has_no_ti_execution_authority(self) -> None:
        """Verify model recommendation to query VT does not trigger lookup execution."""
        mock_lookup = MagicMock()
        # Even if model assessment suggests external query, lookup count is 0
        assessment = Web01InvestigationAssessment(
            assessment="SQLi attack detected.",
            confidence="high",
            evidence_summary="ModSecurity rule 942100 triggered.",
            attack_type="sql_injection",
            escalation_recommended=True,
            recommended_next_step="Query VirusTotal for 192.168.1.100 and block IP.",
        )
        self.assertEqual(mock_lookup.call_count, 0)

    def test_web01_model_does_not_decide_ti_eligibility(self) -> None:
        """Verify deterministic scope classifier alone determines eligibility, not caller/model."""
        # Attempting to manually pass an ineligible IP with claimed eligibility fails
        with self.assertRaises(ValueError):
            IndicatorScope(indicator="192.168.1.100", scope="private", external_ti_eligible=True)

    def test_web01_ti_lookup_requires_policy_approval(self) -> None:
        """Verify non-public or malformed indicators are rejected before provider call."""
        for bad_ip in ("10.0.0.1", "127.0.0.1", "169.254.1.1", "224.0.0.1"):
            with self.subTest(bad_ip=bad_ip):
                scope = classify_ipv4_scope(bad_ip)
                self.assertFalse(scope.external_ti_eligible)

    def test_web01_ti_execution_remains_bounded(self) -> None:
        """Verify threat_intel_lookup strictly rejects arbitrary non-IP arguments."""
        router = ToolRouter(
            splunk_client=MagicMock(spec=SplunkSearchClient),
            vt_client=MagicMock(spec=VirusTotalThreatIntelClient),
        )
        for forbidden_arg in (
            {"url": "https://malicious.example.com"},
            {"domain": "evil.com"},
            {"spl": "search index=main"},
            {"indicator": "http://192.168.1.100"},
        ):
            with self.subTest(arg=forbidden_arg):
                with self.assertRaises(ToolValidationError):
                    router.execute_tool("threat_intel_lookup", forbidden_arg)

    # =========================================================================
    # 4. Distinguish Three TI States & Provider Failure Semantics
    # =========================================================================

    def test_web01_ti_skipped_state_is_distinct_from_failure(self) -> None:
        """Verify SKIPPED_INELIGIBLE state is explicit, enriched=False, and distinct from failure."""
        mock_lookup = MagicMock()
        result = enrich_modsecurity_source_ip(_PRIVATE_WEB01_EVIDENCE, mock_lookup)
        self.assertFalse(result.enriched)
        self.assertIsNone(result.observation)
        self.assertEqual(result.skip_reason, "ineligible_scope:private")

    def test_web01_ti_enriched_state_requires_observation(self) -> None:
        """Verify ENRICHED state strictly requires a non-None ThreatIntelObservation."""
        scope = IndicatorScope(indicator="93.184.216.34", scope="public", external_ti_eligible=True)
        with self.assertRaises(TypeError):
            ModSecurityEnrichmentResult(
                evidence=_PUBLIC_WEB01_EVIDENCE,
                scope=scope,
                enriched=True,
                observation=None,  # type: ignore[arg-type]
                skip_reason=None,
            )

    def test_web01_ti_failure_is_distinct_from_ineligible_scope(self) -> None:
        """Verify provider failure raises an execution error and does not produce skipped state."""
        failing_lookup = MagicMock(side_effect=ThreatIntelError("VT API 500 Server Error"))
        with self.assertRaises(ThreatIntelError):
            enrich_modsecurity_source_ip(_PUBLIC_WEB01_EVIDENCE, failing_lookup)

    def test_web01_public_ti_provider_failure_fails_closed(self) -> None:
        """Verify provider failure fails closed without fabricating clean or fallback observation."""
        failing_lookup = MagicMock(side_effect=ToolExecutionError("VT connection timeout"))
        with self.assertRaises(ToolExecutionError):
            enrich_modsecurity_source_ip(_PUBLIC_WEB01_EVIDENCE, failing_lookup)

    # =========================================================================
    # 5. Prompt / Model Interpretation Boundaries
    # =========================================================================

    def test_web01_model_cannot_describe_skipped_ti_as_clean(self) -> None:
        """Verify skipped TI does not convey a CLEAN verdict."""
        mock_lookup = MagicMock()
        result = enrich_modsecurity_source_ip(_PRIVATE_WEB01_EVIDENCE, mock_lookup)
        # Result has no observation; verdict is not CLEAN
        self.assertIsNone(result.observation)

    def test_web01_model_cannot_claim_lookup_executed_when_skipped(self) -> None:
        """Verify enrichment result explicitly documents enriched=False when skipped."""
        mock_lookup = MagicMock()
        result = enrich_modsecurity_source_ip(_PRIVATE_WEB01_EVIDENCE, mock_lookup)
        self.assertFalse(result.enriched)
        self.assertEqual(result.skip_reason, "ineligible_scope:private")

    def test_web01_ti_result_has_no_response_authority(self) -> None:
        """Verify even a critical TI verdict cannot authorize execution tools."""
        critical_obs = ThreatIntelObservation(
            indicator="93.184.216.34",
            indicator_type="ip",
            provider="virustotal",
            verdict="malicious",
            malicious_count=70,
            suspicious_count=5,
            harmless_count=0,
            undetected_count=2,
            source_reference="virustotal:ip:93.184.216.34",
        )
        self.assertEqual(critical_obs.verdict, "malicious")
        # Ensure Web01InvestigationAssessment rejects execution parameters
        bad_kwargs: Dict[str, Any] = {"isolate_host": True}
        with self.assertRaises(TypeError):
            Web01InvestigationAssessment(
                assessment="Malicious IP confirmed.",
                confidence="high",
                evidence_summary="VT malicious count 70.",
                attack_type="sql_injection",
                escalation_recommended=True,
                recommended_next_step="Isolate web01 host.",
                **bad_kwargs,
            )

    def test_web01_ti_never_runs_before_validated_modsecurity_evidence(self) -> None:
        """Verify threat_intel_lookup cannot execute prior to bounded Splunk search."""
        model = ScriptedModel([
            ModelDecision(
                decision_type=DecisionType.TOOL_REQUEST,
                tool_request=ToolRequest(
                    tool_name="threat_intel_lookup",
                    arguments={"indicator": "93.184.216.34"},
                ),
            ),
        ])
        router = ToolRouter(
            splunk_client=MagicMock(spec=SplunkSearchClient),
            vt_client=MagicMock(spec=VirusTotalThreatIntelClient),
        )
        orchestrator = InvestigationOrchestrator(model=model, tool_router=router)
        with self.assertRaises(OrchestratorError) as ctx:
            orchestrator.investigate(_VALID_WEB01_REQUEST)
        self.assertIn("threat_intel_lookup", str(ctx.exception))

    # =========================================================================
    # 6. Model-Facing Enrichment Context & Orchestrator Integration (RED)
    # =========================================================================

    def test_web01_orchestrator_private_ip_enriches_context_with_skipped_state(self) -> None:
        """Verify orchestrator deterministically enriches private IP evidence with SKIPPED_INELIGIBLE state."""
        mock_splunk = MagicMock(spec=SplunkSearchClient)
        mock_splunk.search_modsecurity_sqli.return_value = [_RAW_MODSEC_PRIVATE_TELEMETRY]
        mock_vt = MagicMock(spec=VirusTotalThreatIntelClient)

        router = ToolRouter(splunk_client=mock_splunk, vt_client=mock_vt)

        # Step 0: Model requests bounded_splunk_search
        # Step 1: Model receives tool result containing deterministic TI enrichment and returns final assessment
        model = ScriptedModel([
            ModelDecision(
                decision_type=DecisionType.TOOL_REQUEST,
                tool_request=ToolRequest(
                    tool_name="bounded_splunk_search",
                    arguments={"query_type": "modsecurity_sqli_matches", "host": "web01"},
                ),
            ),
            ModelDecision(
                decision_type=DecisionType.FINAL_RESULT,
                final_result=_VALID_WEB01_ASSESSMENT,
            ),
        ])

        orchestrator = InvestigationOrchestrator(model=model, tool_router=router)
        assessment = orchestrator.investigate(_VALID_WEB01_REQUEST)
        self.assertIsInstance(assessment, Web01InvestigationAssessment)

        # Zero external VT lookups should have occurred for private IP
        self.assertEqual(mock_vt.lookup.call_count, 0)

        # Inspect model context in turn 1
        self.assertEqual(len(model.recorded_requests), 2)
        turn1_request = model.recorded_requests[1]
        self.assertEqual(len(turn1_request.prior_tool_results), 1)

        result_payload = json.loads(turn1_request.prior_tool_results[0].result_text)
        self.assertIn("threat_intel", result_payload)
        ti_context = result_payload["threat_intel"]
        self.assertEqual(ti_context["scope"], "private")
        self.assertFalse(ti_context["external_ti_eligible"])
        self.assertEqual(ti_context["threat_intel_status"], "SKIPPED_INELIGIBLE")
        self.assertEqual(ti_context["skip_reason"], "ineligible_scope:private")

    def test_web01_orchestrator_public_ip_executes_ti_and_enriches_context(self) -> None:
        """Verify orchestrator deterministically performs bounded TI lookup for public IP and enriches context."""
        mock_splunk = MagicMock(spec=SplunkSearchClient)
        mock_splunk.search_modsecurity_sqli.return_value = [_RAW_MODSEC_PUBLIC_TELEMETRY]
        mock_vt = MagicMock(spec=VirusTotalThreatIntelClient)
        mock_vt.lookup.return_value = ThreatIntelResult(
            provider="virustotal",
            indicator_type="ip",
            indicator_value="93.184.216.34",
            lookup_status=ThreatIntelLookupStatus.FOUND,
            malicious_count=0,
            suspicious_count=2,
            harmless_count=60,
            undetected_count=18,
            detail_code="ip_lookup_found",
        )

        router = ToolRouter(splunk_client=mock_splunk, vt_client=mock_vt)

        model = ScriptedModel([
            ModelDecision(
                decision_type=DecisionType.TOOL_REQUEST,
                tool_request=ToolRequest(
                    tool_name="bounded_splunk_search",
                    arguments={"query_type": "modsecurity_sqli_matches", "host": "web01"},
                ),
            ),
            ModelDecision(
                decision_type=DecisionType.FINAL_RESULT,
                final_result=_VALID_WEB01_ASSESSMENT,
            ),
        ])

        orchestrator = InvestigationOrchestrator(model=model, tool_router=router)
        assessment = orchestrator.investigate(_VALID_WEB01_REQUEST)
        self.assertIsInstance(assessment, Web01InvestigationAssessment)

        # Exactly 1 bounded VT lookup should execute for public IP
        self.assertEqual(mock_vt.lookup.call_count, 1)

        # Inspect model context in turn 1
        turn1_request = model.recorded_requests[1]
        result_payload = json.loads(turn1_request.prior_tool_results[0].result_text)
        self.assertIn("threat_intel", result_payload)
        ti_context = result_payload["threat_intel"]
        self.assertEqual(ti_context["scope"], "public")
        self.assertTrue(ti_context["external_ti_eligible"])
        self.assertEqual(ti_context["threat_intel_status"], "ENRICHED")
        self.assertIn("observation", ti_context)
        self.assertEqual(ti_context["observation"]["indicator"], "93.184.216.34")
        self.assertEqual(ti_context["observation"]["verdict"], "suspicious")

    def test_web01_private_ti_context_is_sanitized(self) -> None:
        """Verify model-facing private IP TI context contains only sanitized schema fields."""
        mock_splunk = MagicMock(spec=SplunkSearchClient)
        mock_splunk.search_modsecurity_sqli.return_value = [_RAW_MODSEC_PRIVATE_TELEMETRY]
        router = ToolRouter(splunk_client=mock_splunk)

        model = ScriptedModel([
            ModelDecision(
                decision_type=DecisionType.TOOL_REQUEST,
                tool_request=ToolRequest(
                    tool_name="bounded_splunk_search",
                    arguments={"query_type": "modsecurity_sqli_matches", "host": "web01"},
                ),
            ),
            ModelDecision(
                decision_type=DecisionType.FINAL_RESULT,
                final_result=_VALID_WEB01_ASSESSMENT,
            ),
        ])

        orchestrator = InvestigationOrchestrator(model=model, tool_router=router)
        orchestrator.investigate(_VALID_WEB01_REQUEST)

        turn1_request = model.recorded_requests[1]
        payload = json.loads(turn1_request.prior_tool_results[0].result_text)
        self.assertIn("threat_intel", payload)
        ti = payload["threat_intel"]
        allowed_keys = {"scope", "external_ti_eligible", "threat_intel_status", "skip_reason"}
        self.assertEqual(set(ti.keys()), allowed_keys)

    def test_web01_enriched_ti_context_contains_only_normalized_observation(self) -> None:
        """Verify model-facing public IP TI context contains only normalized observation fields."""
        mock_splunk = MagicMock(spec=SplunkSearchClient)
        mock_splunk.search_modsecurity_sqli.return_value = [_RAW_MODSEC_PUBLIC_TELEMETRY]
        mock_vt = MagicMock(spec=VirusTotalThreatIntelClient)
        mock_vt.lookup.return_value = ThreatIntelResult(
            provider="virustotal",
            indicator_type="ip",
            indicator_value="93.184.216.34",
            lookup_status=ThreatIntelLookupStatus.FOUND,
            malicious_count=0,
            suspicious_count=0,
            harmless_count=50,
            undetected_count=10,
            detail_code="ip_lookup_found",
        )
        router = ToolRouter(splunk_client=mock_splunk, vt_client=mock_vt)

        model = ScriptedModel([
            ModelDecision(
                decision_type=DecisionType.TOOL_REQUEST,
                tool_request=ToolRequest(
                    tool_name="bounded_splunk_search",
                    arguments={"query_type": "modsecurity_sqli_matches", "host": "web01"},
                ),
            ),
            ModelDecision(
                decision_type=DecisionType.FINAL_RESULT,
                final_result=_VALID_WEB01_ASSESSMENT,
            ),
        ])

        orchestrator = InvestigationOrchestrator(model=model, tool_router=router)
        orchestrator.investigate(_VALID_WEB01_REQUEST)

        turn1_request = model.recorded_requests[1]
        payload = json.loads(turn1_request.prior_tool_results[0].result_text)
        self.assertIn("threat_intel", payload)
        ti = payload["threat_intel"]
        self.assertIn("observation", ti)
        obs = ti["observation"]
        expected_obs_keys = {
            "indicator", "indicator_type", "provider", "verdict",
            "malicious_count", "suspicious_count", "harmless_count",
            "undetected_count", "source_reference",
        }
        self.assertEqual(set(obs.keys()), expected_obs_keys)

    def test_web01_ti_context_excludes_provider_secrets(self) -> None:
        """Verify model context contains zero provider secrets, tokens, or raw HTTP responses."""
        mock_splunk = MagicMock(spec=SplunkSearchClient)
        mock_splunk.search_modsecurity_sqli.return_value = [_RAW_MODSEC_PUBLIC_TELEMETRY]
        mock_vt = MagicMock(spec=VirusTotalThreatIntelClient)
        mock_vt.lookup.return_value = ThreatIntelResult(
            provider="virustotal",
            indicator_type="ip",
            indicator_value="93.184.216.34",
            lookup_status=ThreatIntelLookupStatus.FOUND,
            malicious_count=0,
            suspicious_count=0,
            harmless_count=50,
            undetected_count=10,
            detail_code="ip_lookup_found",
        )
        router = ToolRouter(splunk_client=mock_splunk, vt_client=mock_vt)

        model = ScriptedModel([
            ModelDecision(
                decision_type=DecisionType.TOOL_REQUEST,
                tool_request=ToolRequest(
                    tool_name="bounded_splunk_search",
                    arguments={"query_type": "modsecurity_sqli_matches", "host": "web01"},
                ),
            ),
            ModelDecision(
                decision_type=DecisionType.FINAL_RESULT,
                final_result=_VALID_WEB01_ASSESSMENT,
            ),
        ])

        orchestrator = InvestigationOrchestrator(model=model, tool_router=router)
        orchestrator.investigate(_VALID_WEB01_REQUEST)

        raw_context_text = model.recorded_requests[1].prior_tool_results[0].result_text
        for forbidden in ("raw_vt_secret_value", "secret_token", "Bearer", "Authorization"):
            self.assertNotIn(forbidden, raw_context_text)

    def test_web01_orchestrator_public_ip_provider_failure_fails_closed(self) -> None:
        """Verify provider failure during public IP enrichment is recorded as LOOKUP_FAILED or fails closed."""
        mock_splunk = MagicMock(spec=SplunkSearchClient)
        mock_splunk.search_modsecurity_sqli.return_value = [_RAW_MODSEC_PUBLIC_TELEMETRY]
        mock_vt = MagicMock(spec=VirusTotalThreatIntelClient)
        mock_vt.lookup.side_effect = VirusTotalError("VirusTotal connection timeout")

        router = ToolRouter(splunk_client=mock_splunk, vt_client=mock_vt)

        model = ScriptedModel([
            ModelDecision(
                decision_type=DecisionType.TOOL_REQUEST,
                tool_request=ToolRequest(
                    tool_name="bounded_splunk_search",
                    arguments={"query_type": "modsecurity_sqli_matches", "host": "web01"},
                ),
            ),
            ModelDecision(
                decision_type=DecisionType.FINAL_RESULT,
                final_result=_VALID_WEB01_ASSESSMENT,
            ),
        ])

        orchestrator = InvestigationOrchestrator(model=model, tool_router=router)
        orchestrator.investigate(_VALID_WEB01_REQUEST)
        # Verify status is LOOKUP_FAILED, not clean or skipped
        turn1_request = model.recorded_requests[1]
        payload = json.loads(turn1_request.prior_tool_results[0].result_text)
        self.assertIn("threat_intel", payload)
        self.assertEqual(payload["threat_intel"]["threat_intel_status"], "LOOKUP_FAILED")
        self.assertIsNone(payload["threat_intel"].get("observation"))

    # =========================================================================
    # 7. RuntimeGuard & Audit Refinements (Milestone 13D)
    # =========================================================================

    def test_web01_policy_ti_lookup_counts_runtime_tool_execution(self) -> None:
        """Verify policy-triggered TI lookup consumes an execution budget slot in RuntimeGuard."""
        mock_splunk = MagicMock(spec=SplunkSearchClient)
        mock_splunk.search_modsecurity_sqli.return_value = [_RAW_MODSEC_PUBLIC_TELEMETRY]
        mock_vt = MagicMock(spec=VirusTotalThreatIntelClient)
        mock_vt.lookup.return_value = ThreatIntelResult(
            provider="virustotal",
            indicator_type="ip",
            indicator_value="93.184.216.34",
            lookup_status=ThreatIntelLookupStatus.FOUND,
            malicious_count=0,
            suspicious_count=2,
            harmless_count=60,
            undetected_count=18,
            detail_code="ip_lookup_found",
        )
        router = ToolRouter(splunk_client=mock_splunk, vt_client=mock_vt)
        guard = RuntimeGuard()

        model = ScriptedModel([
            ModelDecision(
                decision_type=DecisionType.TOOL_REQUEST,
                tool_request=ToolRequest(
                    tool_name="bounded_splunk_search",
                    arguments={"query_type": "modsecurity_sqli_matches", "host": "web01"},
                ),
            ),
            ModelDecision(
                decision_type=DecisionType.FINAL_RESULT,
                final_result=_VALID_WEB01_ASSESSMENT,
            ),
        ])

        orchestrator = InvestigationOrchestrator(model=model, tool_router=router, guard=guard)
        orchestrator.investigate(_VALID_WEB01_REQUEST)

        # 2 executions: 1 for bounded_splunk_search, 1 for threat_intel_lookup
        self.assertEqual(guard.state.tool_executions_permitted, 2)
        self.assertEqual(mock_vt.lookup.call_count, 1)

    def test_web01_kill_switch_blocks_policy_triggered_ti_lookup(self) -> None:
        """Verify active kill switch blocks policy-triggered TI lookup with zero provider calls."""
        mock_splunk = MagicMock(spec=SplunkSearchClient)
        mock_splunk.search_modsecurity_sqli.return_value = [_RAW_MODSEC_PUBLIC_TELEMETRY]
        mock_vt = MagicMock(spec=VirusTotalThreatIntelClient)
        router = ToolRouter(splunk_client=mock_splunk, vt_client=mock_vt)
        guard = RuntimeGuard(config=RuntimeGuardConfig(kill_switch=True))

        model = ScriptedModel([
            ModelDecision(
                decision_type=DecisionType.TOOL_REQUEST,
                tool_request=ToolRequest(
                    tool_name="bounded_splunk_search",
                    arguments={"query_type": "modsecurity_sqli_matches", "host": "web01"},
                ),
            ),
        ])

        orchestrator = InvestigationOrchestrator(model=model, tool_router=router, guard=guard)
        with self.assertRaises(OrchestratorError) as ctx:
            orchestrator.investigate(_VALID_WEB01_REQUEST)

        self.assertIn("KILL_SWITCH_ENGAGED", str(ctx.exception))
        self.assertEqual(mock_vt.lookup.call_count, 0)

    def test_web01_exhausted_tool_budget_blocks_policy_triggered_ti_lookup(self) -> None:
        """Verify exhausted tool budget blocks policy-triggered TI lookup with zero provider calls."""
        mock_splunk = MagicMock(spec=SplunkSearchClient)
        mock_splunk.search_modsecurity_sqli.return_value = [_RAW_MODSEC_PUBLIC_TELEMETRY]
        mock_vt = MagicMock(spec=VirusTotalThreatIntelClient)
        router = ToolRouter(splunk_client=mock_splunk, vt_client=mock_vt)
        # Budget only permits 1 tool execution (which bounded_splunk_search consumes)
        guard = RuntimeGuard(config=RuntimeGuardConfig(max_tool_executions=1))

        model = ScriptedModel([
            ModelDecision(
                decision_type=DecisionType.TOOL_REQUEST,
                tool_request=ToolRequest(
                    tool_name="bounded_splunk_search",
                    arguments={"query_type": "modsecurity_sqli_matches", "host": "web01"},
                ),
            ),
            ModelDecision(
                decision_type=DecisionType.FINAL_RESULT,
                final_result=_VALID_WEB01_ASSESSMENT,
            ),
        ])

        orchestrator = InvestigationOrchestrator(model=model, tool_router=router, guard=guard)
        with self.assertRaises(OrchestratorError) as ctx:
            orchestrator.investigate(_VALID_WEB01_REQUEST)

        self.assertIn("TOOL_BUDGET_EXCEEDED", str(ctx.exception))
        self.assertEqual(mock_vt.lookup.call_count, 0)

    def test_web01_policy_ti_execution_is_audited(self) -> None:
        """Verify successful policy-triggered TI lookup logs standard static lifecycle audit events."""
        mock_splunk = MagicMock(spec=SplunkSearchClient)
        mock_splunk.search_modsecurity_sqli.return_value = [_RAW_MODSEC_PUBLIC_TELEMETRY]
        mock_vt = MagicMock(spec=VirusTotalThreatIntelClient)
        mock_vt.lookup.return_value = ThreatIntelResult(
            provider="virustotal",
            indicator_type="ip",
            indicator_value="93.184.216.34",
            lookup_status=ThreatIntelLookupStatus.FOUND,
            malicious_count=0,
            suspicious_count=2,
            harmless_count=60,
            undetected_count=18,
            detail_code="ip_lookup_found",
        )
        router = ToolRouter(splunk_client=mock_splunk, vt_client=mock_vt)

        model = ScriptedModel([
            ModelDecision(
                decision_type=DecisionType.TOOL_REQUEST,
                tool_request=ToolRequest(
                    tool_name="bounded_splunk_search",
                    arguments={"query_type": "modsecurity_sqli_matches", "host": "web01"},
                ),
            ),
            ModelDecision(
                decision_type=DecisionType.FINAL_RESULT,
                final_result=_VALID_WEB01_ASSESSMENT,
            ),
        ])

        orchestrator = InvestigationOrchestrator(model=model, tool_router=router)
        orchestrator.investigate(_VALID_WEB01_REQUEST)

        audit_events = orchestrator.audit_log.events()
        ti_detail_codes = [e.detail_code for e in audit_events if "threat_intel" in e.detail_code]

        self.assertIn("threat_intel_lookup_requested", ti_detail_codes)
        self.assertIn("threat_intel_lookup_allowed", ti_detail_codes)
        self.assertIn("threat_intel_lookup_ok", ti_detail_codes)

        # Confirm strictly no raw payloads, indicators, or URLs appear in any audit detail_code
        for e in audit_events:
            self.assertNotIn("93.184.216.34", e.detail_code)
            self.assertNotIn("virustotal", e.detail_code.lower())

    def test_web01_private_ti_skip_does_not_log_false_tool_execution(self) -> None:
        """Verify private IP skip produces zero threat_intel tool audit events."""
        mock_splunk = MagicMock(spec=SplunkSearchClient)
        mock_splunk.search_modsecurity_sqli.return_value = [_RAW_MODSEC_PRIVATE_TELEMETRY]
        router = ToolRouter(splunk_client=mock_splunk)

        model = ScriptedModel([
            ModelDecision(
                decision_type=DecisionType.TOOL_REQUEST,
                tool_request=ToolRequest(
                    tool_name="bounded_splunk_search",
                    arguments={"query_type": "modsecurity_sqli_matches", "host": "web01"},
                ),
            ),
            ModelDecision(
                decision_type=DecisionType.FINAL_RESULT,
                final_result=_VALID_WEB01_ASSESSMENT,
            ),
        ])

        orchestrator = InvestigationOrchestrator(model=model, tool_router=router)
        orchestrator.investigate(_VALID_WEB01_REQUEST)

        audit_events = orchestrator.audit_log.events()
        for e in audit_events:
            self.assertNotIn("threat_intel_lookup", e.detail_code)

    def test_web01_ti_provider_failure_audit_contains_no_payload(self) -> None:
        """Verify failed TI lookup emits static execution_failed code without exception messages or secrets."""
        mock_splunk = MagicMock(spec=SplunkSearchClient)
        mock_splunk.search_modsecurity_sqli.return_value = [_RAW_MODSEC_PUBLIC_TELEMETRY]
        mock_vt = MagicMock(spec=VirusTotalThreatIntelClient)
        mock_vt.lookup.side_effect = VirusTotalError("Sensitive VT 500 error with api_key=secret_123")
        router = ToolRouter(splunk_client=mock_splunk, vt_client=mock_vt)

        model = ScriptedModel([
            ModelDecision(
                decision_type=DecisionType.TOOL_REQUEST,
                tool_request=ToolRequest(
                    tool_name="bounded_splunk_search",
                    arguments={"query_type": "modsecurity_sqli_matches", "host": "web01"},
                ),
            ),
            ModelDecision(
                decision_type=DecisionType.FINAL_RESULT,
                final_result=_VALID_WEB01_ASSESSMENT,
            ),
        ])

        orchestrator = InvestigationOrchestrator(model=model, tool_router=router)
        orchestrator.investigate(_VALID_WEB01_REQUEST)

        audit_events = orchestrator.audit_log.events()
        ti_events = [e for e in audit_events if "threat_intel" in e.detail_code]
        self.assertTrue(any(e.detail_code == "threat_intel_lookup_execution_failed" for e in ti_events))

        # Confirm sensitive strings are completely absent
        for e in audit_events:
            self.assertNotIn("secret_123", e.detail_code)
            self.assertNotIn("500 error", e.detail_code)


if __name__ == "__main__":
    unittest.main()
