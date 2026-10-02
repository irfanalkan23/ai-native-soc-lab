"""Unit tests for Milestone 12B-3: Bounded Splunk Retrieval for ModSecurity SQLi.

TDD RED PHASE ONLY.

Defines the contract for bounded Splunk retrieval of Apache ModSecurity / OWASP CRS
SQL injection events:
1. Allowlist enforcement: 'modsecurity_sqli_matches' is the only accepted web query type.
2. Immutability and parameter boundaries: index, sourcetype, SPL, and rule ID cannot be
   injected or overridden by callers.
3. Deterministic static SPL generation referencing index=main and sourcetype=modsecurity.
4. Bounded client execution on SplunkSearchClient and ToolRouter dispatch.
5. Normalization of candidate Splunk rows containing (_raw, host) into ModSecuritySqliEvidence
   via parse_modsecurity_sqli_event.
6. Fail-closed rejection of missing fields, malformed logs, fragments, and non-SQLi events.
"""

from typing import Any, Dict, List
import unittest
from unittest.mock import MagicMock, patch

from gateway.policy import (
    ALLOWED_HOSTS,
    ALLOWED_QUERY_TYPES,
    PolicyValidationError,
    SearchRequest,
    build_allowlisted_spl,
    validate_search_request,
)
from gateway.splunk_search import (
    SPLUNK_EXPORT_ENDPOINT,
    SplunkSearchClient,
)
from investigator.modsecurity import (
    ModSecurityError,
    ModSecuritySqliEvidence,
    ModSecurityValidationError,
    parse_modsecurity_sqli_event,
)
from investigator.tool_router import (
    ALLOWED_SPLUNK_QUERY_TYPES,
    ToolExecutionError,
    ToolRouter,
    ToolValidationError,
)

try:
    from investigator.modsecurity import (  # type: ignore
        normalize_modsecurity_sqli_record,
        normalize_modsecurity_sqli_results,
    )
except ImportError:
    normalize_modsecurity_sqli_record = None  # type: ignore
    normalize_modsecurity_sqli_results = None  # type: ignore


# ---------------------------------------------------------------------------
# Sanitized Live-Derived ModSecurity Fixture
# ---------------------------------------------------------------------------

SAMPLE_HOST = "web01"
SAMPLE_SRC_IP = "192.168.1.100"
SAMPLE_RULE_ID = 942100
SAMPLE_RULE_MSG = "SQL Injection Attack Detected via libinjection"
SAMPLE_SEVERITY = "CRITICAL"
SAMPLE_ANOMALY_SCORE = 8
SAMPLE_TRANSACTION_ID = "ar1Z9uxU-NFJV-LskY52NwAAAEQ"

LIVE_DERIVED_MODSEC_EVENT = f"""--{SAMPLE_TRANSACTION_ID}-A--
[01/Oct/2026:14:22:18 +0000] {SAMPLE_TRANSACTION_ID} {SAMPLE_SRC_IP} 48292 192.168.1.10 80
--{SAMPLE_TRANSACTION_ID}-B--
GET /dvwa/vulnerabilities/sqli/?id=1%27%20OR%20%271%27=%271&Submit=Submit HTTP/1.1
Host: {SAMPLE_HOST}
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Cookie: PHPSESSID=liveverifiedsessionid12345; security=low
Connection: keep-alive
--{SAMPLE_TRANSACTION_ID}-F--
HTTP/1.1 403 Forbidden
Content-Type: text/html; charset=iso-8859-1
Connection: close
--{SAMPLE_TRANSACTION_ID}-H--
Message: Warning. Pattern match "^[\\d.]+$" at REQUEST_HEADERS:Host. [file "/etc/modsecurity/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "738"] [id "920350"] [msg "Host header is a numeric IP address"] [severity "WARNING"] [ver "OWASP_CRS/3.3.4"]
Message: Access denied with code 403 (phase 2). Matched "Operator DetectSQLi" at ARGS:id. [file "/etc/modsecurity/owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"] [line "45"] [id "942100"] [msg "{SAMPLE_RULE_MSG}"] [data "Matched Data: 1' OR '1'='1 found within ARGS:id: 1' OR '1'='1"] [severity "{SAMPLE_SEVERITY}"] [ver "OWASP_CRS/3.3.4"] [tag "attack-sqli"] [tag "OWASP_CRS"]
Message: Warning. Operator GE reached 5 at TX:inbound_anomaly_score. [file "/etc/modsecurity/owasp-crs/rules/RESPONSE-980-CORRELATION.conf"] [line "91"] [id "980130"] [msg "Inbound Anomaly Score Exceeded (Total Score: {SAMPLE_ANOMALY_SCORE})"] [severity "CRITICAL"] [ver "OWASP_CRS/3.3.4"]
Action: Intercepted (eval_status 403)
Stopwatch: 1727792538000000 1420 (- - -)
Server: Apache/2.4.57 (Debian)
Engine-Mode: "ENABLED"
--{SAMPLE_TRANSACTION_ID}-Z--
"""


class TestModSecurityBoundedSplunkRetrieval(unittest.TestCase):
    """Test suite defining bounded Splunk query and evidence normalization contracts."""

    def setUp(self) -> None:
        self.client = SplunkSearchClient(verify_tls=False, timeout=10.0)
        self.router = ToolRouter(splunk_client=self.client)

    # -------------------------------------------------------------------------
    # Red Phase Capability Check Helpers
    # -------------------------------------------------------------------------

    def _require_gateway_query_type(self) -> None:
        if "modsecurity_sqli_matches" not in ALLOWED_QUERY_TYPES or "web01" not in ALLOWED_HOSTS:
            self.fail("RED PHASE: 'modsecurity_sqli_matches' or 'web01' is not yet allowlisted in gateway.policy")

    def _require_splunk_client_method(self) -> None:
        if not hasattr(self.client, "search_modsecurity_sqli"):
            self.fail("RED PHASE: SplunkSearchClient.search_modsecurity_sqli is not yet implemented in gateway.splunk_search")

    def _require_router_query_type(self) -> None:
        if "modsecurity_sqli_matches" not in ALLOWED_SPLUNK_QUERY_TYPES:
            self.fail("RED PHASE: 'modsecurity_sqli_matches' is not yet allowlisted in investigator.tool_router")

    def _require_normalizer(self) -> None:
        if normalize_modsecurity_sqli_record is None:
            self.fail("RED PHASE: normalize_modsecurity_sqli_record is not yet implemented in investigator.modsecurity")

    def _require_batch_normalizer(self) -> None:
        if normalize_modsecurity_sqli_results is None:
            self.fail("RED PHASE: normalize_modsecurity_sqli_results is not yet implemented in investigator.modsecurity")

    # -------------------------------------------------------------------------
    # 1. ALLOWLIST / BOUNDED QUERY CONTRACT
    # -------------------------------------------------------------------------

    def test_modsecurity_sqli_matches_query_type_accepted(self) -> None:
        """Query type 'modsecurity_sqli_matches' is allowlisted and accepted for host web01."""
        self._require_gateway_query_type()

        req = validate_search_request(
            query_type="modsecurity_sqli_matches",
            host="web01",
            minutes=15,
            limit=10,
        )
        self.assertIsInstance(req, SearchRequest)
        self.assertEqual(req.query_type, "modsecurity_sqli_matches")
        self.assertEqual(req.host, "web01")

    def test_unknown_query_type_rejected(self) -> None:
        """Arbitrary query types outside the allowlist are rejected fail-closed."""
        self._require_gateway_query_type()

        with self.assertRaises(PolicyValidationError):
            validate_search_request(
                query_type="arbitrary_web_search",
                host="web01",
                minutes=15,
                limit=10,
            )

    def test_caller_cannot_inject_arbitrary_spl(self) -> None:
        """Attempting to inject raw SPL parameters via ToolRouter is strictly rejected."""
        self._require_router_query_type()

        for forbidden in ("search", "spl", "query", "raw_spl"):
            with self.subTest(forbidden=forbidden):
                args = {
                    "query_type": "modsecurity_sqli_matches",
                    "host": "web01",
                    "minutes": 15,
                    "limit": 10,
                    forbidden: "search index=* | delete",
                }
                with self.assertRaises(ToolValidationError):
                    self.router.execute_tool("bounded_splunk_search", args)

    def test_caller_cannot_override_index(self) -> None:
        """Callers cannot specify or override the Splunk index parameter."""
        self._require_router_query_type()

        args = {
            "query_type": "modsecurity_sqli_matches",
            "host": "web01",
            "index": "sensitive_index",
        }
        with self.assertRaises(ToolValidationError):
            self.router.execute_tool("bounded_splunk_search", args)

    def test_caller_cannot_override_sourcetype(self) -> None:
        """Callers cannot specify or override the sourcetype parameter."""
        self._require_router_query_type()

        args = {
            "query_type": "modsecurity_sqli_matches",
            "host": "web01",
            "sourcetype": "access_combined",
        }
        with self.assertRaises(ToolValidationError):
            self.router.execute_tool("bounded_splunk_search", args)

    def test_caller_cannot_override_rule_id(self) -> None:
        """Callers cannot specify or override the targeted rule ID."""
        self._require_router_query_type()

        args = {
            "query_type": "modsecurity_sqli_matches",
            "host": "web01",
            "rule_id": 999999,
        }
        with self.assertRaises(ToolValidationError):
            self.router.execute_tool("bounded_splunk_search", args)

    def test_caller_cannot_add_search_fragments_or_pipes(self) -> None:
        """Pipes, eval statements, and boolean injection in host parameter fail closed."""
        self._require_gateway_query_type()

        injection_hosts = [
            'web01" | eval injected=1 | search index=*',
            'web01 OR index=other',
            'web01; rm -rf /',
            'web01 | head 1',
        ]
        for bad_host in injection_hosts:
            with self.subTest(bad_host=bad_host):
                with self.assertRaises(PolicyValidationError):
                    validate_search_request(
                        query_type="modsecurity_sqli_matches",
                        host=bad_host,
                        minutes=15,
                        limit=10,
                    )

    # -------------------------------------------------------------------------
    # 2. STATIC QUERY CONTRACT
    # -------------------------------------------------------------------------

    def test_generated_spl_is_deterministic(self) -> None:
        """Generated SPL for modsecurity_sqli_matches is identical across multiple calls."""
        self._require_gateway_query_type()

        req = SearchRequest(query_type="modsecurity_sqli_matches", host="web01", minutes=15, limit=10)
        spl_1 = build_allowlisted_spl(req)
        spl_2 = build_allowlisted_spl(req)

        self.assertEqual(spl_1, spl_2)

    def test_query_references_index_main(self) -> None:
        """Generated SPL strictly queries index=main."""
        self._require_gateway_query_type()

        req = SearchRequest(query_type="modsecurity_sqli_matches", host="web01", minutes=15, limit=10)
        spl = build_allowlisted_spl(req)

        self.assertIn("index=main", spl)

    def test_query_references_sourcetype_modsecurity(self) -> None:
        """Generated SPL strictly targets sourcetype=modsecurity."""
        self._require_gateway_query_type()

        req = SearchRequest(query_type="modsecurity_sqli_matches", host="web01", minutes=15, limit=10)
        spl = build_allowlisted_spl(req)

        self.assertTrue("sourcetype=modsecurity" in spl or 'sourcetype="modsecurity"' in spl)

    def test_query_bounded_specifically_to_sqli_rule_or_msg(self) -> None:
        """Generated SPL is bounded specifically to SQLi rule 942100 or detection message."""
        self._require_gateway_query_type()

        req = SearchRequest(query_type="modsecurity_sqli_matches", host="web01", minutes=15, limit=10)
        spl = build_allowlisted_spl(req)

        self.assertTrue(
            "942100" in spl or "SQL Injection Attack Detected via libinjection" in spl,
            msg="SPL must be statically bounded to rule 942100 or its exact message",
        )

    def test_query_does_not_incorporate_arbitrary_caller_text(self) -> None:
        """Query construction only accepts validated host/minutes/limit parameters."""
        self._require_gateway_query_type()

        req = SearchRequest(query_type="modsecurity_sqli_matches", host="web01", minutes=30, limit=5)
        spl = build_allowlisted_spl(req)

        self.assertIn('host="web01"', spl)
        self.assertIn('earliest="-30m"', spl)
        self.assertIn("head 5", spl)

    def test_query_projects_required_fields(self) -> None:
        """Generated SPL projects _raw and host fields required for evidence normalization."""
        self._require_gateway_query_type()

        req = SearchRequest(query_type="modsecurity_sqli_matches", host="web01", minutes=15, limit=10)
        spl = build_allowlisted_spl(req)

        self.assertIn("_raw", spl)
        self.assertIn("host", spl)

    # -------------------------------------------------------------------------
    # 3. CLIENT & ROUTER EXECUTION CONTRACT
    # -------------------------------------------------------------------------

    def test_splunk_search_client_exposes_search_modsecurity_sqli(self) -> None:
        """SplunkSearchClient exposes dedicated search_modsecurity_sqli method."""
        self._require_splunk_client_method()

        with patch.object(self.client, "_execute_bounded_search", return_value=[]) as mock_exec:
            res = self.client.search_modsecurity_sqli(host="web01", minutes=15, limit=10)  # type: ignore[attr-defined]
            mock_exec.assert_called_once()
            self.assertEqual(res, [])

    def test_tool_router_dispatches_modsecurity_sqli_matches(self) -> None:
        """ToolRouter accepts 'modsecurity_sqli_matches' and delegates to search_modsecurity_sqli."""
        self._require_router_query_type()

        mock_client = MagicMock()
        mock_client.search_modsecurity_sqli.return_value = [{"host": "web01", "_raw": LIVE_DERIVED_MODSEC_EVENT}]
        router = ToolRouter(splunk_client=mock_client)

        result = router.execute_tool(
            "bounded_splunk_search",
            {
                "query_type": "modsecurity_sqli_matches",
                "host": "web01",
                "minutes": 15,
                "limit": 10,
            },
        )
        mock_client.search_modsecurity_sqli.assert_called_once_with(
            host="web01",
            minutes=15,
            limit=10,
        )
        self.assertEqual(len(result), 1)

    def test_tool_router_normalizes_modsecurity_results_before_return(self) -> None:
        """ToolRouter normalizes raw Splunk rows into validated evidence dicts before returning."""
        self._require_router_query_type()

        mock_client = MagicMock()
        mock_client.search_modsecurity_sqli.return_value = [
            {"host": "web01", "_raw": LIVE_DERIVED_MODSEC_EVENT}
        ]
        router = ToolRouter(splunk_client=mock_client)

        result = router.execute_tool(
            "bounded_splunk_search",
            {
                "query_type": "modsecurity_sqli_matches",
                "host": "web01",
                "minutes": 15,
                "limit": 10,
            },
        )
        self.assertEqual(len(result), 1)
        event = result[0]
        # _raw must not be returned in the normalized evidence payload to AI
        self.assertNotIn("_raw", event)
        # Normalized evidence fields must be present
        self.assertEqual(event["host"], "web01")
        self.assertEqual(event["src_ip"], "192.168.1.100")
        self.assertEqual(event["rule_id"], 942100)
        self.assertEqual(event["rule_msg"], "SQL Injection Attack Detected via libinjection")
        self.assertEqual(event["severity"], "CRITICAL")
        self.assertEqual(event["anomaly_score"], 8)
        self.assertEqual(event["unique_id"], "ar1Z9uxU-NFJV-LskY52NwAAAEQ")

    def test_tool_router_returns_validated_modsecurity_evidence_fields(self) -> None:
        """Expected returned event should contain exactly the 7 normalized evidence fields."""
        self._require_router_query_type()

        mock_client = MagicMock()
        mock_client.search_modsecurity_sqli.return_value = [
            {"host": "web01", "_raw": LIVE_DERIVED_MODSEC_EVENT}
        ]
        router = ToolRouter(splunk_client=mock_client)

        result = router.execute_tool(
            "bounded_splunk_search",
            {
                "query_type": "modsecurity_sqli_matches",
                "host": "web01",
                "minutes": 15,
                "limit": 10,
            },
        )
        expected_keys = {
            "host",
            "src_ip",
            "rule_id",
            "rule_msg",
            "severity",
            "anomaly_score",
            "unique_id",
        }
        self.assertEqual(set(result[0].keys()), expected_keys)

    def test_tool_router_rejects_malformed_modsecurity_candidate(self) -> None:
        """Malformed Splunk row fails closed during normalization in ToolRouter."""
        self._require_router_query_type()

        mock_client = MagicMock()
        mock_client.search_modsecurity_sqli.return_value = [
            {"host": "web01", "_raw": "MALFORMED UNPARSABLE NOT MODSECURITY"}
        ]
        router = ToolRouter(splunk_client=mock_client)

        with self.assertRaises(ToolExecutionError):
            router.execute_tool(
                "bounded_splunk_search",
                {
                    "query_type": "modsecurity_sqli_matches",
                    "host": "web01",
                    "minutes": 15,
                    "limit": 10,
                },
            )

    def test_tool_router_rejects_fragmented_modsecurity_candidate(self) -> None:
        """Fragmented CRS candidate without transaction context fails closed in ToolRouter."""
        self._require_router_query_type()

        mock_client = MagicMock()
        mock_client.search_modsecurity_sqli.return_value = [
            {
                "host": "web01",
                "_raw": 'SecRule ARGS "@detectSQLi" "id:942100,msg:\'SQL Injection Attack Detected via libinjection\'"',
            }
        ]
        router = ToolRouter(splunk_client=mock_client)

        with self.assertRaises(ToolExecutionError):
            router.execute_tool(
                "bounded_splunk_search",
                {
                    "query_type": "modsecurity_sqli_matches",
                    "host": "web01",
                    "minutes": 15,
                    "limit": 10,
                },
            )

    # -------------------------------------------------------------------------
    # 4. RESULT PARSING & NORMALIZATION
    # -------------------------------------------------------------------------

    def test_valid_splunk_row_parsed_to_modsecurity_sqli_evidence(self) -> None:
        """Valid Splunk candidate row containing host and _raw normalizes to ModSecuritySqliEvidence."""
        self._require_normalizer()

        raw_row = {
            "host": SAMPLE_HOST,
            "_raw": LIVE_DERIVED_MODSEC_EVENT,
            "_time": "2026-10-01T14:22:18.000+00:00",
        }
        evidence = normalize_modsecurity_sqli_record(raw_row)  # type: ignore[misc]

        self.assertIsInstance(evidence, ModSecuritySqliEvidence)
        self.assertEqual(evidence.host, SAMPLE_HOST)
        self.assertEqual(evidence.src_ip, SAMPLE_SRC_IP)
        self.assertEqual(evidence.rule_id, SAMPLE_RULE_ID)
        self.assertEqual(evidence.rule_msg, SAMPLE_RULE_MSG)
        self.assertEqual(evidence.severity, SAMPLE_SEVERITY)
        self.assertEqual(evidence.anomaly_score, SAMPLE_ANOMALY_SCORE)
        self.assertEqual(evidence.unique_id, SAMPLE_TRANSACTION_ID)

    def test_returned_host_passed_into_parser(self) -> None:
        """The host present on the Splunk record is passed to the parser and preserved."""
        self._require_normalizer()

        custom_host = "web-prod-node01"
        raw_row = {
            "host": custom_host,
            "_raw": LIVE_DERIVED_MODSEC_EVENT,
        }
        evidence = normalize_modsecurity_sqli_record(raw_row)  # type: ignore[misc]

        self.assertEqual(evidence.host, custom_host)

    def test_parsed_evidence_contains_all_expected_fields(self) -> None:
        """Normalized evidence contains all 7 mandatory fields matching live verified telemetry."""
        self._require_normalizer()

        raw_row = {"host": "web01", "_raw": LIVE_DERIVED_MODSEC_EVENT}
        evidence = normalize_modsecurity_sqli_record(raw_row)  # type: ignore[misc]

        expected_dict = {
            "host": "web01",
            "src_ip": "192.168.1.100",
            "rule_id": 942100,
            "rule_msg": "SQL Injection Attack Detected via libinjection",
            "severity": "CRITICAL",
            "anomaly_score": 8,
            "unique_id": "ar1Z9uxU-NFJV-LskY52NwAAAEQ",
        }
        self.assertEqual(evidence.to_dict(), expected_dict)

    def test_normalize_modsecurity_sqli_results_batch(self) -> None:
        """Batch normalizer converts a list of valid candidate rows to immutable evidence list."""
        self._require_batch_normalizer()

        rows = [
            {"host": "web01", "_raw": LIVE_DERIVED_MODSEC_EVENT},
            {"host": "web01", "_raw": LIVE_DERIVED_MODSEC_EVENT},
        ]
        results = normalize_modsecurity_sqli_results(rows)  # type: ignore[misc]

        self.assertEqual(len(results), 2)
        for ev in results:
            self.assertIsInstance(ev, ModSecuritySqliEvidence)
            self.assertEqual(ev.rule_id, 942100)

    # -------------------------------------------------------------------------
    # 5. FAIL-CLOSED RESULT CASES
    # -------------------------------------------------------------------------

    def test_missing_raw_field_rejected(self) -> None:
        """Splunk candidate row missing '_raw' field fails closed."""
        self._require_normalizer()

        bad_row = {"host": "web01"}
        with self.assertRaises((ModSecurityValidationError, ValueError, KeyError)):
            normalize_modsecurity_sqli_record(bad_row)  # type: ignore[misc]

    def test_missing_host_field_rejected(self) -> None:
        """Splunk candidate row missing 'host' field fails closed."""
        self._require_normalizer()

        bad_row = {"_raw": LIVE_DERIVED_MODSEC_EVENT}
        with self.assertRaises((ModSecurityValidationError, ValueError, KeyError)):
            normalize_modsecurity_sqli_record(bad_row)  # type: ignore[misc]

    def test_malformed_raw_event_rejected(self) -> None:
        """Splunk candidate row with malformed/non-ModSecurity text fails closed."""
        self._require_normalizer()

        bad_row = {"host": "web01", "_raw": "Not a modsecurity audit log"}
        with self.assertRaises((ModSecurityValidationError, ValueError)):
            normalize_modsecurity_sqli_record(bad_row)  # type: ignore[misc]

    def test_fragmented_crs_event_rejected(self) -> None:
        """Splunk candidate row with fragmented CRS rule text lacking transaction context fails closed."""
        self._require_normalizer()

        fragment = 'SecRule ARGS "@detectSQLi" "id:942100,msg:\'SQL Injection Attack Detected via libinjection\'"'
        bad_row = {"host": "web01", "_raw": fragment}
        with self.assertRaises((ModSecurityValidationError, ValueError)):
            normalize_modsecurity_sqli_record(bad_row)  # type: ignore[misc]

    def test_non_sqli_event_rejected(self) -> None:
        """Splunk candidate row containing non-SQLi rule (e.g. protocol warning 920350 only) fails closed."""
        self._require_normalizer()

        non_sqli = f"""--{SAMPLE_TRANSACTION_ID}-A--
[01/Oct/2026:14:22:18 +0000] {SAMPLE_TRANSACTION_ID} {SAMPLE_SRC_IP} 48292 192.168.1.10 80
--{SAMPLE_TRANSACTION_ID}-H--
Message: Warning. Pattern match "^[\\d.]+$" [id "920350"] [msg "Host header is a numeric IP address"] [severity "WARNING"]
Message: Warning. Operator GE reached 5 at TX:inbound_anomaly_score. [id "980130"] [msg "Inbound Anomaly Score Exceeded (Total Score: 3)"]
--{SAMPLE_TRANSACTION_ID}-Z--
"""
        bad_row = {"host": "web01", "_raw": non_sqli}
        with self.assertRaises((ModSecurityValidationError, ValueError)):
            normalize_modsecurity_sqli_record(bad_row)  # type: ignore[misc]

    def test_ipv6_source_rejected_under_current_ipv4_only_contract(self) -> None:
        """Splunk candidate row with an IPv6 client IP is rejected under Milestone 12B IPv4-only contract."""
        self._require_normalizer()

        ipv6_event = LIVE_DERIVED_MODSEC_EVENT.replace(SAMPLE_SRC_IP, "2001:db8::1")
        bad_row = {"host": "web01", "_raw": ipv6_event}
        with self.assertRaises((ModSecurityValidationError, ValueError)):
            normalize_modsecurity_sqli_record(bad_row)  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
