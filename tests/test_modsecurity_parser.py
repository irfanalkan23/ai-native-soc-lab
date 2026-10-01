"""Unit tests for Milestone 12B-2: Deterministic ModSecurity Raw Event Parser.

TDD RED PHASE ONLY.

Defines the contract and deterministic parsing behavior for extracting
ModSecuritySqliEvidence from raw Apache ModSecurity / OWASP CRS transaction logs.

Validates:
1. Deterministic extraction of SQLi rule 942100, message, CRITICAL severity,
   source IPv4, anomaly score, and unique transaction ID.
2. Immunity to preceding non-SQLi rules (e.g. 920350 WARNING).
3. Fail-closed rejection of missing, malformed, non-SQLi, IPv6, or fragmented inputs.
"""

import unittest

from investigator.modsecurity import (
    ModSecurityError,
    ModSecuritySqliEvidence,
    ModSecurityValidationError,
)

try:
    from investigator.modsecurity import parse_modsecurity_sqli_event  # type: ignore
except ImportError:
    parse_modsecurity_sqli_event = None  # type: ignore


# ---------------------------------------------------------------------------
# Canonical Realistic ModSecurity Log Fixtures (modeled after live WEB01)
# ---------------------------------------------------------------------------

SAMPLE_TRANSACTION_ID = "ar1Z9uxU-NFJV-LskY52NwAAAEQ"
SAMPLE_SRC_IP = "192.168.1.100"
SAMPLE_HOST = "web01"

# Realistic multi-rule transaction where an earlier rule (920350 WARNING) precedes
# the SQLi rule (942100 CRITICAL), followed by the correlation anomaly score rule.
VALID_MODSEC_SQLI_EVENT = f"""--{SAMPLE_TRANSACTION_ID}-A--
[01/Oct/2026:15:30:00 +0000] {SAMPLE_TRANSACTION_ID} {SAMPLE_SRC_IP} 52342 192.168.1.10 80
--{SAMPLE_TRANSACTION_ID}-B--
GET /index.php?id=1%20OR%201=1 HTTP/1.1
Host: {SAMPLE_HOST}
User-Agent: curl/7.88.1
Accept: */*
--{SAMPLE_TRANSACTION_ID}-F--
HTTP/1.1 403 Forbidden
Status: 403 Forbidden
--{SAMPLE_TRANSACTION_ID}-H--
Message: Warning. Pattern match "^[\\\\d.]+$" at REQUEST_HEADERS:Host. [file "/etc/modsecurity/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "738"] [id "920350"] [msg "Host header is a numeric IP address"] [severity "WARNING"] [ver "OWASP_CRS/3.3.4"]
Message: Access denied with code 403 (phase 2). Matched "Operator DetectSQLi" at ARGS:id. [file "/etc/modsecurity/owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"] [line "45"] [id "942100"] [msg "SQL Injection Attack Detected via libinjection"] [data "Matched Data: 1 OR 1=1 found within ARGS:id"] [severity "CRITICAL"] [ver "OWASP_CRS/3.3.4"]
Message: Warning. Operator GE reached 5 at TX:inbound_anomaly_score. [file "/etc/modsecurity/owasp-crs/rules/RESPONSE-980-CORRELATION.conf"] [line "91"] [id "980130"] [msg "Inbound Anomaly Score Exceeded (Total Score: 8)"] [severity "CRITICAL"] [ver "OWASP_CRS/3.3.4"]
Action: Intercepted (eval_status 403)
--{SAMPLE_TRANSACTION_ID}-Z--
"""


class TestModSecurityRawEventParser(unittest.TestCase):
    """Tests establishing the raw ModSecurity SQLi event parser contract."""

    def _require_parser(self):
        """Helper to assert RED phase if production parser function does not exist."""
        if parse_modsecurity_sqli_event is None:
            self.fail("RED PHASE: parse_modsecurity_sqli_event is not yet implemented in investigator.modsecurity")

    # -------------------------------------------------------------------------
    # POSITIVE EXTRACTION TESTS
    # -------------------------------------------------------------------------

    def test_valid_realistic_sqli_transaction_parses_successfully(self) -> None:
        """Realistic ModSecurity audit log parses into a valid ModSecuritySqliEvidence record."""
        self._require_parser()

        evidence = parse_modsecurity_sqli_event(
            raw_event=VALID_MODSEC_SQLI_EVENT,
            host=SAMPLE_HOST,
        )

        self.assertIsInstance(evidence, ModSecuritySqliEvidence)
        self.assertEqual(evidence.host, SAMPLE_HOST)
        self.assertEqual(evidence.src_ip, SAMPLE_SRC_IP)
        self.assertEqual(evidence.rule_id, 942100)
        self.assertEqual(evidence.rule_msg, "SQL Injection Attack Detected via libinjection")
        self.assertEqual(evidence.severity, "CRITICAL")
        self.assertEqual(evidence.anomaly_score, 8)
        self.assertEqual(evidence.unique_id, SAMPLE_TRANSACTION_ID)

    def test_parser_selects_sqli_rule_not_earlier_rule(self) -> None:
        """Parser deterministically targets SQLi rule 942100, not preceding rule 920350."""
        self._require_parser()

        evidence = parse_modsecurity_sqli_event(
            raw_event=VALID_MODSEC_SQLI_EVENT,
            host=SAMPLE_HOST,
        )

        self.assertEqual(evidence.rule_id, 942100)
        self.assertNotEqual(evidence.rule_id, 920350)
        self.assertEqual(evidence.rule_msg, "SQL Injection Attack Detected via libinjection")

    def test_parser_selects_sqli_severity_not_earlier_severity(self) -> None:
        """Parser extracts CRITICAL severity associated with rule 942100, ignoring earlier WARNING."""
        self._require_parser()

        evidence = parse_modsecurity_sqli_event(
            raw_event=VALID_MODSEC_SQLI_EVENT,
            host=SAMPLE_HOST,
        )

        self.assertEqual(evidence.severity, "CRITICAL")
        self.assertNotEqual(evidence.severity, "WARNING")

    def test_deterministic_repeated_parsing_returns_equivalent_evidence(self) -> None:
        """Repeated invocations on the same raw event return identical evidence and serialization."""
        self._require_parser()

        evidence_1 = parse_modsecurity_sqli_event(raw_event=VALID_MODSEC_SQLI_EVENT, host=SAMPLE_HOST)
        evidence_2 = parse_modsecurity_sqli_event(raw_event=VALID_MODSEC_SQLI_EVENT, host=SAMPLE_HOST)

        self.assertEqual(evidence_1, evidence_2)
        self.assertEqual(evidence_1.to_dict(), evidence_2.to_dict())

    def test_supplied_host_preserved(self) -> None:
        """Supplied host parameter is preserved in the resulting evidence object."""
        self._require_parser()

        custom_host = "web-cluster-node-02"
        evidence = parse_modsecurity_sqli_event(
            raw_event=VALID_MODSEC_SQLI_EVENT,
            host=custom_host,
        )

        self.assertEqual(evidence.host, custom_host)

    # -------------------------------------------------------------------------
    # REJECTION / FAIL-CLOSED TESTS
    # -------------------------------------------------------------------------

    def test_raw_event_none_rejected(self) -> None:
        """Passing None for raw_event raises an appropriate validation error."""
        self._require_parser()

        error_types = (ModSecurityValidationError, ValueError, TypeError)
        with self.assertRaises(error_types):
            parse_modsecurity_sqli_event(raw_event=None, host=SAMPLE_HOST)  # type: ignore[arg-type]

    def test_raw_event_non_string_rejected(self) -> None:
        """Passing a non-string type for raw_event is rejected fail-closed."""
        self._require_parser()

        error_types = (ModSecurityValidationError, ValueError, TypeError)
        for bad_raw in (12345, True, ["log line"], {"raw": "data"}):
            with self.subTest(bad_raw=bad_raw):
                with self.assertRaises(error_types):
                    parse_modsecurity_sqli_event(raw_event=bad_raw, host=SAMPLE_HOST)  # type: ignore[arg-type]

    def test_raw_event_empty_or_whitespace_rejected(self) -> None:
        """Passing an empty or whitespace-only string for raw_event is rejected fail-closed."""
        self._require_parser()

        error_types = (ModSecurityValidationError, ValueError)
        for bad_raw in ("", "   ", "\n\t  \n"):
            with self.subTest(bad_raw=bad_raw):
                with self.assertRaises(error_types):
                    parse_modsecurity_sqli_event(raw_event=bad_raw, host=SAMPLE_HOST)

    def test_host_missing_or_empty_rejected(self) -> None:
        """Missing, empty, whitespace-only, or non-string host is rejected."""
        self._require_parser()

        error_types = (ModSecurityValidationError, ValueError, TypeError)
        for bad_host in (None, "", "   ", 123, True):
            with self.subTest(bad_host=bad_host):
                with self.assertRaises(error_types):
                    parse_modsecurity_sqli_event(raw_event=VALID_MODSEC_SQLI_EVENT, host=bad_host)  # type: ignore[arg-type]

    def test_non_sqli_modsecurity_transaction_rejected(self) -> None:
        """A valid ModSecurity transaction that lacks the SQLi rule (e.g. only protocol enforcement) is rejected."""
        self._require_parser()

        non_sqli_event = f"""--{SAMPLE_TRANSACTION_ID}-A--
[01/Oct/2026:15:30:00 +0000] {SAMPLE_TRANSACTION_ID} {SAMPLE_SRC_IP} 52342 192.168.1.10 80
--{SAMPLE_TRANSACTION_ID}-B--
GET /index.php HTTP/1.1
Host: {SAMPLE_HOST}
--{SAMPLE_TRANSACTION_ID}-H--
Message: Warning. Pattern match "^[\\\\d.]+$" at REQUEST_HEADERS:Host. [file "REQUEST-920.conf"] [line "738"] [id "920350"] [msg "Host header is a numeric IP address"] [severity "WARNING"]
Message: Warning. Operator GE reached 5 at TX:inbound_anomaly_score. [file "RESPONSE-980.conf"] [line "91"] [id "980130"] [msg "Inbound Anomaly Score Exceeded (Total Score: 3)"] [severity "NOTICE"]
Action: Intercepted (eval_status 403)
--{SAMPLE_TRANSACTION_ID}-Z--
"""
        error_types = (ModSecurityValidationError, ValueError)
        with self.assertRaises(error_types):
            parse_modsecurity_sqli_event(raw_event=non_sqli_event, host=SAMPLE_HOST)

    def test_sqli_rule_msg_present_without_rule_942100_rejected(self) -> None:
        """An event containing the SQLi message string but missing rule ID 942100 is rejected."""
        self._require_parser()

        event = VALID_MODSEC_SQLI_EVENT.replace('[id "942100"]', '[id "999999"]')
        error_types = (ModSecurityValidationError, ValueError)
        with self.assertRaises(error_types):
            parse_modsecurity_sqli_event(raw_event=event, host=SAMPLE_HOST)

    def test_rule_942100_present_without_sqli_msg_rejected(self) -> None:
        """An event containing rule ID 942100 but missing the expected SQLi message is rejected."""
        self._require_parser()

        event = VALID_MODSEC_SQLI_EVENT.replace(
            '[msg "SQL Injection Attack Detected via libinjection"]',
            '[msg "Generic Cross-Site Scripting Attempt"]'
        )
        error_types = (ModSecurityValidationError, ValueError)
        with self.assertRaises(error_types):
            parse_modsecurity_sqli_event(raw_event=event, host=SAMPLE_HOST)

    def test_source_ipv4_missing_rejected(self) -> None:
        """An event lacking the Section A header containing the source IPv4 is rejected fail-closed."""
        self._require_parser()

        # Remove Section A completely
        lines = [line for line in VALID_MODSEC_SQLI_EVENT.splitlines(keepends=True) if "-A--" not in line and SAMPLE_SRC_IP not in line]
        event = "".join(lines)
        error_types = (ModSecurityValidationError, ValueError)
        with self.assertRaises(error_types):
            parse_modsecurity_sqli_event(raw_event=event, host=SAMPLE_HOST)

    def test_source_ipv4_malformed_rejected(self) -> None:
        """An event with a malformed source IP literal in Section A is rejected."""
        self._require_parser()

        for bad_ip in ("not-an-ip", "999.999.999.999", "192.168.1."):
            with self.subTest(bad_ip=bad_ip):
                event = VALID_MODSEC_SQLI_EVENT.replace(SAMPLE_SRC_IP, bad_ip)
                error_types = (ModSecurityValidationError, ValueError)
                with self.assertRaises(error_types):
                    parse_modsecurity_sqli_event(raw_event=event, host=SAMPLE_HOST)

    def test_unique_id_missing_rejected(self) -> None:
        """An event lacking a valid unique transaction ID in delimiters and Section A is rejected."""
        self._require_parser()

        # Replace unique_id with empty/whitespace or placeholder
        event = VALID_MODSEC_SQLI_EVENT.replace(SAMPLE_TRANSACTION_ID, "-")
        error_types = (ModSecurityValidationError, ValueError)
        with self.assertRaises(error_types):
            parse_modsecurity_sqli_event(raw_event=event, host=SAMPLE_HOST)

    def test_anomaly_score_missing_rejected(self) -> None:
        """An event lacking the inbound anomaly score correlation entry is rejected fail-closed."""
        self._require_parser()

        lines = [line for line in VALID_MODSEC_SQLI_EVENT.splitlines(keepends=True) if "Inbound Anomaly Score Exceeded" not in line]
        event = "".join(lines)
        error_types = (ModSecurityValidationError, ValueError)
        with self.assertRaises(error_types):
            parse_modsecurity_sqli_event(raw_event=event, host=SAMPLE_HOST)

    def test_anomaly_score_malformed_rejected(self) -> None:
        """An event with a non-integer or negative anomaly score is rejected."""
        self._require_parser()

        for bad_score in ("(Total Score: NaN)", "(Total Score: -5)", "(Total Score: 8.5)"):
            with self.subTest(bad_score=bad_score):
                event = VALID_MODSEC_SQLI_EVENT.replace("(Total Score: 8)", bad_score)
                error_types = (ModSecurityValidationError, ValueError)
                with self.assertRaises(error_types):
                    parse_modsecurity_sqli_event(raw_event=event, host=SAMPLE_HOST)

    def test_fragmented_rule_definition_without_transaction_context_rejected(self) -> None:
        """A fragmented event containing CRS rule definition text but no transaction context is rejected."""
        self._require_parser()

        fragment = (
            'SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* '
            '"@detectSQLi" "id:942100,phase:2,block,capture,t:none,t:utf8toUnicode,t:urlDecodeUni,'
            'msg:\'SQL Injection Attack Detected via libinjection\',logdata:\'Matched Data: %{TX.0} found\','
            'tag:\'application-multi\',tag:\'language-multi\',tag:\'attack-sqli\',ver:\'OWASP_CRS/3.3.4\',severity:\'CRITICAL\'"'
        )
        error_types = (ModSecurityValidationError, ValueError)
        with self.assertRaises(error_types):
            parse_modsecurity_sqli_event(raw_event=fragment, host=SAMPLE_HOST)

    def test_ipv6_source_transaction_rejected(self) -> None:
        """An event with an IPv6 client address is rejected; Milestone 12B is strictly IPv4-only."""
        self._require_parser()

        ipv6_event = VALID_MODSEC_SQLI_EVENT.replace(SAMPLE_SRC_IP, "2001:db8::1")
        error_types = (ModSecurityValidationError, ValueError)
        with self.assertRaises(error_types):
            parse_modsecurity_sqli_event(raw_event=ipv6_event, host=SAMPLE_HOST)

    def test_misleading_earlier_rules_do_not_contaminate_sqli_extraction(self) -> None:
        """Multiple preceding rules with different IDs and severities must not contaminate SQLi extraction."""
        self._require_parser()

        multi_rule_event = f"""--{SAMPLE_TRANSACTION_ID}-A--
[01/Oct/2026:15:30:00 +0000] {SAMPLE_TRANSACTION_ID} {SAMPLE_SRC_IP} 52342 192.168.1.10 80
--{SAMPLE_TRANSACTION_ID}-B--
GET /search.php?q=1%20OR%201=1 HTTP/1.1
Host: {SAMPLE_HOST}
--{SAMPLE_TRANSACTION_ID}-H--
Message: Warning. [file "920.conf"] [line "10"] [id "920100"] [msg "Invalid HTTP Request Line"] [severity "NOTICE"]
Message: Warning. [file "920.conf"] [line "738"] [id "920350"] [msg "Host header is a numeric IP address"] [severity "WARNING"]
Message: Warning. [file "930.conf"] [line "50"] [id "930100"] [msg "Path Traversal Attack Detected"] [severity "ERROR"]
Message: Access denied with code 403 (phase 2). [file "942.conf"] [line "45"] [id "942100"] [msg "SQL Injection Attack Detected via libinjection"] [severity "CRITICAL"]
Message: Warning. Operator GE reached 5 at TX:inbound_anomaly_score. [file "980.conf"] [line "91"] [id "980130"] [msg "Inbound Anomaly Score Exceeded (Total Score: 8)"] [severity "CRITICAL"]
Action: Intercepted (eval_status 403)
--{SAMPLE_TRANSACTION_ID}-Z--
"""
        evidence = parse_modsecurity_sqli_event(raw_event=multi_rule_event, host=SAMPLE_HOST)

        self.assertEqual(evidence.rule_id, 942100)
        self.assertEqual(evidence.rule_msg, "SQL Injection Attack Detected via libinjection")
        self.assertEqual(evidence.severity, "CRITICAL")
        self.assertEqual(evidence.anomaly_score, 8)
        self.assertEqual(evidence.src_ip, SAMPLE_SRC_IP)
        self.assertEqual(evidence.unique_id, SAMPLE_TRANSACTION_ID)

    def test_live_derived_web01_sqli_event_parses_correctly(self) -> None:
        """Sanitized live-derived WEB01 ModSecurity SQLi transaction parses into exact expected evidence."""
        self._require_parser()

        live_derived_event = """--ar1Z9uxU-NFJV-LskY52NwAAAEQ-A--
[01/Oct/2026:14:22:18 +0000] ar1Z9uxU-NFJV-LskY52NwAAAEQ 192.168.1.100 48292 192.168.1.10 80
--ar1Z9uxU-NFJV-LskY52NwAAAEQ-B--
GET /dvwa/vulnerabilities/sqli/?id=1%27%20OR%20%271%27=%271&Submit=Submit HTTP/1.1
Host: web01
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Cookie: PHPSESSID=liveverifiedsessionid12345; security=low
Connection: keep-alive
--ar1Z9uxU-NFJV-LskY52NwAAAEQ-F--
HTTP/1.1 403 Forbidden
Content-Type: text/html; charset=iso-8859-1
Connection: close
--ar1Z9uxU-NFJV-LskY52NwAAAEQ-H--
Message: Warning. Pattern match "^[\\d.]+$" at REQUEST_HEADERS:Host. [file "/etc/modsecurity/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "738"] [id "920350"] [msg "Host header is a numeric IP address"] [severity "WARNING"] [ver "OWASP_CRS/3.3.4"]
Message: Access denied with code 403 (phase 2). Matched "Operator DetectSQLi" at ARGS:id. [file "/etc/modsecurity/owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"] [line "45"] [id "942100"] [msg "SQL Injection Attack Detected via libinjection"] [data "Matched Data: 1' OR '1'='1 found within ARGS:id: 1' OR '1'='1"] [severity "CRITICAL"] [ver "OWASP_CRS/3.3.4"] [tag "attack-sqli"] [tag "OWASP_CRS"]
Message: Warning. Operator GE reached 5 at TX:inbound_anomaly_score. [file "/etc/modsecurity/owasp-crs/rules/RESPONSE-980-CORRELATION.conf"] [line "91"] [id "980130"] [msg "Inbound Anomaly Score Exceeded (Total Score: 8)"] [severity "CRITICAL"] [ver "OWASP_CRS/3.3.4"]
Action: Intercepted (eval_status 403)
Stopwatch: 1727792538000000 1420 (- - -)
Server: Apache/2.4.57 (Debian)
Engine-Mode: "ENABLED"
--ar1Z9uxU-NFJV-LskY52NwAAAEQ-Z--
"""
        evidence = parse_modsecurity_sqli_event(
            raw_event=live_derived_event,
            host="web01",
        )

        self.assertEqual(evidence.host, "web01")
        self.assertEqual(evidence.src_ip, "192.168.1.100")
        self.assertEqual(evidence.rule_id, 942100)
        self.assertEqual(evidence.rule_msg, "SQL Injection Attack Detected via libinjection")
        self.assertEqual(evidence.severity, "CRITICAL")
        self.assertEqual(evidence.anomaly_score, 8)
        self.assertEqual(evidence.unique_id, "ar1Z9uxU-NFJV-LskY52NwAAAEQ")


if __name__ == "__main__":
    unittest.main()
