"""Unit tests for Milestone 12B: ModSecurity SQLi Detection & Evidence Contract.

TDD RED PHASE ONLY.

Defines the normalized evidence contract for Apache ModSecurity / OWASP CRS
SQL Injection (SQLi) attack events detected on WEB01.

Validates:
1. ModSecuritySqliEvidence immutable schema, types, and values.
2. Deterministic to_dict() output.
3. Strict validation boundaries rejecting invalid/missing/malformed fields.
4. Rejection of fragments/non-transaction entries lacking full transaction context.
"""

from dataclasses import FrozenInstanceError
import unittest

try:
    from investigator.modsecurity import (
        ModSecurityError,
        ModSecuritySqliEvidence,
        ModSecurityValidationError,
    )
except ImportError:
    try:
        from investigator.modsecurity import (  # type: ignore
            ModSecurityError,
            ModSecurityEvidence as ModSecuritySqliEvidence,
            ModSecurityValidationError,
        )
    except ImportError:
        ModSecurityError = None  # type: ignore
        ModSecuritySqliEvidence = None  # type: ignore
        ModSecurityValidationError = None  # type: ignore


class TestModSecuritySqliEvidenceContract(unittest.TestCase):
    """Tests establishing the normalized ModSecurity SQLi evidence contract."""

    def setUp(self) -> None:
        """Define canonical valid evidence fields from live verified WEB01 telemetry."""
        self.valid_fields = {
            "host": "web01",
            "src_ip": "192.168.1.100",
            "rule_id": 942100,
            "rule_msg": "SQL Injection Attack Detected via libinjection",
            "severity": "CRITICAL",
            "anomaly_score": 8,
            "unique_id": "ar1Z9uxU-NFJV-LskY52NwAAAEQ",
        }

    # -------------------------------------------------------------------------
    # VALID CASES
    # -------------------------------------------------------------------------

    def test_valid_evidence_creation(self) -> None:
        """Fully populated valid SQLi evidence object instantiates with correct values and types."""
        if ModSecuritySqliEvidence is None:
            self.fail("RED PHASE: ModSecuritySqliEvidence is not yet implemented in investigator.modsecurity")

        evidence = ModSecuritySqliEvidence(**self.valid_fields)

        self.assertEqual(evidence.host, "web01")
        self.assertEqual(evidence.src_ip, "192.168.1.100")
        self.assertEqual(evidence.rule_id, 942100)
        self.assertEqual(evidence.rule_msg, "SQL Injection Attack Detected via libinjection")
        self.assertEqual(evidence.severity, "CRITICAL")
        self.assertEqual(evidence.anomaly_score, 8)
        self.assertEqual(evidence.unique_id, "ar1Z9uxU-NFJV-LskY52NwAAAEQ")

        self.assertIs(type(evidence.host), str)
        self.assertIs(type(evidence.src_ip), str)
        self.assertIs(type(evidence.rule_id), int)
        self.assertIs(type(evidence.rule_msg), str)
        self.assertIs(type(evidence.severity), str)
        self.assertIs(type(evidence.anomaly_score), int)
        self.assertIs(type(evidence.unique_id), str)

    def test_evidence_immutability(self) -> None:
        """ModSecuritySqliEvidence is frozen and fields cannot be mutated."""
        if ModSecuritySqliEvidence is None:
            self.fail("RED PHASE: ModSecuritySqliEvidence is not yet implemented in investigator.modsecurity")

        evidence = ModSecuritySqliEvidence(**self.valid_fields)
        with self.assertRaises((FrozenInstanceError, AttributeError)):
            evidence.host = "web02"  # type: ignore[misc]

    def test_deterministic_to_dict_output(self) -> None:
        """to_dict() returns a deterministic dictionary matching declared schema."""
        if ModSecuritySqliEvidence is None:
            self.fail("RED PHASE: ModSecuritySqliEvidence is not yet implemented in investigator.modsecurity")

        evidence = ModSecuritySqliEvidence(**self.valid_fields)
        expected = {
            "host": "web01",
            "src_ip": "192.168.1.100",
            "rule_id": 942100,
            "rule_msg": "SQL Injection Attack Detected via libinjection",
            "severity": "CRITICAL",
            "anomaly_score": 8,
            "unique_id": "ar1Z9uxU-NFJV-LskY52NwAAAEQ",
        }
        self.assertEqual(evidence.to_dict(), expected)

    # -------------------------------------------------------------------------
    # INVALID / REJECTED CASES — src_ip
    # -------------------------------------------------------------------------

    def test_missing_or_empty_src_ip_rejected(self) -> None:
        """Missing, None, empty, or whitespace-only src_ip is rejected fail-closed."""
        if ModSecuritySqliEvidence is None:
            self.fail("RED PHASE: ModSecuritySqliEvidence is not yet implemented in investigator.modsecurity")

        error_types = (ModSecurityValidationError, ValueError, TypeError) if ModSecurityValidationError else (ValueError, TypeError)

        # Missing entirely
        incomplete = dict(self.valid_fields)
        del incomplete["src_ip"]
        with self.assertRaises(error_types):
            ModSecuritySqliEvidence(**incomplete)

        # None
        with self.assertRaises(error_types):
            bad = dict(self.valid_fields, src_ip=None)
            ModSecuritySqliEvidence(**bad)

        # Empty string
        with self.assertRaises(error_types):
            bad = dict(self.valid_fields, src_ip="")
            ModSecuritySqliEvidence(**bad)

        # Whitespace only
        with self.assertRaises(error_types):
            bad = dict(self.valid_fields, src_ip="   ")
            ModSecuritySqliEvidence(**bad)

    def test_malformed_src_ip_rejected(self) -> None:
        """Malformed IP literals (non-IP, CIDR, URL, port notation) are rejected."""
        if ModSecuritySqliEvidence is None:
            self.fail("RED PHASE: ModSecuritySqliEvidence is not yet implemented in investigator.modsecurity")

        error_types = (ModSecurityValidationError, ValueError, TypeError) if ModSecurityValidationError else (ValueError, TypeError)
        invalid_ips = [
            "not-an-ip",
            "999.999.999.999",
            "192.168.1.100/24",
            "http://192.168.1.100",
            "192.168.1.100:80",
            "192.168.1.",
            "192.168.1.100.1",
            1921681100,
            True,
            ["192.168.1.100"],
        ]
        for bad_ip in invalid_ips:
            with self.subTest(bad_ip=bad_ip):
                with self.assertRaises(error_types):
                    bad = dict(self.valid_fields, src_ip=bad_ip)
                    ModSecuritySqliEvidence(**bad)

    def test_ipv6_src_ip_rejected(self) -> None:
        """Syntactically valid IPv6 addresses are rejected; Milestone 12B contract is IPv4-only."""
        if ModSecuritySqliEvidence is None:
            self.fail("ModSecuritySqliEvidence is not implemented in investigator.modsecurity")

        error_types = (ModSecurityValidationError, ValueError, TypeError) if ModSecurityValidationError else (ValueError, TypeError)
        valid_ipv6_addresses = [
            "2001:db8::1",
            "::1",
            "fe80::1",
            "2600:1400:1::1",
            "::ffff:192.168.1.100",
        ]
        for ipv6 in valid_ipv6_addresses:
            with self.subTest(ipv6=ipv6):
                with self.assertRaises(error_types):
                    bad = dict(self.valid_fields, src_ip=ipv6)
                    ModSecuritySqliEvidence(**bad)

    # -------------------------------------------------------------------------
    # INVALID / REJECTED CASES — host
    # -------------------------------------------------------------------------

    def test_missing_or_empty_host_rejected(self) -> None:
        """Missing, None, empty, whitespace-only, or non-string host is rejected."""
        if ModSecuritySqliEvidence is None:
            self.fail("RED PHASE: ModSecuritySqliEvidence is not yet implemented in investigator.modsecurity")

        error_types = (ModSecurityValidationError, ValueError, TypeError) if ModSecurityValidationError else (ValueError, TypeError)

        incomplete = dict(self.valid_fields)
        del incomplete["host"]
        with self.assertRaises(error_types):
            ModSecuritySqliEvidence(**incomplete)

        for bad_host in (None, "", "   ", 123, True):
            with self.subTest(bad_host=bad_host):
                with self.assertRaises(error_types):
                    bad = dict(self.valid_fields, host=bad_host)
                    ModSecuritySqliEvidence(**bad)

    # -------------------------------------------------------------------------
    # INVALID / REJECTED CASES — rule_id
    # -------------------------------------------------------------------------

    def test_wrong_or_unsupported_rule_id_rejected(self) -> None:
        """Non-SQLi rule IDs or unsupported rule IDs are rejected fail-closed."""
        if ModSecuritySqliEvidence is None:
            self.fail("RED PHASE: ModSecuritySqliEvidence is not yet implemented in investigator.modsecurity")

        error_types = (ModSecurityValidationError, ValueError, TypeError) if ModSecurityValidationError else (ValueError, TypeError)
        unsupported_rule_ids = [
            920100,   # Protocol violation
            941100,   # XSS rule
            930100,   # LFI rule
            999999,   # Unknown rule
            0,        # Zero
            -942100,  # Negative
        ]
        for bad_id in unsupported_rule_ids:
            with self.subTest(bad_id=bad_id):
                with self.assertRaises(error_types):
                    bad = dict(self.valid_fields, rule_id=bad_id)
                    ModSecuritySqliEvidence(**bad)

    def test_rule_id_type_validation_rejects_bool_and_non_int(self) -> None:
        """rule_id must be exact int type; bool, float, str, None are rejected."""
        if ModSecuritySqliEvidence is None:
            self.fail("RED PHASE: ModSecuritySqliEvidence is not yet implemented in investigator.modsecurity")

        error_types = (ModSecurityValidationError, ValueError, TypeError) if ModSecurityValidationError else (ValueError, TypeError)
        invalid_types = [
            True,        # bool (int subclass in Python) must be rejected
            False,
            "942100",    # str
            942100.0,    # float
            None,
        ]
        for bad_val in invalid_types:
            with self.subTest(bad_val=bad_val):
                with self.assertRaises(error_types):
                    bad = dict(self.valid_fields, rule_id=bad_val)
                    ModSecuritySqliEvidence(**bad)

    # -------------------------------------------------------------------------
    # INVALID / REJECTED CASES — rule_msg
    # -------------------------------------------------------------------------

    def test_missing_or_empty_rule_msg_rejected(self) -> None:
        """Missing, empty, or whitespace-only rule_msg is rejected."""
        if ModSecuritySqliEvidence is None:
            self.fail("RED PHASE: ModSecuritySqliEvidence is not yet implemented in investigator.modsecurity")

        error_types = (ModSecurityValidationError, ValueError, TypeError) if ModSecurityValidationError else (ValueError, TypeError)

        incomplete = dict(self.valid_fields)
        del incomplete["rule_msg"]
        with self.assertRaises(error_types):
            ModSecuritySqliEvidence(**incomplete)

        for bad_msg in (None, "", "   ", 942100, True):
            with self.subTest(bad_msg=bad_msg):
                with self.assertRaises(error_types):
                    bad = dict(self.valid_fields, rule_msg=bad_msg)
                    ModSecuritySqliEvidence(**bad)

    def test_wrong_or_non_sqli_rule_msg_rejected(self) -> None:
        """Rule message that does not represent SQL injection is rejected."""
        if ModSecuritySqliEvidence is None:
            self.fail("RED PHASE: ModSecuritySqliEvidence is not yet implemented in investigator.modsecurity")

        error_types = (ModSecurityValidationError, ValueError, TypeError) if ModSecurityValidationError else (ValueError, TypeError)
        non_sqli_messages = [
            "XSS Attack Detected via libinjection",
            "Inbound Anomaly Score Exceeded",
            "Request Header Fields Too Large",
            "Path Traversal Attack Detected",
            "Benign Web Request",
        ]
        for bad_msg in non_sqli_messages:
            with self.subTest(bad_msg=bad_msg):
                with self.assertRaises(error_types):
                    bad = dict(self.valid_fields, rule_msg=bad_msg)
                    ModSecuritySqliEvidence(**bad)

    # -------------------------------------------------------------------------
    # INVALID / REJECTED CASES — severity
    # -------------------------------------------------------------------------

    def test_missing_or_empty_severity_rejected(self) -> None:
        """Missing, empty, or whitespace-only severity is rejected."""
        if ModSecuritySqliEvidence is None:
            self.fail("RED PHASE: ModSecuritySqliEvidence is not yet implemented in investigator.modsecurity")

        error_types = (ModSecurityValidationError, ValueError, TypeError) if ModSecurityValidationError else (ValueError, TypeError)

        incomplete = dict(self.valid_fields)
        del incomplete["severity"]
        with self.assertRaises(error_types):
            ModSecuritySqliEvidence(**incomplete)

        for bad_sev in (None, "", "   ", 1, True):
            with self.subTest(bad_sev=bad_sev):
                with self.assertRaises(error_types):
                    bad = dict(self.valid_fields, severity=bad_sev)
                    ModSecuritySqliEvidence(**bad)

    def test_unsupported_severity_rejected(self) -> None:
        """Severities not matching allowed CRS severity levels are rejected."""
        if ModSecuritySqliEvidence is None:
            self.fail("RED PHASE: ModSecuritySqliEvidence is not yet implemented in investigator.modsecurity")

        error_types = (ModSecurityValidationError, ValueError, TypeError) if ModSecurityValidationError else (ValueError, TypeError)
        unsupported_severities = [
            "EXTREME",
            "UNKNOWN",
            "INFORMATIONAL",
            "DEBUG",
            "FATAL",
        ]
        for bad_sev in unsupported_severities:
            with self.subTest(bad_sev=bad_sev):
                with self.assertRaises(error_types):
                    bad = dict(self.valid_fields, severity=bad_sev)
                    ModSecuritySqliEvidence(**bad)

    # -------------------------------------------------------------------------
    # INVALID / REJECTED CASES — anomaly_score
    # -------------------------------------------------------------------------

    def test_bool_passed_as_anomaly_score_rejected(self) -> None:
        """Boolean True/False passed for anomaly_score must be explicitly rejected."""
        if ModSecuritySqliEvidence is None:
            self.fail("RED PHASE: ModSecuritySqliEvidence is not yet implemented in investigator.modsecurity")

        error_types = (ModSecurityValidationError, ValueError, TypeError) if ModSecurityValidationError else (ValueError, TypeError)
        for bool_val in (True, False):
            with self.subTest(bool_val=bool_val):
                with self.assertRaises(error_types):
                    bad = dict(self.valid_fields, anomaly_score=bool_val)
                    ModSecuritySqliEvidence(**bad)

    def test_negative_anomaly_score_rejected(self) -> None:
        """Negative anomaly scores are rejected fail-closed."""
        if ModSecuritySqliEvidence is None:
            self.fail("RED PHASE: ModSecuritySqliEvidence is not yet implemented in investigator.modsecurity")

        error_types = (ModSecurityValidationError, ValueError, TypeError) if ModSecurityValidationError else (ValueError, TypeError)
        for neg_val in (-1, -8, -100):
            with self.subTest(neg_val=neg_val):
                with self.assertRaises(error_types):
                    bad = dict(self.valid_fields, anomaly_score=neg_val)
                    ModSecuritySqliEvidence(**bad)

    def test_malformed_anomaly_score_rejected(self) -> None:
        """Non-integer anomaly_score values (str, float, None) are rejected."""
        if ModSecuritySqliEvidence is None:
            self.fail("RED PHASE: ModSecuritySqliEvidence is not yet implemented in investigator.modsecurity")

        error_types = (ModSecurityValidationError, ValueError, TypeError) if ModSecurityValidationError else (ValueError, TypeError)
        for malformed in ("8", 8.0, 8.5, None, [8]):
            with self.subTest(malformed=malformed):
                with self.assertRaises(error_types):
                    bad = dict(self.valid_fields, anomaly_score=malformed)
                    ModSecuritySqliEvidence(**bad)

    # -------------------------------------------------------------------------
    # INVALID / REJECTED CASES — unique_id
    # -------------------------------------------------------------------------

    def test_missing_or_empty_unique_id_rejected(self) -> None:
        """Missing, empty, or whitespace-only transaction unique_id is rejected."""
        if ModSecuritySqliEvidence is None:
            self.fail("RED PHASE: ModSecuritySqliEvidence is not yet implemented in investigator.modsecurity")

        error_types = (ModSecurityValidationError, ValueError, TypeError) if ModSecurityValidationError else (ValueError, TypeError)

        incomplete = dict(self.valid_fields)
        del incomplete["unique_id"]
        with self.assertRaises(error_types):
            ModSecuritySqliEvidence(**incomplete)

        for bad_uid in (None, "", "   ", 12345, True):
            with self.subTest(bad_uid=bad_uid):
                with self.assertRaises(error_types):
                    bad = dict(self.valid_fields, unique_id=bad_uid)
                    ModSecuritySqliEvidence(**bad)

    # -------------------------------------------------------------------------
    # FRAGMENT / NON-TRANSACTION CASE
    # -------------------------------------------------------------------------

    def test_fragment_without_transaction_fields_rejected(self) -> None:
        """ModSecurity fragment containing CRS rule text but lacking attack transaction fields is rejected."""
        if ModSecuritySqliEvidence is None:
            self.fail("RED PHASE: ModSecuritySqliEvidence is not yet implemented in investigator.modsecurity")

        error_types = (ModSecurityValidationError, ValueError, TypeError) if ModSecurityValidationError else (ValueError, TypeError)

        # Fragment missing transaction unique_id
        fragment_no_uid = {
            "host": "web01",
            "src_ip": "192.168.1.100",
            "rule_id": 942100,
            "rule_msg": "SQL Injection Attack Detected via libinjection",
            "severity": "CRITICAL",
            "anomaly_score": 8,
        }
        with self.assertRaises(error_types):
            ModSecuritySqliEvidence(**fragment_no_uid)  # type: ignore[call-arg]

        # Fragment missing source IP
        fragment_no_src = {
            "host": "web01",
            "rule_id": 942100,
            "rule_msg": "SQL Injection Attack Detected via libinjection",
            "severity": "CRITICAL",
            "anomaly_score": 8,
            "unique_id": "ar1Z9uxU-NFJV-LskY52NwAAAEQ",
        }
        with self.assertRaises(error_types):
            ModSecuritySqliEvidence(**fragment_no_src)  # type: ignore[call-arg]

        # Fragment missing host
        fragment_no_host = {
            "src_ip": "192.168.1.100",
            "rule_id": 942100,
            "rule_msg": "SQL Injection Attack Detected via libinjection",
            "severity": "CRITICAL",
            "anomaly_score": 8,
            "unique_id": "ar1Z9uxU-NFJV-LskY52NwAAAEQ",
        }
        with self.assertRaises(error_types):
            ModSecuritySqliEvidence(**fragment_no_host)  # type: ignore[call-arg]

        # Fragment with generic placeholder unique_id
        fragment_placeholder_uid = dict(self.valid_fields, unique_id="-")
        with self.assertRaises(error_types):
            ModSecuritySqliEvidence(**fragment_placeholder_uid)


if __name__ == "__main__":
    unittest.main()
