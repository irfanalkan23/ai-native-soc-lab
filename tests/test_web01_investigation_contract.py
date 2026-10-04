"""Unit tests for the WEB01 AI-assisted investigation contracts.

Milestone 13A — TDD RED Phase.

Defines and validates the typed input and output contracts for WEB01 web-application
telemetry investigations without modifying production code or existing agent behavior.

Architecture Principles:
1. AI proposes -> deterministic policy evaluates -> human approves consequential actions
   -> system executes only permitted/simulated actions -> everything is logged and evaluated.
2. Single-Agent Architecture: WEB01 contracts coexist alongside existing DC01/PowerShell
   contracts without requiring a second agent architecture or separate ToolRouter.
3. Untrusted Evidence Boundary: Raw telemetry (_raw, ModSecurity audit transactions,
   raw Splunk envelopes, raw VirusTotal payloads) is NEVER placed into the AI contract.
4. Advisory-Only AI Output: AI emits bounded assessment, confidence, and recommendations.
   The AI has ZERO execution authority (no isolate_host, disable_account, block_ip,
   or firewall_change fields).
5. Strict Schema Invariants: Input and output models are frozen (immutable) dataclasses
   enforcing fail-closed validation on all fields.
"""

from dataclasses import FrozenInstanceError, fields
import unittest
from typing import Any, Dict

# Existing single-agent contracts (must remain unaffected)
from investigator.schemas import (
    ConfidenceLevel,
    InvestigationInput,
    InvestigationResult,
    SchemaValidationError,
)

# Milestone 13A Target Contracts (TDD RED: Imported from investigator.schemas)
try:
    from investigator.schemas import (  # type: ignore[attr-defined]
        ALLOWED_WEB01_ATTACK_TYPES,
        WEB01_SUPPORTED_DETECTION_ID,
        WEB01_SUPPORTED_DETECTION_TYPE,
        WEB01_SUPPORTED_HOST,
        WEB01_SUPPORTED_RULE_ID,
        Web01InvestigationAssessment,
        Web01InvestigationRequest,
    )
except ImportError:
    Web01InvestigationRequest = None  # type: ignore[assignment,misc]
    Web01InvestigationAssessment = None  # type: ignore[assignment,misc]
    ALLOWED_WEB01_ATTACK_TYPES = None  # type: ignore[assignment,misc]
    WEB01_SUPPORTED_DETECTION_ID = None  # type: ignore[assignment,misc]
    WEB01_SUPPORTED_HOST = None  # type: ignore[assignment,misc]
    WEB01_SUPPORTED_DETECTION_TYPE = None  # type: ignore[assignment,misc]
    WEB01_SUPPORTED_RULE_ID = None  # type: ignore[assignment,misc]


class TestWeb01InvestigationContract(unittest.TestCase):
    """Test suite for Milestone 13A WEB01 investigation input and output contracts."""

    def _require_contracts(self) -> None:
        """Helper to ensure target contracts are implemented; fails closed during RED phase."""
        if Web01InvestigationRequest is None or Web01InvestigationAssessment is None:
            self.fail(
                "Milestone 13A RED Phase: Web01InvestigationRequest / "
                "Web01InvestigationAssessment not yet implemented in investigator.schemas."
            )

    # =========================================================================
    # 1. Web01InvestigationRequest — Valid & Invariant Tests
    # =========================================================================

    def test_valid_web01_investigation_request(self) -> None:
        """Verify successful creation of compliant Web01InvestigationRequest."""
        self._require_contracts()
        req = Web01InvestigationRequest(
            detection_id="DET-WEB-001",
            host="web01",
            detection_type="modsecurity_sqli",
            rule_id=942100,
        )
        self.assertEqual(req.detection_id, "DET-WEB-001")
        self.assertEqual(req.host, "web01")
        self.assertEqual(req.detection_type, "modsecurity_sqli")
        self.assertEqual(req.rule_id, 942100)

    def test_request_immutability(self) -> None:
        """Verify Web01InvestigationRequest is deeply immutable (frozen dataclass)."""
        self._require_contracts()
        req = Web01InvestigationRequest(
            detection_id="DET-WEB-001",
            host="web01",
            detection_type="modsecurity_sqli",
            rule_id=942100,
        )
        with self.assertRaises((FrozenInstanceError, AttributeError, TypeError)):
            req.host = "DC01"  # type: ignore[misc]

    def test_request_deterministic_to_dict(self) -> None:
        """Verify Web01InvestigationRequest produces a deterministic dict representation."""
        self._require_contracts()
        req = Web01InvestigationRequest(
            detection_id="DET-WEB-001",
            host="web01",
            detection_type="modsecurity_sqli",
            rule_id=942100,
        )
        expected: Dict[str, Any] = {
            "detection_id": "DET-WEB-001",
            "host": "web01",
            "detection_type": "modsecurity_sqli",
            "rule_id": 942100,
        }
        self.assertEqual(req.to_dict(), expected)

    def test_request_rejects_none_or_empty_fields(self) -> None:
        """Verify Web01InvestigationRequest rejects None, empty, or whitespace strings."""
        self._require_contracts()
        base = {
            "detection_id": "DET-WEB-001",
            "host": "web01",
            "detection_type": "modsecurity_sqli",
            "rule_id": 942100,
        }
        for str_field in ("detection_id", "host", "detection_type"):
            for bad_val in (None, "", "   ", "\t\n"):
                kwargs = dict(base)
                kwargs[str_field] = bad_val
                with self.subTest(field=str_field, val=repr(bad_val)):
                    with self.assertRaises((SchemaValidationError, ValueError, TypeError)):
                        Web01InvestigationRequest(**kwargs)

    def test_request_rejects_wrong_detection_id(self) -> None:
        """Verify Web01InvestigationRequest rejects unsupported detection IDs."""
        self._require_contracts()
        invalid_ids = ["DET-WEB-999", "DET-001", "INC-2026-001", "random-id"]
        for bad_id in invalid_ids:
            with self.subTest(bad_id=bad_id):
                with self.assertRaises((SchemaValidationError, ValueError)):
                    Web01InvestigationRequest(
                        detection_id=bad_id,
                        host="web01",
                        detection_type="modsecurity_sqli",
                        rule_id=942100,
                    )

    def test_request_rejects_wrong_host(self) -> None:
        """Verify Web01InvestigationRequest rejects hosts other than web01."""
        self._require_contracts()
        invalid_hosts = ["DC01", "web02", "srv-linux", "192.168.1.102"]
        for bad_host in invalid_hosts:
            with self.subTest(bad_host=bad_host):
                with self.assertRaises((SchemaValidationError, ValueError)):
                    Web01InvestigationRequest(
                        detection_id="DET-WEB-001",
                        host=bad_host,
                        detection_type="modsecurity_sqli",
                        rule_id=942100,
                    )

    def test_request_rejects_host_casing_mismatch(self) -> None:
        """Verify Web01InvestigationRequest enforces exact host casing ('web01')."""
        self._require_contracts()
        for bad_casing in ["WEB01", "Web01", "wEb01"]:
            with self.subTest(bad_casing=bad_casing):
                with self.assertRaises((SchemaValidationError, ValueError)):
                    Web01InvestigationRequest(
                        detection_id="DET-WEB-001",
                        host=bad_casing,
                        detection_type="modsecurity_sqli",
                        rule_id=942100,
                    )

    def test_request_rejects_wrong_detection_type(self) -> None:
        """Verify Web01InvestigationRequest rejects unsupported detection types."""
        self._require_contracts()
        invalid_types = ["powershell", "xss", "rce", "directory_traversal", "suricata_alert"]
        for bad_type in invalid_types:
            with self.subTest(bad_type=bad_type):
                with self.assertRaises((SchemaValidationError, ValueError)):
                    Web01InvestigationRequest(
                        detection_id="DET-WEB-001",
                        host="web01",
                        detection_type=bad_type,
                        rule_id=942100,
                    )

    def test_request_rejects_wrong_rule_id(self) -> None:
        """Verify Web01InvestigationRequest rejects rule IDs other than allowlisted 942100."""
        self._require_contracts()
        invalid_rules = [999999, 942101, 941100, 0, -1]
        for bad_rule in invalid_rules:
            with self.subTest(bad_rule=bad_rule):
                with self.assertRaises((SchemaValidationError, ValueError)):
                    Web01InvestigationRequest(
                        detection_id="DET-WEB-001",
                        host="web01",
                        detection_type="modsecurity_sqli",
                        rule_id=bad_rule,
                    )

    def test_request_rejects_bool_rule_id(self) -> None:
        """Verify Web01InvestigationRequest strictly rejects bool masquerading as int."""
        self._require_contracts()
        for bool_val in (True, False):
            with self.subTest(bool_val=bool_val):
                with self.assertRaises((SchemaValidationError, ValueError, TypeError)):
                    Web01InvestigationRequest(
                        detection_id="DET-WEB-001",
                        host="web01",
                        detection_type="modsecurity_sqli",
                        rule_id=bool_val,  # type: ignore[arg-type]
                    )

    def test_request_rejects_non_int_rule_id(self) -> None:
        """Verify Web01InvestigationRequest rejects strings, floats, and None for rule_id."""
        self._require_contracts()
        for non_int in ("942100", 942100.0, None, [942100]):
            with self.subTest(non_int=non_int):
                with self.assertRaises((SchemaValidationError, ValueError, TypeError)):
                    Web01InvestigationRequest(
                        detection_id="DET-WEB-001",
                        host="web01",
                        detection_type="modsecurity_sqli",
                        rule_id=non_int,  # type: ignore[arg-type]
                    )

    def test_request_contains_no_raw_spl_or_provider_controls(self) -> None:
        """Verify Web01InvestigationRequest rejects arbitrary SPL, provider, or tool controls."""
        self._require_contracts()
        # Verify schema field list only has 4 bounded fields
        field_names = {f.name for f in fields(Web01InvestigationRequest)}
        expected_fields = {"detection_id", "host", "detection_type", "rule_id"}
        self.assertEqual(field_names, expected_fields)

        # Attempting to supply arbitrary tool/SPL/provider kwargs must fail closed
        with self.assertRaises(TypeError):
            Web01InvestigationRequest(
                detection_id="DET-WEB-001",
                host="web01",
                detection_type="modsecurity_sqli",
                rule_id=942100,
                spl="search index=* | evil",  # type: ignore[call-arg]
            )

    # =========================================================================
    # 2. Web01InvestigationAssessment — Valid & Invariant Tests
    # =========================================================================

    def test_valid_web01_investigation_assessment(self) -> None:
        """Verify successful creation of compliant Web01InvestigationAssessment."""
        self._require_contracts()
        assessment = Web01InvestigationAssessment(
            assessment="SQL injection attempt detected on web01 targeting OWASP Juice Shop via libinjection rule 942100.",
            confidence="high",
            evidence_summary="ModSecurity rule 942100 triggered with anomaly score 8; HTTP 403 returned.",
            attack_type="sql_injection",
            escalation_recommended=True,
            recommended_next_step="Review WAF audit logs and confirm blocked status.",
        )
        self.assertIn("SQL injection attempt", assessment.assessment)
        self.assertEqual(assessment.confidence, "high")
        self.assertEqual(assessment.attack_type, "sql_injection")
        self.assertTrue(assessment.escalation_recommended)
        self.assertIn("Review WAF audit logs", assessment.recommended_next_step)

    def test_assessment_immutability(self) -> None:
        """Verify Web01InvestigationAssessment is deeply immutable."""
        self._require_contracts()
        assessment = Web01InvestigationAssessment(
            assessment="SQL injection attempt detected on web01.",
            confidence="medium",
            evidence_summary="ModSecurity rule 942100 triggered.",
            attack_type="sql_injection",
            escalation_recommended=False,
            recommended_next_step="Monitor web01 for repeat requests.",
        )
        with self.assertRaises((FrozenInstanceError, AttributeError, TypeError)):
            assessment.confidence = "high"  # type: ignore[misc]

    def test_assessment_deterministic_to_dict(self) -> None:
        """Verify Web01InvestigationAssessment produces a deterministic dict representation."""
        self._require_contracts()
        assessment = Web01InvestigationAssessment(
            assessment="SQL injection attempt detected on web01.",
            confidence="low",
            evidence_summary="ModSecurity rule 942100 triggered.",
            attack_type="sql_injection",
            escalation_recommended=False,
            recommended_next_step="No action required.",
        )
        d = assessment.to_dict()
        expected = {
            "assessment": "SQL injection attempt detected on web01.",
            "confidence": "low",
            "evidence_summary": "ModSecurity rule 942100 triggered.",
            "attack_type": "sql_injection",
            "escalation_recommended": False,
            "recommended_next_step": "No action required.",
        }
        self.assertEqual(d, expected)

    def test_assessment_rejects_empty_fields(self) -> None:
        """Verify Web01InvestigationAssessment rejects None, empty, or whitespace strings."""
        self._require_contracts()
        base = {
            "assessment": "Valid assessment text",
            "confidence": "high",
            "evidence_summary": "Valid evidence summary",
            "attack_type": "sql_injection",
            "escalation_recommended": True,
            "recommended_next_step": "Valid next step",
        }
        for str_field in ("assessment", "evidence_summary", "attack_type", "recommended_next_step"):
            for bad_val in (None, "", "   ", "\t"):
                kwargs = dict(base)
                kwargs[str_field] = bad_val
                with self.subTest(field=str_field, val=repr(bad_val)):
                    with self.assertRaises((SchemaValidationError, ValueError, TypeError)):
                        Web01InvestigationAssessment(**kwargs)

    def test_assessment_rejects_invalid_confidence(self) -> None:
        """Verify Web01InvestigationAssessment strictly respects repository confidence scale."""
        self._require_contracts()
        invalid_levels = ["critical", "none", "very_high", "0.95", "", 10, True, False, None]
        for bad_conf in invalid_levels:
            with self.subTest(bad_conf=bad_conf):
                with self.assertRaises((SchemaValidationError, ValueError, TypeError)):
                    Web01InvestigationAssessment(
                        assessment="Valid assessment",
                        confidence=bad_conf,  # type: ignore[arg-type]
                        evidence_summary="Valid summary",
                        attack_type="sql_injection",
                        escalation_recommended=True,
                        recommended_next_step="Valid next step",
                    )

    def test_assessment_rejects_unsupported_attack_type(self) -> None:
        """Verify Web01InvestigationAssessment rejects attack types other than sql_injection."""
        self._require_contracts()
        unsupported = ["xss", "rce", "path_traversal", "dos", "malware", "phishing"]
        for bad_type in unsupported:
            with self.subTest(bad_type=bad_type):
                with self.assertRaises((SchemaValidationError, ValueError)):
                    Web01InvestigationAssessment(
                        assessment="Valid assessment",
                        confidence="high",
                        evidence_summary="Valid summary",
                        attack_type=bad_type,
                        escalation_recommended=True,
                        recommended_next_step="Valid next step",
                    )

    def test_assessment_rejects_non_bool_escalation_flag(self) -> None:
        """Verify escalation_recommended must be a strict boolean (not int, str, None)."""
        self._require_contracts()
        invalid_bools = [1, 0, "True", "False", "true", None, [True]]
        for bad_val in invalid_bools:
            with self.subTest(bad_val=bad_val):
                with self.assertRaises((SchemaValidationError, ValueError, TypeError)):
                    Web01InvestigationAssessment(
                        assessment="Valid assessment",
                        confidence="high",
                        evidence_summary="Valid summary",
                        attack_type="sql_injection",
                        escalation_recommended=bad_val,  # type: ignore[arg-type]
                        recommended_next_step="Valid next step",
                    )

    def test_assessment_is_advisory_only(self) -> None:
        """Verify Web01InvestigationAssessment has ZERO execution authority fields."""
        self._require_contracts()
        field_names = {f.name for f in fields(Web01InvestigationAssessment)}

        # Forbidden action execution fields
        forbidden_execution_fields = {
            "isolate_host",
            "disable_account",
            "block_ip",
            "firewall_change",
            "execute_containment",
            "action_executed",
            "status",
        }
        intersection = field_names.intersection(forbidden_execution_fields)
        self.assertEqual(
            intersection,
            set(),
            f"Web01InvestigationAssessment must not have execution fields: {intersection}",
        )

        # Attempting to supply action execution fields must fail closed
        with self.assertRaises(TypeError):
            Web01InvestigationAssessment(
                assessment="Valid assessment",
                confidence="high",
                evidence_summary="Valid summary",
                attack_type="sql_injection",
                escalation_recommended=True,
                recommended_next_step="Valid next step",
                isolate_host=True,  # type: ignore[call-arg]
            )

    # =========================================================================
    # 3. Security Boundary & Single-Agent Architecture Coexistence Tests
    # =========================================================================

    def test_contract_excludes_raw_modsecurity_payload(self) -> None:
        """Verify neither request nor assessment schemas expose raw telemetry fields."""
        self._require_contracts()
        raw_telemetry_fields = {
            "_raw",
            "raw_log",
            "raw_telemetry",
            "raw_payload",
            "raw_audit_log",
            "splunk_envelope",
            "virustotal_json",
        }
        req_fields = {f.name for f in fields(Web01InvestigationRequest)}
        assessment_fields = {f.name for f in fields(Web01InvestigationAssessment)}

        self.assertEqual(req_fields.intersection(raw_telemetry_fields), set())
        self.assertEqual(assessment_fields.intersection(raw_telemetry_fields), set())

    def test_contract_excludes_secret_fields(self) -> None:
        """Verify neither request nor assessment schemas expose credential or secret fields."""
        self._require_contracts()
        secret_fields = {
            "api_key",
            "token",
            "password",
            "authorization",
            "jira_token",
            "splunk_token",
        }
        req_fields = {f.name for f in fields(Web01InvestigationRequest)}
        assessment_fields = {f.name for f in fields(Web01InvestigationAssessment)}

        self.assertEqual(req_fields.intersection(secret_fields), set())
        self.assertEqual(assessment_fields.intersection(secret_fields), set())

    def test_web01_contract_coexists_with_existing_powershell_contract(self) -> None:
        """Verify WEB01 contracts coexist cleanly with existing PowerShell contracts."""
        self._require_contracts()

        # Existing PowerShell/DC01 contract continues to function identically
        ps_input = InvestigationInput(
            incident_id="INC-2026-001",
            timestamp="2026-09-15T17:05:00Z",
            host="DC01",
            user="SOCLAB\\Administrator",
            image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            command_line="powershell.exe -NoProfile -EncodedCommand VwBy...",
            parent_image="C:\\Windows\\System32\\cmd.exe",
            parent_command_line='"C:\\Windows\\system32\\cmd.exe"',
            detection_name="Suspicious Encoded PowerShell Execution",
            detection_id="4e4f13c0-89a9-4f0e-a08f-b70b9c19e729",
        )
        self.assertEqual(ps_input.host, "DC01")

        # New WEB01 contract operates in same process with distinct schema invariants
        web_req = Web01InvestigationRequest(
            detection_id="DET-WEB-001",
            host="web01",
            detection_type="modsecurity_sqli",
            rule_id=942100,
        )
        self.assertEqual(web_req.host, "web01")

        # Invariant verification: neither schema pollutes the other
        self.assertNotEqual(ps_input.host, web_req.host)
        self.assertFalse(hasattr(web_req, "command_line"))
        self.assertFalse(hasattr(ps_input, "detection_type"))


if __name__ == "__main__":
    unittest.main()
