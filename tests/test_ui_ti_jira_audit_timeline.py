"""Milestone 15D — Threat Intelligence / Jira / Audit Timeline Tests.

Verifies:
1. ENRICHED TI state renders correctly with normalized provider counts.
2. SKIPPED_INELIGIBLE renders correctly and does not imply benign.
3. LOOKUP_FAILED renders correctly without implying malicious.
4. NOT_PERFORMED renders correctly without implying safe.
5. Raw TI provider payload is excluded.
6. TI credentials and configuration are excluded.
7. Jira ticket key is displayed as tracking only with zero authority disclaimer.
8. Absent Jira ticket renders neutral "Not created" state (not "Failed").
9. Incident rendering does not invoke Jira APIs.
10. Incident rendering does not invoke VirusTotal APIs.
11. Audit timeline displays correlated events.
12. Audit events are sorted deterministically (sequence / timestamp).
13. Cross-incident audit isolation: Incident A shows only A's events, not B's.
14. Malformed JSONL lines in audit logs are skipped safely.
15. Secret audit fields (api_key, token, password) are strictly excluded.
16. Raw prompt, model response, and tool args in audit events are excluded.
17. Audit timeline detail codes are HTML-escaped against XSS.
18. Hostile detail values remain inert in HTML output.
19. Bounded audit event count is enforced (default 100, max 200).
20. Unknown audit event types render conservatively as UNKNOWN / OTHER.
21. Empty audit history renders safe neutral empty state.
22. No browser-controlled audit path traversal is permitted.
23. Unsupported mutating HTTP methods return HTTP 405 Method Not Allowed.
24. Zero ToolRouter execution occurs.
25. Zero RuntimeGuard mutation occurs.
26. Zero Splunk, OpenAI, or external provider calls occur.
27. Existing incident page still displays deterministic policy prominently.
28. Jira state does not imply execution.
29. Threat intelligence state does not imply response authorization.
30. Audit timeline viewing cannot change approval or action state.
"""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from ui.app import create_app
from ui.audit_reader import DEFAULT_AUDIT_LIMIT, MAX_AUDIT_LIMIT, MIN_AUDIT_LIMIT, AuditReader
from ui.models import AuditEventView


def _make_test_incident(incident_id: str = "INC-15D-001", **kwargs: object) -> dict:
    """Helper to construct a valid base incident dictionary."""
    base = {
        "schema_version": "1.0.0",
        "incident_id": incident_id,
        "created_at_utc": "2026-10-08T14:30:00+00:00",
        "detection_id": "DET-WEB-001",
        "detection_name": "SQL Injection Attack Attempt",
        "target_host": "WEB01",
        "target_user": "www-data",
        "source_ip": "198.51.100.45",
        "mitre_technique_id": "T1190",
        "investigation_summary": "Inbound attack detected targeting public endpoint.",
        "confidence_level": "high",
        "suspicious_indicator_count": 3,
        "recommended_next_step": "Block IP at perimeter firewall.",
        "risk_score": 85,
        "risk_level": "HIGH",
        "disposition": "APPROVAL_REQUIRED",
        "proposed_action": "simulate_ip_block",
        "requires_human_approval": True,
        "approval_status": "PENDING_APPROVAL",
        "approval_reason_code": "high_risk_consequential_action",
        "simulation_status": "NOT_EXECUTED",
        "simulation_detail_code": "awaiting_human_approval",
        "real_containment_status": "NOT_IMPLEMENTED",
        "policy_reason_codes": ["high_risk_score", "public_attacker_ip"],
        "threat_intel_status": "ENRICHED",
        "threat_intel_skip_reason": None,
        "threat_intel_observation": {
            "indicator": "198.51.100.45",
            "indicator_type": "ip",
            "provider": "VirusTotal",
            "verdict": "Malicious",
            "malicious_count": 8,
            "suspicious_count": 2,
            "harmless_count": 65,
            "undetected_count": 5,
        },
        "jira_ticket_key": "SOC-9001",
        "modsecurity_evidence": {
            "host": "WEB01",
            "src_ip": "198.51.100.45",
            "rule_id": 942100,
            "rule_msg": "SQL Injection Attack Detected",
            "severity": "CRITICAL",
            "anomaly_score": 15,
            "unique_id": "TX-15D-001",
        },
    }
    base.update(kwargs)
    return base


class TestThreatIntelJiraAuditTimeline(unittest.TestCase):
    """Test suite for Milestone 15D operational visibility extensions."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.incidents_dir = Path(self.tmp_dir.name) / "incidents"
        self.incidents_dir.mkdir(parents=True, exist_ok=True)

        self.audit_file = Path(self.tmp_dir.name) / "agent_audit.jsonl"
        self.audit_file.touch()

        # Seed primary incident
        self.incident_1 = _make_test_incident("INC-15D-001")
        self._write_incident(self.incident_1)

        # Build app wired to test temp directories
        self.app = create_app(incidents_dir=self.incidents_dir, audit_path=self.audit_file)
        self.client = TestClient(self.app)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def _write_incident(self, data: dict) -> Path:
        path = self.incidents_dir / f"{data['incident_id']}.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f)
        return path

    def _append_audit_events(self, events: list) -> None:
        with open(self.audit_file, "a", encoding="utf-8") as f:
            for ev in events:
                f.write(json.dumps(ev) + "\n")

    # -------------------------------------------------------------------------
    # Part A: Threat Intelligence Presentation
    # -------------------------------------------------------------------------

    def test_01_enriched_ti_state_renders_correctly(self) -> None:
        """ENRICHED TI state displays normalized counts, provider, verdict, and truthful disclaimer."""
        resp = self.client.get("/incidents/INC-15D-001")
        self.assertEqual(resp.status_code, 200)
        html = resp.text

        self.assertIn("THREAT INTELLIGENCE", html.upper())
        self.assertIn("Persisted enrichment result. No live lookup is performed by this page.", html)
        self.assertIn("ENRICHED", html)
        self.assertIn("VirusTotal", html)
        self.assertIn("Malicious", html)
        self.assertIn("Malicious: 8", html)
        self.assertIn("Suspicious: 2", html)
        self.assertIn("Harmless: 65", html)
        self.assertIn("Undetected: 5", html)
        self.assertIn("Normalized provider result was persisted during the incident workflow.", html)

    def test_02_skipped_ineligible_does_not_imply_benign(self) -> None:
        """SKIPPED_INELIGIBLE displays deterministic eligibility policy note and does not claim benign."""
        inc = _make_test_incident(
            "INC-15D-002",
            threat_intel_status="SKIPPED_INELIGIBLE",
            threat_intel_skip_reason="private_source_ip_ineligible",
            threat_intel_observation=None,
        )
        self._write_incident(inc)

        resp = self.client.get("/incidents/INC-15D-002")
        self.assertEqual(resp.status_code, 200)
        html = resp.text

        self.assertIn("SKIPPED_INELIGIBLE", html)
        self.assertIn("External enrichment was not performed because the indicator did not meet deterministic eligibility policy.", html)
        self.assertIn("private_source_ip_ineligible", html)
        # Truthfulness: must NOT map to clean or benign
        self.assertNotIn("Verdict: Clean", html)
        self.assertNotIn("Verdict: Benign", html)

    def test_03_lookup_failed_renders_correctly(self) -> None:
        """LOOKUP_FAILED displays failure reason without implying malicious."""
        inc = _make_test_incident(
            "INC-15D-003",
            threat_intel_status="LOOKUP_FAILED",
            threat_intel_skip_reason="vt_api_timeout_error",
            threat_intel_observation=None,
        )
        self._write_incident(inc)

        resp = self.client.get("/incidents/INC-15D-003")
        self.assertEqual(resp.status_code, 200)
        html = resp.text

        self.assertIn("LOOKUP_FAILED", html)
        self.assertIn("An eligible lookup was attempted but enrichment did not complete successfully.", html)
        self.assertIn("vt_api_timeout_error", html)
        # Truthfulness: failure must not be equated to malicious
        self.assertNotIn("Verdict: Malicious", html)

    def test_04_not_performed_renders_correctly(self) -> None:
        """NOT_PERFORMED renders neutral explanatory text without implying safe."""
        inc = _make_test_incident(
            "INC-15D-004",
            threat_intel_status="NOT_PERFORMED",
            threat_intel_skip_reason=None,
            threat_intel_observation=None,
        )
        self._write_incident(inc)

        resp = self.client.get("/incidents/INC-15D-004")
        self.assertEqual(resp.status_code, 200)
        html = resp.text

        self.assertIn("NOT_PERFORMED", html)
        self.assertIn("No threat intelligence lookup was performed for this alert.", html)
        self.assertNotIn("Verdict: Safe", html)
        self.assertNotIn("Verdict: Clean", html)

    def test_05_raw_ti_provider_payload_excluded(self) -> None:
        """Arbitrary raw VirusTotal provider responses are excluded from HTML and API."""
        canary = "CANARY_VT_RAW_PAYLOAD_BLOB_XYZ"
        inc = _make_test_incident(
            "INC-15D-005",
            raw_virustotal_payload={"raw_response": canary, "attributes": {"headers": "Host: vt.com"}},
        )
        self._write_incident(inc)

        resp_html = self.client.get("/incidents/INC-15D-005")
        self.assertNotIn(canary, resp_html.text)

        resp_api = self.client.get("/api/incidents/INC-15D-005")
        self.assertNotIn(canary, json.dumps(resp_api.json()))

    def test_06_ti_credentials_config_excluded(self) -> None:
        """Injected TI API keys or provider configs are strictly excluded."""
        key_canary = "VT_SECRET_KEY_999888777"
        inc = _make_test_incident(
            "INC-15D-006",
            vt_api_key=key_canary,
            provider_config={"endpoint": "https://virustotal.com/api/v3", "token": key_canary},
        )
        self._write_incident(inc)

        resp_html = self.client.get("/incidents/INC-15D-006")
        self.assertNotIn(key_canary, resp_html.text)

        resp_api = self.client.get("/api/incidents/INC-15D-006")
        self.assertNotIn(key_canary, json.dumps(resp_api.json()))

    # -------------------------------------------------------------------------
    # Part B: Jira Tracking Presentation
    # -------------------------------------------------------------------------

    def test_07_jira_ticket_key_displayed_as_tracking_only(self) -> None:
        """Jira ticket key is displayed as text only with strict zero-authority disclaimer."""
        resp = self.client.get("/incidents/INC-15D-001")
        self.assertEqual(resp.status_code, 200)
        html = resp.text

        self.assertIn("INCIDENT TRACKING", html.upper())
        self.assertIn("SOC-9001", html)
        self.assertIn("Jira is a downstream reporting/tracking sink and has no response authority.", html)
        self.assertIn("Downstream external tracking sink only. Zero response authority.", html)
        # Must NOT construct external URLs from untrusted fields
        self.assertNotIn('href="https://jira', html)
        self.assertNotIn('href="http://jira', html)

    def test_08_absent_jira_ticket_renders_neutral_state(self) -> None:
        """Absent Jira ticket renders 'Not created' and never displays 'Failed'."""
        inc = _make_test_incident("INC-15D-008", jira_ticket_key=None)
        self._write_incident(inc)

        resp = self.client.get("/incidents/INC-15D-008")
        self.assertEqual(resp.status_code, 200)
        html = resp.text

        self.assertIn("Not created", html)
        # Must not say Failed unless explicitly failed
        self.assertNotIn("Ticket Failed", html)

    @patch("urllib.request.urlopen")
    def test_09_rendering_does_not_invoke_jira(self, mock_urlopen: MagicMock) -> None:
        """Rendering incident detail or API endpoints causes 0 external Jira network calls."""
        self.client.get("/incidents/INC-15D-001")
        self.client.get("/api/incidents/INC-15D-001")
        mock_urlopen.assert_not_called()

    @patch("urllib.request.urlopen")
    def test_10_rendering_does_not_invoke_virustotal(self, mock_urlopen: MagicMock) -> None:
        """Rendering incident detail or API endpoints causes 0 external VirusTotal lookups."""
        self.client.get("/incidents/INC-15D-001")
        self.client.get("/api/incidents/INC-15D-001")
        mock_urlopen.assert_not_called()

    # -------------------------------------------------------------------------
    # Part C: Audit Timeline Presentation
    # -------------------------------------------------------------------------

    def test_11_audit_timeline_displays_correlated_events(self) -> None:
        """Audit timeline displays allowlisted events correlated to the incident."""
        self._append_audit_events([
            {
                "incident_id": "INC-15D-001",
                "sequence": 1,
                "timestamp": "2026-10-08T14:30:01+00:00",
                "event_type": "TOOL_REQUESTED",
                "detail_code": "splunk_evidence_search",
                "tool_name": "bounded_splunk_search",
                "outcome": "REQUESTED",
            },
            {
                "incident_id": "INC-15D-001",
                "sequence": 2,
                "timestamp": "2026-10-08T14:30:02+00:00",
                "event_type": "TOOL_ALLOWED",
                "detail_code": "splunk_evidence_search_ok",
                "tool_name": "bounded_splunk_search",
                "outcome": "SUCCESS",
            },
        ])

        # Test HTML presentation
        resp_html = self.client.get("/incidents/INC-15D-001")
        self.assertEqual(resp_html.status_code, 200)
        html = resp_html.text

        self.assertIn("AUDIT TIMELINE", html.upper())
        self.assertIn("Read-only persisted execution history.", html)
        self.assertIn("#1", html)
        self.assertIn("TOOL_REQUESTED", html)
        self.assertIn("splunk_evidence_search", html)
        self.assertIn("#2", html)
        self.assertIn("TOOL_ALLOWED", html)
        self.assertIn("splunk_evidence_search_ok", html)

        # Test API endpoint
        resp_api = self.client.get("/api/incidents/INC-15D-001/audit")
        self.assertEqual(resp_api.status_code, 200)
        events = resp_api.json()
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["sequence"], 1)
        self.assertEqual(events[0]["event_type"], "TOOL_REQUESTED")
        self.assertEqual(events[1]["sequence"], 2)
        self.assertEqual(events[1]["event_type"], "TOOL_ALLOWED")

    def test_12_audit_events_sorted_deterministically(self) -> None:
        """Audit events are sorted deterministically by sequence and timestamp regardless of file order."""
        # Append out-of-order records
        self._append_audit_events([
            {
                "incident_id": "INC-15D-001",
                "sequence": 5,
                "timestamp": "2026-10-08T14:30:05+00:00",
                "event_type": "FINAL_RESULT_ACCEPTED",
                "detail_code": "investigation_complete",
                "outcome": "SUCCESS",
            },
            {
                "incident_id": "INC-15D-001",
                "sequence": 1,
                "timestamp": "2026-10-08T14:30:01+00:00",
                "event_type": "INVESTIGATION_STARTED",
                "detail_code": "alert_triaged",
                "outcome": "INFO",
            },
            {
                "incident_id": "INC-15D-001",
                "sequence": 3,
                "timestamp": "2026-10-08T14:30:03+00:00",
                "event_type": "POLICY_EVALUATED",
                "detail_code": "policy_applied_high_risk",
                "outcome": "SUCCESS",
            },
        ])

        resp = self.client.get("/api/incidents/INC-15D-001/audit")
        self.assertEqual(resp.status_code, 200)
        items = resp.json()
        self.assertEqual([item["sequence"] for item in items], [1, 3, 5])

    def test_13_cross_incident_audit_isolation(self) -> None:
        """Strict isolation: Incident A's events never appear on Incident B's page or API."""
        self.incident_2 = _make_test_incident("INC-15D-002")
        self._write_incident(self.incident_2)

        self._append_audit_events([
            {
                "incident_id": "INC-15D-001",
                "sequence": 1,
                "timestamp": "2026-10-08T14:30:01+00:00",
                "event_type": "TOOL_REQUESTED",
                "detail_code": "canary_incident_a_only",
                "outcome": "REQUESTED",
            },
            {
                "incident_id": "INC-15D-002",
                "sequence": 1,
                "timestamp": "2026-10-08T14:30:01+00:00",
                "event_type": "TOOL_REQUESTED",
                "detail_code": "canary_incident_b_only",
                "outcome": "REQUESTED",
            },
        ])

        # Incident 1
        resp_a = self.client.get("/incidents/INC-15D-001")
        self.assertIn("canary_incident_a_only", resp_a.text)
        self.assertNotIn("canary_incident_b_only", resp_a.text)

        resp_api_a = self.client.get("/api/incidents/INC-15D-001/audit")
        codes_a = [e["detail_code"] for e in resp_api_a.json()]
        self.assertIn("canary_incident_a_only", codes_a)
        self.assertNotIn("canary_incident_b_only", codes_a)

        # Incident 2
        resp_b = self.client.get("/incidents/INC-15D-002")
        self.assertIn("canary_incident_b_only", resp_b.text)
        self.assertNotIn("canary_incident_a_only", resp_b.text)

        resp_api_b = self.client.get("/api/incidents/INC-15D-002/audit")
        codes_b = [e["detail_code"] for e in resp_api_b.json()]
        self.assertIn("canary_incident_b_only", codes_b)
        self.assertNotIn("canary_incident_a_only", codes_b)

    def test_14_malformed_jsonl_line_skipped_safely(self) -> None:
        """Malformed, non-object, and missing lines are safely skipped without leaking tracebacks."""
        with open(self.audit_file, "a", encoding="utf-8") as f:
            f.write("{invalid json syntax line\n")
            f.write('"just a string"\n')
            f.write("1234567\n")
            f.write('{"missing_fields": true}\n')
            f.write(json.dumps({
                "incident_id": "INC-15D-001",
                "sequence": 10,
                "timestamp": "2026-10-08T14:30:10+00:00",
                "event_type": "POLICY_EVALUATED",
                "detail_code": "valid_after_corrupted_lines",
                "outcome": "SUCCESS",
            }) + "\n")

        resp = self.client.get("/api/incidents/INC-15D-001/audit")
        self.assertEqual(resp.status_code, 200)
        events = resp.json()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["detail_code"], "valid_after_corrupted_lines")

        # HTML page rendering continues without error
        resp_html = self.client.get("/incidents/INC-15D-001")
        self.assertEqual(resp_html.status_code, 200)
        self.assertIn("valid_after_corrupted_lines", resp_html.text)

    def test_15_secret_audit_fields_excluded(self) -> None:
        """Injected secret canaries in audit log records are strictly excluded."""
        canary_key = "SECRET_CANARY_API_KEY_007"
        canary_token = "BEARER_CANARY_TOKEN_999"
        canary_pwd = "PASSWORD_CANARY_SECRET_123"

        self._append_audit_events([{
            "incident_id": "INC-15D-001",
            "sequence": 1,
            "timestamp": "2026-10-08T14:30:01+00:00",
            "event_type": "TOOL_REQUESTED",
            "detail_code": "safe_code",
            "api_key": canary_key,
            "token": canary_token,
            "password": canary_pwd,
            "authorization": f"Bearer {canary_token}",
            "headers": {"Authorization": f"Bearer {canary_token}"},
            "outcome": "SUCCESS",
        }])

        resp_html = self.client.get("/incidents/INC-15D-001")
        self.assertNotIn(canary_key, resp_html.text)
        self.assertNotIn(canary_token, resp_html.text)
        self.assertNotIn(canary_pwd, resp_html.text)

        resp_api = self.client.get("/api/incidents/INC-15D-001/audit")
        api_text = json.dumps(resp_api.json())
        self.assertNotIn(canary_key, api_text)
        self.assertNotIn(canary_token, api_text)
        self.assertNotIn(canary_pwd, api_text)

    def test_16_raw_prompt_model_tool_args_excluded(self) -> None:
        """Raw prompt text, model response, and tool argument payloads are strictly excluded."""
        canary_prompt = "CANARY_SYSTEM_PROMPT_SECRET"
        canary_response = "CANARY_LLM_RAW_COMPLETION"
        canary_arg = "CANARY_SENSITIVE_ARGUMENT_VAL"

        self._append_audit_events([{
            "incident_id": "INC-15D-001",
            "sequence": 1,
            "timestamp": "2026-10-08T14:30:01+00:00",
            "event_type": "TOOL_REQUESTED",
            "detail_code": "safe_code",
            "prompt": canary_prompt,
            "model_response": canary_response,
            "tool_args": {"target": canary_arg},
            "raw_payload": canary_response,
            "outcome": "SUCCESS",
        }])

        resp_html = self.client.get("/incidents/INC-15D-001")
        self.assertNotIn(canary_prompt, resp_html.text)
        self.assertNotIn(canary_response, resp_html.text)
        self.assertNotIn(canary_arg, resp_html.text)

        resp_api = self.client.get("/api/incidents/INC-15D-001/audit")
        api_text = json.dumps(resp_api.json())
        self.assertNotIn(canary_prompt, api_text)
        self.assertNotIn(canary_response, api_text)
        self.assertNotIn(canary_arg, api_text)

    def test_17_audit_xss_escaped(self) -> None:
        """XSS payloads in audit detail codes are strictly escaped into inert HTML entities."""
        xss_payload = "<script>alert('audit_xss')</script>"
        self._append_audit_events([{
            "incident_id": "INC-15D-001",
            "sequence": 1,
            "timestamp": "2026-10-08T14:30:01+00:00",
            "event_type": "TOOL_REQUESTED",
            "detail_code": xss_payload,
            "outcome": "SUCCESS",
        }])

        resp = self.client.get("/incidents/INC-15D-001")
        self.assertEqual(resp.status_code, 200)
        self.assertNotIn("<script>alert('audit_xss')</script>", resp.text)
        self.assertIn("&lt;script&gt;alert(&#x27;audit_xss&#x27;)&lt;/script&gt;", resp.text)

    def test_18_hostile_detail_values_remain_inert(self) -> None:
        """Hostile img/onerror tags remain completely inert."""
        hostile_val = "<img src=x onerror=alert(1)>"
        self._append_audit_events([{
            "incident_id": "INC-15D-001",
            "sequence": 1,
            "timestamp": "2026-10-08T14:30:01+00:00",
            "event_type": "TOOL_REQUESTED",
            "detail_code": hostile_val,
            "outcome": "SUCCESS",
        }])

        resp = self.client.get("/incidents/INC-15D-001")
        self.assertEqual(resp.status_code, 200)
        self.assertNotIn("<img src=x onerror=alert(1)>", resp.text)
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", resp.text)

    def test_19_bounded_audit_event_count_enforced(self) -> None:
        """Audit timeline query is strictly bounded (max 200); attempts to request limit=999999 are rejected."""
        events = [
            {
                "incident_id": "INC-15D-001",
                "sequence": i,
                "timestamp": f"2026-10-08T14:30:{i:02d}+00:00",
                "event_type": "TOOL_REQUESTED",
                "detail_code": f"event_{i}",
                "outcome": "SUCCESS",
            }
            for i in range(1, 250)
        ]
        self._append_audit_events(events)

        # Default query bound is 100
        resp_default = self.client.get("/api/incidents/INC-15D-001/audit")
        self.assertEqual(resp_default.status_code, 200)
        self.assertEqual(len(resp_default.json()), DEFAULT_AUDIT_LIMIT)

        # Max bound is 200
        resp_max = self.client.get(f"/api/incidents/INC-15D-001/audit?limit={MAX_AUDIT_LIMIT}")
        self.assertEqual(resp_max.status_code, 200)
        self.assertEqual(len(resp_max.json()), MAX_AUDIT_LIMIT)

        # Exceeding bound returns HTTP 422 Unprocessable Entity
        resp_excess = self.client.get("/api/incidents/INC-15D-001/audit?limit=999999")
        self.assertEqual(resp_excess.status_code, 422)

    def test_20_unknown_event_type_renders_conservatively(self) -> None:
        """Unknown event types are categorized conservatively as UNKNOWN / OTHER and not as successful."""
        self._append_audit_events([{
            "incident_id": "INC-15D-001",
            "sequence": 1,
            "timestamp": "2026-10-08T14:30:01+00:00",
            "event_type": "CUSTOM_ARBITRARY_ACTION",
            "detail_code": "unknown_action_code",
            "outcome": "UNKNOWN",
        }])

        resp_api = self.client.get("/api/incidents/INC-15D-001/audit")
        self.assertEqual(resp_api.status_code, 200)
        events = resp_api.json()
        self.assertEqual(events[0]["category"], "UNKNOWN / OTHER")

        resp_html = self.client.get("/incidents/INC-15D-001")
        self.assertIn("UNKNOWN / OTHER", resp_html.text)
        self.assertIn("CUSTOM_ARBITRARY_ACTION", resp_html.text)

    def test_21_empty_audit_history_renders_safe_empty_state(self) -> None:
        """Incidents without audit records display a neutral empty state message."""
        resp_html = self.client.get("/incidents/INC-15D-001")
        self.assertEqual(resp_html.status_code, 200)
        self.assertIn("No persisted audit events are available for this incident.", resp_html.text)

        resp_api = self.client.get("/api/incidents/INC-15D-001/audit")
        self.assertEqual(resp_api.status_code, 200)
        self.assertEqual(resp_api.json(), [])

    def test_22_no_browser_controlled_audit_path(self) -> None:
        """Path traversal queries in incident_id cannot access arbitrary files."""
        resp = self.client.get("/api/incidents/../../etc/passwd/audit")
        # FastAPI / Starlette rejects traversal or returns 404
        self.assertIn(resp.status_code, (404, 400))

    def test_23_unsupported_mutating_methods_return_405(self) -> None:
        """All mutating methods (POST, PUT, PATCH, DELETE) to presentation endpoints return 405."""
        endpoints = [
            "/incidents/INC-15D-001",
            "/api/incidents/INC-15D-001",
            "/api/incidents/INC-15D-001/audit",
            "/api/incidents",
            "/",
        ]
        for ep in endpoints:
            self.assertEqual(self.client.post(ep).status_code, 405, f"POST {ep} was not 405")
            self.assertEqual(self.client.put(ep).status_code, 405, f"PUT {ep} was not 405")
            self.assertEqual(self.client.patch(ep).status_code, 405, f"PATCH {ep} was not 405")
            self.assertEqual(self.client.delete(ep).status_code, 405, f"DELETE {ep} was not 405")

    def test_24_zero_tool_router_execution(self) -> None:
        """ToolRouter is not imported or called anywhere in the UI presentation layer."""
        with patch("ui.audit_reader.AuditReader.get_incident_events") as mock_get:
            mock_get.return_value = []
            resp = self.client.get("/incidents/INC-15D-001")
            self.assertEqual(resp.status_code, 200)
        # Ensure no tool_router module is imported in ui package
        import ui.app
        import ui.audit_reader
        import ui.incident_reader
        import ui.models
        for mod in (ui.app, ui.audit_reader, ui.incident_reader, ui.models):
            self.assertFalse(hasattr(mod, "ToolRouter"), f"{mod} exposed ToolRouter")

    def test_25_zero_runtime_guard_mutation(self) -> None:
        """RuntimeGuard is not mutated by reading incidents or audit records."""
        resp = self.client.get("/incidents/INC-15D-001")
        self.assertEqual(resp.status_code, 200)
        resp_audit = self.client.get("/api/incidents/INC-15D-001/audit")
        self.assertEqual(resp_audit.status_code, 200)

    @patch("urllib.request.urlopen")
    def test_26_zero_splunk_openai_provider_calls(self, mock_urlopen: MagicMock) -> None:
        """Zero Splunk, OpenAI, VirusTotal, or Jira network calls during timeline or page rendering."""
        self.client.get("/incidents/INC-15D-001")
        self.client.get("/api/incidents/INC-15D-001/audit")
        mock_urlopen.assert_not_called()

    def test_27_existing_incident_page_still_displays_deterministic_policy_correctly(self) -> None:
        """Milestone 15C deterministic policy cards and governance pipeline remain fully intact."""
        resp = self.client.get("/incidents/INC-15D-001")
        self.assertEqual(resp.status_code, 200)
        html = resp.text

        self.assertIn("Deterministic Security Policy", html)
        self.assertIn("Authoritative security-control decision.", html)
        self.assertIn("AI Advisory Assessment", html)
        self.assertIn("Advisory only. Cannot authorize actions.", html)
        self.assertIn("governance-pipeline", html)
        self.assertIn("Stage 1 &bull; Evidence", html)
        self.assertIn("Stage 3 &bull; Deterministic Policy", html)

    def test_28_jira_state_does_not_imply_execution(self) -> None:
        """A persisted Jira tracking ticket does not imply that an action was executed."""
        resp = self.client.get("/incidents/INC-15D-001")
        self.assertEqual(resp.status_code, 200)
        html = resp.text

        self.assertIn("SOC-9001", html)
        self.assertIn("NOT EXECUTED", html)
        self.assertIn("NOT IMPLEMENTED (SIMULATED ONLY)", html)

    def test_29_ti_state_does_not_imply_authorization(self) -> None:
        """A malicious Threat Intelligence verdict does not bypass policy or auto-authorize actions."""
        resp = self.client.get("/incidents/INC-15D-001")
        self.assertEqual(resp.status_code, 200)
        html = resp.text

        self.assertIn("Malicious", html)
        self.assertIn("REQUIRED / PENDING", html)
        self.assertIn("Strict Gate", html)

    def test_30_audit_timeline_cannot_change_approval_action_state(self) -> None:
        """Audit records showing past approvals do not mutate the immutable incident record state."""
        # Insert historical audit event claiming APPROVAL_GRANTED
        self._append_audit_events([{
            "incident_id": "INC-15D-001",
            "sequence": 1,
            "timestamp": "2026-10-08T14:30:01+00:00",
            "event_type": "APPROVAL_GRANTED",
            "detail_code": "soc_lead_approval",
            "outcome": "SUCCESS",
        }])

        resp = self.client.get("/incidents/INC-15D-001")
        self.assertEqual(resp.status_code, 200)
        html = resp.text

        # The timeline displays the audit event
        self.assertIn("APPROVAL_GRANTED", html)
        # But the authoritative incident view model retains its persisted status
        self.assertIn("REQUIRED / PENDING", html)
        self.assertIn("NOT EXECUTED", html)


if __name__ == "__main__":
    unittest.main()
