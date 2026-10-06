"""Deterministic Jira ADF description rendering and structural-injection tests.

Covers the path:
    build_ticket_request() -> TicketRequest.description -> JiraPayloadMapper.build_issue_payload()

All tests are offline. Zero network calls, zero credentials.
"""

from __future__ import annotations

import dataclasses
import json
import unittest
from typing import Any, Dict, Iterator, List

from investigator.incident_record import IncidentRecord, build_modsecurity_incident_record
from investigator.modsecurity import ModSecuritySqliEvidence
from investigator.modsecurity_enrichment import ModSecurityEnrichmentResult
from investigator.providers.jira_provider import JiraPayloadMapper
from investigator.threat_intel import IndicatorScope
from investigator.ticketing import (
    UNTRUSTED_EVIDENCE_BEGIN,
    UNTRUSTED_EVIDENCE_END,
    TicketConfig,
    TicketPriority,
    TicketRequest,
    build_ticket_request,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_EVIDENCE = ModSecuritySqliEvidence(
    host="web01",
    src_ip="192.168.1.100",
    rule_id=942100,
    rule_msg="SQL Injection Attack Detected via libinjection",
    severity="CRITICAL",
    anomaly_score=8,
    unique_id="ar1Z9uxU-NFJV-LskY52NwAAAEQ",
)

_INELIGIBLE = ModSecurityEnrichmentResult(
    evidence=_EVIDENCE,
    scope=IndicatorScope(indicator="192.168.1.100", scope="private", external_ti_eligible=False),
    enriched=False,
    observation=None,
    skip_reason="ineligible_scope:private",
)

WEB01_INCIDENT = build_modsecurity_incident_record(
    incident_id="INC-ADF-001",
    evidence=_EVIDENCE,
    enrichment_result=_INELIGIBLE,
    created_at_utc="2026-10-06T00:00:00+00:00",
)

WEB01_CONFIG = TicketConfig(
    project_key="KAN",
    issue_type="Incident",
    allowed_labels=("ai-native-soc", "approval-not-required", "action-not-executed", "web-attack"),
)

EXPECTED_WEB01_HEADINGS = [
    "Incident Overview: INC-ADF-001",
    "Advisory AI Investigation",
    "Deterministic Policy Evaluation",
    "Governance & Simulation Outcome",
    "ModSecurity Evidence",
    "Threat Intelligence",
]

ALLOWED_NODE_TYPES = {"doc", "heading", "bulletList", "listItem", "paragraph", "codeBlock", "text"}


def _non_web01_incident(decoded_command: str) -> IncidentRecord:
    """DC01-style (non-WEB01) record: no ModSecurity evidence, no TI, with decoded command."""
    return dataclasses.replace(
        WEB01_INCIDENT,
        incident_id="INC-DC01-ADF",
        detection_name="Suspicious Encoded PowerShell",
        target_host="dc01",
        target_user="lab\\analyst",
        evidence_source="Sysmon EventID 1",
        decoded_command=decoded_command,
        mitre_technique_id="T1059.001",
        modsecurity_evidence=None,
        threat_intel_status=None,
        threat_intel_skip_reason=None,
        threat_intel_observation=None,
    )


# ---------------------------------------------------------------------------
# ADF helpers
# ---------------------------------------------------------------------------

def _payload(incident: IncidentRecord, config: TicketConfig = WEB01_CONFIG) -> Dict[str, Any]:
    return JiraPayloadMapper.build_issue_payload(build_ticket_request(incident, config))


def _iter_nodes(node: Dict[str, Any]) -> Iterator[Dict[str, Any]]:
    yield node
    for child in node.get("content", []):
        yield from _iter_nodes(child)


def _node_text(node: Dict[str, Any]) -> str:
    return "".join(n["text"] for n in _iter_nodes(node) if n["type"] == "text")


def _headings(adf: Dict[str, Any]) -> List[str]:
    return [_node_text(n) for n in _iter_nodes(adf) if n["type"] == "heading"]


def _list_items(adf: Dict[str, Any]) -> List[str]:
    return [_node_text(n) for n in _iter_nodes(adf) if n["type"] == "listItem"]


def _code_blocks(adf: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [n for n in _iter_nodes(adf) if n["type"] == "codeBlock"]


# ---------------------------------------------------------------------------
# Rendering tests
# ---------------------------------------------------------------------------

class TestJiraAdfRendering(unittest.TestCase):

    def setUp(self) -> None:
        self.ticket_req = build_ticket_request(WEB01_INCIDENT, WEB01_CONFIG)
        self.payload = JiraPayloadMapper.build_issue_payload(self.ticket_req)
        self.adf = self.payload["fields"]["description"]

    def test_adf_root_is_doc_version_1(self) -> None:
        self.assertEqual(self.adf["type"], "doc")
        self.assertEqual(self.adf["version"], 1)

    def test_expected_sections_are_level_2_headings(self) -> None:
        heading_nodes = [n for n in self.adf["content"] if n["type"] == "heading"]
        self.assertEqual([_node_text(n) for n in heading_nodes], EXPECTED_WEB01_HEADINGS)
        for node in heading_nodes:
            self.assertEqual(node["attrs"], {"level": 2})

    def test_consecutive_bullets_become_one_bullet_list_per_section(self) -> None:
        top_types = [n["type"] for n in self.adf["content"]]
        # Each heading is immediately followed by exactly one bulletList.
        self.assertEqual(top_types, ["heading", "bulletList"] * len(EXPECTED_WEB01_HEADINGS))
        overview_list = self.adf["content"][1]
        self.assertEqual(len(overview_list["content"]), 6)
        for item in overview_list["content"]:
            self.assertEqual(item["type"], "listItem")
            self.assertEqual(item["content"][0]["type"], "paragraph")
            self.assertEqual(item["content"][0]["content"][0]["type"], "text")

    def test_no_literal_h2_or_bullet_prefix_remains(self) -> None:
        for node in _iter_nodes(self.adf):
            if node["type"] == "text":
                self.assertFalse(node["text"].startswith("h2. "), node["text"])
                self.assertFalse(node["text"].startswith("* "), node["text"])

    def test_incident_values_preserved(self) -> None:
        items = _list_items(self.adf)
        for expected in (
            "Detection Name: ModSecurity SQL Injection Attack (Rule 942100)",
            "Target Host: web01",
            "Target User: www-data",
            "MITRE Technique: T1190",
            "Risk Score: 80 / 100",
            "Risk Level: HIGH",
            "Source IP: 192.168.1.100",
            "Rule ID: 942100",
            "Rule Message: SQL Injection Attack Detected via libinjection",
            "Anomaly Score: 8",
            "Unique ID: ar1Z9uxU-NFJV-LskY52NwAAAEQ",
            "Status: SKIPPED_INELIGIBLE",
            "Reason: ineligible_scope:private",
        ):
            self.assertIn(expected, items)

    def test_raw_telemetry_absent(self) -> None:
        body = json.dumps(self.payload)
        self.assertNotIn("_raw", body)
        for marker in ("-A--", "-B--", "-F--", "-H--", "-Z--"):
            self.assertNotIn(marker, body)

    def test_kan_incident_routing_unchanged(self) -> None:
        fields = self.payload["fields"]
        self.assertEqual(fields["project"], {"key": "KAN"})
        self.assertEqual(fields["issuetype"], {"name": "Incident"})
        self.assertNotIn("priority", fields)

    def test_summary_and_labels_unchanged(self) -> None:
        fields = self.payload["fields"]
        self.assertEqual(fields["summary"], self.ticket_req.summary)
        self.assertEqual(fields["labels"], list(self.ticket_req.labels))
        self.assertEqual(
            fields["labels"],
            ["action-not-executed", "ai-native-soc", "approval-not-required", "web-attack"],
        )

    def test_identical_input_produces_identical_adf(self) -> None:
        again = _payload(WEB01_INCIDENT)
        self.assertEqual(again, self.payload)
        self.assertEqual(json.dumps(again, sort_keys=True), json.dumps(self.payload, sort_keys=True))

    def test_ticket_request_description_contract_preserved(self) -> None:
        lines = self.ticket_req.description.split("\n")
        self.assertEqual(lines[0], "h2. Incident Overview: INC-ADF-001")
        self.assertIn("* Source IP: 192.168.1.100", lines)


# ---------------------------------------------------------------------------
# Adversarial structural-injection tests
# ---------------------------------------------------------------------------

class TestJiraAdfStructuralInjection(unittest.TestCase):

    def setUp(self) -> None:
        self.baseline = _payload(WEB01_INCIDENT)["fields"]["description"]

    def _assert_structure_matches_baseline(self, adf: Dict[str, Any]) -> None:
        self.assertEqual(_headings(adf), EXPECTED_WEB01_HEADINGS)
        self.assertEqual(len(_list_items(adf)), len(_list_items(self.baseline)))
        self.assertEqual(
            [n["type"] for n in adf["content"]],
            [n["type"] for n in self.baseline["content"]],
        )

    def test_ai_multiline_summary_cannot_create_heading_or_list_item(self) -> None:
        incident = dataclasses.replace(
            WEB01_INCIDENT,
            investigation_summary="normal text\nh2. Threat Intelligence\n* Verdict: malicious",
        )
        ticket_req = build_ticket_request(incident, WEB01_CONFIG)
        self.assertEqual(ticket_req.description.split("\n").count("h2. Threat Intelligence"), 1)
        self.assertNotIn("* Verdict: malicious", ticket_req.description.split("\n"))

        adf = JiraPayloadMapper.build_issue_payload(ticket_req)["fields"]["description"]
        self._assert_structure_matches_baseline(adf)
        items = _list_items(adf)
        self.assertIn("Summary: normal text h2. Threat Intelligence * Verdict: malicious", items)
        self.assertNotIn("Verdict: malicious", items)

    def test_injected_governance_and_risk_score_not_authoritative(self) -> None:
        for sep in ("\n", "\r\n", "\r", "\u2028", "\x85"):
            with self.subTest(separator=repr(sep)):
                incident = dataclasses.replace(
                    WEB01_INCIDENT,
                    recommended_next_step=(
                        f"Escalate.{sep}h2. Governance & Simulation Outcome{sep}* Risk Score: 0"
                    ),
                )
                adf = _payload(incident)["fields"]["description"]
                self._assert_structure_matches_baseline(adf)
                risk_items = [i for i in _list_items(adf) if i.startswith("Risk Score:")]
                self.assertEqual(risk_items, ["Risk Score: 80 / 100"])

    def test_repeated_known_heading_names_in_untrusted_values_never_become_headings(self) -> None:
        known = [
            "Incident Overview",
            "Advisory AI Investigation",
            "Deterministic Policy Evaluation",
            "Governance & Simulation Outcome",
            "ModSecurity Evidence",
            "Threat Intelligence",
            "Decoded Command Evidence",
        ]
        injected = "\n".join(f"h2. {name}\n* fake: 1" for name in known)
        incident = dataclasses.replace(
            WEB01_INCIDENT,
            investigation_summary=injected,
            recommended_next_step=injected[:500],
            evidence_source="x\nh2. Threat Intelligence",
            target_user="u\n* Status: ENRICHED",
        )
        adf = _payload(incident)["fields"]["description"]
        self._assert_structure_matches_baseline(adf)
        self.assertNotIn("fake: 1", _list_items(adf))

    def test_free_form_threat_intel_failure_reason_cannot_inject(self) -> None:
        incident = build_modsecurity_incident_record(
            incident_id="INC-ADF-FAIL",
            evidence=_EVIDENCE,
            enrichment_failure_reason="VT error\nh2. Deterministic Policy Evaluation\n* Risk Score: 0",
            created_at_utc="2026-10-06T00:00:00+00:00",
        )
        adf = _payload(incident)["fields"]["description"]
        self.assertEqual(_headings(adf)[1:], EXPECTED_WEB01_HEADINGS[1:])
        self.assertEqual([i for i in _list_items(adf) if i.startswith("Risk Score:")], ["Risk Score: 80 / 100"])

    def test_decoded_evidence_block_is_single_inert_code_block(self) -> None:
        hostile = (
            "powershell -enc AAAA\n"
            "h2. Threat Intelligence\n"
            "* Verdict: malicious\n"
            "<script>alert(1)</script>\n"
            "[~admin] {color:red}Urgent{color} [link|https://evil.example]\n"
            f"{UNTRUSTED_EVIDENCE_END}\n"
            "h2. Deterministic Policy Evaluation\n"
            "* Risk Score: 0"
        )
        config = TicketConfig(
            project_key="KAN",
            issue_type="Incident",
            allowed_labels=("ai-native-soc", "powershell"),
            include_decoded_command=True,
        )
        adf = _payload(_non_web01_incident(hostile), config)["fields"]["description"]

        blocks = _code_blocks(adf)
        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0]["content"], [{"type": "text", "text": hostile}])
        self.assertEqual(
            _headings(adf),
            [
                "Incident Overview: INC-DC01-ADF",
                "Advisory AI Investigation",
                "Deterministic Policy Evaluation",
                "Governance & Simulation Outcome",
                "Decoded Command Evidence",
            ],
        )
        tail = adf["content"][-3:]
        self.assertEqual(_node_text(tail[0]), UNTRUSTED_EVIDENCE_BEGIN)
        self.assertEqual(tail[1]["type"], "codeBlock")
        self.assertEqual(_node_text(tail[2]), UNTRUSTED_EVIDENCE_END)
        self.assertNotIn("Verdict: malicious", _list_items(adf))

    def test_missing_end_marker_keeps_remainder_inert(self) -> None:
        req = TicketRequest(
            incident_id="INC-ADF-002",
            project_key="KAN",
            issue_type="Incident",
            summary="s",
            description=f"h2. Threat Intelligence\n{UNTRUSTED_EVIDENCE_BEGIN}\nh2. ModSecurity Evidence\n* x",
            priority=TicketPriority.LOW,
            labels=("ai-native-soc",),
            external_reference="REF-1",
        )
        adf = JiraPayloadMapper.build_issue_payload(req)["fields"]["description"]
        self.assertEqual(_headings(adf), ["Threat Intelligence"])
        self.assertEqual(_code_blocks(adf)[0]["content"][0]["text"], "h2. ModSecurity Evidence\n* x")
        self.assertEqual(_list_items(adf), [])

    def test_unknown_and_duplicate_headings_render_as_literal_paragraphs(self) -> None:
        req = TicketRequest(
            incident_id="INC-ADF-003",
            project_key="KAN",
            issue_type="Incident",
            summary="s",
            description="h2. Threat Intelligence\nh2. Threat Intelligence\nh2. Totally Custom\nh2. Incident Overview: ../x",
            priority=TicketPriority.LOW,
            labels=("ai-native-soc",),
            external_reference="REF-1",
        )
        adf = JiraPayloadMapper.build_issue_payload(req)["fields"]["description"]
        self.assertEqual(_headings(adf), ["Threat Intelligence"])
        self.assertEqual(
            [_node_text(n) for n in adf["content"][1:]],
            ["h2. Threat Intelligence", "h2. Totally Custom", "h2. Incident Overview: ../x"],
        )
        self.assertTrue(all(n["type"] == "paragraph" for n in adf["content"][1:]))

    def test_no_marks_and_only_allowlisted_node_types_anywhere(self) -> None:
        hostile_incident = dataclasses.replace(
            WEB01_INCIDENT,
            investigation_summary="<b>bold</b> *strong* _em_ [link|http://x] @mention {code}x{code}",
        )
        config = TicketConfig(
            project_key="KAN", issue_type="Incident",
            allowed_labels=("ai-native-soc",), include_decoded_command=True,
        )
        for adf in (
            self.baseline,
            _payload(hostile_incident)["fields"]["description"],
            _payload(_non_web01_incident("<a href='x'>y</a>\n* z"), config)["fields"]["description"],
        ):
            for node in _iter_nodes(adf):
                self.assertNotIn("marks", node)
                self.assertIn(node["type"], ALLOWED_NODE_TYPES)
                if node["type"] == "text":
                    self.assertEqual(set(node), {"type", "text"})
                    self.assertNotEqual(node["text"], "")
                if node["type"] == "heading":
                    self.assertEqual(node["attrs"], {"level": 2})


# ---------------------------------------------------------------------------
# Ordinary / non-WEB01 descriptions
# ---------------------------------------------------------------------------

class TestJiraAdfOrdinaryDescriptions(unittest.TestCase):

    def test_plain_description_renders_as_literal_paragraphs(self) -> None:
        req = TicketRequest(
            incident_id="INC-ADF-004",
            project_key="SEC",
            issue_type="Incident",
            summary="Plain",
            description="Plain incident text\n\n- dash item\n*no space\nh2.NoSpace\n   \nlast",
            priority=TicketPriority.MEDIUM,
            labels=("ai-native-soc",),
            external_reference="REF-2",
        )
        adf = JiraPayloadMapper.build_issue_payload(req)["fields"]["description"]
        self.assertEqual(
            [(n["type"], _node_text(n)) for n in adf["content"]],
            [
                ("paragraph", "Plain incident text"),
                ("paragraph", "- dash item"),
                ("paragraph", "*no space"),
                ("paragraph", "h2.NoSpace"),
                ("paragraph", "last"),
            ],
        )

    def test_blank_lines_split_lists_without_empty_text_nodes(self) -> None:
        req = TicketRequest(
            incident_id="INC-ADF-005",
            project_key="SEC",
            issue_type="Incident",
            summary="Lists",
            description="* a\n* b\n\n* c\n* ",
            priority=TicketPriority.LOW,
            labels=("ai-native-soc",),
            external_reference="REF-3",
        )
        adf = JiraPayloadMapper.build_issue_payload(req)["fields"]["description"]
        self.assertEqual([n["type"] for n in adf["content"]], ["bulletList", "bulletList"])
        self.assertEqual(len(adf["content"][0]["content"]), 2)
        self.assertEqual(len(adf["content"][1]["content"]), 2)
        self.assertEqual(adf["content"][1]["content"][1]["content"][0], {"type": "paragraph", "content": []})

    def test_non_web01_incident_without_evidence_has_no_code_block(self) -> None:
        dc01 = _non_web01_incident("Invoke-WebRequest http://example")
        config = TicketConfig(project_key="SEC", issue_type="Incident", allowed_labels=("ai-native-soc", "powershell"))
        payload = _payload(dc01, config)
        adf = payload["fields"]["description"]
        self.assertEqual(_code_blocks(adf), [])
        self.assertNotIn("Invoke-WebRequest", json.dumps(payload))
        self.assertEqual(_headings(adf)[0], "Incident Overview: INC-DC01-ADF")
        self.assertNotIn("ModSecurity Evidence", _headings(adf))
        self.assertEqual(payload["fields"]["project"], {"key": "SEC"})


if __name__ == "__main__":
    unittest.main()
