"""Tests for deterministic JSON and Markdown evaluation report generation.

TDD RED PHASE ONLY - Milestone 10E.
Exercises contract, consistency validation, deterministic JSON/Markdown rendering,
sanitization boundaries, and integration with Milestone 10C scenarios.
"""

import json
from typing import List, Tuple
import unittest

from evaluation.metrics import EvaluationMetrics, aggregate_results
from evaluation.reporting import (
    EvaluationReport,
    EvaluationReportingError,
    render_json_report,
    render_markdown_report,
)
from evaluation.scenarios import (
    SCENARIO_ARBITRARY_SPL,
    SCENARIO_PROMPT_INJECTION,
    SCENARIO_RUNTIME_KILL_SWITCH,
)
from evaluation.schema import EvaluationResult, EvaluationScenario


class TestEvaluationReportContract(unittest.TestCase):
    """Tests for EvaluationReport schema and consistency validation rules."""

    def setUp(self) -> None:
        self.scenario_1 = EvaluationScenario(
            scenario_id="eval-scenario-1",
            name="Scenario One",
            category="injection",
            description="Testing prompt injection containment.",
            expected_control="ToolRouter allowlist",
            expected_outcome="Tool execution blocked",
        )
        self.scenario_2 = EvaluationScenario(
            scenario_id="eval-scenario-2",
            name="Scenario Two",
            category="query_abuse",
            description="Testing arbitrary query containment.",
            expected_control="QueryValidator allowlist",
            expected_outcome="Query execution blocked",
        )
        self.result_1 = EvaluationResult(
            scenario_id="eval-scenario-1",
            passed=True,
            actual_outcome="Tool execution blocked cleanly",
            unsafe_tool_execution=False,
            approval_bypass=False,
            arbitrary_query_execution=False,
            runtime_guard_bypass=False,
            audit_leakage=False,
            policy_override=False,
            detail_code="INVALID_TOOL_REQUEST",
        )
        self.result_2 = EvaluationResult(
            scenario_id="eval-scenario-2",
            passed=True,
            actual_outcome="Query rejected before backend",
            unsafe_tool_execution=False,
            approval_bypass=False,
            arbitrary_query_execution=False,
            runtime_guard_bypass=False,
            audit_leakage=False,
            policy_override=False,
            detail_code="UNALLOWLISTED_QUERY_TYPE",
        )
        self.metrics_2 = aggregate_results([self.result_1, self.result_2])

    def test_valid_report_creation(self) -> None:
        """EvaluationReport instantiates with valid scenarios, results, and metrics."""
        report = EvaluationReport(
            scenarios=[self.scenario_1, self.scenario_2],
            results=[self.result_1, self.result_2],
            metrics=self.metrics_2,
        )
        self.assertEqual(len(report.scenarios), 2)
        self.assertEqual(len(report.results), 2)
        self.assertEqual(report.metrics.total_scenarios, 2)
        self.assertEqual(report.metrics.passed, 2)
        self.assertEqual(report.metrics.pass_rate, 1.0)

    def test_report_immutability(self) -> None:
        """EvaluationReport is frozen and fields cannot be mutated."""
        report = EvaluationReport(
            scenarios=[self.scenario_1],
            results=[self.result_1],
            metrics=aggregate_results([self.result_1]),
        )
        with self.assertRaises(AttributeError):
            report.results = [self.result_2]  # type: ignore

    def test_empty_report_valid(self) -> None:
        """Empty results and scenarios with zero metrics is a valid state."""
        empty_metrics = aggregate_results([])
        report = EvaluationReport(
            scenarios=[],
            results=[],
            metrics=empty_metrics,
        )
        self.assertEqual(len(report.scenarios), 0)
        self.assertEqual(len(report.results), 0)
        self.assertEqual(report.metrics.total_scenarios, 0)
        self.assertEqual(report.metrics.pass_rate, 0.0)

    def test_metrics_total_mismatch_fails_closed(self) -> None:
        """Report creation fails if metrics.total_scenarios != len(results)."""
        metrics_with_1 = aggregate_results([self.result_1])
        with self.assertRaises(EvaluationReportingError):
            EvaluationReport(
                scenarios=[self.scenario_1, self.scenario_2],
                results=[self.result_1, self.result_2],
                metrics=metrics_with_1,  # total=1, results=2
            )

    def test_scenario_and_result_length_mismatch_fails_closed(self) -> None:
        """Report creation fails if len(scenarios) != len(results)."""
        with self.assertRaises(EvaluationReportingError):
            EvaluationReport(
                scenarios=[self.scenario_1],
                results=[self.result_1, self.result_2],
                metrics=self.metrics_2,
            )

    def test_scenario_and_result_id_order_mismatch_fails_closed(self) -> None:
        """Report creation fails if scenario_id does not correspond index-by-index."""
        # Reversed results order
        with self.assertRaises(EvaluationReportingError):
            EvaluationReport(
                scenarios=[self.scenario_1, self.scenario_2],
                results=[self.result_2, self.result_1],
                metrics=self.metrics_2,
            )

    def test_duplicate_scenario_ids_fail_closed(self) -> None:
        """Duplicate scenario IDs create ambiguity and must fail closed."""
        dup_scenario = EvaluationScenario(
            scenario_id="eval-scenario-1",
            name="Duplicate One",
            category="injection",
            description="Duplicate ID scenario.",
            expected_control="Control",
            expected_outcome="Outcome",
        )
        with self.assertRaises(EvaluationReportingError):
            EvaluationReport(
                scenarios=[self.scenario_1, dup_scenario],
                results=[self.result_1, self.result_1],
                metrics=aggregate_results([self.result_1, self.result_1]),
            )

    def test_invalid_types_rejected(self) -> None:
        """Reject non-sequence, non-EvaluationScenario, non-EvaluationResult, non-EvaluationMetrics."""
        with self.assertRaises(EvaluationReportingError):
            EvaluationReport(
                scenarios="not-a-sequence",  # type: ignore
                results=[self.result_1],
                metrics=aggregate_results([self.result_1]),
            )
        with self.assertRaises(EvaluationReportingError):
            EvaluationReport(
                scenarios=[self.scenario_1],
                results=[{"not": "a result"}],  # type: ignore
                metrics=aggregate_results([self.result_1]),
            )
        with self.assertRaises(EvaluationReportingError):
            EvaluationReport(
                scenarios=[self.scenario_1],
                results=[self.result_1],
                metrics={"total_scenarios": 1},  # type: ignore
            )


class TestJsonReportRendering(unittest.TestCase):
    """Tests for deterministic JSON report rendering."""

    def setUp(self) -> None:
        self.scenario = EvaluationScenario(
            scenario_id="eval-sec-01",
            name="Unauthorized Tool Blocked",
            category="tool_boundary",
            description="Ensure tool router rejects unallowlisted tools.",
            expected_control="ToolRouter allowlist",
            expected_outcome="Blocked with INVALID_TOOL_REQUEST",
        )
        self.result = EvaluationResult(
            scenario_id="eval-sec-01",
            passed=True,
            actual_outcome="Blocked cleanly",
            unsafe_tool_execution=False,
            approval_bypass=False,
            arbitrary_query_execution=False,
            runtime_guard_bypass=False,
            audit_leakage=False,
            policy_override=False,
            detail_code="INVALID_TOOL_REQUEST",
        )
        self.metrics = aggregate_results([self.result])
        self.report = EvaluationReport(
            scenarios=[self.scenario],
            results=[self.result],
            metrics=self.metrics,
        )

    def test_render_json_valid_json_structure(self) -> None:
        """render_json_report produces valid JSON with required top-level shape."""
        rendered = render_json_report(self.report)
        self.assertIsInstance(rendered, str)
        data = json.loads(rendered)

        self.assertEqual(data.get("report_type"), "ai_native_soc_agent_security_evaluation")
        self.assertIn("scope", data)
        self.assertEqual(data["scope"].get("environment"), "controlled_lab")
        self.assertEqual(data["scope"].get("assurance_level"), "tested_scenarios_only")
        self.assertIn("metrics", data)
        self.assertIn("results", data)

    def test_json_metrics_field_contract(self) -> None:
        """Metrics section in JSON contains exact aggregate counters and float pass_rate."""
        rendered = render_json_report(self.report)
        data = json.loads(rendered)
        metrics_dict = data["metrics"]

        self.assertEqual(metrics_dict["total_scenarios"], 1)
        self.assertEqual(metrics_dict["passed"], 1)
        self.assertEqual(metrics_dict["failed"], 0)
        self.assertEqual(metrics_dict["pass_rate"], 1.0)
        self.assertEqual(metrics_dict["unsafe_tool_executions"], 0)
        self.assertEqual(metrics_dict["approval_bypasses"], 0)
        self.assertEqual(metrics_dict["arbitrary_query_executions"], 0)
        self.assertEqual(metrics_dict["runtime_guard_bypasses"], 0)
        self.assertEqual(metrics_dict["audit_leakage_findings"], 0)
        self.assertEqual(metrics_dict["policy_override_findings"], 0)

    def test_json_results_field_contract(self) -> None:
        """Results section in JSON preserves scenario metadata and all 6 violation flags."""
        rendered = render_json_report(self.report)
        data = json.loads(rendered)
        self.assertEqual(len(data["results"]), 1)
        res_entry = data["results"][0]

        self.assertEqual(res_entry["scenario_id"], "eval-sec-01")
        self.assertEqual(res_entry["name"], "Unauthorized Tool Blocked")
        self.assertEqual(res_entry["category"], "tool_boundary")
        self.assertEqual(res_entry["expected_control"], "ToolRouter allowlist")
        self.assertEqual(res_entry["passed"], True)
        self.assertEqual(res_entry["detail_code"], "INVALID_TOOL_REQUEST")
        self.assertEqual(res_entry["unsafe_tool_execution"], False)
        self.assertEqual(res_entry["approval_bypass"], False)
        self.assertEqual(res_entry["arbitrary_query_execution"], False)
        self.assertEqual(res_entry["runtime_guard_bypass"], False)
        self.assertEqual(res_entry["audit_leakage"], False)
        self.assertEqual(res_entry["policy_override"], False)

    def test_json_order_preservation(self) -> None:
        """JSON results array preserves input scenario order exactly."""
        scenario_2 = EvaluationScenario(
            scenario_id="eval-sec-02",
            name="Secondary Scenario",
            category="guard",
            description="Testing guard.",
            expected_control="Guard",
            expected_outcome="Halt",
        )
        result_2 = EvaluationResult(
            scenario_id="eval-sec-02",
            passed=False,
            actual_outcome="Failed to halt",
            unsafe_tool_execution=False,
            approval_bypass=False,
            arbitrary_query_execution=False,
            runtime_guard_bypass=True,
            audit_leakage=False,
            policy_override=False,
            detail_code="GUARD_BYPASSED",
        )
        report = EvaluationReport(
            scenarios=[self.scenario, scenario_2],
            results=[self.result, result_2],
            metrics=aggregate_results([self.result, result_2]),
        )
        data = json.loads(render_json_report(report))
        self.assertEqual(data["results"][0]["scenario_id"], "eval-sec-01")
        self.assertEqual(data["results"][1]["scenario_id"], "eval-sec-02")

    def test_json_serialization_deterministic(self) -> None:
        """Repeated serialization on identical report produces byte-for-byte identical string."""
        render1 = render_json_report(self.report)
        render2 = render_json_report(self.report)
        self.assertEqual(render1, render2)

    def test_empty_report_json(self) -> None:
        """Empty report renders valid JSON without crash."""
        empty_report = EvaluationReport(
            scenarios=[],
            results=[],
            metrics=aggregate_results([]),
        )
        rendered = render_json_report(empty_report)
        data = json.loads(rendered)
        self.assertEqual(data["metrics"]["total_scenarios"], 0)
        self.assertEqual(data["metrics"]["pass_rate"], 0.0)
        self.assertEqual(data["results"], [])


class TestMarkdownReportRendering(unittest.TestCase):
    """Tests for deterministic Markdown report rendering."""

    def setUp(self) -> None:
        self.scenario = EvaluationScenario(
            scenario_id="eval-sec-01",
            name="Telemetry Injection Blocked",
            category="injection",
            description="Hostile telemetry shell injection blocked.",
            expected_control="ToolRouter allowlist",
            expected_outcome="INVALID_TOOL_REQUEST",
        )
        self.result = EvaluationResult(
            scenario_id="eval-sec-01",
            passed=True,
            actual_outcome="Blocked cleanly",
            unsafe_tool_execution=False,
            approval_bypass=False,
            arbitrary_query_execution=False,
            runtime_guard_bypass=False,
            audit_leakage=False,
            policy_override=False,
            detail_code="INVALID_TOOL_REQUEST",
        )
        self.report = EvaluationReport(
            scenarios=[self.scenario],
            results=[self.result],
            metrics=aggregate_results([self.result]),
        )

    def test_markdown_title_and_disclaimer(self) -> None:
        """Markdown report includes title and controlled-lab disclaimer."""
        md = render_markdown_report(self.report)
        self.assertTrue(md.startswith("# ") or "\n# " in md)
        # Controlled-lab disclaimer assertions
        self.assertIn("controlled lab environment", md.lower())
        self.assertIn("tested scenarios", md.lower())
        self.assertIn("production assurance", md.lower())
        # Distinction between tested and simulated
        self.assertTrue("TESTED" in md or "tested" in md.lower())
        self.assertTrue("SIMULATED" in md or "simulated" in md.lower())

    def test_markdown_summary_metrics_and_percentage_formatting(self) -> None:
        """Markdown report contains total, passed, failed, and pass rate formatted as percentage."""
        md = render_markdown_report(self.report)
        self.assertIn("Total Scenarios", md)
        self.assertIn("Passed", md)
        self.assertIn("Failed", md)
        self.assertIn("Pass Rate", md)
        self.assertIn("100.0%", md)

        # Half pass rate case
        failed_res = EvaluationResult(
            scenario_id="eval-sec-02",
            passed=False,
            actual_outcome="Failed",
            unsafe_tool_execution=True,
            approval_bypass=False,
            arbitrary_query_execution=False,
            runtime_guard_bypass=False,
            audit_leakage=False,
            policy_override=False,
            detail_code="UNSAFE_EXEC",
        )
        scenario_2 = EvaluationScenario(
            scenario_id="eval-sec-02",
            name="Sec 2",
            category="cat",
            description="desc",
            expected_control="ctrl",
            expected_outcome="out",
        )
        report_half = EvaluationReport(
            scenarios=[self.scenario, scenario_2],
            results=[self.result, failed_res],
            metrics=aggregate_results([self.result, failed_res]),
        )
        md_half = render_markdown_report(report_half)
        self.assertIn("50.0%", md_half)

    def test_markdown_violation_counters(self) -> None:
        """Markdown report displays all six violation counters."""
        md = render_markdown_report(self.report)
        self.assertIn("Unsafe Tool Executions", md)
        self.assertIn("Approval Bypasses", md)
        self.assertIn("Arbitrary Query Executions", md)
        self.assertIn("Runtime Guard Bypasses", md)
        self.assertIn("Audit Leakage Findings", md)
        self.assertIn("Policy Override Findings", md)

    def test_markdown_scenario_results_table(self) -> None:
        """Markdown report includes a scenario table with required columns."""
        md = render_markdown_report(self.report)
        # Required columns in table
        self.assertIn("Scenario ID", md)
        self.assertIn("Category", md)
        self.assertIn("Name", md)
        self.assertIn("Status", md)
        self.assertIn("Detail Code", md)
        # Required row entries
        self.assertIn("eval-sec-01", md)
        self.assertIn("injection", md)
        self.assertIn("Telemetry Injection Blocked", md)
        self.assertIn("PASS", md)
        self.assertIn("INVALID_TOOL_REQUEST", md)

    def test_markdown_order_preservation(self) -> None:
        """Scenario table rows preserve input scenario order."""
        scenario_2 = EvaluationScenario(
            scenario_id="eval-sec-02",
            name="Secondary Scenario",
            category="guard",
            description="Testing guard.",
            expected_control="Guard",
            expected_outcome="Halt",
        )
        result_2 = EvaluationResult(
            scenario_id="eval-sec-02",
            passed=False,
            actual_outcome="Failed to halt",
            unsafe_tool_execution=False,
            approval_bypass=False,
            arbitrary_query_execution=False,
            runtime_guard_bypass=True,
            audit_leakage=False,
            policy_override=False,
            detail_code="GUARD_BYPASSED",
        )
        report = EvaluationReport(
            scenarios=[self.scenario, scenario_2],
            results=[self.result, result_2],
            metrics=aggregate_results([self.result, result_2]),
        )
        md = render_markdown_report(report)
        pos_1 = md.index("eval-sec-01")
        pos_2 = md.index("eval-sec-02")
        self.assertLess(pos_1, pos_2)
        self.assertIn("FAIL", md)

    def test_markdown_rejects_subjective_claims(self) -> None:
        """Markdown report must not include subjective promotional or assurance claims."""
        md = render_markdown_report(self.report)
        lower_md = md.lower()
        prohibited = [
            "production-ready",
            "production ready",
            "enterprise-grade",
            "enterprise grade",
            "robust",
            "high quality",
            "bulletproof",
            "completely secure",
        ]
        for term in prohibited:
            self.assertNotIn(term, lower_md, f"Prohibited marketing term found: {term}")

    def test_empty_report_markdown(self) -> None:
        """Empty report renders valid Markdown with 0.0% pass rate without crashing."""
        empty_report = EvaluationReport(
            scenarios=[],
            results=[],
            metrics=aggregate_results([]),
        )
        md = render_markdown_report(empty_report)
        self.assertIn("0.0%", md)
        self.assertIn("Total Scenarios: 0", md.replace(" | ", " ").replace("|", ""))

    def test_markdown_serialization_deterministic(self) -> None:
        """Repeated rendering produces byte-for-byte identical output."""
        md1 = render_markdown_report(self.report)
        md2 = render_markdown_report(self.report)
        self.assertEqual(md1, md2)


class TestReportSanitizationAndBoundedContent(unittest.TestCase):
    """Tests ensuring report output does not leak sensitive or raw content."""

    def setUp(self) -> None:
        self.scenario = EvaluationScenario(
            scenario_id="eval-clean-01",
            name="Sanitization Check",
            category="injection",
            description="Testing bounded reporting content.",
            expected_control="ToolRouter allowlist",
            expected_outcome="INVALID_TOOL_REQUEST",
        )
        self.result = EvaluationResult(
            scenario_id="eval-clean-01",
            passed=True,
            actual_outcome="Clean outcome",
            unsafe_tool_execution=False,
            approval_bypass=False,
            arbitrary_query_execution=False,
            runtime_guard_bypass=False,
            audit_leakage=False,
            policy_override=False,
            detail_code="INVALID_TOOL_REQUEST",
        )
        self.report = EvaluationReport(
            scenarios=[self.scenario],
            results=[self.result],
            metrics=aggregate_results([self.result]),
        )

    def test_reports_do_not_contain_unbounded_artifacts(self) -> None:
        """Reports must not contain sensitive environment, raw telemetry, or stack traces."""
        json_out = render_json_report(self.report)
        md_out = render_markdown_report(self.report)

        for content in (json_out, md_out):
            self.assertNotIn("sk-proj-", content)
            self.assertNotIn("Traceback (most recent call last)", content)
            self.assertNotIn("OPENAI_API_KEY", content)
            self.assertNotIn("AZURE_OPENAI_API_KEY", content)
            self.assertNotIn("PATH=", content)
            self.assertNotIn("rm -rf", content)


class TestMilestone10CIntegrationReport(unittest.TestCase):
    """Integration test using the three Milestone 10C scenarios."""

    def test_three_scenario_passing_report(self) -> None:
        """Assemble a report using all three 10C scenarios with compliant passing results."""
        scenarios = [
            SCENARIO_PROMPT_INJECTION,
            SCENARIO_ARBITRARY_SPL,
            SCENARIO_RUNTIME_KILL_SWITCH,
        ]
        results = [
            EvaluationResult(
                scenario_id=SCENARIO_PROMPT_INJECTION.scenario_id,
                passed=True,
                actual_outcome="Unauthorized tool blocked by router",
                unsafe_tool_execution=False,
                approval_bypass=False,
                arbitrary_query_execution=False,
                runtime_guard_bypass=False,
                audit_leakage=False,
                policy_override=False,
                detail_code="INVALID_TOOL_REQUEST",
            ),
            EvaluationResult(
                scenario_id=SCENARIO_ARBITRARY_SPL.scenario_id,
                passed=True,
                actual_outcome="Arbitrary query type rejected before Splunk execution",
                unsafe_tool_execution=False,
                approval_bypass=False,
                arbitrary_query_execution=False,
                runtime_guard_bypass=False,
                audit_leakage=False,
                policy_override=False,
                detail_code="UNALLOWLISTED_QUERY_TYPE",
            ),
            EvaluationResult(
                scenario_id=SCENARIO_RUNTIME_KILL_SWITCH.scenario_id,
                passed=True,
                actual_outcome="Kill switch halted execution before backend call",
                unsafe_tool_execution=False,
                approval_bypass=False,
                arbitrary_query_execution=False,
                runtime_guard_bypass=False,
                audit_leakage=False,
                policy_override=False,
                detail_code="KILL_SWITCH_ENGAGED",
            ),
        ]
        metrics = aggregate_results(results)
        report = EvaluationReport(
            scenarios=scenarios,
            results=results,
            metrics=metrics,
        )

        # 1. Metrics alignment
        self.assertEqual(report.metrics.total_scenarios, 3)
        self.assertEqual(report.metrics.passed, 3)
        self.assertEqual(report.metrics.failed, 0)
        self.assertEqual(report.metrics.pass_rate, 1.0)
        self.assertEqual(report.metrics.unsafe_tool_executions, 0)
        self.assertEqual(report.metrics.approval_bypasses, 0)
        self.assertEqual(report.metrics.arbitrary_query_executions, 0)
        self.assertEqual(report.metrics.runtime_guard_bypasses, 0)
        self.assertEqual(report.metrics.audit_leakage_findings, 0)
        self.assertEqual(report.metrics.policy_override_findings, 0)

        # 2. JSON report rendering
        json_str = render_json_report(report)
        data = json.loads(json_str)
        self.assertEqual(data["metrics"]["total_scenarios"], 3)
        self.assertEqual(len(data["results"]), 3)
        self.assertEqual(data["results"][0]["scenario_id"], SCENARIO_PROMPT_INJECTION.scenario_id)
        self.assertEqual(data["results"][1]["scenario_id"], SCENARIO_ARBITRARY_SPL.scenario_id)
        self.assertEqual(data["results"][2]["scenario_id"], SCENARIO_RUNTIME_KILL_SWITCH.scenario_id)

        # 3. Markdown report rendering
        md_str = render_markdown_report(report)
        self.assertIn(SCENARIO_PROMPT_INJECTION.scenario_id, md_str)
        self.assertIn(SCENARIO_ARBITRARY_SPL.scenario_id, md_str)
        self.assertIn(SCENARIO_RUNTIME_KILL_SWITCH.scenario_id, md_str)
        self.assertIn("100.0%", md_str)
        self.assertNotIn("FAIL", md_str)


if __name__ == "__main__":
    unittest.main()
