"""Tests for the deterministic end-to-end evaluation harness.

TDD RED PHASE ONLY - Milestone 10F.
Exercises end-to-end orchestration of existing 10C scenarios, runner,
metrics aggregation, and deterministic report rendering.
"""

import json
from unittest.mock import MagicMock, patch
import unittest

from evaluation.harness import (
    EvaluationHarnessError,
    run_and_render_security_evaluation,
    run_security_evaluation,
)
from evaluation.runner import EvaluationObservation, EvaluationRunnerError
from evaluation.scenarios import (
    SCENARIO_ARBITRARY_SPL,
    SCENARIO_PROMPT_INJECTION,
    SCENARIO_RUNTIME_KILL_SWITCH,
)


EXPECTED_SCENARIO_IDS = [
    "eval-10c-prompt-injection",
    "eval-10c-arbitrary-spl",
    "eval-10c-runtime-guard",
    "eval-11d-ti-private-ip",
    "eval-11d-ti-argument-smuggling",
    "eval-11d-ti-prompt-injection",
    "eval-11d-ti-provider-failure",
    "eval-12g-web01-modsecurity-prompt-injection",
    "eval-12g-web01-raw-parser-bypass",
    "eval-12g-web01-private-ip-ti-bypass",
    "eval-12g-web01-argument-smuggling",
    "eval-12g-web01-ti-provider-failure",
    "eval-12g-web01-jira-payload-injection",
    "eval-12g-web01-unauthorized-jira-config",
    "eval-12g-web01-raw-spl-bypass",
    "eval-12g-web01-semantic-confusion",
    "eval-12g-web01-live-derived-private",
]


class TestEvaluationHarnessExecution(unittest.TestCase):
    """Tests verifying run_security_evaluation() contract, ordering, and metrics integration."""

    def test_default_execution_runs_all_seven_real_scenarios(self) -> None:
        """Harness executes all 17 real scenarios and returns complete EvaluationReport."""
        report = run_security_evaluation()

        # 1. Scenarios and results alignment
        self.assertEqual(len(report.scenarios), len(EXPECTED_SCENARIO_IDS))
        self.assertEqual(len(report.results), len(EXPECTED_SCENARIO_IDS))

        # 2. Strict, explicit scenario ordering
        actual_scenario_ids = [s.scenario_id for s in report.scenarios]
        actual_result_ids = [r.scenario_id for r in report.results]
        self.assertEqual(actual_scenario_ids, EXPECTED_SCENARIO_IDS)
        self.assertEqual(actual_result_ids, EXPECTED_SCENARIO_IDS)

        # 3. Real controls hold across all scenarios
        for result in report.results:
            self.assertTrue(result.passed, f"Scenario {result.scenario_id} unexpectedly failed")

        # 4. Computed metrics reflect passing real controls
        self.assertEqual(report.metrics.total_scenarios, 17)
        self.assertEqual(report.metrics.passed, 17)
        self.assertEqual(report.metrics.failed, 0)
        self.assertEqual(report.metrics.pass_rate, 1.0)
        self.assertEqual(report.metrics.unsafe_tool_executions, 0)
        self.assertEqual(report.metrics.approval_bypasses, 0)
        self.assertEqual(report.metrics.arbitrary_query_executions, 0)
        self.assertEqual(report.metrics.runtime_guard_bypasses, 0)
        self.assertEqual(report.metrics.audit_leakage_findings, 0)
        self.assertEqual(report.metrics.policy_override_findings, 0)

    def test_scenario_ordering_is_fixed_and_stable(self) -> None:
        """Scenario order must match: 1. prompt-injection, 2. arbitrary-spl, 3. runtime-guard."""
        report = run_security_evaluation()
        self.assertEqual(report.scenarios[0].scenario_id, SCENARIO_PROMPT_INJECTION.scenario_id)
        self.assertEqual(report.scenarios[1].scenario_id, SCENARIO_ARBITRARY_SPL.scenario_id)
        self.assertEqual(report.scenarios[2].scenario_id, SCENARIO_RUNTIME_KILL_SWITCH.scenario_id)

    def test_each_scenario_executed_exactly_once(self) -> None:
        """Each scenario executor must be invoked exactly once with no retries."""
        with patch("evaluation.harness.run_evaluation", wraps=None) as mock_runner:
            # Configure mock runner to return passing results
            from evaluation.schema import EvaluationResult

            def fake_run(scenario, executor):
                return EvaluationResult(
                    scenario_id=scenario.scenario_id,
                    passed=True,
                    actual_outcome="Pass",
                    unsafe_tool_execution=False,
                    approval_bypass=False,
                    arbitrary_query_execution=False,
                    runtime_guard_bypass=False,
                    audit_leakage=False,
                    policy_override=False,
                    detail_code="OK",
                )

            mock_runner.side_effect = fake_run

            report = run_security_evaluation()
            self.assertEqual(mock_runner.call_count, len(EXPECTED_SCENARIO_IDS))
            called_scenario_ids = [call.args[0].scenario_id for call in mock_runner.call_args_list]
            self.assertEqual(called_scenario_ids, EXPECTED_SCENARIO_IDS)


class TestEvaluationHarnessRendering(unittest.TestCase):
    """Tests verifying run_and_render_security_evaluation() output and determinism."""

    def test_run_and_render_produces_valid_reports(self) -> None:
        """run_and_render_security_evaluation() returns valid JSON and Markdown strings."""
        json_str, md_str = run_and_render_security_evaluation()

        # 1. JSON report validation
        self.assertIsInstance(json_str, str)
        data = json.loads(json_str)
        self.assertEqual(data.get("report_type"), "ai_native_soc_agent_security_evaluation")
        self.assertEqual(data["metrics"]["total_scenarios"], len(EXPECTED_SCENARIO_IDS))
        self.assertEqual(data["metrics"]["passed"], len(EXPECTED_SCENARIO_IDS))
        self.assertEqual(data["metrics"]["failed"], 0)
        self.assertEqual(data["metrics"]["pass_rate"], 1.0)
        self.assertEqual(data["metrics"]["unsafe_tool_executions"], 0)
        self.assertEqual(len(data["results"]), len(EXPECTED_SCENARIO_IDS))
        for i, sc_id in enumerate(EXPECTED_SCENARIO_IDS):
            self.assertEqual(data["results"][i]["scenario_id"], sc_id)

        # 2. Markdown report validation
        self.assertIsInstance(md_str, str)
        self.assertIn("# AI SOC Agent Security Evaluation Report", md_str)
        self.assertIn("controlled lab environment", md_str.lower())
        self.assertIn(f"Total Scenarios: {len(EXPECTED_SCENARIO_IDS)}", md_str)
        self.assertIn(f"Passed: {len(EXPECTED_SCENARIO_IDS)}", md_str)
        self.assertIn("Failed: 0", md_str)
        self.assertIn("Pass Rate: 100.0%", md_str)
        for sc_id in EXPECTED_SCENARIO_IDS:
            self.assertIn(sc_id, md_str)
        self.assertNotIn("FAIL", md_str)

    def test_rendering_is_deterministic(self) -> None:
        """Repeated harness execution produces byte-for-byte identical output."""
        json_1, md_1 = run_and_render_security_evaluation()
        json_2, md_2 = run_and_render_security_evaluation()
        self.assertEqual(json_1, json_2)
        self.assertEqual(md_1, md_2)


class TestEvaluationHarnessFailClosedBehavior(unittest.TestCase):
    """Tests verifying fail-closed handling if an executor fails unexpectedly."""

    def test_executor_exception_fails_closed(self) -> None:
        """Unexpected executor exception must fail closed and never yield partial pass report."""
        faulty_executors = {
            "eval-10c-prompt-injection": lambda scenario: (_ for _ in ()).throw(
                RuntimeError("Simulated infrastructure crash")
            ),
        }
        with self.assertRaises((EvaluationHarnessError, EvaluationRunnerError)):
            run_security_evaluation(executors=faulty_executors)

    def test_executor_malformed_observation_fails_closed(self) -> None:
        """Malformed observation from executor fails closed via schema/runner validation."""
        faulty_executors = {
            "eval-10c-prompt-injection": lambda scenario: "not-an-observation",
        }
        with self.assertRaises((EvaluationHarnessError, EvaluationRunnerError)):
            run_security_evaluation(executors=faulty_executors)


class TestEvaluationHarnessNegativeControl(unittest.TestCase):
    """Negative control testing simulating a security boundary failure."""

    def test_simulated_breach_reflected_in_metrics_and_reports(self) -> None:
        """Simulated unsafe tool execution reflects in metrics, result status, and rendered reports."""
        def breaching_executor(scenario):
            return EvaluationObservation(
                actual_outcome="Simulated unsafe tool invocation succeeded",
                unsafe_tool_execution=True,
                approval_bypass=False,
                arbitrary_query_execution=False,
                runtime_guard_bypass=False,
                audit_leakage=False,
                policy_override=False,
                detail_code="UNSAFE_TOOL_EXECUTED",
            )

        simulated_executors = {
            "eval-10c-prompt-injection": breaching_executor,
        }

        report = run_security_evaluation(executors=simulated_executors)

        # 1. Metrics reflect breach
        total_scenarios = 17
        self.assertEqual(report.metrics.total_scenarios, total_scenarios)
        self.assertEqual(report.metrics.passed, total_scenarios - 1)
        self.assertEqual(report.metrics.failed, 1)
        self.assertAlmostEqual(report.metrics.pass_rate, (total_scenarios - 1) / total_scenarios, places=4)
        self.assertEqual(report.metrics.unsafe_tool_executions, 1)

        # 2. Result state
        self.assertFalse(report.results[0].passed)
        self.assertTrue(report.results[0].unsafe_tool_execution)
        self.assertEqual(report.results[0].detail_code, "UNSAFE_TOOL_EXECUTED")
        for res in report.results[1:]:
            self.assertTrue(res.passed)

        # 3. Rendered output reflects failure
        from evaluation.reporting import render_json_report, render_markdown_report

        json_str = render_json_report(report)
        md_str = render_markdown_report(report)

        data = json.loads(json_str)
        self.assertEqual(data["metrics"]["failed"], 1)
        self.assertEqual(data["results"][0]["passed"], False)
        self.assertIn("FAIL", md_str)
        self.assertIn("94.1%", md_str)


class TestThreatIntelEvaluationHarnessIntegration(unittest.TestCase):
    """Milestone 11D: Harness integration with expanded canonical scenarios."""

    def test_harness_scenarios_contains_all_seven_scenarios(self) -> None:
        """EVALUATION_SCENARIOS must contain the baseline 7 canonical scenarios in fixed order."""
        from evaluation.harness import EVALUATION_SCENARIOS

        expected_scenario_ids = (
            "eval-10c-prompt-injection",
            "eval-10c-arbitrary-spl",
            "eval-10c-runtime-guard",
            "eval-11d-ti-private-ip",
            "eval-11d-ti-argument-smuggling",
            "eval-11d-ti-prompt-injection",
            "eval-11d-ti-provider-failure",
        )
        actual_ids = tuple(s.scenario_id for s in EVALUATION_SCENARIOS[:7])
        self.assertEqual(actual_ids, expected_scenario_ids)

    def test_harness_executes_all_seven_scenarios_cleanly(self) -> None:
        """Harness default execution must run all scenarios cleanly with baseline 7 passing."""
        report = run_security_evaluation()
        self.assertGreaterEqual(len(report.scenarios), 7)
        for res in report.results[:7]:
            self.assertTrue(res.passed)

        self.assertEqual(report.metrics.failed, 0)
        self.assertEqual(report.metrics.pass_rate, 1.0)
        self.assertEqual(report.metrics.unsafe_tool_executions, 0)
        self.assertEqual(report.metrics.approval_bypasses, 0)
        self.assertEqual(report.metrics.arbitrary_query_executions, 0)
        self.assertEqual(report.metrics.runtime_guard_bypasses, 0)
        self.assertEqual(report.metrics.audit_leakage_findings, 0)
        self.assertEqual(report.metrics.policy_override_findings, 0)

    def test_harness_renders_all_seven_scenarios(self) -> None:
        """Harness rendered JSON and Markdown must include all 7 baseline scenarios."""
        json_str, md_str = run_and_render_security_evaluation()
        data = json.loads(json_str)

        self.assertGreaterEqual(data["metrics"]["total_scenarios"], 7)
        self.assertEqual(data["metrics"]["failed"], 0)
        self.assertEqual(data["metrics"]["pass_rate"], 1.0)

        expected_ids = [
            "eval-10c-prompt-injection",
            "eval-10c-arbitrary-spl",
            "eval-10c-runtime-guard",
            "eval-11d-ti-private-ip",
            "eval-11d-ti-argument-smuggling",
            "eval-11d-ti-prompt-injection",
            "eval-11d-ti-provider-failure",
        ]
        actual_ids = [r["scenario_id"] for r in data["results"]]
        for sc_id in expected_ids:
            self.assertIn(sc_id, actual_ids)
            self.assertIn(sc_id, md_str)


if __name__ == "__main__":
    unittest.main()
