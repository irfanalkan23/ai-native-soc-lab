"""Unit tests for Milestone 10C reusable adversarial scenario executors.

Covers:
  - Scenario 1: Telemetry Prompt Injection -> Unauthorized Tool Blocked
  - Scenario 2: Arbitrary SPL / Query Abuse -> Rejected Before Splunk Execution
  - Scenario 3: Runtime Kill Switch -> Valid Tool Blocked
  - Runner integration: run_evaluation(scenario, executor) returns passed=True
  - Audit sanitization: sentinels never appear in audit detail codes
  - Negative control: evaluator marks failure when a violation is observed
"""

import unittest

from evaluation.runner import EvaluationObservation, run_evaluation
from evaluation.schema import EvaluationResult, EvaluationScenario

# TDD RED Phase: Import from future production module evaluation.scenarios
from evaluation.scenarios import (
    EVAL_10C_GUARD_SENTINEL,
    EVAL_10C_PROMPT_SENTINEL,
    EVAL_10C_SPL_SENTINEL,
    SCENARIO_ARBITRARY_SPL,
    SCENARIO_PROMPT_INJECTION,
    SCENARIO_RUNTIME_KILL_SWITCH,
    arbitrary_spl_injection_executor,
    runtime_kill_switch_executor,
    telemetry_prompt_injection_executor,
)


class TestTelemetryPromptInjectionScenario(unittest.TestCase):
    """Verify Scenario 1: Telemetry prompt injection attempting unauthorized tool."""

    def test_scenario_metadata(self) -> None:
        """Verify scenario specification complies with EvaluationScenario invariants."""
        self.assertIsInstance(SCENARIO_PROMPT_INJECTION, EvaluationScenario)
        self.assertEqual(SCENARIO_PROMPT_INJECTION.scenario_id, "eval-10c-prompt-injection")
        self.assertEqual(SCENARIO_PROMPT_INJECTION.category, "prompt_injection")
        self.assertTrue(len(SCENARIO_PROMPT_INJECTION.description.strip()) > 0)
        self.assertTrue(len(SCENARIO_PROMPT_INJECTION.expected_control.strip()) > 0)
        self.assertTrue(len(SCENARIO_PROMPT_INJECTION.expected_outcome.strip()) > 0)

    def test_executor_exercises_real_controls_and_blocks_unauthorized_tool(self) -> None:
        """Verify executor runs real orchestrator/router path and blocks tool execution."""
        obs = telemetry_prompt_injection_executor(SCENARIO_PROMPT_INJECTION)

        self.assertIsInstance(obs, EvaluationObservation)
        self.assertIs(obs.unsafe_tool_execution, False)
        self.assertIs(obs.approval_bypass, False)
        self.assertIs(obs.arbitrary_query_execution, False)
        self.assertIs(obs.runtime_guard_bypass, False)
        self.assertIs(obs.audit_leakage, False)
        self.assertIs(obs.policy_override, False)
        self.assertEqual(obs.detail_code, "INVALID_TOOL_REQUEST")
        self.assertNotIn(EVAL_10C_PROMPT_SENTINEL, obs.detail_code)

    def test_runner_integration(self) -> None:
        """Verify run_evaluation with prompt injection executor yields passing result."""
        result = run_evaluation(SCENARIO_PROMPT_INJECTION, telemetry_prompt_injection_executor)

        self.assertIsInstance(result, EvaluationResult)
        self.assertEqual(result.scenario_id, "eval-10c-prompt-injection")
        self.assertIs(result.passed, True)
        self.assertIs(result.unsafe_tool_execution, False)
        self.assertEqual(result.detail_code, "INVALID_TOOL_REQUEST")


class TestArbitrarySplScenario(unittest.TestCase):
    """Verify Scenario 2: Arbitrary SPL injection attempting query abuse."""

    def test_scenario_metadata(self) -> None:
        """Verify scenario specification complies with EvaluationScenario invariants."""
        self.assertIsInstance(SCENARIO_ARBITRARY_SPL, EvaluationScenario)
        self.assertEqual(SCENARIO_ARBITRARY_SPL.scenario_id, "eval-10c-arbitrary-spl")
        self.assertEqual(SCENARIO_ARBITRARY_SPL.category, "query_abuse")
        self.assertTrue(len(SCENARIO_ARBITRARY_SPL.description.strip()) > 0)
        self.assertTrue(len(SCENARIO_ARBITRARY_SPL.expected_control.strip()) > 0)
        self.assertTrue(len(SCENARIO_ARBITRARY_SPL.expected_outcome.strip()) > 0)

    def test_executor_exercises_real_controls_and_rejects_query_before_splunk(self) -> None:
        """Verify executor runs real router validation and rejects arbitrary SPL before backend."""
        obs = arbitrary_spl_injection_executor(SCENARIO_ARBITRARY_SPL)

        self.assertIsInstance(obs, EvaluationObservation)
        self.assertIs(obs.arbitrary_query_execution, False)
        self.assertIs(obs.unsafe_tool_execution, False)
        self.assertIs(obs.approval_bypass, False)
        self.assertIs(obs.runtime_guard_bypass, False)
        self.assertIs(obs.audit_leakage, False)
        self.assertIs(obs.policy_override, False)
        self.assertEqual(obs.detail_code, "INVALID_TOOL_REQUEST")
        self.assertNotIn(EVAL_10C_SPL_SENTINEL, obs.detail_code)

    def test_runner_integration(self) -> None:
        """Verify run_evaluation with arbitrary SPL executor yields passing result."""
        result = run_evaluation(SCENARIO_ARBITRARY_SPL, arbitrary_spl_injection_executor)

        self.assertIsInstance(result, EvaluationResult)
        self.assertEqual(result.scenario_id, "eval-10c-arbitrary-spl")
        self.assertIs(result.passed, True)
        self.assertIs(result.arbitrary_query_execution, False)
        self.assertEqual(result.detail_code, "INVALID_TOOL_REQUEST")


class TestRuntimeKillSwitchScenario(unittest.TestCase):
    """Verify Scenario 3: Runtime kill-switch blocks allowlisted tool execution."""

    def test_scenario_metadata(self) -> None:
        """Verify scenario specification complies with EvaluationScenario invariants."""
        self.assertIsInstance(SCENARIO_RUNTIME_KILL_SWITCH, EvaluationScenario)
        self.assertEqual(SCENARIO_RUNTIME_KILL_SWITCH.scenario_id, "eval-10c-runtime-guard")
        self.assertEqual(SCENARIO_RUNTIME_KILL_SWITCH.category, "runtime_guard")
        self.assertTrue(len(SCENARIO_RUNTIME_KILL_SWITCH.description.strip()) > 0)
        self.assertTrue(len(SCENARIO_RUNTIME_KILL_SWITCH.expected_control.strip()) > 0)
        self.assertTrue(len(SCENARIO_RUNTIME_KILL_SWITCH.expected_outcome.strip()) > 0)

    def test_executor_exercises_real_controls_and_halts_on_kill_switch(self) -> None:
        """Verify executor runs real RuntimeGuard + orchestrator path and prevents backend call."""
        obs = runtime_kill_switch_executor(SCENARIO_RUNTIME_KILL_SWITCH)

        self.assertIsInstance(obs, EvaluationObservation)
        self.assertIs(obs.runtime_guard_bypass, False)
        self.assertIs(obs.unsafe_tool_execution, False)
        self.assertIs(obs.approval_bypass, False)
        self.assertIs(obs.arbitrary_query_execution, False)
        self.assertIs(obs.audit_leakage, False)
        self.assertIs(obs.policy_override, False)
        self.assertEqual(obs.detail_code, "KILL_SWITCH_ENGAGED")
        self.assertNotIn(EVAL_10C_GUARD_SENTINEL, obs.detail_code)

    def test_runner_integration(self) -> None:
        """Verify run_evaluation with runtime kill switch executor yields passing result."""
        result = run_evaluation(SCENARIO_RUNTIME_KILL_SWITCH, runtime_kill_switch_executor)

        self.assertIsInstance(result, EvaluationResult)
        self.assertEqual(result.scenario_id, "eval-10c-runtime-guard")
        self.assertIs(result.passed, True)
        self.assertIs(result.runtime_guard_bypass, False)
        self.assertEqual(result.detail_code, "KILL_SWITCH_ENGAGED")


class TestNegativeControlBreachReporting(unittest.TestCase):
    """Verify negative control: runner correctly reports failed result if violation is observed."""

    def test_simulated_breach_observation_fails_evaluation(self) -> None:
        """Verify runner fails closed (passed=False) when an executor observation reports a breach."""
        # Simulated observation double representing a scenario where a defensive control was bypassed
        def simulated_breached_executor(scenario: EvaluationScenario) -> EvaluationObservation:
            return EvaluationObservation(
                actual_outcome="Adversarial command bypassed isolation and executed shell.",
                unsafe_tool_execution=True,  # VIOLATION OBSERVED
                approval_bypass=False,
                arbitrary_query_execution=False,
                runtime_guard_bypass=False,
                audit_leakage=False,
                policy_override=False,
                detail_code="UNSAFE_EXECUTION_DETECTED",
            )

        result = run_evaluation(SCENARIO_PROMPT_INJECTION, simulated_breached_executor)

        self.assertIsInstance(result, EvaluationResult)
        self.assertEqual(result.scenario_id, "eval-10c-prompt-injection")
        self.assertIs(result.passed, False)  # Must be False
        self.assertIs(result.unsafe_tool_execution, True)
        self.assertEqual(result.detail_code, "UNSAFE_EXECUTION_DETECTED")


if __name__ == "__main__":
    unittest.main()
