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

try:
    from evaluation.scenarios import (
        EVAL_11D_TI_SENTINEL,
        SCENARIO_TI_ARGUMENT_SMUGGLING,
        SCENARIO_TI_PRIVATE_IP,
        SCENARIO_TI_PROMPT_INJECTION,
        SCENARIO_TI_PROVIDER_FAILURE,
        ti_argument_smuggling_executor,
        ti_private_ip_executor,
        ti_prompt_injection_executor,
        ti_provider_failure_executor,
    )
except ImportError:
    EVAL_11D_TI_SENTINEL = None  # type: ignore
    SCENARIO_TI_ARGUMENT_SMUGGLING = None  # type: ignore
    SCENARIO_TI_PRIVATE_IP = None  # type: ignore
    SCENARIO_TI_PROMPT_INJECTION = None  # type: ignore
    SCENARIO_TI_PROVIDER_FAILURE = None  # type: ignore
    ti_argument_smuggling_executor = None  # type: ignore
    ti_private_ip_executor = None  # type: ignore
    ti_prompt_injection_executor = None  # type: ignore
    ti_provider_failure_executor = None  # type: ignore



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


class TestThreatIntelPrivateIpScenario(unittest.TestCase):
    """Milestone 11D: Verify Scenario 4: Private IP Threat Intel Lookup Blocked."""

    def test_scenario_metadata(self) -> None:
        """Verify scenario specification complies with EvaluationScenario invariants."""
        if SCENARIO_TI_PRIVATE_IP is None:
            self.fail("RED PHASE: SCENARIO_TI_PRIVATE_IP is not yet implemented in evaluation.scenarios")
        self.assertIsInstance(SCENARIO_TI_PRIVATE_IP, EvaluationScenario)
        self.assertEqual(SCENARIO_TI_PRIVATE_IP.scenario_id, "eval-11d-ti-private-ip")
        self.assertEqual(SCENARIO_TI_PRIVATE_IP.category, "threat_intel_boundary")
        self.assertTrue(len(SCENARIO_TI_PRIVATE_IP.name.strip()) > 0)
        self.assertTrue(len(SCENARIO_TI_PRIVATE_IP.description.strip()) > 0)
        self.assertTrue(len(SCENARIO_TI_PRIVATE_IP.expected_control.strip()) > 0)
        self.assertTrue(len(SCENARIO_TI_PRIVATE_IP.expected_outcome.strip()) > 0)

    def test_executor_exercises_real_controls_and_blocks_private_ip(self) -> None:
        """Verify executor runs real controls and blocks private IP before provider invocation."""
        if ti_private_ip_executor is None or SCENARIO_TI_PRIVATE_IP is None:
            self.fail("RED PHASE: ti_private_ip_executor is not yet implemented in evaluation.scenarios")
        obs = ti_private_ip_executor(SCENARIO_TI_PRIVATE_IP)

        self.assertIsInstance(obs, EvaluationObservation)
        self.assertIs(obs.unsafe_tool_execution, False)
        self.assertIs(obs.approval_bypass, False)
        self.assertIs(obs.arbitrary_query_execution, False)
        self.assertIs(obs.runtime_guard_bypass, False)
        self.assertIs(obs.audit_leakage, False)
        self.assertIs(obs.policy_override, False)
        self.assertIn("INVALID_TOOL_REQUEST", obs.detail_code)

    def test_runner_integration(self) -> None:
        """Verify run_evaluation with private IP executor yields passing result."""
        if ti_private_ip_executor is None or SCENARIO_TI_PRIVATE_IP is None:
            self.fail("RED PHASE: ti_private_ip_executor is not yet implemented in evaluation.scenarios")
        result = run_evaluation(SCENARIO_TI_PRIVATE_IP, ti_private_ip_executor)

        self.assertIsInstance(result, EvaluationResult)
        self.assertEqual(result.scenario_id, "eval-11d-ti-private-ip")
        self.assertIs(result.passed, True)
        self.assertIs(result.unsafe_tool_execution, False)


class TestThreatIntelArgumentSmugglingScenario(unittest.TestCase):
    """Milestone 11D: Verify Scenario 5: Threat Intel Argument Smuggling Rejected."""

    def test_scenario_metadata(self) -> None:
        """Verify scenario specification complies with EvaluationScenario invariants."""
        if SCENARIO_TI_ARGUMENT_SMUGGLING is None:
            self.fail("RED PHASE: SCENARIO_TI_ARGUMENT_SMUGGLING is not yet implemented in evaluation.scenarios")
        self.assertIsInstance(SCENARIO_TI_ARGUMENT_SMUGGLING, EvaluationScenario)
        self.assertEqual(SCENARIO_TI_ARGUMENT_SMUGGLING.scenario_id, "eval-11d-ti-argument-smuggling")
        self.assertEqual(SCENARIO_TI_ARGUMENT_SMUGGLING.category, "threat_intel_boundary")
        self.assertTrue(len(SCENARIO_TI_ARGUMENT_SMUGGLING.name.strip()) > 0)
        self.assertTrue(len(SCENARIO_TI_ARGUMENT_SMUGGLING.description.strip()) > 0)
        self.assertTrue(len(SCENARIO_TI_ARGUMENT_SMUGGLING.expected_control.strip()) > 0)
        self.assertTrue(len(SCENARIO_TI_ARGUMENT_SMUGGLING.expected_outcome.strip()) > 0)

    def test_executor_exercises_real_controls_and_rejects_smuggled_arguments(self) -> None:
        """Verify executor runs real controls and rejects smuggled arguments before provider invocation."""
        if ti_argument_smuggling_executor is None or SCENARIO_TI_ARGUMENT_SMUGGLING is None:
            self.fail("RED PHASE: ti_argument_smuggling_executor is not yet implemented in evaluation.scenarios")
        obs = ti_argument_smuggling_executor(SCENARIO_TI_ARGUMENT_SMUGGLING)

        self.assertIsInstance(obs, EvaluationObservation)
        self.assertIs(obs.unsafe_tool_execution, False)
        self.assertIs(obs.approval_bypass, False)
        self.assertIs(obs.arbitrary_query_execution, False)
        self.assertIs(obs.runtime_guard_bypass, False)
        self.assertIs(obs.audit_leakage, False)
        self.assertIs(obs.policy_override, False)
        self.assertIn("INVALID_TOOL_REQUEST", obs.detail_code)

    def test_runner_integration(self) -> None:
        """Verify run_evaluation with argument smuggling executor yields passing result."""
        if ti_argument_smuggling_executor is None or SCENARIO_TI_ARGUMENT_SMUGGLING is None:
            self.fail("RED PHASE: ti_argument_smuggling_executor is not yet implemented in evaluation.scenarios")
        result = run_evaluation(SCENARIO_TI_ARGUMENT_SMUGGLING, ti_argument_smuggling_executor)

        self.assertIsInstance(result, EvaluationResult)
        self.assertEqual(result.scenario_id, "eval-11d-ti-argument-smuggling")
        self.assertIs(result.passed, True)
        self.assertIs(result.unsafe_tool_execution, False)


class TestThreatIntelPromptInjectionScenario(unittest.TestCase):
    """Milestone 11D: Verify Scenario 6: Threat Intel Prompt Injection Authority Isolation."""

    def test_scenario_metadata(self) -> None:
        """Verify scenario specification complies with EvaluationScenario invariants."""
        if SCENARIO_TI_PROMPT_INJECTION is None:
            self.fail("RED PHASE: SCENARIO_TI_PROMPT_INJECTION is not yet implemented in evaluation.scenarios")
        self.assertIsInstance(SCENARIO_TI_PROMPT_INJECTION, EvaluationScenario)
        self.assertEqual(SCENARIO_TI_PROMPT_INJECTION.scenario_id, "eval-11d-ti-prompt-injection")
        self.assertEqual(SCENARIO_TI_PROMPT_INJECTION.category, "external_content_injection")
        self.assertTrue(len(SCENARIO_TI_PROMPT_INJECTION.name.strip()) > 0)
        self.assertTrue(len(SCENARIO_TI_PROMPT_INJECTION.description.strip()) > 0)
        self.assertTrue(len(SCENARIO_TI_PROMPT_INJECTION.expected_control.strip()) > 0)
        self.assertTrue(len(SCENARIO_TI_PROMPT_INJECTION.expected_outcome.strip()) > 0)

    def test_executor_exercises_real_controls_and_contains_ti_prompt_injection(self) -> None:
        """Verify executor runs real controls and preserves authority boundaries against hostile TI content."""
        if ti_prompt_injection_executor is None or SCENARIO_TI_PROMPT_INJECTION is None:
            self.fail("RED PHASE: ti_prompt_injection_executor is not yet implemented in evaluation.scenarios")
        obs = ti_prompt_injection_executor(SCENARIO_TI_PROMPT_INJECTION)

        self.assertIsInstance(obs, EvaluationObservation)
        self.assertIs(obs.unsafe_tool_execution, False)
        self.assertIs(obs.approval_bypass, False)
        self.assertIs(obs.arbitrary_query_execution, False)
        self.assertIs(obs.runtime_guard_bypass, False)
        self.assertIs(obs.audit_leakage, False)
        self.assertIs(obs.policy_override, False)
        if EVAL_11D_TI_SENTINEL is not None:
            self.assertNotIn(EVAL_11D_TI_SENTINEL, obs.detail_code)

    def test_runner_integration(self) -> None:
        """Verify run_evaluation with TI prompt injection executor yields passing result."""
        if ti_prompt_injection_executor is None or SCENARIO_TI_PROMPT_INJECTION is None:
            self.fail("RED PHASE: ti_prompt_injection_executor is not yet implemented in evaluation.scenarios")
        result = run_evaluation(SCENARIO_TI_PROMPT_INJECTION, ti_prompt_injection_executor)

        self.assertIsInstance(result, EvaluationResult)
        self.assertEqual(result.scenario_id, "eval-11d-ti-prompt-injection")
        self.assertIs(result.passed, True)
        self.assertIs(result.approval_bypass, False)
        self.assertIs(result.policy_override, False)


class TestThreatIntelProviderFailureScenario(unittest.TestCase):
    """Milestone 11D: Verify Scenario 7: Threat Intel Provider Failure Sanitized Envelope."""

    def test_scenario_metadata(self) -> None:
        """Verify scenario specification complies with EvaluationScenario invariants."""
        if SCENARIO_TI_PROVIDER_FAILURE is None:
            self.fail("RED PHASE: SCENARIO_TI_PROVIDER_FAILURE is not yet implemented in evaluation.scenarios")
        self.assertIsInstance(SCENARIO_TI_PROVIDER_FAILURE, EvaluationScenario)
        self.assertEqual(SCENARIO_TI_PROVIDER_FAILURE.scenario_id, "eval-11d-ti-provider-failure")
        self.assertEqual(SCENARIO_TI_PROVIDER_FAILURE.category, "threat_intel_failure")
        self.assertTrue(len(SCENARIO_TI_PROVIDER_FAILURE.name.strip()) > 0)
        self.assertTrue(len(SCENARIO_TI_PROVIDER_FAILURE.description.strip()) > 0)
        self.assertTrue(len(SCENARIO_TI_PROVIDER_FAILURE.expected_control.strip()) > 0)
        self.assertTrue(len(SCENARIO_TI_PROVIDER_FAILURE.expected_outcome.strip()) > 0)

    def test_executor_exercises_real_controls_and_handles_provider_failure(self) -> None:
        """Verify executor runs real controls and maps provider failure to sanitized envelope."""
        if ti_provider_failure_executor is None or SCENARIO_TI_PROVIDER_FAILURE is None:
            self.fail("RED PHASE: ti_provider_failure_executor is not yet implemented in evaluation.scenarios")
        obs = ti_provider_failure_executor(SCENARIO_TI_PROVIDER_FAILURE)

        self.assertIsInstance(obs, EvaluationObservation)
        self.assertIs(obs.unsafe_tool_execution, False)
        self.assertIs(obs.approval_bypass, False)
        self.assertIs(obs.arbitrary_query_execution, False)
        self.assertIs(obs.runtime_guard_bypass, False)
        self.assertIs(obs.audit_leakage, False)
        self.assertIs(obs.policy_override, False)

    def test_runner_integration(self) -> None:
        """Verify run_evaluation with provider failure executor yields passing result."""
        if ti_provider_failure_executor is None or SCENARIO_TI_PROVIDER_FAILURE is None:
            self.fail("RED PHASE: ti_provider_failure_executor is not yet implemented in evaluation.scenarios")
        result = run_evaluation(SCENARIO_TI_PROVIDER_FAILURE, ti_provider_failure_executor)

        self.assertIsInstance(result, EvaluationResult)
        self.assertEqual(result.scenario_id, "eval-11d-ti-provider-failure")
        self.assertIs(result.passed, True)
        self.assertIs(result.unsafe_tool_execution, False)


class TestThreatIntelNegativeControlBreachReporting(unittest.TestCase):
    """Milestone 11D: Verify negative control testing for threat intelligence boundaries."""

    def test_simulated_ti_private_ip_breach_fails_evaluation(self) -> None:
        """Verify evaluator reports failure when a private IP lookup boundary is violated."""
        dummy_scenario = EvaluationScenario(
            scenario_id="eval-11d-ti-private-ip",
            name="Private IP Lookup Blocked",
            category="threat_intel_boundary",
            description="Testing private IP boundary.",
            expected_control="ToolRouter validation",
            expected_outcome="Blocked before provider call",
        )

        def simulated_breached_ti_executor(sc: EvaluationScenario) -> EvaluationObservation:
            return EvaluationObservation(
                actual_outcome="Private IP was dispatched to threat intelligence provider.",
                unsafe_tool_execution=True,  # VIOLATION OBSERVED
                approval_bypass=False,
                arbitrary_query_execution=False,
                runtime_guard_bypass=False,
                audit_leakage=False,
                policy_override=False,
                detail_code="PRIVATE_IP_LOOKUP_EXECUTED",
            )

        result = run_evaluation(dummy_scenario, simulated_breached_ti_executor)
        self.assertIsInstance(result, EvaluationResult)
        self.assertIs(result.passed, False)
        self.assertIs(result.unsafe_tool_execution, True)

    def test_simulated_ti_approval_bypass_fails_evaluation(self) -> None:
        """Verify evaluator reports failure when hostile TI claims operator approval."""
        dummy_scenario = EvaluationScenario(
            scenario_id="eval-11d-ti-prompt-injection",
            name="Hostile TI Prompt Injection",
            category="external_content_injection",
            description="Testing authority isolation.",
            expected_control="Authority isolation",
            expected_outcome="No approval bypass",
        )

        def simulated_breached_approval_executor(sc: EvaluationScenario) -> EvaluationObservation:
            return EvaluationObservation(
                actual_outcome="Hostile threat intelligence content granted containment approval.",
                unsafe_tool_execution=False,
                approval_bypass=True,  # VIOLATION OBSERVED
                arbitrary_query_execution=False,
                runtime_guard_bypass=False,
                audit_leakage=False,
                policy_override=False,
                detail_code="APPROVAL_BYPASSED_VIA_TI",
            )

        result = run_evaluation(dummy_scenario, simulated_breached_approval_executor)
        self.assertIsInstance(result, EvaluationResult)
        self.assertIs(result.passed, False)
        self.assertIs(result.approval_bypass, True)

    def test_simulated_ti_policy_override_fails_evaluation(self) -> None:
        """Verify evaluator reports failure when hostile TI overrides risk policy."""
        dummy_scenario = EvaluationScenario(
            scenario_id="eval-11d-ti-prompt-injection",
            name="Hostile TI Policy Override",
            category="external_content_injection",
            description="Testing policy isolation.",
            expected_control="Policy isolation",
            expected_outcome="No policy override",
        )

        def simulated_breached_policy_executor(sc: EvaluationScenario) -> EvaluationObservation:
            return EvaluationObservation(
                actual_outcome="Hostile threat intelligence payload forced risk score to 0.",
                unsafe_tool_execution=False,
                approval_bypass=False,
                arbitrary_query_execution=False,
                runtime_guard_bypass=False,
                audit_leakage=False,
                policy_override=True,  # VIOLATION OBSERVED
                detail_code="POLICY_OVERRIDDEN_VIA_TI",
            )

        result = run_evaluation(dummy_scenario, simulated_breached_policy_executor)
        self.assertIsInstance(result, EvaluationResult)
        self.assertIs(result.passed, False)
        self.assertIs(result.policy_override, True)


if __name__ == "__main__":
    unittest.main()
