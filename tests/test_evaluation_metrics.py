"""Unit tests for Milestone 10D security metrics aggregation.

Covers:
  - EvaluationMetrics schema: required fields, exact types, count bounds, pass_rate bounds, immutability, to_dict()
  - aggregate_results(): empty collection, safe all-pass, mixed results, multiple concurrent violations,
    exact counter accounting, pass_rate calculation, input validation, and fail-closed error handling.
"""

from dataclasses import FrozenInstanceError
import unittest

from evaluation.schema import EvaluationResult

# TDD RED Phase: Import from future production module evaluation.metrics
from evaluation.metrics import (
    EvaluationMetrics,
    EvaluationMetricsError,
    aggregate_results,
)


def _make_result(
    scenario_id: str = "SCN-001",
    passed: bool = True,
    unsafe_tool_execution: bool = False,
    approval_bypass: bool = False,
    arbitrary_query_execution: bool = False,
    runtime_guard_bypass: bool = False,
    audit_leakage: bool = False,
    policy_override: bool = False,
    detail_code: str = "SAFE",
) -> EvaluationResult:
    """Helper to construct compliant EvaluationResult test instances."""
    return EvaluationResult(
        scenario_id=scenario_id,
        passed=passed,
        actual_outcome=f"Outcome for {scenario_id}",
        unsafe_tool_execution=unsafe_tool_execution,
        approval_bypass=approval_bypass,
        arbitrary_query_execution=arbitrary_query_execution,
        runtime_guard_bypass=runtime_guard_bypass,
        audit_leakage=audit_leakage,
        policy_override=policy_override,
        detail_code=detail_code,
    )


class TestEvaluationMetricsSchema(unittest.TestCase):
    """Verify EvaluationMetrics schema constraints, type bounds, and immutability."""

    def setUp(self) -> None:
        self.valid_kwargs = {
            "total_scenarios": 10,
            "passed": 8,
            "failed": 2,
            "pass_rate": 0.8,
            "unsafe_tool_executions": 1,
            "approval_bypasses": 0,
            "arbitrary_query_executions": 1,
            "runtime_guard_bypasses": 0,
            "audit_leakage_findings": 0,
            "policy_override_findings": 0,
        }

    def test_valid_metrics_creation(self) -> None:
        """Verify compliant EvaluationMetrics instantiates with expected attributes."""
        metrics = EvaluationMetrics(**self.valid_kwargs)
        self.assertEqual(metrics.total_scenarios, 10)
        self.assertEqual(metrics.passed, 8)
        self.assertEqual(metrics.failed, 2)
        self.assertEqual(metrics.pass_rate, 0.8)
        self.assertEqual(metrics.unsafe_tool_executions, 1)
        self.assertEqual(metrics.approval_bypasses, 0)
        self.assertEqual(metrics.arbitrary_query_executions, 1)

    def test_count_fields_reject_non_int_and_bools(self) -> None:
        """Verify count fields require exact int and reject bools, floats, and strings."""
        int_fields = [
            "total_scenarios",
            "passed",
            "failed",
            "unsafe_tool_executions",
            "approval_bypasses",
            "arbitrary_query_executions",
            "runtime_guard_bypasses",
            "audit_leakage_findings",
            "policy_override_findings",
        ]
        bad_types = [True, False, 1.5, "10", None, [], {}]
        for field in int_fields:
            for bad_val in bad_types:
                bad_kwargs = dict(self.valid_kwargs, **{field: bad_val})
                with self.subTest(field=field, bad_val=bad_val):
                    with self.assertRaises((EvaluationMetricsError, TypeError, ValueError)):
                        EvaluationMetrics(**bad_kwargs)

    def test_count_fields_reject_negative_values(self) -> None:
        """Verify count fields reject negative values."""
        int_fields = [
            "total_scenarios",
            "passed",
            "failed",
            "unsafe_tool_executions",
            "approval_bypasses",
            "arbitrary_query_executions",
            "runtime_guard_bypasses",
            "audit_leakage_findings",
            "policy_override_findings",
        ]
        for field in int_fields:
            bad_kwargs = dict(self.valid_kwargs, **{field: -1})
            with self.subTest(field=field):
                with self.assertRaises((EvaluationMetricsError, ValueError)):
                    EvaluationMetrics(**bad_kwargs)

    def test_pass_rate_must_be_float_and_bounded(self) -> None:
        """Verify pass_rate must be exact float between 0.0 and 1.0 inclusive."""
        invalid_rates = [-0.1, 1.01, 2.0, 1, 0, "0.5", None]
        for bad_rate in invalid_rates:
            bad_kwargs = dict(self.valid_kwargs, pass_rate=bad_rate)
            with self.subTest(bad_rate=bad_rate):
                with self.assertRaises((EvaluationMetricsError, TypeError, ValueError)):
                    EvaluationMetrics(**bad_kwargs)

        # Valid edge bounds
        self.assertEqual(EvaluationMetrics(**dict(self.valid_kwargs, pass_rate=0.0)).pass_rate, 0.0)
        self.assertEqual(EvaluationMetrics(**dict(self.valid_kwargs, pass_rate=1.0)).pass_rate, 1.0)

    def test_metrics_immutability(self) -> None:
        """Verify EvaluationMetrics is frozen and cannot be mutated."""
        metrics = EvaluationMetrics(**self.valid_kwargs)
        with self.assertRaises((FrozenInstanceError, AttributeError, TypeError)):
            metrics.passed = 10  # type: ignore[misc]

    def test_metrics_to_dict_contract(self) -> None:
        """Verify to_dict returns exactly the declared 10 metric fields."""
        metrics = EvaluationMetrics(**self.valid_kwargs)
        data = metrics.to_dict()

        expected_keys = {
            "total_scenarios",
            "passed",
            "failed",
            "pass_rate",
            "unsafe_tool_executions",
            "approval_bypasses",
            "arbitrary_query_executions",
            "runtime_guard_bypasses",
            "audit_leakage_findings",
            "policy_override_findings",
        }
        self.assertEqual(set(data.keys()), expected_keys)
        self.assertEqual(data["total_scenarios"], 10)
        self.assertEqual(data["pass_rate"], 0.8)


class TestEvaluationMetricsAggregator(unittest.TestCase):
    """Verify aggregate_results behavior across empty, all-pass, mixed, and invalid inputs."""

    def test_empty_results_aggregation(self) -> None:
        """Empty sequence produces zeroed metrics with pass_rate 0.0."""
        metrics = aggregate_results([])

        self.assertIsInstance(metrics, EvaluationMetrics)
        self.assertEqual(metrics.total_scenarios, 0)
        self.assertEqual(metrics.passed, 0)
        self.assertEqual(metrics.failed, 0)
        self.assertEqual(metrics.pass_rate, 0.0)
        self.assertEqual(metrics.unsafe_tool_executions, 0)
        self.assertEqual(metrics.approval_bypasses, 0)
        self.assertEqual(metrics.arbitrary_query_executions, 0)
        self.assertEqual(metrics.runtime_guard_bypasses, 0)
        self.assertEqual(metrics.audit_leakage_findings, 0)
        self.assertEqual(metrics.policy_override_findings, 0)

    def test_safe_all_pass_case(self) -> None:
        """Safe passing case: 3 compliant results -> total=3, passed=3, failed=0, pass_rate=1.0."""
        results = [
            _make_result("SCN-001", passed=True),
            _make_result("SCN-002", passed=True),
            _make_result("SCN-003", passed=True),
        ]
        metrics = aggregate_results(results)

        self.assertEqual(metrics.total_scenarios, 3)
        self.assertEqual(metrics.passed, 3)
        self.assertEqual(metrics.failed, 0)
        self.assertEqual(metrics.pass_rate, 1.0)
        self.assertEqual(metrics.unsafe_tool_executions, 0)
        self.assertEqual(metrics.approval_bypasses, 0)
        self.assertEqual(metrics.arbitrary_query_executions, 0)
        self.assertEqual(metrics.runtime_guard_bypasses, 0)
        self.assertEqual(metrics.audit_leakage_findings, 0)
        self.assertEqual(metrics.policy_override_findings, 0)
        self.assertEqual(metrics.passed + metrics.failed, metrics.total_scenarios)

    def test_mixed_results_and_exact_counters(self) -> None:
        """Mixed scenario results increment individual violation counters accurately without deduplication."""
        results = [
            _make_result("SCN-PASS-1", passed=True),
            _make_result("SCN-PASS-2", passed=True),
            _make_result("SCN-FAIL-TOOL", passed=False, unsafe_tool_execution=True),
            _make_result("SCN-FAIL-APPROVAL", passed=False, approval_bypass=True),
            _make_result("SCN-FAIL-SPL", passed=False, arbitrary_query_execution=True),
            _make_result("SCN-FAIL-GUARD", passed=False, runtime_guard_bypass=True),
            _make_result("SCN-FAIL-AUDIT", passed=False, audit_leakage=True),
            _make_result("SCN-FAIL-POLICY", passed=False, policy_override=True),
            # Concurrent multi-violation scenario
            _make_result(
                "SCN-FAIL-MULTI",
                passed=False,
                unsafe_tool_execution=True,
                approval_bypass=True,
                audit_leakage=True,
            ),
        ]
        metrics = aggregate_results(results)

        self.assertEqual(metrics.total_scenarios, 9)
        self.assertEqual(metrics.passed, 2)
        self.assertEqual(metrics.failed, 7)
        self.assertAlmostEqual(metrics.pass_rate, 2 / 9, places=5)

        # Counter checks
        self.assertEqual(metrics.unsafe_tool_executions, 2)
        self.assertEqual(metrics.approval_bypasses, 2)
        self.assertEqual(metrics.arbitrary_query_executions, 1)
        self.assertEqual(metrics.runtime_guard_bypasses, 1)
        self.assertEqual(metrics.audit_leakage_findings, 2)
        self.assertEqual(metrics.policy_override_findings, 1)

        self.assertEqual(metrics.passed + metrics.failed, metrics.total_scenarios)

    def test_consistency_invariant(self) -> None:
        """Invariant: passed + failed == total_scenarios holds for any distribution."""
        results = [
            _make_result("SCN-01", passed=True),
            _make_result("SCN-02", passed=False, unsafe_tool_execution=True),
            _make_result("SCN-03", passed=True),
            _make_result("SCN-04", passed=False, policy_override=True),
        ]
        metrics = aggregate_results(results)
        self.assertEqual(metrics.passed + metrics.failed, metrics.total_scenarios)
        self.assertEqual(metrics.total_scenarios, 4)
        self.assertEqual(metrics.pass_rate, 0.5)

    def test_invalid_input_types_rejected(self) -> None:
        """Aggregator rejects non-sequence inputs or malformed items."""
        invalid_inputs = [
            None,
            {},
            "results",
            123,
            [None],
            [{"passed": True}],
            [_make_result("SCN-01"), "invalid_element"],
            [_make_result("SCN-01"), None],
        ]
        for bad_input in invalid_inputs:
            with self.subTest(bad_input=type(bad_input).__name__):
                with self.assertRaises((EvaluationMetricsError, TypeError, ValueError)):
                    aggregate_results(bad_input)  # type: ignore[arg-type]

    def test_input_sequence_not_mutated(self) -> None:
        """Aggregator does not alter or reorder input list."""
        r1 = _make_result("SCN-01", passed=True)
        r2 = _make_result("SCN-02", passed=False, unsafe_tool_execution=True)
        results = [r1, r2]

        aggregate_results(results)

        self.assertEqual(len(results), 2)
        self.assertIs(results[0], r1)
        self.assertIs(results[1], r2)


if __name__ == "__main__":
    unittest.main()
