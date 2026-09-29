"""Deterministic security evaluation metrics aggregation over EvaluationResult objects."""

from dataclasses import dataclass
from typing import Any, Dict, Sequence

from evaluation.schema import EvaluationResult


class EvaluationMetricsError(ValueError):
    """Raised when evaluation metrics constraints or aggregation invariants are violated."""
    pass


@dataclass(frozen=True)
class EvaluationMetrics:
    """Immutable aggregate security metrics over evaluation results."""

    total_scenarios: int
    passed: int
    failed: int
    pass_rate: float
    unsafe_tool_executions: int
    approval_bypasses: int
    arbitrary_query_executions: int
    runtime_guard_bypasses: int
    audit_leakage_findings: int
    policy_override_findings: int

    def __post_init__(self) -> None:
        int_fields = (
            ("total_scenarios", self.total_scenarios),
            ("passed", self.passed),
            ("failed", self.failed),
            ("unsafe_tool_executions", self.unsafe_tool_executions),
            ("approval_bypasses", self.approval_bypasses),
            ("arbitrary_query_executions", self.arbitrary_query_executions),
            ("runtime_guard_bypasses", self.runtime_guard_bypasses),
            ("audit_leakage_findings", self.audit_leakage_findings),
            ("policy_override_findings", self.policy_override_findings),
        )
        for field_name, value in int_fields:
            if type(value) is not int:
                raise EvaluationMetricsError(
                    f"EvaluationMetrics.{field_name} must be exact int, got {type(value).__name__}"
                )
            if value < 0:
                raise EvaluationMetricsError(
                    f"EvaluationMetrics.{field_name} cannot be negative"
                )

        if type(self.pass_rate) is not float:
            raise EvaluationMetricsError(
                f"EvaluationMetrics.pass_rate must be exact float, got {type(self.pass_rate).__name__}"
            )
        if not (0.0 <= self.pass_rate <= 1.0):
            raise EvaluationMetricsError(
                "EvaluationMetrics.pass_rate must be between 0.0 and 1.0 inclusive"
            )

        if self.passed + self.failed != self.total_scenarios:
            raise EvaluationMetricsError(
                "EvaluationMetrics consistency invariant violated: passed + failed must equal total_scenarios"
            )

    def to_dict(self) -> Dict[str, Any]:
        """Return deterministic dictionary representation containing declared metric fields only."""
        return {
            "total_scenarios": self.total_scenarios,
            "passed": self.passed,
            "failed": self.failed,
            "pass_rate": self.pass_rate,
            "unsafe_tool_executions": self.unsafe_tool_executions,
            "approval_bypasses": self.approval_bypasses,
            "arbitrary_query_executions": self.arbitrary_query_executions,
            "runtime_guard_bypasses": self.runtime_guard_bypasses,
            "audit_leakage_findings": self.audit_leakage_findings,
            "policy_override_findings": self.policy_override_findings,
        }


def aggregate_results(
    results: Sequence[EvaluationResult],
) -> EvaluationMetrics:
    """Aggregate a sequence of EvaluationResult objects into EvaluationMetrics.

    Rules & Invariants:
      - Validates results is a concrete sequence (list or tuple).
      - Rejects non-EvaluationResult elements fail-closed.
      - Mechanically counts passed/failed and category violations without inspecting prose.
      - Increments each violation category independently (no cross-category deduplication).
      - Computes pass_rate = passed / total_scenarios when total > 0, else 0.0.
      - Enforces passed + failed == total_scenarios.
      - Does not mutate input sequence.

    Args:
        results: Sequence of EvaluationResult instances to aggregate.

    Returns:
        Immutable EvaluationMetrics object.

    Raises:
        EvaluationMetricsError: If inputs or elements violate contracts.
    """
    if not isinstance(results, (list, tuple)):
        raise EvaluationMetricsError(
            f"results must be a list or tuple, got {type(results).__name__}"
        )

    for idx, item in enumerate(results):
        if not isinstance(item, EvaluationResult):
            raise EvaluationMetricsError(
                f"results[{idx}] must be EvaluationResult, got {type(item).__name__}"
            )

    total_scenarios = len(results)
    passed = sum(1 for r in results if r.passed is True)
    failed = sum(1 for r in results if r.passed is False)

    unsafe_tool_executions = sum(1 for r in results if r.unsafe_tool_execution is True)
    approval_bypasses = sum(1 for r in results if r.approval_bypass is True)
    arbitrary_query_executions = sum(1 for r in results if r.arbitrary_query_execution is True)
    runtime_guard_bypasses = sum(1 for r in results if r.runtime_guard_bypass is True)
    audit_leakage_findings = sum(1 for r in results if r.audit_leakage is True)
    policy_override_findings = sum(1 for r in results if r.policy_override is True)

    pass_rate = float(passed / total_scenarios) if total_scenarios > 0 else 0.0

    return EvaluationMetrics(
        total_scenarios=total_scenarios,
        passed=passed,
        failed=failed,
        pass_rate=pass_rate,
        unsafe_tool_executions=unsafe_tool_executions,
        approval_bypasses=approval_bypasses,
        arbitrary_query_executions=arbitrary_query_executions,
        runtime_guard_bypasses=runtime_guard_bypasses,
        audit_leakage_findings=audit_leakage_findings,
        policy_override_findings=policy_override_findings,
    )
