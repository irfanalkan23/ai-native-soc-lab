"""Evaluation harness, schemas, and metrics for automated security decision evaluation."""

from evaluation.runner import (
    EvaluationObservation,
    EvaluationRunnerError,
    run_evaluation,
)
from evaluation.schema import (
    EvaluationResult,
    EvaluationScenario,
    EvaluationSchemaError,
)

__all__ = [
    "EvaluationObservation",
    "EvaluationResult",
    "EvaluationRunnerError",
    "EvaluationScenario",
    "EvaluationSchemaError",
    "run_evaluation",
]
