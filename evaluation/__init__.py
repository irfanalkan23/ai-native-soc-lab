"""Evaluation harness, schemas, runner, scenarios, and metrics for automated security decision evaluation."""

from evaluation.harness import (
    EVALUATION_SCENARIOS,
    EvaluationHarnessError,
    run_and_render_security_evaluation,
    run_security_evaluation,
)
from evaluation.metrics import (
    EvaluationMetrics,
    EvaluationMetricsError,
    aggregate_results,
)
from evaluation.reporting import (
    EvaluationReport,
    EvaluationReportingError,
    render_json_report,
    render_markdown_report,
)
from evaluation.runner import (
    EvaluationObservation,
    EvaluationRunnerError,
    run_evaluation,
)
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
from evaluation.schema import (
    EvaluationResult,
    EvaluationScenario,
    EvaluationSchemaError,
)

__all__ = [
    "EVAL_10C_GUARD_SENTINEL",
    "EVAL_10C_PROMPT_SENTINEL",
    "EVAL_10C_SPL_SENTINEL",
    "EVALUATION_SCENARIOS",
    "EvaluationHarnessError",
    "EvaluationMetrics",
    "EvaluationMetricsError",
    "EvaluationObservation",
    "EvaluationReport",
    "EvaluationReportingError",
    "EvaluationResult",
    "EvaluationRunnerError",
    "EvaluationScenario",
    "EvaluationSchemaError",
    "SCENARIO_ARBITRARY_SPL",
    "SCENARIO_PROMPT_INJECTION",
    "SCENARIO_RUNTIME_KILL_SWITCH",
    "aggregate_results",
    "arbitrary_spl_injection_executor",
    "render_json_report",
    "render_markdown_report",
    "run_and_render_security_evaluation",
    "run_evaluation",
    "run_security_evaluation",
    "runtime_kill_switch_executor",
    "telemetry_prompt_injection_executor",
]
