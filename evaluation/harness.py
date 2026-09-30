"""Deterministic end-to-end evaluation harness for security evaluations."""

from typing import Callable, Mapping, Optional, Tuple

from evaluation.metrics import aggregate_results
from evaluation.reporting import (
    EvaluationReport,
    render_json_report,
    render_markdown_report,
)
from evaluation.runner import EvaluationObservation, EvaluationRunnerError, run_evaluation
from evaluation.scenarios import (
    SCENARIO_ARBITRARY_SPL,
    SCENARIO_PROMPT_INJECTION,
    SCENARIO_RUNTIME_KILL_SWITCH,
    SCENARIO_TI_ARGUMENT_SMUGGLING,
    SCENARIO_TI_PRIVATE_IP,
    SCENARIO_TI_PROMPT_INJECTION,
    SCENARIO_TI_PROVIDER_FAILURE,
    arbitrary_spl_injection_executor,
    runtime_kill_switch_executor,
    telemetry_prompt_injection_executor,
    ti_argument_smuggling_executor,
    ti_private_ip_executor,
    ti_prompt_injection_executor,
    ti_provider_failure_executor,
)
from evaluation.schema import EvaluationScenario


class EvaluationHarnessError(ValueError):
    """Raised when evaluation harness input validation or execution invariants fail."""
    pass


# Strict, immutable scenario sequence (no dynamic discovery or reflection)
EVALUATION_SCENARIOS: Tuple[EvaluationScenario, ...] = (
    SCENARIO_PROMPT_INJECTION,
    SCENARIO_ARBITRARY_SPL,
    SCENARIO_RUNTIME_KILL_SWITCH,
    SCENARIO_TI_PRIVATE_IP,
    SCENARIO_TI_ARGUMENT_SMUGGLING,
    SCENARIO_TI_PROMPT_INJECTION,
    SCENARIO_TI_PROVIDER_FAILURE,
)

# Canonical default scenario executors
DEFAULT_EXECUTORS: Mapping[str, Callable[[EvaluationScenario], EvaluationObservation]] = {
    SCENARIO_PROMPT_INJECTION.scenario_id: telemetry_prompt_injection_executor,
    SCENARIO_ARBITRARY_SPL.scenario_id: arbitrary_spl_injection_executor,
    SCENARIO_RUNTIME_KILL_SWITCH.scenario_id: runtime_kill_switch_executor,
    SCENARIO_TI_PRIVATE_IP.scenario_id: ti_private_ip_executor,
    SCENARIO_TI_ARGUMENT_SMUGGLING.scenario_id: ti_argument_smuggling_executor,
    SCENARIO_TI_PROMPT_INJECTION.scenario_id: ti_prompt_injection_executor,
    SCENARIO_TI_PROVIDER_FAILURE.scenario_id: ti_provider_failure_executor,
}


def run_security_evaluation(
    executors: Optional[
        Mapping[str, Callable[[EvaluationScenario], EvaluationObservation]]
    ] = None,
) -> EvaluationReport:
    """Execute evaluation scenarios in deterministic order and produce an EvaluationReport.

    Args:
        executors: Optional mapping of scenario_id to executor callables.
                   When provided, overrides matching executors for the fixed 3 scenarios.
                   Unknown scenario IDs or non-callable values are rejected fail-closed.

    Returns:
        Validated, immutable EvaluationReport container.

    Raises:
        EvaluationHarnessError: On invalid override configuration or harness failure.
        EvaluationRunnerError: When a scenario execution violates runner contracts.
    """
    active_executors = dict(DEFAULT_EXECUTORS)

    if executors is not None:
        if not hasattr(executors, "items"):
            raise EvaluationHarnessError("executors must be a mapping of scenario_id to callable")

        for scenario_id, executor in executors.items():
            if scenario_id not in DEFAULT_EXECUTORS:
                raise EvaluationHarnessError(
                    f"Unknown scenario ID in executor overrides: {scenario_id}"
                )
            if not callable(executor):
                raise EvaluationHarnessError(
                    f"Executor override for scenario {scenario_id} must be a callable"
                )
            active_executors[scenario_id] = executor

    results = []
    for scenario in EVALUATION_SCENARIOS:
        executor = active_executors[scenario.scenario_id]
        try:
            result = run_evaluation(scenario, executor)
        except EvaluationRunnerError:
            raise
        except Exception as exc:
            raise EvaluationHarnessError(
                "Scenario execution failed unexpectedly in evaluation harness"
            ) from exc

        results.append(result)

    metrics = aggregate_results(results)

    return EvaluationReport(
        scenarios=EVALUATION_SCENARIOS,
        results=tuple(results),
        metrics=metrics,
    )


def run_and_render_security_evaluation(
    executors: Optional[
        Mapping[str, Callable[[EvaluationScenario], EvaluationObservation]]
    ] = None,
) -> Tuple[str, str]:
    """Execute evaluation harness and render deterministic JSON and Markdown reports.

    Args:
        executors: Optional mapping to override scenario executors.

    Returns:
        Tuple of (json_report_string, markdown_report_string).
    """
    report = run_security_evaluation(executors=executors)
    json_text = render_json_report(report)
    markdown_text = render_markdown_report(report)
    return json_text, markdown_text
