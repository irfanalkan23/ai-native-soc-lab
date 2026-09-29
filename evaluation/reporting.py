"""Deterministic JSON and Markdown report generation for security evaluations."""

from dataclasses import dataclass
import json
from typing import Sequence, Tuple

from evaluation.metrics import EvaluationMetrics
from evaluation.schema import EvaluationResult, EvaluationScenario


class EvaluationReportingError(ValueError):
    """Raised when evaluation report input violates consistency or schema invariants."""
    pass


@dataclass(frozen=True)
class EvaluationReport:
    """Immutable evaluation report container with consistency validation."""

    scenarios: Tuple[EvaluationScenario, ...]
    results: Tuple[EvaluationResult, ...]
    metrics: EvaluationMetrics

    def __post_init__(self) -> None:
        if type(self.scenarios) not in (list, tuple):
            raise EvaluationReportingError("scenarios must be a list or tuple of EvaluationScenario")
        if type(self.results) not in (list, tuple):
            raise EvaluationReportingError("results must be a list or tuple of EvaluationResult")
        if type(self.metrics) is not EvaluationMetrics:
            raise EvaluationReportingError("metrics must be an exact EvaluationMetrics instance")

        for item in self.scenarios:
            if type(item) is not EvaluationScenario:
                raise EvaluationReportingError("All items in scenarios must be exact EvaluationScenario instances")

        for item in self.results:
            if type(item) is not EvaluationResult:
                raise EvaluationReportingError("All items in results must be exact EvaluationResult instances")

        if len(self.scenarios) != len(self.results):
            raise EvaluationReportingError("scenarios and results must have identical length")

        if self.metrics.total_scenarios != len(self.results):
            raise EvaluationReportingError("metrics.total_scenarios must equal the number of results")

        scenario_ids = [s.scenario_id for s in self.scenarios]
        if len(set(scenario_ids)) != len(scenario_ids):
            raise EvaluationReportingError("scenario IDs must be unique across all scenarios")

        for i, (scenario, result) in enumerate(zip(self.scenarios, self.results)):
            if scenario.scenario_id != result.scenario_id:
                raise EvaluationReportingError(
                    f"Mismatched scenario_id at index {i}: scenario and result IDs must correspond in exact order"
                )

        object.__setattr__(self, "scenarios", tuple(self.scenarios))
        object.__setattr__(self, "results", tuple(self.results))


def render_json_report(report: EvaluationReport) -> str:
    """Render deterministic JSON report from an EvaluationReport container.

    Args:
        report: EvaluationReport container instance.

    Returns:
        Deterministic formatted JSON string.

    Raises:
        EvaluationReportingError: If report is not an EvaluationReport.
    """
    if type(report) is not EvaluationReport:
        raise EvaluationReportingError("Input must be an exact EvaluationReport instance")

    payload = {
        "report_type": "ai_native_soc_agent_security_evaluation",
        "scope": {
            "environment": "controlled_lab",
            "assurance_level": "tested_scenarios_only",
        },
        "metrics": report.metrics.to_dict(),
        "results": [
            {
                "scenario_id": r.scenario_id,
                "name": s.name,
                "category": s.category,
                "expected_control": s.expected_control,
                "passed": r.passed,
                "detail_code": r.detail_code,
                "unsafe_tool_execution": r.unsafe_tool_execution,
                "approval_bypass": r.approval_bypass,
                "arbitrary_query_execution": r.arbitrary_query_execution,
                "runtime_guard_bypass": r.runtime_guard_bypass,
                "audit_leakage": r.audit_leakage,
                "policy_override": r.policy_override,
            }
            for s, r in zip(report.scenarios, report.results)
        ],
    }

    return json.dumps(payload, indent=2)


def render_markdown_report(report: EvaluationReport) -> str:
    """Render deterministic Markdown report from an EvaluationReport container.

    Args:
        report: EvaluationReport container instance.

    Returns:
        Deterministic Markdown formatted string.

    Raises:
        EvaluationReportingError: If report is not an EvaluationReport.
    """
    if type(report) is not EvaluationReport:
        raise EvaluationReportingError("Input must be an exact EvaluationReport instance")

    lines = [
        "# AI SOC Agent Security Evaluation Report",
        "",
        "## Scope and Disclaimer",
        "",
        "- Validation occurred in a controlled lab environment.",
        "- Findings apply only to the tested scenarios.",
        "- Results do not constitute production assurance.",
        "- Security controls are evaluated against TESTED and SIMULATED threat vectors.",
        "",
        "## Summary Metrics",
        "",
        f"- Total Scenarios: {report.metrics.total_scenarios}",
        f"- Passed: {report.metrics.passed}",
        f"- Failed: {report.metrics.failed}",
        f"- Pass Rate: {report.metrics.pass_rate * 100:.1f}%",
        "",
        "### Security Violation Counters",
        "",
        f"- Unsafe Tool Executions: {report.metrics.unsafe_tool_executions}",
        f"- Approval Bypasses: {report.metrics.approval_bypasses}",
        f"- Arbitrary Query Executions: {report.metrics.arbitrary_query_executions}",
        f"- Runtime Guard Bypasses: {report.metrics.runtime_guard_bypasses}",
        f"- Audit Leakage Findings: {report.metrics.audit_leakage_findings}",
        f"- Policy Override Findings: {report.metrics.policy_override_findings}",
        "",
        "## Scenario Results",
        "",
        "| Scenario ID | Category | Name | Status | Detail Code |",
        "| --- | --- | --- | --- | --- |",
    ]

    for scenario, result in zip(report.scenarios, report.results):
        status_label = "PASS" if result.passed else "FAIL"
        lines.append(
            f"| {scenario.scenario_id} | {scenario.category} | {scenario.name} | {status_label} | {result.detail_code} |"
        )

    lines.append("")
    return "\n".join(lines)
