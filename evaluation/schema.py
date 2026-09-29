"""Evaluation scenario and result schemas for repeatable agent security evaluations."""

from dataclasses import dataclass
from typing import Any, Dict


class EvaluationSchemaError(ValueError):
    """Raised when an evaluation scenario or result violates schema invariants."""
    pass


@dataclass(frozen=True)
class EvaluationScenario:
    """Immutable scenario specification for agent-security evaluation cases."""

    scenario_id: str
    name: str
    category: str
    description: str
    expected_control: str
    expected_outcome: str

    def __post_init__(self) -> None:
        string_fields = (
            ("scenario_id", self.scenario_id),
            ("name", self.name),
            ("category", self.category),
            ("description", self.description),
            ("expected_control", self.expected_control),
            ("expected_outcome", self.expected_outcome),
        )
        for field_name, value in string_fields:
            if type(value) is not str:
                raise EvaluationSchemaError(
                    f"EvaluationScenario.{field_name} must be exact str, got {type(value).__name__}"
                )
            if not value.strip():
                raise EvaluationSchemaError(
                    f"EvaluationScenario.{field_name} cannot be empty or whitespace-only"
                )

        if any(c.isspace() for c in self.scenario_id):
            raise EvaluationSchemaError(
                f"EvaluationScenario.scenario_id must be machine-readable and contain no whitespace: {self.scenario_id!r}"
            )

    def to_dict(self) -> Dict[str, Any]:
        """Return deterministic dictionary representation containing declared fields only."""
        return {
            "scenario_id": self.scenario_id,
            "name": self.name,
            "category": self.category,
            "description": self.description,
            "expected_control": self.expected_control,
            "expected_outcome": self.expected_outcome,
        }


@dataclass(frozen=True)
class EvaluationResult:
    """Immutable evaluation result capturing security boundary invariants and outcomes."""

    scenario_id: str
    passed: bool
    actual_outcome: str
    unsafe_tool_execution: bool
    approval_bypass: bool
    arbitrary_query_execution: bool
    runtime_guard_bypass: bool
    audit_leakage: bool
    policy_override: bool
    detail_code: str

    def __post_init__(self) -> None:
        string_fields = (
            ("scenario_id", self.scenario_id),
            ("actual_outcome", self.actual_outcome),
            ("detail_code", self.detail_code),
        )
        for field_name, value in string_fields:
            if type(value) is not str:
                raise EvaluationSchemaError(
                    f"EvaluationResult.{field_name} must be exact str, got {type(value).__name__}"
                )
            if not value.strip():
                raise EvaluationSchemaError(
                    f"EvaluationResult.{field_name} cannot be empty or whitespace-only"
                )

        bool_fields = (
            ("passed", self.passed),
            ("unsafe_tool_execution", self.unsafe_tool_execution),
            ("approval_bypass", self.approval_bypass),
            ("arbitrary_query_execution", self.arbitrary_query_execution),
            ("runtime_guard_bypass", self.runtime_guard_bypass),
            ("audit_leakage", self.audit_leakage),
            ("policy_override", self.policy_override),
        )
        for field_name, value in bool_fields:
            if type(value) is not bool:
                raise EvaluationSchemaError(
                    f"EvaluationResult.{field_name} must be exact bool without coercion, got {type(value).__name__}"
                )

    def to_dict(self) -> Dict[str, Any]:
        """Return deterministic dictionary representation containing declared fields only."""
        return {
            "scenario_id": self.scenario_id,
            "passed": self.passed,
            "actual_outcome": self.actual_outcome,
            "unsafe_tool_execution": self.unsafe_tool_execution,
            "approval_bypass": self.approval_bypass,
            "arbitrary_query_execution": self.arbitrary_query_execution,
            "runtime_guard_bypass": self.runtime_guard_bypass,
            "audit_leakage": self.audit_leakage,
            "policy_override": self.policy_override,
            "detail_code": self.detail_code,
        }
