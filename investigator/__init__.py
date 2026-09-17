"""AI Investigator scaffolding package for deterministic incident triage and tool routing."""

from investigator.approval import (
    DEFAULT_APPROVER,
    ActionAuthorizationContext,
    ApprovalDecision,
    ApprovalGateError,
    ApprovalReasonCode,
    ApprovalRecord,
    request_cli_approval,
)
from investigator.policy import (
    MAX_POLICY_REASONS,
    POLICY_REASON_CODES,
    ActionDisposition,
    PolicyContext,
    PolicyDecision,
    PolicyEngineError,
    ProposedAction,
    RiskLevel,
    RiskPolicyEngine,
)
from investigator.schemas import (
    ConfidenceLevel,
    InvestigationInput,
    InvestigationResult,
    SchemaValidationError,
)
from investigator.simulator import (
    SimulatedResponseExecutor,
    SimulationError,
    SimulationResult,
    SimulationStatus,
)
from investigator.tool_router import (
    ALLOWED_TOOLS,
    ToolExecutionError,
    ToolRouter,
    ToolValidationError,
)

__all__ = [
    "ALLOWED_TOOLS",
    "ActionAuthorizationContext",
    "ActionDisposition",
    "ApprovalDecision",
    "ApprovalGateError",
    "ApprovalReasonCode",
    "ApprovalRecord",
    "ConfidenceLevel",
    "DEFAULT_APPROVER",
    "InvestigationInput",
    "InvestigationResult",
    "MAX_POLICY_REASONS",
    "POLICY_REASON_CODES",
    "PolicyContext",
    "PolicyDecision",
    "PolicyEngineError",
    "ProposedAction",
    "RiskLevel",
    "RiskPolicyEngine",
    "SchemaValidationError",
    "SimulatedResponseExecutor",
    "SimulationError",
    "SimulationResult",
    "SimulationStatus",
    "ToolExecutionError",
    "ToolRouter",
    "ToolValidationError",
    "request_cli_approval",
]
