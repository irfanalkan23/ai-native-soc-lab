"""Structured, sanitized tool output envelope for the AI investigator.

Security Guarantee:
Tool outputs are UNTRUSTED DATA. result_text must never be evaluated as code,
executed, or passed to shell interpreters. It is a bounded JSON string for
structured evidence only.
"""

from dataclasses import dataclass
from typing import Optional


class ToolResultError(ValueError):
    """Raised when ToolResultEnvelope construction fails validation."""
    pass


# Maximum length of result_text presented to the model layer.
# Prevents unbounded memory and prompt-stuffing via large tool outputs.
MAX_RESULT_TEXT_LENGTH = 4096


@dataclass(frozen=True)
class ToolResultEnvelope:
    """Immutable, sanitized wrapper for a single tool execution outcome.

    Fields:
        tool_name:   Name of the tool that was invoked.
        success:     True if the tool completed without error.
        result_text: Bounded JSON string of the tool output. Treat as UNTRUSTED DATA.
        error_code:  Sanitized short error identifier when success=False, else None.
                     Must never contain raw Python exception messages or secrets.
    """
    tool_name: str
    success: bool
    result_text: str
    error_code: Optional[str]

    def __post_init__(self) -> None:
        if type(self.tool_name) is not str or not self.tool_name.strip():
            raise ToolResultError("tool_name must be a non-empty str")
        if type(self.success) is not bool:
            raise ToolResultError(
                f"success must be bool, got {type(self.success).__name__}"
            )
        if type(self.result_text) is not str:
            raise ToolResultError(
                f"result_text must be str, got {type(self.result_text).__name__}"
            )
        if len(self.result_text) > MAX_RESULT_TEXT_LENGTH:
            raise ToolResultError(
                f"result_text length {len(self.result_text)} exceeds maximum {MAX_RESULT_TEXT_LENGTH}"
            )
        if self.error_code is not None:
            if type(self.error_code) is not str or not self.error_code.strip():
                raise ToolResultError(
                    "error_code must be None or a non-empty str"
                )
        # --- State invariants ---
        # success=True  → error_code must be absent (None)
        # success=False → error_code must be a non-empty sanitized string
        if self.success and self.error_code is not None:
            raise ToolResultError(
                "success=True envelope must have error_code=None"
            )
        if not self.success and (self.error_code is None):
            raise ToolResultError(
                "success=False envelope must have a non-empty error_code"
            )
