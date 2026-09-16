"""Deterministic fake / mock model for orchestration testing.

This module exists solely for unit tests and local development.
It must NEVER be connected to a live LLM provider.

Design:
  FakeModel is pre-configured with a fixed sequence of ModelDecision objects.
  Each call to decide() returns the next decision in order.
  When the sequence is exhausted, FakeModelExhaustedError is raised.
  No network, no randomness, no dynamic imports, no execution of untrusted content.
"""

from typing import List

from investigator.model import ModelDecision, ModelRequest


class FakeModelExhaustedError(Exception):
    """Raised by FakeModel when its pre-configured decision sequence is exhausted."""
    pass


class FakeModel:
    """Deterministic test double for the model interface.

    Usage:
        decisions = [
            ModelDecision(DecisionType.TOOL_REQUEST, tool_request=...),
            ModelDecision(DecisionType.FINAL_RESULT, final_result=...),
        ]
        model = FakeModel(decisions)
        decision = model.decide(request)  # returns decisions[0], then decisions[1], etc.
    """

    def __init__(self, decisions: List[ModelDecision]) -> None:
        if not isinstance(decisions, list):
            raise TypeError(
                f"decisions must be a list, got {type(decisions).__name__}"
            )
        for i, d in enumerate(decisions):
            if not isinstance(d, ModelDecision):
                raise TypeError(
                    f"decisions[{i}] must be ModelDecision, got {type(d).__name__}"
                )
        # Defensive copy so external mutation of the list cannot alter the fake model
        self._decisions: List[ModelDecision] = list(decisions)
        self._index: int = 0

    def decide(self, request: ModelRequest) -> ModelDecision:
        """Return the next pre-configured decision.

        Args:
            request: The ModelRequest from the orchestrator (validated but not used
                     by the fake model — it always returns its preconfigured sequence).

        Returns:
            The next ModelDecision in the sequence.

        Raises:
            FakeModelExhaustedError: When the sequence is exhausted.
        """
        if self._index >= len(self._decisions):
            raise FakeModelExhaustedError(
                f"FakeModel sequence exhausted after {len(self._decisions)} decision(s). "
                f"The investigation orchestrator received more model calls than anticipated."
            )
        decision = self._decisions[self._index]
        self._index += 1
        return decision

    @property
    def decisions_remaining(self) -> int:
        """Return the number of unconsumed decisions in the sequence."""
        return max(0, len(self._decisions) - self._index)
