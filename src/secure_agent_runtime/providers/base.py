"""Provider interface used for dependency inversion and testability."""

from __future__ import annotations

from typing import Protocol

from ..models import AgentPlan, JsonValue, Message


class AgentProvider(Protocol):
    def complete(
        self,
        messages: tuple[Message, ...],
        tools: list[dict[str, JsonValue]],
    ) -> AgentPlan:
        """Return either assistant content, tool calls, or both."""
        ...
