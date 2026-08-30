"""Deterministic offline provider for demos, tests, and CI."""

from __future__ import annotations

import re

from ..models import AgentPlan, JsonValue, Message, ToolCall

_CALCULATION = re.compile(
    r"(?:calculate|compute|what is)\s+([0-9().+\-*/% ]{1,160})\??",
    re.IGNORECASE,
)
_SEARCH = re.compile(r"(?:search|find|look up)\s+(?:for\s+)?(.{1,300})", re.IGNORECASE)


class DeterministicProvider:
    """A small planner that makes repository behavior reproducible without an API key."""

    def complete(
        self,
        messages: tuple[Message, ...],
        tools: list[dict[str, JsonValue]],
    ) -> AgentPlan:
        if messages and messages[-1].role == "tool":
            outputs = [message.content for message in messages if message.role == "tool"]
            return AgentPlan(content=f"Tool result: {outputs[-1]}")

        user_messages = [message.content for message in messages if message.role == "user"]
        if not user_messages:
            return AgentPlan(content="No user message was supplied.")
        latest = user_messages[-1].strip()

        calculation = _CALCULATION.fullmatch(latest)
        if calculation is not None:
            return AgentPlan(
                tool_calls=(
                    ToolCall.create(
                        "calculator",
                        {"expression": calculation.group(1).strip()},
                    ),
                )
            )

        search = _SEARCH.fullmatch(latest)
        if search is not None:
            return AgentPlan(
                tool_calls=(
                    ToolCall.create(
                        "document_search",
                        {"query": search.group(1).strip(), "limit": 3},
                    ),
                )
            )

        return AgentPlan(
            content=(
                "Offline provider accepted the request. Configure an OpenAI-compatible "
                "provider for generative responses."
            )
        )


class ScriptedProvider:
    """Test double that returns preconfigured plans in order."""

    def __init__(self, plans: list[AgentPlan]) -> None:
        self._plans = list(plans)
        self.calls = 0

    def complete(
        self,
        messages: tuple[Message, ...],
        tools: list[dict[str, JsonValue]],
    ) -> AgentPlan:
        del messages, tools
        self.calls += 1
        if not self._plans:
            raise RuntimeError("scripted provider has no remaining plans")
        return self._plans.pop(0)
