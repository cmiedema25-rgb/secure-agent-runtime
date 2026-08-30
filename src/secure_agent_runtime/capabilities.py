from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import uuid4


@dataclass(frozen=True, slots=True)
class AgentSession:
    """Bounded authority granted to one agent execution session."""

    session_id: str
    capabilities: frozenset[str]
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @classmethod
    def create(cls, capabilities: set[str] | frozenset[str]) -> AgentSession:
        return cls(session_id=str(uuid4()), capabilities=frozenset(capabilities))

    def permits(self, tool_name: str) -> bool:
        return tool_name in self.capabilities
