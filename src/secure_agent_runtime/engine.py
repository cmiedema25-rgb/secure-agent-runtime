from __future__ import annotations

from dataclasses import dataclass
from threading import Lock
from typing import Any
from uuid import uuid4

from .audit import AuditLog
from .capabilities import AgentSession
from .policy import PolicyEngine
from .rate_limit import FixedWindowRateLimiter
from .registry import ToolNotFound, ToolRegistry


class RuntimeDenied(PermissionError):
    def __init__(self, code: str, message: str | None = None) -> None:
        super().__init__(message or code)
        self.code = code


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    correlation_id: str
    tool: str
    result: Any


class RuntimeEngine:
    """Coordinates capability checks, policy evaluation, limiting, execution and audit."""

    def __init__(
        self,
        registry: ToolRegistry,
        policy: PolicyEngine,
        *,
        audit_log: AuditLog | None = None,
        rate_limiter: FixedWindowRateLimiter | None = None,
    ) -> None:
        self.registry = registry
        self.policy = policy
        self.audit = audit_log or AuditLog()
        self.rate_limiter = rate_limiter or FixedWindowRateLimiter()
        self._sessions: dict[str, AgentSession] = {}
        self._session_lock = Lock()

    def create_session(self, capabilities: set[str]) -> AgentSession:
        unknown = capabilities - self.registry.names()
        if unknown:
            raise ValueError(f"unregistered capabilities: {','.join(sorted(unknown))}")
        forbidden = capabilities - self.policy.allowed_tools
        if forbidden:
            raise ValueError(f"capabilities blocked by policy: {','.join(sorted(forbidden))}")
        session = AgentSession.create(capabilities)
        with self._session_lock:
            self._sessions[session.session_id] = session
        return session

    def execute(self, session_id: str, tool: str, arguments: dict[str, Any]) -> ExecutionResult:
        correlation_id = str(uuid4())
        with self._session_lock:
            session = self._sessions.get(session_id)

        if session is None:
            self._deny(correlation_id, session_id, tool, arguments, "unknown_session")

        assert session is not None
        if not session.permits(tool):
            self._deny(correlation_id, session_id, tool, arguments, "capability_denied")

        if not self.rate_limiter.allow(session_id):
            self._deny(correlation_id, session_id, tool, arguments, "rate_limit_exceeded")

        decision = self.policy.evaluate(tool, arguments)
        if not decision.allowed:
            self._deny(correlation_id, session_id, tool, arguments, decision.reason)

        try:
            result = self.registry.invoke(tool, arguments)
        except ToolNotFound as exc:
            self._deny(correlation_id, session_id, tool, arguments, "tool_not_registered")
            raise AssertionError("unreachable") from exc

        self.audit.append(
            correlation_id=correlation_id,
            session_id=session_id,
            tool=tool,
            decision="allowed",
            reason="allowed",
            arguments=arguments,
            result=result,
        )
        return ExecutionResult(correlation_id=correlation_id, tool=tool, result=result)

    def _deny(
        self,
        correlation_id: str,
        session_id: str,
        tool: str,
        arguments: dict[str, Any],
        reason: str,
    ) -> None:
        self.audit.append(
            correlation_id=correlation_id,
            session_id=session_id,
            tool=tool,
            decision="denied",
            reason=reason,
            arguments=arguments,
        )
        raise RuntimeDenied(reason)
