"""Typed domain models shared by the runtime, policy engine, and providers."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, TypeAlias
from uuid import uuid4

JsonValue: TypeAlias = None | bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"]


class Decision(StrEnum):
    ALLOW = "allow"
    REVIEW = "review"
    BLOCK = "block"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class Finding:
    detector: str
    category: str
    severity: Severity
    score: int
    evidence: str
    source_view: str = "normalized"

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "detector": self.detector,
            "category": self.category,
            "severity": self.severity.value,
            "score": self.score,
            "evidence": self.evidence,
            "source_view": self.source_view,
        }


@dataclass(frozen=True, slots=True)
class Message:
    role: str
    content: str
    name: str | None = None
    tool_call_id: str | None = None
    tool_calls: tuple[ToolCall, ...] = ()

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> Message:
        role = str(value.get("role", "")).strip()
        content = str(value.get("content", ""))
        if role not in {"system", "developer", "user", "assistant", "tool"}:
            raise ValueError(f"unsupported message role: {role!r}")
        parsed_calls: list[ToolCall] = []
        for item in value.get("tool_calls") or []:
            function = item.get("function", {})
            arguments = function.get("arguments", {})
            if isinstance(arguments, str):
                arguments = json.loads(arguments)
            if not isinstance(arguments, dict):
                raise ValueError("tool call arguments must be an object")
            parsed_calls.append(
                ToolCall(
                    id=str(item.get("id", "")),
                    name=str(function.get("name", "")),
                    arguments=arguments,
                )
            )
        return cls(
            role=role,
            content=content,
            name=str(value["name"]) if value.get("name") is not None else None,
            tool_call_id=(
                str(value["tool_call_id"]) if value.get("tool_call_id") is not None else None
            ),
            tool_calls=tuple(parsed_calls),
        )

    def to_dict(self) -> dict[str, JsonValue]:
        data: dict[str, JsonValue] = {"role": self.role, "content": self.content}
        if self.name is not None:
            data["name"] = self.name
        if self.tool_call_id is not None:
            data["tool_call_id"] = self.tool_call_id
        if self.tool_calls:
            data["tool_calls"] = [
                {
                    "id": call.id,
                    "type": "function",
                    "function": {
                        "name": call.name,
                        "arguments": json.dumps(call.arguments, ensure_ascii=False),
                    },
                }
                for call in self.tool_calls
            ]
        return data


@dataclass(frozen=True, slots=True)
class ToolCall:
    id: str
    name: str
    arguments: dict[str, JsonValue]

    @classmethod
    def create(cls, name: str, arguments: dict[str, JsonValue]) -> ToolCall:
        return cls(id=f"call_{uuid4().hex[:12]}", name=name, arguments=arguments)

    def to_dict(self) -> dict[str, JsonValue]:
        return {"id": self.id, "name": self.name, "arguments": self.arguments}


@dataclass(frozen=True, slots=True)
class AgentPlan:
    content: str = ""
    tool_calls: tuple[ToolCall, ...] = ()


@dataclass(frozen=True, slots=True)
class PolicyResult:
    decision: Decision
    score: int
    reasons: tuple[str, ...] = ()
    findings: tuple[Finding, ...] = ()

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "decision": self.decision.value,
            "score": self.score,
            "reasons": list(self.reasons),
            "findings": [finding.to_dict() for finding in self.findings],
        }


@dataclass(frozen=True, slots=True)
class RuntimeRequest:
    messages: tuple[Message, ...]
    request_id: str = field(default_factory=lambda: f"req_{uuid4().hex}")
    metadata: dict[str, JsonValue] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> RuntimeRequest:
        raw_messages = value.get("messages")
        if not isinstance(raw_messages, list) or not raw_messages:
            raise ValueError("messages must be a non-empty array")
        request_id = str(value.get("request_id") or f"req_{uuid4().hex}")
        metadata = value.get("metadata", {})
        if not isinstance(metadata, dict):
            raise ValueError("metadata must be an object")
        return cls(
            messages=tuple(Message.from_dict(item) for item in raw_messages),
            request_id=request_id,
            metadata=metadata,
        )


@dataclass(frozen=True, slots=True)
class ToolExecution:
    call: ToolCall
    decision: Decision
    output: JsonValue = None
    error: str | None = None

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "call": self.call.to_dict(),
            "decision": self.decision.value,
            "output": self.output,
            "error": self.error,
        }


@dataclass(frozen=True, slots=True)
class RuntimeResponse:
    request_id: str
    decision: Decision
    content: str
    risk_score: int
    reasons: tuple[str, ...] = ()
    findings: tuple[Finding, ...] = ()
    tool_executions: tuple[ToolExecution, ...] = ()

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "request_id": self.request_id,
            "decision": self.decision.value,
            "content": self.content,
            "risk_score": self.risk_score,
            "reasons": list(self.reasons),
            "findings": [finding.to_dict() for finding in self.findings],
            "tool_executions": [execution.to_dict() for execution in self.tool_executions],
        }
