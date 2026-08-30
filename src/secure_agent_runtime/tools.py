"""Capability-limited tools exposed to the agent runtime."""

from __future__ import annotations

import ast
import math
import operator
import re
from collections.abc import Callable
from dataclasses import dataclass

from .models import JsonValue, ToolCall


class ToolError(RuntimeError):
    pass


ToolHandler = Callable[[dict[str, JsonValue]], JsonValue]


@dataclass(frozen=True, slots=True)
class ToolDefinition:
    name: str
    description: str
    input_schema: dict[str, JsonValue]
    handler: ToolHandler

    def schema(self) -> dict[str, JsonValue]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.input_schema,
            },
        }


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolDefinition] = {}

    def register(self, definition: ToolDefinition) -> None:
        if definition.name in self._tools:
            raise ValueError(f"duplicate tool: {definition.name}")
        self._tools[definition.name] = definition

    def schemas(self) -> list[dict[str, JsonValue]]:
        return [self._tools[name].schema() for name in sorted(self._tools)]

    def execute(self, call: ToolCall) -> JsonValue:
        try:
            definition = self._tools[call.name]
        except KeyError as exc:
            raise ToolError(f"unknown tool: {call.name}") from exc
        return definition.handler(call.arguments)

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._tools))


_BINARY_OPS: dict[type[ast.operator], Callable[[float, float], float]] = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
}
_UNARY_OPS: dict[type[ast.unaryop], Callable[[float], float]] = {
    ast.UAdd: operator.pos,
    ast.USub: operator.neg,
}


def safe_calculate(expression: str) -> int | float:
    if len(expression) > 160:
        raise ToolError("expression is too long")
    try:
        tree = ast.parse(expression, mode="eval")
    except SyntaxError as exc:
        raise ToolError("invalid expression") from exc

    def evaluate(node: ast.AST, depth: int = 0) -> float:
        if depth > 12:
            raise ToolError("expression is too deeply nested")
        if isinstance(node, ast.Expression):
            return evaluate(node.body, depth + 1)
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            value = float(node.value)
        elif isinstance(node, ast.BinOp) and type(node.op) in _BINARY_OPS:
            left = evaluate(node.left, depth + 1)
            right = evaluate(node.right, depth + 1)
            if isinstance(node.op, ast.Pow) and (abs(right) > 12 or abs(left) > 1_000_000):
                raise ToolError("exponentiation exceeds safety bounds")
            try:
                value = _BINARY_OPS[type(node.op)](left, right)
            except (ArithmeticError, OverflowError) as exc:
                raise ToolError("arithmetic operation failed") from exc
        elif isinstance(node, ast.UnaryOp) and type(node.op) in _UNARY_OPS:
            value = _UNARY_OPS[type(node.op)](evaluate(node.operand, depth + 1))
        else:
            raise ToolError(f"unsupported expression node: {type(node).__name__}")
        if not math.isfinite(value) or abs(value) > 1e15:
            raise ToolError("result exceeds safety bounds")
        return value

    result = evaluate(tree)
    return int(result) if result.is_integer() else result


class DocumentStore:
    """Small local retrieval tool with deterministic scoring and no egress."""

    def __init__(self, documents: dict[str, str] | None = None) -> None:
        self.documents = documents or {
            "security-model": (
                "The runtime applies least privilege, fail-closed policy decisions, "
                "prompt-injection screening, and tamper-evident audit logging."
            ),
            "operations": (
                "Human review is required whenever policy returns review. Blocked tool "
                "calls are never executed, and raw prompts are not written to audit logs."
            ),
        }

    def search(self, query: str, limit: int = 3) -> list[JsonValue]:
        if not query.strip():
            raise ToolError("query must not be empty")
        if len(query) > 300:
            raise ToolError("query is too long")
        if not 1 <= limit <= 5:
            raise ToolError("limit must be between 1 and 5")
        terms = set(re.findall(r"[a-z0-9]+", query.lower()))
        ranked: list[tuple[int, str, str]] = []
        for doc_id, text in self.documents.items():
            haystack = set(re.findall(r"[a-z0-9]+", (doc_id + " " + text).lower()))
            score = len(terms & haystack)
            if score:
                ranked.append((score, doc_id, text))
        ranked.sort(key=lambda item: (-item[0], item[1]))
        return [
            {"document_id": doc_id, "score": score, "text": text}
            for score, doc_id, text in ranked[:limit]
        ]


def default_registry() -> ToolRegistry:
    store = DocumentStore()
    registry = ToolRegistry()

    def calculator(arguments: dict[str, JsonValue]) -> JsonValue:
        expression = arguments.get("expression")
        if not isinstance(expression, str):
            raise ToolError("expression must be a string")
        return {"result": safe_calculate(expression)}

    def document_search(arguments: dict[str, JsonValue]) -> JsonValue:
        query = arguments.get("query")
        limit = arguments.get("limit", 3)
        if not isinstance(query, str):
            raise ToolError("query must be a string")
        if not isinstance(limit, int) or isinstance(limit, bool):
            raise ToolError("limit must be an integer")
        return {"results": store.search(query, limit)}

    registry.register(
        ToolDefinition(
            name="calculator",
            description="Evaluate a bounded arithmetic expression without eval or shell access.",
            input_schema={
                "type": "object",
                "properties": {"expression": {"type": "string", "maxLength": 160}},
                "required": ["expression"],
                "additionalProperties": False,
            },
            handler=calculator,
        )
    )
    registry.register(
        ToolDefinition(
            name="document_search",
            description="Search a local, non-networked security knowledge base.",
            input_schema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "maxLength": 300},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 5},
                },
                "required": ["query"],
                "additionalProperties": False,
            },
            handler=document_search,
        )
    )
    return registry
