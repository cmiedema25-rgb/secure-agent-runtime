from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    allowed: bool
    reason: str


class PolicyEngine:
    """Deterministic, default-deny policy evaluator for tool arguments."""

    def __init__(self, rules: dict[str, dict[str, Any]]) -> None:
        self._rules = rules

    @property
    def allowed_tools(self) -> frozenset[str]:
        return frozenset(self._rules)

    def evaluate(self, tool_name: str, arguments: dict[str, Any]) -> PolicyDecision:
        rule = self._rules.get(tool_name)
        if rule is None:
            return PolicyDecision(False, "tool_not_allowed_by_policy")

        argument_rules = rule.get("arguments", {})
        required = set(rule.get("required", []))
        supplied = set(arguments)

        missing = required - supplied
        if missing:
            return PolicyDecision(False, f"missing_required:{','.join(sorted(missing))}")

        unexpected = supplied - set(argument_rules)
        if unexpected:
            return PolicyDecision(False, f"unexpected_arguments:{','.join(sorted(unexpected))}")

        for name, value in arguments.items():
            failure = self._validate_value(name, value, argument_rules[name])
            if failure is not None:
                return PolicyDecision(False, failure)

        return PolicyDecision(True, "allowed")

    @staticmethod
    def _validate_value(name: str, value: Any, spec: dict[str, Any]) -> str | None:
        expected = spec.get("type")
        type_ok = {
            "string": isinstance(value, str),
            "integer": isinstance(value, int) and not isinstance(value, bool),
            "number": isinstance(value, (int, float)) and not isinstance(value, bool),
            "boolean": isinstance(value, bool),
        }.get(expected, False)
        if not type_ok:
            return f"invalid_type:{name}"

        if isinstance(value, str):
            if "max_length" in spec and len(value) > int(spec["max_length"]):
                return f"max_length_exceeded:{name}"
            if "allowed_values" in spec and value not in spec["allowed_values"]:
                return f"value_not_allowed:{name}"

        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if "min" in spec and value < spec["min"]:
                return f"below_minimum:{name}"
            if "max" in spec and value > spec["max"]:
                return f"above_maximum:{name}"

        return None


def default_policy() -> PolicyEngine:
    return PolicyEngine(
        {
            "math.add": {
                "required": ["a", "b"],
                "arguments": {
                    "a": {"type": "number", "min": -1_000_000, "max": 1_000_000},
                    "b": {"type": "number", "min": -1_000_000, "max": 1_000_000},
                },
            },
            "text.word_count": {
                "required": ["text"],
                "arguments": {"text": {"type": "string", "max_length": 10_000}},
            },
            "text.summarize": {
                "required": ["text"],
                "arguments": {
                    "text": {"type": "string", "max_length": 4_000},
                    "max_sentences": {"type": "integer", "min": 1, "max": 5},
                },
            },
        }
    )
