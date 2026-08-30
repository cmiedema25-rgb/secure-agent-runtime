"""Policy configuration loading with safe defaults and validation."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class PolicyConfig:
    policy_version: str = "1.0"
    review_score: int = 35
    block_score: int = 70
    max_input_chars: int = 12000
    max_messages: int = 32
    block_critical_findings: bool = True
    block_encoded_injection: bool = True
    max_tool_rounds: int = 3
    max_tool_calls_per_round: int = 4
    fail_closed: bool = True
    allowed_tools: tuple[str, ...] = ("calculator", "document_search")
    review_required_tools: tuple[str, ...] = ()
    require_https: bool = True
    allowed_egress_hosts: tuple[str, ...] = ("api.openai.com",)
    block_output_secrets: bool = True
    block_instruction_leakage: bool = True

    @classmethod
    def load(cls, path: str | Path) -> PolicyConfig:
        with Path(path).open("rb") as handle:
            raw = tomllib.load(handle)
        return cls.from_dict(raw)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> PolicyConfig:
        thresholds = raw.get("thresholds", {})
        input_config = raw.get("input", {})
        runtime = raw.get("runtime", {})
        tools = raw.get("tools", {})
        egress = raw.get("egress", {})
        output = raw.get("output", {})
        config = cls(
            policy_version=str(raw.get("policy_version", "1.0")),
            review_score=int(thresholds.get("review_score", 35)),
            block_score=int(thresholds.get("block_score", 70)),
            max_input_chars=int(input_config.get("max_chars", 12000)),
            max_messages=int(input_config.get("max_messages", 32)),
            block_critical_findings=bool(input_config.get("block_critical_findings", True)),
            block_encoded_injection=bool(input_config.get("block_encoded_injection", True)),
            max_tool_rounds=int(runtime.get("max_tool_rounds", 3)),
            max_tool_calls_per_round=int(runtime.get("max_tool_calls_per_round", 4)),
            fail_closed=bool(runtime.get("fail_closed", True)),
            allowed_tools=tuple(map(str, tools.get("allowed", ["calculator", "document_search"]))),
            review_required_tools=tuple(map(str, tools.get("review_required", []))),
            require_https=bool(egress.get("require_https", True)),
            allowed_egress_hosts=tuple(map(str, egress.get("allowed_hosts", []))),
            block_output_secrets=bool(output.get("block_secrets", True)),
            block_instruction_leakage=bool(output.get("block_instruction_leakage", True)),
        )
        config.validate()
        return config

    def validate(self) -> None:
        if not 0 <= self.review_score < self.block_score <= 100:
            raise ValueError("thresholds must satisfy 0 <= review_score < block_score <= 100")
        if self.max_input_chars < 1 or self.max_messages < 1:
            raise ValueError("input limits must be positive")
        if self.max_tool_rounds < 1 or self.max_tool_calls_per_round < 1:
            raise ValueError("runtime limits must be positive")
        if len(set(self.allowed_tools)) != len(self.allowed_tools):
            raise ValueError("allowed tools must be unique")
        if not set(self.review_required_tools).issubset(self.allowed_tools):
            raise ValueError("review-required tools must also be allowed")
