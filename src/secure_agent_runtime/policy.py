"""Central policy decision point for inputs, outputs, and tool calls."""

from __future__ import annotations

import json
import re
from urllib.parse import urlparse

from .config import PolicyConfig
from .detectors import RiskScanner
from .models import Decision, Finding, JsonValue, Message, PolicyResult, Severity, ToolCall

_SENSITIVE_PATH = re.compile(
    r"(?:^|[/\\])(?:\.env|\.ssh|\.aws|credentials|secrets?)(?:$|[/\\])",
    re.IGNORECASE,
)
_SHELL_META = re.compile(r"(?:&&|\|\||[;$\x60]|\$\(|>\s*/|<\s*/)")
_URL = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


class PolicyEngine:
    def __init__(self, config: PolicyConfig, scanner: RiskScanner | None = None) -> None:
        self.config = config
        self.scanner = scanner or RiskScanner()

    def evaluate_input(self, messages: tuple[Message, ...]) -> PolicyResult:
        if not messages:
            return PolicyResult(Decision.BLOCK, 100, ("empty message sequence",))
        if len(messages) > self.config.max_messages:
            return PolicyResult(
                Decision.BLOCK,
                100,
                (f"message count exceeds limit of {self.config.max_messages}",),
            )

        total_chars = sum(len(message.content) for message in messages)
        if total_chars > self.config.max_input_chars:
            return PolicyResult(
                Decision.BLOCK,
                100,
                (f"input exceeds {self.config.max_input_chars} characters",),
            )

        # User and tool content are untrusted. System/developer prompts are authored
        # by the application and are not classified as attacks on themselves.
        untrusted = tuple(message for message in messages if message.role in {"user", "tool"})
        findings = tuple(
            finding for message in untrusted for finding in self.scanner.scan(message.content)
        )
        return self._classify(findings)

    def evaluate_output(self, content: str) -> PolicyResult:
        findings = self.scanner.scan(content)
        relevant: list[Finding] = []
        for finding in findings:
            if finding.detector == "secret" and self.config.block_output_secrets:
                relevant.append(finding)
            elif finding.category == "prompt_extraction" and self.config.block_instruction_leakage:
                relevant.append(finding)
        if relevant:
            return PolicyResult(
                Decision.BLOCK,
                max(item.score for item in relevant),
                ("model output matched a protected-data rule",),
                tuple(relevant),
            )
        return PolicyResult(Decision.ALLOW, 0)

    def evaluate_tool_call(self, call: ToolCall) -> PolicyResult:
        if call.name not in self.config.allowed_tools:
            return PolicyResult(
                Decision.BLOCK,
                100,
                (f"tool {call.name!r} is not on the allowlist",),
            )

        serialized = json.dumps(call.arguments, sort_keys=True, ensure_ascii=False)
        findings = self.scanner.scan(serialized)
        if findings:
            classified = self._classify(findings)
            if classified.decision is not Decision.ALLOW:
                return PolicyResult(
                    Decision.BLOCK,
                    max(classified.score, 80),
                    ("tool arguments contain unsafe content", *classified.reasons),
                    classified.findings,
                )

        if _SENSITIVE_PATH.search(serialized):
            return PolicyResult(
                Decision.BLOCK,
                100,
                ("tool arguments reference a sensitive path",),
            )
        if _SHELL_META.search(serialized):
            return PolicyResult(
                Decision.BLOCK,
                90,
                ("tool arguments contain shell metacharacters",),
            )

        url_result = self._evaluate_urls(serialized)
        if url_result is not None:
            return url_result

        if call.name in self.config.review_required_tools:
            return PolicyResult(
                Decision.REVIEW,
                self.config.review_score,
                (f"tool {call.name!r} requires human approval",),
            )
        return PolicyResult(Decision.ALLOW, 0)

    def _evaluate_urls(self, text: str) -> PolicyResult | None:
        for raw_url in _URL.findall(text):
            parsed = urlparse(raw_url)
            hostname = (parsed.hostname or "").lower()
            if self.config.require_https and parsed.scheme.lower() != "https":
                return PolicyResult(
                    Decision.BLOCK,
                    90,
                    ("non-HTTPS egress is prohibited",),
                )
            if not self._host_allowed(hostname):
                return PolicyResult(
                    Decision.BLOCK,
                    90,
                    (f"egress host {hostname!r} is not allowed",),
                )
        return None

    def _host_allowed(self, hostname: str) -> bool:
        for allowed in self.config.allowed_egress_hosts:
            allowed = allowed.lower().lstrip(".")
            if hostname == allowed or hostname.endswith("." + allowed):
                return True
        return False

    def _classify(self, findings: tuple[Finding, ...]) -> PolicyResult:
        if not findings:
            return PolicyResult(Decision.ALLOW, 0)
        score = self.scanner.aggregate_score(findings)
        critical = any(finding.severity is Severity.CRITICAL for finding in findings)
        encoded = any(finding.source_view.startswith("base64:") for finding in findings)
        reasons: list[str] = []
        if critical and self.config.block_critical_findings:
            reasons.append("critical security finding")
        if encoded and self.config.block_encoded_injection:
            reasons.append("encoded injection payload")

        if reasons or score >= self.config.block_score:
            decision = Decision.BLOCK
        elif score >= self.config.review_score:
            decision = Decision.REVIEW
            reasons.append("risk score requires human review")
        else:
            decision = Decision.ALLOW
        if not reasons and decision is Decision.BLOCK:
            reasons.append("risk score exceeds block threshold")
        return PolicyResult(decision, score, tuple(reasons), findings)


def redact_json(value: JsonValue) -> JsonValue:
    """Redact secret-like fields before data enters an audit event."""
    if isinstance(value, dict):
        redacted: dict[str, JsonValue] = {}
        for key, item in value.items():
            if re.search(r"(?:password|secret|token|api.?key|authorization)", key, re.IGNORECASE):
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = redact_json(item)
        return redacted
    if isinstance(value, list):
        return [redact_json(item) for item in value]
    return value
