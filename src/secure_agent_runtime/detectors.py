"""Explainable, deterministic detectors for agent-facing text."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .models import Finding, Severity
from .normalization import analysis_views, normalize_text


@dataclass(frozen=True, slots=True)
class _Rule:
    category: str
    severity: Severity
    score: int
    pattern: re.Pattern[str]


def _compile(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE | re.DOTALL)


_INJECTION_RULES = (
    _Rule(
        "instruction_override",
        Severity.CRITICAL,
        90,
        _compile(
            r"\b(?:ignore|disregard|forget|override|bypass)\b.{0,80}"
            r"\b(?:previous|prior|above|system|developer|safety|original)\b.{0,40}"
            r"\b(?:instruction|message|rule|policy|guardrail)s?\b"
        ),
    ),
    _Rule(
        "prompt_extraction",
        Severity.HIGH,
        65,
        _compile(
            r"\b(?:reveal|show|print|repeat|quote|expose|leak)\b.{0,80}"
            r"\b(?:system|developer|hidden|internal)\b.{0,40}"
            r"\b(?:prompt|instruction|message|policy|rule)s?\b"
        ),
    ),
    _Rule(
        "role_impersonation",
        Severity.HIGH,
        55,
        _compile(
            r"(?:^|\n)\s*(?:\[?system\]?|developer|assistant)\s*:"
            r"|\byou are now\b.{0,60}\b(?:unrestricted|developer mode|DAN)\b"
        ),
    ),
    _Rule(
        "jailbreak",
        Severity.HIGH,
        60,
        _compile(
            r"\b(?:jailbreak|DAN mode|developer mode|unrestricted mode)\b"
            r"|\b(?:disable|remove|evade)\b.{0,50}\b(?:safety|filter|guardrail|moderation)s?\b"
        ),
    ),
    _Rule(
        "credential_access",
        Severity.CRITICAL,
        85,
        _compile(
            r"\b(?:read|dump|print|return|send|steal|exfiltrat\w*)\b.{0,80}"
            r"\b(?:credential|secret|api[\s_-]?key|token|password|environment variable|\.env)s?\b"
        ),
    ),
    _Rule(
        "tool_abuse",
        Severity.HIGH,
        60,
        _compile(
            r"\b(?:call|invoke|run|use)\b.{0,50}\b(?:shell|terminal|exec|filesystem|http|tool)\b"
            r".{0,80}\b(?:without|bypass|ignore|secret|credential|approval|permission)\b"
        ),
    ),
    _Rule(
        "data_exfiltration",
        Severity.CRITICAL,
        85,
        _compile(
            r"\b(?:send|post|upload|forward|exfiltrat\w*)\b.{0,100}"
            r"\b(?:data|document|secret|credential|conversation|file)s?\b.{0,80}"
            r"(?:https?://|webhook|external server|attacker)"
        ),
    ),
)

_SECRET_RULES = (
    _Rule("private_key", Severity.CRITICAL, 95, _compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    _Rule("aws_access_key", Severity.CRITICAL, 95, _compile(r"\bAKIA[0-9A-Z]{16}\b")),
    _Rule("github_token", Severity.CRITICAL, 95, _compile(r"\bgh[pousr]_[A-Za-z0-9]{30,255}\b")),
    _Rule("openai_key", Severity.CRITICAL, 95, _compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    _Rule(
        "assigned_secret",
        Severity.HIGH,
        70,
        _compile(
            r"\b(?:api[\s_-]?key|access[\s_-]?token|password|secret)\b\s*[:=]\s*"
            r"[\"']?[A-Za-z0-9_./+=-]{12,}"
        ),
    ),
)


def _safe_evidence(text: str, start: int, end: int, *, max_length: int = 120) -> str:
    left = max(0, start - 20)
    right = min(len(text), end + 20)
    snippet = re.sub(r"\s+", " ", text[left:right]).strip()
    for rule in _SECRET_RULES:
        snippet = rule.pattern.sub(f"[REDACTED {rule.category}]", snippet)
    if len(snippet) > max_length:
        snippet = snippet[: max_length - 1] + "…"
    return snippet


class PromptInjectionDetector:
    name = "prompt_injection"

    def scan(self, text: str) -> tuple[Finding, ...]:
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()
        for view in analysis_views(text):
            for rule in _INJECTION_RULES:
                match = rule.pattern.search(view.text)
                if match is None:
                    continue
                key = (rule.category, view.name)
                if key in seen:
                    continue
                seen.add(key)
                score = min(100, rule.score + (10 if view.name.startswith("base64:") else 0))
                findings.append(
                    Finding(
                        detector=self.name,
                        category=rule.category,
                        severity=rule.severity,
                        score=score,
                        evidence=_safe_evidence(view.text, match.start(), match.end()),
                        source_view=view.name,
                    )
                )
        return tuple(findings)


class SecretDetector:
    name = "secret"

    def scan(self, text: str) -> tuple[Finding, ...]:
        normalized = normalize_text(text)
        findings: list[Finding] = []
        for rule in _SECRET_RULES:
            match = rule.pattern.search(normalized)
            if match is None:
                continue
            findings.append(
                Finding(
                    detector=self.name,
                    category=rule.category,
                    severity=rule.severity,
                    score=rule.score,
                    evidence=f"[REDACTED {rule.category}]",
                    source_view="normalized",
                )
            )
        return tuple(findings)


class RiskScanner:
    """Combine independent detectors while returning stable, explainable results."""

    def __init__(self) -> None:
        self._detectors = (PromptInjectionDetector(), SecretDetector())

    def scan(self, text: str) -> tuple[Finding, ...]:
        findings = [finding for detector in self._detectors for finding in detector.scan(text)]
        return tuple(
            sorted(
                findings,
                key=lambda item: (-item.score, item.detector, item.category, item.source_view),
            )
        )

    @staticmethod
    def aggregate_score(findings: tuple[Finding, ...]) -> int:
        if not findings:
            return 0
        scores = sorted((finding.score for finding in findings), reverse=True)
        return min(100, scores[0] + min(10, 3 * (len(scores) - 1)))
