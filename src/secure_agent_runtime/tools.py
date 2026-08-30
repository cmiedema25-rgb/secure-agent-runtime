from __future__ import annotations

import re

from .registry import ToolRegistry

_SENTENCE_BOUNDARY = re.compile(r"(?<=[.!?])\s+")


def math_add(a: float, b: float) -> float:
    return a + b


def word_count(text: str) -> int:
    return len(text.split())


def summarize(text: str, max_sentences: int = 3) -> str:
    """Small deterministic demo tool; real deployments can wrap an LLM provider here."""

    normalized = " ".join(text.split())
    if not normalized:
        return ""
    sentences = _SENTENCE_BOUNDARY.split(normalized)
    return " ".join(sentences[:max_sentences])


def build_registry() -> ToolRegistry:
    registry = ToolRegistry()
    registry.register("math.add", math_add)
    registry.register("text.word_count", word_count)
    registry.register("text.summarize", summarize)
    return registry
