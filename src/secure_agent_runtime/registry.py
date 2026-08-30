from __future__ import annotations

from collections.abc import Callable
from typing import Any

Tool = Callable[..., Any]


class ToolNotFound(KeyError):
    pass


class ToolRegistry:
    """Explicit registry. Nothing is executable unless registered here."""

    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(self, name: str, handler: Tool) -> None:
        if not name or name.startswith("_"):
            raise ValueError("invalid tool name")
        if name in self._tools:
            raise ValueError(f"tool already registered: {name}")
        self._tools[name] = handler

    def names(self) -> frozenset[str]:
        return frozenset(self._tools)

    def invoke(self, name: str, arguments: dict[str, Any]) -> Any:
        try:
            handler = self._tools[name]
        except KeyError as exc:
            raise ToolNotFound(name) from exc
        return handler(**arguments)
