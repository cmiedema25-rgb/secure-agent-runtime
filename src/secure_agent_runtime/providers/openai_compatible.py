"""Standard-library adapter for OpenAI-compatible chat-completions APIs."""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from ..models import AgentPlan, JsonValue, Message, ToolCall


class ProviderError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class OpenAICompatibleProvider:
    api_key: str
    model: str
    base_url: str = "https://api.openai.com/v1"
    timeout_seconds: float = 30.0
    allowed_hosts: tuple[str, ...] = ("api.openai.com",)

    def __post_init__(self) -> None:
        if not self.api_key:
            raise ValueError("api_key must not be empty")
        parsed = urlparse(self.base_url)
        if parsed.scheme != "https":
            raise ValueError("provider base URL must use HTTPS")
        hostname = (parsed.hostname or "").lower()
        if not any(
            hostname == allowed or hostname.endswith("." + allowed)
            for allowed in self.allowed_hosts
        ):
            raise ValueError(f"provider host {hostname!r} is not allowed")

    def complete(
        self,
        messages: tuple[Message, ...],
        tools: list[dict[str, JsonValue]],
    ) -> AgentPlan:
        endpoint = self.base_url.rstrip("/") + "/chat/completions"
        body: dict[str, Any] = {
            "model": self.model,
            "messages": [message.to_dict() for message in messages],
            "temperature": 0,
        }
        if tools:
            body["tools"] = tools
            body["tool_choice"] = "auto"
        # The constructor rejects non-HTTPS and non-allowlisted base URLs.
        request = urllib.request.Request(  # noqa: S310
            endpoint,
            data=json.dumps(body).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "User-Agent": "secure-agent-runtime/1.0",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(  # noqa: S310
                request,
                timeout=self.timeout_seconds,
                context=ssl.create_default_context(),
            ) as response:
                if response.status != 200:
                    raise ProviderError(f"provider returned HTTP {response.status}")
                payload = json.loads(response.read())
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise ProviderError("provider request failed") from exc
        return self._parse_response(payload)

    @staticmethod
    def _parse_response(payload: dict[str, Any]) -> AgentPlan:
        try:
            message = payload["choices"][0]["message"]
        except (KeyError, IndexError, TypeError) as exc:
            raise ProviderError("provider response is missing choices[0].message") from exc
        content = message.get("content") or ""
        if not isinstance(content, str):
            raise ProviderError("provider content must be a string or null")
        calls: list[ToolCall] = []
        for item in message.get("tool_calls") or []:
            try:
                function = item["function"]
                arguments = json.loads(function["arguments"])
                if not isinstance(arguments, dict):
                    raise TypeError
                calls.append(
                    ToolCall(
                        id=str(item["id"]),
                        name=str(function["name"]),
                        arguments=arguments,
                    )
                )
            except (KeyError, TypeError, json.JSONDecodeError) as exc:
                raise ProviderError("provider returned an invalid tool call") from exc
        return AgentPlan(content=content, tool_calls=tuple(calls))
