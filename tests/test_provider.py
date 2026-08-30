from __future__ import annotations

import unittest

from secure_agent_runtime.models import Message
from secure_agent_runtime.providers.mock import DeterministicProvider
from secure_agent_runtime.providers.openai_compatible import (
    OpenAICompatibleProvider,
    ProviderError,
)


class ProviderTests(unittest.TestCase):
    def test_offline_provider_plans_calculator_call(self) -> None:
        plan = DeterministicProvider().complete(
            (Message(role="user", content="Calculate 6 * 7"),),
            [],
        )
        self.assertEqual(plan.tool_calls[0].name, "calculator")

    def test_offline_provider_plans_document_search(self) -> None:
        plan = DeterministicProvider().complete(
            (Message(role="user", content="Search for audit integrity"),),
            [],
        )
        self.assertEqual(plan.tool_calls[0].name, "document_search")

    def test_provider_rejects_non_https_base_url(self) -> None:
        with self.assertRaises(ValueError):
            OpenAICompatibleProvider(
                api_key="key",
                model="model",
                base_url="http://api.openai.com/v1",
            )

    def test_provider_rejects_unlisted_host(self) -> None:
        with self.assertRaises(ValueError):
            OpenAICompatibleProvider(
                api_key="key",
                model="model",
                base_url="https://evil.example/v1",
            )

    def test_response_parser_handles_tool_call(self) -> None:
        plan = OpenAICompatibleProvider._parse_response(
            {
                "choices": [
                    {
                        "message": {
                            "content": None,
                            "tool_calls": [
                                {
                                    "id": "call_1",
                                    "function": {
                                        "name": "calculator",
                                        "arguments": '{"expression": "2+2"}',
                                    },
                                }
                            ],
                        }
                    }
                ]
            }
        )
        self.assertEqual(plan.tool_calls[0].arguments["expression"], "2+2")

    def test_response_parser_rejects_invalid_shape(self) -> None:
        with self.assertRaises(ProviderError):
            OpenAICompatibleProvider._parse_response({})


if __name__ == "__main__":
    unittest.main()
