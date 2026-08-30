from __future__ import annotations

import unittest

from secure_agent_runtime.models import ToolCall
from secure_agent_runtime.tools import (
    DocumentStore,
    ToolDefinition,
    ToolError,
    ToolRegistry,
    default_registry,
    safe_calculate,
)


class ToolTests(unittest.TestCase):
    def test_basic_arithmetic(self) -> None:
        self.assertEqual(safe_calculate("144 / 12 + 7"), 19)

    def test_float_result(self) -> None:
        self.assertAlmostEqual(safe_calculate("1 / 4"), 0.25)

    def test_parentheses_and_unary(self) -> None:
        self.assertEqual(safe_calculate("-(2 + 3) * 4"), -20)

    def test_function_call_is_rejected(self) -> None:
        with self.assertRaises(ToolError):
            safe_calculate("__import__('os').system('id')")

    def test_large_exponent_is_rejected(self) -> None:
        with self.assertRaises(ToolError):
            safe_calculate("2 ** 100")

    def test_division_by_zero_is_rejected(self) -> None:
        with self.assertRaises(ToolError):
            safe_calculate("2 / 0")

    def test_overlong_expression_is_rejected(self) -> None:
        with self.assertRaises(ToolError):
            safe_calculate("1+" * 100 + "1")

    def test_document_search_returns_ranked_match(self) -> None:
        store = DocumentStore({"a": "alpha security", "b": "beta"})
        results = store.search("security")
        self.assertEqual(results[0]["document_id"], "a")

    def test_document_search_rejects_empty_query(self) -> None:
        with self.assertRaises(ToolError):
            DocumentStore().search(" ")

    def test_document_search_limit_is_bounded(self) -> None:
        with self.assertRaises(ToolError):
            DocumentStore().search("security", limit=6)

    def test_default_registry_executes_calculator(self) -> None:
        result = default_registry().execute(ToolCall.create("calculator", {"expression": "6 * 7"}))
        self.assertEqual(result, {"result": 42})

    def test_registry_rejects_unknown_tool(self) -> None:
        with self.assertRaises(ToolError):
            default_registry().execute(ToolCall.create("shell", {}))

    def test_registry_rejects_duplicate_registration(self) -> None:
        registry = ToolRegistry()
        definition = ToolDefinition(
            name="test",
            description="test",
            input_schema={"type": "object"},
            handler=lambda arguments: arguments,
        )
        registry.register(definition)
        with self.assertRaises(ValueError):
            registry.register(definition)


if __name__ == "__main__":
    unittest.main()
