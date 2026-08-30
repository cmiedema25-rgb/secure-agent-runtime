from secure_agent_runtime.policy import default_policy


def test_default_deny_unknown_tool() -> None:
    decision = default_policy().evaluate("shell.exec", {"command": "whoami"})
    assert decision.allowed is False
    assert decision.reason == "tool_not_allowed_by_policy"


def test_policy_rejects_out_of_range_argument() -> None:
    decision = default_policy().evaluate("math.add", {"a": 2_000_000, "b": 1})
    assert decision.allowed is False
    assert decision.reason == "above_maximum:a"


def test_policy_rejects_unexpected_argument() -> None:
    decision = default_policy().evaluate("math.add", {"a": 1, "b": 2, "debug": True})
    assert decision.allowed is False
    assert decision.reason == "unexpected_arguments:debug"
