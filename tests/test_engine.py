import pytest

from secure_agent_runtime.engine import RuntimeDenied, RuntimeEngine
from secure_agent_runtime.policy import default_policy
from secure_agent_runtime.rate_limit import FixedWindowRateLimiter
from secure_agent_runtime.tools import build_registry


def build_engine(limit: int = 30) -> RuntimeEngine:
    return RuntimeEngine(
        build_registry(),
        default_policy(),
        rate_limiter=FixedWindowRateLimiter(limit=limit, window_seconds=60),
    )


def test_capability_is_required() -> None:
    engine = build_engine()
    session = engine.create_session({"math.add"})

    with pytest.raises(RuntimeDenied) as error:
        engine.execute(session.session_id, "text.word_count", {"text": "hello"})

    assert error.value.code == "capability_denied"


def test_permitted_tool_executes() -> None:
    engine = build_engine()
    session = engine.create_session({"math.add"})
    outcome = engine.execute(session.session_id, "math.add", {"a": 7, "b": 5})
    assert outcome.result == 12
    assert outcome.tool == "math.add"


def test_rate_limit_stops_runaway_session() -> None:
    engine = build_engine(limit=1)
    session = engine.create_session({"math.add"})
    engine.execute(session.session_id, "math.add", {"a": 1, "b": 1})

    with pytest.raises(RuntimeDenied) as error:
        engine.execute(session.session_id, "math.add", {"a": 1, "b": 1})

    assert error.value.code == "rate_limit_exceeded"
