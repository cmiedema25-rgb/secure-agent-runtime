from fastapi.testclient import TestClient

from secure_agent_runtime.api import app

client = TestClient(app)


def test_health() -> None:
    assert client.get("/healthz").json() == {"status": "ok"}


def test_session_and_execution_flow() -> None:
    session_response = client.post(
        "/v1/sessions",
        json={"capabilities": ["math.add"]},
    )
    assert session_response.status_code == 201
    session_id = session_response.json()["session_id"]

    execute_response = client.post(
        "/v1/execute",
        json={
            "session_id": session_id,
            "tool": "math.add",
            "arguments": {"a": 10, "b": 32},
        },
    )
    assert execute_response.status_code == 200
    assert execute_response.json()["result"] == 42


def test_denied_tool_returns_403() -> None:
    session_id = client.post(
        "/v1/sessions",
        json={"capabilities": ["math.add"]},
    ).json()["session_id"]

    response = client.post(
        "/v1/execute",
        json={
            "session_id": session_id,
            "tool": "text.word_count",
            "arguments": {"text": "should be denied"},
        },
    )
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "capability_denied"
