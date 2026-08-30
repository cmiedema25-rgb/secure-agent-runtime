from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .engine import RuntimeDenied, RuntimeEngine
from .policy import default_policy
from .tools import build_registry

app = FastAPI(
    title="Secure Agent Runtime",
    version="0.1.0",
    description="Capability-scoped, policy-enforced tool execution for AI agents.",
)
engine = RuntimeEngine(build_registry(), default_policy())


class SessionRequest(BaseModel):
    capabilities: set[str] = Field(min_length=1, max_length=32)


class SessionResponse(BaseModel):
    session_id: str
    capabilities: list[str]


class ExecuteRequest(BaseModel):
    session_id: str = Field(min_length=1, max_length=128)
    tool: str = Field(min_length=1, max_length=128)
    arguments: dict[str, Any] = Field(default_factory=dict)


class ExecuteResponse(BaseModel):
    correlation_id: str
    tool: str
    result: Any


@app.get("/healthz")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/sessions", response_model=SessionResponse, status_code=201)
def create_session(request: SessionRequest) -> SessionResponse:
    try:
        session = engine.create_session(set(request.capabilities))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return SessionResponse(
        session_id=session.session_id,
        capabilities=sorted(session.capabilities),
    )


@app.post("/v1/execute", response_model=ExecuteResponse)
def execute(request: ExecuteRequest) -> ExecuteResponse:
    try:
        outcome = engine.execute(request.session_id, request.tool, request.arguments)
    except RuntimeDenied as exc:
        status = 404 if exc.code == "unknown_session" else 403
        raise HTTPException(status_code=status, detail={"code": exc.code}) from exc
    return ExecuteResponse(
        correlation_id=outcome.correlation_id,
        tool=outcome.tool,
        result=outcome.result,
    )


@app.get("/v1/audit/verify")
def verify_audit_chain() -> dict[str, bool | int]:
    events = engine.audit.snapshot()
    return {"valid": engine.audit.verify(), "events": len(events)}
