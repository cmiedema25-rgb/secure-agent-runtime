# Secure Agent Runtime

A policy-enforced execution layer for AI agents that need to call tools without receiving unrestricted authority.

`secure-agent-runtime` demonstrates a production-oriented pattern for running tool-using agents behind explicit capabilities, deterministic policy checks, request validation, rate limits, structured audit events, and a narrow HTTP API.

## Why this exists

Modern AI agents can plan, call APIs, read data, and trigger workflows. The dangerous architectural shortcut is to let the model directly inherit application credentials or invoke arbitrary tools. This project separates **reasoning** from **authority**:

```text
Agent / LLM
    |
    v
Runtime API
    |
    +--> Request validation
    +--> Capability resolution
    +--> Policy engine
    +--> Rate limiter
    +--> Tool registry
    +--> Executor
    +--> Structured audit log
```

The model proposes an action. The runtime decides whether that action is permitted.

## Security properties

- **Default deny**: tools are unavailable unless explicitly granted.
- **Capability scoping**: sessions receive a bounded set of tool permissions.
- **Argument constraints**: policies can restrict fields and values per tool.
- **No dynamic code execution**: tools are registered Python callables, not arbitrary shell snippets.
- **Deterministic authorization**: policy decisions are independent of model output prose.
- **Rate limits**: per-session invocation ceilings reduce runaway loops.
- **Tamper-evident audit chain**: each audit event includes the previous event hash.
- **Correlation IDs**: every execution is traceable across request, decision, and result.
- **Secret minimization**: the agent never needs direct access to provider credentials.

## Repository layout

```text
secure-agent-runtime/
├── src/secure_agent_runtime/
│   ├── api.py            # FastAPI service
│   ├── audit.py          # hash-chained structured audit log
│   ├── capabilities.py   # capability and session models
│   ├── engine.py         # authorization + execution orchestration
│   ├── policy.py         # deterministic policy evaluator
│   ├── rate_limit.py     # in-memory fixed-window limiter
│   ├── registry.py       # explicit tool registry
│   └── tools.py          # safe example tools
├── docs/architecture.md  # trust boundaries and threat model
├── examples/demo_client.py
├── policies/default.json
├── tests/
├── .github/workflows/ci.yml
├── Dockerfile
└── pyproject.toml
```

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
pytest
uvicorn secure_agent_runtime.api:app --reload
```

Open `http://127.0.0.1:8000/docs` for the generated OpenAPI UI.

In a second terminal, run the demonstration client:

```bash
python examples/demo_client.py
```

The demo creates a constrained session, executes an allowed tool, deliberately requests a capability that was not granted, verifies the request is denied, and checks the audit-chain integrity endpoint.

## Example request

Create a constrained session:

```bash
curl -X POST http://127.0.0.1:8000/v1/sessions \
  -H 'content-type: application/json' \
  -d '{"capabilities":["math.add","text.summarize"]}'
```

Then execute a permitted tool:

```bash
curl -X POST http://127.0.0.1:8000/v1/execute \
  -H 'content-type: application/json' \
  -d '{"session_id":"<session-id>","tool":"math.add","arguments":{"a":7,"b":5}}'
```

A request for a tool outside the session capability set is denied before the tool handler runs.

## Threat model

The runtime assumes the agent or model may be unreliable, prompt-injected, or adversarially influenced. It therefore treats model-generated tool calls as untrusted input. The runtime is designed to contain authority at the application boundary.

The full trust-boundary analysis and production extension model are documented in [`docs/architecture.md`](docs/architecture.md).

This example does **not** claim to be a complete sandbox for hostile native code. Production deployments should place high-risk tools in separate processes or isolated workloads, use durable audit storage, external identity, distributed rate limiting, and a secrets manager.

## Skills demonstrated

- AI Agents & Assistants
- AI Integration & APIs
- Workflow Automation
- Prompt/agent safety architecture
- Python backend engineering
- FastAPI + Pydantic
- Policy enforcement and capability-based security
- Threat modeling and secure system design
- Automated testing and CI/CD
- Containerized deployment

## License

MIT
