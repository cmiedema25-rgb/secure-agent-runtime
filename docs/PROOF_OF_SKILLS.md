# Proof of Skills

This document maps each claimed skill to inspectable implementation evidence.
A reviewer can verify the repository without an external model account.

## AI Safety & Red Teaming

Evidence:

- src/secure_agent_runtime/detectors.py implements explainable attack and
  secret detectors.
- src/secure_agent_runtime/normalization.py handles Unicode and bounded Base64
  analysis views.
- src/secure_agent_runtime/policy.py centralizes allow, review, and block
  decisions.
- evals/attack_corpus.jsonl contains malicious and benign regression cases.
- tests/test_runtime.py exercises provider output leakage, indirect injection,
  unauthorized tools, malformed plans, and fail-closed behavior.
- docs/THREAT_MODEL.md states assets, adversaries, trust boundaries,
  mitigations, assumptions, and residual risk.

Verification:

~~~bash
secure-agent evaluate --report evidence/evaluation-report.json
~~~

## Python

Evidence:

- typed dataclasses and enums in models.py;
- dependency inversion through the AgentProvider protocol;
- bounded AST interpretation without eval in tools.py;
- thread-safe HMAC audit appends in audit.py;
- packaging and console entry point in pyproject.toml;
- strict static type checking and reproducible lint configuration;
- 83 standard-library unit and integration tests.

Verification:

~~~bash
python -m compileall -q src tests examples
mypy src/secure_agent_runtime
python -m unittest discover -s tests -v
~~~

## AI Agents & Assistants

Evidence:

- runtime.py implements provider planning, capability authorization, bounded
  tool rounds, execution, tool-result screening, and final output policy.
- providers/mock.py supplies deterministic offline planning.
- providers/openai_compatible.py supplies a real chat-completions adapter.
- tools.py defines JSON schemas and capability-limited handlers.

The important design choice is that the agent can propose actions but cannot
approve them.

## AI Integration & APIs

Evidence:

- api.py implements authenticated JSON routes, input-size enforcement,
  security headers, stable error responses, and audit verification.
- openai_compatible.py validates HTTPS and an egress allowlist before sending a
  provider request.
- tests/test_api.py starts a real local server and tests authentication,
  evaluation, execution, errors, and audit verification over HTTP.
- Dockerfile and compose.yaml provide a non-root, capability-dropped,
  read-only container deployment.

## Prompt Engineering

Evidence:

- prompts.py contains a concise versioned system contract.
- The contract defines instruction priority and treats quoted, retrieved,
  encoded, and tool-returned instructions as untrusted data.
- Runtime audit events include the prompt version and SHA-256 fingerprint.
- docs/PROMPT_ENGINEERING.md documents rationale, separation of duties, and
  the prompt-change procedure.

## Reproducible reviewer path

~~~bash
git clone https://github.com/cmiedema25-rgb/secure-agent-runtime.git
cd secure-agent-runtime
python -m venv .venv
python -m pip install -e '.[dev]'
make verify
~~~

Expected retained baseline:

| Check | Expected |
| --- | ---: |
| Tests | 83 passed |
| Corpus cases | 34 |
| Attack-stop rate | 100% on 22 included attack cases |
| Benign-allow rate | 100% on 12 included benign cases |
| Exact expected decisions | 100% on the included corpus |

The percentages apply only to this curated regression corpus and are not a
claim of universal prompt-injection protection.

## Suggested proof submission

Title: Secure Agent Runtime — AI Agent Security Gateway

Category: AI Agents & Assistants

Skills: AI Safety & Red Teaming, Python, AI Agents & Assistants, AI Integration
& APIs, Prompt Engineering

Short description:

Built a zero-dependency Python security gateway for tool-using AI agents with
prompt-injection and secret detection, centralized allow/review/block policy,
capability-limited tools, tool-output re-screening, an HTTPS-only
OpenAI-compatible adapter, an authenticated JSON API, HMAC hash-chained audit
evidence, 83 automated tests, and a reproducible 34-case red-team regression
benchmark.
