# Verification Record

Date: 2026-08-30 UTC

Environment: CPython 3.12.13 on Linux

The verification used a newly created virtual environment and installed the
repository from its `pyproject.toml` metadata.

## Code quality

Commands:

~~~bash
ruff check .
ruff format --check .
mypy src/secure_agent_runtime
~~~

Results: all Ruff checks passed, all 40 Python files matched the formatter,
and strict mypy reported no issues in 19 source files.

## Source compilation

Command:

~~~bash
PYTHONPATH=src python -m compileall -q src tests examples
~~~

Result: passed with no syntax errors.

## Package build

The PEP 517 build backend produced
secure_agent_runtime-1.0.0-py3-none-any.whl successfully. The wheel was 32,480
bytes and included the typed-package marker and console entry point.

## Automated tests

Command:

~~~bash
PYTHONPATH=src python -m unittest discover -s tests -v
~~~

Result: 83 tests passed in 3.580 seconds.

Coverage areas include normalization, encoded-payload handling, prompt
injection, secret detection, policy thresholds, tool allowlists, egress
restrictions, safe arithmetic, retrieval bounds, provider parsing, provider
failure, tool-result injection, output leakage, HMAC audit integrity, HTTP
authentication, real local HTTP requests, error handling, and evaluation
metrics.

## Red-team regression benchmark

Command:

~~~bash
PYTHONPATH=src python -m secure_agent_runtime \
  --policy config/policy.toml \
  evaluate \
  --corpus evals/attack_corpus.jsonl \
  --report evidence/evaluation-report.json
~~~

Result:

| Metric | Result |
| --- | ---: |
| Cases | 34 |
| Attack cases | 22 |
| Benign cases | 12 |
| Attack-stop rate | 1.0000 |
| Benign-allow rate | 1.0000 |
| Exact-decision accuracy | 1.0000 |

## Manual behavior check

The offline demo executed the bounded calculator for a benign request and
returned 19. A direct instruction-override request was blocked before provider
execution with critical and high findings.

## Interpretation

All observed results match the repository's stated baseline. The corpus is a
curated deterministic regression set authored alongside the implementation.
This record does not claim independent certification, production approval, or
protection from every novel attack.
