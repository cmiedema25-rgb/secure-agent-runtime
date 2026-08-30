# Prompt Engineering Contract

## Versioning

The system prompt is maintained in src/secure_agent_runtime/prompts.py with an
explicit version and SHA-256 fingerprint. Each request audit trail records both,
allowing an evaluator to connect behavior to the exact prompt contract.

Current version: 2026-08-30.1

## Design principles

The prompt is intentionally short. It defines:

1. the assistant's operating context;
2. an explicit system, developer, user, and tool instruction hierarchy;
3. the rule that retrieved, quoted, encoded, and tool-returned text is data;
4. the prohibition on invented tool output;
5. protected information categories;
6. behavior when a capability is unavailable;
7. a concise uncertainty requirement.

These instructions reduce ambiguity, but the prompt is not treated as a
security control by itself. Deterministic policy remains authoritative.

## Why the prompt and runtime are separate

A model can misunderstand, forget, or be induced to ignore natural-language
rules. Conversely, a fixed pattern detector cannot produce a useful assistant
response. The design assigns each layer a suitable responsibility:

| Layer | Responsibility |
| --- | --- |
| Prompt | Guide model behavior and clarify instruction priority |
| Provider | Plan a response or propose a capability |
| Policy | Authorize or stop the proposed action |
| Tool handler | Enforce capability-specific validation |
| Audit | Record which decision occurred and under which prompt version |

## Evaluation method

Prompt-injection cases are expressed independently in
evals/attack_corpus.jsonl. Expected decisions are explicit. The benchmark
checks exact decisions and separately calculates attack-stop and benign-allow
rates. Tests also inject malicious provider output and tool output so evaluation
is not limited to user prompts.

The corpus is deliberately labeled a curated regression benchmark. Perfect
performance on self-authored cases proves reproducibility, not general
resistance to novel attacks.

## Change procedure

A prompt change should:

- increment SYSTEM_PROMPT_VERSION;
- add or update a failing test that motivates the change;
- rerun the full corpus and preserve the result;
- document any new protected-information category;
- avoid replacing a deterministic policy check with prompt wording alone.
