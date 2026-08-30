# Architecture

## Design goal

Secure Agent Runtime demonstrates a narrow but complete control plane for an
AI assistant that can call tools. Its primary invariant is:

> No model-generated capability request executes unless deterministic policy
> authorizes the exact tool name and arguments.

The model is a planner, not a security boundary.

## Components

| Component | Responsibility | Trust level |
| --- | --- | --- |
| Runtime | Owns orchestration and stop conditions | Trusted control plane |
| Policy engine | Returns allow, review, or block | Trusted decision point |
| Risk scanner | Produces explainable findings | Trusted but imperfect detector |
| Provider | Proposes content and tool calls | Untrusted external component |
| Tool registry | Exposes named, bounded capabilities | Trusted implementation |
| Tool output | Data returned by a capability | Untrusted data |
| HTTP client | Accepts caller-controlled requests | Untrusted boundary |
| Audit log | Retains authenticated decision evidence | Integrity-protected record |

## Request lifecycle

~~~mermaid
sequenceDiagram
    participant Caller
    participant Runtime
    participant Policy
    participant Provider
    participant Tool

    Caller->>Runtime: Messages
    Runtime->>Policy: Screen untrusted input
    alt blocked or review
        Policy-->>Caller: Stop decision
    else allowed
        Runtime->>Provider: Prompt plus tool schemas
        Provider-->>Runtime: Content or tool proposal
        Runtime->>Policy: Screen output and proposal
        alt approved tool
            Runtime->>Tool: Bounded arguments
            Tool-->>Runtime: Untrusted result
            Runtime->>Policy: Re-screen result
        else stopped
            Policy-->>Caller: Stop decision
        end
    end
~~~

The loop is capped by both tool calls per round and total tool rounds. Duplicate
call identifiers and provider exceptions stop execution.

## Policy layers

### Input policy

Input is Unicode-normalized, stripped of invisible formatting characters, and
inspected through bounded analysis views. Plausible Base64 fragments are
decoded only when they remain within token and byte limits. Findings include
category, severity, score, evidence snippet, detector, and source view.

The runtime only treats user and tool roles as untrusted input. System and
developer messages are application-controlled. An internet-facing caller
should not be allowed to submit those privileged roles unless the surrounding
application authenticates that capability.

### Tool policy

The runtime checks:

- exact tool-name membership in the allowlist;
- detector findings in serialized arguments;
- sensitive filesystem path fragments;
- shell metacharacters;
- HTTPS requirements and exact or subdomain host matching;
- configured human-review requirements.

Tool handlers also validate types, lengths, recursion depth, numeric bounds,
and result size relevant to their own capability.

### Output policy

Provider text is checked for credential patterns and instruction-extraction
content. A blocked output is replaced with a generic explanation; the original
content is not returned or written to the audit log.

### Tool-result policy

Tool results are serialized as untrusted tool messages and sent through input
policy before provider re-entry. This addresses indirect injection through
retrieved documents or external data.

## Audit integrity

Each JSONL record contains a monotonically increasing sequence, UTC timestamp,
event name, request identifier, redacted details, a SHA-256 digest of sensitive
payload data, the prior record hash, and an HMAC-SHA-256 record hash.

The digest proves that a request produced a specific decision without storing
the raw prompt. The HMAC chain detects edits, reordering, and truncation inside
the retained chain. Protecting the signing key and detecting deletion of the
entire log require controls outside this repository.

## Concurrency

The HTTP server handles requests in separate threads. Audit appends are
serialized by a process-local lock so sequences and chain links remain ordered.
The supplied tools hold immutable or read-only state. A distributed deployment
would replace the file log with a transactional append-only store or a remote
ledger that provides cross-process sequencing.

## Dependency strategy

The runtime has no mandatory third-party package. This keeps the supply-chain
surface small, enables offline verification, and makes every security-relevant
operation inspectable in the repository. The tradeoff is a deliberately small
HTTP surface and provider client.
