# Architecture and Threat Model

## Design objective

The runtime is built around one rule: **the model may propose authority, but it never owns authority**.

An agent can generate a tool name and arguments, but the runtime independently evaluates whether the request is registered, granted to the session, within rate limits, and compliant with deterministic policy constraints before any handler executes.

## Execution pipeline

```text
Untrusted agent output
        |
        v
+--------------------+
| API validation     |  Pydantic request boundary
+--------------------+
        |
        v
+--------------------+
| Session lookup     |  Reject unknown session
+--------------------+
        |
        v
+--------------------+
| Capability check   |  Reject ungranted tool
+--------------------+
        |
        v
+--------------------+
| Rate limiter       |  Bound runaway loops
+--------------------+
        |
        v
+--------------------+
| Policy evaluation  |  Validate tool + arguments
+--------------------+
        |
        v
+--------------------+
| Tool registry      |  Resolve explicit handler only
+--------------------+
        |
        v
+--------------------+
| Handler execution  |
+--------------------+
        |
        v
+--------------------+
| Audit chain        |  Record allow/deny decision
+--------------------+
```

## Trust boundaries

### 1. Agent output is untrusted

Tool names, argument names, values, and execution order are treated as attacker-controlled input. Prompt instructions do not modify runtime authorization state.

### 2. The registry is trusted application configuration

Only Python callables deliberately registered by the host application are executable. There is no `eval`, `exec`, dynamic module import, arbitrary shell bridge, or model-selected filesystem path.

### 3. Capabilities are session-scoped authority

A session receives a finite set of tool identifiers. Possession of a valid session ID does not grant access to tools outside that set.

### 4. Policy is deterministic

Policy decisions depend on structured data, not natural-language interpretation. A model cannot talk the policy engine into granting access.

## Default-deny behavior

Authorization is conjunctive. A call succeeds only when all of the following are true:

1. The session exists.
2. The requested tool is in the session capability set.
3. The session is below its invocation limit.
4. The tool exists in policy.
5. Every supplied argument is known to policy.
6. All required arguments are present.
7. Every value satisfies its type and constraint rules.
8. The tool exists in the explicit registry.

Failure at any stage prevents handler execution and emits a denied audit event.

## Audit integrity

Audit events are chained with SHA-256. Each event stores the hash of the previous event, and its own digest covers the prior hash plus a canonical JSON representation of the event body.

This provides tamper evidence for in-memory event history. It is not a replacement for durable append-only storage. A production deployment should export these events to an immutable or access-controlled log sink.

## Prompt-injection containment

Prompt injection is modeled as a compromise of the model's decision-making, not a compromise of the runtime itself. Even if the model is convinced to request an unauthorized action, capability and policy checks remain unchanged.

Example:

```text
Prompt-injected model request:
  tool = "shell.exec"
  arguments = {"command": "..."}

Runtime result:
  denied: tool_not_allowed_by_policy or capability_denied
```

The security property is therefore **containment of agent authority**, not prevention of every malicious or incorrect model output.

## Concurrency

Session state, rate-limit buckets, and the audit chain use synchronization around shared mutable structures. The sample is suitable for a single Python process. Horizontal deployment requires external shared state for sessions, limits, and durable audit ordering.

## Production extension points

A production implementation can preserve the same architecture while replacing individual components:

| Demo component | Production replacement |
|---|---|
| In-memory sessions | Redis, database, signed capability tokens |
| In-memory rate limiter | Redis/token bucket service |
| Local audit chain | Append-only log store / SIEM pipeline |
| Local policy object | Versioned policy service or OPA-style engine |
| In-process tools | Isolated workers, containers, serverless functions |
| Session ID | Authenticated principal + scoped authorization token |

## Non-goals

This repository does not claim to provide a hostile native-code sandbox, kernel isolation, container escape protection, or a complete identity system. High-risk tools should execute in an isolated process or workload with OS-level and network-level restrictions.
