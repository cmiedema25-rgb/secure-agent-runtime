# Threat Model

## Scope

This model covers one process that accepts JSON requests, consults a model
provider, optionally executes registered tools, and appends local audit events.
It focuses on authorization and integrity around agent tool use.

## Assets

- credentials and provider API tokens;
- application system and developer instructions;
- private user input and tool results;
- authorization policy and tool allowlists;
- integrity of audit evidence;
- availability of the runtime;
- downstream systems reachable through future tools.

## Adversaries

1. A remote caller who can submit user content.
2. An attacker who controls text in a retrieved document or tool result.
3. A compromised or unreliable model provider that returns malicious content
   or malformed tool calls.
4. An operator or process that can edit the audit file but does not possess the
   signing key.

An attacker who controls the runtime process, policy file, and audit key is
outside the enforcement boundary of this demonstration.

## Trust boundaries

| Boundary | Untrusted side | Required control |
| --- | --- | --- |
| HTTP request | Caller JSON, headers, size | Authentication, parsing limits, role validation |
| Prompt boundary | User and retrieved text | Normalization, classification, instruction hierarchy |
| Provider response | Content and tool proposals | Output checks, allowlists, argument policy |
| Tool execution | Model-selected arguments | Capability limits and handler validation |
| Tool re-entry | Retrieved or computed output | Full untrusted-input screening |
| Audit storage | Mutable local file | HMAC chain and protected signing key |
| Network egress | Provider destination | HTTPS and host allowlist |

## Threats and mitigations

| Threat | Example | Mitigation | Residual risk |
| --- | --- | --- | --- |
| Direct prompt injection | Override prior instructions | Rules, severity scoring, stop decisions | Novel phrasing may evade patterns |
| Indirect prompt injection | Malicious retrieved document | Re-screen tool messages before model re-entry | Semantic attacks may evade patterns |
| Encoded injection | Base64 instruction payload | Bounded decoding and source-view findings | Other encodings are not decoded |
| Unicode evasion | Full-width or zero-width text | NFKC normalization and format removal | Visual homoglyphs remain possible |
| Prompt extraction | Request hidden policies | Review gate and output screening | Model may paraphrase protected content |
| Credential leakage | Model returns an API token | Secret detector and withheld output | Unknown credential formats may evade rules |
| Unauthorized tool use | Model proposes a shell tool | Exact tool allowlist | A permitted tool may contain its own flaw |
| Argument injection | Shell syntax in an argument | Metacharacter and path checks | Context-specific encodings may bypass generic checks |
| Egress bypass | Attacker URL in tool arguments | HTTPS plus hostname allowlist | DNS and infrastructure controls remain external |
| Tool-result poisoning | Retrieved text changes behavior | Tool output treated as untrusted | Detector coverage is incomplete |
| Resource exhaustion | Huge input or tool loop | Body, message, character, decode, round, and call limits | Connection-level rate limiting is external |
| Audit editing | Change a prior decision | HMAC sequence and hash chain | Whole-file deletion needs remote anchoring |
| Provider failure | Timeout or malformed JSON | Bounded timeout and fail-closed response | Availability is reduced during outages |

## Abuse cases exercised by tests

- input injection is blocked before any provider call;
- a proposed unlisted shell capability is never executed;
- duplicate tool-call identifiers are rejected;
- unsafe calculator syntax and excessive exponents fail closed;
- injected tool output is blocked before provider re-entry;
- a credential-shaped provider response is withheld;
- tampering with one audit record invalidates the chain;
- unauthenticated versioned API calls return 401;
- caller errors return stable JSON without a traceback.

## Security assumptions

- The application supplies and protects system and developer messages.
- The audit signing key is generated randomly, stored outside the repository,
  and not shared with untrusted operators.
- TLS termination and caller authentication are correctly configured.
- Only reviewed ToolDefinition implementations are registered.
- Policy changes receive code review and regression tests.

## Recommended production extensions

- rate limiting and request quotas at a reverse proxy;
- secret management through a managed key service;
- remote append-only audit storage with periodic signed checkpoints;
- semantic or model-assisted detection used as an additional signal, not the
  sole authorization mechanism;
- multilingual and adaptive red-team corpora;
- sandboxed tool execution in a separate identity and process;
- independent penetration testing and incident-response monitoring.
