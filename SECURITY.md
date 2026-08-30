# Security Policy

## Scope

This repository is a reference implementation of a policy-enforced tool runtime. It deliberately avoids arbitrary shell execution, dynamic imports controlled by agent input, and direct credential exposure to the agent.

## Reporting a vulnerability

Do not publish active secrets, tokens, private keys, or sensitive exploit data in a public issue. Provide a minimal reproduction that demonstrates the security boundary being violated.

Useful reports include:

- a tool executing without a matching session capability;
- a policy validation bypass;
- argument smuggling that reaches a registered handler;
- an audit-chain integrity failure;
- a rate-limit bypass in the documented single-process threat model.

## Production hardening

Before using this pattern in a production environment, add authenticated principals, durable session storage, distributed rate limiting, external policy administration, secrets management, process or workload isolation for high-risk tools, telemetry export, dependency scanning, and deployment-specific network controls.
