# Security Policy

## Supported version

The current 1.x release line receives security fixes.

## Reporting a vulnerability

Use the repository's private GitHub Security Advisory form. Do not open a
public issue containing exploit details, credentials, private prompts, or audit
signing material.

Include the affected version, configuration, reproduction steps, expected and
observed behavior, and any proposed mitigation. Reports that demonstrate a
policy bypass should state whether the bypass occurs at input screening, tool
authorization, tool-output screening, provider output screening, or audit
verification.

## Scope

In scope:

- policy bypasses that result in unauthorized tool execution;
- prompt or credential leakage through provider output;
- egress allowlist bypasses;
- audit-chain tampering that is not detected;
- parser or normalization behavior that creates a practical injection bypass;
- denial-of-service conditions within documented input limits.

The curated evaluation corpus is a regression suite, not a security
certification. New attack classes should be added as failing regression cases
before a fix is merged.
