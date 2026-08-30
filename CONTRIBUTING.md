# Contributing

Changes should preserve the runtime's fail-closed behavior and zero mandatory
runtime dependencies.

## Development workflow

1. Create a focused branch.
2. Add a failing test or red-team corpus case that demonstrates the behavior.
3. Implement the smallest complete fix.
4. Run make verify.
5. Document any change to a trust boundary, policy default, prompt contract, or
   retained audit data.

Security-control changes require tests for both malicious and benign inputs.
This reduces the chance of improving attack detection by making the runtime
unusable for legitimate requests.

## Evidence rules

- Do not claim production certification or independent validation.
- Keep generated evidence tied to a reproducible command.
- Preserve failed cases during development instead of deleting inconvenient
  results.
- Never commit real credentials, raw private prompts, or production audit keys.
