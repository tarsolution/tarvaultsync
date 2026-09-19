# Contributing to TAR Vault Sync

## Principles

Security and predictability take priority over convenience. Do not add a feature that persists, logs, sends, or displays secret values unless the feature explicitly renders the value to its authorized target.

## Before opening a change

1. Keep source references and target mappings secret-free.
2. Document any new secret type, provider, renderer, configuration field, or platform behavior.
3. Add tests for both success and failure paths.
4. Confirm that diagnostics redact values, headers, tokens, and provider responses.

## Code expectations

- Use Rust formatting and linting tools required by the repository.
- Prefer explicit typed models over stringly typed provider or renderer behavior.
- Preserve atomic-write behavior for all files containing rendered data or state.
- Make polling, retry, and file-permission behavior configurable only through validated config.
- Never silently resolve Drive/OneDrive configuration conflicts.

## Security reports

Do not report potential vulnerabilities in a public issue. Send a private report to the maintainers with a minimal reproduction, affected version, impact, and suggested mitigation if available.

## Pull requests

Describe the motivation, configuration changes, platform coverage, tests run, and security implications. Never include real credentials, certificates, tokens, provider exports, or logs containing sensitive data.
