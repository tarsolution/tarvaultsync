# TAR Vault Sync Requirements

## Product requirements

1. Run without a central TAR Vault Sync service or database.
2. Run as an invisible background agent on Windows, macOS, and Linux.
3. Use a single distributed binary with agent, UI, sync, status, and log modes.
4. Let the user edit mappings through an on-demand configuration UI.
5. Store all application configuration and state in text-based JSON files.
6. Optionally synchronize secret-free configuration through a user-selected Google Drive or OneDrive folder.
7. Optionally store encrypted secret vaults in Google Drive or OneDrive.
8. Support Azure Key Vault and Google Secret Manager as source providers.
9. Detect source changes by version metadata without downloading unchanged values.
10. Record redacted operational events in rotating NDJSON log files.

## Binding requirements

A binding must define a source reference, a target, an explicit secret type, and missing-target behavior. It must support:

- `.env` / dotenv key replacement
- JSON Pointer replacement
- properties and YAML fields
- Docker environment files
- text and binary file rendering
- Git Credential Manager records, scoped by protocol, host, and optional path prefix

## Security requirements

- Secret values may exist only in provider storage, the encrypted optional Drive/OneDrive vault, and transient agent memory while rendering.
- Authentication material must reside in operating-system secure storage.
- No secret values, derived hashes, access tokens, or file contents may appear in configuration, state, diagnostics, or logs.
- Shared configuration must be schema validated and can be integrity signed.
- A failed validation, failed source read, or write failure must leave the existing target unchanged.
- Per-device state and logs must never be placed inside synchronized folders.

## Non-functional requirements

- Low idle CPU and memory usage.
- Exponential retry with jitter after provider or network failures.
- Atomic file updates and crash-safe state writes.
- Configuration conflict detection for Drive/OneDrive conflict copies; never silently merge conflicting bindings.
- Human-readable error messages and machine-readable NDJSON events.
