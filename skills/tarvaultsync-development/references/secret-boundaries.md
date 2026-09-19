# Secret Boundaries

## Allowed locations

- Source-provider storage: Azure Key Vault, Google Secret Manager, or encrypted Drive/OneDrive vault entries.
- Short-lived memory while an authorized binding is being rendered.
- An authorized target file or Git Credential Manager record after a successful render.

## Forbidden locations

- `config.json`, `state.json`, logs, telemetry, errors, panic output, snapshots, test fixtures, sample files, or issue text.
- Filenames, cache keys, hashes, debug output, and metrics that reveal a secret or permit secret comparison.

## Boundary contracts

Providers expose metadata retrieval separately from payload retrieval. Renderers receive typed payloads and write atomically. State stores version identifiers and redacted outcomes only. Logging uses event IDs, provider names, binding IDs, timing, and redacted error categories.

For binary and certificate payloads, operate on bytes. For text formats, preserve the encoding and line-ending policy required by the explicit secret type; do not guess from a filename extension.
