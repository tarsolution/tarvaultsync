# TAR Vault Sync Design

## Purpose

TAR Vault Sync is a local-first, cross-platform secret synchronization agent. It applies secrets from supported sources to developer-machine targets such as `.env` files, JSON, properties files, Docker environment files, certificate files, and Git Credential Manager.

TAR Vault Sync has no central backend and does not retain a copy of secret values. Azure Key Vault, Google Secret Manager, or an optionally encrypted Google Drive/OneDrive vault are the sources of truth.

## Architecture

One Rust binary has several modes:

- `tarvaultsync agent`: invisible, long-running background process.
- `tarvaultsync config`: opens the configuration UI only when requested.
- `tarvaultsync sync`: performs one synchronization pass.
- `tarvaultsync status` and `tarvaultsync logs`: inspect local state.

The agent and UI share a Rust core. The UI communicates with the running agent over authenticated local IPC. The agent remains operational when the UI is closed.

## Local-first storage

All persisted state is text based; no database server is required.

```text
TARVaultSync/
  shared/
    config.json          # secret-free, optionally Drive/OneDrive synchronized
    config.sig           # optional integrity signature
  local/
    state.json           # per-device, never cloud synchronized
  logs/
    events-YYYY-MM-DD.ndjson
```

`config.json` stores only source references, target mappings, policies, and profiles. `state.json` stores source version IDs, timestamps, status, and errors. Neither file may contain a secret value, access token, private key, or a secret-derived hash.

Credentials used to authenticate the device to providers are stored only in the platform secure store: Windows Credential Manager/DPAPI, macOS Keychain, or Linux Secret Service.

## Synchronization model

For every binding, the agent compares a provider's current version metadata with `lastAppliedVersion` in `state.json`.

1. Read metadata only.
2. If the version is unchanged, do nothing.
3. If the version changed, retrieve the secret once.
4. Render it to the target atomically.
5. Persist the new version and append a redacted event.

Polling is the reliability mechanism. Provider events may request an immediate check, but cannot replace polling in a no-central-server topology.

## Sources

- Azure Key Vault
- Google Secret Manager
- Encrypted Google Drive vault
- Encrypted OneDrive vault

Drive and OneDrive vaults contain encrypted blobs, never plaintext secrets. A vault encryption key is wrapped for each paired device. Each device's private key stays in its operating-system secure store.

## Targets

- dotenv fields
- JSON Pointer fields
- YAML and properties fields
- Docker Compose environment or `env_file` inputs
- raw text and binary files
- Git Credential Manager entries

Missing target fields default to `alert`; bindings can instead be configured to recreate or disable.

## Secret representation

Every secret has an explicit type, MIME type, extension, and encoding. Values are never inferred solely from a filename.

Supported categories include `string`, `text`, `json`, `binary`, certificate types (`crt`, `cer`, `ca`, `pem`, `der`, `p7b`, `p12`, `pfx`, `jks`) and private-key types (`key`, `pk`, PKCS#8, RSA, EC, Ed25519, SSH). Binary formats are written byte-for-byte; PEM/text formats retain safe line endings.

## Security rules

- Never log, display, hash, or persist secret values.
- Write target files through a temporary file followed by atomic replacement.
- Restrict sensitive file permissions where the platform permits it.
- Validate target paths, JSON pointers, and config schema before writing.
- Do not use plaintext `~/.git-credentials`; write Git credentials through Git Credential Manager.
- Reject an invalid or unsigned shared configuration when integrity enforcement is enabled.
