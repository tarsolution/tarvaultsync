# Roadmap

TAR Vault Sync will be built in the following order. Each phase should deliver a usable vertical slice with focused tests and documentation. Connector and sync modules own their configuration UI; the core provides only the contracts and host surface for those screens.

Phase 1 is complete for the fake-module test host described below. Phases 2–5 have development implementations; [phase 2–5 QA](qa-phase2-5.md) records verified behavior and remaining native release gates. Later phases remain planned. [Requirements](requirements.md) define the product and security constraints.

## 1. Core infrastructure

**Status:** Complete for the fake-module test host; native secure-store authentication, desktop packaging, and platform integration remain later work.

- Define typed contracts for vault stores, source connections, local sync targets, secret payloads, and sync outcomes.
- Provide module registration and UI mounting so each store connector and local sync module can supply its own settings screen.
- Implement versioned JSON configuration, per-device state, redacted NDJSON events, and local IPC between the background agent and the on-demand UI.
- Implement a scheduler with interval, manual trigger, jitter, retry/backoff, and single-flight execution per binding.

**Acceptance criteria:**

- Typed core contracts cover source references and versions, byte-safe payloads, targets, bindings, missing-target policy, sync outcomes, and module registration. A fake store and fake target module implement them.
- Versioned JSON configuration rejects unsupported versions, malformed or secret-bearing fields, and invalid target scope. Per-device state survives restart and contains only safe metadata.
- Fake source checks metadata first. An unchanged version does not fetch a payload; a changed version fetches and applies once. State advances only after success; a failed application remains retryable.
- Both interval and manual triggers execute through the same single-flight path. Concurrent triggers for one binding never overlap, and retry/backoff with jitter has deterministic tests.
- An authenticated local IPC client can request status and trigger a sync; an unauthenticated client is rejected. The agent runs with the UI closed.
- The host mounts or resolves each fake module's own settings screen, proving both registration and UI ownership. A lightweight test host is sufficient for this phase.
- Events parse as redacted NDJSON, and tests verify fake payloads and credential-like inputs cannot enter configuration, state, events, or errors. Focused unit and integration tests pass.

**Done when:** the fake store and fake target module complete an end-to-end scheduled and manual sync through the core, IPC, and UI host, with the criteria above verified. Real providers, encrypted vaults, file renderers, and native packaging begin in later phases.

## 2. Vault entry and local vault store

**Status:** Encrypted store, CLI flow, and native desktop vault entry screen implemented; platform packaging and visual QA remain open.

- Build the vault unlock/entry screen and local encrypted vault store.
- Define the store-connection UI contract used by local and future cloud stores.
- Support explicit secret types and byte-safe storage for strings, text, JSON, certificates, private keys, and binary files.
- Define key creation, unlock, backup/recovery, and failure behavior before storing real secrets.

**Done when:** a user can create, lock, unlock, and edit a local vault; no plaintext secret is persisted outside its encrypted payload.

## 3. File sync

**Status:** Implemented and covered by focused Linux-container tests; native-platform validation remains open.

- Map a secret to an entire file or a selected `.env`, JSON, YAML, or properties field.
- Support text and binary outputs, including PEM, CRT, CA, P12/PFX, and private-key files.
- Preserve unrelated content where the format permits; validate paths and write atomically.

**Done when:** changing a local-vault secret updates each configured file target while a failed sync leaves existing files intact.

## 4. Docker sync

**Status:** Compose mapping and `env_file` inputs implemented, with restart-required status; native-platform validation remains open.

- Support Docker Compose environment values and `env_file` targets.
- Define separately whether Docker secrets or container restart hooks are needed; do not assume writing a file updates a running container.

**Done when:** configured Docker inputs are updated safely and the UI states when a container restart is required.

## 5. Git credentials

**Status:** GCM protocol target implemented; Windows credential-store and path-scope smoke checks passed, while integrated agent and macOS/Linux checks remain open.

- Synchronize HTTPS credentials into Git Credential Manager using Git's credential protocol.
- Match by protocol, host, and optional repository path. Avoid plaintext `~/.git-credentials` storage.

**Done when:** a rotated token is available to Git through the configured credential manager without editing repository files.

## 6. Microsoft password manager import and sync

**Status:** Import-only scope selected; native CSV-to-encrypted-vault implementation is in development. Real Edge export/UI acceptance remains open. See [browser import](browser-import.md).

- Investigate supported Microsoft Edge/password-manager import and write interfaces and their platform restrictions.
- Implement user-approved import first. Add ongoing sync only if a supported API permits it safely.
- Define conflict resolution and deletion rules before enabling two-way changes.

**Done when:** the documented, supported integration works end to end, or the phase records a clear feasibility decision and a safe import-only scope.

## 7. Chrome password manager import and sync

**Status:** Shares the explicit-consent CSV import implementation; continuous sync is disabled. Real Chrome export/UI acceptance remains open. See [browser import](browser-import.md).

- Investigate supported Chrome/Google Password Manager import and write interfaces.
- Follow the same explicit-consent, conflict, and deletion rules as phase 6; do not modify browser profile databases directly.

**Done when:** the supported integration is verified, or an import-only scope is documented if direct sync is unavailable.

## 8. OneDrive store connector

- Store encrypted vault data in the user's OneDrive with revision-aware reads and writes.
- Detect concurrent edits and present conflicts rather than silently overwriting a vault.

**Done when:** two devices can access the same encrypted vault and a conflicting edit cannot silently discard data.

## 9. Google Drive store connector

- Apply the same encrypted-vault, revision, and conflict contracts to Google Drive.

**Done when:** a paired device can read and update the encrypted vault through Google Drive without exposing plaintext to Drive.

## 10. Azure Key Vault connector

- Add authentication, metadata-only version checks, and secret-value retrieval on change.
- Map Azure secret versions and errors into the common store contract.

**Done when:** a rotated Key Vault secret updates its local targets and unchanged versions do not fetch the payload.

## 11. AWS Secrets Manager connector

- Add authentication, version/stage checks, and value retrieval through AWS Secrets Manager.
- Confirm the intended service name before implementation; this phase interprets "AWS password manager" as AWS Secrets Manager.

**Done when:** a changed AWS secret updates its targets under least-privilege access.

## 12. Google Secret Manager connector

- Add Google Cloud Secret Manager authentication, version metadata checks, and value retrieval.
- Confirm the intended service name before implementation; this phase interprets "Google vault" as Google Cloud Secret Manager.

**Done when:** a changed Google secret updates its targets without downloading unchanged payloads.

## 13. Git-backed store connector

- Store only encrypted vault payloads in a Git repository; keep keys and tokens out of the repository.
- Handle pull/push conflicts, history retention, file size, and accidental plaintext detection.

**Done when:** encrypted vault changes synchronize through Git and conflicts require an explicit resolution.

## Cross-cutting release gates

Every phase must keep secret values out of configuration, state, logs, errors, and test artifacts. File writes must be atomic; source and target permissions must be validated. Core behavior is tested in the Dev Container, and native integrations are verified on Windows, macOS, and Linux runners as they are introduced.
