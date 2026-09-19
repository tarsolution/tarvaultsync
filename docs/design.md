# TAR Vault Sync Architecture and Technical Design

## Scope and invariants

TAR Vault Sync is a local-first Rust agent distributed as one user-facing binary with agent, configuration UI, one-shot sync, status, and log modes. It has no application server or central database. A closed UI cannot stop the agent. Configuration and device state are JSON; events are rotating NDJSON. Optional encrypted vault payloads are opaque binary files, so the text-file requirement applies to application configuration and state, not ciphertext.

Secret bytes may exist only at a source provider, inside an encrypted vault payload, in short-lived process memory, or at an explicitly authorized target. Provider credentials and vault-unlock keys belong in the operating-system secure store. Configuration, state, events, IPC diagnostics, errors, tests, and examples contain neither secret bytes nor secret-derived hashes. Every source checks version metadata before payload retrieval. Failed validation, read, or write leaves the previous target intact. Per-device state and logs remain outside shared folders.

## Process and component boundaries

```text
CLI / on-demand UI --authenticated local IPC--> background agent
                                              |-- config loader and validator
                                              |-- module registry and UI host
                                              |-- scheduler / binding coordinator
                                              |-- vault store and source adapters
                                              |-- local sync target modules
                                              |-- per-device state and redacted events
                                              `-- OS secure-store adapter

shared folder: config.json, optional config.sig, encrypted vault blobs only
local folder: state.json, event logs, IPC endpoint metadata only
```

The core owns binding orchestration and persistence contracts. A **vault store** locates and manages secret entries (local encrypted vault, cloud encrypted vault, or external provider); a **source connection** supplies version metadata and retrieves a typed payload; a **local sync module** validates and applies a typed target. A module registers stable IDs, supported secret/target kinds, validation, and a settings screen. The UI host mounts each registered module's working settings surface on demand; screen ownership and field validation stay with the module. Dynamically loaded third-party code is outside the initial trust model; registration is compiled in.

The one distributed binary can launch an embedded UI entry point; any Tauri packaging must preserve this one user-facing executable requirement or be explicitly revisited before implementation. The agent is the only writer of local state and events. CLI and UI request actions over IPC and do not edit state directly.

## Domain contracts

Use exhaustive, versioned enums and opaque identifiers at persistence boundaries:

- `StoreKind`, `ConnectionId`, `SourceRef`, and `SourceVersion` identify a provider and a specific entry/version. Version identifiers are opaque and compared for equality; they never contain a payload.
- `SecretType` specifies text, JSON, binary, certificate, or private-key semantics plus explicit encoding/MIME where relevant. `SecretPayload` owns transient bytes and is never serialized, debug-printed, or used in errors.
- `TargetSpec` is a tagged enum for whole-file, structured field, Docker input, or Git credential scope. Its path or credential scope is validated before any payload fetch.
- `MissingTargetPolicy` is `Alert`, `Recreate`, or `Disable`, selected per binding. `Disable` changes effective local state through an explicit transition and event; it does not silently edit shared configuration.
- `Binding` contains ID, source reference, explicit secret type, target spec, policy, and schedule. It contains no credential or payload.
- `SyncOutcome` is unchanged, applied, skipped/disabled, or failed with a redacted error category. A manual request is a metadata check, not an unconditional payload download; force-reapply requires a separate explicit operation if later needed.

The source interface separates `get_version(reference)` from `get_value(reference, observed_version)`. A source must reject a version mismatch or surface a retryable conflict rather than return a value under a different version. The target module separates `validate(spec, type, scope)` from `apply(spec, payload)`; `apply` returns only non-secret metadata. For file targets, validation resolves the exact authorized path before retrieval, and application stages a sibling temporary file, flushes it, applies appropriate permissions, and atomically replaces the destination. On platforms where atomic replacement cannot be guaranteed, the module rejects the operation rather than fall back to in-place mutation. Structured renderers preserve unrelated fields and validate syntax before replacement.

The module registry rejects duplicate IDs and unsupported source/target/type combinations at startup or configuration validation. UI-submitted configuration is validated again by the agent. No UI-provided path or scope is trusted merely because a module screen produced it.

## Configuration, state, and events

```text
application root/
  shared/config.json       versioned, secret-free; optionally synchronized
  shared/config.sig        optional integrity signature
  local/state.json         per-device, non-secret
  logs/events-*.ndjson     per-device, redacted and rotating
```

Shared configuration has a schema version, stable binding/module IDs, connection references, target specs, schedules, and policies. Unknown required fields, unsupported versions, duplicate IDs, invalid paths, and invalid enum values fail closed. Migration reads an older version, validates the result, and atomically commits a new version; unknown future versions are rejected. Signed configuration is verified before use when integrity enforcement is enabled. An absent signature is acceptable only when enforcement is disabled. A Drive/OneDrive conflict copy is reported as a conflict and never auto-merged into active bindings.

`state.json` contains the last successfully applied source version per binding, timing, retry state, and redacted status. One agent writer uses a temporary sibling, flush, and atomic replacement. `lastAppliedVersion` advances only after target application succeeds. On restart, an observed but uncommitted version is checked and safely reapplied. Target modules make repeated application idempotent where practical. Event records have a stable event ID, timestamp, binding ID, source/target kind, outcome, duration, and redacted error category; they contain no source path, payload, token, file contents, or arbitrary provider error string. Rotation and retention are bounded. Status and logs commands expose this redacted model only.

## Sync state machine and scheduling

For each enabled binding: validate configuration and target scope; wait for its interval or manual trigger; enforce single-flight; read source version metadata; compare to `lastAppliedVersion`; fetch a transient payload only when changed; validate returned type/version; apply target; commit state; append an event. A manual trigger coalesces with an active run and causes a subsequent check only if needed. Independent bindings may run concurrently within a bounded global limit; a shared target is serialized or rejected as a configuration conflict to avoid lost updates.

Provider and network failures use exponential backoff with jitter and a cap. Validation and unsupported-type failures remain visible until configuration changes; they do not hammer the provider. Scheduler timing uses a monotonic clock while persisted timestamps are informational. A crash during rendering may leave a temporary sibling, which startup cleanup may remove after verifying it belongs to the agent. It must not infer success from a leftover temp file.

## Local IPC and UI

IPC uses an OS-local endpoint with restrictive permissions and an authenticated handshake. An installation-specific token or key resides in the OS secure store; it never enters configuration, state, logs, or process arguments. Requests are bounded and versioned. Phase 1 operations are `GetStatus` and `TriggerSync`; configuration read, validation, and update operations can be added when interactive editing is implemented. Changes are written by the agent after schema and module validation. The UI gets metadata and settings forms, never payloads. A single-agent lock prevents two writers from racing.

**Phase 1 acceptance requires a working host surface**, even if it is a lightweight test host: start the agent, mount or resolve both fake modules' actual settings screens, use an authenticated IPC client to request status and trigger sync, and inspect redacted status/events. A registry containing only unrendered descriptors does not satisfy this criterion. A validated fixture binding may drive this first end-to-end flow; interactive configuration editing and native desktop packaging follow later.

## Phase integration design

| Roadmap phase | Technical boundary and acceptance focus |
| --- | --- |
| 1 Core | Typed contracts, registry and working UI host, versioned config/state/events, authenticated local IPC, scheduler, fake store and target. No real secrets or renderer. |
| 2 Local vault | Encrypted local vault store and unlock UI. Define KDF, key wrapping, backup/recovery, lock timeout, and corruption behavior before storing real secrets. |
| 3 File sync | Whole-file and `.env`/JSON Pointer/YAML/properties modules. Format-specific parsing, encoding, path scope, permissions, and atomic replacement. |
| 4 Docker | Compose environment and `env_file` are file targets with Docker-specific validation. Show restart-required status; no implicit container restart. |
| 5 Git credentials | Target invokes Git credential protocol through an approved credential manager with protocol/host/optional path scope; no plaintext credential file. |
| 6–7 Browser import | Research supported Edge/Chrome APIs and platform constraints before design commitment. User-approved import is the minimum; ongoing sync, conflict and deletion semantics require supported interfaces. Never edit browser profile databases. |
| 8–9 Cloud vault | Encrypt locally, upload opaque payload, compare remote revision/ETag before writes, surface concurrent-edit conflicts. Keep device private keys and tokens in secure storage. |
| 10–12 External providers | Azure, AWS Secrets Manager, and Google Secret Manager adapters implement metadata-first version checks, least-privilege authentication, typed retrieval, and redacted errors. |
| 13 Git vault | Store encrypted payload only; reconcile repository revisions explicitly. Validate content and history policy before push. |

## Consistency and open decisions

1. Earlier design text listed Azure and Google as the complete source set, while the roadmap also includes local vault, AWS, and Git-backed vault. The roadmap is the scope source; each phase adds an adapter under the same boundary.
2. “All application configuration and state are text-based JSON” coexists with encrypted vault storage. Ciphertext is a separate payload artifact, not application configuration or state.
3. “Single distributed binary” and a conventional Tauri bundle may conflict. Packaging must be verified before UI implementation; phase 1 should avoid assuming a separate permanent UI executable.
4. Cloud-shared configuration is optional and independent of cloud vault storage. Synchronizing one does not implicitly enable the other.
5. Browser password-manager write APIs and two-way deletion behavior are feasibility gates in phases 6–7, not promised implementations.
6. Linux secure-store availability, service installation, IPC ACL details, cloud vault cryptographic formats, signing-key distribution, and cross-device recovery remain platform/design decisions before their respective phases. Their absence does not relax phase 1's no-payload-persistence rule.

## Verification gates

Each phase tests its own boundary. Phase 1 proves schema rejection, state atomicity, event redaction, authenticated IPC, trigger coalescing, single-flight, retry behavior, metadata-before-payload ordering, and a user-visible fake module flow. Later renderer phases prove failed writes preserve targets and binary bytes remain unchanged. Native Windows, macOS, and Linux integration tests are required as platform adapters arrive; Linux Dev Container tests alone cannot validate those adapters.
