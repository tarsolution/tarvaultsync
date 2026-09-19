# TAR Vault Sync Requirements

## Product goal and scope

Restore a developer workspace's secret-dependent local configuration from approved sources without placing plaintext secrets in ordinary backups. TAR Vault Sync is a local-first, cross-platform agent with no project-operated server or database. The first deliverable is the core infrastructure in [roadmap phase 1](roadmap.md#1-core-infrastructure); source connectors, encrypted vaults, concrete file targets, and native integrations follow later.

## Actors and workflows

- A developer configures source-to-target bindings on a device, triggers a sync, sees status and redacted events, and can close the UI while the agent continues.
- A second device may receive secret-free shared configuration through a user-selected Google Drive or OneDrive folder. Each device keeps its own credentials, state, and logs.
- A connector supplies source access and its settings screen; a local sync module supplies target behavior and its settings screen. The core validates and orchestrates both.

## Functional requirements

| ID | Requirement | Planned phase |
| --- | --- | --- |
| F01 | One distributed application exposes `agent`, `config`, `sync`, `status`, and `logs` modes; the UI is on demand and the background agent operates independently. | 1 contract; native packaging later |
| F02 | A binding identifies a typed source reference, typed target, explicit secret type, and missing-target policy (`alert` by default, `recreate`, or `disable`). Configuration may group bindings into profiles. | 1 contracts; later target modules |
| F03 | A store connector and local sync module can register capabilities and mount their own configuration screens through core host contracts. | 1 contracts and fakes; concrete screens later |
| F04 | JSON configuration has a version, rejects unsupported or malformed content, and contains references and policies only. Per-device JSON state tracks versions and outcomes. | 1 |
| F05 | The agent checks source version metadata before retrieving a payload; unchanged versions skip value retrieval. A successful target application advances `lastAppliedVersion`. | 1 orchestration with fakes; real sources later |
| F06 | Scheduling supports interval checks, manual triggers, bounded retry with exponential backoff and jitter, and at most one active run per binding. | 1 |
| F07 | Agent and on-demand UI communicate over authenticated local IPC for status and manual sync operations. | 1 |
| F08 | Redacted, rotating NDJSON events record time, binding identifier, operation, outcome, and safe error category. | 1 |
| F09 | Optional secret-free configuration synchronization uses a selected Google Drive or OneDrive folder; conflicting copies require explicit resolution. Integrity signing is optional, and enforcement rejects invalid or unsigned shared configuration. | Later cloud integration; validation contract starts in 1 |
| F10 | Local encrypted vault supports explicit secret types and device unlock, backup, and recovery rules. Optional OneDrive, Google Drive, and Git-backed stores contain encrypted vault payloads only. | 2, 8, 9, 13 |
| F11 | Local targets include dotenv/Docker environment keys, JSON Pointer, YAML and properties fields, raw text and binary files, and Git Credential Manager entries scoped by protocol, host, and optional path prefix. | 3–5 |
| F12 | External sources include Azure Key Vault and Google Secret Manager with metadata-first reads. AWS Secrets Manager is planned subject to service-name confirmation in phase 11. | 10–12 |
| F13 | Microsoft and Chrome password-manager integrations require supported interfaces, explicit user consent, and defined conflict/deletion rules. Import-only is an acceptable feasibility outcome. | 6–7 |

## Security and data requirements

| ID | Invariant |
| --- | --- |
| S01 | Secret bytes exist only in an approved provider, an encrypted vault payload, a transient agent buffer, or the explicitly authorized local output target. They never enter configuration, state, events, diagnostics, errors, examples, or test artifacts. |
| S02 | Provider authentication material and vault private keys remain in operating-system secure storage. Shared configuration contains neither credentials nor secret-derived hashes. |
| S03 | Treat shared configuration as untrusted: validate schema, version, scope, and integrity policy before use. Never silently merge conflicting bindings. |
| S04 | Verify target path and scope before a write. A failed read, validation, render, or replacement leaves the previous target intact. File output uses a temporary sibling and atomic replacement. |
| S05 | State and events remain local to each device and outside synchronized folders. State JSON writes are crash safe; events contain only allowlisted, redacted fields. |
| S06 | A version is recorded as applied only after the target operation succeeds. Failed operations retain retry eligibility and report a safe error. |

## Quality and platform requirements

- Support Windows, macOS, and Linux. Core behavior is tested in the Dev Container; native secure-store, background lifecycle, UI, and installer behavior receive platform tests when introduced.
- Keep idle CPU and memory use low through interval polling rather than busy loops. Polling remains the reliability mechanism even if providers later offer notifications.
- Make failures understandable through safe status and machine-readable event categories. Never suppress a failure that changes a sync result.
- Use explicit typed contracts at security boundaries. Binary payloads remain byte-safe, while text encodings and line-ending behavior are explicit.

## Phase 1 acceptance criteria

1. The Rust core defines typed source reference, source version, secret payload, target, binding, missing-target policy, sync outcome, and module registration contracts. A fake store and fake target module implement them without real credentials or secret values.
2. A versioned sample configuration loads when valid and rejects an unsupported version, malformed binding, unknown target scope, and secret-bearing fields. Local state persists only safe fields and survives a restart.
3. A fake unchanged version causes no payload retrieval or target application. A changed version is retrieved once and applied once; only success advances the recorded version. A failed fake application preserves the previous state and is eligible for retry.
4. Interval and manual triggers work. Concurrent triggers for the same binding do not overlap. Retry/backoff and jitter are testable through injected timing or equivalent deterministic control.
5. The local IPC endpoint authenticates a client, supports status and manual trigger, and rejects an unauthenticated request. The agent still works with the UI closed.
6. The host can register and display or resolve both fake modules' settings screens through a defined UI mounting contract. A lightweight test host is sufficient in phase 1; production native UI packaging belongs to a later integration milestone.
7. Events are parseable NDJSON with allowlisted fields. Tests verify no fake payload bytes or credential-like inputs appear in configuration, state, events, or error text.
8. Focused unit and integration tests pass for the preceding behavior. The phase does not claim real provider, vault, file-rendering, or native-platform integration support.

## Decisions to resolve before affected phases

- Define vault key creation, unlock, backup/recovery, and lost-key behavior before phase 2 stores real secrets.
- Confirm the intended AWS and Google service names before phases 11 and 12; the roadmap currently interprets them as AWS Secrets Manager and Google Secret Manager.
- Assess supported password-manager APIs and platform restrictions before promising ongoing synchronization in phases 6 and 7.
