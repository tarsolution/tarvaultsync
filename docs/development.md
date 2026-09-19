# TAR Vault Sync Development Guide

## Technology direction

The production implementation is Rust-first:

- Rust core for provider clients, file rendering, validation, and agent lifecycle.
- Tokio for asynchronous polling and IPC.
- Tauri with a Rust-oriented UI framework for the on-demand configuration application.
- Native secure-store adapters for Windows, macOS, and Linux.

The agent must not depend on the UI process to stay alive.

## Agreed development environment

Development uses a local **Dev Container**. The host machine does not need Rust, Cargo, Visual Studio Build Tools, Node.js, Azure CLI, Google Cloud CLI, or other SDK toolchains. Docker Desktop and an editor capable of opening Dev Containers are the only local development prerequisites.

The container mounts the workspace and provides Rust stable, Cargo, Bash, formatting/linting tools, test tools, Git, and only the native libraries required for core Linux builds. All repository automation scripts must use Bash.

The Dev Container is the primary environment for fast functional validation: configuration parsing, provider adapters, secret-version polling, renderers, encrypted Drive/OneDrive vault behavior, atomic writes, and redacted NDJSON logs.

Native platform artifacts are not built inside the Linux Dev Container. GitHub Actions is responsible for final native builds and platform integration tests:

- Ubuntu: core checks and Linux artifacts.
- Windows: Windows agent, Credential Manager/Git Credential Manager integration, Tauri package, and installer artifacts.
- macOS: Keychain integration and macOS artifacts.

Before a release, download the Windows CI artifact and test it on a real Windows machine. This validates behavior that cannot be accurately reproduced inside the Dev Container, including Windows startup, DPAPI/Credential Manager, Git Credential Manager, and the native Tauri application.

## Suggested workspace layout

```text
crates/
  tarvaultsync-core/       # domain model, config, validation
  tarvaultsync-agent/      # daemon, scheduling, IPC
  tarvaultsync-providers/  # Azure, GCP, Drive, OneDrive
  tarvaultsync-renderers/  # dotenv, JSON, files, Git credentials
  tarvaultsync-ui/         # on-demand Tauri application
```

## Configuration lifecycle

1. Load `shared/config.json`.
2. Validate against a versioned JSON schema.
3. Verify `config.sig` when signature enforcement is enabled.
4. Resolve paths without allowing unsafe traversal outside an approved workspace or explicit target.
5. Persist only non-secret per-device runtime data in `local/state.json`.

Write every JSON file as `*.tmp`, flush it, validate it, then replace the destination atomically. A single agent process is the only writer of `state.json`.

## Provider contract

Every provider adapter exposes two operations:

```text
get_version(reference) -> SourceVersion
get_value(reference, version) -> SecretPayload
```

`get_version` must not request secret payload data. `get_value` is called only after a version change or explicit manual sync.

## Rendering contract

Renderers receive an explicit `SecretPayload` type and target specification. They must:

- never include a payload in an error message;
- render to a temporary sibling file when writing files;
- preserve unrelated structured-file fields;
- apply restrictive permissions for private material;
- treat binary payloads as bytes, not UTF-8 strings.

## Tests

Add unit tests for config validation, version comparison, target path validation, redaction, and every renderer. Add integration tests with fake providers and temporary directories. Test crashes and write failures to prove existing files are not corrupted.
