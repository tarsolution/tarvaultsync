# TAR Vault Sync

TAR Vault Sync is a planned local-first agent for keeping development secrets in sync across machines and project files. It is designed to read from Azure Key Vault, Google Secret Manager, or an optional encrypted vault stored in Google Drive or OneDrive, then apply the current values to configured local targets.

**Status:** Roadmap phases 2–5 provide a local encrypted vault, file and Docker renderers, a Git Credential Manager target, and an English native desktop interface. The release pipeline builds and tests Windows, macOS, and Linux on AMD64 and ARM64. Preview packages are published only after the complete matrix succeeds. External connectors and production IPC authentication remain roadmap work. See the [release notes](docs/release-notes.md) and [phase 2–5 QA record](docs/qa-phase2-5.md).

## Intended capabilities

- Run quietly in the background on Windows, macOS, and Linux, with an on-demand configuration UI.
- Map a secret source to a field in `.env`, JSON, YAML, properties, or Docker environment files; to a certificate or key file; or to a Git Credential Manager entry.
- Support strings, text, JSON, binary data, certificates, and private keys, including PEM, CRT, CA, P12, and PFX formats.
- Check provider version metadata before retrieving a changed value, then update the target safely.
- Keep configuration and device state in local JSON files and write redacted events to NDJSON logs.
- Optionally sync configuration through Google Drive or OneDrive. Secret values placed in those services must be encrypted on the device first.

The design has no TAR Vault Sync server or database. Configuration stores source references and target mappings; provider credentials stay in the operating system's secure store. Secret values are handled in memory during synchronization and written only to authorized targets.

## Development approach

The implementation is planned in Rust. Day-to-day development and core tests will run in a local Dev Container, so the host needs Docker Desktop and a Dev Container-capable editor rather than a local Rust or cloud SDK installation. Native Windows, macOS, and Linux builds will run in GitHub Actions. Repository scripts are Bash-based.

Run `cargo test --workspace` for the core and phase 2–5 tests. On a machine with a graphical desktop and Rust 1.95 or newer, set `TAR_VAULT_SYNC_DIR` to the workspace root and run `cargo run -- desktop`. The native window manages local-vault creation/unlock/lock, entry rotation/removal, encrypted backup/recovery, typed bindings, sync/status, restart acknowledgement, disabled-binding reactivation, and redacted events. It uses no browser or local HTTP server. The window runs the scheduler while open; the separate `agent` mode remains available for background operation and still uses the development-only `TAR_VAULT_SYNC_TEST_TOKEN` IPC credential. Do not treat that mode as production authentication. CLI vault/config commands remain available; see the [development guide](docs/development.md).

The Settings page can switch to an existing workspace root. Only one writer (`desktop` or `agent`) may own a workspace at a time. Download packages from [GitHub Releases](https://github.com/tarsolution/tarvaultsync/releases); each release includes all six builds and checksums. Open the executable without arguments to start the desktop app. Without `TAR_VAULT_SYNC_DIR`, it uses the platform's per-user application-data folder. `--help` and `--version` work without creating a workspace.

## Documentation

- [Design](docs/design.md)
- [Requirements](docs/requirements.md)
- [Development guide](docs/development.md)
- [Development environment](docs/development-environment.md)
- [Project history](docs/history.md)
- [Roadmap](docs/roadmap.md)
- [Contributing](docs/contributing.md)
- [AI development rules](AGENTS.md) and [project skill](skills/tarvaultsync-development/SKILL.md)

## Security

Do not commit real secrets, credentials, certificates, private keys, or logs containing sensitive values. See the [security boundaries](skills/tarvaultsync-development/references/secret-boundaries.md) and [contribution guide](docs/contributing.md) before proposing changes.
