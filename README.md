# TAR Vault Sync

TAR Vault Sync is a planned local-first agent for keeping development secrets in sync across machines and project files. It is designed to read from Azure Key Vault, Google Secret Manager, or an optional encrypted vault stored in Google Drive or OneDrive, then apply the current values to configured local targets.

**Status:** design and documentation stage. The agent, desktop UI, Dev Container, and release builds are not implemented yet.

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

There is no runnable build yet. Start with the [development guide](docs/development.md) and [development environment decision](docs/development-environment.md) before scaffolding the implementation.

## Documentation

- [Design](docs/design.md)
- [Requirements](docs/requirements.md)
- [Development guide](docs/development.md)
- [Development environment](docs/development-environment.md)
- [Project history](docs/history.md)
- [Contributing](docs/contributing.md)
- [AI development rules](AGENTS.md) and [project skill](skills/tarvaultsync-development/SKILL.md)

## Security

Do not commit real secrets, credentials, certificates, private keys, or logs containing sensitive values. See the [security boundaries](skills/tarvaultsync-development/references/secret-boundaries.md) and [contribution guide](docs/contributing.md) before proposing changes.
