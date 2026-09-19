# Development Environment

## Decision

TAR Vault Sync uses a local Dev Container for day-to-day development and GitHub Actions native runners for release builds. This keeps local developer machines free of SDK/toolchain installations while retaining trustworthy Windows, macOS, and Linux artifacts.

## Local prerequisites

- Docker Desktop
- A Dev Container-capable editor, if an editor is desired

Rust, Cargo, Visual Studio Build Tools, Node.js, Azure CLI, Google Cloud CLI, and provider SDK installations are not required on the host machine.

## Container responsibilities

The Dev Container will contain Rust stable, Cargo, Bash, Git, formatting/linting/test tooling, and required Linux build libraries. It mounts the repository so tests can safely render into dedicated test directories on the host-mounted workspace.

Use it to validate core behavior and integrations that are platform independent:

- config and state JSON validation;
- provider metadata/version logic;
- encrypted Drive/OneDrive vault handling;
- dotenv, JSON, YAML, properties, certificate, and binary renderers;
- retries, atomic writes, and redacted event logs.

## Native release responsibilities

GitHub Actions runs the native build matrix. Windows-specific functionality is built and tested on Windows, while macOS-specific functionality is built and tested on macOS. The Linux Dev Container must not be treated as proof that Windows service behavior, Windows Credential Manager, Git Credential Manager, or final Tauri installers work.

The release gate includes downloading and manually testing the Windows CI artifact on a real Windows machine.
