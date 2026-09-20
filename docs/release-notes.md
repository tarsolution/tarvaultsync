# TAR Vault Sync desktop preview

Native desktop builds for Windows, macOS, and Linux, each in AMD64/x64 and ARM64.
This release candidate includes filesystem, Azure Key Vault, OneDrive, and Google Drive sources.
It is not a claim that every roadmap connector or production-hardening task is complete.

## Included

- English desktop interface for vault access, bindings, activity, and workspace settings.
- Encrypted local vault, locking, secret rotation, encrypted backup and recovery.
- File, dotenv, JSON, YAML, properties, Docker input, and Git Credential Manager targets.
- Scheduled and manual sync with redacted events and explicit restart notices.
- Native OAuth/PKCE setup for OneDrive and Google Drive encrypted vaults in a selected folder.
- OS-protected OAuth credentials, revision-pinned Google downloads, and conditional cloud writes.
- Explicit-consent browser CSV import and Azure public-cloud text-secret sources.

## Start

Extract the archive. On Windows, open `tar-vault-sync.exe`; on macOS, open `TAR Vault Sync.app`;
on Linux, run `./tar-vault-sync` from the extracted directory. No arguments opens the desktop app.
`--help` lists command-line modes; `--version` prints the build version.

The default workspace is `%LOCALAPPDATA%/tar-vault-sync` on Windows,
`~/Library/Application Support/tar-vault-sync` on macOS, or
`${XDG_DATA_HOME:-~/.local/share}/tar-vault-sync` on Linux.
Set `TAR_VAULT_SYNC_DIR` to use an existing workspace. File targets must be inside that workspace.

Linux packages target Ubuntu 24.04 or a compatible glibc system and require a graphical session,
OpenGL/EGL, X11 or Wayland, and desktop libraries (`libx11-6`, `libxkbcommon0`, `libegl1`, `libgl1`).
Git credential targets require Git Credential Manager to be installed and configured separately.

## Verification and limits

CI runs native tests, compiles the release binary, and executes `--version` on all six runner architectures.
Each archive has a SHA-256 checksum in `SHA256SUMS`. Checksums detect corruption; they are not publisher signatures.
These archives are not code-signed or notarized and are not installers.

Windows real-account OneDrive and Google Drive tests passed: encrypted create/read/update,
stale-write rejection, lock/reopen, and test-file cleanup. Live OAuth acceptance on macOS
and Linux remains unverified; CI native tests are not a substitute for those account tests.
Linux OAuth storage requires an unlocked Secret Service keyring. Google setup requires
the configured desktop OAuth client's secret in the masked field; it is never bundled.
Azure requires an existing Azure CLI sign-in; native embedded sign-in remains open.
AWS/Google secret-manager sources and a Git-backed vault remain roadmap work.
Signed distribution is not included.
The independent CLI agent still uses development IPC authentication; the desktop app runs its scheduler while open.
