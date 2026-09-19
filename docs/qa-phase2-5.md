# Phase 2–5 QA record

The PO/architect review kept these boundaries explicit: vault payloads are authenticated ciphertext at rest; source metadata is checked before payload retrieval; file writes stay within the configured root and replace atomically; Docker writes report a restart requirement rather than implying a running container changed; Git credentials go to an OS-backed GCM store, never a plaintext credentials file.

Developer and QA verification on 2026-09-19:

| Slice | Evidence | Remaining gate |
| --- | --- | --- |
| Local vault | Create/unlock/edit/lock, rotation, encrypted backup/recovery, wrong passphrase, tampering, metadata-only version check, and concurrent writers covered by tests. | Native desktop entry screen and platform file-permission checks. |
| File sync | Whole-file binary and `.env`, JSON, YAML, properties field tests; unrelated content and failed-write preservation checked. An end-to-end local-vault rotation updates an authorized file. | Windows/macOS target write and ACL checks. |
| Docker sync | Compose environment and declared `env_file` path tests; restart-required and acknowledgement state tested. | Docker runtime integration and native-platform checks; Docker secrets and restart hooks intentionally not implemented. |
| Git credentials | Windows synthetic GCM store/get/erase and repository-path isolation checks; target rejects binary payloads and requires path-aware Git configuration for path scope. | Integrated agent-to-GCM rotation test on each supported OS, including macOS/Linux secure-store availability. |

The repository preflight (`fmt`, Clippy, and workspace tests) passed after the desktop work: 22 tests, 0 failures. Windows GCM smoke records used reserved `.invalid` hosts and were erased after each check. No real credential was used.

The native management window was added after the initial phase 2–5 QA run. A Linux/Xvfb launch rendered the empty-workspace overview without browser or HTTP server, and the desktop binding/config tests passed. Native Windows/macOS builds and interactive visual QA remain open; the new build workflow has not yet run. The separate development agent still authenticates IPC through `TAR_VAULT_SYNC_TEST_TOKEN`; there is no packaged installer or native secure-store IPC adapter. These limits remain open before real-secret deployment.
