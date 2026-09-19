# Phase 1 Independent QA

## Result

The phase 1 **fake-module test host** meets the core acceptance criteria in `requirements.md` and `roadmap.md`. It is not a production native agent: IPC authentication uses the explicitly named `TAR_VAULT_SYNC_TEST_TOKEN` environment variable, and the settings host is a CLI fixture rather than a native UI. Real providers, vaults, file targets, secure-store integration, and native platform packaging remain outside this phase.

| Criterion | QA result | Evidence |
| --- | --- | --- |
| 1. Typed contracts and fake modules | Pass for phase 1 | Typed source, version, payload, target, policy and outcome; registry rejects duplicate screens without replacing the existing registration and exposes store/target capabilities. |
| 2. Configuration and state | Pass for fake scope | Version and unknown/unsafe field rejection; safe labels and version checks; atomic state replacement and restart read. Windows replacement has code review only, without a Windows runner test. |
| 3. Metadata-first sync | Pass | Unchanged version avoids value read; changed version applies; failed apply preserves the last applied version and remains retryable. |
| 4. Scheduling | Pass for tested path | Manual and interval triggers share the engine lock. Paused-clock tests cover interval jitter and retry waiting; a concurrent trigger test covers single-flight. |
| 5. Authenticated IPC | Pass for test host | Loopback status, events and trigger requests; wrong token is rejected. Token storage is test-only and does not satisfy the later native secure-store design. |
| 6. Module settings host | Pass for lightweight host | Fake store and target own settings parsers and renderable CLI surfaces; a test builds a fixture through both, then runs manual IPC and scheduled sync. Native UI and interactive persistence remain later work. |
| 7. Redacted events | Pass for tested path | Typed operation/outcome fields, bounded rotation and recent-event view; probe payload and test token absent from state and events. Rotation has a focused test. |
| 8. Verification | Pass for available environment | After the duplicate-registration fix, root independently ran final Docker `cargo test --workspace`: 8 passed, 0 failed; `cargo fmt --all -- --check` and Clippy with `-D warnings` exited 0. QA reviewed code and test coverage independently. |

## Residual limits

- Native Windows/macOS/Linux behavior, including Windows atomic replacement and secure-store use, has not been exercised in platform tests.
- The CLI `config` mode emits a fake binding fixture for manual placement; it does not provide production configuration editing.
- IPC event reading loads the active log file before selecting the latest 100 records. Normal agent rotation bounds that file to about 1 MiB; a manually oversized local file is not separately capped on read.
- This QA agent's own Docker command was blocked by local Docker permission escalation; the execution evidence above is attributed to the root agent, while the code and tests were independently inspected here.
