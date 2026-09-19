---
name: tarvaultsync-development
description: Implement or review TAR Vault Sync Rust code with local-first secret-safety invariants, minimal maintainable designs, and targeted validation. Use for agent, provider, renderer, configuration, or UI changes in this repository.
---

# TAR Vault Sync Development

Build the smallest maintainable solution that satisfies the requested behavior. This is a security-sensitive local agent: secret payloads are transient and must never enter persistent state, diagnostics, tests, examples, or logs.

## Default workflow

1. Read `AGENTS.md` and only the files relevant to the requested behavior.
2. Identify the boundary being changed: configuration, provider metadata/value retrieval, renderer, local state, log, IPC, or UI.
3. Implement the narrowest clear design. Avoid new dependencies and abstractions unless they eliminate current, concrete complexity.
4. Verify only the affected surface. Use `scripts/preflight.sh` when the Rust workspace exists.
5. Report changed behavior, files, and actual verification results concisely.

## Non-negotiable invariants

- Query source version metadata before fetching a secret payload.
- Treat provider and Drive/OneDrive configuration as untrusted until validated.
- Never persist or expose secret content outside an authorized output target.
- Preserve existing target data on every failed write.
- Emit redacted, structured events only.

## References

- Read [code-quality.md](references/code-quality.md) for implementation and review choices.
- Read [secret-boundaries.md](references/secret-boundaries.md) for provider, renderer, state, and logging changes.

## Scope boundary

Do not use this skill for broad product planning, brand work, or unrelated documentation-only edits.
