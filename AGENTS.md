# TAR Vault Sync: AI Development Contract

For implementation and review tasks, read the repository skill at `skills/tarvaultsync-development/SKILL.md` and its relevant references. This path is tracked in Git and is available in every clone.

TAR Vault Sync is a local-first Rust security agent. Prefer the smallest correct change that preserves its security model: secrets must never be persisted outside approved providers or encrypted vault payloads, and never appear in logs, diagnostics, state, tests, or examples.

## Working rules

- Read the relevant code and contract before editing; do not scan or summarize unrelated files.
- State the intended behavior and invariants briefly before making a non-trivial change.
- Reuse existing abstractions only when they reduce real duplication. Do not add layers, traits, configuration flags, or dependencies for hypothetical future use.
- Keep functions small when doing so makes ownership, error handling, or testing clearer. Do not split simple linear code merely to make more files.
- Favor explicit domain types and exhaustive enums at security boundaries. Avoid unstructured strings for provider references, target kinds, secret types, and sync outcomes.
- Use one clear error path with useful, redacted context. Never catch and ignore failures that affect a sync result.
- Keep public APIs narrow. Do not expose internal modules without a concrete caller.
- Change only the files needed for the request. Preserve user changes and avoid drive-by reformatting.

## Security and sync invariants

- Check source version metadata before retrieving a payload.
- Handle secret bytes as transient data; do not clone, serialize, log, display, hash, or include them in errors.
- Render through a temporary sibling file and atomic replacement. A failed render must leave the previous target unchanged.
- Store only redacted event fields in NDJSON logs and only non-secret state in `state.json`.
- Treat Drive/OneDrive shared configuration as untrusted input until schema and integrity checks pass.
- Never silently resolve configuration conflicts or write outside the configured target scope.

## Verification

- Run the narrowest relevant formatter, linter, and test set after a change.
- Add a regression test when a behavior change, bug fix, parser, renderer, provider boundary, or security invariant is involved.
- Do not claim tests passed unless they were run. Report skipped validation and why.

## Communication and token discipline

- Be concise. Report outcome, changed files, and verification; omit narration of routine commands.
- Ask one precise question only when a missing choice materially changes behavior or safety.
- Do not generate boilerplate documents, scaffolding, compatibility layers, or speculative tests unless the task requires them.
- Prefer an implementation over a lengthy plan when the requested change is clear and low risk.
