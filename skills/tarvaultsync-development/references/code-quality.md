# Code Quality Guide

## Choose simplicity deliberately

- Prefer a direct data flow over indirection. A new trait, generic, service layer, feature flag, or crate needs a present caller or a measurable reduction in complexity.
- Keep configuration schemas explicit and versioned. Reject invalid configuration rather than guessing intent.
- Use names that communicate domain intent: `SourceVersion`, `SecretPayload`, `TargetBinding`, and `SyncOutcome` are better than generic maps and strings.
- Keep structured formats round-trippable: preserve unrelated JSON/YAML/properties fields and comments whenever the chosen format supports it.
- Make retries and backoff localized to network/provider failures; do not retry validation or authorization failures blindly.

## Review checklist

- Is the change the smallest one that fulfills the request?
- Can an error leave a partially written target or stale state record?
- Could any secret bytes or secret-derived material reach an error, log, metric, test fixture, or debug formatter?
- Does the new code introduce an abstraction without at least two real consumers?
- Is a focused test needed to show the new contract or regression?

## Token-efficient investigation

- Search for the exact type, function, config field, or target format first.
- Read callers and tests before broad directory exploration.
- Do not restate large source files, dependency documentation, or command output in chat.
- Stop exploring once the relevant contract and call path are clear.
