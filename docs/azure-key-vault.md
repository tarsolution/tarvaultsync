# Azure Key Vault development connector

The native desktop binding editor supports read-only **Azure public-cloud text secrets**. Select Azure Key Vault, enter the vault name and secret name, and configure an authorized local target. JSON/binary conversion, sovereign clouds, embedded sign-in, and the independent CLI background agent are not supported by this connector yet. Keep the desktop open for scheduled Azure sync.

## Authentication and scope

Install the official Azure CLI and sign in to the intended tenant using `az login` before opening the application. Azure CLI manages its own credential cache. The app requests a short-lived token for `https://vault.azure.net`; it does not store credentials in its configuration, logs, or state. It does not create accounts, resources, secrets, or role assignments. Grant only the required `secrets/list` and `secrets/get` access through your administrator.

Only vault/secret references and schedules enter shared configuration. Secret values are fetched directly over certificate-validated HTTPS, never by `az keyvault secret show`. CLI stderr, HTTP error bodies, tokens, and payloads are not displayed or logged. Network requests reject redirects; pagination stays on the same vault and secret. Credential acquisition is bounded to 20 seconds, HTTP requests to 15 seconds, response bodies to 256 KiB, and metadata traversal to 100 pages.

## Version contract

1. Read all version metadata pages without requesting values.
2. Select the most recently created version. Equal creation timestamps with different newest versions are rejected as ambiguous, not silently ordered. A disabled, expired, or not-yet-valid newest version fails closed; older versions are not substituted.
3. Skip value retrieval when the checked version is already applied.
4. Fetch exactly the checked version, validate its returned identity and validity, then use the existing atomic target writer. Failed reads/writes preserve the existing target and applied version.

Reference: Microsoft's [metadata-only version API](https://learn.microsoft.com/en-us/rest/api/keyvault/secrets/get-secret-versions/get-secret-versions) and [version-specific value API](https://learn.microsoft.com/en-us/rest/api/keyvault/secrets/get-secret/get-secret). API version: `2025-07-01`.

## Validation

Ordinary tests use synthetic responses and never contact Azure. They cover metadata pagination, unchanged-version suppression, rotation, authorization failure, wrong returned versions, invalid names, cross-host continuation links, expiry, and redacted persistent state/events. Desktop-controller tests cover saving, reopening, and editing Azure bindings without requiring a local vault.

The opt-in `azure::tests::live_azure_rotation_and_cleanup` test requires explicit spending/write approval. It creates only a unique `tarvaultsync-test-…` secret, checks two versions through the actual connector and target writer, verifies unchanged-version suppression and redaction, then soft-deletes that secret and verifies failed reads preserve the target. It never purges deleted secrets or reads existing secret values. It caps connector GETs at 20; creation, preflight, and cleanup add fewer than 10 operations. Set `TAR_VAULT_AZURE_LIVE_APPROVED=yes`, `TAR_VAULT_AZURE_TEST_VAULT`, and `TAR_VAULT_AZURE_TEST_SECRET`, then explicitly select the ignored test. It is excluded from routine CI.

### Real-account result — 2026-09-20

Passed on the Windows host using the Windows GNU test executable compiled in the Linux container and an existing, explicitly approved Azure vault. The complete successful run used 11 Key Vault requests: creation, first apply, metadata-only unchanged check, rotation/apply, soft-delete, bounded deletion convergence, and target preservation. Both synthetic secrets created during validation were soft-deleted; neither was purged. Existing secrets and access policies were not modified.

Two earlier checks exposed test assumptions: a nonexistent secret can return an empty version list instead of HTTP 404, and a successful delete may remain briefly visible in version metadata. The test now accepts only an empty/absent preflight and waits for bounded post-delete convergence. The connector did not read unrelated secret values or overwrite a target after source failure.

Local validation: Linux 39 unit tests plus one CLI test, Windows 39 unit tests, Clippy with warnings denied, and the packaging test passed. The live test is additional to those totals. Native macOS/Linux cloud authentication, embedded sign-in, independent CLI-agent support, and interactive UI acceptance remain open release gates. This evidence is not a release approval or an all-provider completion claim.
