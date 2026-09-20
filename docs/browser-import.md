# Browser password import: scope and acceptance

## Supported scope

Edge and Chrome document desktop CSV export/import flows. TAR Vault Sync uses a
user-selected export only; it never opens profile databases, extracts browser
encryption keys, or reads the user's signed-in browser session. No supported
third-party password-store write API has been verified for this project, so
continuous and bidirectional browser synchronization remain disabled.

- [Microsoft: export passwords in Edge](https://support.microsoft.com/en-us/edge/export-passwords-in-microsoft-edge)
- [Google: manage passwords in Chrome](https://support.google.com/chrome/answer/95606?hl=en)
- [Google: password CSV column requirements](https://support.google.com/accounts/answer/10500247?hl=en)

## Native desktop flow

Unlock the local vault. In **Vault → Import browser passwords**, enter the path
to a CSV you exported yourself and a unique non-secret prefix. Approve the
plaintext-file warning and select **Import CSV into vault**. Consent is cleared
after each attempt. Nothing is imported automatically on startup or by polling.

Required CSV headers are `url`, `username`, `password`; optional headers are
`name` and `note`/`notes`. UTF-8 with an optional BOM, quoted delimiters, escaped
quotes, and multiline fields are supported. Unknown/duplicate headers, malformed
quotes, inconsistent column counts, empty URLs/passwords, files over 8 MiB, and
imports over 1,000 records are rejected. Empty usernames are allowed.

Each row becomes one encrypted JSON entry named `prefix-0001`, `prefix-0002`, etc.
URL, username, password, name and notes remain inside that encrypted entry, not
in entry IDs, configuration, logs or status. Imported entries contain the entire
credential record; they are not automatically mapped to password-only targets.

The whole batch is committed in one encrypted vault replacement. Existing IDs
cause rejection of the entire batch. No credential comparison, automatic merge,
deduplication or deletion occurs. Reimport requires an explicitly different
prefix, or deliberate removal of previous entries. Duplicate rows within a file
are retained as separate entries. The plaintext source CSV is not copied or
automatically deleted: the user must remove it when no longer needed. Secure
erasure cannot be guaranteed on SSDs, backups, or synchronized folders.

## Verification status

Implementation and synthetic regression tests are in development. Actual Edge
and Chrome export-to-vault UI acceptance is still pending on Windows, macOS and
Linux. Unit tests and CI do not close these real-environment release gates.
No real user password export is required or authorized as a test fixture.

### Manual UI acceptance (isolated test workspace)

Use a new empty workspace and synthetic credentials only. Do not export your
everyday browser profile for testing. First validate the supplied CSV shape;
then repeat using an export from a separate browser test profile containing only
synthetic entries. Record OS, architecture, browser version, application commit,
and each outcome. Never attach passwords, CSV contents, or vault passphrases.

1. In the desktop app, create a test vault with a test-only passphrase.
2. Enter the synthetic CSV path and prefix `browser-test`. With consent unchecked,
   verify the import button is disabled. With the vault locked it must also be disabled.
3. Unlock, approve consent, and import. Verify the success count, cleared consent,
   and generated JSON entry IDs. No credential values should appear in messages.
4. Re-enter the same file and prefix and explicitly approve again. Verify rejection,
   unchanged entry count, and no silently overwritten data.
5. Try a malformed CSV and verify no partial entries appear. Lock, close, reopen,
   and unlock the app; previously imported IDs must remain available.
6. Confirm the original CSV still exists. Remove synthetic test data when finished;
   do not interpret deleting a CSV as guaranteed secure erasure.
