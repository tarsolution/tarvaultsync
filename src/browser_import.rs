//! Explicit, one-way import of a user-selected browser CSV into an encrypted vault.
//! No browser profile access, background import, plaintext output, or payload logging.

use crate::{
    core::{safe_label, SecretPayload, SecretType},
    vault::VaultSource,
};
use csv_core::{ReadRecordResult, Reader};
use std::{collections::BTreeMap, fs::File, io::Read, path::Path};
use zeroize::{Zeroize, Zeroizing};

const MAX_BYTES: usize = 8 * 1024 * 1024;

pub(crate) fn import_file(
    source: &VaultSource,
    path: &Path,
    prefix: &str,
    consent: bool,
) -> Result<usize, &'static str> {
    if !consent {
        return Err("Explicit import consent is required.");
    }
    if !source.is_unlocked() {
        return Err("Unlock the vault before importing.");
    }
    if !safe_label(prefix) || prefix.len() > 48 {
        return Err(
            "Use a unique import prefix of 1–48 letters, numbers, dots, dashes or underscores.",
        );
    }
    let file = File::open(path).map_err(|_| "Could not open the selected CSV.")?;
    let metadata = file
        .metadata()
        .map_err(|_| "Could not read the selected CSV.")?;
    if !metadata.is_file() || metadata.len() > MAX_BYTES as u64 {
        return Err("Select a regular CSV file no larger than 8 MiB.");
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Could not read the selected CSV.")?;
    let entries = parse(&bytes, prefix)?;
    source.import_entries(&entries).map_err(|_| "Import failed: the vault may be locked, storage unavailable, or the prefix already used. No entries were imported.")?;
    Ok(entries.len())
}

fn parse(bytes: &[u8], prefix: &str) -> Result<Vec<(String, SecretPayload)>, &'static str> {
    const INVALID: &str = "Invalid browser CSV. No entries were imported.";
    if bytes.is_empty() || bytes.len() > MAX_BYTES || !safe_label(prefix) || prefix.len() > 48 {
        return Err(INVALID);
    }
    let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes);
    strict_quotes(bytes)?;
    let mut input = bytes;
    let mut parser = Reader::new();
    let mut output = Zeroizing::new(vec![0; bytes.len() + 1]);
    let mut ends = [0; 6];
    let (mut written, mut fields) = (0, 0);
    let mut columns: Option<Vec<&'static str>> = None;
    let mut entries = Vec::new();
    loop {
        let (result, used, produced, count) =
            parser.read_record(input, &mut output[written..], &mut ends[fields..]);
        input = &input[used..];
        written += produced;
        fields += count;
        match result {
            ReadRecordResult::InputEmpty => continue,
            ReadRecordResult::End => break,
            ReadRecordResult::OutputFull | ReadRecordResult::OutputEndsFull => return Err(INVALID),
            ReadRecordResult::Record => {
                let mut start = 0;
                let mut values = Vec::new();
                for end in &ends[..fields] {
                    values.push(std::str::from_utf8(&output[start..*end]).map_err(|_| INVALID)?);
                    start = *end;
                }
                if let Some(columns) = &columns {
                    if fields != columns.len() || entries.len() >= 1000 {
                        return Err(INVALID);
                    }
                    let record: BTreeMap<_, _> = columns.iter().copied().zip(values).collect();
                    if record["url"].is_empty() || record["password"].is_empty() {
                        return Err(INVALID);
                    }
                    let mut json = Zeroizing::new(Vec::new());
                    serde_json::to_writer(&mut *json, &record).map_err(|_| INVALID)?;
                    entries.push((
                        format!("{prefix}-{:04}", entries.len() + 1),
                        SecretPayload::new(std::mem::take(&mut *json), SecretType::Json),
                    ));
                } else {
                    let mut names = Vec::new();
                    for value in values {
                        let name = match value {
                            "name" => "name",
                            "url" => "url",
                            "username" => "username",
                            "password" => "password",
                            "note" | "notes" => "notes",
                            _ => return Err(INVALID),
                        };
                        if names.contains(&name) {
                            return Err(INVALID);
                        }
                        names.push(name);
                    }
                    if !["url", "username", "password"]
                        .iter()
                        .all(|name| names.contains(name))
                    {
                        return Err(INVALID);
                    }
                    columns = Some(names);
                }
                output[..written].zeroize();
                written = 0;
                fields = 0;
            }
        }
    }
    if entries.is_empty() {
        return Err(INVALID);
    }
    Ok(entries)
}

// csv-core deliberately accepts malformed quoting. Reject it before decoding so
// an incomplete export cannot silently change a password or discard a column.
fn strict_quotes(bytes: &[u8]) -> Result<(), &'static str> {
    enum State {
        Start,
        Plain,
        Quoted,
        Closed,
    }
    let mut state = State::Start;
    for byte in bytes {
        state = match (&state, byte) {
            (State::Start, b'"') => State::Quoted,
            (State::Start | State::Plain | State::Closed, b',' | b'\r' | b'\n') => State::Start,
            (State::Plain, b'"') => return Err("Malformed CSV quoting. No entries were imported."),
            (State::Quoted, b'"') => State::Closed,
            (State::Closed, b'"') => State::Quoted,
            (State::Closed, _) => return Err("Malformed CSV quoting. No entries were imported."),
            (State::Quoted, _) => State::Quoted,
            _ => State::Plain,
        };
    }
    if matches!(state, State::Quoted) {
        return Err("Incomplete CSV. No entries were imported.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_exports_preserve_quoted_values_without_revealing_them() {
        for input in [
            "name,url,username,password\r\nsample,https://example.invalid,user,\"synthetic,\"\"quoted\"\"\"\r\n",
            "\u{feff}name,url,username,password,notes\nsample,https://example.invalid,user,\"synthetic,\"\"quoted\"\"\",\"line1\nline2\"",
        ] {
            let entries = parse(input.as_bytes(), "import").unwrap();
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].0, "import-0001");
            let mut decoded: BTreeMap<String, String> = serde_json::from_slice(entries[0].1.as_bytes()).unwrap();
            assert!(decoded["password"] == "synthetic,\"quoted\"");
            for value in decoded.values_mut() { value.zeroize(); }
        }
    }

    #[test]
    fn invalid_exports_fail_closed() {
        for input in [
            "url,username,password\n",
            "url,username,password\na,b,",
            "url,username,password\na,b,\"unfinished",
            "url,username,password\na,b,\"closed\"garbage",
            "url,username,password\na,b,un\"quoted",
            "url,username,password,password\na,b,c,d",
            "url,username,password\na,b,c,d",
            "url,username,password,extra\na,b,c,d",
            "url,password\na,b",
        ] {
            assert!(parse(input.as_bytes(), "import").is_err());
        }
        assert!(parse(b"url,username,password\na,b,c", "bad/prefix").is_err());
    }

    #[test]
    fn explicit_consent_and_unlock_are_required_before_reading() {
        let dir = tempfile::tempdir().unwrap();
        let source = VaultSource::new(dir.path().join("vault.bin"), "local".into()).unwrap();
        assert!(import_file(&source, Path::new("missing.csv"), "import", false).is_err());
        assert!(import_file(&source, Path::new("missing.csv"), "import", true).is_err());
        assert!(!source.exists());
    }

    #[test]
    fn batch_is_encrypted_and_conflicts_do_not_change_the_vault() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.bin");
        let mut vault = crate::vault::LocalVault::create(&path, "test-only-passphrase").unwrap();
        let entries = parse(
            b"url,username,password\nhttps://example.invalid,user,synthetic-probe",
            "import",
        )
        .unwrap();
        vault.import_new(&entries).unwrap();
        let before = std::fs::read(&path).unwrap();
        assert!(!before.windows(15).any(|part| part == b"synthetic-probe"));
        let mut conflict = parse(b"url,username,password\na,b,c", "fresh").unwrap();
        conflict.extend(parse(b"url,username,password\na,b,c", "import").unwrap());
        assert!(vault.import_new(&conflict).is_err());
        assert_eq!(before, std::fs::read(&path).unwrap());
        assert_eq!(vault.entries().unwrap().len(), 1);
    }

    #[test]
    fn file_import_is_all_or_nothing_and_leaves_source_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let source = VaultSource::new(dir.path().join("vault.bin"), "local".into()).unwrap();
        source.create("test-only-passphrase").unwrap();
        let csv = dir.path().join("synthetic.csv");
        let invalid = b"url,username,password\nhttps://example.invalid,user,synthetic\na,b,";
        std::fs::write(&csv, invalid).unwrap();
        let before = std::fs::read(dir.path().join("vault.bin")).unwrap();
        assert!(import_file(&source, &csv, "browser", true).is_err());
        assert_eq!(before, std::fs::read(dir.path().join("vault.bin")).unwrap());
        let valid = b"url,username,password\nhttps://example.invalid,user,synthetic\n";
        std::fs::write(&csv, valid).unwrap();
        assert_eq!(import_file(&source, &csv, "browser", true).unwrap(), 1);
        assert!(std::fs::read(&csv).unwrap() == valid);
        assert!(import_file(&source, &csv, "browser", true).is_err());
        assert_eq!(source.entries().unwrap().len(), 1);
    }

    #[test]
    fn oversized_input_and_record_count_are_rejected() {
        assert!(parse(&vec![b'a'; MAX_BYTES + 1], "import").is_err());
        let input = format!("url,username,password\n{}", "a,b,c\n".repeat(1001));
        assert!(parse(input.as_bytes(), "import").is_err());
    }

    #[test]
    fn encrypted_write_limit_rolls_back_entire_batch() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.bin");
        let mut vault = crate::vault::LocalVault::create(&path, "test-only-passphrase").unwrap();
        let before = std::fs::read(&path).unwrap();
        let entries: Vec<_> = (0..2)
            .map(|i| {
                (
                    format!("entry-{i}"),
                    SecretPayload::new(vec![0; MAX_BYTES / 2], SecretType::Binary),
                )
            })
            .collect();
        assert!(vault.import_new(&entries).is_err());
        assert_eq!(before, std::fs::read(&path).unwrap());
        assert!(vault.entries().unwrap().is_empty());
    }
}
