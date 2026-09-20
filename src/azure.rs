//! Read-only Azure public-cloud secrets. Authentication belongs to Azure CLI;
//! values travel directly over HTTPS, never through CLI output or its logs.

use crate::core::{
    ErrorCategory, SecretPayload, SecretType, SourceConnection, SourceRef, SourceVersion, StoreKind,
};
use serde::Deserialize;
use std::{
    io::Read,
    process::{Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use url::Url;
use zeroize::Zeroizing;

pub(crate) struct DesktopSources {
    pub(crate) local: std::sync::Arc<crate::vault::VaultSource>,
    pub(crate) azure: AzureSource,
}
impl SourceConnection for DesktopSources {
    fn get_version(&self, source: &SourceRef) -> Result<SourceVersion, ErrorCategory> {
        match source.store {
            StoreKind::LocalVault => self.local.get_version(source),
            StoreKind::Azure => self.azure.get_version(source),
            _ => Err(ErrorCategory::InvalidConfig),
        }
    }
    fn get_value(
        &self,
        source: &SourceRef,
        version: &SourceVersion,
    ) -> Result<SecretPayload, ErrorCategory> {
        match source.store {
            StoreKind::LocalVault => self.local.get_value(source, version),
            StoreKind::Azure => self.azure.get_value(source, version),
            _ => Err(ErrorCategory::InvalidConfig),
        }
    }
}

const API_VERSION: &str = "2025-07-01";
const MAX_RESPONSE: u64 = 256 * 1024;
const MAX_PAGES: usize = 100;

pub(crate) fn valid_source(source: &SourceRef) -> bool {
    source.store == StoreKind::Azure
        && (3..=24).contains(&source.connection.len())
        && source.connection.as_bytes()[0].is_ascii_alphabetic()
        && source
            .connection
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
        && !source.connection.contains("--")
        && source
            .connection
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && (1..=127).contains(&source.entry.len())
        && source
            .entry
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

// Kept private: the test transport exercises the real parser and source contract
// without granting tests network access or reading an Azure CLI credential cache.
trait Transport: Send + Sync {
    fn get(&self, url: &str) -> Result<Zeroizing<Vec<u8>>, ErrorCategory>;
}

pub(crate) struct AzureSource {
    transport: Box<dyn Transport>,
}

impl AzureSource {
    pub(crate) fn new() -> Self {
        Self {
            transport: Box::new(HttpsTransport),
        }
    }
}

struct HttpsTransport;
impl Transport for HttpsTransport {
    fn get(&self, url: &str) -> Result<Zeroizing<Vec<u8>>, ErrorCategory> {
        let token = cli_token()?;
        let token = std::str::from_utf8(&token)
            .map_err(|_| ErrorCategory::Unauthorized)?
            .trim();
        if token.is_empty()
            || token
                .bytes()
                .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
        {
            return Err(ErrorCategory::Unauthorized);
        }
        let authorization = Zeroizing::new(format!("Bearer {token}"));
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(15)))
            .max_redirects(0)
            .https_only(true)
            .build()
            .new_agent();
        let mut response = agent
            .get(url)
            .header("Authorization", authorization.as_str())
            .header("Accept", "application/json")
            .call()
            .map_err(|e| match e {
                ureq::Error::StatusCode(401 | 403) => ErrorCategory::Unauthorized,
                _ => ErrorCategory::Source,
            })?;
        if response.status().as_u16() != 200 {
            return Err(ErrorCategory::Source);
        }
        read_bounded(response.body_mut().as_reader(), MAX_RESPONSE)
    }
}

fn read_bounded(reader: impl Read, limit: u64) -> Result<Zeroizing<Vec<u8>>, ErrorCategory> {
    let mut data = Zeroizing::new(Vec::new());
    reader
        .take(limit + 1)
        .read_to_end(&mut data)
        .map_err(|_| ErrorCategory::Source)?;
    if data.len() as u64 > limit {
        return Err(ErrorCategory::Source);
    }
    Ok(data)
}

fn cli_token() -> Result<Zeroizing<Vec<u8>>, ErrorCategory> {
    let mut command = Command::new(if cfg!(windows) { "az.cmd" } else { "az" });
    command
        .args([
            "account",
            "get-access-token",
            "--resource",
            "https://vault.azure.net",
            "--query",
            "accessToken",
            "--output",
            "tsv",
            "--only-show-errors",
        ])
        .env("AZURE_CORE_COLLECT_TELEMETRY", "false")
        .env("AZURE_CORE_LOG_LEVEL", "critical")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }
    let mut child = command.spawn().map_err(|_| ErrorCategory::Unauthorized)?;
    let stdout = child.stdout.take().ok_or(ErrorCategory::Unauthorized)?;
    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let _ = sender.send(read_bounded(stdout, 16 * 1024));
    });
    let deadline = Instant::now() + Duration::from_secs(20);
    let result = loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => {
                break receiver
                    .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                    .map_err(|_| ErrorCategory::Unauthorized)
                    .and_then(|result| result.map_err(|_| ErrorCategory::Unauthorized));
            }
            Ok(Some(_)) | Err(_) => break Err(ErrorCategory::Unauthorized),
            Ok(None) if Instant::now() >= deadline => break Err(ErrorCategory::Unauthorized),
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
        }
    };
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}

#[derive(Deserialize)]
struct Attributes {
    created: u64,
    enabled: bool,
    exp: Option<u64>,
    nbf: Option<u64>,
}
impl Attributes {
    fn usable(&self, now: u64) -> bool {
        self.enabled
            && self.exp.is_none_or(|exp| now < exp)
            && self.nbf.is_none_or(|nbf| now >= nbf)
    }
}
#[derive(Deserialize)]
struct VersionItem {
    id: String,
    attributes: Attributes,
}
#[derive(Deserialize)]
struct VersionPage {
    value: Vec<VersionItem>,
    #[serde(rename = "nextLink")]
    next_link: Option<String>,
}
#[derive(Deserialize)]
struct SecretResponse {
    id: String,
    attributes: Attributes,
    #[serde(deserialize_with = "secret_string")]
    value: Zeroizing<String>,
}
fn secret_string<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(d).map(Zeroizing::new)
}
fn now() -> Result<u64, ErrorCategory> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| ErrorCategory::Source)
}
fn base_url(source: &SourceRef) -> Result<String, ErrorCategory> {
    if !valid_source(source) {
        return Err(ErrorCategory::InvalidConfig);
    }
    Ok(format!(
        "https://{}.vault.azure.net/secrets/{}",
        source.connection.to_ascii_lowercase(),
        source.entry
    ))
}
fn valid_version(version: &str) -> bool {
    version.len() == 32 && version.bytes().all(|b| b.is_ascii_hexdigit())
}
fn version_from_id(base: &str, id: &str) -> Result<String, ErrorCategory> {
    let prefix = format!("{base}/");
    let version = id
        .strip_prefix(&prefix)
        .ok_or(ErrorCategory::VersionConflict)?;
    if !valid_version(version) {
        return Err(ErrorCategory::VersionConflict);
    }
    Ok(version.to_owned())
}
fn checked_next(base: &str, next: &str) -> Result<(), ErrorCategory> {
    let expected = Url::parse(&format!("{base}/versions")).map_err(|_| ErrorCategory::Source)?;
    let url = Url::parse(next).map_err(|_| ErrorCategory::Source)?;
    if url.scheme() != "https"
        || url.host_str() != expected.host_str()
        || url.port_or_known_default() != Some(443)
        || url.path() != expected.path()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(ErrorCategory::Source);
    }
    Ok(())
}

impl SourceConnection for AzureSource {
    fn get_version(&self, source: &SourceRef) -> Result<SourceVersion, ErrorCategory> {
        let base = base_url(source)?;
        let mut url = format!("{base}/versions?api-version={API_VERSION}&maxresults=25");
        let mut latest: Option<VersionItem> = None;
        let mut ambiguous = false;
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..MAX_PAGES {
            if !seen.insert(url.clone()) {
                return Err(ErrorCategory::Source);
            }
            let bytes = self.transport.get(&url)?;
            let page: VersionPage =
                serde_json::from_slice(&bytes).map_err(|_| ErrorCategory::Source)?;
            for item in page.value {
                version_from_id(&base, &item.id)?;
                match &latest {
                    Some(old) if item.attributes.created < old.attributes.created => {}
                    Some(old) if item.attributes.created == old.attributes.created => {
                        if item.id != old.id {
                            ambiguous = true;
                        }
                    }
                    _ => {
                        latest = Some(item);
                        ambiguous = false;
                    }
                }
            }
            if let Some(next) = page.next_link {
                checked_next(&base, &next)?;
                url = next;
            } else {
                let latest = latest.ok_or(ErrorCategory::Source)?;
                if ambiguous {
                    return Err(ErrorCategory::VersionConflict);
                }
                if !latest.attributes.usable(now()?) {
                    return Err(ErrorCategory::Source);
                }
                return version_from_id(&base, &latest.id).map(SourceVersion);
            }
        }
        Err(ErrorCategory::Source)
    }
    fn get_value(
        &self,
        source: &SourceRef,
        version: &SourceVersion,
    ) -> Result<SecretPayload, ErrorCategory> {
        let base = base_url(source)?;
        if !valid_version(&version.0) {
            return Err(ErrorCategory::InvalidConfig);
        }
        let bytes = self
            .transport
            .get(&format!("{base}/{}?api-version={API_VERSION}", version.0))?;
        let mut response: SecretResponse =
            serde_json::from_slice(&bytes).map_err(|_| ErrorCategory::Source)?;
        if version_from_id(&base, &response.id)? != version.0 {
            return Err(ErrorCategory::VersionConflict);
        }
        if !response.attributes.usable(now()?) {
            return Err(ErrorCategory::Source);
        }
        Ok(SecretPayload::new(
            std::mem::take(&mut *response.value).into_bytes(),
            SecretType::Text,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
    };
    const V1: &str = "11111111111111111111111111111111";
    const V2: &str = "22222222222222222222222222222222";
    const BASE: &str = "https://test-vault.vault.azure.net/secrets/test-secret";

    // Explicitly opt-in: never runs in ordinary CI or reads existing secrets.
    #[test]
    #[ignore = "requires approved Azure synthetic-secret writes and Azure CLI sign-in"]
    fn live_azure_rotation_and_cleanup() {
        use crate::{
            core::{
                Binding, Config, Engine, MissingTargetPolicy, Schedule, SyncOutcome, TargetSpec,
            },
            targets::ProductionTarget,
        };
        assert_eq!(
            std::env::var("TAR_VAULT_AZURE_LIVE_APPROVED").as_deref(),
            Ok("yes")
        );
        let reference = SourceRef {
            store: StoreKind::Azure,
            connection: std::env::var("TAR_VAULT_AZURE_TEST_VAULT").expect("test vault required"),
            entry: std::env::var("TAR_VAULT_AZURE_TEST_SECRET")
                .expect("unique test secret required"),
        };
        assert!(reference.entry.starts_with("tarvaultsync-test-"));
        let base = base_url(&reference).unwrap();
        let token = cli_token().unwrap();
        let token = std::str::from_utf8(&token).unwrap().trim();
        let authorization = Zeroizing::new(format!("Bearer {token}"));
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(15)))
            .max_redirects(0)
            .https_only(true)
            .build()
            .new_agent();
        let missing = agent
            .get(&format!("{base}/versions?api-version={API_VERSION}"))
            .header("Authorization", authorization.as_str())
            .call();
        match missing {
            Err(ureq::Error::StatusCode(404)) => {}
            Ok(mut response) if response.status().as_u16() == 200 => {
                let bytes = read_bounded(response.body_mut().as_reader(), MAX_RESPONSE).unwrap();
                let page: VersionPage =
                    serde_json::from_slice(&bytes).expect("invalid metadata preflight response");
                assert!(
                    page.value.is_empty() && page.next_link.is_none(),
                    "test name already exists"
                );
            }
            Err(ureq::Error::StatusCode(code)) => {
                panic!("metadata preflight denied: HTTP {code}; no secret was created")
            }
            _ => panic!("metadata preflight transport failed; no secret was created"),
        }
        struct Cleanup<'a> {
            agent: &'a ureq::Agent,
            authorization: &'a str,
            url: String,
            pending: bool,
        }
        impl Cleanup<'_> {
            fn remove(&mut self) -> bool {
                if !self.pending {
                    return true;
                }
                match self
                    .agent
                    .delete(&self.url)
                    .header("Authorization", self.authorization)
                    .call()
                {
                    Ok(response) if response.status().is_success() => {
                        self.pending = false;
                        true
                    }
                    _ => false,
                }
            }
        }
        impl Drop for Cleanup<'_> {
            fn drop(&mut self) {
                if !self.remove() {
                    eprintln!("Synthetic Azure test cleanup failed; manual removal is required.");
                }
            }
        }
        let url = format!("{base}?api-version={API_VERSION}");
        // Arm before PUT: a network timeout can follow a successful server write.
        let mut cleanup = Cleanup {
            agent: &agent,
            authorization: authorization.as_str(),
            url: url.clone(),
            pending: true,
        };
        eprintln!("Synthetic Azure test secret: {}", reference.entry);
        let put = |body: &'static [u8]| {
            let mut response = agent
                .put(&url)
                .header("Authorization", authorization.as_str())
                .header("Content-Type", "application/json")
                .send(body)
                .map_err(|_| ErrorCategory::Source)?;
            let bytes = read_bounded(response.body_mut().as_reader(), MAX_RESPONSE)?;
            let response: SecretResponse =
                serde_json::from_slice(&bytes).map_err(|_| ErrorCategory::Source)?;
            version_from_id(&base, &response.id)
        };
        let first =
            put(br#"{"value":"synthetic-azure-integration-one","attributes":{"enabled":true}}"#)
                .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("authorized-test-target.txt");
        std::fs::write(&path, "initial").unwrap();
        struct Counted {
            calls: Arc<std::sync::atomic::AtomicUsize>,
        }
        impl Transport for Counted {
            fn get(&self, url: &str) -> Result<Zeroizing<Vec<u8>>, ErrorCategory> {
                if self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) >= 20 {
                    return Err(ErrorCategory::Source);
                }
                HttpsTransport.get(url)
            }
        }
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let source = AzureSource {
            transport: Box::new(Counted {
                calls: calls.clone(),
            }),
        };
        let config = Config {
            version: 1,
            bindings: vec![Binding {
                id: "live-azure".into(),
                source: reference.clone(),
                secret_type: SecretType::Text,
                target: TargetSpec::WholeFile { path: path.clone() },
                missing_target: MissingTargetPolicy::Alert,
                schedule: Schedule {
                    interval_seconds: 60,
                },
            }],
        };
        let engine = Engine::new(
            config,
            dir.path().join("state.json"),
            dir.path().join("events.ndjson"),
            Arc::new(source),
            Arc::new(ProductionTarget::new(dir.path().to_path_buf()).unwrap()),
        )
        .unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        assert_eq!(
            runtime.block_on(engine.sync("live-azure")),
            SyncOutcome::Applied
        );
        assert_eq!(engine.status().applied["live-azure"].0, first);
        let before = calls.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            runtime.block_on(engine.sync("live-azure")),
            SyncOutcome::Unchanged
        );
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst) - before,
            1,
            "unchanged version must only read metadata"
        );
        // Azure timestamps have second precision; avoid an intentionally ambiguous tie.
        std::thread::sleep(Duration::from_secs(2));
        let second =
            put(br#"{"value":"synthetic-azure-integration-two","attributes":{"enabled":true}}"#)
                .unwrap();
        assert_ne!(first, second);
        assert_eq!(
            runtime.block_on(engine.sync("live-azure")),
            SyncOutcome::Applied
        );
        assert_eq!(engine.status().applied["live-azure"].0, second);
        let target = Zeroizing::new(std::fs::read(&path).unwrap());
        assert!(target.as_slice() == b"synthetic-azure-integration-two");
        for path in [&engine.state_path, &engine.events_path] {
            assert!(!std::fs::read_to_string(path)
                .unwrap()
                .contains("synthetic-azure-integration-"));
        }
        assert!(cleanup.remove(), "synthetic secret deletion failed");
        // Azure deletion is eventually visible to metadata listing. Do not
        // mistake an immediately repeated old metadata snapshot for a failed delete.
        let mut deletion_visible = false;
        for _ in 0..10 {
            match runtime.block_on(engine.sync("live-azure")) {
                SyncOutcome::Failed(ErrorCategory::Source) => {
                    deletion_visible = true;
                    break;
                }
                SyncOutcome::Unchanged => std::thread::sleep(Duration::from_secs(2)),
                _ => panic!("unexpected post-deletion sync result"),
            }
        }
        assert!(
            deletion_visible,
            "deleted secret metadata did not converge within the bounded check"
        );
        assert_eq!(engine.status().applied["live-azure"].0, second);
        assert!(Zeroizing::new(std::fs::read(&path).unwrap()).as_slice() == target.as_slice());
        eprintln!("Azure rotation, unchanged-version, redaction, deletion and target-preservation checks passed; synthetic secret soft-deleted.");
        eprintln!(
            "Key Vault test requests: {}",
            calls.load(std::sync::atomic::Ordering::SeqCst) + 4
        );
    }

    struct Scripted {
        replies: Mutex<VecDeque<(&'static str, Result<String, ErrorCategory>)>>,
        calls: Arc<Mutex<Vec<String>>>,
    }
    impl Transport for Scripted {
        fn get(&self, url: &str) -> Result<Zeroizing<Vec<u8>>, ErrorCategory> {
            self.calls.lock().unwrap().push(url.to_owned());
            let (suffix, response) = self
                .replies
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected request");
            assert!(url.contains(suffix));
            response.map(|v| Zeroizing::new(v.into_bytes()))
        }
    }
    fn reference() -> SourceRef {
        SourceRef {
            store: StoreKind::Azure,
            connection: "test-vault".into(),
            entry: "test-secret".into(),
        }
    }
    fn page(version: &str, created: u64) -> String {
        format!(
            r#"{{"value":[{{"id":"{BASE}/{version}","attributes":{{"created":{created},"enabled":true}}}}]}}"#
        )
    }
    fn value(version: &str) -> String {
        format!(
            r#"{{"id":"{BASE}/{version}","attributes":{{"created":10,"enabled":true}},"value":"synthetic-azure-probe"}}"#
        )
    }
    fn scripted(
        replies: Vec<(&'static str, Result<String, ErrorCategory>)>,
    ) -> (AzureSource, Arc<Mutex<Vec<String>>>) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        (
            AzureSource {
                transport: Box::new(Scripted {
                    replies: Mutex::new(replies.into()),
                    calls: calls.clone(),
                }),
            },
            calls,
        )
    }

    #[test]
    fn endpoint_validation_rejects_injection_and_cross_host_pagination() {
        for vault in [
            "a",
            "-vault",
            "vault-",
            "a--b",
            "test.vault",
            "x/../../",
            "a&echo",
            "a%PATH%",
        ] {
            let mut source = reference();
            source.connection = vault.into();
            assert!(!valid_source(&source));
        }
        for entry in ["", "../secret", "secret?query", "x#y", "a_b"] {
            let mut source = reference();
            source.entry = entry.into();
            assert!(!valid_source(&source));
        }
        for next in [
            "http://test-vault.vault.azure.net/secrets/test-secret/versions",
            "https://attacker.invalid/secrets/test-secret/versions",
            "https://test-vault.vault.azure.net/secrets/other/versions",
            "https://user@test-vault.vault.azure.net/secrets/test-secret/versions",
            "https://test-vault.vault.azure.net:444/secrets/test-secret/versions",
        ] {
            assert!(checked_next(BASE, next).is_err());
        }
        assert!(checked_next(
            BASE,
            &format!("{BASE}/versions?api-version={API_VERSION}&$skiptoken=opaque")
        )
        .is_ok());
        assert!(read_bounded(&b"oversized"[..], 3).is_err());
    }

    #[test]
    fn paginated_metadata_selects_latest_and_never_reads_value() {
        let first = page(V1, 10).trim_end_matches('}').to_owned()
            + &format!(
                r#", "nextLink":"{BASE}/versions?api-version={API_VERSION}&$skiptoken=next"}}"#
            );
        let (source, calls) = scripted(vec![
            ("/versions?", Ok(first)),
            ("$skiptoken=next", Ok(page(V2, 20))),
        ]);
        assert_eq!(source.get_version(&reference()).unwrap().0, V2);
        assert_eq!(calls.lock().unwrap().len(), 2);
        assert!(calls
            .lock()
            .unwrap()
            .iter()
            .all(|url| url.contains("/versions?")));
    }

    #[test]
    fn ambiguous_disabled_expired_and_untrusted_metadata_fail_closed() {
        let tied = format!(
            r#"{{"value":[{{"id":"{BASE}/{V1}","attributes":{{"created":10,"enabled":true}}}},{{"id":"{BASE}/{V2}","attributes":{{"created":10,"enabled":true}}}}]}}"#
        );
        for response in [
            tied,
            page(V1, 10).replace("true", "false"),
            page(V1, 10).replace("\"enabled\":true", "\"enabled\":true,\"exp\":1"),
            page(V1, 10).replace(
                "\"enabled\":true",
                "\"enabled\":true,\"nbf\":18446744073709551615",
            ),
            page(V1, 10).replace(BASE, "https://attacker.invalid/secrets/secret"),
            "{\"value\":[]}".into(),
            "not json".into(),
        ] {
            let (source, calls) = scripted(vec![("/versions?", Ok(response))]);
            assert!(source.get_version(&reference()).is_err());
            assert_eq!(calls.lock().unwrap().len(), 1);
        }
        let malicious_next = r#"{"value":[],"nextLink":"https://attacker.invalid/"}"#.to_owned();
        let (source, calls) = scripted(vec![("/versions?", Ok(malicious_next))]);
        assert!(source.get_version(&reference()).is_err());
        assert_eq!(calls.lock().unwrap().len(), 1);
    }

    #[test]
    fn value_is_pinned_to_checked_version_and_failures_are_redacted() {
        let (source, _) = scripted(vec![(V1, Ok(value(V2)))]);
        assert!(matches!(
            source.get_value(&reference(), &SourceVersion(V1.into())),
            Err(ErrorCategory::VersionConflict)
        ));
        let (source, _) = scripted(vec![(V1, Ok("synthetic-azure-probe malformed".into()))]);
        let error = source
            .get_value(&reference(), &SourceVersion(V1.into()))
            .err()
            .unwrap();
        assert_eq!(error.to_string(), "Source");
        let (source, calls) = scripted(vec![]);
        assert!(source
            .get_value(&reference(), &SourceVersion("../latest".into()))
            .is_err());
        assert!(calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn engine_rotation_skips_unchanged_payload_and_preserves_target_on_failure() {
        use crate::{
            core::{
                Binding, Config, Engine, MissingTargetPolicy, Schedule, SyncOutcome, TargetSpec,
            },
            targets::ProductionTarget,
        };
        let (source, calls) = scripted(vec![
            ("/versions?", Ok(page(V1, 10))),
            (V1, Ok(value(V1))),
            ("/versions?", Ok(page(V1, 10))),
            ("/versions?", Ok(page(V2, 20))),
            (V2, Err(ErrorCategory::Unauthorized)),
            ("/versions?", Ok(page(V2, 20))),
            (V2, Ok(value(V2))),
        ]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("authorized-target.txt");
        std::fs::write(&path, "old").unwrap();
        let config = Config {
            version: 1,
            bindings: vec![Binding {
                id: "azure-test".into(),
                source: reference(),
                secret_type: SecretType::Text,
                target: TargetSpec::WholeFile { path: path.clone() },
                missing_target: MissingTargetPolicy::Alert,
                schedule: Schedule {
                    interval_seconds: 60,
                },
            }],
        };
        let config_bytes = serde_json::to_vec(&config).unwrap();
        crate::core::validate_config(&config_bytes, dir.path()).unwrap();
        let engine = Engine::new(
            config,
            dir.path().join("state.json"),
            dir.path().join("events.ndjson"),
            Arc::new(source),
            Arc::new(ProductionTarget::new(dir.path().to_path_buf()).unwrap()),
        )
        .unwrap();
        assert_eq!(engine.sync("azure-test").await, SyncOutcome::Applied);
        assert_eq!(engine.sync("azure-test").await, SyncOutcome::Unchanged);
        assert_eq!(calls.lock().unwrap().len(), 3);
        assert_eq!(
            engine.sync("azure-test").await,
            SyncOutcome::Failed(ErrorCategory::Unauthorized)
        );
        assert_eq!(engine.status().applied["azure-test"].0, V1);
        let data = Zeroizing::new(std::fs::read(&path).unwrap());
        assert!(data.as_slice() == b"synthetic-azure-probe");
        assert_eq!(engine.sync("azure-test").await, SyncOutcome::Applied);
        assert_eq!(engine.status().applied["azure-test"].0, V2);
        for path in [&engine.state_path, &engine.events_path] {
            assert!(!std::fs::read_to_string(path)
                .unwrap()
                .contains("synthetic-azure-probe"));
        }
        assert!(!String::from_utf8(config_bytes)
            .unwrap()
            .contains("synthetic-azure-probe"));
    }
}
