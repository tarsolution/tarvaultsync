//! Encrypted Drive transport. Credentials never enter source configuration.
use crate::{
    cloud_auth,
    vault::{CipherStore, VaultError},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    io::Read,
    sync::Mutex,
    time::{Duration, Instant},
};
use url::Url;
use zeroize::Zeroizing;

pub(crate) const MAX_CIPHERTEXT: usize = 16 * 1024 * 1024;
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Provider {
    OneDrive,
    GoogleDrive,
}
impl Provider {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::OneDrive => "OneDrive",
            Self::GoogleDrive => "Google Drive",
        }
    }
    pub(crate) fn store(self) -> crate::core::StoreKind {
        match self {
            Self::OneDrive => crate::core::StoreKind::OneDrive,
            Self::GoogleDrive => crate::core::StoreKind::GoogleDrive,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DriveError {
    Authorization,
    CredentialStore,
    InvalidInput,
    Network,
    Conflict,
    InvalidResponse,
}
impl std::fmt::Display for DriveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Authorization => "Drive authorization failed or expired. Reconnect the account.",
            Self::CredentialStore => "The operating-system credential store is unavailable. No plaintext fallback is used.",
            Self::InvalidInput => "Invalid Drive selection or configuration.",
            Self::Network => "Drive request failed. Check connectivity and retry; no automatic overwrite was attempted.",
            Self::Conflict => "The remote vault changed. Reload it before retrying your edit.",
            Self::InvalidResponse => "Drive returned an unsupported or invalid response.",
        })
    }
}
impl From<DriveError> for VaultError {
    fn from(error: DriveError) -> Self {
        match error {
            DriveError::Conflict => Self::VersionConflict,
            DriveError::Authorization | DriveError::CredentialStore => Self::Locked,
            DriveError::InvalidInput | DriveError::InvalidResponse => Self::Corrupt,
            DriveError::Network => Self::Storage,
        }
    }
}
pub(crate) fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 256
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-!".contains(&b))
}
pub(crate) fn bounded(reader: impl Read, limit: usize) -> Result<Zeroizing<Vec<u8>>, DriveError> {
    let mut result = Zeroizing::new(Vec::new());
    reader
        .take(limit as u64 + 1)
        .read_to_end(&mut result)
        .map_err(|_| DriveError::Network)?;
    if result.len() > limit {
        return Err(DriveError::InvalidResponse);
    }
    Ok(result)
}
fn parse(bytes: &[u8]) -> Result<Value, DriveError> {
    serde_json::from_slice(bytes).map_err(|_| DriveError::InvalidResponse)
}
fn string(value: &Value, key: &str) -> Result<String, DriveError> {
    value[key]
        .as_str()
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
        .ok_or(DriveError::InvalidResponse)
}
fn checked_etag(etag: String) -> Result<String, DriveError> {
    if etag.len() > 1024
        || etag.starts_with("W/")
        || !etag.starts_with('"')
        || !etag.ends_with('"')
        || etag.bytes().any(|b| b.is_ascii_control())
    {
        return Err(DriveError::InvalidResponse);
    }
    Ok(etag)
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RemoteRef {
    pub provider: Provider,
    pub credential_id: String,
    pub file_id: String,
}
impl RemoteRef {
    pub(crate) fn validate(&self) -> bool {
        valid_id(&self.credential_id) && valid_id(&self.file_id)
    }
}
pub(crate) struct Item {
    pub id: String,
    pub name: String,
    pub folder: bool,
}
impl Item {
    fn parse(provider: Provider, value: &Value) -> Result<Self, DriveError> {
        let id = string(value, "id")?;
        if !valid_id(&id) {
            return Err(DriveError::InvalidResponse);
        }
        let name = string(
            value,
            if provider == Provider::OneDrive {
                "name"
            } else {
                "title"
            },
        )?;
        if name.len() > 1024 {
            return Err(DriveError::InvalidResponse);
        }
        Ok(Self {
            id,
            name,
            folder: if provider == Provider::OneDrive {
                value.get("folder").is_some()
            } else {
                value["mimeType"] == "application/vnd.google-apps.folder"
            },
        })
    }
}
pub(crate) struct Api {
    pub provider: Provider,
    pub credential_id: String,
    token: Mutex<Option<(Zeroizing<String>, Instant)>>,
    #[cfg(test)]
    script: Option<Mutex<std::collections::VecDeque<ScriptStep>>>,
}
impl Api {
    pub(crate) fn new(provider: Provider, credential_id: String) -> Self {
        Self {
            provider,
            credential_id,
            token: Mutex::new(None),
            #[cfg(test)]
            script: None,
        }
    }
    fn request(
        &self,
        method: &str,
        url: &str,
        body: &[u8],
        content_type: &str,
        condition: Option<&str>,
        limit: usize,
    ) -> Result<Zeroizing<Vec<u8>>, DriveError> {
        let expected_host = match self.provider {
            Provider::OneDrive => "graph.microsoft.com",
            Provider::GoogleDrive => "www.googleapis.com",
        };
        let parsed = Url::parse(url).map_err(|_| DriveError::InvalidInput)?;
        if parsed.scheme() != "https"
            || parsed.host_str() != Some(expected_host)
            || parsed.port().is_some()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
        {
            return Err(DriveError::InvalidInput);
        }
        let mut token = self.token.lock().map_err(|_| DriveError::Authorization)?;
        #[cfg(test)]
        if let Some(script) = &self.script {
            let step = script
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected request");
            assert_eq!(method, step.method);
            assert!(url.contains(step.url_part));
            assert_eq!(condition, step.condition);
            if method == "PUT" {
                assert!(body.starts_with(b"TVAULT02"));
            }
            return step.result.map(Zeroizing::new);
        }
        if token
            .as_ref()
            .is_none_or(|(_, at)| at.elapsed() > Duration::from_secs(300))
        {
            *token = Some((
                cloud_auth::access_token(self.provider, &self.credential_id)?,
                Instant::now(),
            ));
        }
        let authorization = Zeroizing::new(format!(
            "Bearer {}",
            token.as_ref().ok_or(DriveError::Authorization)?.0.as_str()
        ));
        let agent = cloud_auth::agent();
        macro_rules! headers {
            ($request:expr) => {{
                let mut request = $request
                    .header("Authorization", authorization.as_str())
                    .header("Content-Type", content_type);
                if let Some(etag) = condition {
                    request = request.header("If-Match", etag);
                }
                request
            }};
        }
        let result = match method {
            "GET" => headers!(agent.get(url)).call(),
            "PUT" => headers!(agent.put(url)).send(body),
            "POST" => headers!(agent.post(url)).send(body),
            #[cfg(test)]
            "DELETE" => headers!(agent.delete(url)).call(),
            _ => return Err(DriveError::InvalidInput),
        };
        let mut response = result.map_err(|error| match error {
            ureq::Error::StatusCode(401 | 403) => {
                *token = None;
                DriveError::Authorization
            }
            ureq::Error::StatusCode(409 | 412) => DriveError::Conflict,
            _ => DriveError::Network,
        })?;
        if !response.status().is_success() {
            return Err(DriveError::Network);
        }
        bounded(response.body_mut().as_reader(), limit)
    }
    fn metadata_url(&self, id: &str) -> Result<String, DriveError> {
        if !valid_id(id) {
            return Err(DriveError::InvalidInput);
        }
        Ok(match self.provider {
            Provider::OneDrive if id == "root" => "https://graph.microsoft.com/v1.0/me/drive/root".into(),
            Provider::OneDrive => format!("https://graph.microsoft.com/v1.0/me/drive/items/{id}"),
            Provider::GoogleDrive => format!("https://www.googleapis.com/drive/v2/files/{id}?fields=id,title,mimeType,etag,labels,fileSize,headRevisionId"),
        })
    }
    fn metadata(&self, id: &str) -> Result<Value, DriveError> {
        parse(&self.request(
            "GET",
            &self.metadata_url(id)?,
            &[],
            "application/json",
            None,
            256 * 1024,
        )?)
    }
    pub(crate) fn item(&self, id: &str) -> Result<Item, DriveError> {
        Item::parse(self.provider, &self.metadata(id)?)
    }
    pub(crate) fn children(&self, folder: &str) -> Result<Vec<Item>, DriveError> {
        if !valid_id(folder) {
            return Err(DriveError::InvalidInput);
        }
        let mut url = match self.provider {
            Provider::OneDrive => format!("https://graph.microsoft.com/v1.0/me/drive/items/{folder}/children?$top=200&$select=id,name,folder"),
            Provider::GoogleDrive => {
                let mut url = Url::parse("https://www.googleapis.com/drive/v2/files").map_err(|_| DriveError::InvalidInput)?;
                url.query_pairs_mut().append_pair("q", &format!("'{folder}' in parents and trashed = false"))
                    .append_pair("maxResults", "1000").append_pair("fields", "items(id,title,mimeType),nextPageToken");
                url.to_string()
            }
        };
        let first = url.clone();
        let mut items = Vec::new();
        for _ in 0..100 {
            let value =
                parse(&self.request("GET", &url, &[], "application/json", None, 1024 * 1024)?)?;
            let key = if self.provider == Provider::OneDrive {
                "value"
            } else {
                "items"
            };
            for item in value[key].as_array().ok_or(DriveError::InvalidResponse)? {
                items.push(Item::parse(self.provider, item)?);
            }
            if items.len() > 10_000 {
                return Err(DriveError::InvalidResponse);
            }
            if self.provider == Provider::OneDrive {
                match value["@odata.nextLink"].as_str() {
                    Some(next) => url = next.into(),
                    None => return Ok(items),
                }
            } else {
                match value["nextPageToken"].as_str() {
                    Some(next) => {
                        let mut next_url =
                            Url::parse(&first).map_err(|_| DriveError::InvalidResponse)?;
                        next_url.query_pairs_mut().append_pair("pageToken", next);
                        url = next_url.into();
                    }
                    None => return Ok(items),
                }
            }
        }
        Err(DriveError::InvalidResponse)
    }
    fn etag(&self, metadata: &Value) -> Result<String, DriveError> {
        if metadata.get("deleted").is_some() || metadata["labels"]["trashed"] == true {
            return Err(DriveError::InvalidResponse);
        }
        let item = Item::parse(self.provider, metadata)?;
        if item.folder {
            return Err(DriveError::InvalidInput);
        }
        checked_etag(string(
            metadata,
            if self.provider == Provider::OneDrive {
                "eTag"
            } else {
                "etag"
            },
        )?)
    }
    pub(crate) fn create(
        &self,
        folder: &str,
        name: &str,
        ciphertext: &[u8],
    ) -> Result<RemoteRef, DriveError> {
        if !valid_id(folder)
            || name.is_empty()
            || name.len() > 128
            || !name.ends_with(".tarvault")
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            || ciphertext.len() > MAX_CIPHERTEXT
            || !ciphertext.starts_with(b"TVAULT02")
        {
            return Err(DriveError::InvalidInput);
        }
        if !self.item(folder)?.folder {
            return Err(DriveError::InvalidInput);
        }
        let response = match self.provider {
            Provider::OneDrive => self.request("PUT", &format!("https://graph.microsoft.com/v1.0/me/drive/items/{folder}:/{name}:/content?@microsoft.graph.conflictBehavior=fail"), ciphertext, "application/octet-stream", None, 256 * 1024)?,
            Provider::GoogleDrive => {
                let boundary = cloud_auth::random_id();
                let metadata = json!({"title": name, "mimeType": "application/octet-stream", "parents": [{"id": folder}]});
                let mut body = format!("--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n{metadata}\r\n--{boundary}\r\nContent-Type: application/octet-stream\r\n\r\n").into_bytes();
                body.extend_from_slice(ciphertext);
                body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
                self.request("POST", "https://www.googleapis.com/upload/drive/v2/files?uploadType=multipart", &body, &format!("multipart/related; boundary={boundary}"), None, 256 * 1024)?
            }
        };
        let file_id = string(&parse(&response)?, "id")?;
        if !valid_id(&file_id) {
            return Err(DriveError::InvalidResponse);
        }
        Ok(RemoteRef {
            provider: self.provider,
            credential_id: self.credential_id.clone(),
            file_id,
        })
    }
}

// Two concrete backends (Drive and local filesystem) share the vault cryptography.
pub(crate) struct RemoteFile {
    api: Api,
    id: String,
    state: Mutex<Option<(String, Vec<u8>)>>,
}
impl RemoteFile {
    pub(crate) fn new(reference: &RemoteRef) -> Result<Self, DriveError> {
        if !reference.validate() {
            return Err(DriveError::InvalidInput);
        }
        Ok(Self {
            api: Api::new(reference.provider, reference.credential_id.clone()),
            id: reference.file_id.clone(),
            state: Mutex::new(None),
        })
    }
    fn read_remote(&self) -> Result<Vec<u8>, DriveError> {
        let mut state = self.state.lock().map_err(|_| DriveError::Network)?;
        let metadata = self.api.metadata(&self.id)?;
        let etag = self.api.etag(&metadata)?;
        if let Some((cached, bytes)) = &*state {
            if *cached == etag {
                return Ok(bytes.clone());
            }
        }
        let bytes = match self.api.provider {
            Provider::GoogleDrive => {
                // Metadata and media representations have different ETags. Pin the
                // payload to the revision observed before retrieval instead.
                let revision = string(&metadata, "headRevisionId")?;
                if !valid_id(&revision) {
                    return Err(DriveError::InvalidResponse);
                }
                self.api.request(
                    "GET",
                    &format!(
                        "https://www.googleapis.com/drive/v2/files/{}?alt=media&revisionId={revision}",
                        self.id
                    ),
                    &[],
                    "application/octet-stream",
                    None,
                    MAX_CIPHERTEXT,
                )?
            }
            Provider::OneDrive => {
                let download = string(&metadata, "@microsoft.graph.downloadUrl")?;
                check_download_url(&download)?;
                // Preauthenticated URL: never forward the Graph bearer token to a CDN.
                let mut response = cloud_auth::agent()
                    .get(&download)
                    .call()
                    .map_err(|_| DriveError::Network)?;
                if !response.status().is_success() {
                    return Err(DriveError::Network);
                }
                bounded(response.body_mut().as_reader(), MAX_CIPHERTEXT)?
            }
        };
        if !bytes.starts_with(b"TVAULT02") {
            return Err(DriveError::InvalidResponse);
        }
        if self.api.etag(&self.api.metadata(&self.id)?)? != etag {
            return Err(DriveError::Conflict);
        }
        // Only ciphertext is cached; LocalVault authenticates it before using entries.
        *state = Some((etag, bytes.to_vec()));
        Ok(bytes.to_vec())
    }
    fn write_remote(&self, bytes: &[u8]) -> Result<(), DriveError> {
        if bytes.len() > MAX_CIPHERTEXT || !bytes.starts_with(b"TVAULT02") {
            return Err(DriveError::InvalidInput);
        }
        let mut state = self.state.lock().map_err(|_| DriveError::Network)?;
        let etag = &state.as_ref().ok_or(DriveError::Conflict)?.0;
        let url = match self.api.provider {
            Provider::OneDrive => format!(
                "https://graph.microsoft.com/v1.0/me/drive/items/{}/content",
                self.id
            ),
            Provider::GoogleDrive => format!(
                "https://www.googleapis.com/upload/drive/v2/files/{}?uploadType=media",
                self.id
            ),
        };
        self.api.request(
            "PUT",
            &url,
            bytes,
            "application/octet-stream",
            Some(etag),
            256 * 1024,
        )?;
        // Force the next read to obtain the server's committed revision, never guess it.
        *state = None;
        Ok(())
    }
}
impl CipherStore for RemoteFile {
    fn disconnect(&self) -> Result<(), VaultError> {
        *self.api.token.lock().map_err(|_| VaultError::Locked)? = None;
        *self.state.lock().map_err(|_| VaultError::Locked)? = None;
        cloud_auth::disconnect(&self.api.credential_id).map_err(Into::into)
    }
    fn read(&self) -> Result<Vec<u8>, VaultError> {
        self.read_remote().map_err(Into::into)
    }
    fn replace(&self, bytes: &[u8]) -> Result<(), VaultError> {
        self.write_remote(bytes).map_err(Into::into)
    }
}
fn check_download_url(value: &str) -> Result<(), DriveError> {
    let url = Url::parse(value).map_err(|_| DriveError::InvalidResponse)?;
    let host = url.host_str().ok_or(DriveError::InvalidResponse)?;
    if url.scheme() != "https"
        || url.port().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || ![".1drv.com", ".sharepoint.com", ".storage.live.com"]
            .iter()
            .any(|suffix| host.ends_with(suffix))
    {
        return Err(DriveError::InvalidResponse);
    }
    Ok(())
}

#[cfg(test)]
struct ScriptStep {
    method: &'static str,
    url_part: &'static str,
    condition: Option<&'static str>,
    result: Result<Vec<u8>, DriveError>,
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "interactive Microsoft sign-in; creates and trashes only an isolated synthetic vault"]
    fn live_onedrive_encrypted_roundtrip_and_conflict() {
        live_roundtrip(Provider::OneDrive, Zeroizing::new(String::new()));
    }
    #[test]
    #[ignore = "interactive Google Picker; requires TAR_VAULT_GOOGLE_CLIENT_FILE and a selected test folder"]
    fn live_google_encrypted_roundtrip_and_conflict() {
        live_roundtrip(
            Provider::GoogleDrive,
            cloud_auth::tests::test_google_client_secret().unwrap(),
        );
    }
    fn live_roundtrip(provider: Provider, client_secret: Zeroizing<String>) {
        use crate::core::{SecretPayload, SecretType, SourceConnection, SourceRef, StoreKind};
        use crate::vault::{LocalVault, VaultSource};
        use std::sync::Arc;
        eprintln!("Opening provider OAuth consent for the TAR Vault Sync Desktop app.");
        let login = cloud_auth::login(provider, client_secret).unwrap();
        let api = Api::new(login.provider, login.credential_id.clone());
        let dir = tempfile::tempdir().unwrap();
        let seed_path = dir.path().join("synthetic.tarvault");
        let passphrase = Zeroizing::new(cloud_auth::random_id());
        let mut seed = LocalVault::create(&seed_path, &passphrase).unwrap();
        let ciphertext = std::fs::read(&seed_path).unwrap();
        let filename = format!(
            "tarvaultsync-test-{}.tarvault",
            &cloud_auth::random_id()[..12]
        );
        let created = (|| {
            let selected = if provider == Provider::GoogleDrive {
                login.picked.as_deref().ok_or(DriveError::InvalidInput)?
            } else {
                "root"
            };
            let root = api.item(selected)?;
            api.create(&root.id, &filename, &ciphertext)
        })();
        let reference = match created {
            Ok(reference) => reference,
            Err(error) => {
                cloud_auth::disconnect(&login.credential_id).unwrap();
                panic!("Live vault creation failed: {error}");
            }
        };
        let result = (|| -> Result<(), String> {
            let first = RemoteFile::new(&reference).map_err(|e| e.to_string())?;
            let second = RemoteFile::new(&reference).map_err(|e| e.to_string())?;
            first
                .read_remote()
                .map_err(|e| format!("initial download: {e}"))?;
            second
                .read_remote()
                .map_err(|e| format!("second download: {e}"))?;
            seed.put(
                "sample",
                &SecretPayload::new(vec![1, 2, 3], SecretType::Binary),
            )
            .map_err(|e| e.to_string())?;
            let updated = std::fs::read(&seed_path).map_err(|_| "fixture read failed")?;
            second
                .write_remote(&updated)
                .map_err(|e| format!("first conditional update: {e}"))?;
            if first.write_remote(&ciphertext) != Err(DriveError::Conflict) {
                return Err("Provider did not reject stale If-Match".into());
            }
            eprintln!("PASS: provider rejects a stale conditional write.");
            let remote = Arc::new(RemoteFile::new(&reference).map_err(|e| e.to_string())?);
            let source =
                VaultSource::remote(dir.path().join("never-cached.bin"), "live".into(), remote)
                    .map_err(|e| e.to_string())?;
            source.unlock(&passphrase).map_err(|e| e.to_string())?;
            let entry = SourceRef {
                store: StoreKind::LocalVault,
                connection: "live".into(),
                entry: "sample".into(),
            };
            let old = source.get_version(&entry).map_err(|e| e.to_string())?;
            if source
                .get_value(&entry, &old)
                .map_err(|e| e.to_string())?
                .as_bytes()
                != [1, 2, 3]
            {
                return Err("Payload mismatch".into());
            }
            source
                .put_entry(
                    "sample",
                    &SecretPayload::new(vec![4, 5, 6], SecretType::Binary),
                )
                .map_err(|e| e.to_string())?;
            let current = source.get_version(&entry).map_err(|e| e.to_string())?;
            if current == old
                || source
                    .get_value(&entry, &current)
                    .map_err(|e| e.to_string())?
                    .as_bytes()
                    != [4, 5, 6]
            {
                return Err("Rotation mismatch".into());
            }
            source.lock();
            source.unlock(&passphrase).map_err(|e| e.to_string())?;
            if source.get_version(&entry).map_err(|e| e.to_string())? != current {
                return Err("Reopen mismatch".into());
            }
            if dir.path().join("never-cached.bin").exists() {
                return Err("Unexpected local cache".into());
            }
            eprintln!("PASS: encrypted upload, authenticated download, rotation, lock and reopen.");
            Ok(())
        })();
        let cleanup = if provider == Provider::GoogleDrive {
            api.request(
                "POST",
                &format!(
                    "https://www.googleapis.com/drive/v2/files/{}/trash",
                    reference.file_id
                ),
                &[],
                "application/json",
                None,
                256 * 1024,
            )
        } else {
            api.request(
                "DELETE",
                &format!(
                    "https://graph.microsoft.com/v1.0/me/drive/items/{}",
                    reference.file_id
                ),
                &[],
                "application/json",
                None,
                1024,
            )
        };
        let disconnected = cloud_auth::disconnect(&login.credential_id);
        if cleanup.is_err() {
            eprintln!("Cleanup required for synthetic file: {filename}");
        }
        cleanup.unwrap();
        disconnected.unwrap();
        eprintln!(
            "PASS: synthetic vault moved to provider trash; temporary OAuth credential removed."
        );
        result.unwrap();
    }
    #[test]
    fn google_metadata_first_skips_unchanged_download_and_conditionally_writes() {
        let metadata = serde_json::to_vec(&json!({"id":"file", "title":"vault.tarvault", "mimeType":"application/octet-stream", "etag":"\"v1\"", "headRevisionId":"revision1"})).unwrap();
        let step = |method, url_part, condition, result| ScriptStep {
            method,
            url_part,
            condition,
            result,
        };
        let mut api = Api::new(Provider::GoogleDrive, "test".into());
        api.script = Some(Mutex::new(
            [
                step("GET", "fields=", None, Ok(metadata.clone())),
                step(
                    "GET",
                    "alt=media&revisionId=revision1",
                    None,
                    Ok(b"TVAULT02encrypted-fixture".to_vec()),
                ),
                step("GET", "fields=", None, Ok(metadata.clone())),
                step("GET", "fields=", None, Ok(metadata)),
                step(
                    "PUT",
                    "uploadType=media",
                    Some("\"v1\""),
                    Err(DriveError::Conflict),
                ),
            ]
            .into(),
        ));
        let remote = RemoteFile {
            api,
            id: "file".into(),
            state: Mutex::new(None),
        };
        assert!(remote.read_remote().is_ok());
        assert!(remote.read_remote().is_ok());
        assert_eq!(
            remote.write_remote(b"TVAULT02new-ciphertext"),
            Err(DriveError::Conflict)
        );
        assert!(remote
            .api
            .script
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .is_empty());
        assert_eq!(remote.state.lock().unwrap().as_ref().unwrap().0, "\"v1\"");
    }
    #[test]
    fn google_download_requires_a_valid_revision_and_rejects_concurrent_change() {
        for revision in [None, Some("../invalid"), Some("revision1")] {
            let mut metadata = json!({"id":"file", "title":"vault.tarvault", "mimeType":"application/octet-stream", "etag":"\"v1\""});
            if let Some(revision) = revision {
                metadata["headRevisionId"] = json!(revision);
            }
            let mut steps = vec![ScriptStep {
                method: "GET",
                url_part: "fields=",
                condition: None,
                result: Ok(serde_json::to_vec(&metadata).unwrap()),
            }];
            if revision == Some("revision1") {
                steps.push(ScriptStep {
                    method: "GET",
                    url_part: "alt=media&revisionId=revision1",
                    condition: None,
                    result: Ok(b"TVAULT02encrypted-fixture".to_vec()),
                });
                metadata["etag"] = json!("\"v2\"");
                steps.push(ScriptStep {
                    method: "GET",
                    url_part: "fields=",
                    condition: None,
                    result: Ok(serde_json::to_vec(&metadata).unwrap()),
                });
            }
            let mut api = Api::new(Provider::GoogleDrive, "test".into());
            api.script = Some(Mutex::new(steps.into()));
            let remote = RemoteFile {
                api,
                id: "file".into(),
                state: Mutex::new(None),
            };
            let expected = if revision == Some("revision1") {
                DriveError::Conflict
            } else {
                DriveError::InvalidResponse
            };
            assert_eq!(remote.read_remote(), Err(expected));
            assert!(remote.state.lock().unwrap().is_none());
            assert!(remote
                .api
                .script
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .is_empty());
        }
    }
    #[test]
    fn onedrive_write_carries_the_observed_etag_and_never_retries_conflict() {
        let mut api = Api::new(Provider::OneDrive, "test".into());
        api.script = Some(Mutex::new(
            [ScriptStep {
                method: "PUT",
                url_part: "/items/file/content",
                condition: Some("\"v1\""),
                result: Err(DriveError::Conflict),
            }]
            .into(),
        ));
        let remote = RemoteFile {
            api,
            id: "file".into(),
            state: Mutex::new(Some(("\"v1\"".into(), b"TVAULT02old".to_vec()))),
        };
        assert_eq!(
            remote.write_remote(b"TVAULT02new"),
            Err(DriveError::Conflict)
        );
        assert!(remote
            .api
            .script
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .is_empty());
    }
    #[test]
    fn rejects_injected_references_and_download_urls() {
        for id in ["", "../x", "a/b", "x?q=1", "a%2fb"] {
            assert!(!valid_id(id));
        }
        for url in [
            "http://x.1drv.com/a",
            "https://127.0.0.1/a",
            "https://evil.test/a",
            "https://x.1drv.com.evil.test/a",
            "https://user@x.1drv.com/a",
        ] {
            assert!(check_download_url(url).is_err());
        }
        assert!(check_download_url("https://x.1drv.com/a?token=opaque").is_ok());
        assert!(checked_etag("W/\"weak\"".into()).is_err());
        assert!(checked_etag("\"revision\"".into()).is_ok());
        assert!(bounded(&b"oversized"[..], 2).is_err());
    }
}
