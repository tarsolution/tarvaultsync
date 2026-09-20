//! Native OAuth: PKCE, a one-shot loopback callback, and OS credential storage.
use crate::drive::{DriveError, Provider};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    net::TcpListener,
    time::{Duration, Instant},
};
use url::Url;
use zeroize::{Zeroize, Zeroizing};

const MICROSOFT_CLIENT: &str = "18435542-f783-44d8-9c63-c92e18bb46cb";
const GOOGLE_CLIENT: &str =
    "60346833173-iu18a5o5ki37208rijd998e0gltihrvj.apps.googleusercontent.com";

#[derive(Serialize, Deserialize)]
struct Credential {
    provider: Provider,
    refresh_token: String,
    client_secret: String,
}
impl Drop for Credential {
    fn drop(&mut self) {
        self.refresh_token.zeroize();
        self.client_secret.zeroize();
    }
}
#[derive(Deserialize)]
struct Tokens {
    access_token: String,
    refresh_token: Option<String>,
    token_type: String,
}
impl Drop for Tokens {
    fn drop(&mut self) {
        self.access_token.zeroize();
        if let Some(token) = &mut self.refresh_token {
            token.zeroize();
        }
    }
}
pub(crate) struct Login {
    pub provider: Provider,
    pub credential_id: String,
    pub picked: Option<String>,
}

pub(crate) fn random_id() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
fn endpoints(provider: Provider) -> (&'static str, &'static str, &'static str, &'static str) {
    match provider {
        Provider::OneDrive => (
            MICROSOFT_CLIENT,
            "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
            "https://login.microsoftonline.com/common/oauth2/v2.0/token",
            "offline_access Files.ReadWrite",
        ),
        Provider::GoogleDrive => (
            GOOGLE_CLIENT,
            "https://accounts.google.com/o/oauth2/v2/auth",
            "https://oauth2.googleapis.com/token",
            "https://www.googleapis.com/auth/drive.file",
        ),
    }
}
pub(crate) fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .https_only(true)
        .max_redirects(0)
        .timeout_global(Some(Duration::from_secs(30)))
        .build()
        .new_agent()
}
fn credential_entry(id: &str) -> Result<keyring::Entry, DriveError> {
    if !crate::drive::valid_id(id) {
        return Err(DriveError::InvalidInput);
    }
    keyring::Entry::new("TAR Vault Sync OAuth", id).map_err(|_| DriveError::CredentialStore)
}
fn save(id: &str, credential: &Credential) -> Result<(), DriveError> {
    let encoded =
        Zeroizing::new(serde_json::to_string(credential).map_err(|_| DriveError::CredentialStore)?);
    if encoded.len() > 64 * 1024 {
        return Err(DriveError::CredentialStore);
    }
    let previous = head(id)?;
    let next = CredentialHead {
        generation: random_id(),
        chunks: encoded.len().div_ceil(2000),
    };
    // Windows limits each credential blob to 2560 bytes. The small head is the
    // commit point: a failed chunk write leaves the previous generation readable.
    let write = (|| {
        for (index, chunk) in encoded.as_bytes().chunks(2000).enumerate() {
            credential_entry(&chunk_id(id, &next, index))?
                .set_secret(chunk)
                .map_err(|_| DriveError::CredentialStore)?;
        }
        credential_entry(id)?
            .set_password(&serde_json::to_string(&next).map_err(|_| DriveError::CredentialStore)?)
            .map_err(|_| DriveError::CredentialStore)
    })();
    if write.is_err() {
        remove_chunks(id, &next)?;
        return write;
    }
    if let Some(previous) = previous {
        remove_chunks(id, &previous)?;
    }
    Ok(())
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialHead {
    generation: String,
    chunks: usize,
}
fn head(id: &str) -> Result<Option<CredentialHead>, DriveError> {
    let value = match credential_entry(id)?.get_password() {
        Ok(value) => Zeroizing::new(value),
        Err(keyring::Error::NoEntry) => return Ok(None),
        Err(_) => return Err(DriveError::CredentialStore),
    };
    let head: CredentialHead =
        serde_json::from_str(&value).map_err(|_| DriveError::CredentialStore)?;
    if !crate::drive::valid_id(&head.generation) || !(1..=33).contains(&head.chunks) {
        return Err(DriveError::CredentialStore);
    }
    Ok(Some(head))
}
fn chunk_id(id: &str, head: &CredentialHead, index: usize) -> String {
    format!("{id}-{}-{index}", head.generation)
}
fn remove_entry(id: &str) -> Result<(), DriveError> {
    match credential_entry(id)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(_) => Err(DriveError::CredentialStore),
    }
}
fn remove_chunks(id: &str, head: &CredentialHead) -> Result<(), DriveError> {
    for index in 0..head.chunks {
        remove_entry(&chunk_id(id, head, index))?;
    }
    Ok(())
}
fn read_credential(id: &str) -> Result<Zeroizing<Vec<u8>>, DriveError> {
    let head = head(id)?.ok_or(DriveError::Authorization)?;
    let mut bytes = Zeroizing::new(Vec::new());
    for index in 0..head.chunks {
        let chunk = Zeroizing::new(
            credential_entry(&chunk_id(id, &head, index))?
                .get_secret()
                .map_err(|_| DriveError::CredentialStore)?,
        );
        if chunk.len() > 2000 {
            return Err(DriveError::CredentialStore);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
pub(crate) fn disconnect(id: &str) -> Result<(), DriveError> {
    if let Some(head) = head(id)? {
        remove_chunks(id, &head)?;
    }
    remove_entry(id)
}
fn exchange(provider: Provider, fields: &[(&str, &str)]) -> Result<Tokens, DriveError> {
    let body = Zeroizing::new(
        url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(fields.iter().copied())
            .finish(),
    );
    let mut response = agent()
        .post(endpoints(provider).2)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .send(body.as_bytes())
        .map_err(|_| DriveError::Authorization)?;
    let bytes = crate::drive::bounded(response.body_mut().as_reader(), 64 * 1024)?;
    let tokens: Tokens = serde_json::from_slice(&bytes).map_err(|_| DriveError::Authorization)?;
    if !tokens.token_type.eq_ignore_ascii_case("bearer") || tokens.access_token.is_empty() {
        return Err(DriveError::Authorization);
    }
    Ok(tokens)
}
pub(crate) fn access_token(provider: Provider, id: &str) -> Result<Zeroizing<String>, DriveError> {
    // Serialize refresh-token rotation across different connections/process-local clients.
    static REFRESH_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = REFRESH_LOCK.lock().map_err(|_| DriveError::Authorization)?;
    let bytes = read_credential(id)?;
    let mut credential: Credential =
        serde_json::from_slice(&bytes).map_err(|_| DriveError::CredentialStore)?;
    if credential.provider != provider {
        return Err(DriveError::Authorization);
    }
    let mut fields = vec![
        ("client_id", endpoints(provider).0),
        ("grant_type", "refresh_token"),
        ("refresh_token", credential.refresh_token.as_str()),
    ];
    if provider == Provider::GoogleDrive {
        fields.push(("client_secret", &credential.client_secret));
    }
    let mut tokens = exchange(provider, &fields)?;
    if let Some(refresh) = tokens.refresh_token.take() {
        credential.refresh_token.zeroize();
        credential.refresh_token = refresh;
        save(id, &credential)?;
    }
    Ok(Zeroizing::new(std::mem::take(&mut tokens.access_token)))
}

fn callback(target: &str, state: &str) -> Result<(Zeroizing<String>, Option<String>), DriveError> {
    if !target.starts_with("/?") {
        return Err(DriveError::Authorization);
    }
    let url =
        Url::parse(&format!("http://127.0.0.1{target}")).map_err(|_| DriveError::Authorization)?;
    let pairs: Vec<_> = url.query_pairs().collect();
    let single = |key: &str| -> Result<Option<String>, DriveError> {
        let values: Vec<_> = pairs.iter().filter(|(k, _)| k == key).collect();
        if values.len() > 1 {
            return Err(DriveError::Authorization);
        }
        Ok(values.first().map(|(_, value)| value.to_string()))
    };
    if single("state")?.as_deref() != Some(state) || single("error")?.is_some() {
        return Err(DriveError::Authorization);
    }
    let code = Zeroizing::new(
        single("code")?
            .filter(|s| !s.is_empty())
            .ok_or(DriveError::Authorization)?,
    );
    let picked = single("picked_file_ids")?;
    if picked.as_ref().is_some_and(|s| !crate::drive::valid_id(s)) {
        return Err(DriveError::InvalidInput);
    }
    Ok((code, picked))
}

pub(crate) fn login(
    provider: Provider,
    client_secret: Zeroizing<String>,
) -> Result<Login, DriveError> {
    if provider == Provider::GoogleDrive && client_secret.is_empty() {
        return Err(DriveError::InvalidInput);
    }
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|_| DriveError::Authorization)?;
    listener
        .set_nonblocking(true)
        .map_err(|_| DriveError::Authorization)?;
    let port = listener
        .local_addr()
        .map_err(|_| DriveError::Authorization)?
        .port();
    let host = if provider == Provider::GoogleDrive {
        "127.0.0.1"
    } else {
        "localhost"
    };
    let redirect = format!("http://{host}:{port}/");
    let state = random_id();
    let verifier = Zeroizing::new(random_id());
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let (client, endpoint, _, scope) = endpoints(provider);
    let mut url = Url::parse(endpoint).map_err(|_| DriveError::Authorization)?;
    url.query_pairs_mut().extend_pairs([
        ("client_id", client),
        ("redirect_uri", redirect.as_str()),
        ("response_type", "code"),
        ("scope", scope),
        ("state", state.as_str()),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
        ("prompt", "consent"),
    ]);
    if provider == Provider::GoogleDrive {
        url.query_pairs_mut().extend_pairs([
            ("access_type", "offline"),
            ("trigger_onepick", "true"),
            ("allow_folder_selection", "true"),
            ("allow_multiple", "false"),
        ]);
    }
    webbrowser::open(url.as_str()).map_err(|_| DriveError::Authorization)?;
    let deadline = Instant::now() + Duration::from_secs(180);
    let (code, picked) = loop {
        if Instant::now() >= deadline {
            return Err(DriveError::Authorization);
        }
        match listener.accept() {
            Ok((mut stream, peer)) => {
                if !peer.ip().is_loopback() {
                    continue;
                }
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .map_err(|_| DriveError::Authorization)?;
                stream
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .map_err(|_| DriveError::Authorization)?;
                let mut request = Zeroizing::new(Vec::new());
                // Read only the bounded request line, never log its authorization code.
                for _ in 0..16_384 {
                    let mut byte = [0];
                    if stream
                        .read(&mut byte)
                        .map_err(|_| DriveError::Authorization)?
                        == 0
                    {
                        break;
                    }
                    request.push(byte[0]);
                    if byte[0] == b'\n' {
                        break;
                    }
                }
                let line = std::str::from_utf8(&request).map_err(|_| DriveError::Authorization)?;
                let mut words = line.split_whitespace();
                let result = if words.next() == Some("GET") {
                    callback(words.next().unwrap_or_default(), &state)
                } else {
                    Err(DriveError::Authorization)
                };
                let response = if result.is_ok() {
                    "HTTP/1.1 200 OK\r\n"
                } else {
                    "HTTP/1.1 400 Bad Request\r\n"
                };
                stream.write_all(format!("{response}Content-Type: text/plain\r\nCache-Control: no-store\r\nContent-Security-Policy: default-src 'none'\r\nConnection: close\r\n\r\nReturn to TAR Vault Sync. No credentials are displayed here.").as_bytes()).map_err(|_| DriveError::Authorization)?;
                if let Ok(value) = result {
                    break value;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100))
            }
            Err(_) => return Err(DriveError::Authorization),
        }
    };
    let mut fields = vec![
        ("client_id", client),
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", redirect.as_str()),
        ("code_verifier", verifier.as_str()),
    ];
    if provider == Provider::GoogleDrive {
        fields.push(("client_secret", client_secret.as_str()));
    }
    let mut tokens = exchange(provider, &fields)?;
    let credential_id = random_id();
    let credential = Credential {
        provider,
        refresh_token: tokens
            .refresh_token
            .take()
            .ok_or(DriveError::Authorization)?,
        client_secret: client_secret.to_string(),
    };
    save(&credential_id, &credential)?;
    Ok(Login {
        provider,
        credential_id,
        picked,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    #[test]
    #[ignore = "uses the native OS credential store with an isolated synthetic credential"]
    fn native_credential_store_roundtrip() {
        let id = random_id();
        let credential = Credential {
            provider: Provider::OneDrive,
            refresh_token: "synthetic-test-token-not-valid".repeat(400),
            client_secret: String::new(),
        };
        save(&id, &credential).unwrap();
        let read = read_credential(&id);
        let removed = disconnect(&id);
        let read = read.unwrap();
        let decoded: Credential = serde_json::from_slice(&read).unwrap();
        assert!(decoded.refresh_token == credential.refresh_token);
        removed.unwrap();
        assert!(matches!(
            credential_entry(&id).unwrap().get_password(),
            Err(keyring::Error::NoEntry)
        ));
    }
    #[test]
    fn callback_rejects_csrf_duplicates_and_untrusted_picker_ids() {
        assert!(callback("/?state=s&code=x", "s").is_ok());
        for target in [
            "/?state=wrong&code=x",
            "/?state=s&state=s&code=x",
            "/?state=s&code=x&code=y",
            "/?state=s&error=denied",
            "/other?state=s&code=x",
            "/?state=s&code=x&picked_file_ids=..%2Fescape",
        ] {
            assert!(callback(target, "s").is_err());
        }
    }
    pub(crate) fn test_google_client_secret() -> Result<Zeroizing<String>, DriveError> {
        #[derive(Deserialize)]
        struct Installed {
            client_id: String,
            client_secret: String,
        }
        impl Drop for Installed {
            fn drop(&mut self) {
                self.client_secret.zeroize();
            }
        }
        #[derive(Deserialize)]
        struct ClientFile {
            installed: Installed,
        }
        let path =
            std::env::var_os("TAR_VAULT_GOOGLE_CLIENT_FILE").ok_or(DriveError::InvalidInput)?;
        let file = std::fs::File::open(path).map_err(|_| DriveError::InvalidInput)?;
        let bytes = crate::drive::bounded(file, 64 * 1024)?;
        let mut client: ClientFile =
            serde_json::from_slice(&bytes).map_err(|_| DriveError::InvalidInput)?;
        if client.installed.client_id != GOOGLE_CLIENT {
            return Err(DriveError::InvalidInput);
        }
        Ok(Zeroizing::new(std::mem::take(
            &mut client.installed.client_secret,
        )))
    }
}
