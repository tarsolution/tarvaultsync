//! Local encrypted vault. Only the authenticated ciphertext is written to disk.

use crate::core::{
    safe_label, ErrorCategory, ModuleKind, ModuleSetting, SecretPayload, SecretType,
    SettingsScreen, SourceConnection, SourceRef, SourceVersion, StoreKind,
};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use fs2::FileExt;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 8] = b"TVAULT02";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const MAX_VAULT_BYTES: u64 = 16 * 1024 * 1024;
const IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// Errors never contain a password, path, entry ID, or secret value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultError {
    InvalidInput,
    Locked,
    MissingEntry,
    AlreadyExists,
    VersionConflict,
    AuthenticationOrCorrupt,
    Corrupt,
    Storage,
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::InvalidInput => "invalid vault input",
                Self::Locked => "vault locked",
                Self::MissingEntry => "vault entry missing",
                Self::AlreadyExists => "vault already exists",
                Self::VersionConflict => "vault entry version changed",
                Self::AuthenticationOrCorrupt => "vault unlock failed or payload corrupt",
                Self::Corrupt => "vault format corrupt",
                Self::Storage => "vault storage failed",
            }
        )
    }
}
impl std::error::Error for VaultError {}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EntryMeta {
    kind: SecretType,
    version: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u32,
    entries: BTreeMap<String, EntryMeta>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SealedPayload {
    nonce: [u8; NONCE_LEN],
    ciphertext: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u32,
    salt: [u8; SALT_LEN],
    manifest_nonce: [u8; NONCE_LEN],
    manifest_ciphertext: Vec<u8>,
    sealed: BTreeMap<String, SealedPayload>,
}

#[derive(Serialize)]
struct EnvelopeRef<'a> {
    version: u32,
    salt: [u8; SALT_LEN],
    manifest_nonce: [u8; NONCE_LEN],
    manifest_ciphertext: &'a [u8],
    sealed: &'a BTreeMap<String, SealedPayload>,
}

/// A vault stays unlocked only in this process and locks after 15 idle minutes.
pub struct LocalVault {
    path: PathBuf,
    salt: [u8; SALT_LEN],
    key: Zeroizing<[u8; 32]>,
    manifest: Manifest,
    sealed: BTreeMap<String, SealedPayload>,
    last_used: Instant,
}

impl LocalVault {
    /// Create a new vault. The caller must collect and zeroize the passphrase safely.
    pub fn create(path: &Path, passphrase: &str) -> Result<Self, VaultError> {
        if passphrase.len() < 12 || passphrase.len() > 4096 {
            return Err(VaultError::InvalidInput);
        }
        if path.exists() {
            return Err(VaultError::AlreadyExists);
        }
        let mut salt = [0; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        let key = derive_key(passphrase, &salt)?;
        let vault = Self {
            path: path.to_path_buf(),
            salt,
            key,
            manifest: Manifest {
                version: 2,
                entries: BTreeMap::new(),
            },
            sealed: BTreeMap::new(),
            last_used: Instant::now(),
        };
        vault.persist(true)?;
        Ok(vault)
    }

    pub fn unlock(path: &Path, passphrase: &str) -> Result<Self, VaultError> {
        let data = read_limited(path)?;
        let envelope = parse_envelope(&data)?;
        let key = derive_key(passphrase, &envelope.salt)?;
        let manifest = open_manifest(&envelope, &key)?;
        Ok(Self {
            path: path.to_path_buf(),
            salt: envelope.salt,
            key,
            manifest,
            sealed: envelope.sealed,
            last_used: Instant::now(),
        })
    }

    /// Drop the in-memory key and entries. A later access requires unlock again.
    pub fn lock(self) {}

    pub fn put(
        &mut self,
        entry_id: &str,
        payload: &SecretPayload,
    ) -> Result<SourceVersion, VaultError> {
        self.touch()?;
        if !safe_label(entry_id) || payload.as_bytes().len() > MAX_VAULT_BYTES as usize / 2 {
            return Err(VaultError::InvalidInput);
        }
        let _write_lock = lock_for_update(&self.path)?;
        self.reload()?;
        let version = loop {
            let mut random = [0u8; 16];
            OsRng.fill_bytes(&mut random);
            let candidate = hex_version(&random);
            if !self.sealed.contains_key(&candidate) {
                break candidate;
            }
        };
        let new_sealed = seal_payload(&self.key, entry_id, &version, payload.as_bytes())?;
        let old_meta = self.manifest.entries.insert(
            entry_id.to_owned(),
            EntryMeta {
                kind: payload.kind.clone(),
                version: version.clone(),
            },
        );
        let old_sealed = old_meta
            .as_ref()
            .and_then(|meta| self.sealed.remove(&meta.version));
        self.sealed.insert(version.clone(), new_sealed);
        if let Err(error) = self.persist(false) {
            self.sealed.remove(&version);
            self.manifest.entries.remove(entry_id);
            if let Some(meta) = old_meta {
                if let Some(sealed) = old_sealed {
                    self.sealed.insert(meta.version.clone(), sealed);
                }
                self.manifest.entries.insert(entry_id.to_owned(), meta);
            }
            return Err(error);
        }
        Ok(SourceVersion(version))
    }

    pub fn remove(&mut self, entry_id: &str) -> Result<(), VaultError> {
        self.touch()?;
        let _write_lock = lock_for_update(&self.path)?;
        self.reload()?;
        let old = self
            .manifest
            .entries
            .remove(entry_id)
            .ok_or(VaultError::MissingEntry)?;
        let sealed = self
            .sealed
            .remove(&old.version)
            .ok_or(VaultError::Corrupt)?;
        if let Err(error) = self.persist(false) {
            self.sealed.insert(old.version.clone(), sealed);
            self.manifest.entries.insert(entry_id.to_owned(), old);
            return Err(error);
        }
        Ok(())
    }

    pub fn get_version(&mut self, entry_id: &str) -> Result<SourceVersion, VaultError> {
        self.touch()?;
        self.reload()?;
        self.manifest
            .entries
            .get(entry_id)
            .map(|entry| SourceVersion(entry.version.clone()))
            .ok_or(VaultError::MissingEntry)
    }

    pub fn entries(&mut self) -> Result<Vec<VaultEntry>, VaultError> {
        self.check_active()?;
        self.reload()?;
        Ok(self
            .manifest
            .entries
            .iter()
            .map(|(id, meta)| VaultEntry {
                id: id.clone(),
                kind: meta.kind.clone(),
                version: meta.version.clone(),
            })
            .collect())
    }

    pub fn get_value(
        &mut self,
        entry_id: &str,
        version: &SourceVersion,
    ) -> Result<SecretPayload, VaultError> {
        self.touch()?;
        self.reload()?;
        let entry = self
            .manifest
            .entries
            .get(entry_id)
            .ok_or(VaultError::MissingEntry)?;
        if entry.version != version.0 {
            return Err(VaultError::VersionConflict);
        }
        let sealed = self.sealed.get(&entry.version).ok_or(VaultError::Corrupt)?;
        let bytes = open_payload(&self.key, entry_id, &entry.version, sealed)?;
        Ok(SecretPayload::new(bytes, entry.kind.clone()))
    }

    /// Copy only authenticated ciphertext to a new backup path.
    pub fn backup(&mut self, destination: &Path) -> Result<(), VaultError> {
        self.touch()?;
        if self.path == destination || destination.exists() {
            return Err(VaultError::AlreadyExists);
        }
        let data = read_limited(&self.path)?;
        verify_all(&data, &self.key)?;
        create_new_synced(destination, &data)
    }

    /// Verify a backup with its passphrase before copying encrypted bytes to a new location.
    pub fn recover(
        backup: &Path,
        destination: &Path,
        passphrase: &str,
    ) -> Result<Self, VaultError> {
        if backup == destination || destination.exists() {
            return Err(VaultError::AlreadyExists);
        }
        let checked = Self::unlock(backup, passphrase)?;
        let data = read_limited(backup)?;
        verify_all(&data, &checked.key)?;
        create_new_synced(destination, &data)?;
        drop(checked);
        Self::unlock(destination, passphrase)
    }

    fn touch(&mut self) -> Result<(), VaultError> {
        self.check_active()?;
        self.last_used = Instant::now();
        Ok(())
    }

    fn check_active(&mut self) -> Result<(), VaultError> {
        if self.last_used.elapsed() >= IDLE_TIMEOUT {
            self.key.zeroize();
            self.manifest.entries.clear();
            self.sealed.clear();
            return Err(VaultError::Locked);
        }
        Ok(())
    }

    fn reload(&mut self) -> Result<(), VaultError> {
        let data = read_limited(&self.path)?;
        let envelope = parse_envelope(&data)?;
        if envelope.salt != self.salt {
            return Err(VaultError::AuthenticationOrCorrupt);
        }
        let manifest = open_manifest(&envelope, &self.key)?;
        self.manifest = manifest;
        self.sealed = envelope.sealed;
        Ok(())
    }

    fn persist(&self, create: bool) -> Result<(), VaultError> {
        let mut manifest_nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut manifest_nonce);
        let plaintext =
            Zeroizing::new(serde_json::to_vec(&self.manifest).map_err(|_| VaultError::Corrupt)?);
        let cipher = XChaCha20Poly1305::new((&*self.key).into());
        let aad = manifest_aad(&self.salt);
        let manifest_ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&manifest_nonce),
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| VaultError::Storage)?;
        let envelope = EnvelopeRef {
            version: 2,
            salt: self.salt,
            manifest_nonce,
            manifest_ciphertext: &manifest_ciphertext,
            sealed: &self.sealed,
        };
        let encoded = serde_json::to_vec(&envelope).map_err(|_| VaultError::Storage)?;
        if encoded.len() as u64 + MAGIC.len() as u64 > MAX_VAULT_BYTES {
            return Err(VaultError::InvalidInput);
        }
        let mut output = Vec::with_capacity(MAGIC.len() + encoded.len());
        output.extend_from_slice(MAGIC);
        output.extend_from_slice(&encoded);
        if create {
            create_new_synced(&self.path, &output)
        } else {
            atomic_replace(&self.path, &output)
        }
    }
}

fn derive_key(passphrase: &str, salt: &[u8; SALT_LEN]) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    let params = Params::new(64 * 1024, 3, 1, Some(32)).map_err(|_| VaultError::Corrupt)?;
    let kdf = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    kdf.hash_password_into(passphrase.as_bytes(), salt, &mut *key)
        .map_err(|_| VaultError::AuthenticationOrCorrupt)?;
    Ok(key)
}

fn parse_envelope(data: &[u8]) -> Result<Envelope, VaultError> {
    if data.len() <= MAGIC.len() || &data[..MAGIC.len()] != MAGIC {
        return Err(VaultError::Corrupt);
    }
    let envelope: Envelope =
        serde_json::from_slice(&data[MAGIC.len()..]).map_err(|_| VaultError::Corrupt)?;
    if envelope.version != 2 || envelope.manifest_ciphertext.len() < 16 {
        return Err(VaultError::Corrupt);
    }
    Ok(envelope)
}

fn manifest_aad(salt: &[u8; SALT_LEN]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(MAGIC.len() + SALT_LEN);
    aad.extend_from_slice(MAGIC);
    aad.extend_from_slice(salt);
    aad
}

fn payload_aad(entry_id: &str, version: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(MAGIC.len() + entry_id.len() + version.len() + 2);
    aad.extend_from_slice(MAGIC);
    aad.extend_from_slice(entry_id.as_bytes());
    aad.push(0);
    aad.extend_from_slice(version.as_bytes());
    aad
}

fn open_manifest(envelope: &Envelope, key: &[u8; 32]) -> Result<Manifest, VaultError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let aad = manifest_aad(&envelope.salt);
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&envelope.manifest_nonce),
                Payload {
                    msg: &envelope.manifest_ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| VaultError::AuthenticationOrCorrupt)?,
    );
    let manifest: Manifest = serde_json::from_slice(&plaintext).map_err(|_| VaultError::Corrupt)?;
    if manifest.version != 2
        || manifest.entries.len() != envelope.sealed.len()
        || manifest.entries.iter().any(|(id, meta)| {
            !safe_label(id)
                || !crate::core::safe_version(&meta.version)
                || envelope
                    .sealed
                    .get(&meta.version)
                    .is_none_or(|payload| payload.ciphertext.len() < 16)
        })
    {
        return Err(VaultError::Corrupt);
    }
    Ok(manifest)
}

fn seal_payload(
    key: &[u8; 32],
    entry_id: &str,
    version: &str,
    bytes: &[u8],
) -> Result<SealedPayload, VaultError> {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new(key.into());
    let aad = payload_aad(entry_id, version);
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: bytes,
                aad: &aad,
            },
        )
        .map_err(|_| VaultError::Storage)?;
    Ok(SealedPayload { nonce, ciphertext })
}

fn open_payload(
    key: &[u8; 32],
    entry_id: &str,
    version: &str,
    payload: &SealedPayload,
) -> Result<Vec<u8>, VaultError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let aad = payload_aad(entry_id, version);
    cipher
        .decrypt(
            XNonce::from_slice(&payload.nonce),
            Payload {
                msg: &payload.ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| VaultError::AuthenticationOrCorrupt)
}

fn verify_all(data: &[u8], key: &[u8; 32]) -> Result<(), VaultError> {
    let envelope = parse_envelope(data)?;
    let manifest = open_manifest(&envelope, key)?;
    for (id, meta) in &manifest.entries {
        let sealed = envelope
            .sealed
            .get(&meta.version)
            .ok_or(VaultError::Corrupt)?;
        let _plaintext = Zeroizing::new(open_payload(key, id, &meta.version, sealed)?);
    }
    Ok(())
}

fn read_limited(path: &Path) -> Result<Vec<u8>, VaultError> {
    let file = File::open(path).map_err(|_| VaultError::Storage)?;
    if file.metadata().map_err(|_| VaultError::Storage)?.len() > MAX_VAULT_BYTES {
        return Err(VaultError::Corrupt);
    }
    let mut data = Vec::new();
    file.take(MAX_VAULT_BYTES + 1)
        .read_to_end(&mut data)
        .map_err(|_| VaultError::Storage)?;
    if data.len() as u64 > MAX_VAULT_BYTES {
        return Err(VaultError::Corrupt);
    }
    Ok(data)
}

fn lock_for_update(path: &Path) -> Result<File, VaultError> {
    let lock_path = path.with_extension("vault.lock");
    if fs::symlink_metadata(&lock_path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(VaultError::Storage);
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let lock = options.open(lock_path).map_err(|_| VaultError::Storage)?;
    lock.lock_exclusive().map_err(|_| VaultError::Storage)?;
    Ok(lock)
}

fn create_new_synced(path: &Path, data: &[u8]) -> Result<(), VaultError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|_| VaultError::Storage)?;
    file.write_all(data)
        .and_then(|_| file.sync_all())
        .map_err(|_| VaultError::Storage)
}

fn atomic_replace(path: &Path, data: &[u8]) -> Result<(), VaultError> {
    if fs::symlink_metadata(path)
        .map_err(|_| VaultError::Storage)?
        .file_type()
        .is_symlink()
    {
        return Err(VaultError::Storage);
    }
    let mut suffix = [0u8; 8];
    OsRng.fill_bytes(&mut suffix);
    let tmp = path.with_extension(format!("vault-{}.tmp", hex_version(&suffix)));
    create_new_synced(&tmp, data)?;
    if replace_file(&tmp, path).is_err() {
        let _ = fs::remove_file(&tmp);
        return Err(VaultError::Storage);
    }
    Ok(())
}

#[cfg(not(windows))]
fn replace_file(tmp: &Path, path: &Path) -> std::io::Result<()> {
    fs::rename(tmp, path)
}

#[cfg(windows)]
fn replace_file(tmp: &Path, path: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "Kernel32")]
    extern "system" {
        fn ReplaceFileW(
            replaced: *const u16,
            replacement: *const u16,
            backup: *const u16,
            flags: u32,
            exclude: *const std::ffi::c_void,
            reserved: *const std::ffi::c_void,
        ) -> i32;
    }
    let destination: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let source: Vec<u16> = tmp.as_os_str().encode_wide().chain(Some(0)).collect();
    let result = unsafe {
        ReplaceFileW(
            destination.as_ptr(),
            source.as_ptr(),
            std::ptr::null(),
            0,
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    if result == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn hex_version(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(HEX[(byte >> 4) as usize] as char);
        value.push(HEX[(byte & 15) as usize] as char);
    }
    value
}

/// The core fetches a version before asking this adapter for entry bytes.
pub struct VaultSource {
    vault: Mutex<Option<LocalVault>>,
    path: PathBuf,
    connection: String,
}
#[derive(Serialize)]
pub struct VaultEntry {
    pub id: String,
    pub kind: SecretType,
    pub version: String,
}
impl VaultSource {
    pub fn new(path: PathBuf, connection: String) -> Result<Self, VaultError> {
        if !safe_label(&connection) {
            return Err(VaultError::InvalidInput);
        }
        Ok(Self {
            vault: Mutex::new(None),
            path,
            connection,
        })
    }
    pub fn unlock(&self, passphrase: &str) -> Result<(), VaultError> {
        let opened = LocalVault::unlock(&self.path, passphrase)?;
        *self.vault.lock().map_err(|_| VaultError::Locked)? = Some(opened);
        Ok(())
    }
    pub fn create(&self, passphrase: &str) -> Result<(), VaultError> {
        let created = LocalVault::create(&self.path, passphrase)?;
        *self.vault.lock().map_err(|_| VaultError::Locked)? = Some(created);
        Ok(())
    }
    pub fn recover(&self, backup: &Path, passphrase: &str) -> Result<(), VaultError> {
        let recovered = LocalVault::recover(backup, &self.path, passphrase)?;
        *self.vault.lock().map_err(|_| VaultError::Locked)? = Some(recovered);
        Ok(())
    }
    pub fn exists(&self) -> bool {
        self.path.exists()
    }
    pub fn is_unlocked(&self) -> bool {
        self.vault.lock().is_ok_and(|mut guard| {
            if guard
                .as_mut()
                .is_some_and(|vault| vault.check_active().is_ok())
            {
                true
            } else {
                *guard = None;
                false
            }
        })
    }
    pub fn entries(&self) -> Result<Vec<VaultEntry>, VaultError> {
        self.with_open(LocalVault::entries)
    }
    pub fn put_entry(&self, id: &str, payload: &SecretPayload) -> Result<(), VaultError> {
        self.with_open(|vault| vault.put(id, payload).map(|_| ()))
    }
    pub fn remove_entry(&self, id: &str) -> Result<(), VaultError> {
        self.with_open(|vault| vault.remove(id))
    }
    pub fn backup(&self, destination: &Path) -> Result<(), VaultError> {
        self.with_open(|vault| vault.backup(destination))
    }
    fn with_open<T>(
        &self,
        action: impl FnOnce(&mut LocalVault) -> Result<T, VaultError>,
    ) -> Result<T, VaultError> {
        let mut guard = self.vault.lock().map_err(|_| VaultError::Locked)?;
        let vault = guard.as_mut().ok_or(VaultError::Locked)?;
        let result = action(vault);
        if matches!(&result, Err(VaultError::Locked)) {
            *guard = None;
        }
        result
    }
    pub fn lock(&self) {
        if let Ok(mut guard) = self.vault.lock() {
            *guard = None;
        }
    }
    fn with_vault<T>(
        &self,
        reference: &SourceRef,
        f: impl FnOnce(&mut LocalVault) -> Result<T, VaultError>,
    ) -> Result<T, ErrorCategory> {
        if reference.store != StoreKind::LocalVault
            || reference.connection != self.connection
            || !safe_label(&reference.entry)
        {
            return Err(ErrorCategory::InvalidConfig);
        }
        let mut guard = self.vault.lock().map_err(|_| ErrorCategory::Source)?;
        let vault = guard.as_mut().ok_or(ErrorCategory::Unauthorized)?;
        match f(vault) {
            Ok(value) => Ok(value),
            Err(VaultError::Locked) => {
                *guard = None;
                Err(ErrorCategory::Unauthorized)
            }
            Err(VaultError::VersionConflict) => Err(ErrorCategory::VersionConflict),
            Err(_) => Err(ErrorCategory::Source),
        }
    }
}
impl SourceConnection for VaultSource {
    fn get_version(&self, source: &SourceRef) -> Result<SourceVersion, ErrorCategory> {
        self.with_vault(source, |vault| vault.get_version(&source.entry))
    }
    fn get_value(
        &self,
        source: &SourceRef,
        version: &SourceVersion,
    ) -> Result<SecretPayload, ErrorCategory> {
        self.with_vault(source, |vault| vault.get_value(&source.entry, version))
    }
}

pub struct VaultStoreScreen;
impl SettingsScreen for VaultStoreScreen {
    fn module_id(&self) -> &'static str {
        "local_vault"
    }
    fn kind(&self) -> ModuleKind {
        ModuleKind::Store
    }
    fn supported_types(&self) -> &'static [SecretType] {
        &[
            SecretType::Text,
            SecretType::Json,
            SecretType::Binary,
            SecretType::Certificate,
            SecretType::PrivateKey,
        ]
    }
    fn render(&self) -> &'static str {
        "Local vault: create, unlock, lock, edit, backup, recover; configure connection,entry"
    }
    fn configure(&self, input: &str) -> Result<ModuleSetting, ErrorCategory> {
        let (connection, entry) = input.split_once(',').ok_or(ErrorCategory::InvalidConfig)?;
        if !safe_label(connection) || !safe_label(entry) {
            return Err(ErrorCategory::InvalidConfig);
        }
        Ok(ModuleSetting::Source(SourceRef {
            store: StoreKind::LocalVault,
            connection: connection.into(),
            entry: entry.into(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_rotation_and_recovery() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.bin");
        let backup = dir.path().join("backup.bin");
        let recovered = dir.path().join("restored.bin");
        let mut vault = LocalVault::create(&path, "test-only-passphrase").unwrap();
        let payload = SecretPayload::new(vec![0, 1, 2, 255], SecretType::Binary);
        let first = vault.put("sample", &payload).unwrap();
        assert_eq!(
            vault.get_value("sample", &first).unwrap().as_bytes(),
            payload.as_bytes()
        );
        let next = vault.put("sample", &payload).unwrap();
        assert_ne!(first, next);
        assert!(vault.get_value("sample", &first).is_err());
        vault.backup(&backup).unwrap();
        vault.lock();
        assert!(!fs::read(&path)
            .unwrap()
            .windows(payload.as_bytes().len())
            .any(|v| v == payload.as_bytes()));
        assert!(matches!(
            LocalVault::unlock(&path, "wrong-passphrase"),
            Err(VaultError::AuthenticationOrCorrupt)
        ));
        let mut vault = LocalVault::recover(&backup, &recovered, "test-only-passphrase").unwrap();
        assert_eq!(vault.get_version("sample").unwrap(), next);
        assert_eq!(
            vault.get_value("sample", &next).unwrap().as_bytes(),
            payload.as_bytes()
        );
    }

    #[test]
    fn tampering_rejected_and_previous_file_survives_bad_edit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.bin");
        let mut vault = LocalVault::create(&path, "test-only-passphrase").unwrap();
        let before = fs::read(&path).unwrap();
        assert_eq!(
            vault
                .put("bad/id", &SecretPayload::new(vec![7], SecretType::Text))
                .unwrap_err(),
            VaultError::InvalidInput
        );
        assert_eq!(fs::read(&path).unwrap(), before);
        vault.lock();
        let mut damaged = parse_envelope(&before).unwrap();
        damaged.manifest_ciphertext[0] ^= 1;
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&serde_json::to_vec(&damaged).unwrap());
        fs::write(&path, bytes).unwrap();
        assert!(matches!(
            LocalVault::unlock(&path, "test-only-passphrase"),
            Err(VaultError::AuthenticationOrCorrupt)
        ));
    }

    #[test]
    fn metadata_read_never_opens_payload_and_payload_corruption_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.bin");
        let backup = dir.path().join("backup.bin");
        let mut vault = LocalVault::create(&path, "test-only-passphrase").unwrap();
        let payload = SecretPayload::new(vec![5, 6, 7], SecretType::Binary);
        let version = vault.put("sample", &payload).unwrap();
        vault.lock();
        let mut envelope = parse_envelope(&fs::read(&path).unwrap()).unwrap();
        envelope.sealed.get_mut(&version.0).unwrap().ciphertext[0] ^= 1;
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&serde_json::to_vec(&envelope).unwrap());
        fs::write(&path, bytes).unwrap();
        let mut vault = LocalVault::unlock(&path, "test-only-passphrase").unwrap();
        assert_eq!(vault.get_version("sample").unwrap(), version);
        assert!(matches!(
            vault.get_value("sample", &version),
            Err(VaultError::AuthenticationOrCorrupt)
        ));
        assert!(matches!(
            vault.backup(&backup),
            Err(VaultError::AuthenticationOrCorrupt)
        ));
        assert!(!backup.exists());
    }

    #[test]
    fn metadata_check_observes_external_rotation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.bin");
        let mut first = LocalVault::create(&path, "test-only-passphrase").unwrap();
        let payload = SecretPayload::new(vec![1, 2, 3], SecretType::Binary);
        let original = first.put("sample", &payload).unwrap();
        let mut second = LocalVault::unlock(&path, "test-only-passphrase").unwrap();
        let rotated = second.put("sample", &payload).unwrap();
        assert_eq!(first.get_version("sample").unwrap(), rotated);
        assert!(matches!(
            first.get_value("sample", &original),
            Err(VaultError::VersionConflict)
        ));
    }

    #[test]
    fn concurrent_writers_keep_both_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.bin");
        LocalVault::create(&path, "test-only-passphrase").unwrap();
        let first = LocalVault::unlock(&path, "test-only-passphrase").unwrap();
        let second = LocalVault::unlock(&path, "test-only-passphrase").unwrap();
        let a = std::thread::spawn(move || {
            let mut vault = first;
            vault
                .put("first", &SecretPayload::new(vec![1], SecretType::Binary))
                .unwrap();
        });
        let b = std::thread::spawn(move || {
            let mut vault = second;
            vault
                .put("second", &SecretPayload::new(vec![2], SecretType::Binary))
                .unwrap();
        });
        a.join().unwrap();
        b.join().unwrap();
        let mut vault = LocalVault::unlock(&path, "test-only-passphrase").unwrap();
        assert!(vault.get_version("first").is_ok());
        assert!(vault.get_version("second").is_ok());
    }
}
