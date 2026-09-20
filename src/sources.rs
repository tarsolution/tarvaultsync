//! Device-local source catalogue. It contains references only, never credentials.
use crate::{
    azure::AzureSource,
    core::{
        self, ErrorCategory, SecretPayload, SourceConnection, SourceRef, SourceVersion, StoreKind,
    },
    vault::VaultSource,
};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, RwLock},
};

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Location {
    FileSystem { path: PathBuf },
    AzureKeyVault { vault_name: String },
    Drive { remote: crate::drive::RemoteRef },
}
impl Location {
    pub(crate) fn store(&self) -> StoreKind {
        match self {
            Self::FileSystem { .. } => StoreKind::LocalVault,
            Self::AzureKeyVault { .. } => StoreKind::Azure,
            Self::Drive { remote } => remote.provider.store(),
        }
    }
    pub(crate) fn label(&self) -> &'static str {
        match self {
            Self::FileSystem { .. } => "File System",
            Self::AzureKeyVault { .. } => "Azure Key Vault",
            Self::Drive { remote } => remote.provider.label(),
        }
    }
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Connection {
    pub(crate) id: String,
    pub(crate) location: Location,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Catalogue {
    version: u32,
    connections: Vec<Connection>,
}

pub(crate) struct Sources {
    local: Arc<VaultSource>,
    azure: AzureSource,
    path: PathBuf,
    saved_bytes: Mutex<Option<Vec<u8>>>,
    connections: RwLock<BTreeMap<String, Connection>>,
    files: RwLock<BTreeMap<String, Arc<VaultSource>>>,
}
impl Sources {
    pub(crate) fn open(root: &Path, local: Arc<VaultSource>) -> Result<Self, ErrorCategory> {
        let path = root.join("local/sources.json");
        let saved_bytes = read_catalogue(&path)?;
        let connections = match &saved_bytes {
            Some(bytes) => {
                let data: Catalogue =
                    serde_json::from_slice(bytes).map_err(|_| ErrorCategory::InvalidConfig)?;
                if data.version != 1 || data.connections.len() > 64 {
                    return Err(ErrorCategory::InvalidConfig);
                }
                data.connections
            }
            None => Vec::new(),
        };
        let mut map = BTreeMap::new();
        let mut files = BTreeMap::new();
        for connection in connections {
            validate(&connection)?;
            if map.contains_key(&connection.id) {
                return Err(ErrorCategory::InvalidConfig);
            }
            if let Location::FileSystem { path } = &connection.location {
                files.insert(
                    connection.id.clone(),
                    Arc::new(
                        VaultSource::new(path.clone(), connection.id.clone())
                            .map_err(|_| ErrorCategory::InvalidConfig)?,
                    ),
                );
            }
            if let Location::Drive { remote } = &connection.location {
                files.insert(
                    connection.id.clone(),
                    remote_source(root, &connection.id, remote)?,
                );
            }
            map.insert(connection.id.clone(), connection);
        }
        Ok(Self {
            local,
            azure: AzureSource::new(),
            path,
            saved_bytes: Mutex::new(saved_bytes),
            connections: RwLock::new(map),
            files: RwLock::new(files),
        })
    }
    pub(crate) fn list(&self) -> Result<Vec<Connection>, ErrorCategory> {
        Ok(self
            .connections
            .read()
            .map_err(|_| ErrorCategory::State)?
            .values()
            .cloned()
            .collect())
    }
    pub(crate) fn file(&self, id: &str) -> Result<Arc<VaultSource>, ErrorCategory> {
        if id == "local" {
            return Ok(self.local.clone());
        }
        self.files
            .read()
            .map_err(|_| ErrorCategory::Source)?
            .get(id)
            .cloned()
            .ok_or(ErrorCategory::InvalidConfig)
    }
    pub(crate) fn add(&self, connection: Connection) -> Result<(), ErrorCategory> {
        validate(&connection)?;
        let mut connections = self.connections.write().map_err(|_| ErrorCategory::State)?;
        let mut files = self.files.write().map_err(|_| ErrorCategory::State)?;
        if connections.len() >= 64 || connections.contains_key(&connection.id) {
            return Err(ErrorCategory::InvalidConfig);
        }
        let source = if let Location::FileSystem { path } = &connection.location {
            Some(Arc::new(
                VaultSource::new(path.clone(), connection.id.clone())
                    .map_err(|_| ErrorCategory::InvalidConfig)?,
            ))
        } else if let Location::Drive { remote } = &connection.location {
            Some(remote_source(
                self.path
                    .parent()
                    .and_then(Path::parent)
                    .ok_or(ErrorCategory::State)?,
                &connection.id,
                remote,
            )?)
        } else {
            None
        };
        let mut next = connections.values().cloned().collect::<Vec<_>>();
        next.push(connection.clone());
        persist(
            &self.path,
            &mut *self.saved_bytes.lock().map_err(|_| ErrorCategory::State)?,
            &Catalogue {
                version: 1,
                connections: next,
            },
        )?;
        if let Some(source) = source {
            files.insert(connection.id.clone(), source);
        }
        connections.insert(connection.id.clone(), connection);
        Ok(())
    }
    pub(crate) fn remove(&self, id: &str) -> Result<(), ErrorCategory> {
        let mut connections = self.connections.write().map_err(|_| ErrorCategory::State)?;
        let mut files = self.files.write().map_err(|_| ErrorCategory::State)?;
        if !connections.contains_key(id) {
            return Err(ErrorCategory::InvalidConfig);
        }
        persist(
            &self.path,
            &mut *self.saved_bytes.lock().map_err(|_| ErrorCategory::State)?,
            &Catalogue {
                version: 1,
                connections: connections
                    .values()
                    .filter(|c| c.id != id)
                    .cloned()
                    .collect(),
            },
        )?;
        connections.remove(id);
        if let Some(source) = files.remove(id) {
            source.lock();
        }
        Ok(())
    }
    /// Renew credentials without repointing any existing binding to another vault.
    pub(crate) fn reconnect(&self, connection: Connection) -> Result<(), ErrorCategory> {
        validate(&connection)?;
        let mut connections = self.connections.write().map_err(|_| ErrorCategory::State)?;
        let old = connections
            .get(&connection.id)
            .ok_or(ErrorCategory::InvalidConfig)?;
        let (Location::Drive { remote: previous }, Location::Drive { remote: next }) =
            (&old.location, &connection.location)
        else {
            return Err(ErrorCategory::InvalidConfig);
        };
        if previous.provider != next.provider || previous.file_id != next.file_id {
            return Err(ErrorCategory::InvalidConfig);
        }
        let mut files = self.files.write().map_err(|_| ErrorCategory::State)?;
        let source = remote_source(
            self.path
                .parent()
                .and_then(Path::parent)
                .ok_or(ErrorCategory::State)?,
            &connection.id,
            next,
        )?;
        let updated = connections
            .values()
            .map(|c| {
                if c.id == connection.id {
                    connection.clone()
                } else {
                    c.clone()
                }
            })
            .collect();
        persist(
            &self.path,
            &mut *self.saved_bytes.lock().map_err(|_| ErrorCategory::State)?,
            &Catalogue {
                version: 1,
                connections: updated,
            },
        )?;
        if let Some(old) = files.insert(connection.id.clone(), source) {
            old.lock();
        }
        connections.insert(connection.id.clone(), connection);
        Ok(())
    }
    pub(crate) fn validate_ref(&self, source: &SourceRef) -> Result<(), ErrorCategory> {
        let routed = self.routed(source)?;
        match routed.store {
            StoreKind::LocalVault => self.file(&routed.connection).map(|_| ()),
            StoreKind::Azure if crate::azure::valid_source(&routed) => Ok(()),
            _ => Err(ErrorCategory::InvalidConfig),
        }
    }
    fn routed(&self, source: &SourceRef) -> Result<SourceRef, ErrorCategory> {
        if let Some(connection) = self
            .connections
            .read()
            .map_err(|_| ErrorCategory::Source)?
            .get(&source.connection)
        {
            if connection.location.store() != source.store {
                return Err(ErrorCategory::InvalidConfig);
            }
            if let Location::AzureKeyVault { vault_name } = &connection.location {
                return Ok(SourceRef {
                    store: StoreKind::Azure,
                    connection: vault_name.clone(),
                    entry: source.entry.clone(),
                });
            }
            if matches!(connection.location, Location::Drive { .. }) {
                return Ok(SourceRef {
                    store: StoreKind::LocalVault,
                    connection: source.connection.clone(),
                    entry: source.entry.clone(),
                });
            }
        }
        Ok(source.clone()) // Existing Azure bindings use the vault name directly.
    }
}
impl SourceConnection for Sources {
    fn get_version(&self, source: &SourceRef) -> Result<SourceVersion, ErrorCategory> {
        let source = self.routed(source)?;
        match source.store {
            StoreKind::LocalVault => self.file(&source.connection)?.get_version(&source),
            StoreKind::Azure => self.azure.get_version(&source),
            _ => Err(ErrorCategory::InvalidConfig),
        }
    }
    fn get_value(
        &self,
        source: &SourceRef,
        version: &SourceVersion,
    ) -> Result<SecretPayload, ErrorCategory> {
        let source = self.routed(source)?;
        match source.store {
            StoreKind::LocalVault => self.file(&source.connection)?.get_value(&source, version),
            StoreKind::Azure => self.azure.get_value(&source, version),
            _ => Err(ErrorCategory::InvalidConfig),
        }
    }
}
fn validate(connection: &Connection) -> Result<(), ErrorCategory> {
    if !core::safe_label(&connection.id) || connection.id == "local" {
        return Err(ErrorCategory::InvalidConfig);
    }
    match &connection.location {
        Location::FileSystem { path } => {
            if !path.is_absolute()
                || path
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir))
                || path.parent().is_none_or(|p| !p.is_dir())
                || fs::symlink_metadata(path)
                    .is_ok_and(|m| m.file_type().is_symlink() || !m.is_file())
            {
                return Err(ErrorCategory::InvalidConfig);
            }
        }
        Location::AzureKeyVault { vault_name } => {
            if connection.id != *vault_name {
                return Err(ErrorCategory::InvalidConfig);
            }
            if !crate::azure::valid_source(&SourceRef {
                store: StoreKind::Azure,
                connection: vault_name.clone(),
                entry: "validation".into(),
            }) {
                return Err(ErrorCategory::InvalidConfig);
            }
        }
        Location::Drive { remote } if remote.validate() => {}
        Location::Drive { .. } => return Err(ErrorCategory::InvalidConfig),
    }
    Ok(())
}
fn remote_source(
    root: &Path,
    id: &str,
    remote: &crate::drive::RemoteRef,
) -> Result<Arc<VaultSource>, ErrorCategory> {
    let store = crate::drive::RemoteFile::new(remote).map_err(|_| ErrorCategory::InvalidConfig)?;
    Ok(Arc::new(
        VaultSource::remote(
            root.join("local").join(format!("remote-{id}.bin")),
            id.into(),
            Arc::new(store),
        )
        .map_err(|_| ErrorCategory::InvalidConfig)?,
    ))
}
fn read_catalogue(path: &Path) -> Result<Option<Vec<u8>>, ErrorCategory> {
    if fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink() || !m.is_file()) {
        return Err(ErrorCategory::InvalidConfig);
    }
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(ErrorCategory::State),
    };
    let mut bytes = Vec::new();
    file.take(64 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ErrorCategory::State)?;
    if bytes.len() > 64 * 1024 {
        return Err(ErrorCategory::InvalidConfig);
    }
    Ok(Some(bytes))
}
fn persist(
    path: &Path,
    expected: &mut Option<Vec<u8>>,
    data: &Catalogue,
) -> Result<(), ErrorCategory> {
    let lock_path = path.with_extension("lock");
    if fs::symlink_metadata(&lock_path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(ErrorCategory::State);
    }
    let lock = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(lock_path)
        .map_err(|_| ErrorCategory::State)?;
    lock.try_lock_exclusive()
        .map_err(|_| ErrorCategory::VersionConflict)?;
    if read_catalogue(path)? != *expected {
        return Err(ErrorCategory::VersionConflict);
    }
    let bytes = serde_json::to_vec_pretty(data).map_err(|_| ErrorCategory::State)?;
    if bytes.len() > 64 * 1024 {
        return Err(ErrorCategory::InvalidConfig);
    }
    let mut file = tempfile::NamedTempFile::new_in(path.parent().ok_or(ErrorCategory::State)?)
        .map_err(|_| ErrorCategory::State)?;
    file.write_all(&bytes)
        .and_then(|_| file.as_file().sync_all())
        .map_err(|_| ErrorCategory::State)?;
    file.persist(path).map_err(|_| ErrorCategory::State)?;
    *expected = Some(bytes);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::SecretType;

    fn open(root: &Path) -> Sources {
        fs::create_dir_all(root.join("local")).unwrap();
        Sources::open(
            root,
            Arc::new(VaultSource::new(root.join("local/vault.bin"), "local".into()).unwrap()),
        )
        .unwrap()
    }
    fn connection(root: &Path, id: &str) -> Connection {
        Connection {
            id: id.into(),
            location: Location::FileSystem {
                path: root.join(format!("{id}.bin")),
            },
        }
    }
    #[test]
    fn catalogue_routes_isolated_vaults_and_preserves_files_on_removal() {
        let dir = tempfile::tempdir().unwrap();
        let sources = open(dir.path());
        for id in ["first", "second"] {
            sources.add(connection(dir.path(), id)).unwrap();
        }
        let first = sources.file("first").unwrap();
        first.create("synthetic-test-passphrase").unwrap();
        let payload = SecretPayload::new(vec![17, 42, 91], SecretType::Binary);
        first.put_entry("entry", &payload).unwrap();
        let reference = SourceRef {
            store: StoreKind::LocalVault,
            connection: "first".into(),
            entry: "entry".into(),
        };
        let version = sources.get_version(&reference).unwrap();
        assert!(sources.get_value(&reference, &version).unwrap().as_bytes() == payload.as_bytes());
        let mut wrong = reference.clone();
        wrong.connection = "second".into();
        assert!(matches!(
            sources.get_version(&wrong),
            Err(ErrorCategory::Unauthorized)
        ));
        wrong.store = StoreKind::Azure;
        assert!(sources.validate_ref(&wrong).is_err());
        first.put_entry("entry", &payload).unwrap();
        assert!(matches!(
            sources.get_value(&reference, &version),
            Err(ErrorCategory::VersionConflict)
        ));
        let reopened = open(dir.path());
        assert_eq!(reopened.list().unwrap().len(), 2);
        assert!(!reopened.file("first").unwrap().is_unlocked());
        sources.remove("first").unwrap();
        assert!(dir.path().join("first.bin").exists());
        assert!(!first.is_unlocked());
        assert!(sources.file("first").is_err());
    }
    #[test]
    fn stale_catalogue_is_not_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let first = open(dir.path());
        let stale = open(dir.path());
        first.add(connection(dir.path(), "first")).unwrap();
        assert_eq!(
            stale.add(connection(dir.path(), "stale")),
            Err(ErrorCategory::VersionConflict)
        );
        assert!(stale.list().unwrap().is_empty());
        assert!(stale.file("stale").is_err());
        assert_eq!(open(dir.path()).list().unwrap().len(), 1);
    }
    #[test]
    fn invalid_paths_duplicates_and_unknown_fields_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let sources = open(dir.path());
        assert!(sources.add(connection(dir.path(), "local")).is_err());
        assert!(sources
            .add(Connection {
                id: "relative".into(),
                location: Location::FileSystem {
                    path: "vault.bin".into()
                }
            })
            .is_err());
        sources.add(connection(dir.path(), "first")).unwrap();
        assert!(sources.add(connection(dir.path(), "first")).is_err());
        assert!(sources
            .add(Connection {
                id: "alias".into(),
                location: Location::AzureKeyVault {
                    vault_name: "different-vault".into()
                }
            })
            .is_err());
        fs::write(
            dir.path().join("local/sources.json"),
            br#"{"version":1,"connections":[],"credentials":"rejected"}"#,
        )
        .unwrap();
        let local =
            Arc::new(VaultSource::new(dir.path().join("local/vault.bin"), "local".into()).unwrap());
        assert!(Sources::open(dir.path(), local).is_err());
    }
}
