use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SourceRef {
    pub store: StoreKind,
    pub connection: String,
    pub entry: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StoreKind {
    Fake,
    LocalVault,
    Azure,
    Aws,
    Google,
    OneDrive,
    GoogleDrive,
    Git,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SecretType {
    Text,
    Json,
    Binary,
    Certificate,
    PrivateKey,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TargetSpec {
    Fake {
        slot: String,
    },
    WholeFile {
        path: PathBuf,
    },
    StructuredField {
        path: PathBuf,
        key: String,
    },
    DockerInput {
        path: PathBuf,
        key: String,
    },
    GitCredential {
        protocol: String,
        host: String,
        path: Option<String>,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MissingTargetPolicy {
    Alert,
    Recreate,
    Disable,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Schedule {
    pub interval_seconds: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub id: String,
    pub source: SourceRef,
    pub secret_type: SecretType,
    pub target: TargetSpec,
    pub missing_target: MissingTargetPolicy,
    pub schedule: Schedule,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    pub bindings: Vec<Binding>,
}
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub version: u32,
    pub applied: BTreeMap<String, SourceVersion>,
    pub status: BTreeMap<String, RedactedStatus>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactedStatus {
    pub timestamp: u64,
    pub outcome: SyncOutcome,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceVersion(pub String);
pub struct SecretPayload {
    bytes: Vec<u8>,
    pub kind: SecretType,
}
impl SecretPayload {
    pub fn new(bytes: Vec<u8>, kind: SecretType) -> Self {
        Self { bytes, kind }
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}
impl Drop for SecretPayload {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SyncOutcome {
    Unchanged,
    Applied,
    Disabled,
    Failed(ErrorCategory),
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCategory {
    InvalidConfig,
    Source,
    VersionConflict,
    Target,
    State,
    Unauthorized,
}
impl std::fmt::Display for ErrorCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl std::error::Error for ErrorCategory {}
pub trait SourceConnection: Send + Sync {
    fn get_version(&self, source: &SourceRef) -> Result<SourceVersion, ErrorCategory>;
    fn get_value(
        &self,
        source: &SourceRef,
        version: &SourceVersion,
    ) -> Result<SecretPayload, ErrorCategory>;
}
pub trait LocalTarget: Send + Sync {
    fn validate(&self, spec: &TargetSpec, kind: &SecretType) -> Result<(), ErrorCategory>;
    fn apply(&self, spec: &TargetSpec, payload: &SecretPayload) -> Result<(), ErrorCategory>;
}
pub trait SettingsScreen: Send + Sync {
    fn module_id(&self) -> &'static str;
    fn kind(&self) -> ModuleKind;
    fn supported_types(&self) -> &'static [SecretType];
    fn render(&self) -> &'static str;
    fn configure(&self, input: &str) -> Result<ModuleSetting, ErrorCategory>;
}
pub enum ModuleSetting {
    Source(SourceRef),
    Target(TargetSpec),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModuleKind {
    Store,
    Target,
}
pub struct ModuleRegistry {
    screens: HashMap<&'static str, Arc<dyn SettingsScreen>>,
}
impl ModuleRegistry {
    pub fn new() -> Self {
        Self {
            screens: HashMap::new(),
        }
    }
    pub fn register(&mut self, screen: Arc<dyn SettingsScreen>) -> Result<(), ErrorCategory> {
        if self.screens.contains_key(screen.module_id()) {
            return Err(ErrorCategory::InvalidConfig);
        }
        self.screens.insert(screen.module_id(), screen);
        Ok(())
    }
    pub fn mount(&self, id: &str) -> Option<&'static str> {
        self.screens.get(id).map(|s| s.render())
    }
    pub fn capability(&self, id: &str) -> Option<(ModuleKind, &'static [SecretType])> {
        self.screens
            .get(id)
            .map(|s| (s.kind(), s.supported_types()))
    }
    pub fn configure(&self, id: &str, input: &str) -> Result<ModuleSetting, ErrorCategory> {
        self.screens
            .get(id)
            .ok_or(ErrorCategory::InvalidConfig)?
            .configure(input)
    }
}
impl Default for ModuleRegistry {
    fn default() -> Self {
        Self::new()
    }
}
pub struct FakeStoreScreen;
impl SettingsScreen for FakeStoreScreen {
    fn module_id(&self) -> &'static str {
        "fake_store"
    }
    fn kind(&self) -> ModuleKind {
        ModuleKind::Store
    }
    fn supported_types(&self) -> &'static [SecretType] {
        &[SecretType::Text]
    }
    fn render(&self) -> &'static str {
        "Fake store settings: connection,entry"
    }
    fn configure(&self, input: &str) -> Result<ModuleSetting, ErrorCategory> {
        let (connection, entry) = input.split_once(',').ok_or(ErrorCategory::InvalidConfig)?;
        if !safe_label(connection) || !safe_label(entry) {
            return Err(ErrorCategory::InvalidConfig);
        }
        Ok(ModuleSetting::Source(SourceRef {
            store: StoreKind::Fake,
            connection: connection.into(),
            entry: entry.into(),
        }))
    }
}
pub struct FakeTargetScreen;
impl SettingsScreen for FakeTargetScreen {
    fn module_id(&self) -> &'static str {
        "fake_target"
    }
    fn kind(&self) -> ModuleKind {
        ModuleKind::Target
    }
    fn supported_types(&self) -> &'static [SecretType] {
        &[SecretType::Text]
    }
    fn render(&self) -> &'static str {
        "Fake target settings: slot"
    }
    fn configure(&self, input: &str) -> Result<ModuleSetting, ErrorCategory> {
        if !safe_label(input) {
            return Err(ErrorCategory::InvalidConfig);
        }
        Ok(ModuleSetting::Target(TargetSpec::Fake {
            slot: input.into(),
        }))
    }
}

pub fn validate_config(data: &[u8], root: &Path) -> Result<Config, ErrorCategory> {
    let config: Config = serde_json::from_slice(data).map_err(|_| ErrorCategory::InvalidConfig)?;
    if config.version != SCHEMA_VERSION {
        return Err(ErrorCategory::InvalidConfig);
    }
    let mut ids = std::collections::HashSet::new();
    for b in &config.bindings {
        if !safe_label(&b.id)
            || !ids.insert(&b.id)
            || !safe_label(&b.source.connection)
            || !safe_label(&b.source.entry)
            || !(1..=86400).contains(&b.schedule.interval_seconds)
        {
            return Err(ErrorCategory::InvalidConfig);
        }
        match &b.target {
            TargetSpec::Fake { slot } if safe_label(slot) => {}
            TargetSpec::WholeFile { path }
            | TargetSpec::StructuredField { path, .. }
            | TargetSpec::DockerInput { path, .. }
                if path.is_absolute()
                    && path.starts_with(root)
                    && !path
                        .components()
                        .any(|c| matches!(c, std::path::Component::ParentDir)) => {}
            TargetSpec::GitCredential { protocol, host, .. }
                if !protocol.is_empty() && !host.is_empty() => {}
            _ => return Err(ErrorCategory::InvalidConfig),
        }
        if b.source.store != StoreKind::Fake || !matches!(b.target, TargetSpec::Fake { .. }) {
            return Err(ErrorCategory::InvalidConfig);
        }
    }
    Ok(config)
}
fn atomic_json<T: Serialize>(path: &Path, value: &T) -> Result<(), ErrorCategory> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|_| ErrorCategory::State)?;
    let tmp = path.with_extension("tmp");
    let mut f = fs::File::create(&tmp).map_err(|_| ErrorCategory::State)?;
    f.write_all(&bytes)
        .and_then(|_| f.sync_all())
        .map_err(|_| ErrorCategory::State)?;
    replace_file(&tmp, path).map_err(|_| ErrorCategory::State)
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
    if !path.exists() {
        return fs::rename(tmp, path);
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
pub fn load_state(path: &Path) -> Result<State, ErrorCategory> {
    if !path.exists() {
        return Ok(State {
            version: SCHEMA_VERSION,
            ..State::default()
        });
    }
    let data = fs::read(path).map_err(|_| ErrorCategory::State)?;
    let s: State = serde_json::from_slice(&data).map_err(|_| ErrorCategory::State)?;
    if s.version != SCHEMA_VERSION
        || s.applied
            .iter()
            .any(|(k, v)| !safe_label(k) || !safe_version(&v.0))
        || s.status.keys().any(|k| !safe_label(k))
    {
        return Err(ErrorCategory::State);
    }
    Ok(s)
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub timestamp: u64,
    pub binding_id: String,
    pub operation: EventOperation,
    pub source_kind: StoreKind,
    pub outcome: SyncOutcome,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventOperation {
    Sync,
}
pub struct Engine {
    pub config: Config,
    pub state: Mutex<State>,
    pub state_path: PathBuf,
    pub events_path: PathBuf,
    pub source: Arc<dyn SourceConnection>,
    pub target: Arc<dyn LocalTarget>,
    flights: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}
impl Engine {
    pub fn new(
        config: Config,
        state_path: PathBuf,
        events_path: PathBuf,
        source: Arc<dyn SourceConnection>,
        target: Arc<dyn LocalTarget>,
    ) -> Result<Self, ErrorCategory> {
        let state = load_state(&state_path)?;
        Ok(Self {
            config,
            state: Mutex::new(state),
            state_path,
            events_path,
            source,
            target,
            flights: Mutex::new(HashMap::new()),
        })
    }
    pub async fn sync(&self, id: &str) -> SyncOutcome {
        let binding = match self.config.bindings.iter().find(|b| b.id == id) {
            Some(b) => b,
            None => return SyncOutcome::Failed(ErrorCategory::InvalidConfig),
        };
        let gate = {
            let mut g = self.flights.lock().unwrap();
            g.entry(id.to_string())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                .clone()
        };
        let _flight = gate.lock().await;
        let outcome = self.sync_inner(binding);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        {
            let mut state = self.state.lock().unwrap();
            let mut next = state.clone();
            next.status.insert(
                id.to_string(),
                RedactedStatus {
                    timestamp,
                    outcome: outcome.clone(),
                },
            );
            if atomic_json(&self.state_path, &next).is_err() {
                return SyncOutcome::Failed(ErrorCategory::State);
            }
            *state = next;
        }
        let event = Event {
            timestamp,
            binding_id: id.to_string(),
            operation: EventOperation::Sync,
            source_kind: binding.source.store.clone(),
            outcome: outcome.clone(),
        };
        if self.append_event(&event).is_err() {
            return SyncOutcome::Failed(ErrorCategory::State);
        }
        outcome
    }
    fn sync_inner(&self, b: &Binding) -> SyncOutcome {
        if let Err(e) = self.target.validate(&b.target, &b.secret_type) {
            return SyncOutcome::Failed(e);
        }
        let version = match self.source.get_version(&b.source) {
            Ok(v) => v,
            Err(e) => return SyncOutcome::Failed(e),
        };
        if !safe_version(&version.0) {
            return SyncOutcome::Failed(ErrorCategory::VersionConflict);
        }
        if self.state.lock().unwrap().applied.get(&b.id) == Some(&version) {
            return SyncOutcome::Unchanged;
        }
        let payload = match self.source.get_value(&b.source, &version) {
            Ok(p) => p,
            Err(e) => return SyncOutcome::Failed(e),
        };
        if payload.kind != b.secret_type {
            return SyncOutcome::Failed(ErrorCategory::VersionConflict);
        }
        if let Err(e) = self.target.apply(&b.target, &payload) {
            return SyncOutcome::Failed(e);
        }
        let mut state = self.state.lock().unwrap();
        let mut next = state.clone();
        next.applied.insert(b.id.clone(), version);
        if atomic_json(&self.state_path, &next).is_err() {
            return SyncOutcome::Failed(ErrorCategory::State);
        }
        *state = next;
        SyncOutcome::Applied
    }
    fn append_event(&self, e: &Event) -> Result<(), ErrorCategory> {
        const LIMIT: u64 = 1024 * 1024;
        let data = serde_json::to_vec(e).map_err(|_| ErrorCategory::State)?;
        if self
            .events_path
            .metadata()
            .map(|m| m.len() + data.len() as u64 + 1 > LIMIT)
            .unwrap_or(false)
        {
            let old = self.events_path.with_extension("ndjson.1");
            if old.exists() {
                fs::remove_file(&old).map_err(|_| ErrorCategory::State)?;
            }
            fs::rename(&self.events_path, old).map_err(|_| ErrorCategory::State)?;
        }
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.events_path)
            .map_err(|_| ErrorCategory::State)?;
        f.write_all(&data)
            .and_then(|_| f.write_all(b"\n"))
            .map_err(|_| ErrorCategory::State)
    }
    pub fn status(&self) -> State {
        self.state.lock().unwrap().clone()
    }
}
pub fn retry_delay(attempt: u32, seed: u64) -> std::time::Duration {
    let base = 2u64.saturating_pow(attempt.min(8)).min(300);
    std::time::Duration::from_millis(base * 1000 + (seed % 501))
}
pub fn safe_version(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 128
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}
pub fn safe_label(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 64
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}
pub struct FakeStore {
    pub version: Mutex<SourceVersion>,
    pub reads: Mutex<(u32, u32)>,
}
impl SourceConnection for FakeStore {
    fn get_version(&self, _: &SourceRef) -> Result<SourceVersion, ErrorCategory> {
        self.reads.lock().unwrap().0 += 1;
        Ok(self.version.lock().unwrap().clone())
    }
    fn get_value(&self, _: &SourceRef, v: &SourceVersion) -> Result<SecretPayload, ErrorCategory> {
        if *self.version.lock().unwrap() != *v {
            return Err(ErrorCategory::VersionConflict);
        }
        self.reads.lock().unwrap().1 += 1;
        Ok(SecretPayload::new(
            b"FAKE_PAYLOAD_PROBE".to_vec(),
            SecretType::Text,
        ))
    }
}
pub struct FakeTarget {
    pub applies: Mutex<u32>,
    pub fail: Mutex<bool>,
}
impl LocalTarget for FakeTarget {
    fn validate(&self, s: &TargetSpec, _: &SecretType) -> Result<(), ErrorCategory> {
        if matches!(s, TargetSpec::Fake { .. }) {
            Ok(())
        } else {
            Err(ErrorCategory::InvalidConfig)
        }
    }
    fn apply(&self, _: &TargetSpec, _: &SecretPayload) -> Result<(), ErrorCategory> {
        if *self.fail.lock().unwrap() {
            return Err(ErrorCategory::Target);
        }
        *self.applies.lock().unwrap() += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn binding() -> Binding {
        Binding {
            id: "b1".into(),
            source: SourceRef {
                store: StoreKind::Fake,
                connection: "fake".into(),
                entry: "item".into(),
            },
            secret_type: SecretType::Text,
            target: TargetSpec::Fake { slot: "one".into() },
            missing_target: MissingTargetPolicy::Alert,
            schedule: Schedule {
                interval_seconds: 1,
            },
        }
    }
    #[test]
    fn rejects_secret_fields_and_bad_versions() {
        let root = Path::new("/");
        let valid = serde_json::to_value(Config {
            version: 1,
            bindings: vec![binding()],
        })
        .unwrap();
        assert!(validate_config(serde_json::to_string(&valid).unwrap().as_bytes(), root).is_ok());
        let mut bad = valid.clone();
        bad["bindings"][0]["credential"] = "forbidden".into();
        assert!(validate_config(serde_json::to_string(&bad).unwrap().as_bytes(), root).is_err());
        let mut bad_id = valid.clone();
        bad_id["bindings"][0]["id"] = "credential\nvalue".into();
        assert!(validate_config(serde_json::to_string(&bad_id).unwrap().as_bytes(), root).is_err());
        let mut future = valid;
        future["version"] = 2.into();
        assert!(validate_config(serde_json::to_string(&future).unwrap().as_bytes(), root).is_err());
    }
    #[tokio::test]
    async fn metadata_first_and_failed_apply_retry() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FakeStore {
            version: Mutex::new(SourceVersion("v1".into())),
            reads: Mutex::new((0, 0)),
        });
        let target = Arc::new(FakeTarget {
            applies: Mutex::new(0),
            fail: Mutex::new(false),
        });
        let engine = Engine::new(
            Config {
                version: 1,
                bindings: vec![binding()],
            },
            dir.path().join("state.json"),
            dir.path().join("events.ndjson"),
            store.clone(),
            target.clone(),
        )
        .unwrap();
        assert_eq!(engine.sync("b1").await, SyncOutcome::Applied);
        assert_eq!(engine.sync("b1").await, SyncOutcome::Unchanged);
        assert_eq!(*store.reads.lock().unwrap(), (2, 1));
        *store.version.lock().unwrap() = SourceVersion("v2".into());
        *target.fail.lock().unwrap() = true;
        assert_eq!(
            engine.sync("b1").await,
            SyncOutcome::Failed(ErrorCategory::Target)
        );
        assert_eq!(engine.status().applied["b1"].0, "v1");
        assert_eq!(
            engine.status().status["b1"].outcome,
            SyncOutcome::Failed(ErrorCategory::Target)
        );
        *target.fail.lock().unwrap() = false;
        assert_eq!(engine.sync("b1").await, SyncOutcome::Applied);
        assert_eq!(engine.status().applied["b1"].0, "v2");
        assert_eq!(engine.status().status["b1"].outcome, SyncOutcome::Applied);
        assert_eq!(
            load_state(&dir.path().join("state.json")).unwrap().applied["b1"].0,
            "v2"
        );
        for line in fs::read_to_string(dir.path().join("events.ndjson"))
            .unwrap()
            .lines()
        {
            let _: Event = serde_json::from_str(line).unwrap();
        }
    }
    #[test]
    fn retry_and_screen_contract() {
        struct DuplicateStoreScreen;
        impl SettingsScreen for DuplicateStoreScreen {
            fn module_id(&self) -> &'static str {
                "fake_store"
            }
            fn kind(&self) -> ModuleKind {
                ModuleKind::Store
            }
            fn supported_types(&self) -> &'static [SecretType] {
                &[SecretType::Text]
            }
            fn render(&self) -> &'static str {
                "replacement"
            }
            fn configure(&self, _: &str) -> Result<ModuleSetting, ErrorCategory> {
                Err(ErrorCategory::InvalidConfig)
            }
        }
        assert_eq!(retry_delay(1, 0).as_millis(), 2000);
        assert_eq!(retry_delay(1, 500).as_millis(), 2500);
        let mut r = ModuleRegistry::new();
        r.register(Arc::new(FakeStoreScreen)).unwrap();
        r.register(Arc::new(FakeTargetScreen)).unwrap();
        assert_eq!(
            r.mount("fake_store"),
            Some("Fake store settings: connection,entry")
        );
        assert_eq!(r.mount("fake_target"), Some("Fake target settings: slot"));
        assert!(matches!(
            r.configure("fake_store", "c,e"),
            Ok(ModuleSetting::Source(_))
        ));
        assert!(matches!(
            r.configure("fake_target", "slot"),
            Ok(ModuleSetting::Target(_))
        ));
        assert_eq!(r.capability("fake_store").unwrap().0, ModuleKind::Store);
        assert_eq!(r.capability("fake_target").unwrap().0, ModuleKind::Target);
        assert!(matches!(
            r.register(Arc::new(DuplicateStoreScreen)),
            Err(ErrorCategory::InvalidConfig)
        ));
        assert_eq!(
            r.mount("fake_store"),
            Some("Fake store settings: connection,entry")
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_triggers_share_single_flight() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FakeStore {
            version: Mutex::new(SourceVersion("v1".into())),
            reads: Mutex::new((0, 0)),
        });
        let target = Arc::new(FakeTarget {
            applies: Mutex::new(0),
            fail: Mutex::new(false),
        });
        let engine = Arc::new(
            Engine::new(
                Config {
                    version: 1,
                    bindings: vec![binding()],
                },
                dir.path().join("state.json"),
                dir.path().join("events.ndjson"),
                store,
                target.clone(),
            )
            .unwrap(),
        );
        let mut tasks = Vec::new();
        for _ in 0..12 {
            let engine = engine.clone();
            tasks.push(tokio::spawn(async move { engine.sync("b1").await }));
        }
        let mut applied = 0;
        for task in tasks {
            if task.await.unwrap() == SyncOutcome::Applied {
                applied += 1;
            }
        }
        assert_eq!(applied, 1);
        assert_eq!(*target.applies.lock().unwrap(), 1);
    }

    #[test]
    fn event_rotation_keeps_one_previous_file() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FakeStore {
            version: Mutex::new(SourceVersion("v1".into())),
            reads: Mutex::new((0, 0)),
        });
        let target = Arc::new(FakeTarget {
            applies: Mutex::new(0),
            fail: Mutex::new(false),
        });
        let engine = Engine::new(
            Config {
                version: 1,
                bindings: vec![binding()],
            },
            dir.path().join("state.json"),
            dir.path().join("events.ndjson"),
            store,
            target,
        )
        .unwrap();
        fs::write(&engine.events_path, vec![b' '; 1024 * 1024]).unwrap();
        engine
            .append_event(&Event {
                timestamp: 1,
                binding_id: "b1".into(),
                operation: EventOperation::Sync,
                source_kind: StoreKind::Fake,
                outcome: SyncOutcome::Unchanged,
            })
            .unwrap();
        assert!(engine.events_path.with_extension("ndjson.1").exists());
        assert!(fs::metadata(&engine.events_path).unwrap().len() < 1024 * 1024);
    }
}
