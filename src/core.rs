use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

pub const SCHEMA_VERSION: u32 = 1;

pub fn acquire_agent_lock(path: &Path) -> std::io::Result<fs::File> {
    if fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink()) {
        return Err(std::io::Error::other("agent lock path is a symlink"));
    }
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    file.try_lock_exclusive()?;
    Ok(file)
}

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
        format: StructuredFormat,
    },
    DockerInput {
        path: PathBuf,
        key: String,
        input: DockerInputKind,
    },
    GitCredential {
        protocol: String,
        host: String,
        path: Option<String>,
        username: String,
    },
}
#[derive(Clone, Hash, PartialEq, Eq)]
enum TargetIdentity {
    File(PathBuf),
    GitCredential(String, String, Option<String>),
    Fake(String),
}
impl TargetSpec {
    fn identity(&self) -> TargetIdentity {
        match self {
            Self::WholeFile { path }
            | Self::StructuredField { path, .. }
            | Self::DockerInput { path, .. } => TargetIdentity::File(path.clone()),
            Self::GitCredential {
                protocol,
                host,
                path,
                ..
            } => TargetIdentity::GitCredential(protocol.clone(), host.clone(), path.clone()),
            Self::Fake { slot } => TargetIdentity::Fake(slot.clone()),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StructuredFormat {
    DotEnv,
    Json,
    Yaml,
    Properties,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DockerInputKind {
    ComposeEnvironment,
    EnvFile {
        compose_path: PathBuf,
        service: String,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MissingTargetPolicy {
    Alert,
    Recreate,
    Disable,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Schedule {
    pub interval_seconds: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
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
    #[serde(default)]
    pub disabled: BTreeSet<String>,
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
    RestartRequired,
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
    fn is_missing(&self, _spec: &TargetSpec) -> bool {
        false
    }
    fn apply_with_policy(
        &self,
        spec: &TargetSpec,
        payload: &SecretPayload,
        _policy: &MissingTargetPolicy,
    ) -> Result<(), ErrorCategory> {
        self.apply(spec, payload)
    }
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
            TargetSpec::WholeFile { path } if valid_scoped_path(path, root) => {}
            TargetSpec::StructuredField { path, key, format }
                if valid_scoped_path(path, root) && valid_field_key(key, format) => {}
            TargetSpec::DockerInput { path, key, input }
                if valid_scoped_path(path, root) && valid_docker_key(key, input, root) => {}
            TargetSpec::GitCredential {
                protocol,
                host,
                path,
                username,
            } if protocol == "https"
                && safe_host(host)
                && safe_git_path(path.as_deref())
                && safe_git_username(username) => {}
            _ => return Err(ErrorCategory::InvalidConfig),
        }
        if matches!(b.source.store, StoreKind::Fake) != matches!(b.target, TargetSpec::Fake { .. })
            || !matches!(b.source.store, StoreKind::Fake | StoreKind::LocalVault)
        {
            return Err(ErrorCategory::InvalidConfig);
        }
    }
    Ok(config)
}
fn valid_scoped_path(path: &Path, root: &Path) -> bool {
    if !path.is_absolute()
        || !path.starts_with(root)
        || path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return false;
    }
    let Ok(approved) = root.canonicalize() else {
        return false;
    };
    let Some(parent) = path.parent() else {
        return false;
    };
    let Ok(parent) = parent.canonicalize() else {
        return false;
    };
    if !parent.starts_with(approved) {
        return false;
    }
    !fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink())
}
fn valid_field_key(key: &str, format: &StructuredFormat) -> bool {
    match format {
        StructuredFormat::DotEnv | StructuredFormat::Properties => {
            !key.is_empty()
                && key
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
        }
        StructuredFormat::Json | StructuredFormat::Yaml => {
            key.starts_with('/') && key.len() > 1 && !key.contains('\n') && !key.contains('\r')
        }
    }
}
fn valid_docker_key(key: &str, input: &DockerInputKind, root: &Path) -> bool {
    let valid_name = |name: &str| {
        !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    };
    match input {
        DockerInputKind::EnvFile {
            compose_path,
            service,
        } => valid_name(key) && safe_label(service) && valid_scoped_path(compose_path, root),
        DockerInputKind::ComposeEnvironment => key
            .split_once(':')
            .is_some_and(|(service, variable)| safe_label(service) && valid_name(variable)),
    }
}
fn safe_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'))
}
fn safe_git_path(path: Option<&str>) -> bool {
    path.is_none_or(|p| {
        !p.is_empty()
            && p.len() <= 512
            && !p.starts_with('/')
            && p.split('/').all(|part| {
                !part.is_empty()
                    && part != "."
                    && part != ".."
                    && part
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
            })
    })
}
fn safe_git_username(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|b| (0x21..=0x7e).contains(&b) && b != b'=' && b != b'\\')
}
fn atomic_json<T: Serialize>(path: &Path, value: &T) -> Result<(), ErrorCategory> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|_| ErrorCategory::State)?;
    let tmp = path.with_extension("tmp");
    let mut f = fs::File::create(&tmp).map_err(|_| ErrorCategory::State)?;
    f.write_all(&bytes)
        .and_then(|_| f.sync_all())
        .map_err(|_| ErrorCategory::State)?;
    // ReplaceFileW needs to reopen the replacement with read/delete access.
    // File::create leaves a write-only handle open until explicitly dropped.
    drop(f);
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
        || s.disabled.iter().any(|k| !safe_label(k))
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
    AcknowledgeRestart,
    Enable,
}
pub struct Engine {
    pub config: Config,
    pub state: Mutex<State>,
    pub state_path: PathBuf,
    pub events_path: PathBuf,
    pub source: Arc<dyn SourceConnection>,
    pub target: Arc<dyn LocalTarget>,
    flights: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    target_flights: Mutex<HashMap<TargetIdentity, Arc<tokio::sync::Mutex<()>>>>,
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
            target_flights: Mutex::new(HashMap::new()),
        })
    }
    pub fn invalidate_bindings(&self, ids: &[String]) -> Result<(), ErrorCategory> {
        let mut state = self.state.lock().map_err(|_| ErrorCategory::State)?;
        let mut next = state.clone();
        for id in ids {
            next.applied.remove(id);
            next.status.remove(id);
            next.disabled.remove(id);
        }
        atomic_json(&self.state_path, &next)?;
        *state = next;
        Ok(())
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
        if self.state.lock().unwrap().disabled.contains(id) {
            return SyncOutcome::Disabled;
        }
        let outcome = self.sync_inner(binding).await;
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
            if outcome == SyncOutcome::Disabled {
                next.disabled.insert(id.to_owned());
            }
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
    pub async fn enable_binding(&self, id: &str) -> Result<(), ErrorCategory> {
        let binding = self
            .config
            .bindings
            .iter()
            .find(|b| b.id == id)
            .ok_or(ErrorCategory::InvalidConfig)?;
        let gate = {
            let mut gates = self.flights.lock().unwrap();
            gates
                .entry(id.to_owned())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                .clone()
        };
        let _flight = gate.lock().await;
        let mut state = self.state.lock().unwrap();
        let mut next = state.clone();
        if !next.disabled.remove(id) {
            return Err(ErrorCategory::InvalidConfig);
        }
        atomic_json(&self.state_path, &next)?;
        *state = next;
        drop(state);
        self.append_event(&Event {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            binding_id: id.to_owned(),
            operation: EventOperation::Enable,
            source_kind: binding.source.store.clone(),
            outcome: SyncOutcome::Unchanged,
        })
    }
    pub async fn acknowledge_restart(&self, id: &str) -> Result<(), ErrorCategory> {
        let binding = self
            .config
            .bindings
            .iter()
            .find(|b| b.id == id)
            .ok_or(ErrorCategory::InvalidConfig)?;
        if !matches!(binding.target, TargetSpec::DockerInput { .. }) {
            return Err(ErrorCategory::InvalidConfig);
        }
        let gate = {
            let mut gates = self.flights.lock().unwrap();
            gates
                .entry(id.to_owned())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                .clone()
        };
        let _flight = gate.lock().await;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        {
            let mut state = self.state.lock().unwrap();
            if !matches!(
                state.status.get(id).map(|s| &s.outcome),
                Some(SyncOutcome::RestartRequired)
            ) {
                return Err(ErrorCategory::InvalidConfig);
            }
            let mut next = state.clone();
            next.status.insert(
                id.to_owned(),
                RedactedStatus {
                    timestamp,
                    outcome: SyncOutcome::Unchanged,
                },
            );
            atomic_json(&self.state_path, &next)?;
            *state = next;
        }
        self.append_event(&Event {
            timestamp,
            binding_id: id.to_owned(),
            operation: EventOperation::AcknowledgeRestart,
            source_kind: binding.source.store.clone(),
            outcome: SyncOutcome::Unchanged,
        })
    }
    async fn sync_inner(&self, b: &Binding) -> SyncOutcome {
        if let Err(e) = self.target.validate(&b.target, &b.secret_type) {
            return SyncOutcome::Failed(e);
        }
        let target_missing = self.target.is_missing(&b.target);
        if target_missing {
            match &b.missing_target {
                MissingTargetPolicy::Alert => return SyncOutcome::Failed(ErrorCategory::Target),
                MissingTargetPolicy::Disable => return SyncOutcome::Disabled,
                MissingTargetPolicy::Recreate => {}
            }
        }
        let version = match self.source.get_version(&b.source) {
            Ok(v) => v,
            Err(e) => return SyncOutcome::Failed(e),
        };
        if !safe_version(&version.0) {
            return SyncOutcome::Failed(ErrorCategory::VersionConflict);
        }
        if !target_missing && self.state.lock().unwrap().applied.get(&b.id) == Some(&version) {
            return if matches!(b.target, TargetSpec::DockerInput { .. })
                && matches!(
                    self.state
                        .lock()
                        .unwrap()
                        .status
                        .get(&b.id)
                        .map(|s| &s.outcome),
                    Some(SyncOutcome::RestartRequired)
                ) {
                SyncOutcome::RestartRequired
            } else {
                SyncOutcome::Unchanged
            };
        }
        let payload = match self.source.get_value(&b.source, &version) {
            Ok(p) => p,
            Err(e) => return SyncOutcome::Failed(e),
        };
        if payload.kind != b.secret_type {
            return SyncOutcome::Failed(ErrorCategory::VersionConflict);
        }
        let target_gate = {
            let mut gates = self.target_flights.lock().unwrap();
            gates
                .entry(b.target.identity())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                .clone()
        };
        let _target_flight = target_gate.lock().await;
        if let Err(e) = self
            .target
            .apply_with_policy(&b.target, &payload, &b.missing_target)
        {
            return SyncOutcome::Failed(e);
        }
        let mut state = self.state.lock().unwrap();
        let mut next = state.clone();
        next.applied.insert(b.id.clone(), version);
        if atomic_json(&self.state_path, &next).is_err() {
            return SyncOutcome::Failed(ErrorCategory::State);
        }
        *state = next;
        if matches!(b.target, TargetSpec::DockerInput { .. }) {
            SyncOutcome::RestartRequired
        } else {
            SyncOutcome::Applied
        }
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
    #[test]
    fn state_replacement_persists_repeated_updates() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let mut state = State {
            version: SCHEMA_VERSION,
            ..State::default()
        };
        atomic_json(&path, &state).unwrap();
        for version in ["v1", "v2", "v3"] {
            state
                .applied
                .insert("binding".into(), SourceVersion(version.into()));
            atomic_json(&path, &state).unwrap();
            assert_eq!(load_state(&path).unwrap().applied, state.applied);
            assert!(!path.with_extension("tmp").exists());
        }
    }

    #[test]
    fn failed_replacement_preserves_previous_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let state = State {
            version: SCHEMA_VERSION,
            ..State::default()
        };
        atomic_json(&path, &state).unwrap();
        let previous = fs::read(&path).unwrap();
        assert!(replace_file(&dir.path().join("missing.tmp"), &path).is_err());
        assert_eq!(fs::read(&path).unwrap(), previous);
    }

    #[test]
    fn single_agent_lock_rejects_second_writer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.lock");
        let first = acquire_agent_lock(&path).unwrap();
        assert!(acquire_agent_lock(&path).is_err());
        drop(first);
        assert!(acquire_agent_lock(&path).is_ok());
    }
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

    #[tokio::test]
    async fn docker_restart_notice_and_recreate_are_explicit() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FakeStore {
            version: Mutex::new(SourceVersion("v1".into())),
            reads: Mutex::new((0, 0)),
        });
        let target_path = dir.path().join("app.env");
        fs::write(
            dir.path().join("compose.yaml"),
            "services:\n  web:\n    env_file: app.env\n",
        )
        .unwrap();
        let engine = Engine::new(
            Config {
                version: 1,
                bindings: vec![Binding {
                    target: TargetSpec::DockerInput {
                        path: target_path.clone(),
                        key: "TOKEN".into(),
                        input: DockerInputKind::EnvFile {
                            compose_path: dir.path().join("compose.yaml"),
                            service: "web".into(),
                        },
                    },
                    missing_target: MissingTargetPolicy::Recreate,
                    ..binding()
                }],
            },
            dir.path().join("state.json"),
            dir.path().join("events.ndjson"),
            store.clone(),
            Arc::new(crate::targets::ProductionTarget::new(dir.path().to_path_buf()).unwrap()),
        )
        .unwrap();
        assert_eq!(engine.sync("b1").await, SyncOutcome::RestartRequired);
        assert!(target_path.exists());
        assert_eq!(engine.sync("b1").await, SyncOutcome::RestartRequired);
        assert_eq!(*store.reads.lock().unwrap(), (2, 1));
        engine.acknowledge_restart("b1").await.unwrap();
        assert_eq!(engine.sync("b1").await, SyncOutcome::Unchanged);
        fs::remove_file(&target_path).unwrap();
        assert_eq!(engine.sync("b1").await, SyncOutcome::RestartRequired);
        assert_eq!(*store.reads.lock().unwrap(), (4, 2));
    }

    #[tokio::test]
    async fn local_vault_rotation_updates_authorized_file_without_persisting_payload_metadata() {
        use crate::vault::{LocalVault, VaultSource};
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("vault.bin");
        let target_path = dir.path().join("target.bin");
        fs::write(&target_path, b"old").unwrap();
        let mut vault = LocalVault::create(&vault_path, "test-only-passphrase").unwrap();
        vault
            .put(
                "entry",
                &SecretPayload::new(b"PROBE-ONE".to_vec(), SecretType::Binary),
            )
            .unwrap();
        vault.lock();
        let source = Arc::new(VaultSource::new(vault_path.clone(), "local".into()).unwrap());
        source.unlock("test-only-passphrase").unwrap();
        let binding = Binding {
            id: "b1".into(),
            source: SourceRef {
                store: StoreKind::LocalVault,
                connection: "local".into(),
                entry: "entry".into(),
            },
            secret_type: SecretType::Binary,
            target: TargetSpec::WholeFile {
                path: target_path.clone(),
            },
            missing_target: MissingTargetPolicy::Alert,
            schedule: Schedule {
                interval_seconds: 60,
            },
        };
        let config = Config {
            version: 1,
            bindings: vec![binding],
        };
        let bytes = serde_json::to_vec(&config).unwrap();
        let config = validate_config(&bytes, dir.path()).unwrap();
        let engine = Engine::new(
            config,
            dir.path().join("state.json"),
            dir.path().join("events.ndjson"),
            source,
            Arc::new(crate::targets::ProductionTarget::new(dir.path().to_path_buf()).unwrap()),
        )
        .unwrap();
        assert_eq!(engine.sync("b1").await, SyncOutcome::Applied);
        assert_eq!(fs::read(&target_path).unwrap(), b"PROBE-ONE");
        assert_eq!(engine.sync("b1").await, SyncOutcome::Unchanged);
        let mut vault = LocalVault::unlock(&vault_path, "test-only-passphrase").unwrap();
        vault
            .put(
                "entry",
                &SecretPayload::new(b"PROBE-TWO".to_vec(), SecretType::Binary),
            )
            .unwrap();
        assert_eq!(engine.sync("b1").await, SyncOutcome::Applied);
        assert_eq!(fs::read(&target_path).unwrap(), b"PROBE-TWO");
        let metadata = [
            fs::read(dir.path().join("state.json")).unwrap(),
            fs::read(dir.path().join("events.ndjson")).unwrap(),
        ]
        .concat();
        assert!(!metadata
            .windows(b"PROBE-TWO".len())
            .any(|window| window == b"PROBE-TWO"));
    }

    #[tokio::test]
    async fn missing_target_disable_requires_explicit_enable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("target.txt");
        let store = Arc::new(FakeStore {
            version: Mutex::new(SourceVersion("v1".into())),
            reads: Mutex::new((0, 0)),
        });
        let engine = Engine::new(
            Config {
                version: 1,
                bindings: vec![Binding {
                    target: TargetSpec::WholeFile { path: path.clone() },
                    missing_target: MissingTargetPolicy::Disable,
                    ..binding()
                }],
            },
            dir.path().join("state.json"),
            dir.path().join("events.ndjson"),
            store.clone(),
            Arc::new(crate::targets::ProductionTarget::new(dir.path().to_path_buf()).unwrap()),
        )
        .unwrap();
        assert_eq!(engine.sync("b1").await, SyncOutcome::Disabled);
        assert!(engine.status().disabled.contains("b1"));
        fs::write(&path, b"old").unwrap();
        assert_eq!(engine.sync("b1").await, SyncOutcome::Disabled);
        assert_eq!(*store.reads.lock().unwrap(), (0, 0));
        engine.enable_binding("b1").await.unwrap();
        assert_eq!(engine.sync("b1").await, SyncOutcome::Applied);
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
