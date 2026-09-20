//! Native management window. No browser, web server, or UI persistence.

use crate::{
    core::{
        self, Binding, Config, DockerInputKind, Engine, LocalTarget, MissingTargetPolicy, Schedule,
        SecretPayload, SecretType, SourceRef, StoreKind, StructuredFormat, SyncOutcome, TargetSpec,
    },
    scheduler,
    targets::ProductionTarget,
    vault::VaultSource,
};
use eframe::egui::{self, Color32, RichText};
use std::{
    fs,
    io::Write,
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::task::JoinHandle;
use zeroize::{Zeroize, Zeroizing};

const ACCENT: Color32 = Color32::from_rgb(15, 118, 110);
const MUTED: Color32 = Color32::from_rgb(105, 119, 137);
const INK: Color32 = Color32::from_rgb(24, 39, 57);
const CANVAS: Color32 = Color32::from_rgb(245, 247, 250);
const BORDER: Color32 = Color32::from_rgb(225, 231, 237);
const NAV: Color32 = Color32::from_rgb(19, 32, 48);
const DANGER: Color32 = Color32::from_rgb(185, 55, 62);
const BRAND_MARK: &[u8] = include_bytes!("../assets/branding/tar-vault-sync-mark-v1.png");

#[derive(Clone, Copy, PartialEq, Eq)]
enum Page {
    Overview,
    Vault,
    Bindings,
    Events,
    Settings,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TargetChoice {
    WholeFile,
    DotEnv,
    Json,
    Yaml,
    Properties,
    DockerCompose,
    DockerEnvFile,
    GitCredential,
}
impl TargetChoice {
    const ALL: [Self; 8] = [
        Self::WholeFile,
        Self::DotEnv,
        Self::Json,
        Self::Yaml,
        Self::Properties,
        Self::DockerCompose,
        Self::DockerEnvFile,
        Self::GitCredential,
    ];
    fn label(self) -> &'static str {
        match self {
            Self::WholeFile => "Whole file",
            Self::DotEnv => ".env variable",
            Self::Json => "JSON field",
            Self::Yaml => "YAML field",
            Self::Properties => "Properties field",
            Self::DockerCompose => "Docker Compose environment",
            Self::DockerEnvFile => "Docker env_file",
            Self::GitCredential => "Git Credential Manager",
        }
    }
}

struct BindingForm {
    original_id: Option<String>,
    source_kind: StoreKind,
    connection: String,
    id: String,
    entry: String,
    secret_type: SecretType,
    target_kind: TargetChoice,
    path: String,
    key: String,
    compose_path: String,
    service: String,
    host: String,
    git_path: String,
    username: String,
    policy: MissingTargetPolicy,
    interval: String,
}
impl Default for BindingForm {
    fn default() -> Self {
        Self {
            original_id: None,
            source_kind: StoreKind::LocalVault,
            connection: String::new(),
            id: String::new(),
            entry: String::new(),
            secret_type: SecretType::Text,
            target_kind: TargetChoice::WholeFile,
            path: String::new(),
            key: String::new(),
            compose_path: String::new(),
            service: String::new(),
            host: String::new(),
            git_path: String::new(),
            username: String::new(),
            policy: MissingTargetPolicy::Alert,
            interval: "60".into(),
        }
    }
}
impl BindingForm {
    fn from_binding(binding: &Binding) -> Self {
        let mut form = Self {
            original_id: Some(binding.id.clone()),
            source_kind: binding.source.store.clone(),
            connection: binding.source.connection.clone(),
            id: binding.id.clone(),
            entry: binding.source.entry.clone(),
            secret_type: binding.secret_type.clone(),
            policy: binding.missing_target.clone(),
            interval: binding.schedule.interval_seconds.to_string(),
            ..Self::default()
        };
        match &binding.target {
            TargetSpec::WholeFile { path } => {
                form.target_kind = TargetChoice::WholeFile;
                form.path = path.display().to_string();
            }
            TargetSpec::StructuredField { path, key, format } => {
                form.path = path.display().to_string();
                form.key = key.clone();
                form.target_kind = match format {
                    StructuredFormat::DotEnv => TargetChoice::DotEnv,
                    StructuredFormat::Json => TargetChoice::Json,
                    StructuredFormat::Yaml => TargetChoice::Yaml,
                    StructuredFormat::Properties => TargetChoice::Properties,
                };
            }
            TargetSpec::DockerInput { path, key, input } => {
                form.path = path.display().to_string();
                form.key = key.clone();
                match input {
                    DockerInputKind::ComposeEnvironment => {
                        form.target_kind = TargetChoice::DockerCompose
                    }
                    DockerInputKind::EnvFile {
                        compose_path,
                        service,
                    } => {
                        form.target_kind = TargetChoice::DockerEnvFile;
                        form.compose_path = compose_path.display().to_string();
                        form.service = service.clone();
                    }
                }
            }
            TargetSpec::GitCredential {
                host,
                path,
                username,
                ..
            } => {
                form.target_kind = TargetChoice::GitCredential;
                form.host = host.clone();
                form.git_path = path.clone().unwrap_or_default();
                form.username = username.clone();
            }
            TargetSpec::Fake { .. } => {}
        }
        form
    }
    fn binding(&self) -> Result<Binding, &'static str> {
        let target = match self.target_kind {
            TargetChoice::WholeFile => TargetSpec::WholeFile {
                path: self.path.clone().into(),
            },
            TargetChoice::DotEnv
            | TargetChoice::Json
            | TargetChoice::Yaml
            | TargetChoice::Properties => {
                let format = match self.target_kind {
                    TargetChoice::DotEnv => StructuredFormat::DotEnv,
                    TargetChoice::Json => StructuredFormat::Json,
                    TargetChoice::Yaml => StructuredFormat::Yaml,
                    _ => StructuredFormat::Properties,
                };
                TargetSpec::StructuredField {
                    path: self.path.clone().into(),
                    key: self.key.clone(),
                    format,
                }
            }
            TargetChoice::DockerCompose => TargetSpec::DockerInput {
                path: self.path.clone().into(),
                key: self.key.clone(),
                input: DockerInputKind::ComposeEnvironment,
            },
            TargetChoice::DockerEnvFile => TargetSpec::DockerInput {
                path: self.path.clone().into(),
                key: self.key.clone(),
                input: DockerInputKind::EnvFile {
                    compose_path: self.compose_path.clone().into(),
                    service: self.service.clone(),
                },
            },
            TargetChoice::GitCredential => TargetSpec::GitCredential {
                protocol: "https".into(),
                host: self.host.clone(),
                path: (!self.git_path.is_empty()).then(|| self.git_path.clone()),
                username: self.username.clone(),
            },
        };
        let interval_seconds = self
            .interval
            .parse()
            .map_err(|_| "Enter a valid check interval.")?;
        Ok(Binding {
            id: self.id.clone(),
            source: SourceRef {
                store: self.source_kind.clone(),
                connection: if self.source_kind == StoreKind::LocalVault {
                    "local".into()
                } else {
                    self.connection.clone()
                },
                entry: self.entry.clone(),
            },
            secret_type: self.secret_type.clone(),
            target,
            missing_target: self.policy.clone(),
            schedule: Schedule { interval_seconds },
        })
    }
}

struct DesktopApp {
    brand_texture: Option<egui::TextureHandle>,
    pending_sync: Option<JoinHandle<SyncOutcome>>,
    root: PathBuf,
    source: Arc<VaultSource>,
    target: Arc<ProductionTarget>,
    engine: Arc<Engine>,
    runtime: tokio::runtime::Runtime,
    schedules: Vec<JoinHandle<()>>,
    config_bytes: Option<Vec<u8>>,
    page: Page,
    message: String,
    is_error: bool,
    passphrase: Zeroizing<String>,
    entry_id: String,
    entry_kind: SecretType,
    secret_text: Zeroizing<String>,
    secret_file: String,
    backup_path: String,
    import_path: String,
    import_prefix: String,
    import_consent: bool,
    root_input: String,
    form: BindingForm,
    editing: bool,
    pending_delete_entry: Option<String>,
    pending_delete_binding: Option<String>,
}

impl DesktopApp {
    fn new(root: PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        fs::create_dir_all(root.join("shared"))?;
        fs::create_dir_all(root.join("local"))?;
        let config_path = root.join("shared/config.json");
        let config_bytes = match fs::read(&config_path) {
            Ok(bytes) => Some(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        let config = if let Some(bytes) = &config_bytes {
            core::validate_config(bytes, &root)?
        } else {
            Config {
                version: core::SCHEMA_VERSION,
                bindings: Vec::new(),
            }
        };
        if config.bindings.iter().any(|b| {
            !matches!(b.source.store, StoreKind::LocalVault | StoreKind::Azure)
                || (b.source.store == StoreKind::LocalVault && b.source.connection != "local")
        }) {
            return Err(
                "The desktop app supports local vault and Azure Key Vault bindings.".into(),
            );
        }
        let source = Arc::new(VaultSource::new(
            root.join("local/vault.bin"),
            "local".into(),
        )?);
        let target = Arc::new(ProductionTarget::new(root.clone())?);
        let sources = Arc::new(crate::azure::DesktopSources {
            local: source.clone(),
            azure: crate::azure::AzureSource::new(),
        });
        let engine = Arc::new(Engine::new(
            config,
            root.join("local/state.json"),
            root.join("local/events.ndjson"),
            sources,
            target.clone(),
        )?);
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        let schedules = spawn_schedules(&runtime, &engine);
        Ok(Self {
            brand_texture: None,
            pending_sync: None,
            root_input: root.display().to_string(),
            root,
            source,
            target,
            engine,
            runtime,
            schedules,
            config_bytes,
            page: Page::Overview,
            message: String::new(),
            is_error: false,
            passphrase: Zeroizing::new(String::new()),
            entry_id: String::new(),
            entry_kind: SecretType::Text,
            secret_text: Zeroizing::new(String::new()),
            secret_file: String::new(),
            backup_path: String::new(),
            import_path: String::new(),
            import_prefix: String::new(),
            import_consent: false,
            form: BindingForm::default(),
            editing: false,
            pending_delete_entry: None,
            pending_delete_binding: None,
        })
    }
    fn notice(&mut self, text: &str) {
        self.message = text.into();
        self.is_error = false;
    }
    fn error(&mut self, text: &str) {
        self.message = text.into();
        self.is_error = true;
    }
    fn save_config(&mut self, config: Config) -> Result<(), &'static str> {
        if self.pending_sync.is_some() {
            return Err("Wait for the current sync to finish before changing bindings.");
        }
        let bytes = serde_json::to_vec_pretty(&config)
            .map_err(|_| "Could not encode the configuration.")?;
        core::validate_config(&bytes, &self.root).map_err(|_| "The configuration is invalid.")?;
        for binding in &config.bindings {
            if !matches!(
                binding.source.store,
                StoreKind::LocalVault | StoreKind::Azure
            ) || (binding.source.store == StoreKind::LocalVault
                && binding.source.connection != "local")
                || self
                    .target
                    .validate(&binding.target, &binding.secret_type)
                    .is_err()
            {
                return Err("The target or secret type is invalid.");
            }
        }
        let path = self.root.join("shared/config.json");
        let on_disk = match fs::read(&path) {
            Ok(bytes) => Some(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => return Err("Could not read the configuration."),
        };
        if on_disk != self.config_bytes {
            return Err(
                "Configuration changed in another process. Reopen this window before saving.",
            );
        }
        let changed: Vec<String> = self
            .engine
            .config
            .bindings
            .iter()
            .map(|b| b.id.clone())
            .chain(config.bindings.iter().map(|b| b.id.clone()))
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .filter(|id| {
                self.engine.config.bindings.iter().find(|b| &b.id == id)
                    != config.bindings.iter().find(|b| &b.id == id)
            })
            .collect();
        for task in self.schedules.drain(..) {
            task.abort();
            let _ = self.runtime.block_on(task);
        }
        if self.engine.invalidate_bindings(&changed).is_err() {
            self.schedules = spawn_schedules(&self.runtime, &self.engine);
            return Err("Could not update binding status.");
        }
        let next = match Engine::new(
            config,
            self.root.join("local/state.json"),
            self.root.join("local/events.ndjson"),
            self.engine.source.clone(),
            self.target.clone(),
        ) {
            Ok(engine) => Arc::new(engine),
            Err(_) => {
                self.schedules = spawn_schedules(&self.runtime, &self.engine);
                return Err("Could not read the state file.");
            }
        };
        if write_config(&path, &bytes).is_err() {
            self.schedules = spawn_schedules(&self.runtime, &self.engine);
            return Err("Could not save the configuration.");
        }
        self.config_bytes = Some(bytes);
        self.schedules = spawn_schedules(&self.runtime, &next);
        self.engine = next;
        Ok(())
    }
    fn save_binding(&mut self) {
        let binding = match self.form.binding() {
            Ok(b) => b,
            Err(e) => {
                self.error(e);
                return;
            }
        };
        let mut config = self.engine.config.clone();
        if let Some(old_id) = &self.form.original_id {
            let Some(existing) = config.bindings.iter_mut().find(|b| &b.id == old_id) else {
                self.error("Binding not found.");
                return;
            };
            *existing = binding;
        } else {
            config.bindings.push(binding);
        }
        match self.save_config(config) {
            Ok(()) => {
                self.editing = false;
                self.form = BindingForm::default();
                self.notice("Binding saved. The sync schedule is up to date.");
            }
            Err(e) => self.error(e),
        }
    }
    fn delete_binding(&mut self, id: &str) {
        let mut config = self.engine.config.clone();
        config.bindings.retain(|b| b.id != id);
        match self.save_config(config) {
            Ok(()) => self.notice("Binding removed."),
            Err(e) => self.error(e),
        }
    }
    fn sync_binding(&mut self, id: &str) {
        if self.pending_sync.is_some() {
            self.notice("A sync check is already running.");
            return;
        }
        let engine = self.engine.clone();
        let id = id.to_owned();
        self.pending_sync = Some(self.runtime.spawn(async move { engine.sync(&id).await }));
        self.notice("Sync check running…");
    }
    fn vault_action(&mut self, action: &'static str) {
        let passphrase = self.passphrase.as_str();
        let result = match action {
            "create" => self.source.create(passphrase),
            "unlock" => self.source.unlock(passphrase),
            "recover" => self
                .source
                .recover(&PathBuf::from(&self.backup_path), passphrase),
            _ => return,
        };
        self.passphrase.zeroize();
        match result {
            Ok(()) => self.notice("Vault operation complete."),
            Err(_) => {
                self.error("Vault operation failed. Check the passphrase, path, and vault status.")
            }
        }
    }
    fn put_entry(&mut self) {
        let bytes = if self.secret_file.trim().is_empty() {
            std::mem::take(&mut *self.secret_text).into_bytes()
        } else {
            match fs::read(&self.secret_file) {
                Ok(bytes) => bytes,
                Err(_) => {
                    self.error("Could not read the secret file.");
                    return;
                }
            }
        };
        let payload = SecretPayload::new(bytes, self.entry_kind.clone());
        let result = self.source.put_entry(&self.entry_id, &payload);
        self.secret_text.zeroize();
        self.secret_file.clear();
        match result {
            Ok(()) => self.notice("Secret saved as a new version."),
            Err(_) => self.error("Could not save the secret."),
        }
    }
    fn import_browser_csv(&mut self) {
        let consent = std::mem::take(&mut self.import_consent);
        match crate::browser_import::import_file(
            &self.source,
            &PathBuf::from(&self.import_path),
            &self.import_prefix,
            consent,
        ) {
            Ok(count) => {
                self.import_path.clear();
                self.import_prefix.clear();
                self.notice(&format!("Imported {count} encrypted records. The original plaintext CSV was not deleted; remove it when no longer needed."));
            }
            Err(message) => self.error(message),
        }
    }
    fn header(&mut self, ui: &mut egui::Ui) {
        let (title, subtitle) = match self.page {
            Page::Overview => ("Overview", "A clear view of your local secret workspace."),
            Page::Vault => ("Vault", "Secure storage. Simple access. Always local."),
            Page::Bindings => (
                "Bindings",
                "Connect your secrets to the places they are needed.",
            ),
            Page::Events => (
                "Activity",
                "Follow sync results and changes across your workspace.",
            ),
            Page::Settings => ("Settings", "Manage your workspace and desktop agent."),
        };
        ui.label(
            RichText::new("WORKSPACE  /  TAR VAULT SYNC")
                .size(10.0)
                .strong()
                .color(MUTED),
        );
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            ui.heading(RichText::new(title).size(30.0).strong());
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let unlocked = self.source.is_unlocked();
                egui::Frame::group(ui.style())
                    .fill(if unlocked {
                        Color32::from_rgb(227, 244, 238)
                    } else {
                        CANVAS
                    })
                    .stroke(egui::Stroke::NONE)
                    .corner_radius(20)
                    .inner_margin(egui::Margin::symmetric(14, 7))
                    .show(ui, |ui| {
                        ui.label(
                            RichText::new(if unlocked {
                                "Vault unlocked"
                            } else {
                                "Vault locked"
                            })
                            .size(12.0)
                            .strong()
                            .color(if unlocked {
                                ACCENT
                            } else {
                                MUTED
                            }),
                        );
                    });
            });
        });
        ui.label(RichText::new(subtitle).color(MUTED));
        ui.add_space(22.0);
        if !self.message.is_empty() {
            card(ui)
                .fill(if self.is_error {
                    Color32::from_rgb(255, 240, 240)
                } else {
                    Color32::from_rgb(231, 246, 240)
                })
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.label(RichText::new(&self.message).color(if self.is_error {
                        DANGER
                    } else {
                        ACCENT
                    }));
                });
            ui.add_space(12.0);
        }
    }
    fn overview(&mut self, ui: &mut egui::Ui) {
        card(ui).fill(Color32::from_rgb(230, 242, 238)).stroke(egui::Stroke::NONE)
            .inner_margin(28).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(RichText::new("LOCAL FIRST. ALWAYS IN YOUR CONTROL.").size(10.0).strong().color(ACCENT));
                ui.add_space(10.0);
                ui.label(RichText::new("Your secrets. Your workspace.").size(32.0).strong().color(INK));
                ui.label(RichText::new("Keep your files, containers, and credentials in sync\nwith your local vault or Azure Key Vault.").size(15.0).color(MUTED));
                ui.add_space(12.0);
                if primary_button(ui, "Create binding").clicked() {
                    self.page = Page::Bindings;
                    self.editing = true;
                    self.form = BindingForm::default();
                }
            });
        ui.add_space(20.0);
        let state = self.engine.status();
        let attention = self
            .engine
            .config
            .bindings
            .iter()
            .filter(|binding| {
                state.disabled.contains(&binding.id)
                    || state.status.get(&binding.id).is_some_and(|s| {
                        matches!(
                            s.outcome,
                            SyncOutcome::Failed(_) | SyncOutcome::RestartRequired
                        )
                    })
            })
            .count();
        ui.columns(3, |columns| {
            metric(
                &mut columns[0],
                "SYNC BINDINGS",
                &self.engine.config.bindings.len().to_string(),
                "Connected local targets",
                INK,
            );
            metric(
                &mut columns[1],
                "LOCAL VAULT STATUS",
                if self.source.is_unlocked() {
                    "Unlocked"
                } else {
                    "Locked"
                },
                if self.source.is_unlocked() {
                    "Ready to sync"
                } else {
                    "Unlock to access secrets"
                },
                ACCENT,
            );
            metric(
                &mut columns[2],
                "NEEDS ATTENTION",
                &attention.to_string(),
                "Errors or pending restarts",
                if attention == 0 { INK } else { DANGER },
            );
        });
        ui.add_space(24.0);
        ui.horizontal(|ui| {
            ui.heading("Binding health");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.link("View all bindings").clicked() {
                    self.page = Page::Bindings;
                }
            });
        });
        ui.add_space(8.0);
        card(ui).show(ui, |ui| {
            ui.set_width(ui.available_width());
            if self.engine.config.bindings.is_empty() {
                ui.add_space(8.0);
                ui.strong("Start with your first secret");
                ui.label(
                    RichText::new(
                        "Create or unlock your vault, add a secret, then connect a local target.",
                    )
                    .color(MUTED),
                );
                ui.add_space(8.0);
                if ui.button("Open vault").clicked() {
                    self.page = Page::Vault;
                }
                ui.add_space(8.0);
            } else {
                egui::Grid::new("binding_health")
                    .num_columns(3)
                    .spacing([30.0, 16.0])
                    .show(ui, |ui| {
                        for label in ["BINDING", "TARGET", "STATUS"] {
                            ui.label(RichText::new(label).size(10.0).strong().color(MUTED));
                        }
                        ui.end_row();
                        for binding in &self.engine.config.bindings {
                            ui.strong(&binding.id);
                            ui.label(target_label(&binding.target));
                            let outcome = if state.disabled.contains(&binding.id) {
                                "Disabled".into()
                            } else {
                                state
                                    .status
                                    .get(&binding.id)
                                    .map(|s| outcome_label(&s.outcome).to_owned())
                                    .unwrap_or_else(|| "Pending".into())
                            };
                            ui.label(outcome);
                            ui.end_row();
                        }
                    });
            }
        });
    }
    fn vault(&mut self, ui: &mut egui::Ui) {
        ui.label(RichText::new("Manage encrypted secrets and backups. Your vault locks after 15 minutes of inactivity.").color(MUTED));
        ui.add_space(14.0);
        card(ui).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.heading("Vault access");
            secret_field(ui, "Passphrase", &mut self.passphrase);
            ui.horizontal(|ui| {
                if !self.source.exists() && primary_button(ui, "Create vault").clicked() {
                    self.vault_action("create");
                }
                if self.source.exists() && primary_button(ui, "Unlock vault").clicked() {
                    self.vault_action("unlock");
                }
                if ui.button("Lock vault").clicked() {
                    self.source.lock();
                    self.passphrase.zeroize();
                    self.notice("Vault locked.");
                }
            });
        });
        ui.add_space(12.0);
        card(ui).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.heading("Encrypted backup");
            field(ui, "Backup file path", &mut self.backup_path);
            ui.horizontal(|ui| {
                if ui.button("Create backup").clicked() {
                    match self.source.backup(&PathBuf::from(&self.backup_path)) {
                        Ok(()) => self.notice("Encrypted backup created."),
                        Err(_) => self.error("Could not create the backup."),
                    }
                }
                if ui.button("Restore backup").clicked() {
                    self.vault_action("recover");
                }
            });
            ui.label(
                RichText::new("Restore is available only when no vault exists in this workspace.")
                    .color(MUTED),
            );
        });
        ui.add_space(17.0);
        ui.heading("Saved secrets");
        ui.separator();
        match self.source.entries() {
            Ok(entries) if entries.is_empty() => {
                ui.label(
                    RichText::new("No secrets yet. Add your first secret below.").color(MUTED),
                );
            }
            Ok(entries) => {
                let mut remove = None;
                for entry in entries {
                    ui.horizontal(|ui| {
                        ui.strong(&entry.id);
                        ui.label(secret_type_label(&entry.kind));
                        ui.label(
                            RichText::new(format!(
                                "Version {}",
                                &entry.version[..8.min(entry.version.len())]
                            ))
                            .color(MUTED),
                        );
                        if self.pending_delete_entry.as_deref() == Some(entry.id.as_str()) {
                            ui.label(RichText::new("Remove this item?").color(DANGER));
                            if ui.button("Confirm removal").clicked() {
                                remove = Some(entry.id.clone());
                            }
                            if ui.button("Cancel").clicked() {
                                self.pending_delete_entry = None;
                            }
                        } else if ui.button("Remove").clicked() {
                            self.pending_delete_entry = Some(entry.id.clone());
                        }
                    });
                    ui.separator();
                }
                if let Some(id) = remove {
                    self.pending_delete_entry = None;
                    match self.source.remove_entry(&id) {
                        Ok(()) => self.notice("Secret removed."),
                        Err(_) => self.error("Could not remove the secret."),
                    }
                }
            }
            Err(_) => {
                ui.label(
                    RichText::new("Unlock your vault to view saved secret names.").color(MUTED),
                );
            }
        }
        ui.add_space(16.0);
        card(ui).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.heading("Add or rotate a secret");
            field(ui, "Secret ID", &mut self.entry_id);
            secret_type_combo(ui, "Secret type", &mut self.entry_kind);
            secret_field(ui, "Secret value", &mut self.secret_text);
            ui.label(RichText::new("Use a file for multiline or binary values. Saved secret values are never displayed.").color(MUTED));
            field(ui, "Secret file path (optional)", &mut self.secret_file);
            if primary_button(ui, "Save secret").clicked() { self.put_entry(); }
        });
        ui.add_space(12.0);
        card(ui).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.heading("Import browser passwords");
            ui.label("One-way import from an Edge or Chrome CSV you explicitly exported. No browser profile is accessed or changed.");
            ui.label("Each row becomes an encrypted JSON record with its URL, username and password. Existing entries are never overwritten.");
            field(ui, "CSV file path", &mut self.import_path);
            field(ui, "Unique import prefix", &mut self.import_prefix);
            ui.checkbox(&mut self.import_consent, "I approve importing this file and understand the source CSV contains plaintext passwords.");
            if ui.add_enabled(self.import_consent && self.source.is_unlocked(), egui::Button::new("Import CSV into vault")).clicked() {
                self.import_browser_csv();
            }
            ui.label(RichText::new("Maximum 8 MiB / 1,000 records. The source file is never deleted automatically. Reimporting with the same prefix is rejected.").color(MUTED));
        });
    }
    fn bindings(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(
                RichText::new("Connect a vault secret to a file, Docker input, or Git credential.")
                    .color(MUTED),
            );
            if primary_button(ui, "+ New binding").clicked() {
                self.form = BindingForm::default();
                self.editing = true;
            }
        });
        ui.add_space(12.0);
        if self.engine.config.bindings.is_empty() && !self.editing {
            card(ui).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.strong("No bindings yet");
                ui.label(
                    RichText::new(
                        "Create a binding to keep a local target in sync with a vault secret.",
                    )
                    .color(MUTED),
                );
            });
        }
        let state = self.engine.status();
        let mut edit = None;
        let mut remove = None;
        let mut sync = None;
        let mut enable = None;
        let mut ack = None;
        for binding in &self.engine.config.bindings {
            card(ui).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.strong(&binding.id);
                    ui.label(
                        RichText::new(format!(
                            "{} / {}",
                            binding.source.entry,
                            target_label(&binding.target)
                        ))
                        .color(MUTED),
                    );
                    if state.disabled.contains(&binding.id) {
                        ui.colored_label(Color32::from_rgb(239, 190, 115), "Disabled");
                    } else if let Some(status) = state.status.get(&binding.id) {
                        ui.label(outcome_label(&status.outcome));
                    }
                });
                ui.horizontal(|ui| {
                    if ui.button("Edit").clicked() {
                        edit = Some(binding.clone());
                    }
                    if ui.button("Sync now").clicked() {
                        sync = Some(binding.id.clone());
                    }
                    if state.disabled.contains(&binding.id) && ui.button("Enable").clicked() {
                        enable = Some(binding.id.clone());
                    }
                    if state
                        .status
                        .get(&binding.id)
                        .is_some_and(|s| s.outcome == SyncOutcome::RestartRequired)
                        && ui.button("Acknowledge restart").clicked()
                    {
                        ack = Some(binding.id.clone());
                    }
                    if self.pending_delete_binding.as_deref() == Some(binding.id.as_str()) {
                        ui.label(RichText::new("Remove this item?").color(DANGER));
                        if ui.button("Confirm removal").clicked() {
                            remove = Some(binding.id.clone());
                        }
                        if ui.button("Cancel").clicked() {
                            self.pending_delete_binding = None;
                        }
                    } else if ui.button("Remove").clicked() {
                        self.pending_delete_binding = Some(binding.id.clone());
                    }
                });
            });
            ui.add_space(7.0);
        }
        if let Some(binding) = edit {
            self.form = BindingForm::from_binding(&binding);
            self.editing = true;
        }
        if let Some(id) = sync {
            self.sync_binding(&id);
        }
        if let Some(id) = enable {
            if self.pending_sync.is_none() {
                let engine = self.engine.clone();
                self.pending_sync = Some(self.runtime.spawn(async move {
                    match engine.enable_binding(&id).await {
                        Ok(()) => SyncOutcome::Unchanged,
                        Err(error) => SyncOutcome::Failed(error),
                    }
                }));
                self.notice("Enabling binding…");
            }
        }
        if let Some(id) = ack {
            if self.pending_sync.is_none() {
                let engine = self.engine.clone();
                self.pending_sync = Some(self.runtime.spawn(async move {
                    match engine.acknowledge_restart(&id).await {
                        Ok(()) => SyncOutcome::Unchanged,
                        Err(error) => SyncOutcome::Failed(error),
                    }
                }));
                self.notice("Acknowledging restart…");
            }
        }
        if let Some(id) = remove {
            self.pending_delete_binding = None;
            self.delete_binding(&id);
        }
        if self.editing {
            ui.add_space(14.0);
            self.binding_editor(ui);
        }
    }
    fn binding_editor(&mut self, ui: &mut egui::Ui) {
        card(ui).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.heading(if self.form.original_id.is_some() { "Edit binding" } else { "New binding" });
            ui.label(RichText::new("Choose a secret, a destination, and a sync schedule.").color(MUTED));
            ui.add_space(12.0);
            ui.columns(2, |columns| {
                let ui = &mut columns[0];
                ui.label(RichText::new("01  SOURCE").size(11.0).strong().color(ACCENT));
                field(ui, "Binding ID", &mut self.form.id);
                egui::ComboBox::from_id_salt("source_kind")
                    .selected_text(if self.form.source_kind == StoreKind::Azure { "Azure Key Vault" } else { "Local vault" })
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.form.source_kind, StoreKind::LocalVault, "Local vault");
                        ui.selectable_value(&mut self.form.source_kind, StoreKind::Azure, "Azure Key Vault");
                    });
                if self.form.source_kind == StoreKind::Azure {
                    field(ui, "Azure vault name", &mut self.form.connection);
                    field(ui, "Azure secret name", &mut self.form.entry);
                    self.form.secret_type = SecretType::Text;
                    ui.label("Text secrets • Azure public cloud");
                    ui.label("Uses your existing Azure CLI sign-in. Requires secrets/list and secrets/get. Values are fetched only when the version changes.");
                } else {
                    field(ui, "Vault secret ID", &mut self.form.entry);
                    secret_type_combo(ui, "Secret type", &mut self.form.secret_type);
                }
                ui.add_space(18.0);
                ui.label(RichText::new("03  SYNC SCHEDULE").size(11.0).strong().color(ACCENT));
                field(ui, "Check interval (seconds)", &mut self.form.interval);
                ui.label(RichText::new("When the target is missing").size(12.0).strong());
                egui::ComboBox::from_id_salt("missing_target_policy")
                    .width(ui.available_width())
                    .selected_text(policy_label(&self.form.policy)).show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.form.policy, MissingTargetPolicy::Alert, "Alert");
                        ui.selectable_value(&mut self.form.policy, MissingTargetPolicy::Recreate, "Recreate");
                        ui.selectable_value(&mut self.form.policy, MissingTargetPolicy::Disable, "Disable binding");
                    });
                let ui = &mut columns[1];
                ui.label(RichText::new("02  DESTINATION").size(11.0).strong().color(ACCENT));
                ui.label(RichText::new("Target type").size(12.0).strong());
                egui::ComboBox::from_id_salt("target_type")
                    .width(ui.available_width())
                    .selected_text(self.form.target_kind.label()).show_ui(ui, |ui| {
                        for choice in TargetChoice::ALL {
                            ui.selectable_value(&mut self.form.target_kind, choice, choice.label());
                        }
                    });
                if self.form.target_kind == TargetChoice::GitCredential {
                    field(ui, "Git host", &mut self.form.host);
                    field(ui, "Repository path (optional)", &mut self.form.git_path);
                    field(ui, "Git username", &mut self.form.username);
                } else {
                    field(ui, "Absolute target file path", &mut self.form.path);
                    if self.form.target_kind != TargetChoice::WholeFile {
                        field(ui, "Field key (use /path for JSON or YAML)", &mut self.form.key);
                    }
                    if self.form.target_kind == TargetChoice::DockerEnvFile {
                        field(ui, "Absolute Compose file path", &mut self.form.compose_path);
                        field(ui, "Compose service", &mut self.form.service);
                    }
                }
                ui.add_space(8.0);
                ui.label(RichText::new("File targets must be inside your workspace. Repository-specific Git credentials require credential.useHttpPath.").small().color(MUTED));
            });
            ui.add_space(18.0);
            ui.separator();
            ui.horizontal(|ui| {
                if primary_button(ui, "Save binding").clicked() { self.save_binding(); }
                if ui.button("Cancel").clicked() { self.editing = false; }
            });
        });
    }
    fn events(&mut self, ui: &mut egui::Ui) {
        ui.label(
            RichText::new("Recent sync events. Secret values are never included.").color(MUTED),
        );
        ui.add_space(10.0);
        let data = match fs::read_to_string(&self.engine.events_path) {
            Ok(data) => data,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(_) => {
                ui.colored_label(DANGER, "Could not read activity.");
                return;
            }
        };
        let events: Result<Vec<core::Event>, _> = data
            .lines()
            .rev()
            .take(100)
            .map(serde_json::from_str)
            .collect();
        match events {
            Ok(events) if events.is_empty() => {
                card(ui).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.strong("Nothing to report yet");
                    ui.label(
                        RichText::new("Your sync history will appear here after the first check.")
                            .color(MUTED),
                    );
                });
            }
            Ok(events) => {
                for event in events {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(event.timestamp.to_string()).color(MUTED));
                        ui.strong(event.binding_id);
                        ui.label(outcome_label(&event.outcome));
                    });
                    ui.separator();
                }
            }
            Err(_) => {
                ui.colored_label(DANGER, "An activity record is invalid.");
            }
        }
    }
    fn settings(&mut self, ui: &mut egui::Ui) {
        ui.heading("Workspace");
        ui.label(
            RichText::new("Choose the workspace that contains your target files.").color(MUTED),
        );
        field(ui, "Workspace folder", &mut self.root_input);
        if primary_button(ui, "Switch workspace").clicked() {
            let requested = PathBuf::from(&self.root_input);
            match requested.canonicalize() {
                Ok(path) if path == self.root => self.notice("This workspace is already open."),
                Ok(path) if path.is_dir() => {
                    let lock_path = path.join("local/agent.lock");
                    if fs::create_dir_all(path.join("local")).is_err()
                        || core::acquire_agent_lock(&lock_path).is_err()
                    {
                        self.error(
                            "The workspace is in use by another agent or cannot be written.",
                        );
                        return;
                    }
                    let started = std::env::current_exe().ok().and_then(|exe| {
                        std::process::Command::new(exe)
                            .arg("desktop")
                            .env("TAR_VAULT_SYNC_DIR", &path)
                            .current_dir(&path)
                            .spawn()
                            .ok()
                    });
                    if started.is_some() {
                        ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                    } else {
                        self.error("Could not open the workspace.");
                    }
                }
                _ => self.error("Workspace folder not found."),
            }
        }
        ui.add_space(18.0);
        ui.heading("Desktop agent");
        ui.label("Scheduled sync runs locally while this window is open.");
        ui.label("For background sync after closing the window, run the separate agent.");
        ui.label("Azure bindings currently require the desktop window to stay open. Sign in with Azure CLI before syncing; no Azure credentials are saved in workspace settings.");
        ui.add_space(18.0);
        card(ui).show(ui, |ui| {
            ui.set_width(ui.available_width()); ui.strong("Development build");
            ui.label("Native desktop management is available. Release packaging and platform validation are in progress."); });
    }
}

impl eframe::App for DesktopApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self
            .pending_sync
            .as_ref()
            .is_some_and(JoinHandle::is_finished)
        {
            let result = self.runtime.block_on(self.pending_sync.take().unwrap());
            match result {
                Ok(SyncOutcome::Failed(_)) | Err(_) => {
                    self.error("Sync failed. Check the binding status and activity log.")
                }
                Ok(_) => self.notice("Sync check complete."),
            }
        }
        if self.pending_sync.is_some() {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
        egui::SidePanel::left("nav")
            .resizable(false)
            .exact_width(218.0)
            .frame(egui::Frame::NONE.fill(NAV).inner_margin(20))
            .show(ctx, |ui| {
                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    egui::Frame::NONE
                        .fill(CANVAS)
                        .corner_radius(10)
                        .inner_margin(4)
                        .show(ui, |ui| {
                            if let Some(texture) = &self.brand_texture {
                                ui.add(
                                    egui::Image::new((texture.id(), egui::vec2(48.0, 48.0)))
                                        .alt_text("TAR Vault Sync logo"),
                                );
                            }
                        });
                    ui.vertical(|ui| {
                        ui.label(
                            RichText::new("TAR")
                                .size(20.0)
                                .strong()
                                .color(Color32::WHITE),
                        );
                        ui.label(
                            RichText::new("VAULT SYNC")
                                .size(10.0)
                                .color(Color32::from_rgb(149, 172, 191)),
                        );
                    });
                });
                ui.add_space(38.0);
                ui.label(
                    RichText::new("WORKSPACE")
                        .size(10.0)
                        .strong()
                        .color(Color32::from_rgb(121, 144, 165)),
                );
                ui.add_space(8.0);
                for (page, name) in [
                    (Page::Overview, "Overview"),
                    (Page::Vault, "Vault"),
                    (Page::Bindings, "Bindings"),
                    (Page::Events, "Activity"),
                    (Page::Settings, "Settings"),
                ] {
                    let selected = self.page == page;
                    let button =
                        egui::Button::new(RichText::new(name).size(14.0).color(if selected {
                            Color32::WHITE
                        } else {
                            Color32::from_rgb(168, 186, 202)
                        }))
                        .fill(if selected {
                            Color32::from_rgb(36, 64, 76)
                        } else {
                            NAV
                        })
                        .stroke(egui::Stroke::NONE)
                        .corner_radius(8);
                    if ui.add_sized([ui.available_width(), 42.0], button).clicked() {
                        self.page = page;
                        self.message.clear();
                    }
                }
                ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                    ui.label(
                        RichText::new("Desktop  /  v0.1.0")
                            .size(10.0)
                            .color(Color32::from_rgb(121, 144, 165)),
                    );
                    ui.label(
                        RichText::new("Local agent running")
                            .size(12.0)
                            .color(Color32::from_rgb(109, 213, 178)),
                    );
                    ui.add_space(6.0);
                    ui.separator();
                });
            });
        egui::CentralPanel::default()
            .frame(
                egui::Frame::NONE
                    .fill(CANVAS)
                    .inner_margin(egui::Margin::symmetric(30, 26)),
            )
            .show(ctx, |ui| {
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        self.header(ui);
                        match self.page {
                            Page::Overview => self.overview(ui),
                            Page::Vault => self.vault(ui),
                            Page::Bindings => self.bindings(ui),
                            Page::Events => self.events(ui),
                            Page::Settings => self.settings(ui),
                        }
                        ui.add_space(20.0);
                    });
            });
        ctx.request_repaint_after(std::time::Duration::from_secs(3));
    }
}

fn card(ui: &egui::Ui) -> egui::Frame {
    egui::Frame::group(ui.style())
        .fill(Color32::WHITE)
        .stroke(egui::Stroke::new(1.0, BORDER))
        .corner_radius(12)
        .inner_margin(20)
}
fn primary_button(ui: &mut egui::Ui, label: &str) -> egui::Response {
    ui.add(
        egui::Button::new(RichText::new(label).strong().color(Color32::WHITE))
            .fill(ACCENT)
            .stroke(egui::Stroke::NONE),
    )
}
fn metric(ui: &mut egui::Ui, title: &str, value: &str, detail: &str, color: Color32) {
    card(ui).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.label(RichText::new(title).size(10.0).strong().color(MUTED));
        ui.label(RichText::new(value).size(27.0).strong().color(color));
        ui.label(RichText::new(detail).size(11.0).color(MUTED));
    });
}
fn field(ui: &mut egui::Ui, label: &str, value: &mut String) {
    ui.push_id(label, |ui| {
        ui.label(RichText::new(label).size(12.0).strong());
        ui.add(
            egui::TextEdit::singleline(value)
                .desired_width(ui.available_width().min(580.0))
                .margin(egui::vec2(10.0, 9.0)),
        );
    });
}
fn secret_field(ui: &mut egui::Ui, label: &str, value: &mut String) {
    ui.push_id(label, |ui| {
        ui.label(RichText::new(label).size(12.0).strong());
        ui.add(
            egui::TextEdit::singleline(value)
                .password(true)
                .desired_width(ui.available_width().min(580.0))
                .margin(egui::vec2(10.0, 9.0)),
        );
    });
}
fn secret_type_combo(ui: &mut egui::Ui, label: &str, kind: &mut SecretType) {
    ui.label(RichText::new(label).size(12.0).strong());
    egui::ComboBox::from_id_salt(label)
        .width(240.0)
        .selected_text(secret_type_label(kind))
        .show_ui(ui, |ui| {
            for choice in [
                SecretType::Text,
                SecretType::Json,
                SecretType::Binary,
                SecretType::Certificate,
                SecretType::PrivateKey,
            ] {
                let text = secret_type_label(&choice);
                ui.selectable_value(kind, choice, text);
            }
        });
}
fn secret_type_label(kind: &SecretType) -> &'static str {
    match kind {
        SecretType::Text => "Text",
        SecretType::Json => "JSON",
        SecretType::Binary => "Binary",
        SecretType::Certificate => "Certificate",
        SecretType::PrivateKey => "Private key",
    }
}
fn configure_theme(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    style.visuals = egui::Visuals::light();
    style.visuals.override_text_color = Some(INK);
    style.visuals.panel_fill = CANVAS;
    style.visuals.window_fill = Color32::WHITE;
    style.visuals.extreme_bg_color = Color32::from_rgb(248, 250, 252);
    style.visuals.faint_bg_color = CANVAS;
    style.visuals.hyperlink_color = ACCENT;
    style.visuals.selection.bg_fill = Color32::from_rgb(200, 231, 221);
    style.visuals.selection.stroke = egui::Stroke::new(1.0, INK);
    style.visuals.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, BORDER);
    style.visuals.widgets.inactive.bg_fill = Color32::WHITE;
    style.visuals.widgets.inactive.weak_bg_fill = Color32::WHITE;
    style.visuals.widgets.inactive.bg_stroke = egui::Stroke::new(1.0, BORDER);
    style.visuals.widgets.inactive.corner_radius = egui::CornerRadius::same(7);
    style.visuals.widgets.hovered.bg_fill = Color32::from_rgb(235, 245, 241);
    style.visuals.widgets.hovered.weak_bg_fill = Color32::from_rgb(235, 245, 241);
    style.visuals.widgets.hovered.bg_stroke = egui::Stroke::new(1.0, ACCENT);
    style.visuals.widgets.active.bg_fill = Color32::from_rgb(215, 237, 228);
    style.visuals.widgets.active.bg_stroke = egui::Stroke::new(1.0, ACCENT);
    style.spacing.item_spacing = egui::vec2(12.0, 10.0);
    style.spacing.button_padding = egui::vec2(14.0, 9.0);
    style.spacing.interact_size.y = 34.0;
    for (kind, size) in [
        (egui::TextStyle::Heading, 19.0),
        (egui::TextStyle::Body, 14.0),
        (egui::TextStyle::Button, 13.0),
        (egui::TextStyle::Small, 11.0),
        (egui::TextStyle::Monospace, 13.0),
    ] {
        let family = if kind == egui::TextStyle::Monospace {
            egui::FontFamily::Monospace
        } else {
            egui::FontFamily::Proportional
        };
        style
            .text_styles
            .insert(kind, egui::FontId::new(size, family));
    }
    ctx.set_style(style);
}
fn outcome_label(outcome: &SyncOutcome) -> &'static str {
    match outcome {
        SyncOutcome::Unchanged => "Up to date",
        SyncOutcome::Applied => "Synced",
        SyncOutcome::RestartRequired => "Restart required",
        SyncOutcome::Disabled => "Disabled",
        SyncOutcome::Failed(category) => match category {
            core::ErrorCategory::InvalidConfig => "Invalid configuration",
            core::ErrorCategory::Source => "Source unavailable",
            core::ErrorCategory::VersionConflict => "Version conflict",
            core::ErrorCategory::Target => "Target error",
            core::ErrorCategory::State => "State error",
            core::ErrorCategory::Unauthorized => "Access denied",
        },
    }
}
fn policy_label(policy: &MissingTargetPolicy) -> &'static str {
    match policy {
        MissingTargetPolicy::Alert => "Alert",
        MissingTargetPolicy::Recreate => "Recreate",
        MissingTargetPolicy::Disable => "Disable binding",
    }
}
fn target_label(target: &TargetSpec) -> &'static str {
    match target {
        TargetSpec::WholeFile { .. } => "File",
        TargetSpec::StructuredField { .. } => "Field",
        TargetSpec::DockerInput { .. } => "Docker",
        TargetSpec::GitCredential { .. } => "Git",
        TargetSpec::Fake { .. } => "Fake",
    }
}
fn spawn_schedules(runtime: &tokio::runtime::Runtime, engine: &Arc<Engine>) -> Vec<JoinHandle<()>> {
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    engine
        .config
        .bindings
        .iter()
        .map(|binding| {
            runtime.spawn(scheduler::run_binding(
                engine.clone(),
                binding.id.clone(),
                binding.schedule.interval_seconds,
                seed,
            ))
        })
        .collect()
}
fn write_config(path: &PathBuf, bytes: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().ok_or(std::io::Error::other("config path"))?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    temp.write_all(bytes)?;
    temp.as_file().sync_all()?;
    temp.persist(path).map_err(|e| e.error)?;
    Ok(())
}

pub fn run(root: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(root.join("local"))?;
    let _agent_lock = core::acquire_agent_lock(&root.join("local/agent.lock"))?;
    let mut app = DesktopApp::new(root)?;
    let icon = eframe::icon_data::from_png_bytes(BRAND_MARK)?;
    let brand_image = egui::ColorImage::from_rgba_unmultiplied(
        [icon.width as usize, icon.height as usize],
        &icon.rgba,
    );
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_icon(icon)
            .with_inner_size([1240.0, 840.0])
            .with_min_inner_size([900.0, 600.0]),
        ..Default::default()
    };
    eframe::run_native(
        "TAR Vault Sync",
        options,
        Box::new(move |cc| {
            configure_theme(&cc.egui_ctx);
            app.brand_texture = Some(cc.egui_ctx.load_texture(
                "tar-vault-sync-brand",
                brand_image,
                egui::TextureOptions::LINEAR,
            ));
            Ok(Box::new(app))
        }),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn azure_binding_can_be_saved_and_edited_without_a_local_vault() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = DesktopApp::new(dir.path().to_path_buf()).unwrap();
        app.form = BindingForm {
            id: "azure-binding".into(),
            source_kind: StoreKind::Azure,
            connection: "test-vault".into(),
            entry: "test-secret".into(),
            path: dir.path().join("authorized.txt").display().to_string(),
            interval: "86400".into(),
            ..BindingForm::default()
        };
        app.save_binding();
        assert!(!app.is_error);
        assert!(!app.source.exists());
        let binding = &app.engine.config.bindings[0];
        assert_eq!(binding.source.store, StoreKind::Azure);
        assert_eq!(binding.source.connection, "test-vault");
        let edited = BindingForm::from_binding(binding).binding().unwrap();
        assert_eq!(&edited, binding);
        let mut invalid = app.engine.config.clone();
        invalid.bindings[0].secret_type = SecretType::Binary;
        assert!(app.save_config(invalid).is_err());
        let mut invalid = app.engine.config.clone();
        invalid.bindings[0].source.connection = "test.vault".into();
        assert!(app.save_config(invalid).is_err());
        drop(app);
        let reopened = DesktopApp::new(dir.path().to_path_buf()).unwrap();
        assert_eq!(reopened.engine.config.bindings.len(), 1);
        assert_eq!(
            reopened.engine.config.bindings[0].source.store,
            StoreKind::Azure
        );
    }

    #[test]
    fn embedded_brand_mark_is_valid_square_rgba_with_transparency() {
        let icon = eframe::icon_data::from_png_bytes(BRAND_MARK).unwrap();
        assert_eq!(icon.width, icon.height);
        assert!(icon.width >= 256);
        assert_eq!(icon.rgba.len(), (icon.width * icon.height * 4) as usize);
        assert!(icon.rgba.chunks_exact(4).any(|pixel| pixel[3] == 0));
        assert!(icon.rgba.chunks_exact(4).any(|pixel| pixel[3] == 255));
        let image = egui::ColorImage::from_rgba_unmultiplied(
            [icon.width as usize, icon.height as usize],
            &icon.rgba,
        );
        let ctx = egui::Context::default();
        let texture = ctx.load_texture("brand-test", image, egui::TextureOptions::LINEAR);
        assert_eq!(texture.size(), [icon.width as usize, icon.height as usize]);
    }

    #[test]
    fn browser_import_action_requires_fresh_consent_and_redacts_status() {
        let dir = tempfile::tempdir().unwrap();
        let csv = dir.path().join("synthetic.csv");
        fs::write(
            &csv,
            b"url,username,password\nhttps://example.invalid,user,synthetic-probe",
        )
        .unwrap();
        let mut app = DesktopApp::new(dir.path().to_path_buf()).unwrap();
        app.source.create("test-only-passphrase").unwrap();
        app.import_path = csv.display().to_string();
        app.import_prefix = "browser".into();
        app.import_browser_csv();
        assert!(app.is_error);
        assert!(app.source.entries().unwrap().is_empty());
        app.import_consent = true;
        app.import_browser_csv();
        assert!(!app.is_error);
        assert!(!app.import_consent);
        assert!(app.import_path.is_empty());
        assert_eq!(app.source.entries().unwrap().len(), 1);
        assert!(!app.message.contains("synthetic-probe"));
        assert!(!app.message.contains("example.invalid"));
        app.import_path = csv.display().to_string();
        app.import_prefix = "browser".into();
        app.import_consent = true;
        app.import_browser_csv();
        assert!(app.is_error);
        assert!(!app.import_consent);
        assert_eq!(app.source.entries().unwrap().len(), 1);
    }

    #[test]
    fn binding_form_emits_typed_targets_without_secret_values() {
        let mut form = BindingForm {
            id: "binding".into(),
            entry: "entry".into(),
            target_kind: TargetChoice::GitCredential,
            host: "example.invalid".into(),
            username: "user".into(),
            ..BindingForm::default()
        };
        let binding = form.binding().unwrap();
        assert!(matches!(binding.target, TargetSpec::GitCredential { .. }));
        let data = serde_json::to_string(&binding).unwrap();
        assert!(!data.contains("password"));
        form.target_kind = TargetChoice::DockerEnvFile;
        form.path = "/tmp/work/web.env".into();
        form.compose_path = "/tmp/work/compose.yaml".into();
        form.service = "web".into();
        form.key = "TOKEN".into();
        assert!(matches!(
            form.binding().unwrap().target,
            TargetSpec::DockerInput {
                input: DockerInputKind::EnvFile { .. },
                ..
            }
        ));
    }

    #[test]
    fn desktop_saves_validated_binding_and_detects_external_change() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.env");
        fs::write(&target, "TOKEN=old\n").unwrap();
        let mut app = DesktopApp::new(dir.path().to_path_buf()).unwrap();
        app.form = BindingForm {
            id: "binding".into(),
            entry: "entry".into(),
            target_kind: TargetChoice::DotEnv,
            path: target.display().to_string(),
            key: "TOKEN".into(),
            ..BindingForm::default()
        };
        app.save_binding();
        assert_eq!(app.engine.config.bindings.len(), 1);
        let persisted = fs::read(dir.path().join("shared/config.json")).unwrap();
        assert!(core::validate_config(&persisted, dir.path()).is_ok());
        app.engine
            .state
            .lock()
            .unwrap()
            .applied
            .insert("binding".into(), core::SourceVersion("v1".into()));
        let next_target = dir.path().join("next.env");
        fs::write(&next_target, "TOKEN=old\n").unwrap();
        app.form = BindingForm::from_binding(&app.engine.config.bindings[0]);
        app.form.path = next_target.display().to_string();
        app.save_binding();
        assert!(app.engine.status().applied.is_empty());
        fs::write(dir.path().join("shared/config.json"), b"external change").unwrap();
        assert!(app.save_config(app.engine.config.clone()).is_err());
    }
}
