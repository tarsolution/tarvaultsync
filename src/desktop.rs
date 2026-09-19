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

const ACCENT: Color32 = Color32::from_rgb(204, 239, 123);
const MUTED: Color32 = Color32::from_rgb(145, 166, 180);

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
            Self::WholeFile => "Tüm dosya",
            Self::DotEnv => ".env alanı",
            Self::Json => "JSON alanı",
            Self::Yaml => "YAML alanı",
            Self::Properties => "Properties alanı",
            Self::DockerCompose => "Docker Compose environment",
            Self::DockerEnvFile => "Docker env_file",
            Self::GitCredential => "Git Credential Manager",
        }
    }
}

struct BindingForm {
    original_id: Option<String>,
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
            .map_err(|_| "Kontrol aralığı geçersiz")?;
        Ok(Binding {
            id: self.id.clone(),
            source: SourceRef {
                store: StoreKind::LocalVault,
                connection: "local".into(),
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
        if config
            .bindings
            .iter()
            .any(|b| b.source.store != StoreKind::LocalVault || b.source.connection != "local")
        {
            return Err("Masaüstü arayüzü yalnızca yerel kasa eşlemelerini yönetir".into());
        }
        let source = Arc::new(VaultSource::new(
            root.join("local/vault.bin"),
            "local".into(),
        )?);
        let target = Arc::new(ProductionTarget::new(root.clone())?);
        let engine = Arc::new(Engine::new(
            config,
            root.join("local/state.json"),
            root.join("local/events.ndjson"),
            source.clone(),
            target.clone(),
        )?);
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        let schedules = spawn_schedules(&runtime, &engine);
        Ok(Self {
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
        let bytes = serde_json::to_vec_pretty(&config).map_err(|_| "Yapılandırma kodlanamadı")?;
        core::validate_config(&bytes, &self.root).map_err(|_| "Yapılandırma geçersiz")?;
        for binding in &config.bindings {
            if binding.source.store != StoreKind::LocalVault
                || binding.source.connection != "local"
                || self
                    .target
                    .validate(&binding.target, &binding.secret_type)
                    .is_err()
            {
                return Err("Hedef veya sır türü geçersiz");
            }
        }
        let path = self.root.join("shared/config.json");
        let on_disk = match fs::read(&path) {
            Ok(bytes) => Some(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => return Err("Yapılandırma okunamadı"),
        };
        if on_disk != self.config_bytes {
            return Err("Yapılandırma başka bir süreçte değişti; pencereyi yeniden açın");
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
            return Err("Eşleme durumu güncellenemedi");
        }
        let next = match Engine::new(
            config,
            self.root.join("local/state.json"),
            self.root.join("local/events.ndjson"),
            self.source.clone(),
            self.target.clone(),
        ) {
            Ok(engine) => Arc::new(engine),
            Err(_) => {
                self.schedules = spawn_schedules(&self.runtime, &self.engine);
                return Err("Durum dosyası okunamadı");
            }
        };
        if write_config(&path, &bytes).is_err() {
            self.schedules = spawn_schedules(&self.runtime, &self.engine);
            return Err("Yapılandırma yazılamadı");
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
                self.error("Eşleme bulunamadı");
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
                self.notice("Eşleme kaydedildi ve zamanlayıcı güncellendi");
            }
            Err(e) => self.error(e),
        }
    }
    fn delete_binding(&mut self, id: &str) {
        let mut config = self.engine.config.clone();
        config.bindings.retain(|b| b.id != id);
        match self.save_config(config) {
            Ok(()) => self.notice("Eşleme kaldırıldı"),
            Err(e) => self.error(e),
        }
    }
    fn sync_binding(&mut self, id: &str) {
        let outcome = self.runtime.block_on(self.engine.sync(id));
        match outcome {
            SyncOutcome::Failed(_) => {
                self.error("Senkronizasyon başarısız; durum ve olayları kontrol edin")
            }
            _ => self.notice("Senkronizasyon kontrolü tamamlandı"),
        }
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
            Ok(()) => self.notice("Kasa işlemi tamamlandı"),
            Err(_) => {
                self.error("Kasa işlemi başarısız; parola, yol ve kasa durumunu kontrol edin")
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
                    self.error("Sır dosyası okunamadı");
                    return;
                }
            }
        };
        let payload = SecretPayload::new(bytes, self.entry_kind.clone());
        let result = self.source.put_entry(&self.entry_id, &payload);
        self.secret_text.zeroize();
        self.secret_file.clear();
        match result {
            Ok(()) => self.notice("Kasa kaydı yeni sürümle kaydedildi"),
            Err(_) => self.error("Kasa kaydı kaydedilemedi"),
        }
    }
    fn header(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading(match self.page {
                Page::Overview => "Genel Bakış",
                Page::Vault => "Şifreli Kasa",
                Page::Bindings => "Eşlemeler",
                Page::Events => "Olaylar",
                Page::Settings => "Yönetim",
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let label = if self.source.is_unlocked() {
                    "● Kasa açık"
                } else {
                    "○ Kasa kilitli"
                };
                ui.label(RichText::new(label).color(if self.source.is_unlocked() {
                    ACCENT
                } else {
                    MUTED
                }));
            });
        });
        ui.add_space(15.0);
        if !self.message.is_empty() {
            let color = if self.is_error {
                Color32::from_rgb(255, 166, 166)
            } else {
                ACCENT
            };
            ui.group(|ui| {
                ui.label(RichText::new(&self.message).color(color));
            });
            ui.add_space(14.0);
        }
    }
    fn overview(&mut self, ui: &mut egui::Ui) {
        egui::Frame::group(ui.style())
            .fill(Color32::from_rgb(29, 53, 43))
            .show(ui, |ui| {
            ui.set_min_width(690.0);
            ui.set_min_height(135.0);
            ui.heading(RichText::new("Sırlarınız kontrolünüzde.").size(29.0).color(ACCENT));
            ui.label("Kasadaki değerleri yerel hedeflere güvenli biçimde eşleyin. Sır içerikleri arayüzde geri gösterilmez.");
            ui.add_space(9.0);
            if ui.button("Yeni eşleme oluştur").clicked() { self.page = Page::Bindings; self.editing = true; self.form = BindingForm::default(); }
        });
        ui.add_space(16.0);
        let state = self.engine.status();
        ui.horizontal(|ui| {
            ui.group(|ui| {
                ui.set_min_width(150.0);
                ui.set_min_height(76.0);
                ui.label("EŞLEME");
                ui.heading(self.engine.config.bindings.len().to_string());
            });
            ui.group(|ui| {
                ui.set_min_width(150.0);
                ui.set_min_height(76.0);
                ui.label("KASA");
                ui.heading(if self.source.is_unlocked() {
                    "Açık"
                } else {
                    "Kilitli"
                });
            });
            ui.group(|ui| {
                ui.set_min_width(185.0);
                ui.set_min_height(76.0);
                ui.label("DİKKAT GEREKTİREN");
                let count = self
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
                ui.heading(count.to_string());
            });
        });
        ui.add_space(22.0);
        ui.heading("Eşleme durumu");
        ui.separator();
        if self.engine.config.bindings.is_empty() {
            ui.label(
                RichText::new("Henüz eşleme yok. Önce bir kasa kaydı, ardından eşleme oluşturun.")
                    .color(MUTED),
            );
        }
        for binding in &self.engine.config.bindings {
            let outcome = state
                .status
                .get(&binding.id)
                .map(|s| format!("{:?}", s.outcome))
                .unwrap_or_else(|| "Bekliyor".into());
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
                ui.label(outcome);
            });
            ui.separator();
        }
    }
    fn vault(&mut self, ui: &mut egui::Ui) {
        ui.label(RichText::new("Parola ve sır değerleri yalnızca geçici bellekte işlenir. 15 dakika kullanılmayan kasa kilitlenir.").color(MUTED));
        ui.add_space(14.0);
        ui.group(|ui| {
            ui.heading("Kasa erişimi");
            ui.horizontal(|ui| {
                ui.label("Kasa parolası");
                ui.add(
                    egui::TextEdit::singleline(&mut *self.passphrase)
                        .password(true)
                        .desired_width(300.0),
                );
            });
            ui.horizontal(|ui| {
                if !self.source.exists() && ui.button("Kasa oluştur").clicked() {
                    self.vault_action("create");
                }
                if self.source.exists() && ui.button("Kilidi aç").clicked() {
                    self.vault_action("unlock");
                }
                if ui.button("Kilitle").clicked() {
                    self.source.lock();
                    self.passphrase.zeroize();
                    self.notice("Kasa kilitlendi");
                }
            });
        });
        ui.add_space(12.0);
        ui.group(|ui| {
            ui.heading("Şifreli yedek");
            ui.horizontal(|ui| {
                ui.label("Yedek dosyası yolu");
                ui.add(egui::TextEdit::singleline(&mut self.backup_path).desired_width(420.0));
            });
            ui.horizontal(|ui| {
                if ui.button("Yedek oluştur").clicked() {
                    match self.source.backup(&PathBuf::from(&self.backup_path)) {
                        Ok(()) => self.notice("Şifreli yedek oluşturuldu"),
                        Err(_) => self.error("Yedek oluşturulamadı"),
                    }
                }
                if ui.button("Yedekten kurtar").clicked() {
                    self.vault_action("recover");
                }
            });
            ui.label(RichText::new("Kurtarma mevcut kasanın üzerine yazmaz.").color(MUTED));
        });
        ui.add_space(17.0);
        ui.heading("Kasa kayıtları");
        ui.separator();
        match self.source.entries() {
            Ok(entries) if entries.is_empty() => {
                ui.label(RichText::new("Kasa boş.").color(MUTED));
            }
            Ok(entries) => {
                let mut remove = None;
                for entry in entries {
                    ui.horizontal(|ui| {
                        ui.strong(&entry.id);
                        ui.label(format!("{:?}", entry.kind));
                        ui.label(
                            RichText::new(format!(
                                "sürüm {}",
                                &entry.version[..8.min(entry.version.len())]
                            ))
                            .color(MUTED),
                        );
                        if self.pending_delete_entry.as_deref() == Some(entry.id.as_str()) {
                            ui.label(RichText::new("Silinsin mi?").color(Color32::LIGHT_RED));
                            if ui.button("Evet, sil").clicked() {
                                remove = Some(entry.id.clone());
                            }
                            if ui.button("Vazgeç").clicked() {
                                self.pending_delete_entry = None;
                            }
                        } else if ui.button("Kaldır").clicked() {
                            self.pending_delete_entry = Some(entry.id.clone());
                        }
                    });
                    ui.separator();
                }
                if let Some(id) = remove {
                    self.pending_delete_entry = None;
                    match self.source.remove_entry(&id) {
                        Ok(()) => self.notice("Kasa kaydı kaldırıldı"),
                        Err(_) => self.error("Kasa kaydı kaldırılamadı"),
                    }
                }
            }
            Err(_) => {
                ui.label(RichText::new("Kayıtları görmek için kasayı açın.").color(MUTED));
            }
        }
        ui.add_space(16.0);
        ui.group(|ui| {
            ui.heading("Sır ekle veya döndür");
            field(ui, "Kayıt kimliği", &mut self.entry_id);
            secret_type_combo(ui, "Sır türü", &mut self.entry_kind);
            ui.horizontal(|ui| { ui.label("Sır değeri"); ui.add(egui::TextEdit::singleline(&mut *self.secret_text).password(true).desired_width(390.0)); });
            ui.label(RichText::new("Çok satırlı veya ikili değer için dosya yolu kullanın; mevcut sır geri gösterilmez.").color(MUTED));
            field(ui, "Sır dosyası (isteğe bağlı)", &mut self.secret_file);
            if ui.button("Kasaya kaydet").clicked() { self.put_entry(); }
        });
    }
    fn bindings(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(
                    "Kasa kaydını dosya, Docker girdisi veya Git kimlik bilgisine bağlayın.",
                )
                .color(MUTED),
            );
            if ui.button("+ Yeni eşleme").clicked() {
                self.form = BindingForm::default();
                self.editing = true;
            }
        });
        ui.add_space(12.0);
        let state = self.engine.status();
        let mut edit = None;
        let mut remove = None;
        let mut sync = None;
        let mut enable = None;
        let mut ack = None;
        for binding in &self.engine.config.bindings {
            ui.group(|ui| {
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
                        ui.colored_label(Color32::from_rgb(239, 190, 115), "Devre dışı");
                    } else if let Some(status) = state.status.get(&binding.id) {
                        ui.label(format!("{:?}", status.outcome));
                    }
                });
                ui.horizontal(|ui| {
                    if ui.button("Düzenle").clicked() {
                        edit = Some(binding.clone());
                    }
                    if ui.button("Şimdi kontrol et").clicked() {
                        sync = Some(binding.id.clone());
                    }
                    if state.disabled.contains(&binding.id) && ui.button("Etkinleştir").clicked() {
                        enable = Some(binding.id.clone());
                    }
                    if state
                        .status
                        .get(&binding.id)
                        .is_some_and(|s| s.outcome == SyncOutcome::RestartRequired)
                        && ui.button("Yeniden başlatmayı onayla").clicked()
                    {
                        ack = Some(binding.id.clone());
                    }
                    if self.pending_delete_binding.as_deref() == Some(binding.id.as_str()) {
                        ui.label(RichText::new("Silinsin mi?").color(Color32::LIGHT_RED));
                        if ui.button("Evet, sil").clicked() {
                            remove = Some(binding.id.clone());
                        }
                        if ui.button("Vazgeç").clicked() {
                            self.pending_delete_binding = None;
                        }
                    } else if ui.button("Kaldır").clicked() {
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
            match self.runtime.block_on(self.engine.enable_binding(&id)) {
                Ok(()) => self.notice("Eşleme etkinleştirildi"),
                Err(_) => self.error("Eşleme etkinleştirilemedi"),
            }
        }
        if let Some(id) = ack {
            match self.runtime.block_on(self.engine.acknowledge_restart(&id)) {
                Ok(()) => self.notice("Yeniden başlatma onaylandı"),
                Err(_) => self.error("Onay başarısız"),
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
        ui.group(|ui| {
            ui.heading(if self.form.original_id.is_some() { "Eşlemeyi düzenle" } else { "Yeni eşleme" });
            field(ui, "Eşleme kimliği", &mut self.form.id);
            field(ui, "Kasa kayıt kimliği", &mut self.form.entry);
            secret_type_combo(ui, "Sır türü", &mut self.form.secret_type);
            egui::ComboBox::from_label("Hedef türü").selected_text(self.form.target_kind.label()).show_ui(ui, |ui| {
                for choice in TargetChoice::ALL { ui.selectable_value(&mut self.form.target_kind, choice, choice.label()); }
            });
            if self.form.target_kind == TargetChoice::GitCredential {
                field(ui, "Git host", &mut self.form.host);
                field(ui, "Depo yolu (isteğe bağlı)", &mut self.form.git_path);
                field(ui, "Git kullanıcı adı", &mut self.form.username);
            } else {
                field(ui, "Hedef dosyanın mutlak yolu", &mut self.form.path);
                if self.form.target_kind != TargetChoice::WholeFile { field(ui, "Alan anahtarı (JSON/YAML için /path)", &mut self.form.key); }
                if self.form.target_kind == TargetChoice::DockerEnvFile {
                    field(ui, "Compose dosyasının mutlak yolu", &mut self.form.compose_path);
                    field(ui, "Compose servisi", &mut self.form.service);
                }
            }
            egui::ComboBox::from_label("Eksik hedef politikası")
                .selected_text(policy_label(&self.form.policy)).show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.form.policy, MissingTargetPolicy::Alert, "Uyar");
                    ui.selectable_value(&mut self.form.policy, MissingTargetPolicy::Recreate, "Yeniden oluştur");
                    ui.selectable_value(&mut self.form.policy, MissingTargetPolicy::Disable, "Devre dışı bırak");
                });
            field(ui, "Kontrol aralığı (saniye)", &mut self.form.interval);
            ui.label(RichText::new("Dosya yolları çalışma alanı kökü içinde olmalıdır. Git depo yolu için credential.useHttpPath etkin olmalıdır.").color(MUTED));
            ui.horizontal(|ui| { if ui.button("Eşlemeyi kaydet").clicked() { self.save_binding(); }
                if ui.button("Vazgeç").clicked() { self.editing = false; } });
        });
    }
    fn events(&mut self, ui: &mut egui::Ui) {
        ui.label(
            RichText::new("Olaylar yalnızca kimlik, zaman ve güvenli sonuç kategorilerini içerir.")
                .color(MUTED),
        );
        ui.add_space(10.0);
        let data = match fs::read_to_string(&self.engine.events_path) {
            Ok(data) => data,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(_) => {
                ui.colored_label(Color32::LIGHT_RED, "Olaylar okunamadı");
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
                ui.label("Henüz olay yok.");
            }
            Ok(events) => {
                for event in events {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(event.timestamp.to_string()).color(MUTED));
                        ui.strong(event.binding_id);
                        ui.label(format!("{:?}", event.outcome));
                    });
                    ui.separator();
                }
            }
            Err(_) => {
                ui.colored_label(Color32::LIGHT_RED, "Olay kaydı geçersiz");
            }
        }
    }
    fn settings(&mut self, ui: &mut egui::Ui) {
        ui.heading("Çalışma alanı");
        ui.label(RichText::new("Hedef dosyalar seçilen kökün içinde olmalıdır.").color(MUTED));
        field(ui, "Kök klasör", &mut self.root_input);
        if ui.button("Bu çalışma alanına geç").clicked() {
            let requested = PathBuf::from(&self.root_input);
            match requested.canonicalize() {
                Ok(path) if path == self.root => self.notice("Bu çalışma alanı zaten açık"),
                Ok(path) if path.is_dir() => {
                    let lock_path = path.join("local/agent.lock");
                    if fs::create_dir_all(path.join("local")).is_err()
                        || core::acquire_agent_lock(&lock_path).is_err()
                    {
                        self.error(
                            "Çalışma alanı başka bir ajan tarafından kullanılıyor veya yazılamıyor",
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
                        self.error("Yeni çalışma alanı açılamadı");
                    }
                }
                _ => self.error("Kök klasör bulunamadı"),
            }
        }
        ui.add_space(18.0);
        ui.heading("Yerel yönetim");
        ui.label("Bu pencere doğrudan çalışan Rust uygulamasına bağlıdır; HTTP sunucusu veya tarayıcı kullanılmaz.");
        ui.label(
            "Pencere kapandığında yönetim süreci durur. Ayrı 'agent' modu bağımsız çalışabilir.",
        );
        ui.add_space(18.0);
        ui.group(|ui| { ui.strong("Geliştirme sürümü");
            ui.label("Yerel GUI ve çekirdek işlevleri kullanılabilir; paketleme ve üç işletim sistemi üzerinde yerel entegrasyon onayı hâlâ gerekir."); });
    }
}

impl eframe::App for DesktopApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::SidePanel::left("nav")
            .min_width(185.0)
            .max_width(185.0)
            .show(ctx, |ui| {
                ui.add_space(15.0);
                ui.heading(RichText::new("TAR").color(ACCENT));
                ui.label(RichText::new("VAULT SYNC").small().color(MUTED));
                ui.add_space(28.0);
                for (page, name) in [
                    (Page::Overview, "Genel Bakış"),
                    (Page::Vault, "Kasa"),
                    (Page::Bindings, "Eşlemeler"),
                    (Page::Events, "Olaylar"),
                    (Page::Settings, "Yönetim"),
                ] {
                    if ui.selectable_label(self.page == page, name).clicked() {
                        self.page = page;
                        self.message.clear();
                    }
                    ui.add_space(6.0);
                }
                ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                    ui.label(RichText::new("Yerel ajan çalışıyor").color(ACCENT).small());
                });
            });
        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.add_space(8.0);
                self.header(ui);
                match self.page {
                    Page::Overview => self.overview(ui),
                    Page::Vault => self.vault(ui),
                    Page::Bindings => self.bindings(ui),
                    Page::Events => self.events(ui),
                    Page::Settings => self.settings(ui),
                }
            });
        });
        ctx.request_repaint_after(std::time::Duration::from_secs(3));
    }
}

fn field(ui: &mut egui::Ui, label: &str, value: &mut String) {
    ui.horizontal(|ui| {
        ui.label(label);
        ui.add(egui::TextEdit::singleline(value).desired_width(420.0));
    });
}
fn secret_type_combo(ui: &mut egui::Ui, label: &str, kind: &mut SecretType) {
    egui::ComboBox::from_label(label)
        .selected_text(format!("{kind:?}"))
        .show_ui(ui, |ui| {
            for choice in [
                SecretType::Text,
                SecretType::Json,
                SecretType::Binary,
                SecretType::Certificate,
                SecretType::PrivateKey,
            ] {
                let text = format!("{choice:?}");
                ui.selectable_value(kind, choice, text);
            }
        });
}
fn policy_label(policy: &MissingTargetPolicy) -> &'static str {
    match policy {
        MissingTargetPolicy::Alert => "Uyar",
        MissingTargetPolicy::Recreate => "Yeniden oluştur",
        MissingTargetPolicy::Disable => "Devre dışı bırak",
    }
}
fn target_label(target: &TargetSpec) -> &'static str {
    match target {
        TargetSpec::WholeFile { .. } => "Dosya",
        TargetSpec::StructuredField { .. } => "Alan",
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
    let app = DesktopApp::new(root)?;
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1160.0, 760.0])
            .with_min_inner_size([900.0, 600.0]),
        ..Default::default()
    };
    eframe::run_native(
        "TAR Vault Sync",
        options,
        Box::new(move |cc| {
            cc.egui_ctx.set_pixels_per_point(1.12);
            let mut visuals = egui::Visuals::dark();
            visuals.widgets.active.bg_fill = ACCENT;
            visuals.selection.bg_fill = Color32::from_rgb(63, 90, 61);
            cc.egui_ctx.set_visuals(visuals);
            Ok(Box::new(app))
        }),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
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
