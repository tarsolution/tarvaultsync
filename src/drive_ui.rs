//! Native setup flow; only the provider's OAuth/Picker opens a browser.
use crate::{
    cloud_auth,
    drive::{Api, DriveError, Item, Provider, RemoteRef},
    sources::{Connection, Location},
    vault::LocalVault,
};
use eframe::egui;
use std::{
    sync::{mpsc, Arc},
    time::Duration,
};
use zeroize::{Zeroize, Zeroizing};

enum ResultEvent {
    Connected(Arc<Api>, Item, Vec<Item>),
    Listed(String, Vec<Item>),
    Selected(RemoteRef),
}
pub(crate) struct DriveForm {
    provider: Provider,
    client_secret: Zeroizing<String>,
    passphrase: Zeroizing<String>,
    connection_id: String,
    filename: String,
    api: Option<Arc<Api>>,
    folder: String,
    items: Vec<Item>,
    pending: Option<mpsc::Receiver<Result<ResultEvent, DriveError>>>,
    message: String,
    ready: Option<RemoteRef>,
}
impl Default for DriveForm {
    fn default() -> Self {
        Self {
            provider: Provider::OneDrive,
            client_secret: Zeroizing::new(String::new()),
            passphrase: Zeroizing::new(String::new()),
            connection_id: String::new(),
            filename: "vault.tarvault".into(),
            api: None,
            folder: String::new(),
            items: Vec::new(),
            pending: None,
            message: String::new(),
            ready: None,
        }
    }
}
impl DriveForm {
    fn start(&mut self, action: impl FnOnce() -> Result<ResultEvent, DriveError> + Send + 'static) {
        let (sender, receiver) = mpsc::sync_channel(1);
        self.pending = Some(receiver);
        self.message = "Working… Browser authorization expires after three minutes.".into();
        std::thread::spawn(move || {
            let _ = sender.send(action());
        });
    }
    pub(crate) fn show(&mut self, ui: &mut egui::Ui) -> Option<Connection> {
        if let Some(receiver) = &self.pending {
            match receiver.try_recv() {
                Ok(result) => {
                    self.pending = None;
                    match result {
                        Ok(ResultEvent::Connected(api, item, items)) => {
                            if item.folder {
                                self.folder = item.id;
                                self.items = items;
                            } else {
                                self.ready = Some(RemoteRef {
                                    provider: api.provider,
                                    credential_id: api.credential_id.clone(),
                                    file_id: item.id,
                                });
                            }
                            self.api = Some(api);
                            self.message = "Account connected. Select an encrypted vault or create one in the selected folder.".into();
                        }
                        Ok(ResultEvent::Listed(folder, items)) => {
                            self.folder = folder;
                            self.items = items;
                            self.message.clear();
                        }
                        Ok(ResultEvent::Selected(remote)) => {
                            self.ready = Some(remote);
                            self.passphrase.zeroize();
                            self.message = "Vault selected. Add the connection, then unlock it in Manage vault.".into();
                        }
                        Err(error) => self.message = error.to_string(),
                    }
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.pending = None;
                    self.message = "Drive operation stopped unexpectedly.".into();
                }
                Err(mpsc::TryRecvError::Empty) => {
                    ui.ctx().request_repaint_after(Duration::from_millis(100));
                }
            }
        }
        ui.separator();
        ui.heading("Connect a cloud vault");
        ui.label("Cloud vaults stay encrypted. Tokens use the OS credential store. No plaintext fallback.");
        ui.label(&self.message);
        let mut result = None;
        ui.add_enabled_ui(self.pending.is_none(), |ui| {
            ui.label("Connection ID"); ui.text_edit_singleline(&mut self.connection_id);
            if self.api.is_none() {
                ui.horizontal(|ui| {
                    ui.selectable_value(&mut self.provider, Provider::OneDrive, "OneDrive");
                    ui.selectable_value(&mut self.provider, Provider::GoogleDrive, "Google Drive");
                });
                if self.provider == Provider::GoogleDrive {
                    ui.label("Desktop OAuth client secret (stored only in OS credentials)");
                    ui.add(egui::TextEdit::singleline(&mut *self.client_secret).password(true));
                    ui.label("In Google Picker, select the destination folder or an existing .tarvault file.");
                } else {
                    ui.label("OneDrive requests Files.ReadWrite to browse your folders. The app writes only the vault you select/create.");
                }
                if ui.button("Sign in and select location").clicked() {
                    let provider = self.provider;
                    let secret = Zeroizing::new(std::mem::take(&mut *self.client_secret));
                    self.start(move || {
                        let login = cloud_auth::login(provider, secret)?;
                        let api = Arc::new(Api::new(login.provider, login.credential_id.clone()));
                        let result = (|| {
                            let selection = if provider == Provider::GoogleDrive { login.picked.as_deref().ok_or(DriveError::InvalidInput)? } else { "root" };
                            let item = api.item(selection)?;
                            let items = if item.folder { api.children(&item.id)? } else { Vec::new() };
                            Ok(ResultEvent::Connected(api, item, items))
                        })();
                        if result.is_err() { cloud_auth::disconnect(&login.credential_id)?; }
                        result
                    });
                }
            } else if let Some(api) = self.api.clone() {
                if self.ready.is_none() {
                    ui.label(format!("Selected folder ID: {}", self.folder));
                    if self.provider == Provider::OneDrive && ui.button("Browse from OneDrive root").clicked() {
                        let api = api.clone();
                        self.start(move || { let root = api.item("root")?; Ok(ResultEvent::Listed(root.id.clone(), api.children(&root.id)?)) });
                    }
                    if self.provider == Provider::GoogleDrive { ui.label("Only files granted to this app are visible. Disconnect this draft to open Google Picker again."); }
                    let mut selected = None;
                    egui::ScrollArea::vertical().id_salt("drive_items").max_height(220.0).show(ui, |ui| {
                        for item in &self.items {
                            if (item.folder || item.name.ends_with(".tarvault")) && ui.button(format!("{} {}", if item.folder { "Folder:" } else { "Vault:" }, item.name)).clicked() {
                                selected = Some((item.id.clone(), item.folder));
                            }
                        }
                    });
                    if let Some((id, folder)) = selected {
                        let api = api.clone();
                        self.start(move || if folder { Ok(ResultEvent::Listed(id.clone(), api.children(&id)?)) }
                            else { Ok(ResultEvent::Selected(RemoteRef { provider: api.provider, credential_id: api.credential_id.clone(), file_id: id })) });
                    }
                    ui.label("New encrypted vault filename (.tarvault)"); ui.text_edit_singleline(&mut self.filename);
                    ui.label("New vault passphrase (at least 12 characters)");
                    ui.add(egui::TextEdit::singleline(&mut *self.passphrase).password(true));
                    if ui.button("Create encrypted vault in selected folder").clicked() {
                        let api = api.clone();
                        let folder = self.folder.clone(); let name = self.filename.clone();
                        let passphrase = Zeroizing::new(std::mem::take(&mut *self.passphrase));
                        self.start(move || {
                            let temp = tempfile::tempdir().map_err(|_| DriveError::Network)?;
                            let path = temp.path().join("new.tarvault");
                            let vault = LocalVault::create(&path, &passphrase).map_err(|_| DriveError::InvalidInput)?;
                            drop(vault);
                            let file = std::fs::File::open(&path).map_err(|_| DriveError::Network)?;
                            let encrypted = crate::drive::bounded(file, crate::drive::MAX_CIPHERTEXT)?;
                            Ok(ResultEvent::Selected(api.create(&folder, &name, &encrypted)?))
                        });
                    }
                }
                if let Some(remote) = &self.ready {
                    ui.label(format!("Selected vault ID: {}", remote.file_id));
                    if ui.button("Add cloud connection").clicked() {
                        result = Some(Connection { id: self.connection_id.clone(), location: Location::Drive { remote: remote.clone() } });
                    }
                }
                if ui.button("Disconnect this draft (keep remote files)").clicked() {
                    match cloud_auth::disconnect(&api.credential_id) {
                        Ok(()) => *self = Self::default(), Err(error) => self.message = error.to_string(),
                    }
                }
            }
        });
        result
    }
    pub(crate) fn saved(&mut self) {
        *self = Self::default();
    }
}
