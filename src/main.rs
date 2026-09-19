use std::{
    env, fs,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use tar_vault_sync::{
    core::{
        self, Binding, Config, Engine, FakeStore, FakeStoreScreen, FakeTarget, FakeTargetScreen,
        LocalTarget, MissingTargetPolicy, ModuleRegistry, ModuleSetting, Schedule, SecretType,
        SourceConnection, SourceVersion, StoreKind,
    },
    ipc::{self, Request},
    targets::ProductionTarget,
    vault::{VaultSource, VaultStoreScreen},
};
use tokio::net::TcpListener;
use zeroize::Zeroizing;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let root = env::var("TAR_VAULT_SYNC_DIR")
        .map(PathBuf::from)
        .unwrap_or(env::current_dir()?);
    let root = root.canonicalize()?;
    if args.get(1).is_some_and(|mode| mode == "desktop") {
        return tar_vault_sync::desktop::run(root);
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async_main(args, root))
}

async fn async_main(args: Vec<String>, root: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let mode = args.get(1).map(String::as_str).unwrap_or("config");
    let addr: SocketAddr = "127.0.0.1:43871".parse()?;
    let mut screens = ModuleRegistry::new();
    screens.register(Arc::new(FakeStoreScreen)).unwrap();
    screens.register(Arc::new(FakeTargetScreen)).unwrap();
    screens.register(Arc::new(VaultStoreScreen)).unwrap();
    if mode == "config" {
        if args.get(2).is_some_and(|v| v == "add") {
            return config_add(&root);
        }
        if args.len() == 5 {
            let source =
                match screens.configure("fake_store", &format!("{},{}", args[2], args[3]))? {
                    ModuleSetting::Source(s) => s,
                    _ => return Err("invalid source screen".into()),
                };
            let target = match screens.configure("fake_target", &args[4])? {
                ModuleSetting::Target(t) => t,
                _ => return Err("invalid target screen".into()),
            };
            let config = Config {
                version: core::SCHEMA_VERSION,
                bindings: vec![Binding {
                    id: "fake_binding".into(),
                    source,
                    secret_type: SecretType::Text,
                    target,
                    missing_target: MissingTargetPolicy::Alert,
                    schedule: Schedule {
                        interval_seconds: 60,
                    },
                }],
            };
            println!("{}", serde_json::to_string_pretty(&config)?);
            return Ok(());
        }
        println!(
            "{}\n{}\n{}\nUse `config add` to create a local-vault binding.",
            screens.mount("fake_store").unwrap(),
            screens.mount("fake_target").unwrap(),
            screens.mount("local_vault").unwrap()
        );
        return Ok(());
    }
    if mode == "vault" {
        return vault_command(&root, &args);
    }
    let token = env::var("TAR_VAULT_SYNC_TEST_TOKEN")
        .map_err(|_| "test IPC token required; native secure store adapter is pending")?;
    if mode == "status"
        || mode == "sync"
        || mode == "logs"
        || mode == "ack-restart"
        || mode == "enable"
    {
        let req = if mode == "status" {
            Request::Status { token }
        } else if mode == "logs" {
            Request::Events { token }
        } else if mode == "ack-restart" {
            Request::AcknowledgeRestart {
                token,
                binding_id: args.get(2).ok_or("binding id required")?.clone(),
            }
        } else if mode == "enable" {
            Request::Enable {
                token,
                binding_id: args.get(2).ok_or("binding id required")?.clone(),
            }
        } else {
            Request::Trigger {
                token,
                binding_id: args.get(2).ok_or("binding id required")?.clone(),
            }
        };
        let response = ipc::request(addr, &req).await?;
        println!("{}", serde_json::to_string(&response)?);
        return Ok(());
    }
    if mode != "agent" {
        return Err("unknown mode".into());
    }
    fs::create_dir_all(root.join("local"))?;
    let _agent_lock = core::acquire_agent_lock(&root.join("local/agent.lock"))?;
    let data = fs::read(root.join("shared/config.json"))?;
    let config = core::validate_config(&data, &root)?;
    let (store, target): (Arc<dyn SourceConnection>, Arc<dyn LocalTarget>) =
        if config
            .bindings
            .iter()
            .all(|b| b.source.store == StoreKind::Fake)
        {
            (
                Arc::new(FakeStore {
                    version: Mutex::new(SourceVersion("v1".into())),
                    reads: Mutex::new((0, 0)),
                }),
                Arc::new(FakeTarget {
                    applies: Mutex::new(0),
                    fail: Mutex::new(false),
                }),
            )
        } else {
            let connection = &config
                .bindings
                .first()
                .ok_or("no bindings")?
                .source
                .connection;
            if config.bindings.iter().any(|b| {
                b.source.store != StoreKind::LocalVault || b.source.connection != *connection
            }) {
                return Err("mixed or multiple vault connections are unsupported".into());
            }
            let source = Arc::new(VaultSource::new(
                root.join("local/vault.bin"),
                connection.clone(),
            )?);
            let passphrase = Zeroizing::new(rpassword::prompt_password("Vault passphrase: ")?);
            source.unlock(&passphrase)?;
            (source, Arc::new(ProductionTarget::new(root.clone())?))
        };
    let engine = Arc::new(Engine::new(
        config,
        root.join("local/state.json"),
        root.join("local/events.ndjson"),
        store,
        target,
    )?);
    let listener = TcpListener::bind(addr).await?;
    for b in &engine.config.bindings {
        let scheduled = engine.clone();
        let id = b.id.clone();
        let interval = b.schedule.interval_seconds;
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        tokio::spawn(tar_vault_sync::scheduler::run_binding(
            scheduled, id, interval, seed,
        ));
    }
    ipc::serve(listener, engine, token).await?;
    Ok(())
}

fn ask(label: &str) -> Result<String, Box<dyn std::error::Error>> {
    use std::io::Write;
    print!("{label}: ");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_owned())
}

fn config_add(root: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    use tar_vault_sync::core::{DockerInputKind, SourceRef, StructuredFormat, TargetSpec};
    let id = ask("Binding ID")?;
    let entry = ask("Vault entry ID")?;
    let secret_type = parse_secret_type(&ask(
        "Secret type (text/json/binary/certificate/private_key)",
    )?)?;
    let target_kind = ask("Target (whole_file/dotenv/json/yaml/properties/docker_compose/docker_env_file/git_credential)")?;
    let target = match target_kind.as_str() {
        "whole_file" => TargetSpec::WholeFile {
            path: ask("Absolute target path")?.into(),
        },
        "dotenv" | "json" | "yaml" | "properties" => {
            let format = match target_kind.as_str() {
                "dotenv" => StructuredFormat::DotEnv,
                "json" => StructuredFormat::Json,
                "yaml" => StructuredFormat::Yaml,
                _ => StructuredFormat::Properties,
            };
            TargetSpec::StructuredField {
                path: ask("Absolute target path")?.into(),
                key: ask("Field key (JSON/YAML pointer starts with /)")?,
                format,
            }
        }
        "docker_compose" | "docker_env_file" => TargetSpec::DockerInput {
            path: ask("Absolute target path")?.into(),
            key: ask("Key (compose: service:VARIABLE; env_file: VARIABLE)")?,
            input: if target_kind == "docker_compose" {
                DockerInputKind::ComposeEnvironment
            } else {
                DockerInputKind::EnvFile {
                    compose_path: ask("Absolute Compose file path")?.into(),
                    service: ask("Compose service")?,
                }
            },
        },
        "git_credential" => TargetSpec::GitCredential {
            protocol: "https".into(),
            host: ask("Git host")?,
            path: match ask("Repository path (blank for host scope)")?.as_str() {
                "" => None,
                value => Some(value.to_owned()),
            },
            username: ask("Git username")?,
        },
        _ => return Err("unknown target".into()),
    };
    let missing_target = match ask("Missing target policy (alert/recreate/disable)")?.as_str() {
        "alert" => MissingTargetPolicy::Alert,
        "recreate" => MissingTargetPolicy::Recreate,
        "disable" => MissingTargetPolicy::Disable,
        _ => return Err("invalid missing target policy".into()),
    };
    let interval_seconds: u64 = ask("Check interval in seconds")?.parse()?;
    let path = root.join("shared/config.json");
    let mut config: Config = if path.exists() {
        core::validate_config(&fs::read(&path)?, root)?
    } else {
        Config {
            version: core::SCHEMA_VERSION,
            bindings: Vec::new(),
        }
    };
    if config
        .bindings
        .iter()
        .any(|b| b.source.store != StoreKind::LocalVault)
    {
        return Err("existing config uses a different store".into());
    }
    config.bindings.push(Binding {
        id,
        source: SourceRef {
            store: StoreKind::LocalVault,
            connection: "local".into(),
            entry,
        },
        secret_type,
        target,
        missing_target,
        schedule: Schedule { interval_seconds },
    });
    let bytes = serde_json::to_vec_pretty(&config)?;
    core::validate_config(&bytes, root)?;
    let added = config.bindings.last().ok_or("binding missing")?;
    ProductionTarget::new(root.to_path_buf())?.validate(&added.target, &added.secret_type)?;
    fs::create_dir_all(root.join("shared"))?;
    use std::io::Write;
    let mut temp = tempfile::NamedTempFile::new_in(root.join("shared"))?;
    temp.write_all(&bytes)?;
    temp.as_file().sync_all()?;
    temp.persist(&path)?;
    println!("Binding saved");
    Ok(())
}

fn parse_secret_type(s: &str) -> Result<SecretType, Box<dyn std::error::Error>> {
    Ok(match s {
        "text" => SecretType::Text,
        "json" => SecretType::Json,
        "binary" => SecretType::Binary,
        "certificate" => SecretType::Certificate,
        "private_key" => SecretType::PrivateKey,
        _ => return Err("invalid secret type".into()),
    })
}

fn vault_command(
    root: &std::path::Path,
    args: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    use tar_vault_sync::{core::SecretPayload, vault::LocalVault};
    let vault_path = root.join("local/vault.bin");
    fs::create_dir_all(root.join("local"))?;
    let command = args
        .get(2)
        .map(String::as_str)
        .ok_or("vault command required")?;
    if command == "create" {
        let first = Zeroizing::new(rpassword::prompt_password("New vault passphrase: ")?);
        let again = Zeroizing::new(rpassword::prompt_password("Repeat passphrase: ")?);
        if *first != *again {
            return Err("passphrases differ".into());
        }
        LocalVault::create(&vault_path, &first)?;
        println!("Vault created");
        return Ok(());
    }
    if command == "recover" {
        let backup = PathBuf::from(args.get(3).ok_or("encrypted backup path required")?);
        let passphrase = Zeroizing::new(rpassword::prompt_password("Vault passphrase: ")?);
        LocalVault::recover(&backup, &vault_path, &passphrase)?;
        println!("Vault recovered");
        return Ok(());
    }
    let passphrase = Zeroizing::new(rpassword::prompt_password("Vault passphrase: ")?);
    let mut vault = LocalVault::unlock(&vault_path, &passphrase)?;
    match command {
        "put" => {
            let entry = args.get(3).ok_or("entry ID required")?;
            let kind = match args.get(4).map(String::as_str) {
                Some("text") => SecretType::Text,
                Some("json") => SecretType::Json,
                Some("binary") => SecretType::Binary,
                Some("certificate") => SecretType::Certificate,
                Some("private_key") => SecretType::PrivateKey,
                _ => {
                    return Err(
                        "secret type required: text, json, binary, certificate, private_key".into(),
                    )
                }
            };
            let bytes = if let Some(file) = args.get(5) {
                fs::read(file)?
            } else if matches!(kind, SecretType::Text | SecretType::Json) {
                rpassword::prompt_password("Secret value: ")?.into_bytes()
            } else {
                return Err("binary and key types require an input file".into());
            };
            vault.put(entry, &SecretPayload::new(bytes, kind))?;
            println!("Vault entry updated");
        }
        "remove" => {
            vault.remove(args.get(3).ok_or("entry ID required")?)?;
            println!("Vault entry removed");
        }
        "backup" => {
            let destination = PathBuf::from(args.get(3).ok_or("encrypted backup path required")?);
            vault.backup(&destination)?;
            println!("Encrypted backup created");
        }
        _ => return Err("unknown vault command".into()),
    }
    vault.lock();
    Ok(())
}
