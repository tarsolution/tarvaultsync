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
        MissingTargetPolicy, ModuleRegistry, ModuleSetting, Schedule, SecretType, SourceVersion,
    },
    ipc::{self, Request},
};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("config");
    let root = env::var("TAR_VAULT_SYNC_DIR")
        .map(PathBuf::from)
        .unwrap_or(env::current_dir()?);
    let addr: SocketAddr = "127.0.0.1:43871".parse()?;
    let mut screens = ModuleRegistry::new();
    screens.register(Arc::new(FakeStoreScreen)).unwrap();
    screens.register(Arc::new(FakeTargetScreen)).unwrap();
    if mode == "config" {
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
            "{}\n{}",
            screens.mount("fake_store").unwrap(),
            screens.mount("fake_target").unwrap()
        );
        return Ok(());
    }
    let token = env::var("TAR_VAULT_SYNC_TEST_TOKEN")
        .map_err(|_| "test IPC token required; native secure store adapter is pending")?;
    if mode == "status" || mode == "sync" || mode == "logs" {
        let req = if mode == "status" {
            Request::Status { token }
        } else if mode == "logs" {
            Request::Events { token }
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
    let data = fs::read(root.join("shared/config.json"))?;
    let config = core::validate_config(&data, &root)?;
    let store = Arc::new(FakeStore {
        version: Mutex::new(SourceVersion("v1".into())),
        reads: Mutex::new((0, 0)),
    });
    let target = Arc::new(FakeTarget {
        applies: Mutex::new(0),
        fail: Mutex::new(false),
    });
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
