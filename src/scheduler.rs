use crate::core::{retry_delay, Engine, ErrorCategory, SyncOutcome};
use std::{sync::Arc, time::Duration};
use tokio::time::sleep;

pub fn interval_delay(interval_seconds: u64, seed: u64) -> Duration {
    Duration::from_secs(interval_seconds.saturating_add(seed % 3))
}

pub async fn run_binding(engine: Arc<Engine>, id: String, interval_seconds: u64, seed: u64) {
    loop {
        sleep(interval_delay(interval_seconds, seed)).await;
        let mut attempt = 0;
        loop {
            match engine.sync(&id).await {
                SyncOutcome::Failed(
                    ErrorCategory::Source | ErrorCategory::VersionConflict | ErrorCategory::Target,
                ) if attempt < 3 => {
                    attempt += 1;
                    sleep(retry_delay(attempt, seed)).await;
                }
                _ => break,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{
        validate_config, Binding, Config, FakeStore, FakeStoreScreen, FakeTarget, FakeTargetScreen,
        MissingTargetPolicy, ModuleRegistry, ModuleSetting, Schedule, SecretType, SourceVersion,
    };
    use crate::ipc::{request, serve, Request, Response};
    use std::{fs, sync::Mutex};
    use tokio::net::TcpListener;

    #[tokio::test(start_paused = true)]
    async fn settings_fixture_manual_and_scheduled_ipc_sync() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("shared")).unwrap();
        let mut host = ModuleRegistry::new();
        host.register(Arc::new(FakeStoreScreen)).unwrap();
        host.register(Arc::new(FakeTargetScreen)).unwrap();
        assert!(host.mount("fake_store").is_some());
        assert!(host.mount("fake_target").is_some());
        let source = match host.configure("fake_store", "connection,entry").unwrap() {
            ModuleSetting::Source(v) => v,
            _ => panic!(),
        };
        let target_spec = match host.configure("fake_target", "slot").unwrap() {
            ModuleSetting::Target(v) => v,
            _ => panic!(),
        };
        let config = Config {
            version: 1,
            bindings: vec![Binding {
                id: "b1".into(),
                source,
                secret_type: SecretType::Text,
                target: target_spec,
                missing_target: MissingTargetPolicy::Alert,
                schedule: Schedule {
                    interval_seconds: 2,
                },
            }],
        };
        let config_path = dir.path().join("shared/config.json");
        fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
        let config = validate_config(&fs::read(&config_path).unwrap(), dir.path()).unwrap();
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
                config,
                dir.path().join("state.json"),
                dir.path().join("events.ndjson"),
                store.clone(),
                target.clone(),
            )
            .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(serve(listener, engine.clone(), "test-token".into()));
        assert!(matches!(
            request(
                addr,
                &Request::Trigger {
                    token: "test-token".into(),
                    binding_id: "b1".into()
                }
            )
            .await
            .unwrap(),
            Response::Trigger {
                outcome: SyncOutcome::Applied
            }
        ));
        *store.version.lock().unwrap() = SourceVersion("v2".into());
        let scheduler = tokio::spawn(run_binding(engine.clone(), "b1".into(), 2, 0));
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(2)).await;
        tokio::task::yield_now().await;
        assert_eq!(*target.applies.lock().unwrap(), 2);
        assert!(
            matches!(request(addr,&Request::Status { token:"test-token".into() }).await.unwrap(),Response::Status { applied } if applied==vec!["b1"])
        );
        assert_eq!(interval_delay(2, 2), Duration::from_secs(4));
        assert_eq!(retry_delay(2, 17), Duration::from_millis(4017));
        scheduler.abort();
        server.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn jitter_and_retry_wait_before_state_advances() {
        let dir = tempfile::tempdir().unwrap();
        let mut host = ModuleRegistry::new();
        host.register(Arc::new(FakeStoreScreen)).unwrap();
        host.register(Arc::new(FakeTargetScreen)).unwrap();
        let source = match host.configure("fake_store", "c,e").unwrap() {
            ModuleSetting::Source(v) => v,
            _ => panic!(),
        };
        let target_spec = match host.configure("fake_target", "slot").unwrap() {
            ModuleSetting::Target(v) => v,
            _ => panic!(),
        };
        let config = Config {
            version: 1,
            bindings: vec![Binding {
                id: "b1".into(),
                source,
                secret_type: SecretType::Text,
                target: target_spec,
                missing_target: MissingTargetPolicy::Alert,
                schedule: Schedule {
                    interval_seconds: 2,
                },
            }],
        };
        let store = Arc::new(FakeStore {
            version: Mutex::new(SourceVersion("v1".into())),
            reads: Mutex::new((0, 0)),
        });
        let target = Arc::new(FakeTarget {
            applies: Mutex::new(0),
            fail: Mutex::new(true),
        });
        let engine = Arc::new(
            Engine::new(
                config,
                dir.path().join("state.json"),
                dir.path().join("events.ndjson"),
                store.clone(),
                target.clone(),
            )
            .unwrap(),
        );
        let task = tokio::spawn(run_binding(engine.clone(), "b1".into(), 2, 2));
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(3)).await;
        tokio::task::yield_now().await;
        assert_eq!(*store.reads.lock().unwrap(), (0, 0));
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(*store.reads.lock().unwrap(), (1, 1));
        assert!(engine.status().applied.is_empty());
        *target.fail.lock().unwrap() = false;
        tokio::time::advance(Duration::from_millis(2001)).await;
        tokio::task::yield_now().await;
        assert!(engine.status().applied.is_empty());
        tokio::time::advance(Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(engine.status().applied["b1"].0, "v1");
        assert_eq!(*target.applies.lock().unwrap(), 1);
        task.abort();
    }
}
