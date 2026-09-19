use crate::core::{Engine, SyncOutcome};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::Arc};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
};

#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Status { token: String },
    Events { token: String },
    Trigger { token: String, binding_id: String },
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Response {
    Status { applied: Vec<String> },
    Events { events: Vec<crate::core::Event> },
    Trigger { outcome: SyncOutcome },
    Failed,
    Unauthorized,
    Invalid,
}
pub async fn serve(
    listener: TcpListener,
    engine: Arc<Engine>,
    token: String,
) -> std::io::Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        if !peer.ip().is_loopback() {
            continue;
        }
        let engine = engine.clone();
        let token = token.clone();
        tokio::spawn(async move {
            let _ = handle(stream, engine, &token).await;
        });
    }
}
async fn handle(stream: TcpStream, engine: Arc<Engine>, token: &str) -> std::io::Result<()> {
    let (read, mut write) = stream.into_split();
    let mut reader = BufReader::new(read).take(4097);
    let mut line = Vec::new();
    if reader.read_until(b'\n', &mut line).await? > 4096 {
        return Ok(());
    }
    let response = match serde_json::from_slice::<Request>(&line) {
        Ok(Request::Status { token: t }) if t == token => Response::Status {
            applied: engine.status().applied.keys().cloned().collect(),
        },
        Ok(Request::Events { token: t }) if t == token => {
            match std::fs::read_to_string(&engine.events_path) {
                Ok(data) => {
                    let parsed: Result<Vec<_>, _> = data
                        .lines()
                        .rev()
                        .take(100)
                        .map(serde_json::from_str::<crate::core::Event>)
                        .collect();
                    match parsed {
                        Ok(mut events) => {
                            events.reverse();
                            Response::Events { events }
                        }
                        Err(_) => Response::Failed,
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    Response::Events { events: Vec::new() }
                }
                Err(_) => Response::Failed,
            }
        }
        Ok(Request::Trigger {
            token: t,
            binding_id,
        }) if t == token => Response::Trigger {
            outcome: engine.sync(&binding_id).await,
        },
        Ok(_) => Response::Unauthorized,
        Err(_) => Response::Invalid,
    };
    let mut bytes = serde_json::to_vec(&response).map_err(std::io::Error::other)?;
    bytes.push(b'\n');
    write.write_all(&bytes).await
}
pub async fn request(addr: SocketAddr, req: &Request) -> std::io::Result<Response> {
    let mut stream = TcpStream::connect(addr).await?;
    let mut bytes = serde_json::to_vec(req).map_err(std::io::Error::other)?;
    bytes.push(b'\n');
    stream.write_all(&bytes).await?;
    let mut reader = BufReader::new(stream).take(65537);
    let mut line = Vec::new();
    if reader.read_until(b'\n', &mut line).await? > 65536 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "response too large",
        ));
    }
    serde_json::from_slice(&line).map_err(std::io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{
        Binding, Config, FakeStore, FakeTarget, MissingTargetPolicy, Schedule, SecretType,
        SourceRef, SourceVersion, StoreKind, TargetSpec,
    };
    use std::sync::Mutex;

    #[tokio::test]
    async fn authenticated_manual_sync_and_redacted_events() {
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
                    bindings: vec![Binding {
                        id: "b1".into(),
                        source: SourceRef {
                            store: StoreKind::Fake,
                            connection: "fake".into(),
                            entry: "item".into(),
                        },
                        secret_type: SecretType::Text,
                        target: TargetSpec::Fake {
                            slot: "slot".into(),
                        },
                        missing_target: MissingTargetPolicy::Alert,
                        schedule: Schedule {
                            interval_seconds: 1,
                        },
                    }],
                },
                dir.path().join("state.json"),
                dir.path().join("events.ndjson"),
                store.clone(),
                target.clone(),
            )
            .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(serve(listener, engine, "private-test-token".into()));
        assert!(matches!(
            request(
                addr,
                &Request::Status {
                    token: "wrong".into()
                }
            )
            .await
            .unwrap(),
            Response::Unauthorized
        ));
        assert!(matches!(
            request(
                addr,
                &Request::Trigger {
                    token: "private-test-token".into(),
                    binding_id: "b1".into()
                }
            )
            .await
            .unwrap(),
            Response::Trigger {
                outcome: SyncOutcome::Applied
            }
        ));
        assert!(
            matches!(request(addr, &Request::Status { token: "private-test-token".into() }).await.unwrap(), Response::Status { applied } if applied == vec!["b1"])
        );
        assert!(
            matches!(request(addr, &Request::Events { token: "private-test-token".into() }).await.unwrap(), Response::Events { events } if events.len() == 1)
        );
        let persisted = format!(
            "{}{}",
            std::fs::read_to_string(dir.path().join("state.json")).unwrap(),
            std::fs::read_to_string(dir.path().join("events.ndjson")).unwrap()
        );
        assert!(!persisted.contains("FAKE_PAYLOAD_PROBE"));
        assert!(!persisted.contains("private-test-token"));
        task.abort();
    }
}
