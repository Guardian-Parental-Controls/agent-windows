use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

const MAX_TOAST_PIPE_CLIENTS: usize = 16;
const TOAST_QUEUE_DEPTH: usize = 64;
const PIPE_WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

fn get_ipc_connections() -> &'static Arc<Mutex<HashMap<u32, mpsc::Sender<String>>>> {
    static IPC_CONNECTIONS: OnceLock<Arc<Mutex<HashMap<u32, mpsc::Sender<String>>>>> =
        OnceLock::new();
    IPC_CONNECTIONS.get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
}

pub fn register_ipc_client(id: u32, tx: mpsc::Sender<String>) {
    let mut guard = get_ipc_connections().lock().unwrap();
    guard.insert(id, tx);
}

pub fn unregister_ipc_client(id: u32) {
    let mut guard = get_ipc_connections().lock().unwrap();
    guard.remove(&id);
}

pub fn broadcast_toast_notification(title: &str, message: &str) {
    broadcast_json(&serde_json::json!({
        "type": "toast",
        "title": title,
        "message": message
    }));
}

pub fn broadcast_json(payload: &serde_json::Value) {
    if let Ok(serialized) = serde_json::to_string(payload) {
        let guard = get_ipc_connections().lock().unwrap();
        for tx in guard.values() {
            let _ = tx.try_send(serialized.clone());
        }
    }
}

// Named Pipe IPC Server Listener
pub async fn start_ipc_server() {
    println!("Starting Windows Named Pipe IPC Server...");
    let mut client_id_counter = 0;

    loop {
        #[cfg(target_os = "windows")]
        {
            use tokio::net::windows::named_pipe::ServerOptions;
            let pipe_name = r"\\.\pipe\timekpr_ipc";
            let mut security =
                match crate::windows_security::PipeSecurity::authenticated_users() {
                    Ok(security) => security,
                    Err(error) => {
                        eprintln!("Failed to secure Named Pipe: {error}");
                        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                        continue;
                    }
                };
            let mut options = ServerOptions::new();
            options
                .first_pipe_instance(client_id_counter == 0)
                .max_instances(MAX_TOAST_PIPE_CLIENTS)
                .out_buffer_size(64 * 1024);
            let server = match unsafe {
                options.create_with_security_attributes_raw(
                    pipe_name,
                    security.attributes_mut_ptr().cast(),
                )
            } {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Failed to create Named Pipe server instance: {}", e);
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                    continue;
                }
            };

            // Wait for client connection
            if server.connect().await.is_ok() {
                client_id_counter += 1;
                let id = client_id_counter;
                if get_ipc_connections().lock().unwrap().len() >= MAX_TOAST_PIPE_CLIENTS {
                    continue;
                }
                let (tx, mut rx) = mpsc::channel::<String>(TOAST_QUEUE_DEPTH);
                register_ipc_client(id, tx);

                tokio::spawn(async move {
                    let mut pipe = server;
                    while let Some(msg) = rx.recv().await {
                        // Write message to the named pipe
                        let write = async {
                            pipe.write_all(msg.as_bytes()).await?;
                            pipe.write_all(b"\n").await
                        };
                        if !matches!(
                            tokio::time::timeout(PIPE_WRITE_TIMEOUT, write).await,
                            Ok(Ok(()))
                        ) {
                            break;
                        }
                    }
                    unregister_ipc_client(id);
                });
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            // No-op for compilation on Linux
            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
        }
    }
}
