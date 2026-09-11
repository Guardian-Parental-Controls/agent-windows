use std::time::Duration;

use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::sleep;

use crate::domain_policy;
use guardian_agent::ClientMessage;

const POLICY_SYNC_INTERVAL_SECS: u64 = 4 * 60 * 60;

async fn build_policy_sync_check_message() -> Result<ClientMessage, String> {
    let source_revisions = domain_policy::get_source_revisions().await?;
    Ok(ClientMessage::PolicySyncCheck { source_revisions })
}

pub fn spawn_policy_sync_scheduler(
    client_tx: mpsc::UnboundedSender<ClientMessage>,
    mut shutdown: watch::Receiver<bool>,
    mut trigger_rx: mpsc::UnboundedReceiver<()>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        if let Ok(message) = build_policy_sync_check_message().await {
            let _ = client_tx.send(message);
        }

        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                maybe_trigger = trigger_rx.recv() => {
                    if maybe_trigger.is_none() {
                        break;
                    }
                    match build_policy_sync_check_message().await {
                        Ok(message) => {
                            let _ = client_tx.send(message);
                        }
                        Err(error) => {
                            eprintln!("Failed to build policy sync check message: {error}");
                        }
                    }
                }
                _ = sleep(Duration::from_secs(POLICY_SYNC_INTERVAL_SECS)) => {
                    match build_policy_sync_check_message().await {
                        Ok(message) => {
                            let _ = client_tx.send(message);
                        }
                        Err(error) => {
                            eprintln!("Failed to build periodic policy sync check message: {error}");
                        }
                    }
                }
            }
        }
    })
}
