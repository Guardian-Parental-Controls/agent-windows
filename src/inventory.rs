use std::collections::HashMap;

use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::{Duration, sleep};
use uuid::Uuid;

use crate::installed_apps;

const INSTALLED_APPS_SYNC_INTERVAL_SECS: u64 = 24 * 60 * 60;

pub fn push_inventory_for_user(inventory_tx: &mpsc::UnboundedSender<String>, linux_username: &str) {
    let apps = installed_apps::discover_for_user(linux_username);
    let report_id = Uuid::new_v4().to_string();
    for message in installed_apps::build_inventory_messages(linux_username, &apps, &report_id) {
        let _ = inventory_tx.send(message);
    }
}

pub fn push_inventory_for_users(
    inventory_tx: &mpsc::UnboundedSender<String>,
    users: &HashMap<u32, String>,
) {
    for username in users.values() {
        push_inventory_for_user(inventory_tx, username);
    }
}

pub fn spawn_installed_apps_scheduler(
    inventory_tx: mpsc::UnboundedSender<String>,
    users: HashMap<u32, String>,
    mut shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                _ = sleep(Duration::from_secs(INSTALLED_APPS_SYNC_INTERVAL_SECS)) => {
                    push_inventory_for_users(&inventory_tx, &users);
                }
            }
        }
    })
}
