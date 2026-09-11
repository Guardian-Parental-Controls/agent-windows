use std::sync::Mutex;
use std::time::Duration;

use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::sleep;

use crate::screenshot;

const DEFAULT_SCREENSHOT_INTERVAL_SECS: u64 = 300;

static SCREENSHOT_POLICY: std::sync::OnceLock<screenshot::SharedScreenshotPolicy> =
    std::sync::OnceLock::new();
static SCREENSHOT_TRIGGER_TX: Mutex<Option<mpsc::UnboundedSender<Option<String>>>> =
    Mutex::new(None);
static SCREENSHOT_SCHEDULER_WAKE_TX: Mutex<Option<mpsc::UnboundedSender<()>>> = Mutex::new(None);

pub fn get_screenshot_policy_handle() -> &'static screenshot::SharedScreenshotPolicy {
    SCREENSHOT_POLICY.get_or_init(screenshot::new_shared_screenshot_policy)
}

pub fn set_screenshot_trigger_tx(sender: mpsc::UnboundedSender<Option<String>>) {
    if let Ok(mut guard) = SCREENSHOT_TRIGGER_TX.lock() {
        *guard = Some(sender);
    }
}

pub fn clear_screenshot_handles() {
    if let Ok(mut guard) = SCREENSHOT_TRIGGER_TX.lock() {
        *guard = None;
    }
    if let Ok(mut guard) = SCREENSHOT_SCHEDULER_WAKE_TX.lock() {
        *guard = None;
    }
}

pub fn wake_screenshot_scheduler() {
    if let Ok(guard) = SCREENSHOT_SCHEDULER_WAKE_TX.lock() {
        if let Some(sender) = guard.as_ref() {
            let _ = sender.send(());
        }
    }
}

fn push_screenshot_reports(
    report_tx: &mpsc::UnboundedSender<String>,
    linux_username: Option<&str>,
) {
    let captures = screenshot::capture_screenshots(linux_username);
    for capture in captures {
        match screenshot::build_screenshot_report(&capture) {
            Ok(serialized) => {
                let _ = report_tx.send(serialized);
            }
            Err(error) => {
                eprintln!("Failed to build screenshot report: {error}");
            }
        }
    }
}

pub fn spawn_screenshot_capture_worker(
    mut trigger_rx: mpsc::UnboundedReceiver<Option<String>>,
    report_tx: mpsc::UnboundedSender<String>,
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
                maybe_trigger = trigger_rx.recv() => {
                    let Some(username) = maybe_trigger else {
                        break;
                    };
                    let report_sender = report_tx.clone();
                    let _ = tokio::task::spawn_blocking(move || {
                        push_screenshot_reports(&report_sender, username.as_deref());
                    })
                    .await;
                }
            }
        }
    })
}

pub fn spawn_screenshot_scheduler(
    trigger_tx: mpsc::UnboundedSender<Option<String>>,
    policy: screenshot::SharedScreenshotPolicy,
    mut shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    let (wake_tx, mut wake_rx) = mpsc::unbounded_channel::<()>();
    if let Ok(mut guard) = SCREENSHOT_SCHEDULER_WAKE_TX.lock() {
        *guard = Some(wake_tx);
    }

    tokio::spawn(async move {
        loop {
            let sleep_secs = {
                let guard = policy
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if guard.enabled {
                    guard.interval_seconds.max(60)
                } else {
                    DEFAULT_SCREENSHOT_INTERVAL_SECS
                }
            };

            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                _ = wake_rx.recv() => {}
                _ = sleep(Duration::from_secs(sleep_secs)) => {
                    let enabled = policy
                        .lock()
                        .map(|guard| guard.enabled)
                        .unwrap_or(false);
                    if enabled {
                        let _ = trigger_tx.send(None);
                    }
                }
            }
        }
    })
}
