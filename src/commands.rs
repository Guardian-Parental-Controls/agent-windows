use crate::bios_management;
use crate::screenshot;
use crate::screenshots::{get_screenshot_policy_handle, wake_screenshot_scheduler};
use crate::windows_service;
use guardian_agent::CommandOutcome;

fn outcome(success: bool, message: String, data: serde_json::Value) -> CommandOutcome {
    CommandOutcome {
        success,
        message,
        data,
    }
}

pub async fn handle_command(
    action: &str,
    username: &str,
    args: &serde_json::Value,
) -> CommandOutcome {
    match action {
        "sync_screenshot_policy" => {
            match screenshot::apply_screenshot_policy(get_screenshot_policy_handle(), args) {
                Ok(()) => {
                    wake_screenshot_scheduler();
                    outcome(
                        true,
                        "Screenshot policy synchronized".to_string(),
                        serde_json::json!({}),
                    )
                }
                Err(message) => outcome(false, message, serde_json::json!({})),
            }
        }
        "capture_screenshot" => outcome(
            true,
            "Screenshot capture queued".to_string(),
            serde_json::json!({
                "queued": true,
                "linux_username": args
                    .get("linux_username")
                    .and_then(|value| value.as_str())
                    .or_else(|| if username.trim().is_empty() { None } else { Some(username) }),
            }),
        ),
        "detect_hardware_oem" | "audit_hardware_baseline" | "apply_hardware_baseline" => {
            let (success, message, data) = bios_management::handle_command(action, args);
            outcome(success, message, data)
        }
        _ => {
            let (success, message, data) =
                windows_service::policy::handle_windows_command(action, username, args).await;
            outcome(success, message, data)
        }
    }
}
