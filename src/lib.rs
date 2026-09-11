//! Windows enforcement crate for the Guardian agent.

pub mod bios_management;
#[cfg(target_os = "windows")]
pub mod commands;
pub mod domain_notify;
pub mod domain_policy;
pub mod extension_policy;
pub mod firewall;
pub mod installed_apps;
pub mod inventory;
pub mod ipc;
pub mod local_dns;
pub mod netlink;
pub mod policy_sync;
#[cfg(target_os = "windows")]
pub mod runtime;
pub mod screenshot;
pub mod screenshots;
pub mod updater;
pub mod users;

#[cfg(target_os = "windows")]
pub mod windows_service;
#[cfg(target_os = "windows")]
pub mod windows_user_agent;

pub use guardian_agent::build_alert_message;
pub use guardian_agent::i18n;
pub use guardian_agent::{ActiveClientTx, ClientMessage, LinuxUser};
