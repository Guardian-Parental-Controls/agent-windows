#[cfg(target_os = "windows")]
fn init_sentry() -> Option<sentry::ClientInitGuard> {
    let version = option_env!("GUARDIAN_AGENT_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"));
    if let Some(dsn) = option_env!("SENTRY_DSN") {
        if !dsn.is_empty() {
            let options = sentry::ClientOptions {
                release: Some(version.into()),
                auto_session_tracking: true,
                ..Default::default()
            };
            let guard = sentry::init((dsn, options));
            if guard.is_enabled() {
                return Some(guard);
            }
        }
    }
    None
}

#[cfg(target_os = "windows")]
#[tokio::main]
async fn main() {
    let _sentry_guard = init_sentry();
    let args: Vec<String> = std::env::args().collect();
    if args.len() >= 2
        && args
            .iter()
            .any(|arg| arg.starts_with("chrome-extension://"))
    {
        guardian_agent_windows::ipc::run_native_messaging_proxy().await;
        return;
    }
    if args.iter().any(|arg| arg == "--user-agent") {
        guardian_agent_windows::windows_user_agent::run_user_agent().await;
        return;
    }

    guardian_agent_windows::windows_service::run_service().await;
}

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("guardian-agent-windows can only run on Windows");
    std::process::exit(1);
}
