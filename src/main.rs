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
    if args.get(1).map(String::as_str) == Some("--install-config-from-ini") {
        let result = read_install_ini().and_then(|(server_url, registration_token)| {
            guardian_agent_windows::windows_security::write_install_config(
                &server_url,
                &registration_token,
            )
        });
        if let Err(error) = result {
            eprintln!("Failed to install Guardian configuration: {error}");
            std::process::exit(2);
        }
        return;
    }
    if args.get(1).map(String::as_str) == Some("--install-config") {
        let result = match (args.get(2), args.get(3), args.len()) {
            (Some(server_url), Some(registration_token), 4) => {
                guardian_agent_windows::windows_security::write_install_config(
                    server_url,
                    registration_token,
                )
            }
            _ => Err("usage: guardian-agent --install-config <server-url> <token>".to_string()),
        };
        if let Err(error) = result {
            eprintln!("Failed to install Guardian configuration: {error}");
            std::process::exit(2);
        }
        return;
    }
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

#[cfg(target_os = "windows")]
fn read_install_ini() -> Result<(String, String), String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("failed to locate installer directory: {error}"))?;
    let path = executable
        .parent()
        .ok_or_else(|| "installer directory is unavailable".to_string())?
        .join("install.ini");
    let text = std::fs::read_to_string(&path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let mut server_url = None;
    let mut registration_token = String::new();
    for line in text.lines() {
        let line = line.trim();
        if let Some(value) = line.strip_prefix("server_url=") {
            server_url = Some(value.trim().to_string());
        } else if let Some(value) = line.strip_prefix("registration_token=") {
            registration_token = value.trim().to_string();
        }
    }
    server_url
        .filter(|value| !value.is_empty())
        .map(|value| (value, registration_token))
        .ok_or_else(|| format!("install.ini at {} is missing server_url", path.display()))
}

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("guardian-agent-windows can only run on Windows");
    std::process::exit(1);
}
