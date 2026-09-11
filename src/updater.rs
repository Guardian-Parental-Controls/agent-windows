use std::time::Duration;

use guardian_agent::UpdateOffer;
use guardian_agent::update_verify;

const DEFAULT_GITHUB_REPO: &str = "Guardian-Parental-Controls/agent-windows";

async fn download_release_bytes(
    client: &reqwest::Client,
    url: &str,
    label: &str,
) -> Result<Vec<u8>, String> {
    println!("Downloading {label} from: {url}");
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|error| format!("HTTP request failed for {label}: {error}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "Server returned error code {} for {label}: {url}",
            response.status()
        ));
    }
    response
        .bytes()
        .await
        .map_err(|error| format!("Failed to read {label} download stream: {error}"))
        .map(|bytes| bytes.to_vec())
}

pub async fn apply_update(offer: UpdateOffer) -> Result<(), String> {
    let target_version = offer
        .target_version
        .as_deref()
        .ok_or_else(|| "Missing target version".to_string())?;
    println!("Initializing auto-update to version {target_version}...");

    if !update_verify::is_valid_release_version(target_version) {
        return Err(format!(
            "Refusing auto-update: invalid release version '{target_version}'"
        ));
    }

    let (download_url, checksum_url) = match (
        offer.download_url.clone(),
        offer.checksum_url.clone(),
    ) {
        (Some(download), Some(checksum)) => (download, checksum),
        _ => {
            if !update_verify::is_valid_github_repo(DEFAULT_GITHUB_REPO) {
                return Err("Refusing auto-update: invalid default GitHub repository".to_string());
            }
            let asset_name = "guardian-agent-x86_64-pc-windows-msvc.msi";
            (
                format!(
                    "https://github.com/{DEFAULT_GITHUB_REPO}/releases/download/{target_version}/{asset_name}"
                ),
                format!(
                    "https://github.com/{DEFAULT_GITHUB_REPO}/releases/download/{target_version}/{asset_name}.sha256"
                ),
            )
        }
    };

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .map_err(|error| format!("Failed to build HTTP client: {error}"))?;

    let bytes = download_release_bytes(&client, &download_url, "release asset").await?;
    let checksum_bytes = download_release_bytes(&client, &checksum_url, "release checksum").await?;
    let checksum_text = String::from_utf8(checksum_bytes)
        .map_err(|error| format!("Release checksum is not valid UTF-8: {error}"))?;
    update_verify::verify_release_asset(&bytes, &checksum_text)?;

    if download_url.ends_with(".msi") || bytes.starts_with(b"\xD0\xCF\x11\xE0") {
        let temp_msi = std::env::temp_dir().join("guardian-agent-update.msi");
        std::fs::write(&temp_msi, &bytes)
            .map_err(|error| format!("Failed to write MSI update: {error}"))?;
        let status = std::process::Command::new("msiexec")
            .args(["/i", &temp_msi.to_string_lossy(), "/qn", "/norestart"])
            .status()
            .map_err(|error| format!("Failed to launch msiexec: {error}"))?;
        if !status.success() {
            return Err(format!("msiexec exited with {status}"));
        }
        println!("MSI update installed. Exiting to allow service restart.");
        return Ok(());
    }

    let current_bin = std::env::current_exe()
        .map_err(|error| format!("Failed to determine current executable path: {error}"))?;
    let temp_bin = current_bin.with_extension("tmp");
    std::fs::write(&temp_bin, &bytes)
        .map_err(|error| format!("Failed to write temporary binary file: {error}"))?;
    std::fs::rename(&temp_bin, &current_bin).map_err(|error| {
        let _ = std::fs::remove_file(&temp_bin);
        format!("Failed to rename/replace active executable: {error}")
    })?;
    println!("Auto-update completed successfully! Active executable replaced.");
    Ok(())
}
