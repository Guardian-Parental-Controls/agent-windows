use std::time::Duration;
use std::{fs::OpenOptions, io::Write, path::Path};

use guardian_agent::UpdateOffer;
use guardian_agent::update_verify;
use uuid::Uuid;

const DEFAULT_GITHUB_REPO: &str = "Guardian-Parental-Controls/agent-windows";

fn validate_release_urls(download_url: &str, checksum_url: &str) -> Result<(), String> {
    let download = reqwest::Url::parse(download_url)
        .map_err(|error| format!("invalid release URL: {error}"))?;
    let checksum = reqwest::Url::parse(checksum_url)
        .map_err(|error| format!("invalid checksum URL: {error}"))?;
    if download.scheme() != "https" || checksum.scheme() != "https" {
        return Err("release and checksum URLs must use HTTPS".to_string());
    }
    if download.origin() != checksum.origin() {
        return Err("release and checksum URLs must have the same trusted origin".to_string());
    }
    if !checksum.path().ends_with(".sha256") {
        return Err("checksum URL must identify a .sha256 sidecar".to_string());
    }
    Ok(())
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("failed to securely create {}: {error}", path.display()))?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("failed to write {}: {error}", path.display()))
}

#[cfg(target_os = "windows")]
fn verify_publisher(path: &Path) -> Result<(), String> {
    crate::windows_security::verify_authenticode(path)
}

#[cfg(not(target_os = "windows"))]
fn verify_publisher(_path: &Path) -> Result<(), String> {
    Ok(())
}

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

    validate_release_urls(&download_url, &checksum_url)?;
    let bytes = download_release_bytes(&client, &download_url, "release asset").await?;
    let checksum_bytes = download_release_bytes(&client, &checksum_url, "release checksum").await?;
    let checksum_text = String::from_utf8(checksum_bytes)
        .map_err(|error| format!("Release checksum is not valid UTF-8: {error}"))?;
    update_verify::verify_release_asset(&bytes, &checksum_text)?;

    if download_url.ends_with(".msi") || bytes.starts_with(b"\xD0\xCF\x11\xE0") {
        #[cfg(target_os = "windows")]
        let update_dir = {
            let path = crate::windows_security::ensure_guardian_data_dir()?.join("updates");
            crate::windows_security::ensure_secure_directory(&path)?;
            path
        };
        #[cfg(not(target_os = "windows"))]
        let update_dir = std::env::temp_dir();
        let temp_msi = update_dir.join(format!("guardian-update-{}.msi", Uuid::new_v4()));
        write_new_file(&temp_msi, &bytes)?;
        if let Err(error) = verify_publisher(&temp_msi) {
            let _ = std::fs::remove_file(&temp_msi);
            return Err(error);
        }
        let status_result = std::process::Command::new("msiexec")
            .args(["/i", &temp_msi.to_string_lossy(), "/qn", "/norestart"])
            .status();
        let _ = std::fs::remove_file(&temp_msi);
        let status =
            status_result.map_err(|error| format!("Failed to launch msiexec: {error}"))?;
        if !status.success() {
            return Err(format!("msiexec exited with {status}"));
        }
        println!("MSI update installed. Exiting to allow service restart.");
        return Ok(());
    }

    let current_bin = std::env::current_exe()
        .map_err(|error| format!("Failed to determine current executable path: {error}"))?;
    let temp_bin = current_bin.with_extension(format!("{}.tmp", Uuid::new_v4()));
    write_new_file(&temp_bin, &bytes)?;
    if let Err(error) = verify_publisher(&temp_bin) {
        let _ = std::fs::remove_file(&temp_bin);
        return Err(error);
    }
    std::fs::rename(&temp_bin, &current_bin).map_err(|error| {
        let _ = std::fs::remove_file(&temp_bin);
        format!("Failed to rename/replace active executable: {error}")
    })?;
    println!("Auto-update completed successfully! Active executable replaced.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_release_urls;

    #[test]
    fn update_urls_require_https_and_same_origin() {
        assert!(validate_release_urls(
            "https://github.com/org/repo/a.msi",
            "https://github.com/org/repo/a.msi.sha256"
        )
        .is_ok());
        assert!(validate_release_urls(
            "http://github.com/org/repo/a.msi",
            "https://github.com/org/repo/a.msi.sha256"
        )
        .is_err());
        assert!(validate_release_urls(
            "https://example.test/a.msi",
            "https://attacker.test/a.msi.sha256"
        )
        .is_err());
    }
}
