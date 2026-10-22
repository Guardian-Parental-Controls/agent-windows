use std::fs;
use std::path::PathBuf;
use std::process::Command;

use serde_json::json;

use super::compliance::HardwareReceipt;
use super::password;

mod oem_detect;

use oem_detect::detect;

const PAYLOAD_ROOT: &str = r"C:\ProgramData\Guardian\bios-payloads";

pub fn payload_dir(vendor: &str) -> PathBuf {
    PathBuf::from(PAYLOAD_ROOT).join(vendor)
}

pub fn payload_present(vendor: &str) -> bool {
    payload_dir(vendor).is_dir()
}

fn validate_payload(vendor: &str) -> Result<(), String> {
    if !matches!(vendor, "dell" | "hp" | "lenovo" | "surface") {
        return Err("refusing unsupported BIOS payload vendor".to_string());
    }
    let root = PathBuf::from(PAYLOAD_ROOT);
    crate::windows_security::ensure_secure_directory(&root)?;
    let target = payload_dir(vendor);
    let target_text = target.to_string_lossy().into_owned();
    const VERIFY_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
$root = Get-Item -LiteralPath $env:GUARDIAN_PAYLOAD_TARGET -Force
if (-not $root.PSIsContainer -or (($root.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
    throw 'BIOS payload target is not a safe directory'
}
$codeExtensions = @('.exe', '.dll', '.sys', '.ps1', '.psm1', '.psd1')
foreach ($directory in Get-ChildItem -LiteralPath $root.FullName -Recurse -Directory -Force) {
    if (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "BIOS payload contains a reparse point: $($directory.FullName)"
    }
}
foreach ($file in Get-ChildItem -LiteralPath $root.FullName -Recurse -File) {
    if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "BIOS payload contains a reparse point: $($file.FullName)"
    }
    if ($codeExtensions -contains $file.Extension.ToLowerInvariant()) {
        $signature = Get-AuthenticodeSignature -LiteralPath $file.FullName
        if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
            throw "unsigned or invalid payload code: $($file.FullName) ($($signature.Status))"
        }
    }
}
"#;
    let output = crate::windows_security::run_encoded_powershell(
        VERIFY_SCRIPT,
        &[("GUARDIAN_PAYLOAD_TARGET", &target_text)],
    )?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "BIOS payload verification failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

pub fn run_vendor_audit(
    oem: &str,
    model: Option<String>,
    interface: Option<String>,
) -> Result<HardwareReceipt, String> {
    let mut receipt = HardwareReceipt::new("windows", oem, model, interface);
    receipt.vendor_tool = json!({
        "name": receipt.interface.clone().unwrap_or_else(|| "vendor-cli".to_string()),
        "path": payload_dir(oem).display().to_string(),
        "present": payload_present(oem),
    });

    if !payload_present(oem) {
        receipt.supervisor_password.error = Some(format!(
            "Vendor payload for {oem} is not staged. Download from Guardian server first."
        ));
        receipt.usb_boot_disabled.error = receipt.supervisor_password.error.clone();
        receipt.secure_boot_enabled.error = receipt.supervisor_password.error.clone();
        receipt.finalize();
        return Ok(receipt);
    }
    validate_payload(oem)?;

    match oem {
        "dell" => audit_dell(&mut receipt)?,
        "hp" => audit_hp(&mut receipt)?,
        "lenovo" => audit_lenovo(&mut receipt)?,
        "surface" => audit_surface(&mut receipt)?,
        _ => return Err(format!("Unsupported OEM for Windows audit: {oem}")),
    }

    receipt.finalize();
    Ok(receipt)
}

pub fn run_vendor_apply(
    oem: &str,
    model: Option<String>,
    interface: Option<String>,
    force_reset_password: bool,
) -> Result<(HardwareReceipt, Option<String>), String> {
    if !payload_present(oem) {
        return Err(format!(
            "Vendor payload for {oem} is not staged under {PAYLOAD_ROOT}"
        ));
    }
    validate_payload(oem)?;

    let password = password::generate_supervisor_password(16);
    let mut receipt = HardwareReceipt::new("windows", oem, model, interface);
    receipt.vendor_tool = json!({
        "name": receipt.interface.clone().unwrap_or_else(|| "vendor-cli".to_string()),
        "path": payload_dir(oem).display().to_string(),
        "present": true,
    });

    let apply_result = match oem {
        "dell" => apply_dell(&password, force_reset_password),
        "hp" => apply_hp(&password, force_reset_password),
        "lenovo" => apply_lenovo(&password, force_reset_password),
        "surface" => apply_surface(&password, force_reset_password),
        _ => Err(format!("Unsupported OEM for Windows apply: {oem}")),
    };

    match apply_result {
        Ok(()) => {
            receipt.supervisor_password.applied = true;
            receipt.supervisor_password.actual = json!("set");
            let audited = run_vendor_audit(oem, receipt.model.clone(), receipt.interface.clone())?;
            let escrow = Some(password);
            Ok((audited, escrow))
        }
        Err(message) => {
            receipt.supervisor_password.applied = false;
            receipt.supervisor_password.error = Some(message);
            receipt.finalize();
            Ok((receipt, None))
        }
    }
}

fn run_powershell(script: &str, environment: &[(&str, &str)]) -> Result<String, String> {
    let output = crate::windows_security::run_encoded_powershell(script, environment)?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn audit_dell(receipt: &mut HardwareReceipt) -> Result<(), String> {
    let cctk = payload_dir("dell").join("cctk.exe");
    if !cctk.is_file() {
        return Err("Dell CCTK executable not found in staged payload".to_string());
    }
    let secure_boot = Command::new(&cctk)
        .args(["--secureboot", "--val"])
        .output()
        .map_err(|error| format!("Failed to query Dell Secure Boot: {error}"))?;
    let stdout = String::from_utf8_lossy(&secure_boot.stdout);
    receipt.secure_boot_enabled.actual = json!(stdout.contains("Enabled"));
    receipt.secure_boot_enabled.applied = stdout.contains("Enabled");
    Ok(())
}

fn apply_dell(password: &str, _force_reset_password: bool) -> Result<(), String> {
    let cctk = payload_dir("dell").join("cctk.exe");
    if !cctk.is_file() {
        return Err("Dell CCTK executable not found in staged payload".to_string());
    }
    let status = Command::new(&cctk)
        .args(["--setuppwd", password])
        .status()
        .map_err(|error| format!("Failed to set Dell supervisor password: {error}"))?;
    if !status.success() {
        return Err("Dell CCTK rejected supervisor password change".to_string());
    }
    let _ = Command::new(&cctk)
        .args(["--secureboot", "enabled"])
        .status();
    Ok(())
}

fn audit_hp(receipt: &mut HardwareReceipt) -> Result<(), String> {
    let script = r#"
$module = Join-Path $env:GUARDIAN_PAYLOAD_DIR 'HP.ClientManagementScriptLibrary.dll'
if (-not (Test-Path $module)) { throw "HP CMSL module not found" }
Import-Module $module
$boot = Get-HPBIOSSettingValue -Name 'Secure Boot'
Write-Output $boot
"#;
    let payload = payload_dir("hp").to_string_lossy().into_owned();
    let stdout = run_powershell(script, &[("GUARDIAN_PAYLOAD_DIR", &payload)])?;
    receipt.secure_boot_enabled.actual = json!(stdout.to_ascii_lowercase().contains("enable"));
    receipt.secure_boot_enabled.applied = stdout.to_ascii_lowercase().contains("enable");
    Ok(())
}

fn apply_hp(password: &str, _force_reset_password: bool) -> Result<(), String> {
    let script = r#"
$module = Join-Path $env:GUARDIAN_PAYLOAD_DIR 'HP.ClientManagementScriptLibrary.dll'
if (-not (Test-Path $module)) { throw "HP CMSL module not found" }
Import-Module $module
Set-HPBIOSSettingValue -Name 'Setup Password' -Value $env:GUARDIAN_BIOS_PASSWORD
Set-HPBIOSSettingValue -Name 'Secure Boot' -Value 'Enable'
"#;
    let payload = payload_dir("hp").to_string_lossy().into_owned();
    run_powershell(
        script,
        &[
            ("GUARDIAN_PAYLOAD_DIR", &payload),
            ("GUARDIAN_BIOS_PASSWORD", password),
        ],
    )
    .map(|_| ())
}

fn audit_lenovo(receipt: &mut HardwareReceipt) -> Result<(), String> {
    let script = r#"
$boot = (Get-CimInstance -Namespace root/wmi -ClassName Lenovo_BiosSetting -Filter "Name='Secure Boot'" -ErrorAction SilentlyContinue).CurrentSetting
Write-Output $boot
"#;
    let stdout = run_powershell(script, &[]).unwrap_or_default();
    receipt.secure_boot_enabled.actual = json!(stdout.to_ascii_lowercase().contains("enable"));
    receipt.secure_boot_enabled.applied = stdout.to_ascii_lowercase().contains("enable");
    Ok(())
}

fn apply_lenovo(password: &str, _force_reset_password: bool) -> Result<(), String> {
    let script = r#"
$password = $env:GUARDIAN_BIOS_PASSWORD
$setter = Get-CimInstance -Namespace root/wmi -ClassName Lenovo_SetBiosSetting -ErrorAction Stop
Invoke-CimMethod -InputObject $setter -MethodName SetBiosSetting -Arguments @{ Parameter = "Password,$password,ascii,us" } | Out-Null
Invoke-CimMethod -InputObject $setter -MethodName SetBiosSetting -Arguments @{ Parameter = "Secure Boot,Enable" } | Out-Null
"#;
    run_powershell(
        script,
        &[("GUARDIAN_BIOS_PASSWORD", password)],
    )
    .map(|_| ())
}

fn audit_surface(receipt: &mut HardwareReceipt) -> Result<(), String> {
    let script = r#"
$module = Join-Path $env:GUARDIAN_PAYLOAD_DIR 'SurfaceEnterpriseManagementMode.psd1'
if (-not (Test-Path $module)) { throw "Surface SEMM module not found" }
Import-Module $module
Write-Output 'surface-audit-ok'
"#;
    let payload = payload_dir("surface").to_string_lossy().into_owned();
    run_powershell(script, &[("GUARDIAN_PAYLOAD_DIR", &payload)])?;
    receipt.secure_boot_enabled.actual = json!("unknown");
    Ok(())
}

fn apply_surface(password: &str, _force_reset_password: bool) -> Result<(), String> {
    let script = r#"
$module = Join-Path $env:GUARDIAN_PAYLOAD_DIR 'SurfaceEnterpriseManagementMode.psd1'
if (-not (Test-Path $module)) { throw "Surface SEMM module not found" }
Import-Module $module
Write-Output 'surface-apply'
"#;
    let payload = payload_dir("surface").to_string_lossy().into_owned();
    run_powershell(
        script,
        &[
            ("GUARDIAN_PAYLOAD_DIR", &payload),
            ("GUARDIAN_BIOS_PASSWORD", password),
        ],
    )
    .map(|_| ())
}

pub fn stage_payload_from_server(
    vendor: &str,
    server_url: &str,
    agent_token: &str,
) -> Result<(), String> {
    if !matches!(vendor, "dell" | "hp" | "lenovo" | "surface") {
        return Err("refusing unsupported BIOS payload vendor".to_string());
    }
    let mut base = server_url
        .trim_end_matches("/ws")
        .trim_end_matches('/')
        .to_string();
    if base.starts_with("wss://") {
        base.replace_range(..6, "https://");
    } else if base.starts_with("ws://") {
        base.replace_range(..5, "http://");
    }
    let url = format!("{base}/api/agent/bios-payloads/{vendor}");
    let parsed = reqwest::Url::parse(&url)
        .map_err(|error| format!("invalid BIOS payload URL: {error}"))?;
    if parsed.scheme() != "https" {
        return Err("BIOS payload download requires HTTPS".to_string());
    }

    let root = PathBuf::from(PAYLOAD_ROOT);
    crate::windows_security::ensure_secure_directory(&root)?;
    let target = payload_dir(vendor);
    let root_text = root.to_string_lossy().into_owned();
    let target_text = target.to_string_lossy().into_owned();
    const STAGE_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
$headers = @{ Authorization = "Bearer $env:GUARDIAN_AGENT_TOKEN" }
$work = Join-Path $env:GUARDIAN_PAYLOAD_ROOT ([Guid]::NewGuid().ToString('N'))
$archive = "$work.zip"
$staging = "$work.extract"
try {
    Invoke-WebRequest -UseBasicParsing -Uri $env:GUARDIAN_PAYLOAD_URL -Headers $headers -OutFile $archive
    Invoke-WebRequest -UseBasicParsing -Uri ($env:GUARDIAN_PAYLOAD_URL + '.sha256') -Headers $headers -OutFile ($archive + '.sha256')
    $expected = ((Get-Content -LiteralPath ($archive + '.sha256') -Raw).Trim() -split '\s+')[0]
    if ($expected -notmatch '^[0-9a-fA-F]{64}$') { throw 'invalid BIOS payload checksum sidecar' }
    $actual = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash
    if ($actual -ine $expected) { throw 'BIOS payload checksum mismatch' }

    New-Item -ItemType Directory -Path $staging | Out-Null
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead($archive)
    try {
        $prefix = [IO.Path]::GetFullPath($staging).TrimEnd('\') + '\'
        foreach ($entry in $zip.Entries) {
            $candidate = [IO.Path]::GetFullPath((Join-Path $staging $entry.FullName))
            if (-not $candidate.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
                throw "archive entry escapes destination: $($entry.FullName)"
            }
        }
    } finally {
        $zip.Dispose()
    }
    [IO.Compression.ZipFile]::ExtractToDirectory($archive, $staging)

    $codeExtensions = @('.exe', '.dll', '.sys', '.ps1', '.psm1', '.psd1')
    foreach ($file in Get-ChildItem -LiteralPath $staging -Recurse -File) {
        if ($codeExtensions -contains $file.Extension.ToLowerInvariant()) {
            $signature = Get-AuthenticodeSignature -LiteralPath $file.FullName
            if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
                throw "unsigned or invalid payload code: $($file.FullName) ($($signature.Status))"
            }
        }
    }
    if (Test-Path -LiteralPath $env:GUARDIAN_PAYLOAD_TARGET) {
        $existing = Get-Item -LiteralPath $env:GUARDIAN_PAYLOAD_TARGET -Force
        if (($existing.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'refusing reparse-point BIOS payload target'
        }
        Remove-Item -LiteralPath $existing.FullName -Recurse -Force
    }
    Move-Item -LiteralPath $staging -Destination $env:GUARDIAN_PAYLOAD_TARGET
} finally {
    Remove-Item -LiteralPath $archive,($archive + '.sha256'),$work,$staging -Recurse -Force -ErrorAction SilentlyContinue
}
"#;
    let output = crate::windows_security::run_encoded_powershell(
        STAGE_SCRIPT,
        &[
            ("GUARDIAN_AGENT_TOKEN", agent_token),
            ("GUARDIAN_PAYLOAD_URL", &url),
            ("GUARDIAN_PAYLOAD_ROOT", &root_text),
            ("GUARDIAN_PAYLOAD_TARGET", &target_text),
        ],
    )?;
    if !output.status.success() {
        return Err(format!(
            "secure BIOS payload staging failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    if !payload_dir(vendor).is_dir() {
        return Err("Payload directory missing after staging".to_string());
    }
    Ok(())
}

pub fn ensure_payload_staged(oem: &str, server_url: Option<&str>, agent_token: Option<&str>) {
    if payload_present(oem) {
        return;
    }
    if let (Some(server_url), Some(agent_token)) = (server_url, agent_token) {
        let _ = stage_payload_from_server(oem, server_url, agent_token);
    }
}

pub fn read_agent_config() -> (Option<String>, Option<String>) {
    let config_path = PathBuf::from(r"C:\ProgramData\Guardian\config.json");
    let Ok(raw) = fs::read_to_string(config_path) else {
        return (None, None);
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return (None, None);
    };
    let server_url = value
        .get("server_url")
        .and_then(|entry| entry.as_str())
        .map(str::to_string);
    let agent_token = value
        .get("agent_token")
        .and_then(|entry| entry.as_str())
        .map(str::to_string);
    (server_url, agent_token)
}

pub fn run_detect() -> super::compliance::OemDetectResult {
    detect()
}

pub fn run_audit() -> Result<HardwareReceipt, String> {
    let detect = detect();
    if !detect.supported {
        return Err(detect
            .message
            .unwrap_or_else(|| "Hardware baseline is not supported on this device".to_string()));
    }
    let (server_url, agent_token) = read_agent_config();
    ensure_payload_staged(&detect.oem, server_url.as_deref(), agent_token.as_deref());
    run_vendor_audit(&detect.oem, detect.model.clone(), detect.interface.clone())
}

pub fn run_apply(force_reset_password: bool) -> Result<(HardwareReceipt, Option<String>), String> {
    let detect = detect();
    if !detect.supported {
        return Err(detect
            .message
            .unwrap_or_else(|| "Hardware baseline is not supported on this device".to_string()));
    }
    let (server_url, agent_token) = read_agent_config();
    ensure_payload_staged(&detect.oem, server_url.as_deref(), agent_token.as_deref());
    run_vendor_apply(
        &detect.oem,
        detect.model.clone(),
        detect.interface.clone(),
        force_reset_password,
    )
}
