//! Windows privilege-boundary helpers.
//!
//! Paths below ProgramData are created by LocalSystem and must never be
//! redirected through a junction/symlink controlled by an unprivileged user.

use std::path::{Path, PathBuf};

pub const GUARDIAN_DATA_DIR: &str = r"C:\ProgramData\Guardian";

#[cfg(target_os = "windows")]
pub struct PipeSecurity {
    attributes: windows_sys::Win32::Security::SECURITY_ATTRIBUTES,
    descriptor: *mut core::ffi::c_void,
}

#[cfg(target_os = "windows")]
impl PipeSecurity {
    /// Allows LocalSystem/Administrators full access and authenticated local
    /// users read/write access. Anonymous and network logons receive no ACE.
    pub fn authenticated_users() -> Result<Self, String> {
        use windows_sys::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };

        let sddl: Vec<u16> = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut descriptor = std::ptr::null_mut();
        let converted = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        };
        if converted == 0 || descriptor.is_null() {
            return Err(format!(
                "failed to build named-pipe security descriptor: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(Self {
            attributes: windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<windows_sys::Win32::Security::SECURITY_ATTRIBUTES>()
                    as u32,
                lpSecurityDescriptor: descriptor,
                bInheritHandle: 0,
            },
            descriptor,
        })
    }

    pub fn attributes_mut_ptr(
        &mut self,
    ) -> *mut windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
        &mut self.attributes
    }
}

#[cfg(target_os = "windows")]
// The descriptor pointer is owned by this value, and LocalFree is thread-safe.
unsafe impl Send for PipeSecurity {}

#[cfg(target_os = "windows")]
impl Drop for PipeSecurity {
    fn drop(&mut self) {
        if !self.descriptor.is_null() {
            unsafe {
                windows_sys::Win32::Foundation::LocalFree(self.descriptor);
            }
        }
    }
}

#[cfg(target_os = "windows")]
fn is_reparse_point(path: &Path) -> Result<bool, String> {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("failed to inspect {}: {error}", path.display()))?;
    Ok(metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0)
}

#[cfg(target_os = "windows")]
fn reject_reparse_components(path: &Path) -> Result<(), String> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if current.exists() && is_reparse_point(&current)? {
            return Err(format!(
                "refusing privileged path containing a reparse point: {}",
                current.display()
            ));
        }
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn reject_reparse_descendants(path: &Path) -> Result<(), String> {
    for entry in std::fs::read_dir(path)
        .map_err(|error| format!("failed to enumerate {}: {error}", path.display()))?
    {
        let entry =
            entry.map_err(|error| format!("failed to enumerate {}: {error}", path.display()))?;
        let child = entry.path();
        if is_reparse_point(&child)? {
            return Err(format!(
                "refusing Guardian data containing a reparse point: {}",
                child.display()
            ));
        }
        if entry
            .file_type()
            .map_err(|error| format!("failed to inspect {}: {error}", child.display()))?
            .is_dir()
        {
            reject_reparse_descendants(&child)?;
        }
    }
    Ok(())
}

/// Creates a LocalSystem/Administrators-only directory and rejects junctions,
/// symlinks, and other reparse points both before and after creation.
#[cfg(target_os = "windows")]
pub fn ensure_secure_directory(path: &Path) -> Result<(), String> {
    let root = Path::new(GUARDIAN_DATA_DIR);
    if path != root && !path.starts_with(root) {
        return Err(format!(
            "refusing to secure path outside {}: {}",
            root.display(),
            path.display()
        ));
    }

    reject_reparse_components(path)?;
    std::fs::create_dir_all(path)
        .map_err(|error| format!("failed to create {}: {error}", path.display()))?;
    reject_reparse_components(path)?;
    let path_text = path.to_string_lossy().to_string();
    let _ = std::process::Command::new("takeown.exe")
        .args(["/f", &path_text, "/a", "/r", "/d", "y"])
        .status();
    if !std::fs::symlink_metadata(path)
        .map_err(|error| format!("failed to inspect {}: {error}", path.display()))?
        .is_dir()
    {
        return Err(format!("privileged path is not a directory: {}", path.display()));
    }

    let output = std::process::Command::new("icacls.exe")
        .arg(path)
        .args([
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F",
            "/remove:g",
            "*S-1-5-32-545",
            "*S-1-5-11",
            "*S-1-1-0",
        ])
        .output()
        .map_err(|error| format!("failed to launch icacls.exe: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "failed to secure {}: {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    reject_reparse_components(path)
}

#[cfg(not(target_os = "windows"))]
pub fn ensure_secure_directory(path: &Path) -> Result<(), String> {
    std::fs::create_dir_all(path)
        .map_err(|error| format!("failed to create {}: {error}", path.display()))
}

#[cfg(target_os = "windows")]
pub fn ensure_guardian_data_dir() -> Result<PathBuf, String> {
    let path = PathBuf::from(GUARDIAN_DATA_DIR);
    ensure_secure_directory(&path)?;
    reject_reparse_descendants(&path)?;
    Ok(path)
}

#[cfg(not(target_os = "windows"))]
pub fn ensure_guardian_data_dir() -> Result<PathBuf, String> {
    Err("Guardian ProgramData storage is only available on Windows".to_string())
}

#[cfg(target_os = "windows")]
pub fn write_install_config(server_url: &str, registration_token: &str) -> Result<(), String> {
    use std::io::Write;

    let parsed = reqwest::Url::parse(server_url)
        .map_err(|error| format!("invalid Guardian server URL: {error}"))?;
    let secure_transport = matches!(parsed.scheme(), "wss" | "https");
    let loopback = parsed.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    });
    if !secure_transport && !(matches!(parsed.scheme(), "ws" | "http") && loopback) {
        return Err("server URL must use WSS/HTTPS (plain transport is allowed only on loopback)"
            .to_string());
    }
    if server_url.chars().any(char::is_control) || registration_token.chars().any(char::is_control)
    {
        return Err("configuration values may not contain control characters".to_string());
    }
    if server_url.len() > 2048 || registration_token.len() > 8192 {
        return Err("configuration value exceeds the permitted length".to_string());
    }

    let directory = ensure_guardian_data_dir()?;
    let path = directory.join("config.json");
    if path.exists() && is_reparse_point(&path)? {
        return Err("refusing to replace reparse-point config.json".to_string());
    }
    let value = serde_json::json!({
        "server_url": server_url,
        "registration_token": registration_token,
    });
    let encoded = serde_json::to_vec_pretty(&value)
        .map_err(|error| format!("failed to serialize configuration: {error}"))?;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&path)
        .map_err(|error| format!("failed to open {}: {error}", path.display()))?;
    file.write_all(&encoded)
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("failed to write {}: {error}", path.display()))
}

/// Runs a constant PowerShell program via UTF-16LE `-EncodedCommand`. Dynamic
/// values must be passed through environment variables, never script source.
#[cfg(target_os = "windows")]
pub fn run_encoded_powershell(
    script: &str,
    environment: &[(&str, &str)],
) -> Result<std::process::Output, String> {
    use base64::Engine;

    let utf16: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let encoded = base64::engine::general_purpose::STANDARD.encode(utf16);
    std::process::Command::new("powershell.exe")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            &encoded,
        ])
        .envs(environment.iter().copied())
        .output()
        .map_err(|error| format!("failed to execute PowerShell: {error}"))
}

#[cfg(target_os = "windows")]
pub fn verify_authenticode(path: &Path) -> Result<(), String> {
    const SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
$item = Get-Item -LiteralPath $env:GUARDIAN_VERIFY_PATH -Force
if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'refusing to verify a reparse point'
}
$signature = Get-AuthenticodeSignature -LiteralPath $item.FullName
if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
    throw "invalid Authenticode signature: $($signature.Status)"
}
"#;
    let path_text = path
        .to_str()
        .ok_or_else(|| "signature path is not valid Unicode".to_string())?;
    let output = run_encoded_powershell(SCRIPT, &[("GUARDIAN_VERIFY_PATH", path_text)])?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "publisher verification failed for {}: {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::GUARDIAN_DATA_DIR;

    #[test]
    fn guardian_data_directory_is_fixed_machine_wide_path() {
        assert_eq!(GUARDIAN_DATA_DIR, r"C:\ProgramData\Guardian");
    }
}
