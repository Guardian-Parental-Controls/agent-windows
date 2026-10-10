# Package guardian-agent Windows MSI for release.
# Requires: cargo build --release, WiX 3.x (candle.exe + light.exe) on PATH.
param(
    [Parameter(Mandatory = $true)]
    [string]$Version,
    [Parameter(Mandatory = $true)]
    [string]$OutDir
)

$ErrorActionPreference = "Stop"

$stage = Join-Path $OutDir "staging"
New-Item -ItemType Directory -Force -Path $stage | Out-Null

$exe = Join-Path $PWD "target\release\guardian-agent.exe"
if (-not (Test-Path $exe)) {
    throw "Release binary not found at $exe"
}

Copy-Item $exe (Join-Path $stage "guardian-agent.exe")
Copy-Item (Join-Path $PWD "overlay_resources\blockedv2.html") (Join-Path $stage "blockedv2.html")

$wixObj = Join-Path $OutDir "guardian-agent.wixobj"
$msiName = "guardian-agent-x86_64-pc-windows-msvc.msi"
$msiPath = Join-Path $OutDir $msiName

& candle.exe "-dVersion=$Version" "-dSourceDir=$stage" guardian-agent.wxs -out $wixObj
& light.exe -ext WixUIExtension $wixObj -out $msiPath

$hash = (Get-FileHash -Algorithm SHA256 -Path $msiPath).Hash.ToLower()
Set-Content -Path "$msiPath.sha256" -Value $hash -NoNewline
Write-Host "Packaged $msiPath"
