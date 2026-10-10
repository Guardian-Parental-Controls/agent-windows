param(
    [Parameter(Mandatory = $true)]
    [string]$Version,

    [string]$OutputDir = "dist"
)

$ErrorActionPreference = "Stop"

$msiName = "guardian-agent-x86_64-pc-windows-msvc.msi"
$staging = Join-Path $OutputDir "staging"
New-Item -ItemType Directory -Force -Path $OutputDir, $staging | Out-Null

Copy-Item "target\release\guardian-agent.exe" $staging
Copy-Item "overlay_resources\blockedv2.html" $staging

$wixCandidates = @(
    "${env:ProgramFiles(x86)}\WiX Toolset v3.14\bin",
    "${env:ProgramFiles(x86)}\WiX Toolset v3.11\bin"
)
$wixBin = $wixCandidates | Where-Object { Test-Path (Join-Path $_ "candle.exe") } | Select-Object -First 1
if (-not $wixBin) {
    throw "WiX Toolset not found. Install WiX 3.11+ before packaging the MSI."
}

$wixObj = Join-Path $OutputDir "guardian-agent.wixobj"
& (Join-Path $wixBin "candle.exe") `
    -dVersion=$Version `
    -dSourceDir=$staging `
    "guardian-agent.wxs" `
    -out $wixObj
& (Join-Path $wixBin "light.exe") `
    -out (Join-Path $OutputDir $msiName) `
    $wixObj

$msiPath = Join-Path $OutputDir $msiName
$hash = (Get-FileHash -Algorithm SHA256 -Path $msiPath).Hash.ToLower()
Set-Content -Path "$msiPath.sha256" -Value $hash -NoNewline
