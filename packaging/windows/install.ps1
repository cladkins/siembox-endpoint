# install.ps1 - SIEMBox EDR agent installer for Windows (Windows Service).
#
# NOTE: authored against Windows conventions but NOT yet validated on a real
# Windows host. Test on a recent Windows build before relying on it.
#
# Run in an elevated PowerShell. Installs osquery + grype (via winget/choco if
# available), places the agent, seeds config, and registers a Windows service
# via `siembox-agent install`.
#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'

$ConfDir  = Join-Path $env:ProgramData 'SIEMBox\agent'
$ConfFile = Join-Path $ConfDir 'agent.json'
$InstallDir = Join-Path $env:ProgramFiles 'SIEMBox'
$InstallBin = Join-Path $InstallDir 'siembox-agent.exe'

New-Item -ItemType Directory -Force -Path $ConfDir, $InstallDir | Out-Null

# Expect siembox-agent.exe alongside this script (from the release archive).
$src = Join-Path $PSScriptRoot '..\..\siembox-agent.exe'
if (-not (Test-Path $src)) { $src = Join-Path $PSScriptRoot 'siembox-agent.exe' }
if (Test-Path $src) { Copy-Item -Force $src $InstallBin }

if (-not (Test-Path $ConfFile)) {
@'
{
  "server_url": "https://CHANGE-ME.siembox.lan:8421",
  "enrollment_token": "PASTE-ENROLLMENT-TOKEN-FROM-SIEMBOX-UI",
  "ca_cert_path": "",
  "insecure_skip_verify": false
}
'@ | Set-Content -Path $ConfFile -Encoding utf8
}

# Dependencies via winget (fall back to choco).
function Install-Dep($wingetId, $chocoId, $probe) {
    if (Get-Command $probe -ErrorAction SilentlyContinue) { return }
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        winget install --silent --accept-source-agreements --accept-package-agreements --id $wingetId
    } elseif (Get-Command choco -ErrorAction SilentlyContinue) {
        choco install -y $chocoId
    } else {
        Write-Warning "Install $probe manually (no winget/choco found)."
    }
}
Install-Dep 'Anchore.Grype' 'grype' 'grype'
Install-Dep 'osquery.osquery' 'osquery' 'osqueryd'

& $InstallBin -dir "$ConfDir" install
Write-Host "siembox-agent: edit $ConfFile, then: siembox-agent -dir `"$ConfDir`" start"
