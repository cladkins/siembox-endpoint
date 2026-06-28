# install.ps1 - SIEMBox Endpoint agent installer for Windows (Windows Service).
#
# Run in an ELEVATED PowerShell. Installs the agent, fetches grype + osquery
# from their official release URLs (no winget/choco dependency), seeds a config
# template, and registers the Windows service. This is the recommended way to
# install on Windows for testing; the .msi installs the agent + service but not
# the dependencies.
#
#   powershell -ExecutionPolicy Bypass -File packaging\windows\install.ps1
#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$OsqueryVersion = '5.23.0'
$ConfDir    = Join-Path $env:ProgramData 'SIEMBox\agent'
$ConfFile   = Join-Path $ConfDir 'agent.json'
$InstallDir = Join-Path $env:ProgramFiles 'SIEMBox'
$InstallBin = Join-Path $InstallDir 'siembox-agent.exe'

New-Item -ItemType Directory -Force -Path $ConfDir, $InstallDir | Out-Null

# Place the agent binary (from the release archive next to this script).
$src = Join-Path $PSScriptRoot '..\..\siembox-agent.exe'
if (-not (Test-Path $src)) { $src = Join-Path $PSScriptRoot 'siembox-agent.exe' }
if (Test-Path $src) {
    Copy-Item -Force $src $InstallBin
} elseif (-not (Test-Path $InstallBin)) {
    throw "siembox-agent.exe not found next to this script; run from the extracted release archive."
}

# Config template (don't clobber an existing config).
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

# grype.exe -> Program Files\SIEMBox (the agent searches there). Download the
# latest official Windows zip from GitHub releases.
if (-not (Test-Path (Join-Path $InstallDir 'grype.exe'))) {
    Write-Host "Installing grype..."
    try {
        $rel   = Invoke-RestMethod -UseBasicParsing -Uri 'https://api.github.com/repos/anchore/grype/releases/latest'
        $asset = $rel.assets | Where-Object { $_.name -like '*_windows_amd64.zip' } | Select-Object -First 1
        if (-not $asset) { throw "no windows_amd64.zip asset in latest grype release" }
        $zip = Join-Path $env:TEMP $asset.name
        Invoke-WebRequest -UseBasicParsing -Uri $asset.browser_download_url -OutFile $zip
        $ex = Join-Path $env:TEMP 'grype-extract'
        Remove-Item -Recurse -Force $ex -ErrorAction SilentlyContinue
        Expand-Archive -Path $zip -DestinationPath $ex -Force
        Copy-Item -Force (Join-Path $ex 'grype.exe') (Join-Path $InstallDir 'grype.exe')
    } catch {
        Write-Warning "grype install failed: $_  (vulnerability scanning disabled until installed)"
    }
}

# osquery -> official Windows MSI (installs osqueryi/osqueryd to
# C:\Program Files\osquery, which the agent searches).
if (-not (Test-Path 'C:\Program Files\osquery\osqueryi.exe')) {
    Write-Host "Installing osquery $OsqueryVersion..."
    try {
        $msi = Join-Path $env:TEMP "osquery-$OsqueryVersion.msi"
        Invoke-WebRequest -UseBasicParsing -Uri "https://pkg.osquery.io/windows/osquery-$OsqueryVersion.msi" -OutFile $msi
        Start-Process msiexec.exe -ArgumentList "/i `"$msi`" /quiet /norestart" -Wait
    } catch {
        Write-Warning "osquery install failed: $_  (detection disabled until installed)"
    }
}

# Register the Windows service (start manually after configuring agent.json).
& $InstallBin -dir "$ConfDir" install

Write-Host ""
Write-Host "SIEMBox Endpoint installed. Next:"
Write-Host "  1. Edit $ConfFile (server_url + enrollment_token) when your server is ready."
Write-Host "  2. Test now (no server needed):"
Write-Host "       & '$InstallBin' scan      # vulnerability findings (JSON)"
Write-Host "       & '$InstallBin' check     # detection check (JSON)"
Write-Host "  3. Start the background service:"
Write-Host "       & '$InstallBin' -dir '$ConfDir' start"
