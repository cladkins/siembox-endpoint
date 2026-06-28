# build-msi.ps1 - build a Windows .msi installer for the SIEMBox Endpoint agent.
#
# Must run on Windows with the Go toolchain and .NET SDK. Installs the WiX CLI
# if missing, builds the agent, and produces the MSI under dist\.
#
#   pwsh packaging\windows\build-msi.ps1 -Version 1.2.3
param([string]$Version = "0.0.0")
$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path "$PSScriptRoot\..\..").Path
Set-Location $repoRoot
New-Item -ItemType Directory -Force -Path build, dist | Out-Null

Write-Host "building siembox-agent.exe (windows/amd64)..."
$env:GOOS = "windows"; $env:GOARCH = "amd64"; $env:CGO_ENABLED = "0"
$ld = "-s -w -X github.com/cladkins/siembox-endpoint/internal/version.Version=$Version"
go build -ldflags $ld -o build\siembox-agent.exe .\cmd\siembox-agent

if (-not (Get-Command wix -ErrorAction SilentlyContinue)) {
    Write-Host "installing WiX CLI..."
    # Pin to v5: WiX v6/v7 require accepting the Open Source Maintenance Fee
    # (OSMF) EULA, which blocks non-interactive CI builds. v5 uses the same
    # v4 schema namespace this .wxs targets.
    dotnet tool install --global wix --version 5.0.2
    $env:PATH += ";$env:USERPROFILE\.dotnet\tools"
}

$out = "dist\siembox-agent-$Version-windows-amd64.msi"
Write-Host "building $out ..."
wix build packaging\windows\siembox-agent.wxs -d Version=$Version -d BinDir=build -o $out
if ($LASTEXITCODE -ne 0) { throw "wix build failed with exit code $LASTEXITCODE" }
Write-Host "built $out"
