# build-msi.ps1 - build a Windows .msi installer for the SIEMBox EDR agent.
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
$ld = "-s -w -X github.com/cladkins/siembox-edr/internal/version.Version=$Version"
go build -ldflags $ld -o build\siembox-agent.exe .\cmd\siembox-agent

if (-not (Get-Command wix -ErrorAction SilentlyContinue)) {
    Write-Host "installing WiX CLI..."
    dotnet tool install --global wix
    $env:PATH += ";$env:USERPROFILE\.dotnet\tools"
}

$out = "dist\siembox-agent-$Version-windows-amd64.msi"
Write-Host "building $out ..."
wix build packaging\windows\siembox-agent.wxs -d Version=$Version -d BinDir=build -o $out
Write-Host "built $out"
