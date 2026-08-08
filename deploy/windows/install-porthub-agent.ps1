param(
  [string]$InstallDir = "C:\Program Files\PortHub",
  [string]$ConfigPath = "C:\ProgramData\PortHub\agent.json"
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$exeSource = Join-Path $scriptDir "porthub-agent.exe"
$cfgSource = Join-Path $scriptDir "porthub-agent.config.json"

if (!(Test-Path $exeSource)) {
  throw "Missing porthub-agent.exe next to installer"
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $ConfigPath) | Out-Null

Copy-Item -Force $exeSource (Join-Path $InstallDir "porthub-agent.exe")
if (!(Test-Path $ConfigPath) -and (Test-Path $cfgSource)) {
  Copy-Item -Force $cfgSource $ConfigPath
}

$binary = Join-Path $InstallDir "porthub-agent.exe"
$command = "`"$binary`" -config `"$ConfigPath`""

if (Get-Service -Name "PortHubAgent" -ErrorAction SilentlyContinue) {
  Stop-Service -Name "PortHubAgent" -ErrorAction SilentlyContinue
  sc.exe config PortHubAgent binPath= $command | Out-Null
} else {
  New-Service -Name "PortHubAgent" -DisplayName "PortHub Agent" -Description "PortHub Windows node agent" -BinaryPathName $command -StartupType Automatic | Out-Null
}

Start-Service -Name "PortHubAgent"
Get-Service -Name "PortHubAgent"
