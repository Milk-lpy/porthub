param(
  [switch]$RemoveData
)

$ErrorActionPreference = "Stop"

if (Get-Service -Name "PortHubAgent" -ErrorAction SilentlyContinue) {
  Stop-Service -Name "PortHubAgent" -ErrorAction SilentlyContinue
  sc.exe delete PortHubAgent | Out-Null
}

Remove-Item -Force -ErrorAction SilentlyContinue "C:\Program Files\PortHub\porthub-agent.exe"
if ($RemoveData) {
  Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "C:\ProgramData\PortHub"
}
