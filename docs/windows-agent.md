# Windows Agent

Windows Agent is designed as the same PortHub Agent protocol with a native Windows service wrapper.

## Current Stage

- Builds from the same Go source as the Linux Agent.
- Supports service installation through `deploy/windows/install-porthub-agent.ps1`.
- Collects native Windows physical memory, pagefile and system drive capacity through Windows API calls.
- Collects Windows interface byte counters through IP Helper `GetIfEntry`.
- Discovers Windows TCP/UDP IPv4 and IPv6 listeners through IP Helper extended owner PID tables.
- Exposes the same read-only HTTP endpoints:
  - `GET /api/agent/status`
  - `GET /api/agent/discovery`
  - `GET /api/agent/tasks/allowlist`
  - `POST /api/agent/tasks/validate`
- Does not execute arbitrary shell commands.
- Controlled task execution is intentionally disabled in the first Windows build. The endpoint validates task name, timeout, bounded arguments and required signature, then returns `execute=false`.

## Build

```bash
make build-windows-agent
```

Output:

```text
bin/porthub-agent-windows-amd64.exe
```

## Install

Copy the Windows agent binary to the same directory as the PowerShell scripts and rename it:

```powershell
Copy-Item .\porthub-agent-windows-amd64.exe .\porthub-agent.exe
.\install-porthub-agent.ps1
```

Default paths:

- Binary: `C:\Program Files\PortHub\porthub-agent.exe`
- Config: `C:\ProgramData\PortHub\agent.json`
- Service: `PortHubAgent`

## Security Model

- The Windows service listens on `127.0.0.1:9731` by default.
- Task names must be allowlisted.
- Task arguments are length-limited and character-restricted.
- A task signature is required before a task can pass validation.
- This stage has no command runner and no shell execution path.

## Future Work

- Windows CPU load history.
- Runtime smoke testing on a real Windows host.
- Signed task execution for a small allowlist of probes and service inventory commands.
- Automatic update channel with signed releases.
