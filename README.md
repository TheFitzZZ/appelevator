# AppElevator

Windows 10/11 service that listens for an Event Log trigger and launches `cmd.exe` in the currently active user session using local admin permissions.

## Requirements
- Windows 10/11
- .NET SDK 8.x (for build/publish)
- Local administrator account: `localadm`
- Run scripts in an elevated PowerShell session

## Architecture
See [docs/architecture.md](docs/architecture.md).

## Build
- Self-contained single-file publish to the `publish` folder:
	- `scripts/install-service.ps1` runs `dotnet publish` automatically.

## Install/Update Service
Run as Administrator:
- [scripts/install-service.ps1](scripts/install-service.ps1)

The script:
- Builds the service.
- Grants “Log on as a service” to `localadm`.
- Grants “Allow log on locally” to `localadm`.
- Grants required privileges for interactive launch (`SeTcbPrivilege`, `SeAssignPrimaryTokenPrivilege`, `SeIncreaseQuotaPrivilege`, `SeDebugPrivilege`).
- Creates or updates the service to run as `LocalSystem` (so it can adjust session tokens).
- Ensures the Event Log source exists.
- Stores `localadm` credentials in HKLM for launching `cmd.exe` as `localadm` in the active session.

## Trigger the Service
Run as Administrator:
- [scripts/trigger-event.ps1](scripts/trigger-event.ps1)

This writes the Application log entry (Source `AppElevator`, Event ID `1001`) that triggers the service to launch `cmd.exe`.

## Automated End-to-End Test
Run as Administrator:
- [tests/ServiceE2E.ps1](tests/ServiceE2E.ps1)

The test installs/updates the service, triggers the event, and verifies that `cmd.exe` starts in the active session.

## Notes
- The service listens to the Application log for Source `AppElevator` and Event ID `1001`.
- Service operational logs use Event ID `1000` to avoid self-triggering.
- The launched `cmd.exe` is started with a new console and is visible to the active user.