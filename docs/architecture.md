# AppElevator Architecture

## Overview
AppElevator is a Windows 10/11 service that listens for a specific Event Log entry and, upon receiving it, launches `cmd.exe` in the currently active user session with local admin permissions.

## Goals
- Minimal external dependencies (self-contained .NET publish).
- Event Log trigger via the Application log.
- Visible interactive `cmd.exe` in the active user session.
- Easy install/update via PowerShell.
- Fully automated end-to-end test.

## Components

### Windows Service (C#)
- **Binary**: `AppElevator.Service.exe`
- **Service name**: `AppElevator`
- **Trigger**: Event Log entry (Application log, source `AppElevator`, Event ID `1001`).
- **Service logs**: Event ID `1000` (same source), so service logging never retriggers the launch.
- **Service account**: `LocalSystem` (needed to adjust session tokens).
- **Launch mechanism**: `LogonUser` + `CreateProcessAsUser` to run `cmd.exe` as `localadm` in the active session.

### Installer Script
- **Script**: `scripts/install-service.ps1`
- Builds a self-contained single-file executable.
- Grants the `SeServiceLogonRight` to `localadm`.
- Creates/updates the Windows service to run under `localadm`.
- Ensures the Event Log source exists.
- Stores `localadm` credentials in HKLM for interactive launch.

### Trigger Script
- **Script**: `scripts/trigger-event.ps1`
- Writes the trigger event to the Application log.

### End-to-End Test
- **Script**: `tests/ServiceE2E.ps1`
- Installs/updates the service.
- Triggers the event.
- Confirms `cmd.exe` is started in the active session.

## Event Flow
1. Trigger event is written to Application log.
2. Service receives event via `EventLogWatcher`.
3. Service launches `cmd.exe` in active user session.
4. `cmd.exe` becomes visible to the logged-in user.

## Security Notes
- Service runs under `localadm`, which must be a local administrator.
- The service enables `SeTcbPrivilege`, `SeAssignPrimaryTokenPrivilege`, `SeIncreaseQuotaPrivilege`, and `SeDebugPrivilege` to obtain the active user token and spawn an interactive process.
- The Event Log trigger is restricted by event source and event ID filters.
