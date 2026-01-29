# AppElevator Delivery Summary

## Goal
Create a Windows 10/11 service that runs elevated and launches an application (cmd.exe) for the currently active user when triggered via a specific Event Log entry. The launched window must be visible to the active session.

## Final Architecture
- **Service**: Runs as **LocalSystem** to access required privileges (session token manipulation and interactive launch).
- **Trigger**: Application Event Log entry with **Source: AppElevator**, **Event ID: 1001**.
- **Launch**: `LogonUser` + `CreateProcessAsUser` to run **cmd.exe /k** as **localadm** in the **active session**.
- **Visibility**: Uses WinSta0\Default desktop, explicit window-station/desktop ACL updates for localadm, and console show flags.

## Components Delivered
- Service implementation (C#/.NET):
  - [src/Service/Program.cs](../src/Service/Program.cs)
  - [src/Service/InteractiveLaunch.cs](../src/Service/InteractiveLaunch.cs)
- Installer/Updater:
  - [scripts/install-service.ps1](../scripts/install-service.ps1)
- Trigger script:
  - [scripts/trigger-event.ps1](../scripts/trigger-event.ps1)
- Automated end‑to‑end test:
  - [tests/ServiceE2E.ps1](../tests/ServiceE2E.ps1)
- Architecture notes:
  - [docs/architecture.md](architecture.md)

## How It Works (Operational Flow)
1. Service starts and subscribes to Application Event Log for Source `AppElevator`, ID `1001`.
2. Trigger event is written (via PowerShell).
3. Service launches `cmd.exe /k` as **localadm** in the active session.
4. Logging uses **Event ID 1000** to avoid re-trigger loops.

## Installer Actions
The installer performs the following:
- Builds the service and publishes a self‑contained executable.
- Grants required rights to `localadm`:
  - Log on as a service
  - Allow log on locally
  - SeTcbPrivilege
  - SeAssignPrimaryTokenPrivilege
  - SeIncreaseQuotaPrivilege
  - SeDebugPrivilege
- Configures the service to run as **LocalSystem**.
- Stores `localadm` credentials in HKLM for localadm launch.

## Findings & Caveats
1. **Interactive UI for another user requires an active session.**
   - Windows will not reliably display a UI for `localadm` unless `localadm` has an interactive session (console or RDP).
   - Without an active session for `localadm`, the process launches and exits immediately.

2. **Service must run as LocalSystem** to switch tokens/sessions. 
   - Running the service as `localadm` prevents required session token operations.

3. **Event Log self-trigger was fixed.**
   - Service logs use Event ID **1000**, trigger listens to **1001**.

4. **Single-instance guard**
   - The service only launches if no `cmd.exe` is running in the active session.

5. **Credential storage**
   - `localadm` credentials are stored in HKLM to enable non‑interactive launch.
   - This is a security tradeoff that should be reviewed for production.

6. **Visibility vs. Identity**
   - A visible window is guaranteed only when the target user has an active session.
   - SYSTEM can show a visible window in the active session but is not `localadm`.

## What the Customer Should Expect
- If **localadm is logged in**, the service triggers a visible, elevated `cmd.exe` window as `localadm`.
- If **localadm is NOT logged in**, the service logs show a localadm launch attempt, but the process exits immediately (no visible UI).

## Recommended Customer Guidance
- If a visible localadm window is required:
  - **Log in as localadm** (console or RDP), or
  - **Configure autologon** for localadm on the endpoint.

## Trigger Example
- [scripts/trigger-event.ps1](../scripts/trigger-event.ps1)

## Test
- [tests/ServiceE2E.ps1](../tests/ServiceE2E.ps1)

## Summary
The solution meets the trigger mechanism and elevation requirements. The only hard limitation is Windows’ requirement for an interactive session to display UI for another user.
