[CmdletBinding()]
param(
    [string]$ServiceName = "AppElevator",
    [string]$EventSource = "AppElevator",
    [int]$EventId = 1001,
    [string]$Password
)

$ErrorActionPreference = "Stop"

function Assert-Admin {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This test must be run as Administrator."
    }
}

function Get-ActiveSessionId {
    $explorer = Get-Process explorer -ErrorAction SilentlyContinue | Sort-Object StartTime -Descending | Select-Object -First 1
    if (-not $explorer) {
        throw "Could not determine active session (explorer.exe not found)."
    }
    return $explorer.SessionId
}

Assert-Admin

$root = Split-Path -Parent $PSScriptRoot
& (Join-Path $root "scripts\install-service.ps1") -ServiceName $ServiceName -EventSource $EventSource -Password $Password

Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

$sessionId = Get-ActiveSessionId
$triggerTime = Get-Date

& (Join-Path $root "scripts\trigger-event.ps1") -EventSource $EventSource -EventId $EventId

$timeout = [DateTime]::UtcNow.AddSeconds(30)
$found = $false
$cmdProcess = $null

while ([DateTime]::UtcNow -lt $timeout) {
    $cmdProcess = Get-Process cmd -ErrorAction SilentlyContinue |
        Where-Object { $_.SessionId -eq $sessionId -and $_.StartTime -ge $triggerTime } |
        Sort-Object StartTime -Descending |
        Select-Object -First 1

    if ($cmdProcess) {
        $found = $true
        break
    }

    Start-Sleep -Milliseconds 500
}

if (-not $found) {
    throw "cmd.exe was not launched in the active session within the timeout."
}

Write-Host "Success: cmd.exe started with PID $($cmdProcess.Id) in session $sessionId."

try {
    Stop-Process -Id $cmdProcess.Id -Force -ErrorAction SilentlyContinue
}
catch {
    Write-Warning "Could not terminate cmd.exe after test: $_"
}
