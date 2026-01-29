[CmdletBinding()]
param(
    [string]$EventSource = "AppElevator",
    [int]$EventId = 1001,
    [string]$Message = "Launch cmd.exe"
)

$ErrorActionPreference = "Stop"

if (-not [System.Diagnostics.EventLog]::SourceExists($EventSource)) {
    New-EventLog -LogName Application -Source $EventSource
}

Write-EventLog -LogName Application -Source $EventSource -EventId $EventId -EntryType Information -Message $Message
Write-Host "Trigger event written to Application log (Source=$EventSource, EventId=$EventId)."
