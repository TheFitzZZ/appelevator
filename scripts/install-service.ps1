[CmdletBinding()]
param(
    [string]$ServiceName = "AppElevator",
    [string]$DisplayName = "AppElevator Service",
    [string]$EventSource = "AppElevator",
    [string]$UserName = "localadm",
    [string]$Password,
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"



function Assert-Admin {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This script must be run as Administrator."
    }
}

function ConvertTo-UnsecureString {
    param([SecureString]$SecureString)
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

function Ensure-UserExists {
    param([string]$UserName)
    $user = Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue
    if (-not $user) {
        throw "Local user '$UserName' not found. Create it before installing the service."
    }
}

function Grant-UserRight {
    param(
        [string]$UserName,
        [string]$RightName
    )

    $account = "$env:COMPUTERNAME\$UserName"
    $sid = (New-Object System.Security.Principal.NTAccount($account)).Translate([System.Security.Principal.SecurityIdentifier]).Value
    $sidEntry = "*$sid"

    $temp = Join-Path $env:TEMP "secpol-app-elevator.inf"
    $db = Join-Path $env:TEMP "secpol-app-elevator.sdb"

    secedit /export /cfg $temp /areas USER_RIGHTS | Out-Null
    $content = Get-Content $temp

    $lineIndex = [Array]::FindIndex($content, [Predicate[string]]{ param($line) $line -match ("^" + [regex]::Escape($RightName)) })
    if ($lineIndex -lt 0) {
        $content += "$RightName = $sidEntry"
    }
    else {
        if ($content[$lineIndex] -notmatch [regex]::Escape($sid)) {
            $content[$lineIndex] = $content[$lineIndex] + "," + $sidEntry
        }
    }

    $content | Set-Content $temp -Encoding Unicode
    secedit /configure /db $db /cfg $temp /areas USER_RIGHTS | Out-Null
}

function Ensure-EventSource {
    param([string]$EventSource)
    if (-not [System.Diagnostics.EventLog]::SourceExists($EventSource)) {
        New-EventLog -LogName Application -Source $EventSource
    }
}

function Store-ServiceCredentials {
    param(
        [string]$UserName,
        [string]$Password
    )

    $fullUser = "$env:COMPUTERNAME\$UserName"

    $keyPath = "HKLM:\SOFTWARE\AppElevator"
    if (-not (Test-Path $keyPath)) {
        New-Item -Path $keyPath -Force | Out-Null
    }

    New-ItemProperty -Path $keyPath -Name ServiceUser -Value $fullUser -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $keyPath -Name ServicePasswordPlain -Value $Password -PropertyType String -Force | Out-Null
}

Assert-Admin
Ensure-UserExists -UserName $UserName
Grant-UserRight -UserName $UserName -RightName "SeServiceLogonRight"
Grant-UserRight -UserName $UserName -RightName "SeInteractiveLogonRight"
Grant-UserRight -UserName $UserName -RightName "SeTcbPrivilege"
Grant-UserRight -UserName $UserName -RightName "SeAssignPrimaryTokenPrivilege"
Grant-UserRight -UserName $UserName -RightName "SeIncreaseQuotaPrivilege"
Grant-UserRight -UserName $UserName -RightName "SeDebugPrivilege"
Ensure-EventSource -EventSource $EventSource

$root = Split-Path -Parent $PSScriptRoot
$projectPath = Join-Path $root "src\Service\AppElevator.Service.csproj"
$publishDir = Join-Path $root "publish"

if (-not $SkipBuild) {
    $existingForBuild = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existingForBuild -and $existingForBuild.Status -eq 'Running') {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }
    dotnet publish $projectPath -c Release -r win-x64 --self-contained true /p:PublishSingleFile=true /p:IncludeNativeLibrariesForSelfExtract=true /p:PublishDir=$publishDir
}

$exePath = Join-Path $publishDir "AppElevator.Service.exe"
if (-not (Test-Path $exePath)) {
    throw "Service executable not found at $exePath"
}

if (-not $Password) {
    $secure = Read-Host "Enter password for $UserName" -AsSecureString
    $Password = ConvertTo-UnsecureString -SecureString $secure
}

Store-ServiceCredentials -UserName $UserName -Password $Password

$binaryPath = '"' + $exePath + '"'
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    sc.exe config $ServiceName binPath= $binaryPath obj= "LocalSystem" DisplayName= "$DisplayName" start= auto | Out-Null
}
else {
    sc.exe create $ServiceName binPath= $binaryPath obj= "LocalSystem" DisplayName= "$DisplayName" start= auto | Out-Null
}

sc.exe description $ServiceName "Launches cmd.exe on event log trigger." | Out-Null
Start-Service -Name $ServiceName
Write-Host "Service $ServiceName is installed and running."
