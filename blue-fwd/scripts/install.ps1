#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Installs (or upgrades) BlueFwd as a Windows service.
.DESCRIPTION
  Copies the published files to -InstallDir, registers the service (LocalSystem, automatic start,
  restart on failure) and starts it. An existing appsettings.json in the install directory is kept.
  Runtime configuration lives in %ProgramData%\BlueFwd\config.json and is never touched.
#>
param(
    [string]$SourceDir = (Join-Path $PSScriptRoot "..\publish"),
    [string]$InstallDir = (Join-Path $env:ProgramFiles "BlueFwd"),
    [string]$ServiceName = "BlueFwd"
)

$ErrorActionPreference = "Stop"

$exe = Join-Path $SourceDir "BlueFwd.exe"
if (-not (Test-Path $exe)) { throw "BlueFwd.exe not found in '$SourceDir'. Run scripts\publish.ps1 first." }

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing -and $existing.Status -ne "Stopped") {
    Write-Host "Stopping $ServiceName..."
    Stop-Service -Name $ServiceName -Force
    $existing.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(30))
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$keepSettings = Test-Path (Join-Path $InstallDir "appsettings.json")
Get-ChildItem -Path $SourceDir | Where-Object { -not ($keepSettings -and $_.Name -eq "appsettings.json") } |
    Copy-Item -Destination $InstallDir -Recurse -Force
if ($keepSettings) { Write-Host "Kept existing appsettings.json" }

$binPath = "`"$(Join-Path $InstallDir 'BlueFwd.exe')`""
if (-not $existing) {
    Write-Host "Registering service $ServiceName..."
    New-Service -Name $ServiceName -BinaryPathName $binPath -DisplayName "BlueFwd Event Forwarder" `
        -Description "Forwards Windows events (e.g. Sysmon) to a syslog server over TCP." -StartupType Automatic | Out-Null
}
else {
    sc.exe config $ServiceName binPath= $binPath start= auto | Out-Null
}

# Own event source, so the service's log entries are not attributed to ".NET Runtime".
if (-not [System.Diagnostics.EventLog]::SourceExists($ServiceName)) {
    New-EventLog -LogName Application -Source $ServiceName
}

# Restart after 5s, 5s, then 30s if the process dies; reset the failure counter after a day.
sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/5000/restart/30000 | Out-Null

Start-Service -Name $ServiceName
Write-Host "$ServiceName is running. Web UI: http://127.0.0.1:5080 (see 'Urls' in $InstallDir\appsettings.json)"
