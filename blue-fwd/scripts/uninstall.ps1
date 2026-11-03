#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Stops and removes the BlueFwd service. Use -RemoveFiles / -RemoveData to also delete files.
#>
param(
    [string]$InstallDir = (Join-Path $env:ProgramFiles "BlueFwd"),
    [string]$ServiceName = "BlueFwd",
    [switch]$RemoveFiles,
    [switch]$RemoveData
)

$ErrorActionPreference = "Stop"

$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    if ($svc.Status -ne "Stopped") {
        Stop-Service -Name $ServiceName -Force
        $svc.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(30))
    }
    sc.exe delete $ServiceName | Out-Null
    Write-Host "Service $ServiceName removed."
}
else {
    Write-Host "Service $ServiceName is not installed."
}

if ($RemoveFiles -and (Test-Path $InstallDir)) {
    Remove-Item -Recurse -Force -Confirm:$false $InstallDir
    Write-Host "Removed $InstallDir"
}

$dataDir = Join-Path $env:ProgramData "BlueFwd"
if ($RemoveData -and (Test-Path $dataDir)) {
    Remove-Item -Recurse -Force -Confirm:$false $dataDir
    Write-Host "Removed $dataDir (configuration and positions)"
}
