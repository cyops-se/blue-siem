<#
.SYNOPSIS
  Builds a release of BlueFwd into .\publish (or -Output).
.PARAMETER SelfContained
  Bundle the .NET runtime so the target machine does not need the ASP.NET Core 9 runtime installed.
#>
param(
    [string]$Output = (Join-Path $PSScriptRoot "..\publish"),
    [switch]$SelfContained
)

$ErrorActionPreference = "Stop"
$project = Join-Path $PSScriptRoot "..\src\BlueFwd.Service\BlueFwd.Service.csproj"

$publishArgs = @("publish", $project, "-c", "Release", "-o", $Output, "-r", "win-x64",
    "--self-contained", ($(if ($SelfContained) { "true" } else { "false" })))
if ($SelfContained) { $publishArgs += "-p:PublishSingleFile=true" }

dotnet @publishArgs
if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed" }

Write-Host "Published to $((Resolve-Path $Output).Path)"
