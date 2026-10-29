# Builds the frontend into backend/web/dist and compiles a single binary.
$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    Push-Location frontend
    if (-not (Test-Path node_modules)) { npm install }
    npm run build
    Pop-Location

    Push-Location backend
    go build -o ../blue-siem.exe .
    Pop-Location
    Write-Host "Built blue-siem.exe"
} finally {
    Pop-Location
}
