<#
.SYNOPSIS
    Installs or updates Strongroom as a Windows Service (starts with Windows, listens on http://localhost:<Port>).

.DESCRIPTION
    Run from an ELEVATED PowerShell. Safe to re-run: running it again publishes the current code,
    replaces the program files, and restarts the service. Your vault database is never overwritten.

    Steps: publish (Release) -> stop service -> copy to InstallDir -> write appsettings.Production.json
    -> prepare the database folder -> create/update the service -> start it -> health check.

.PARAMETER InstallDir
    Where the program files go. Default C:\Apps\Strongroom.

.PARAMETER DatabasePath
    Full path to the vault database FILE. Default C:\ProgramData\Strongroom\strongroom.db.
    Only written to the service config when you pass it, or on the first install; later runs keep the
    existing setting so an update can never silently point the service at a different database.

.PARAMETER Port
    The localhost port the service listens on. Default 47245 (chosen to avoid the ranges used by .NET templates
    and common dev tools; `dotnet run` keeps using 5245, so both can run side by side).
    Like DatabasePath, it is only changed when you pass it; later runs keep the existing port.
    To move an installed service to another port: re-run this script with -Port <number>.

.PARAMETER ImportVault
    On first install, copy the vault you have been using from the repo (data\strongroom.db) to the
    service's database path. Skipped (with a warning) if a database already exists there.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\deploy\install.ps1 -ImportVault
#>
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$InstallDir = 'C:\Apps\Strongroom',
    [string]$DatabasePath = 'C:\ProgramData\Strongroom\strongroom.db',
    [ValidateRange(1024, 65535)][int]$Port = 47245,
    [switch]$ImportVault
)

$ErrorActionPreference = 'Stop'
$serviceName = 'Strongroom'
$repoRoot = Split-Path $PSScriptRoot -Parent
$project = Join-Path $repoRoot 'src\Strongroom.Web'
$stage = Join-Path $env:TEMP 'strongroom-publish'

function Step($text) { Write-Host "`n==> $text" -ForegroundColor Cyan }

if ($DatabasePath.EndsWith('\') -or $DatabasePath.EndsWith('/') -or (Test-Path $DatabasePath -PathType Container)) {
    throw "DatabasePath must be a file path (for example C:\ProgramData\Strongroom\strongroom.db), not a folder: $DatabasePath"
}

# 1. Publish -------------------------------------------------------------------------------
Step 'Publishing (Release)'
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
dotnet publish $project -c Release -o $stage --nologo -v quiet
if ($LASTEXITCODE -ne 0) { throw 'dotnet publish failed.' }

# 2. Stop the service so files can be replaced -----------------------------------------------
$svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -ne 'Stopped') {
    Step 'Stopping the running service'
    Stop-Service -Name $serviceName
    $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
}

# 3. Copy program files (keeps the machine-specific settings file) ---------------------------
Step "Copying program files to $InstallDir"
robocopy $stage $InstallDir /MIR /XF appsettings.Production.json /NFL /NDL /NJH /NJS /NP | Out-Null
if ($LASTEXITCODE -ge 8) { throw "robocopy failed with exit code $LASTEXITCODE" }

# 4. Machine-specific settings ---------------------------------------------------------------
$prodFile = Join-Path $InstallDir 'appsettings.Production.json'
$existing = if (Test-Path $prodFile) { Get-Content $prodFile -Raw | ConvertFrom-Json } else { $null }

# Explicit parameter wins; otherwise keep what is already installed; otherwise use the default.
$effectiveDb = $DatabasePath
if (-not $PSBoundParameters.ContainsKey('DatabasePath') -and $existing.Strongroom.DatabasePath) {
    $effectiveDb = $existing.Strongroom.DatabasePath
}
$effectivePort = $Port
if (-not $PSBoundParameters.ContainsKey('Port') -and $existing.Kestrel.Endpoints.Http.Url -match ':(\d+)\s*$') {
    $effectivePort = [int]$Matches[1]
}

Step "Writing $prodFile (port $effectivePort)"
$config = @{
    Strongroom = @{ DatabasePath = $effectiveDb }
    Kestrel    = @{ Endpoints = @{ Http = @{ Url = "http://localhost:$effectivePort" } } }
} | ConvertTo-Json -Depth 5
Set-Content -Path $prodFile -Value $config -Encoding UTF8

# 5. Database folder (and optional import of the existing vault) -----------------------------
Step "Preparing the database folder for $effectiveDb"
$dbDir = Split-Path $effectiveDb -Parent
New-Item -ItemType Directory -Force -Path $dbDir | Out-Null

if ($ImportVault) {
    $repoVault = Join-Path $repoRoot 'data\strongroom.db'
    if (Test-Path $effectiveDb) {
        Write-Warning "A database already exists at $effectiveDb; NOT importing. Delete or move it first if you really want to replace it."
    } elseif (Test-Path $repoVault) {
        Copy-Item $repoVault $effectiveDb
        Write-Host "Imported your existing vault from $repoVault"
    } else {
        Write-Warning "No vault found at $repoVault to import."
    }
}

# The service runs as LocalService (a low-privilege account), so it needs write access to the data folder.
icacls $dbDir /grant '*S-1-5-19:(OI)(CI)M' | Out-Null

# 6. Create or update the service ------------------------------------------------------------
$exe = Join-Path $InstallDir 'Strongroom.Web.exe'
if (-not (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) {
    Step 'Creating the Windows Service'
    New-Service -Name $serviceName `
        -BinaryPathName "`"$exe`"" `
        -DisplayName 'Strongroom password manager' `
        -Description 'Local-only password manager (see appsettings.Production.json for the port).' `
        -StartupType Automatic | Out-Null
    sc.exe config $serviceName obj= 'NT AUTHORITY\LocalService' | Out-Null
} else {
    Step 'Updating the existing service'
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName" -Name ImagePath -Value "`"$exe`""
}
# If it ever crashes: restart after 5s, then 30s.
sc.exe failure $serviceName reset= 86400 actions= restart/5000/restart/30000// | Out-Null

# 7. Start and check -----------------------------------------------------------------------
$listener = Get-NetTCPConnection -LocalPort $effectivePort -State Listen -ErrorAction SilentlyContinue
if ($listener) {
    $owner = (Get-Process -Id $listener[0].OwningProcess -ErrorAction SilentlyContinue).ProcessName
    throw "Port $effectivePort is already in use by '$owner'. Stop that program, or re-run this script with a different -Port."
}

Step 'Starting the service'
Start-Service -Name $serviceName

$ok = $false
foreach ($i in 1..15) {
    try {
        $status = Invoke-RestMethod -Uri "http://localhost:$effectivePort/api/status" -TimeoutSec 3
        $ok = $true
        break
    } catch { Start-Sleep -Seconds 1 }
}

if (-not $ok) {
    Write-Warning "The service started but did not answer on port $effectivePort. Check Event Viewer > Windows Logs > Application (source: Strongroom)."
    exit 1
}

Write-Host "`nStrongroom is running as a Windows Service." -ForegroundColor Green
Write-Host "  Open:      http://localhost:$effectivePort"
Write-Host "  Programs:  $InstallDir"
Write-Host "  Database:  $effectiveDb"
Write-Host "  Update:    run this script again after changing the code"
Write-Host "  Remove:    deploy\uninstall.ps1"
