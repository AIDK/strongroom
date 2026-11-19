<#
.SYNOPSIS
    Removes the Strongroom Windows Service. Run from an ELEVATED PowerShell.

.DESCRIPTION
    Your vault database is NEVER deleted by this script. Program files are kept unless you pass -RemoveFiles.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\deploy\uninstall.ps1 -RemoveFiles
#>
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$InstallDir = 'C:\Apps\Strongroom',
    [switch]$RemoveFiles
)

$ErrorActionPreference = 'Stop'
$serviceName = 'Strongroom'

$svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($svc) {
    if ($svc.Status -ne 'Stopped') {
        Stop-Service -Name $serviceName
        $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
    sc.exe delete $serviceName | Out-Null
    Write-Host "Service '$serviceName' removed."
} else {
    Write-Host "Service '$serviceName' is not installed."
}

$prodFile = Join-Path $InstallDir 'appsettings.Production.json'
$dbPath = if (Test-Path $prodFile) { (Get-Content $prodFile -Raw | ConvertFrom-Json).Strongroom.DatabasePath } else { $null }

if ($RemoveFiles -and (Test-Path $InstallDir)) {
    Remove-Item $InstallDir -Recurse -Force
    Write-Host "Removed program files in $InstallDir."
}

if ($dbPath) { Write-Host "Your vault database was left untouched at: $dbPath" }
