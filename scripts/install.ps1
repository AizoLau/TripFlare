#Requires -Version 5.1
<#
.SYNOPSIS
  Registers the TripFlare scheduled tasks:
    TripFlareDaemon - runs tripflare.py (pythonw, windowless) at user logon
    TripFlarePatrol - runs "tripflare.py patrol-tick" every 30 minutes
                   (it is a no-op unless ai.mode = "patrol" in config.json)
#>
[CmdletBinding()]
param(
    [string]$PythonW = ""
)
$ErrorActionPreference = 'Stop'

$root   = Split-Path -Parent $PSScriptRoot
$tripflare = Join-Path $root 'tripflare.py'
if (-not (Test-Path $tripflare)) { throw "tripflare.py not found at $tripflare" }

# Resolve pythonw.exe (windowless interpreter for background running).
if (-not $PythonW) {
    $candidates = @(
        'C:\ProgramData\miniconda3\pythonw.exe',
        (Join-Path $env:LOCALAPPDATA 'Programs\Python\Python312\pythonw.exe'),
        (Join-Path $env:LOCALAPPDATA 'Programs\Python\Python311\pythonw.exe')
    )
    foreach ($c in $candidates) { if (Test-Path $c) { $PythonW = $c; break } }
}
if (-not $PythonW) {
    $py = (Get-Command python.exe -ErrorAction SilentlyContinue)
    if ($py) {
        $maybe = Join-Path (Split-Path $py.Source) 'pythonw.exe'
        if (Test-Path $maybe) { $PythonW = $maybe }
    }
}
if (-not $PythonW) { throw 'pythonw.exe not found; pass -PythonW <path>' }

Write-Host "TripFlare : $tripflare"
Write-Host "PythonW: $PythonW"

$daemonArgs = ('"{0}" "{1}"' -f $PythonW, $tripflare)
$patrolArgs = ('"{0}" "{1}" patrol-tick' -f $PythonW, $tripflare)

schtasks.exe /create /tn 'TripFlareDaemon' /tr $daemonArgs /sc ONLOGON /f | Out-Host
schtasks.exe /create /tn 'TripFlarePatrol' /tr $patrolArgs /sc MINUTE /mo 30 /f | Out-Host

Write-Host "`nRegistered tasks:"
schtasks.exe /query /tn 'TripFlareDaemon' /fo list | Out-Host
schtasks.exe /query /tn 'TripFlarePatrol' /fo list | Out-Host
Write-Host "Done. The daemon starts at next logon; start it now with:"
Write-Host "  schtasks /run /tn TripFlareDaemon"
