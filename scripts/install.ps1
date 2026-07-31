#Requires -Version 5.1
<#
.SYNOPSIS
  Registers the SecMon scheduled tasks:
    SecMonDaemon - runs secmon.py (pythonw, windowless) at user logon
    SecMonPatrol - runs "secmon.py patrol-tick" every 30 minutes
                   (it is a no-op unless ai.mode = "patrol" in config.json)
#>
[CmdletBinding()]
param(
    [string]$PythonW = ""
)
$ErrorActionPreference = 'Stop'

$root   = Split-Path -Parent $PSScriptRoot
$secmon = Join-Path $root 'secmon.py'
if (-not (Test-Path $secmon)) { throw "secmon.py not found at $secmon" }

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

Write-Host "SecMon : $secmon"
Write-Host "PythonW: $PythonW"

$daemonArgs = ('"{0}" "{1}"' -f $PythonW, $secmon)
$patrolArgs = ('"{0}" "{1}" patrol-tick' -f $PythonW, $secmon)

schtasks.exe /create /tn 'SecMonDaemon' /tr $daemonArgs /sc ONLOGON /f | Out-Host
schtasks.exe /create /tn 'SecMonPatrol' /tr $patrolArgs /sc MINUTE /mo 30 /f | Out-Host

Write-Host "`nRegistered tasks:"
schtasks.exe /query /tn 'SecMonDaemon' /fo list | Out-Host
schtasks.exe /query /tn 'SecMonPatrol' /fo list | Out-Host
Write-Host "Done. The daemon starts at next logon; start it now with:"
Write-Host "  schtasks /run /tn SecMonDaemon"
