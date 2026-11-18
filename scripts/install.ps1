#Requires -Version 5.1
<#
.SYNOPSIS
  Registers the TripFlare scheduled tasks:
    TripFlareDaemon - runs TripFlareDaemon.exe or tripflare.py (pythonw) at logon
    TripFlarePatrol - runs patrol-tick every 30 minutes
                      (no-op unless ai.mode = "patrol" in config.json)
    TripFlareTray   - runs TripFlareTray.exe or tripflare_tray.pyw at logon,
                      restarts on failure, and is started immediately
#>
[CmdletBinding()]
param(
    [string]$PythonW = ""
)
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$daemonExe = Join-Path $root 'TripFlareDaemon.exe'
$trayExe   = Join-Path $root 'TripFlareTray.exe'
$useExe    = (Test-Path $daemonExe) -and (Test-Path $trayExe)

$longSettings = New-ScheduledTaskSettingsSet -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit (New-TimeSpan -Seconds 0) `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
$logonTrigger = New-ScheduledTaskTrigger -AtLogOn

if ($useExe) {
    Write-Host "TripFlare : $daemonExe (portable bundle)"
    $daemonAction = New-ScheduledTaskAction -Execute $daemonExe
    $trayAction   = New-ScheduledTaskAction -Execute $trayExe
    $patrolArgs   = ('"{0}" patrol-tick' -f $daemonExe)
} else {
    $tripflare  = Join-Path $root 'tripflare.py'
    $trayScript = Join-Path $root 'tripflare_tray.pyw'
    if (-not (Test-Path $tripflare))  { throw "tripflare.py not found at $tripflare" }
    if (-not (Test-Path $trayScript)) { throw "tripflare_tray.pyw not found at $trayScript" }

    # Resolve pythonw.exe (skip WindowsApps Store alias stubs).
    if (-not $PythonW) {
        $candidates = [System.Collections.Generic.List[string]]::new()
        $candidates.Add('C:\ProgramData\miniconda3\pythonw.exe')
        $candidates.Add((Join-Path $env:USERPROFILE 'miniconda3\pythonw.exe'))
        $candidates.Add((Join-Path $env:USERPROFILE 'anaconda3\pythonw.exe'))
        foreach ($ver in @('313', '312', '311', '310', '39', '38')) {
            $candidates.Add((Join-Path $env:LOCALAPPDATA ("Programs\Python\Python$ver\pythonw.exe")))
            $candidates.Add((Join-Path $env:ProgramFiles ("Python$ver\pythonw.exe")))
        }
        foreach ($c in $candidates) {
            if ($c -and (Test-Path $c) -and ($c -notmatch '\\WindowsApps\\')) {
                $PythonW = $c
                break
            }
        }
    }
    if (-not $PythonW) {
        $pwCmd = Get-Command pythonw.exe -All -ErrorAction SilentlyContinue |
            Where-Object { $_.Source -and ($_.Source -notmatch '\\WindowsApps\\') } |
            Select-Object -First 1
        if ($pwCmd) { $PythonW = $pwCmd.Source }
    }
    if (-not $PythonW) {
        $pyCmd = Get-Command python.exe -All -ErrorAction SilentlyContinue |
            Where-Object { $_.Source -and ($_.Source -notmatch '\\WindowsApps\\') } |
            Select-Object -First 1
        if ($pyCmd) {
            $maybe = Join-Path (Split-Path $pyCmd.Source) 'pythonw.exe'
            if (Test-Path $maybe) { $PythonW = $maybe }
        }
    }
    if (-not $PythonW) { throw 'pythonw.exe not found; pass -PythonW <path>' }

    Write-Host "TripFlare : $tripflare"
    Write-Host "PythonW   : $PythonW"
    $daemonAction = New-ScheduledTaskAction -Execute $PythonW -Argument ('"{0}"' -f $tripflare)
    $trayAction   = New-ScheduledTaskAction -Execute $PythonW -Argument ('"{0}"' -f $trayScript)
    $patrolArgs   = ('"{0}" "{1}" patrol-tick' -f $PythonW, $tripflare)
}

Register-ScheduledTask -TaskName 'TripFlareDaemon' -Action $daemonAction `
    -Trigger $logonTrigger -Settings $longSettings -Force | Out-Null

schtasks.exe /create /tn 'TripFlarePatrol' /tr $patrolArgs /sc MINUTE /mo 30 /f | Out-Host
$patrolSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Set-ScheduledTask -TaskName 'TripFlarePatrol' -Settings $patrolSettings | Out-Null

Register-ScheduledTask -TaskName 'TripFlareTray' -Action $trayAction `
    -Trigger $logonTrigger -Settings $longSettings -Force | Out-Null

schtasks.exe /run /tn 'TripFlareDaemon' | Out-Host
schtasks.exe /run /tn 'TripFlareTray'   | Out-Host

Write-Host "`nRegistered tasks:"
schtasks.exe /query /tn 'TripFlareDaemon' /fo list | Out-Host
schtasks.exe /query /tn 'TripFlarePatrol' /fo list | Out-Host
schtasks.exe /query /tn 'TripFlareTray'   /fo list | Out-Host
Write-Host "Done. TripFlareDaemon and TripFlareTray are registered for logon and started now."
