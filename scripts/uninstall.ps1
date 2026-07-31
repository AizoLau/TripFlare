#Requires -Version 5.1
<#
.SYNOPSIS
  Removes the SecMon scheduled tasks (SecMonDaemon, SecMonPatrol).
  Does NOT delete the project or the data directory %LOCALAPPDATA%\SecMon.
#>
$ErrorActionPreference = 'Continue'

foreach ($name in 'SecMonDaemon', 'SecMonPatrol') {
    schtasks.exe /query /tn $name 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) {
        schtasks.exe /delete /tn $name /f | Out-Host
    } else {
        Write-Host "Task $name not present, skipping."
    }
}
Write-Host "SecMon scheduled tasks removed."
