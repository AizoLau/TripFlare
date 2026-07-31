#Requires -Version 5.1
<#
.SYNOPSIS
  Removes the TripFlare scheduled tasks (TripFlareDaemon, TripFlarePatrol,
  TripFlareTray). Does NOT delete the project folder or its data\ directory.
#>
$ErrorActionPreference = 'Continue'

foreach ($name in 'TripFlareDaemon', 'TripFlarePatrol', 'TripFlareTray') {
    schtasks.exe /query /tn $name 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) {
        schtasks.exe /delete /tn $name /f | Out-Host
    } else {
        Write-Host "Task $name not present, skipping."
    }
}
Write-Host "TripFlare scheduled tasks removed."
