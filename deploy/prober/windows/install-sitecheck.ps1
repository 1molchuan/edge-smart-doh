# Upgrade a Windows prober set up by install.ps1: new echprobe.exe (-budget, -sitecheck), run.cmd with
# a budget, and the site-check scheduled task. Run as Administrator from a directory holding
# echprobe.exe, run.cmd and sitecheck-run.cmd:
#   powershell -NoProfile -ExecutionPolicy Bypass -File install-sitecheck.ps1
$ErrorActionPreference = 'Stop'
$dir = 'C:\ProgramData\echprobe'
# A running echprobe.exe cannot be overwritten, but it can be renamed out of the way.
if (Test-Path "$dir\echprobe.exe") { Move-Item -Force "$dir\echprobe.exe" "$dir\echprobe.exe.old" }
Copy-Item -Force echprobe.exe, run.cmd, sitecheck-run.cmd $dir
$action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument "/c `"$dir\sitecheck-run.cmd`"" -WorkingDirectory $dir
$every15 = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 15)
$boot = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 10) -MultipleInstances IgnoreNew `
  -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
$principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName 'echprobe-sitecheck' -Force -Action $action -Trigger $every15, $boot `
  -Settings $settings -Principal $principal -Description 'Edge Smart DoH site check' | Out-Null
Get-ScheduledTask -TaskName 'echprobe-sitecheck' | Select-Object TaskName, State
