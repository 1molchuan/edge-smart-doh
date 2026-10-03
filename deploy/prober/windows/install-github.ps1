# Add the GitHub prober scheduled task to a Windows prober already set up by install.ps1.
# Run as Administrator from a directory holding the updated echprobe.exe, github-run.cmd and
# github-extra-hosts (deploy/prober/github-extra-hosts):
#   powershell -NoProfile -ExecutionPolicy Bypass -File install-github.ps1
$ErrorActionPreference = 'Stop'
$dir = 'C:\ProgramData\echprobe'
Copy-Item -Force echprobe.exe, github-run.cmd, github-extra-hosts $dir
$action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument "/c `"$dir\github-run.cmd`"" -WorkingDirectory $dir
$every30 = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(6) -RepetitionInterval (New-TimeSpan -Minutes 30)
$boot = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 15) -MultipleInstances IgnoreNew `
  -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
$principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName 'echprobe-github' -Force -Action $action -Trigger $every30, $boot `
  -Settings $settings -Principal $principal -Description 'Edge Smart DoH GitHub preferred-IP prober' | Out-Null
Get-ScheduledTask -TaskName 'echprobe-github' | Select-Object TaskName, State
