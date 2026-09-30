# Install the preferred-IP prober on Windows as a scheduled task (the systemd timer's counterpart).
# Run as Administrator from a directory holding echprobe.exe (windows/amd64) and run.cmd, with the
# admin token on stdin so it never appears on a command line:
#   <token source> | powershell -NoProfile -ExecutionPolicy Bypass -File install.ps1
# Everything lives in C:\ProgramData\echprobe, readable only by SYSTEM and Administrators. The task
# runs run.cmd as SYSTEM every 30 minutes and at startup; output goes to echprobe.log there.
$ErrorActionPreference = 'Stop'
$dir = 'C:\ProgramData\echprobe'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
# SIDs, not names: group names are localized. S-1-5-18 = SYSTEM, S-1-5-32-544 = Administrators.
& icacls $dir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
$token = [Console]::In.ReadToEnd().Trim()
if ($token.Length -lt 16) { throw 'no admin token on stdin' }
Set-Content -NoNewline -Encoding ascii -Path "$dir\token" -Value $token
Copy-Item -Force echprobe.exe, run.cmd $dir

$action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument "/c `"$dir\run.cmd`"" -WorkingDirectory $dir
$every30 = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 30)
$boot = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 25) -MultipleInstances IgnoreNew `
  -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
$principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName 'echprobe-report' -Force -Action $action -Trigger $every30, $boot `
  -Settings $settings -Principal $principal -Description 'Edge Smart DoH preferred-IP prober' | Out-Null
Get-ScheduledTask -TaskName 'echprobe-report' | Select-Object TaskName, State
