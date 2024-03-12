# Create Admin User
$adminUsername = "RunOnceAdmin" 
$adminPassword = ConvertTo-SecureString -String "PleaseGoAwayBD!" -AsPlainText -Force #change this in Auto Login section below also
$adminUserDescription = "temporary BitDefender password removal admin"
New-LocalUser -Name $adminUsername -Password $adminPassword -AccountNeverExpires -UserMayNotChangePassword -Description $adminUserDescription -Verbose
Add-LocalGroupMember -Group Administrators -Member $adminUsername -Verbose

# Enable Auto Logon
$autoLogonUsername = $adminUsername
$autoLogonPassword = "PleaseGoAwayBD!" #needs to match user password set earlier
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$regValueName1 = "AutoAdminLogon"
$regValueName2 = "DefaultUserName"
$regValueName3 = "DefaultPassword"
Set-ItemProperty -Path $regPath -Name $regValueName1 -Value "1" -Verbose
Set-ItemProperty -Path $regPath -Name $regValueName2 -Value $autoLogonUsername -Verbose
Set-ItemProperty -Path $regPath -Name $regValueName3 -Value $autoLogonPassword -Verbose

# Create script to run from within safe mode
$SafeModeScript = @"
REG add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Endpoint Security" /v Key /d "" /f
REG DELETE "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /f
REG DELETE "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName /f
REG DELETE "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword /f
bcdedit /deletevalue "{default}" safeboot
shutdown.exe /r /t 00
"@
$SafeModeScriptPath = "C:\nexigen\SafeModeScript.cmd"
New-Item $SafeModeScriptPath -Force
Set-Content $SafeModeScriptPath -value $SafeModeScript
Set-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name 'RunOnceScript' -Value "$SafeModeScriptPath"

# Create script to do cleanup after exiting safe mode
$CleanupScript = @"
NET LOCALGROUP Administrators /delete $adminUsername 
NET USER $adminUsername /delete
C:\nexigen\BEST_Uninstall_tool.exe /bdparams /bruteForce /noWait
"@
$CleanupScriptPath = "C:\nexigen\CleanupScript.cmd"
New-Item $CleanupScriptPath -Force
Set-Content $CleanupScriptPath -value $CleanupScript

# Restart into Safe Mode
bcdedit /set "{current}" safeboot network
Start-Sleep -Seconds 10
Restart-Computer -Force

# Run cleanup script after exiting safe mode. 