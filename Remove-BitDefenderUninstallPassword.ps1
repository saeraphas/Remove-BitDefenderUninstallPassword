# Get last login user 
$lastLoginUser = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI" -Name "LastLoggedOnUser").LastLoggedOnUser

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

# Set file paths
$SafeModeScriptPath = "C:\nexigen\SafeModeScript.cmd" #runs in Safe Mode
$CleanupScriptPath = "C:\nexigen\CleanupScript.cmd" #runs in Normal Mode
$BitDefenderUninstallPath = "C:\nexigen\BEST_uninstallTool.exe"

# Create safe mode script (runs first)
$SafeModeScript = @"
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Endpoint Security" /v Key /d "" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" /v "*RunOnceScript" /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" /v "CleanupScript" /d "$CleanupScriptPath" /f
bcdedit /deletevalue "{default}" safeboot
shutdown.exe /r /t 00
"@
New-Item $SafeModeScriptPath -Force
Set-Content $SafeModeScriptPath -value $SafeModeScript
Set-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name '*RunOnceScript' -Value "$SafeModeScriptPath"

# Create normal mode script (runs on normal mode)
$CleanupScript = @"
REG DELETE "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /f
REG DELETE "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName /f
REG DELETE "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" /v "CleanupScript" /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI" /v LastLoggedOnUser /d "$lastLoginUser" /f
$BitDefenderUninstallPath /bdparams /bruteForce /noWait
"@
New-Item $CleanupScriptPath -Force
Set-Content $CleanupScriptPath -value $CleanupScript

# Download BitDefender uninstall tool and save it locally. 
# https://download.bitdefender.com/SMB/Hydra/release/bst_win/uninstallTool/BEST_uninstallTool.exe
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri "https://download.bitdefender.com/SMB/Hydra/release/bst_win/uninstallTool/BEST_uninstallTool.exe" -OutFile "$BitDefenderUninstallPath"

if (Test-Path -Path $BitDefenderUninstallPath) {
    # Restart into Safe Mode
    Write-Warning "BitDefender uninstall tool found at $BitDefenderUninstallPath. Restarting into Safe Mode with Networking. Please do not interrupt."
    bcdedit /set "{current}" safeboot network
    Start-Sleep -Seconds 10
    Restart-Computer -Force
}
else {
    # Print error and exit
    Write-Warning "BitDefender uninstall tool not found at $BitDefenderUninstallPath. Please copy the file and try again."
}

# These should be run manually once removal is complete to remove the temp admin account. 
#NET LOCALGROUP Administrators /delete $adminUsername 
#NET USER $adminUsername /delete