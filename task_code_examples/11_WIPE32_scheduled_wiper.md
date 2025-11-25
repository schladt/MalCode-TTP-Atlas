# Finding 11: WIPE32 Wiper - PowerShell Scheduled Task for Destructive Payload

## Metadata
- **Repository**: theZoo-master
- **File Path**: `malware/Binaries/Wiper.WIPE32.P/Wiper.WIPE32.P/6d4d176b7dbe56461041f34582e8029e490a910e9f4829378f0c90898094c48f`
- **Language**: PowerShell
- **Malware Family**: WIPE32 Wiper (Destructive Malware)

## Code Snippet

```powershell
param (
    [ValidateScript({
        # Validate either 12-hour format (HH:mm AM/PM) or 24-hour format (HH:mm)
        if ($_ -match "^(0[0-9]|1[0-9]|2[0-3]):[0-5][0-9]$") {
            $true
        } elseif ($_ -match "^(0[0-9]|1[0-2]):[0-5][0-9] (AM|PM)$") {
            $true
        } else {
            Throw "Invalid time format. Please use HH:mm (24-hour format, e.g., 15:00) or HH:mm AM/PM (e.g., 03:00 PM or 15:00)"
        }
    })]
    [string]$time,
    [switch]$help
)

# Function to convert input time to 24-hour format
function Get-TimeIn24HourFormat {
    param (
        [string]$InputTime
    )

    if ($InputTime -match "^(0[0-9]|1[0-2]):[0-5][0-9] (AM|PM)$") {
        $parts = $InputTime -split ":"
        $hours = [int]$parts[0]
        $period = $InputTime -split " " | Select-Object -Last 1

        if ($period -eq "PM" -and $hours -ne 12) {
            $hours += 12
        } elseif ($period -eq "AM" -and $hours -eq 12) {
            $hours = 0
        }

        return "{0:D2}:{1}" -f $hours, $parts[1]
    } else {
        return $InputTime
    }
}

$helpMenu = @"
Usage: ./blueTask.ps1 [OPTIONS]
Options:
  -h, --help          Show this help menu
  -time               Set Time like this "03:00 PM" or "15:00" (24-hour format)
Examples:
  ./blueTask.ps1 -time "03:00 PM"
  ./blueTask.ps1 -time "15:00"
  ./blueTask.ps1 --help
Version: 1.0
"@

if ($help -or $h) {
    Write-Host $helpMenu
    exit 0
}

# Convert the input time to 24-hour format
$normalizedTime = Get-TimeIn24HourFormat -InputTime $time

# Path to wiper payload
#$scriptPath = "$(Get-Location)\wipe32.exe"
$scriptPath = "$(Get-Location)\new.vbs"

# *** SCHEDULED TASK CREATION - LINE 71 ***
# Create the scheduled task using schtasks
$schtasksArgs = @{
    Create = $true
    TaskName = "wp32Service"
    Action = "`"$scriptPath`""
    Trigger = "-Daily -At `"$normalizedTime`""
    User = ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
    Hidden = $true
}

schtasks.exe /Create /TN wp32Service /TR $scriptPath /SC DAILY /ST "$normalizedTime" /RL HIGHEST /RU $($schtasksArgs.User) /F
```

## Analysis

**What it does:**
WIPE32 is a wiper malware designed to cause destructive damage to systems. This PowerShell script creates a scheduled task to execute the wiper payload at a specified time. Wipers are typically used in targeted attacks to destroy evidence, cause operational disruption, or as part of cyberwarfare operations.

**How it uses Windows Scheduled Tasks (T1053.005):**
- **Task name**: `/TN wp32Service` - generic service-sounding name
- **Target**: `/TR $scriptPath` - points to wiper executable/VBS script
- **Schedule**: `/SC DAILY` - runs daily at specified time
- **Start time**: `/ST "$normalizedTime"` - operator-specified execution time
- **Privilege**: `/RL HIGHEST` - runs with highest available privileges
- **User**: `/RU [CurrentUser]` - runs as current user (with their privileges)
- **Force**: `/F` - overwrites existing task

**Evasion/Stealth Techniques:**
1. **Generic service name**: "wp32Service" appears benign and system-related
2. **Time-delayed execution**: Allows operator to schedule wiper for specific time (e.g., after hours, simultaneous multi-target attack)
3. **User-friendly interface**: PowerShell script with help menu and time validation makes it easy to deploy
4. **Flexible payload**: Can point to `.exe` or `.vbs` wiper payload
5. **Current user context**: Runs as current user to avoid additional authentication prompts
6. **Highest privilege escalation**: Uses `/RL HIGHEST` to gain maximum available privileges

**Wiper Context:**
Wipers are destructive malware designed to:
- Delete critical system files
- Overwrite disk sectors
- Corrupt boot records (MBR/GPT)
- Destroy backups and recovery partitions
- Render systems inoperable

**Operational Characteristics:**

**Time-delayed execution advantages:**
- Allows attackers to plant wiper and evacuate network before detonation
- Enables coordinated attacks across multiple systems simultaneously
- Provides time for privilege escalation and lateral movement
- Delays detection until destructive phase begins

**User-friendly deployment:**
The script includes professional features:
- Parameter validation (time format checking)
- Help menu with examples
- Support for both 12-hour and 24-hour time formats
- Time normalization function
- Clear error messages

**Attack Scenario:**
```
1. Initial Compromise → Gain access to target network
2. Lateral Movement → Compromise multiple systems
3. Privilege Escalation → Gain admin rights where possible
4. Deployment → Copy wiper and PowerShell script to targets
5. Scheduling → Execute script with target time (e.g., ./blueTask.ps1 -time "02:00 AM")
6. Exfiltration/Cleanup → Attackers exit network before scheduled time
7. Detonation → Scheduled tasks trigger wiper simultaneously across network
8. Impact → Mass data destruction, operational disruption
```

**Notable Wiper Campaigns:**
Similar scheduled task-based wipers have been observed in:
- **Shamoon**: Targeted Saudi Aramco (2012, 2016, 2018)
- **NotPetya**: Disguised as ransomware, caused $10B+ damage (2017)
- **HermeticWiper**: Used against Ukrainian targets (2022)
- **IsaacWiper/WhisperGate**: Ukraine-focused attacks (2022)
- **Meteor Wiper**: Iran-focused attacks (2022)

**Detection Indicators:**
- Scheduled task named "wp32Service" with daily trigger
- Task pointing to suspicious executable or VBScript
- Task created with `/RL HIGHEST` privilege
- Recent task creation with near-future execution time
- Presence of wiper executables with names like `wipe32.exe`

**Defensive Considerations:**
- Monitor scheduled task creation events (Event ID 4698)
- Alert on tasks with `/RL HIGHEST` privilege
- Baseline normal scheduled tasks
- Monitor for tasks pointing to unusual file paths
- Implement backup and recovery systems on separate networks
- Offline/air-gapped backup systems

**MITRE ATT&CK Mapping:**
- **T1053.005**: Scheduled Task/Job: Scheduled Task (Primary)
- **T1485**: Data Destruction (wiper payload)
- **T1490**: Inhibit System Recovery (likely wiper functionality)
- **T1529**: System Shutdown/Reboot (possible wiper component)
- **T1561**: Disk Wipe (wiper primary function)
- **T1059.001**: Command and Scripting Interpreter: PowerShell
- **T1036.005**: Masquerading: Match Legitimate Name or Location (service name)
