# SdBot - Redundant Multi-Location Registry Run Key Persistence

**Repository:** `MalwareSourceCode-main`  
**File:** `Win32/Malware Families/Win32.SdBot/Win32.Sd.a/Win32.Sd/sdbot05b.cpp`  
**Language:** C++  
**MITRE ATT&CK:** T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder)

## Overview

SdBot (rBot/xTBot variant) establishes persistence by writing its executable path to multiple `Run` and `RunServices` registry keys. This spatial redundancy technique increases resilience against removal: even if one autostart location is cleaned, others remain active. The malware masquerades as "Windows Update Manager" to appear legitimate and targets both `HKEY_LOCAL_MACHINE\...\Run` (modern Windows) and `HKEY_LOCAL_MACHINE\...\RunServices` (legacy Windows 9x/NT) for maximum compatibility across Windows versions.

## Multi-Location Registry Persistence

```cpp
// Masqueraded value name
char valuename[] = "Windows Update Manager";
char filename1[MAX_PATH];
// ... filename1 populated with malware's path ...

// Location 1: HKLM\...\Run (System-wide, all users)
if (regrun) {
    RegCreateKeyEx(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 
                   0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &key, NULL);
    RegSetValueEx(key, valuename, 0, REG_SZ, (const unsigned char *)&filename1, sizeof(filename)+1);
    RegCloseKey(key);
}

// Location 2: HKLM\...\RunServices (Legacy Windows 9x/NT)
if (regrunservices) {
    RegCreateKeyEx(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices", 
                   0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &key, NULL);
    RegSetValueEx(key, valuename, 0, REG_SZ, (const unsigned char *)&filename1, sizeof(filename)+1);
    RegCloseKey(key);
}

// Note: Other variants also write to HKCU\...\Run for user-level persistence
```

**Technical Details:**

- **`Run` Key**: Standard Windows autostart location executed by `explorer.exe` at user logon
- **`RunServices` Key**: Legacy Windows NT/9x service autostart location (pre-Windows 2000)
- **Configuration Flags**: `regrun` and `regrunservices` booleans control which keys are written
- **Masquerading**: Value name "Windows Update Manager" mimics legitimate Windows Update components
- **System-Wide Persistence**: `HKEY_LOCAL_MACHINE` requires elevated privileges but persists across all user accounts

**Redundancy Strategy:**

| Key Location | Execution Context | Removal Difficulty |
|--------------|-------------------|-------------------|
| `HKLM\...\Run` | System-wide (all users) | Medium (requires admin privileges to clean) |
| `HKLM\...\RunServices` | Service context (legacy) | High (rarely monitored, obsolete key) |
| `HKCU\...\Run` (variants) | Per-user | Low (user-accessible, frequently scanned) |

## Detection and Evasion

**Sysmon Detection Signatures:**

1. **Event ID 13** (Registry Value Set): Same process writing executable path to multiple autostart keys within 5 seconds
   - `HKLM\Software\Microsoft\Windows\CurrentVersion\Run\Windows Update Manager`
   - `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices\Windows Update Manager`

2. **Event ID 1** (Process Create): Execution at logon with parent process `explorer.exe` (Run key) or `services.exe` (RunServices key)

**Evasion Techniques:**

- **Legitimate Name Masquerading**: "Windows Update Manager" mimics genuine Windows Update components
- **Legacy Key Abuse**: `RunServices` key rarely monitored by modern AV/EDR (obsolete since Windows 2000)
- **Spatial Redundancy**: Multiple keys ensure survival if one location is cleaned
- **System-Level Keys**: `HKLM` hive requires admin tools for inspection, reducing visibility to non-admin users

**Behavioral Indicators:**

```
Process X writes to HKLM\...\Run\Windows Update Manager
AND
Process X writes to HKLM\...\RunServices\Windows Update Manager
WITHIN 5 seconds
= High-confidence redundant persistence installation
```

**YARA Rule:**

```yara
rule T1547_SdBot_Multi_Location_Persistence
{
    meta:
        description = "Detects SdBot/rBot multi-location Run key persistence strings"
        mitre_attack = "T1547.001"
        
    strings:
        $valuename = "Windows Update Manager" wide ascii
        $run_key = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide ascii
        $runservices_key = "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices" wide ascii
        $config_flag = "regrunservices" wide ascii
        
    condition:
        uint16(0) == 0x5A4D and all of them
}
```

## Mitigation

1. **Registry Monitoring**: Alert on simultaneous writes to multiple autostart keys by non-system processes
2. **Legitimate Name Validation**: Cross-reference "Windows Update Manager" entries against known good file hashes/paths (legitimate path: `C:\Windows\System32\wuauclt.exe`)
3. **Legacy Key Removal**: Disable `RunServices` key functionality via Group Policy on modern Windows systems
4. **Privilege Restriction**: Limit users' ability to write to `HKEY_LOCAL_MACHINE` hive (requires local administrator privileges)

**Key Differentiator**: SdBot's multi-location redundancy (2-3 registry keys) significantly increases persistence survivability compared to single-key techniques. Modern ransomware and botnets frequently adopt this approach, with some variants writing to 5+ autostart locations simultaneously.
