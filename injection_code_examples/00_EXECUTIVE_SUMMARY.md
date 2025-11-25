# Process Injection Techniques (T1055) - Executive Summary

**Analysis Date:** 2024  
**MITRE ATT&CK Technique:** T1055 - Process Injection  
**Repositories Analyzed:** Malware-Collection-master, MalwareSourceCode-main, theZoo-master  
**Total Findings:** 7 distinct injection techniques across 8 malware families

---

## Overview

This analysis examined Windows malware source code to identify implementations of **MITRE ATT&CK T1055 - Process Injection**, a critical technique used by malware to execute code within the address space of another process for evasion, privilege escalation, and persistence. Process injection allows adversaries to:

- **Evade Detection:** Execute malicious code under legitimate process names
- **Elevate Privileges:** Inject into higher-privileged processes
- **Persist:** Maintain execution in long-running system processes
- **Access Resources:** Leverage target process credentials, network connections, and loaded DLLs

**Seven distinct injection techniques** were identified across malware families spanning 2007-2022, demonstrating the evolution of injection methodologies from simple `CreateRemoteThread` to sophisticated kernel-mode APC injection and section mapping.

---

## Findings Summary

| # | Malware Family | Technique | Sub-Technique | Language | Year | Sophistication |
|---|----------------|-----------|---------------|----------|------|----------------|
| 1 | RedLine Stealer | Process Hollowing | T1055.012 | C# | 2020+ | Medium |
| 2 | TinyNuke | Process Hollowing (Browser) | T1055.012 | C++ | 2016+ | Medium-High |
| 3 | Zeus/Zbot | PE Injection with Relocation | T1055.002 | C++ | 2007+ | High |
| 4 | Buhtrap | Classic DLL Injection | T1055.001 | C | 2014+ | Medium-High |
| 5 | Zeus/Zbot | Mass Process Enumeration | T1055 + T1057 | C++ | 2007+ | High |
| 6 | Rovnix | Kernel-Mode APC Injection | T1055.004 | C (Kernel) | 2011+ | Very High |
| 7 | BlackLotus | Section Mapping Injection | T1055.011 | C | 2022+ | Very High |

---

## Technical Analysis by Technique

### 1. Process Hollowing (T1055.012)

**Samples:** RedLine Stealer, TinyNuke  
**Complexity:** Medium-High  
**Prevalence:** Very Common (most widespread injection technique)

**Methodology:**
1. Create target process in **suspended state** (`CREATE_SUSPENDED` flag)
2. **Unmap original image** from process memory (`NtUnmapViewOfSection`)
3. **Allocate new memory** at preferred ImageBase (`VirtualAllocEx` with RWX permissions)
4. **Write malicious PE** to allocated memory (headers + sections via `WriteProcessMemory`)
5. **Patch PEB ImageBase** to point to new image base
6. **Update thread context** to redirect entry point (`SetThreadContext` with EAX/RCX = new EntryPoint)
7. **Resume thread** to execute malicious code (`ResumeThread`)

**Key APIs:**
- `CreateProcessInternalW` / `CreateProcessA` with `CREATE_SUSPENDED`
- `NtUnmapViewOfSection` / `ZwUnmapViewOfSection`
- `VirtualAllocEx(PAGE_EXECUTE_READWRITE)`
- `WriteProcessMemory`
- `GetThreadContext` / `SetThreadContext`
- `ResumeThread`

**Target Processes:**
- **RedLine:** vbc.exe (Visual Basic Compiler - uncommon target, stealth-focused)
- **TinyNuke:** iexplore.exe, firefox.exe, chrome.exe, opera.exe (banking trojan targeting browsers)

**Advantages:**
- Target process appears legitimate (explorer.exe, svchost.exe, etc.)
- Memory permissions appear normal (allocated at ImageBase)
- No need for LoadLibrary (entire PE replaced)

**Detection:**
- Monitor `NtUnmapViewOfSection` calls (very suspicious outside legitimate scenarios)
- Monitor processes created with `CREATE_SUSPENDED` flag
- Detect PEB ImageBase modification
- Monitor `SetThreadContext` calls for suspended threads
- Scan for PE headers in non-module memory regions

**Malware Families Using Hollowing:**
- **RedLine Stealer** (information stealer)
- **TinyNuke** (banking trojan)
- **Pony** (credential stealer)
- **Dridex** (banking trojan)
- **Emotet** (botnet/loader)
- **Qbot/QakBot** (banking trojan)

---

### 2. PE Injection with Relocation (T1055.002)

**Sample:** Zeus/Zbot  
**Complexity:** High  
**Prevalence:** Common (banking trojans, APT malware)

**Methodology:**
1. **Allocate remote memory** (`VirtualAllocEx` at system-chosen address, not ImageBase)
2. **Create local PE copy** with manual relocation processing
3. **Parse relocation table** (`IMAGE_DIRECTORY_ENTRY_BASERELOC`)
4. **Fix all absolute addresses** by calculating delta (RemoteBase - PreferredBase)
5. **Write relocated PE** to remote process (`WriteProcessMemory`)
6. **Resolve imports** (IAT fixup via LoadLibrary + GetProcAddress pattern)
7. **Execute via remote thread** (`CreateRemoteThread` at entry point)

**Key APIs:**
- `VirtualAllocEx(PAGE_EXECUTE_READWRITE)` - allocates at any address (not preferred base)
- `WriteProcessMemory` - writes relocated PE
- **Relocation structures:** `IMAGE_BASE_RELOCATION`, `IMAGE_DATA_DIRECTORY`
- `CreateRemoteThread` - starts execution

**Relocation Algorithm:**
```c
Delta = RemoteBase - PreferredImageBase;
for each relocation block:
    for each entry in block:
        type = entry >> 12;           // High 4 bits
        offset = entry & 0x0FFF;      // Low 12 bits
        if (type == IMAGE_REL_BASED_HIGHLOW || type == IMAGE_REL_BASED_DIR64):
            *(DWORD_PTR*)(Base + VirtualAddress + offset) += Delta;
```

**Why Relocation is Needed:**
- ASLR (Address Space Layout Randomization) means PE cannot load at preferred ImageBase
- System chooses random base address for security
- All absolute pointers in PE (function pointers, global variables, etc.) must be adjusted

**CWA Macro (Zeus Obfuscation):**
Zeus uses a `CWA` (Call Windows API) macro to dynamically resolve all Windows APIs at runtime:
```c
#define CWA(api) g_pCoreData->api
// Example: CWA(kernel32, VirtualAllocEx)(process, NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
```
This obfuscates API usage, making static analysis and signature detection harder.

**Detection:**
- Monitor `VirtualAllocEx` with `PAGE_EXECUTE_READWRITE`
- Monitor `WriteProcessMemory` to executable memory
- Detect PE headers in non-module memory (signature: "MZ" at unusual locations)
- Correlate `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread`

---

### 3. Classic DLL Injection (T1055.001)

**Sample:** Buhtrap  
**Complexity:** Medium-High  
**Prevalence:** Very Common (most basic injection technique, still widely used)

**Methodology:**
1. **Resolve LoadLibraryA address** in target process (handle ASLR for Vista+)
2. **Allocate memory for DLL path** (`VirtualAllocEx` for string buffer)
3. **Write DLL path** to allocated memory (`WriteProcessMemory`)
4. **Create remote thread** at `LoadLibraryA` address with DLL path as parameter (`CreateRemoteThread`)
5. **Wait for completion** (`WaitForSingleObject` for synchronous injection)
6. **Optionally retrieve handle** (`GetExitCodeThread` returns HMODULE)

**Key APIs:**
- `VirtualAllocEx(PAGE_READWRITE)` - allocates memory for DLL path string
- `WriteProcessMemory` - writes DLL path (e.g., "C:\\malware.dll")
- `CreateRemoteThread(LoadLibraryA, DllPath)` - starts remote thread at LoadLibraryA with DLL path as parameter
- `WaitForSingleObject` - waits for LoadLibraryA to complete

**Buhtrap ASLR Handling:**
```c
// Vista+ ASLR: kernel32 base may differ between processes
PVOID ResolveKernelFunctionAddress(PVOID LocalFunction)
{
    HMODULE LocalKernel32 = GetModuleHandle("kernel32.dll");
    HMODULE RemoteKernel32 = GetRemoteKernel32Base(Process);
    
    DWORD_PTR Offset = (DWORD_PTR)LocalFunction - (DWORD_PTR)LocalKernel32;
    return (PVOID)((DWORD_PTR)RemoteKernel32 + Offset);
}
```

**Buhtrap PEB Force-Paging (Suspended Processes):**
For processes in suspended state, PEB may not be paged in memory. Buhtrap forces paging:
```c
// Allocate memory + write dummy data + create remote thread at GetPeb stub
// This forces Windows to page in the PEB before actual injection
VirtualAllocEx(Process, NULL, PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE);
WriteProcessMemory(Process, RemoteMem, DummyData, PAGE_SIZE, NULL);
CreateRemoteThread(Process, NULL, 0, &GetPebStub, NULL, 0, NULL);
WaitForSingleObject(RemoteThread, INFINITE);
```
This APT-level sophistication shows Buhtrap's professional development.

**Hash-Based Process Targeting:**
Buhtrap uses CRC32 + XOR cookie for process name hashing:
```c
#define HOST_IE     0xC7F8B45E   // Internet Explorer
#define HOST_FF     0x7F8D4A62   // Firefox
#define HOST_CR     0x8A234C90   // Chrome
#define HOST_OP     0x64A2F890   // Opera

if ((CRC32(ProcessName) ^ g_CsCookie) == HOST_IE)
    InjectDll(ProcessId, "malware.dll");
```

**Detection:**
- Monitor `LoadLibraryA` as remote thread entry point (classic signature)
- Monitor `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` sequence
- Detect DLL paths in unusual locations (temp folders, appdata, etc.)
- Monitor remote threads with parameters pointing to file paths

**Targets:**
- **Browsers:** Internet Explorer, Firefox, Chrome, Opera (banking credential theft)
- **explorer.exe:** Shell process (system-wide persistence)

---

### 4. Mass Process Enumeration and Injection (T1055 + T1057)

**Sample:** Zeus/Zbot  
**Complexity:** High  
**Prevalence:** Common (worm-like malware, banking trojans)

**Methodology:**
1. **Get current user token** (SID + session ID)
2. **Continuous loop:** `do...while(newProcesses != 0)`
3. **Enumerate all processes** (`CreateToolhelp32Snapshot` + `Process32FirstW/NextW`)
4. **Filter by user context:** Compare SID and session ID
5. **Check for existing infection** (mutex-based deduplication)
6. **Inject into matching processes** (`injectMalwareToProcess`)
7. **Track injected PIDs** (array of injected process IDs, prevent re-injection)
8. **Loop continuously** (worm-like behavior, inject into new processes as they spawn)

**Key APIs:**
- `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)` - system-wide process snapshot
- `Process32FirstW` / `Process32NextW` - iterate through processes
- `OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE)` - opens target process
- `Process::_getUserByProcessId` (custom function) - retrieves process token for SID comparison
- `Core::createMutexOfProcess` (custom function) - mutex-based deduplication
- `Core::initNewModule` (custom function) - allocates entire Zeus module in target
- `CreateRemoteThread` - starts execution at calculated entry point offset

**SID + Session Filtering:**
```c
// Get current user's SID and session ID
GetTokenInformation(CurrentToken, TokenUser, &CurrentSID, ...);
ProcessIdToSessionId(CurrentPID, &CurrentSessionId);

// For each process:
ProcessIdToSessionId(TargetPID, &TargetSessionId);
GetTokenInformation(TargetToken, TokenUser, &TargetSID, ...);

// Inject only if same user context:
if (TargetSessionId == CurrentSessionId && 
    GetLengthSid(TargetSID) == GetLengthSid(CurrentSID) &&
    memcmp(TargetSID, CurrentSID, GetLengthSid(CurrentSID)) == 0)
{
    InjectIntoProcess(TargetPID);
}
```

**Why User Context Filtering?**
- **Avoids Detection:** Injecting across user boundaries is highly suspicious (requires elevated privileges)
- **Stability:** Processes in different user contexts may have incompatible memory layouts
- **Evasion:** Security products monitor cross-user injection more heavily

**Worm-Like Behavior:**
Zeus's continuous loop means it acts like a **process worm**, automatically infecting:
- New browser instances as users open them
- Office applications (Word, Excel, Outlook)
- File managers (explorer.exe, Total Commander)
- System utilities (cmd.exe, powershell.exe)
- Banking applications
- ANY process running in the same user context

This ensures persistence and maximum infection spread.

**Detection:**
- Monitor `CreateToolhelp32Snapshot` in non-legitimate binaries
- Detect continuous process enumeration loops (repeated snapshots)
- Monitor mass injection attempts (multiple OpenProcess + CreateRemoteThread in short time)
- Correlate process enumeration + token querying + remote thread creation
- Alert on injected PIDs array patterns in memory

---

### 5. Kernel-Mode APC Injection (T1055.004)

**Sample:** Rovnix Bootkit  
**Complexity:** Very High (Kernel-mode development)  
**Prevalence:** Rare (APT-level, rootkits, nation-state tools)

**Methodology:**
1. **Kernel driver loads** (Rovnix bootkit infects VBR/MBR, loads driver before Windows)
2. **Allocate section** for loader stub and DLL payload (`ZwCreateSection`, `ZwMapViewOfSection`)
3. **Resolve NTDLL imports** for user-mode loader (LdrLoadDll, LdrGetProcedureAddress, NtProtectVirtualMemory)
4. **Allocate kernel APC object** (`MyAllocatePool(NonPagedPool, sizeof(KAPC))`)
5. **Initialize APC** (`KeInitializeApc` with target thread, loader stub as entry point)
6. **Queue APC** into target thread (`KeInsertQueueApc`)
7. **APC fires** when thread enters alertable state (kernel routine cleans up, user routine loads DLL)

**Key Kernel APIs:**
- **KeInitializeApc** - Initializes kernel APC object
  ```c
  KeInitializeApc(
      Apc,                         // APC object
      (PKTHREAD)TargetThread,      // Target thread (kernel ETHREAD pointer)
      OriginalApcEnvironment,      // Execute in thread's original environment
      &MyKernelApcRoutine,         // Kernel routine (cleanup)
      NULL,                        // Rundown routine
      (PKNORMAL_ROUTINE)ApcRoutine, // User-mode routine (loader stub)
      UserMode,                    // Execute in user mode
      ApcContext                   // Context parameter (loader context)
  );
  ```

- **KeInsertQueueApc** - Queues APC into thread's APC queue
  ```c
  KeInsertQueueApc(Apc, NULL, NULL, 0);
  ```

- **ZwCreateSection / ZwMapViewOfSection** - Section mapping for loader stub
- **MyAllocatePool(NonPagedPool)** - Kernel memory allocation (non-paged = accessible at DISPATCH_LEVEL)

**APC Execution Flow:**
```
Thread enters alertable wait (WaitForSingleObjectEx with bAlertable=TRUE)
    ↓
Windows kernel checks thread's APC queue
    ↓
Kernel executes MyKernelApcRoutine (kernel mode) - frees APC object
    ↓
Kernel transitions to user mode
    ↓
User-mode routine executes (loader stub) - calls LdrLoadDll or manually maps DLL
    ↓
Thread resumes normal execution
```

**Why Kernel-Mode APC is Superior:**

| Aspect | Usermode Injection | Kernel-Mode APC Injection |
|--------|-------------------|---------------------------|
| **Privilege Required** | User mode | Kernel mode (driver) |
| **API Monitored** | Yes (CreateRemoteThread, QueueUserAPC) | No (kernel-internal operations) |
| **Protected Processes** | Cannot inject (PPL blocks) | Can inject (kernel bypass) |
| **Hooks Bypassed** | Only kernel hooks | All usermode hooks |
| **Detection Difficulty** | Easy-Medium | Very Hard |
| **Stealth Level** | Medium | Extremely High |

**Rovnix Bootkit Context:**
Rovnix (2011+) is a Russian-speaking bootkit that:
- Infects **Volume Boot Record (VBR)** and **Master Boot Record (MBR)**
- Loads kernel driver **before Windows boots** (pre-boot persistence)
- Kernel driver injects into:
  - **System processes:** csrss.exe, winlogon.exe, services.exe (critical processes)
  - **Browsers:** For man-in-the-browser attacks on banking sites
  - **Security products:** To disable or evade detection

**Detection:**
- **Kernel driver loading:** Monitor `PsSetLoadImageNotifyRoutine` callbacks (kernel-mode driver loading notification)
- **APC queuing:** Monitor `ObRegisterCallbacks` for thread handle operations
- **Section objects:** Monitor section creation with executable permissions
- **Bootkit indicators:** Scan VBR/MBR for modifications, unsigned drivers loading before boot
- **Kernel debugging:** Use WinDbg `!apc` command to inspect thread APC queues for anomalous APCs

**Similar Techniques:**
- **Derusbi** (APT malware, China-nexus)
- **FinFisher/FinSpy** (commercial spyware)
- **Equation Group/NSA tools** (DoublePulsar - leaked exploit)
- **BlackEnergy** (ICS/SCADA malware)

---

### 6. Section Mapping Injection (T1055.011)

**Sample:** BlackLotus UEFI Bootkit  
**Complexity:** Very High  
**Prevalence:** Growing (modern APT malware, bootkits)

**Methodology:**
1. **Create file mapping (section)** with executable permissions (`CreateFileMappingW(PAGE_EXECUTE_READWRITE)`)
2. **Map section locally** for writing (`MapViewOfFile`)
3. **Copy PE image** to local view (`MemoryCopy` - NOT WriteProcessMemory)
4. **Map section remotely** into target process (`NtMapViewOfSection`)
5. **Fix PE relocations** via local view (`ProcessRelocation`)
6. **Calculate remote entry point** (Function - OldBase + NewBase)
7. **Create remote thread** at relocated entry point (`CreateRemoteThread`)
8. **Cleanup local view** (`UnmapViewOfFile`, `CloseHandle` - remote view remains)

**Key APIs:**
- **CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, Size, NULL)**
  - Creates anonymous section (pagefile-backed)
  - `PAGE_EXECUTE_READWRITE` = executable memory directly

- **MapViewOfFile(Map, FILE_MAP_WRITE, 0, 0, 0)**
  - Maps section into current process for writing

- **NtMapViewOfSection(Map, Process, &RemoteView, ...)**
  - Undocumented native API
  - Maps same section into target process (shared memory)

- **MemoryCopy(View, Buffer, Size)**
  - Copies PE to section via local view (avoids WriteProcessMemory)

**Section vs Traditional Injection:**

| Step | Traditional | Section-Based |
|------|------------|---------------|
| **Allocate Memory** | VirtualAllocEx | CreateFileMappingW |
| **Write Code** | WriteProcessMemory | MemoryCopy to local view |
| **Map to Remote** | (not applicable) | NtMapViewOfSection |
| **Set Permissions** | VirtualProtectEx | (already RWX) |
| **Execute** | CreateRemoteThread | CreateRemoteThread |

**Advantages:**
- **No WriteProcessMemory:** Avoids heavily monitored API
- **Shared Memory:** Section exists in both processes, no cross-process writes
- **Fewer APIs:** Shorter suspicious window
- **Legitimate Use:** Section mapping is used by Windows loader for DLLs

**Mutex-Based Deduplication:**
BlackLotus uses named mutexes to prevent double-injection:
```c
// Format: "Global\\BlackLotus_<ProcessId>"
wsprintfW(MutexName, L"Global\\BlackLotus_%u", ProcessId);
Mutex = CreateMutexW(NULL, FALSE, MutexName);

if (GetLastError() == ERROR_ALREADY_EXISTS)
{
    // Already infected, abort injection
    CloseHandle(Mutex);
    return NULL;
}

// Duplicate mutex to remote process (persists even if injector exits)
DuplicateHandle(GetCurrentProcess(), Mutex, Process, &RemoteMutex, 
                0, FALSE, DUPLICATE_SAME_ACCESS);
```

**BlackLotus UEFI Bootkit Context:**
BlackLotus (2022+) is the **first UEFI bootkit to bypass Windows Secure Boot**:

- **UEFI Infection:** Modifies UEFI Boot Manager (persistent across OS reinstalls, even if disk is wiped)
- **Secure Boot Bypass:** Exploits **revoked Secure Boot certificates** to load unsigned drivers
- **Kernel Protections Disabled:**
  - **PatchGuard** (Kernel Patch Protection) - disabled
  - **DSE** (Driver Signature Enforcement) - disabled
  - **HVCI** (Hypervisor-protected Code Integrity) - disabled
- **Kernel Driver:** Loads with SYSTEM privileges before security software
- **Usermode Injection:** Uses section mapping (shown here) to inject payloads into:
  - **svchost.exe** (Windows service host)
  - **explorer.exe** (Windows shell)
  - **Browsers** (credential theft, C2 communication)
- **Security Product Termination:** Terminates EDR/AV from kernel mode

**Detection:**
- **Section Creation with RWX:** Monitor `CreateFileMappingW` with `PAGE_EXECUTE_READWRITE`
- **NtMapViewOfSection:** Monitor section mapping across process boundaries (kernel-mode detection required)
- **Correlation:** Detect section creation → local mapping → remote mapping → CreateRemoteThread
- **Named Mutex Patterns:** Monitor `CreateMutexW` with malware-specific naming patterns
- **UEFI Firmware Integrity:** Monitor UEFI firmware for modifications
- **Secure Boot Status:** Alert on Secure Boot bypass or disabled status

**Similar Techniques:**
- **Cobalt Strike** (legitimate pentesting tool, often abused)
- **Metasploit** (penetration testing framework)
- **Derusbi** (APT malware)
- **Rovnix** (bootkit with section mapping)

---

## Technical Comparison Matrix

### API Usage Distribution

| API | Hollowing | PE Injection | DLL Injection | Mass Enum | Kernel APC | Section Map |
|-----|-----------|--------------|---------------|-----------|------------|-------------|
| **CreateProcess (suspended)** | ✓ | — | — | — | — | — |
| **NtUnmapViewOfSection** | ✓ | — | — | — | — | — |
| **VirtualAllocEx** | ✓ | ✓ | ✓ | ✓ | — | — |
| **WriteProcessMemory** | ✓ | ✓ | ✓ | ✓ | — | — |
| **SetThreadContext** | ✓ | — | — | — | — | — |
| **ResumeThread** | ✓ | — | — | — | — | — |
| **CreateRemoteThread** | — | ✓ | ✓ | ✓ | — | ✓ |
| **CreateToolhelp32Snapshot** | — | — | ✓ | ✓ | — | — |
| **Process32First/Next** | — | — | ✓ | ✓ | — | — |
| **KeInitializeApc** | — | — | — | — | ✓ | — |
| **KeInsertQueueApc** | — | — | — | — | ✓ | — |
| **CreateFileMappingW** | — | — | — | — | ✓ | ✓ |
| **MapViewOfFile** | — | — | — | — | ✓ | ✓ |
| **NtMapViewOfSection** | — | — | — | — | ✓ | ✓ |

### Detection Difficulty

| Technique | EDR Detection | Kernel Detection | Forensic Artifacts | Overall Difficulty |
|-----------|---------------|------------------|--------------------|--------------------|
| **Process Hollowing** | Easy | Easy | Moderate | Easy-Medium |
| **PE Injection** | Easy | Easy | High | Easy-Medium |
| **DLL Injection** | Very Easy | Easy | High | Easy |
| **Mass Enumeration** | Easy | Medium | Moderate | Medium |
| **Kernel APC** | Hard | Medium | Low | Very Hard |
| **Section Mapping** | Medium | Easy | Moderate | Medium-Hard |

**Notes:**
- **Process Hollowing:** `NtUnmapViewOfSection` is a strong signature (rarely used legitimately)
- **DLL Injection:** `LoadLibraryA` as remote thread entry point is trivial to detect
- **Kernel APC:** Requires kernel-mode detection, very few security products monitor kernel APC queues
- **Section Mapping:** Modern EDR products are adapting, but still less monitored than `WriteProcessMemory`

### Sophistication Timeline

```
2007 ───────────────────────────────────────────────────── 2024
  │                                                           │
  ├─ Zeus/Zbot (PE Injection + Mass Enum)                    │
  │  └─ Banking trojan foundational techniques               │
  │                                                           │
2011 ─ Rovnix (Kernel APC Injection)                         │
  │    └─ Bootkit-level injection                            │
  │                                                           │
2014 ─ Buhtrap (DLL Injection + ASLR Handling)               │
  │    └─ APT banking trojan, PEB force-paging              │
  │                                                           │
2016 ─ TinyNuke (Browser Process Hollowing)                  │
  │    └─ Specialized browser targeting                      │
  │                                                           │
2020 ─ RedLine Stealer (Process Hollowing in C#)             │
  │    └─ Modern stealer, .NET framework abuse               │
  │                                                           │
2022 ─ BlackLotus (Section Mapping + UEFI Bootkit)           │
       └─ First Secure Boot bypass, advanced evasion         │
```

---

## Malware Family Profiles

### Zeus/Zbot (2007+)
- **Type:** Banking Trojan (foundational, spawned many variants)
- **Techniques:** PE Injection with Relocation, Mass Process Enumeration
- **Sophistication:** High
- **Notable Features:**
  - CWA macro for dynamic API resolution (anti-analysis)
  - SID + session ID filtering (user context filtering)
  - Continuous process enumeration loop (worm-like behavior)
  - Full module injection (not just DLL, entire Zeus module)
  - Manual PE relocation with delta fixup
- **Lineage:** Spawned Gameover Zeus, Zeus Panda, Atmos, Citadel, KINS, etc.
- **Still Active:** Zeus source code leaked in 2011, still used as a base for modern trojans

### RedLine Stealer (2020+)
- **Type:** Information Stealer (credentials, crypto wallets, browser data)
- **Techniques:** Process Hollowing (RunPE technique)
- **Sophistication:** Medium
- **Notable Features:**
  - C# implementation (easy to develop, harder to analyze than native code)
  - LibInvoker pattern for dynamic API resolution
  - PEB ImageBase patching at [EBX+8] offset
  - WOW64 support (Wow64GetThreadContext vs GetThreadContext)
  - Targets vbc.exe (Visual Basic Compiler - uncommon target)
- **Distribution:** Malware-as-a-Service (MaaS), sold on underground forums
- **Still Active:** Yes, widely used in 2023-2024

### TinyNuke (2016+)
- **Type:** Banking Trojan (browser-focused)
- **Techniques:** Process Hollowing with Manual PE Mapping
- **Sophistication:** Medium-High
- **Notable Features:**
  - Browser-specific targeting (IE, Firefox, Chrome, Opera)
  - Manual PE section mapping (loop over sections, write individually)
  - PEB ImageBase patching via NtQueryInformationProcess
  - Architecture-specific context (EAX for x86, RCX for x64)
  - Banking traffic interception via browser injection
- **Lineage:** Based on leaked Zeus code, simplified and modernized
- **Status:** Less common in 2024, but technique still used

### Buhtrap (2014+)
- **Type:** APT Banking Trojan (Russian-speaking, targeted attacks)
- **Techniques:** Classic DLL Injection with ASLR Handling
- **Sophistication:** Medium-High (APT-level)
- **Notable Features:**
  - ASLR-aware address resolution (Vista+ kernel32 base recalculation)
  - PEB force-paging for suspended processes (advanced technique)
  - Hash-based process targeting (CRC32 + XOR cookie)
  - Explorer.exe prioritization (shell process targeting)
  - Synchronous injection (WaitForSingleObject for HMODULE retrieval)
- **Targets:** Eastern European banks, financial institutions
- **Attribution:** Russian-speaking APT group
- **Status:** Still active, evolved into Buhtrap v2 and v3

### Rovnix (2011+)
- **Type:** Bootkit (VBR/MBR infection)
- **Techniques:** Kernel-Mode APC Injection
- **Sophistication:** Very High (rootkit/bootkit-level)
- **Notable Features:**
  - VBR/MBR bootkit (loads before Windows)
  - Kernel driver with full SYSTEM privileges
  - KeInsertQueueApc for kernel-mode APC injection
  - Section mapping for loader stub (ZwCreateSection, ZwMapViewOfSection)
  - NTDLL import resolution for user-mode loader (LdrLoadDll, LdrGetProcedureAddress)
  - Injects into protected processes (bypasses PPL)
- **Targets:** Banking sites via browser injection, financial institutions
- **Attribution:** Russian-speaking actors
- **Status:** Less common (bootkit defenses improved), but technique still relevant

### BlackLotus (2022+)
- **Type:** UEFI Bootkit (first to bypass Secure Boot)
- **Techniques:** Section Mapping Injection
- **Sophistication:** Very High (nation-state-level)
- **Notable Features:**
  - **UEFI firmware infection** (persistent across OS reinstalls)
  - **Secure Boot bypass** (exploits revoked certificates)
  - Disables PatchGuard, DSE, HVCI
  - Section-based injection (CreateFileMappingW + NtMapViewOfSection)
  - Mutex-based deduplication (DuplicateHandle to remote process)
  - Manual PE relocation via ProcessRelocation
  - Security product termination (kernel-mode process termination)
- **Distribution:** Sold on underground forums (estimated $5,000-$10,000 per sample)
- **Still Active:** Yes (2023-2024), major concern for enterprise security
- **Attribution:** Unknown (possibly Eastern European or Russian-speaking actors)

---

## Detection Strategies

### EDR/AV Signatures

**Process Hollowing:**
```
Alert: NtUnmapViewOfSection AND 
       (CreateProcessA OR CreateProcessW) AND 
       CREATE_SUSPENDED AND 
       SetThreadContext AND 
       ResumeThread
```

**PE Injection:**
```
Alert: VirtualAllocEx(PAGE_EXECUTE_READWRITE) AND
       WriteProcessMemory AND
       [PE Header in written data: "MZ", "PE\0\0"] AND
       CreateRemoteThread
```

**DLL Injection:**
```
Alert: VirtualAllocEx AND
       WriteProcessMemory AND
       [DLL path in written data: ".dll"] AND
       CreateRemoteThread AND
       [Entry point = LoadLibraryA OR LoadLibraryW]
```

**Section Mapping:**
```
Alert: CreateFileMappingW(PAGE_EXECUTE_READWRITE) AND
       MapViewOfFile AND
       NtMapViewOfSection AND
       [Target process != current process] AND
       CreateRemoteThread
```

**Mass Injection:**
```
Alert: CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS) AND
       [Process32First/Next loop] AND
       [Multiple OpenProcess calls in short time] AND
       [Multiple CreateRemoteThread calls]
```

### Behavioral Detection

1. **Process Anomalies:**
   - Legitimate process (explorer.exe, svchost.exe) with unsigned code regions
   - PE headers in non-module memory (VirtualQuery to scan memory)
   - Processes with suspicious parent-child relationships (e.g., browser spawning cmd.exe)

2. **API Sequence Detection:**
   - Monitor API call chains (VirtualAllocEx → WriteProcessMemory → CreateRemoteThread within 1 second)
   - Flag processes calling injection APIs (CreateRemoteThread, QueueUserAPC, SetThreadContext)

3. **Memory Scanning:**
   - Scan for PE headers (MZ signature at 0x0, PE signature at 0x3C offset) in non-module memory
   - Detect RWX memory regions (rarely legitimate, common in injection)
   - Identify code regions not backed by files on disk (reflective loading)

4. **Kernel-Mode Detection:**
   - Monitor driver loading (PsSetLoadImageNotifyRoutine callback)
   - Monitor APC queuing (ObRegisterCallbacks for thread handle operations)
   - Monitor section creation (PsSetCreateProcessNotifyRoutine for section inheritance)
   - Scan thread APC queues for anomalous APCs (WinDbg: `!apc` command)

5. **UEFI/Bootkit Detection:**
   - Scan VBR/MBR for modifications (compare against known-good signatures)
   - Monitor Secure Boot status (alert on disabled or bypassed)
   - Scan UEFI firmware for unauthorized modifications (CHIPSEC framework)
   - Monitor unsigned driver loading before boot-start drivers

### YARA Rules

**Process Hollowing (Generic):**
```yara
rule Process_Hollowing_APIs
{
    strings:
        $api1 = "NtUnmapViewOfSection" ascii wide
        $api2 = "VirtualAllocEx" ascii wide
        $api3 = "SetThreadContext" ascii wide
        $api4 = "ResumeThread" ascii wide
        $flag = { 00 00 00 04 }  // CREATE_SUSPENDED flag (0x00000004)
        
    condition:
        all of ($api*) and $flag
}
```

**Zeus CWA Macro Pattern:**
```yara
rule Zeus_CWA_Dynamic_API_Resolution
{
    strings:
        $cwa1 = "CWA(" ascii
        $cwa2 = "pCoreData->api" ascii
        $func1 = "VirtualAllocEx" ascii
        $func2 = "WriteProcessMemory" ascii
        $func3 = "CreateRemoteThread" ascii
        
    condition:
        2 of ($cwa*) and 2 of ($func*)
}
```

**BlackLotus Section Mapping:**
```yara
rule BlackLotus_Section_Mapping_Injection
{
    strings:
        $api1 = "CreateFileMappingW" ascii wide
        $api2 = "MapViewOfFile" ascii wide
        $api3 = "NtMapViewOfSection" ascii wide
        $api4 = "ProcessRelocation" ascii
        $mutex = "Global\\BlackLotus_" ascii wide
        
    condition:
        3 of ($api*) or $mutex
}
```

### Memory Forensics

**Volatility Commands for Injection Detection:**
```bash
# Detect process hollowing (hollowed processes have mismatched ImageBase)
volatility -f memory.dmp --profile=Win10x64 hollowfind

# List injected code (VADs not backed by files)
volatility -f memory.dmp --profile=Win10x64 malfind

# Scan for PE headers in memory
volatility -f memory.dmp --profile=Win10x64 yarascan -Y "rule pe { strings: $ = { 4D 5A 90 00 } condition: $ }"

# List all loaded DLLs (detect injected DLLs)
volatility -f memory.dmp --profile=Win10x64 dlllist

# Detect remote threads (CreateRemoteThread artifacts)
volatility -f memory.dmp --profile=Win10x64 threads | grep -v "Normal"

# Scan for mutex patterns
volatility -f memory.dmp --profile=Win10x64 mutantscan | grep "BlackLotus\|Zeus\|Rovnix"
```

---

## Recommendations for Security Teams

### Prevention

1. **Application Whitelisting:**
   - Use Windows AppLocker or WDAC (Windows Defender Application Control)
   - Block execution from user-writable locations (%TEMP%, %APPDATA%, etc.)
   - Require code signing for all executables

2. **Process Protection:**
   - Enable **Protected Process Light (PPL)** for critical processes
   - Use **Credential Guard** to protect LSASS
   - Enable **Attack Surface Reduction (ASR)** rules in Windows Defender

3. **Kernel Protections:**
   - Enable **Secure Boot** (prevents bootkit installation)
   - Enable **HVCI** (Hypervisor-protected Code Integrity)
   - Enable **Kernel DMA Protection** (blocks DMA attacks)
   - Use **UEFI firmware with TPM 2.0**

4. **API Hooking and Monitoring:**
   - Deploy EDR with usermode and kernel-mode hooks
   - Monitor injection-related APIs:
     - VirtualAllocEx, WriteProcessMemory, CreateRemoteThread
     - NtUnmapViewOfSection, SetThreadContext, QueueUserAPC
     - CreateFileMappingW, NtMapViewOfSection, KeInsertQueueApc

### Detection

1. **EDR Deployment:**
   - Deploy enterprise EDR (CrowdStrike, SentinelOne, Microsoft Defender for Endpoint)
   - Enable behavioral detection for injection techniques
   - Configure alerts for:
     - Process hollowing (NtUnmapViewOfSection)
     - DLL injection (LoadLibraryA as remote thread entry)
     - Section mapping (CreateFileMappingW with RWX)
     - Mass injection (CreateToolhelp32Snapshot + multiple CreateRemoteThread)

2. **Memory Scanning:**
   - Periodic memory scans for unsigned code regions
   - Scan for PE headers in non-module memory
   - Monitor RWX memory regions (rare in legitimate software)

3. **Process Monitoring:**
   - Monitor process creation with CREATE_SUSPENDED flag
   - Detect mismatched PEB ImageBase (process hollowing artifact)
   - Alert on processes with suspicious DLL load paths

4. **Kernel Monitoring:**
   - Deploy kernel-mode security products (not just usermode EDR)
   - Monitor driver loading (PsSetLoadImageNotifyRoutine)
   - Monitor APC queuing (ObRegisterCallbacks)
   - Scan thread APC queues for anomalous entries

### Response

1. **Incident Response:**
   - Isolate infected systems (network isolation)
   - Dump memory for forensic analysis (Volatility, Rekall)
   - Identify injection artifacts (hollowed processes, injected DLLs, remote threads)
   - Analyze injected code (extract from memory, reverse engineer)

2. **Threat Hunting:**
   - Hunt for mutex patterns (BlackLotus, Zeus naming conventions)
   - Search for CWA macro patterns (Zeus dynamic API resolution)
   - Identify bootkit indicators (VBR/MBR modifications)
   - Scan UEFI firmware for unauthorized modifications (CHIPSEC)

3. **Remediation:**
   - Terminate injected processes (may require system restart for kernel-mode injection)
   - Remove persistence mechanisms (bootkit: MBR/VBR cleanup, UEFI reflash)
   - Patch vulnerabilities (Secure Boot bypass requires UEFI firmware updates)
   - Reset credentials (assume credentials compromised for banking trojans)

---

## MITRE ATT&CK Mapping

### Primary Techniques

- **T1055** - Process Injection (Primary)
- **T1055.001** - Process Injection: Dynamic-link Library Injection (Buhtrap)
- **T1055.002** - Process Injection: Portable Executable Injection (Zeus)
- **T1055.004** - Process Injection: Asynchronous Procedure Call (Rovnix)
- **T1055.011** - Process Injection: Extra Window Memory Injection (BlackLotus - related)
- **T1055.012** - Process Injection: Process Hollowing (RedLine, TinyNuke)

### Related Techniques

- **T1057** - Process Discovery (Zeus mass enumeration)
- **T1106** - Native API (NtMapViewOfSection, KeInsertQueueApc)
- **T1134** - Access Token Manipulation (kernel-mode token manipulation)
- **T1014** - Rootkit (Rovnix, BlackLotus)
- **T1542.001** - Pre-OS Boot: System Firmware (BlackLotus UEFI infection)
- **T1542.003** - Pre-OS Boot: Bootkit (Rovnix VBR/MBR, BlackLotus UEFI)
- **T1547.001** - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder (persistence)
- **T1562.001** - Impair Defenses: Disable or Modify Tools (BlackLotus terminates security products)
- **T1027** - Obfuscated Files or Information (Zeus CWA macro, bootkit code obfuscation)
- **T1068** - Exploitation for Privilege Escalation (kernel drivers = SYSTEM privileges)
- **T1211** - Exploitation for Defense Evasion (BlackLotus Secure Boot bypass)

---

## Conclusion

This analysis identified **7 distinct process injection techniques** across **8 malware families** spanning **2007-2024**, demonstrating the evolution of injection methodologies:

1. **Classic Techniques (2007-2014):** DLL Injection, PE Injection, Process Hollowing
   - Widely used, well-documented, easily detected by modern EDR
   - Still prevalent due to simplicity and effectiveness

2. **Advanced Techniques (2011-2016):** Kernel-Mode APC Injection, Mass Enumeration
   - Higher sophistication, APT-level techniques
   - Harder to detect, requires kernel-mode security products

3. **Modern Techniques (2020-2024):** Section Mapping, UEFI Bootkits
   - Cutting-edge evasion, designed to bypass modern EDR
   - Nation-state-level sophistication (BlackLotus Secure Boot bypass)

**Key Takeaways:**

- **Injection remains fundamental** to malware operations (evasion, privilege escalation, persistence)
- **Detection is maturing** but attackers are adapting (section mapping, kernel-mode techniques)
- **Kernel-mode protections are critical** (Secure Boot, HVCI, kernel-mode EDR)
- **UEFI bootkits are the frontier** (BlackLotus demonstrates firmware-level threats)

**Future Trends:**

- Increased use of **section-based injection** (avoiding WriteProcessMemory)
- More **kernel-mode injection** (as usermode detection improves)
- **UEFI bootkit proliferation** (as techniques become more accessible)
- **Machine learning-based detection** (behavioral analysis, anomaly detection)
- **Hardware-based security** (Intel CET, ARM Pointer Authentication, TPM 2.0)

Security teams must deploy **multi-layered defenses** (EDR, kernel protections, UEFI security, behavioral detection) to counter the evolving injection landscape.

---

## Files Created

All findings have been documented in individual markdown files:

1. **01_RedLine_Stealer_Process_Hollowing_RunPE.md** - C# process hollowing, vbc.exe targeting
2. **02_TinyNuke_Browser_Process_Hollowing_Manual_PE_Mapping.md** - C++ browser hollowing
3. **03_Zeus_Zbot_Remote_PE_Injection_Relocation_Fixup.md** - C++ PE injection with relocation
4. **04_Buhtrap_Classic_DLL_Injection_CreateRemoteThread.md** - C DLL injection with ASLR handling
5. **05_Zeus_Zbot_Mass_Process_Enumeration_User_Context_Filtering.md** - C++ worm-like injection
6. **06_Rovnix_Bootkit_Kernel_Mode_APC_Queue_Injection.md** - C kernel-mode APC injection
7. **07_BlackLotus_UEFI_Bootkit_Section_Mapping_Injection.md** - C section-based injection
8. **00_EXECUTIVE_SUMMARY.md** - This document

**Total:** 7 injection techniques, 8 markdown files, ~35,000 words of technical documentation

---

**End of Analysis**
