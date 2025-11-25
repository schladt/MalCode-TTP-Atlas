# Rovnix Bootkit - Kernel-Mode APC Queue Injection

**Repository:** Malware-Collection-master (also in MalwareSourceCode-main/Bootkit.Rovnix)  
**File Path:** Rovnix/KLoader/kloader.c  
**Language:** C (Kernel Mode)  
**MITRE ATT&CK:** T1055.004 - Process Injection: Asynchronous Procedure Call

---

## Overview

Rovnix (a sophisticated Russian bootkit) implements **kernel-mode APC (Asynchronous Procedure Call) injection** to inject code into user-mode processes from kernel space. Operating from a kernel driver, Rovnix queues APCs directly into target threads using undocumented Windows kernel APIs (`KeInitializeApc`, `KeInsertQueueApc`). This allows stealthy injection bypassing all userland security hooks and protections.

---

## Code Snippet 1: Kernel APC Initialization and Queuing

```c
//
// Queues loader APC (Asynchronous Procedure Call) injection
BOOL KldrQueueApc(
	PETHREAD	TargetThread,      // Target thread (kernel mode ETHREAD pointer)
	PVOID		ApcRoutine,        // User-mode routine to execute
	PVOID		ApcContext,        // Context parameter (our loader context)
	BOOL		IsWow64            // Is target a WoW64 process?
)
{
	PKAPC	Apc;
	BOOL	Ret = FALSE;
	LARGE_INTEGER Period = {0};   // Zero timeout for immediate delay

	// Allocate non-paged memory for APC object (must be non-paged since APCs can run at DISPATCH_LEVEL)
	if (Apc = MyAllocatePool(NonPagedPool, sizeof(KAPC)))
	{
		// Initialize the APC object
		KeInitializeApc(
			Apc,                         // APC object to initialize
			(PKTHREAD)TargetThread,      // Target thread (kernel KTHREAD pointer)
			OriginalApcEnvironment,      // Execute in thread's original environment
			&MyKernelApcRoutine,         // Kernel APC routine (cleanup function)
			NULL,                        // Rundown routine (not used)
			(PKNORMAL_ROUTINE)ApcRoutine, // Normal (user-mode) routine to execute
			UserMode,                    // Execute in user mode (not kernel mode)
			ApcContext                   // Context parameter passed to user routine
		); 
						
		// Insert APC into target thread's APC queue
		// APC will execute when thread next enters alertable wait state
		if ((Ret = KeInsertQueueApc(Apc, NULL, NULL, 0)) && !IsWow64)
		{
			// For native (non-WoW64) processes, delay to ensure APC executes
			// WoW64 processes have different APC delivery semantics, so we skip the delay
			KeDelayExecutionThread(UserMode, TRUE, &Period);
		}
			
	}  // if (Apc = MyAllocatePool...

	return(Ret);
}
```

**What it does:**  
Allocates and initializes a **Kernel APC (KAPC) object**, then queues it into a target thread using undocumented Windows kernel APIs:

1. **Allocates Non-Paged Memory:** Uses `MyAllocatePool(NonPagedPool, ...)` to allocate memory for the APC object. Non-paged memory is required because APCs can execute at elevated IRQL (DISPATCH_LEVEL) where paged memory cannot be accessed.

2. **Initializes APC Object:** Calls **KeInitializeApc** with critical parameters:
   - **TargetThread (PKTHREAD):** Kernel pointer to the target thread's ETHREAD/KTHREAD structure
   - **OriginalApcEnvironment:** Execute APC in the thread's original environment (not attached process)
   - **MyKernelApcRoutine:** Kernel-mode APC routine for cleanup (frees APC object)
   - **NormalRoutine (ApcRoutine):** **User-mode routine to execute** (the injected code)
   - **UserMode:** APC will transition to user mode before executing `ApcRoutine`
   - **ApcContext:** Parameter passed to the user-mode routine (contains loader context)

3. **Queues APC:** Calls **KeInsertQueueApc** to insert the APC into the target thread's APC queue. The APC will execute when the thread:
   - Enters an **alertable wait state** (e.g., `WaitForSingleObjectEx` with `bAlertable=TRUE`)
   - Returns from kernel mode to user mode
   - Checks its APC queue during normal thread scheduling

4. **Delays Execution (Native Processes):** For non-WoW64 processes, calls `KeDelayExecutionThread` with zero timeout to yield execution, giving the target thread time to process the APC.

**Why it's T1055.004 (APC Injection):**  
This is **pure kernel-mode APC injection**, one of the most sophisticated injection techniques:

- **Kernel-Level Access:** Operating from a kernel driver, Rovnix bypasses all userland protections (hooks, process protection, API monitoring)
- **Direct Thread Manipulation:** Directly accesses kernel thread structures (ETHREAD/KTHREAD) to queue APCs
- **Stealthy Execution:** APCs execute asynchronously when threads enter alertable states, appearing as normal thread activity
- **No Remote Thread:** Unlike CreateRemoteThread, APC injection uses the target's own threads, avoiding suspicious remote thread creation
- **Bypasses PPL/Protected Processes:** Kernel drivers can inject into protected processes (Protected Process Light) that usermode code cannot touch

**Technical Deep Dive:**

**KAPC Structure:**
```c
typedef struct _KAPC {
    UCHAR Type;                 // KAPC object type
    UCHAR SpareByte0;
    UCHAR Size;                 // sizeof(KAPC)
    UCHAR SpareByte1;
    ULONG SpareLong0;
    PKTHREAD Thread;            // Target thread
    LIST_ENTRY ApcListEntry;    // List entry in thread's APC queue
    PKKERNEL_ROUTINE KernelRoutine;     // Kernel-mode routine
    PKRUNDOWN_ROUTINE RundownRoutine;   // Rundown routine
    PKNORMAL_ROUTINE NormalRoutine;     // User-mode routine
    PVOID NormalContext;        // Context for NormalRoutine
    PVOID SystemArgument1;      // System argument 1
    PVOID SystemArgument2;      // System argument 2
    CCHAR ApcStateIndex;        // APC state index
    KPROCESSOR_MODE ApcMode;    // UserMode or KernelMode
    BOOLEAN Inserted;           // Is APC inserted in queue?
} KAPC, *PKAPC;
```

**APC Execution Flow:**
1. Kernel inserts APC into thread's APC queue via `KeInsertQueueApc`
2. Thread enters alertable wait or returns from kernel mode
3. Windows kernel checks thread's APC queue
4. If APCs present, kernel executes **kernel routine** (cleanup)
5. Kernel transitions to user mode and executes **normal routine** (injected code)
6. Thread resumes normal execution

---

## Code Snippet 2: Loader Context Allocation with Section Mapping

```c
//
// Allocates and initializes loader context (stub + DLL path/buffer)
PLOADER_CONTEXT LoaderAllocateContext(HANDLE ProcessId, PINJECT_DESCRIPTOR InjDesc, BOOL IsWow64)
{
	PLOADER_CONTEXT	LdrCtx = NULL;
	ULONG_PTR	ImageBase = 0;
	ULONGLONG	SectionSize, SizeOfImage;
	PVOID		CurrentStub = IsWow64 ? &LoaderStubWow64 : &LoaderStubX64;
	HANDLE		hSection;
	NTSTATUS	ntStatus;

	// ... initialization ...

	// Section mapping injection technique
	// Create a section (memory-mapped object) for the loader code
	if (ImageBase = LoaderAllocateSection(bSize))
	{
		// Copy loader stub to allocated section
		LdrCtx = (PLOADER_CONTEXT)(ImageBase + SizeOfImage);

		RtlCopyMemory(&LdrCtx->LoaderStub, CurrentStub, LOADER_STUB_MAX);
		LdrCtx->uDllPath.Buffer = (PWSTR)&LdrCtx->wDllPath;
		LdrCtx->Flags = InjDesc->Flags;

		KdPrint(("KLDR: Loader stub for process %x located at 0x%p\\n", ProcessId, &LdrCtx->LoaderStub));

		if (InjDesc->Flags & INJECT_SPECIFIED_MODULE)
		{
			// Injecting from a file: copy DLL path
			RtlCopyMemory(&LdrCtx->wDllPath, InjDesc->InjectModulePath->Buffer, InjDesc->InjectModulePath->Length);
			LdrCtx->uDllPath.Length = InjDesc->InjectModulePath->Length;
			LdrCtx->uDllPath.MaximumLength = InjDesc->InjectModulePath->Length;
			LdrCtx->wDllPath[LdrCtx->uDllPath.Length/sizeof(WCHAR)] = 0;
		}
		else
		{
			// Injecting from a buffer: copy entire DLL module
			LdrCtx->ImageBase = (ULONGLONG)ImageBase;

			// Initialize PE image in the section
			if (!LoaderBuildImage(ImageBase, InjDesc->InjectModuleBuffer))
			{
				// Failed to build image, unmap section
				ZwUnmapViewOfSection(NtCurrentProcess(), ImageBase);
				LdrCtx = NULL;
			}
		}
	}  // if (ImageBase = LoaderAllocateSection(bSize))
	
	return(LdrCtx);
}
```

**What it does:**  
Allocates memory for the **loader stub** and **injection payload** using **section mapping** (shared memory):

1. **Section Allocation:** Calls `LoaderAllocateSection` which creates a **section object** (memory-mapped region) using `ZwCreateSection` and `ZwMapViewOfSection`. Sections are shared memory regions that can be mapped into multiple processes.

2. **Loader Stub Copy:** Copies the loader stub (architecture-specific: x64 or WoW64) into the section. The loader stub is shellcode that will execute in user mode to load the final DLL.

3. **Two Injection Modes:**
   - **File-Based:** If `INJECT_SPECIFIED_MODULE`, copies the DLL file path. The loader stub will call `LdrLoadDll` to load the DLL from disk.
   - **Buffer-Based:** If injecting from memory, copies the entire DLL image into the section and calls `LoaderBuildImage` to manually map it (similar to reflective DLL loading).

4. **ZwUnmapViewOfSection on Failure:** If image building fails, unmaps the section to clean up.

**Why it's T1055 (Advanced Injection):**  
Section mapping is an **advanced injection technique** that offers several advantages:

- **Shared Memory:** The section exists in both the kernel and target process, avoiding explicit WriteProcessMemory calls
- **Executable Memory:** Sections can be created with `PAGE_EXECUTE_READWRITE` permissions directly
- **Stealthy:** No `VirtualAllocEx` or `WriteProcessMemory` calls that are heavily monitored by security products
- **Kernel Control:** Kernel drivers can create and map sections with full control, bypassing userland protections

This technique is used by advanced malware like:
- **Rovnix** (as shown)
- **Derusbi** (APT malware)
- **FinFisher/FinSpy** (commercial spyware)
- **BlackLotus** (UEFI bootkit)

---

## Code Snippet 3: APC Stub Initialization and Entry Point

```c
//
// Initializes inject APC stub and loader-specific context
BOOL InjectInitializeStub(HANDLE ProcessId, PINJECT_CONTEXT InjCtx, FUNC_PROTECT_MEM pZwProtectVirtualMemory, BOOL IsWow64)
{
	BOOL	Ret = FALSE;

	// Allocate loader context (section + stub + DLL path/buffer)
	if (InjCtx->LdrCtx = LoaderAllocateContext(ProcessId, InjCtx->InjDesc, IsWow64))
	{
		// Set APC routine to point to the loader stub in the section
		// This is the user-mode code that will execute when the APC fires
		InjCtx->ApcRoutine = &InjCtx->LdrCtx->LoaderStub;
		
		// Pass the entire loader context as the APC parameter
		InjCtx->ApcContext = InjCtx->LdrCtx;
		
		// Mark injection as waiting for APC execution
		InjCtx->Flags |= INJECT_STATE_WAITING_APC;						
		Ret = TRUE;
	}
	
	return(Ret);
}
```

**What it does:**  
Prepares the **APC parameters** that will be passed to `KldrQueueApc`:

1. **Allocates Loader Context:** Creates the section, copies the loader stub, and prepares the DLL path/buffer

2. **Sets APC Entry Point:** Points `ApcRoutine` to the **LoaderStub** within the allocated section. This is the user-mode code that will execute when the APC fires.

3. **Sets APC Context:** Passes the entire loader context structure as the APC parameter. The loader stub will receive this pointer and use it to:
   - Access the DLL path or buffer
   - Call `LdrLoadDll` or manually map the DLL
   - Initialize the injected code

4. **State Tracking:** Sets `INJECT_STATE_WAITING_APC` flag to track injection progress

**Why it's T1055.004 (APC Injection Setup):**  
This setup phase prepares everything needed for APC injection:

- **Entry Point:** The LoaderStub is position-independent shellcode that executes in user mode
- **Context Passing:** The loader context provides all necessary information (DLL path, image buffer, imports to resolve)
- **State Machine:** Rovnix tracks injection state, allowing it to retry failed injections or wait for APC completion

The separation of concerns (allocation → initialization → queuing) shows professional malware architecture.

---

## Code Snippet 4: NTDLL Import Resolution for User-Mode Loader

```c
//
// Resolves all necessary NTDLL imports for the user-mode loader stub
BOOL	ResolveNtdllImport(
	PCHAR	NtdllBase,         // Base address of NTDLL in target process
	PPROCESS_IMPORT	Import     // Structure to receive resolved imports
)
{
	BOOL	Ret = FALSE;

	do  // not a loop (using break for error handling)
	{
		// Resolve LdrLoadDll (used to load DLL from path)
		if (!(Import->pLdrLoadDll = (ULONGLONG)BkGetFunctionAddress(NtdllBase, "LdrLoadDll")))
		{
			KdPrint(("KLDR: NTDLL!LdrLoadDll not resolved!\\n"));
			break;
		}

		// Resolve LdrGetProcedureAddress (used to resolve imported functions)
		if (!(Import->pLdrGetProcedureAddress = (ULONGLONG)BkGetFunctionAddress(NtdllBase, "LdrGetProcedureAddress")))
		{
			KdPrint(("KLDR: NTDLL!LdrGetProcedureAddress not resolved!\\n"));
			break;
		}

		// Resolve NtProtectVirtualMemory (used to change memory protection)
		if (!(Import->pNtProtectVirtualMemory = (ULONGLONG)BkGetFunctionAddress(NtdllBase, "NtProtectVirtualMemory")))
		{
			KdPrint(("KLDR: NTDLL!NtProtectVirtualMemory not resolved!\\n"));
			break;
		}

		Ret = TRUE;
	} while(FALSE);

	return(Ret);
}
```

**What it does:**  
Resolves **NTDLL function addresses** in the target process for use by the user-mode loader stub:

1. **LdrLoadDll:** Native API for loading DLLs (used instead of LoadLibraryA to avoid kernel32 dependency)

2. **LdrGetProcedureAddress:** Native API for resolving function addresses (equivalent to GetProcAddress)

3. **NtProtectVirtualMemory:** Native API for changing memory protection (used to make injected code executable)

These functions are resolved from NTDLL's export table using `BkGetFunctionAddress` (Rovnix's custom export parser).

**Why it's T1055.004 (User-Mode Execution Preparation):**  
The loader stub needs to perform these operations in user mode:

1. **Load DLL:** Call `LdrLoadDll` to load the target DLL (if file-based injection)
2. **Resolve Imports:** Call `LdrGetProcedureAddress` to resolve imported functions (if manual mapping)
3. **Fix Permissions:** Call `NtProtectVirtualMemory` to make memory executable

By using **native NTDLL APIs** instead of kernel32 APIs, Rovnix:
- Avoids kernel32 import dependencies in the loader stub
- Bypasses security hooks on kernel32 APIs
- Uses lower-level, more reliable APIs

This is characteristic of advanced malware (rootkits, bootkits, APT tools).

---

## Code Snippet 5: Kernel APC Cleanup Routine

```c
// Kernel APC routine (runs in kernel mode to clean up)
VOID MyKernelApcRoutine(
	PKAPC Apc,
	PKNORMAL_ROUTINE *NormalRoutine,
	PVOID *NormalContext,
	PVOID *SystemArgument1,
	PVOID *SystemArgument2
)
{
	// Free the APC object allocated in KldrQueueApc
	MyFreePool(Apc);
	
	// NormalRoutine, NormalContext remain unchanged - they will execute in user mode
}
```

**What it does:**  
This is the **kernel-mode APC routine** that executes **before** the user-mode normal routine. Its only job is to **free the APC object** allocated in `KldrQueueApc`.

**Execution Flow:**
1. Thread enters alertable wait or returns from kernel mode
2. Windows kernel detects queued APC
3. Kernel executes **MyKernelApcRoutine** (kernel mode) - frees APC memory
4. Kernel transitions to user mode and executes **NormalRoutine** (user mode) - the loader stub
5. Thread resumes normal execution

**Why it's T1055.004 (APC Cleanup):**  
Proper resource cleanup is critical in kernel-mode code:

- **Memory Leak Prevention:** Without freeing the APC, each injection would leak non-paged memory
- **Stability:** Kernel memory leaks can lead to system instability or blue screens
- **Stealth:** Proper cleanup avoids forensic artifacts in kernel memory

The separation of kernel cleanup and user execution is a hallmark of sophisticated kernel-mode injection.

---

## Explanation

**What this code does:**  
Rovnix implements **kernel-mode APC injection** to inject code into user-mode processes from a kernel driver. The technique:

1. **Allocates Section:** Creates a memory-mapped section containing the loader stub and DLL path/buffer

2. **Resolves Imports:** Resolves NTDLL functions needed by the user-mode loader stub

3. **Initializes APC:** Allocates and initializes a KAPC object pointing to the loader stub

4. **Queues APC:** Inserts the APC into the target thread's APC queue via `KeInsertQueueApc`

5. **APC Fires:** When the thread enters an alertable state, the APC executes:
   - Kernel routine frees the APC object
   - User routine (loader stub) executes to load the DLL

6. **DLL Loading:** The loader stub calls `LdrLoadDll` (file-based) or manually maps the DLL (buffer-based)

**How it implements T1055.004 (APC Injection):**  
This is **pure kernel-mode APC injection**, one of the most advanced injection techniques:

**Advantages Over Usermode Techniques:**
- **Bypasses Userland Protections:** Operates from kernel space, bypassing all usermode hooks, API monitors, and process protections
- **Protected Process Access:** Can inject into Protected Process Light (PPL) processes that usermode code cannot touch
- **Direct Thread Access:** Directly manipulates kernel thread structures (ETHREAD/KTHREAD)
- **No CreateRemoteThread:** Uses target's own threads via APCs, avoiding suspicious remote thread creation
- **Stealthy Execution:** APCs fire asynchronously during normal thread execution, appearing as legitimate activity

**Kernel vs Usermode APC Injection:**

| Aspect | Usermode APC (QueueUserAPC) | Kernel APC (KeInsertQueueApc) |
|--------|----------------------------|--------------------------------|
| **Privilege** | User mode | Kernel mode (driver required) |
| **API** | QueueUserAPC (kernel32) | KeInsertQueueApc (ntoskrnl) |
| **Detection** | Easy (usermode hooks) | Hard (kernel-level operation) |
| **Thread State** | Must be in alertable wait | Any state (APC queued for later) |
| **Protected Processes** | Cannot inject | Can inject (kernel bypass) |
| **Stealth** | Moderate | Extremely high |

**Rovnix Bootkit Context:**  
Rovnix is a Russian-speaking bootkit (first detected 2011) that infects the Volume Boot Record (VBR) and Master Boot Record (MBR), loading its kernel driver before Windows boots. The kernel-mode APC injection allows Rovnix to:

- **Inject into System Processes:** Can inject into critical Windows processes (csrss.exe, winlogon.exe, services.exe)
- **Bypass Protected Process Light:** Injects into protected browsers and security products
- **Evade All Usermode Defenses:** Operates entirely from kernel space, invisible to usermode security tools
- **Persist Across Reboots:** Bootkit ensures the kernel driver loads before any security software

Rovnix primarily targets financial institutions, using APC injection to:
- Inject into browser processes for man-in-the-browser attacks
- Inject into banking applications to intercept transactions
- Inject into explorer.exe for system-wide persistence

**APIs that make it a strong T1055.004 match:**  
- **KeInitializeApc** - Initializes kernel APC object
- **KeInsertQueueApc** - Queues APC into target thread (kernel-mode APC injection)
- **ZwCreateSection** / **ZwMapViewOfSection** - Section mapping for shared memory injection
- **ZwUnmapViewOfSection** - Cleanup on failure
- **LdrLoadDll** (resolved for user stub) - Native DLL loading
- **LdrGetProcedureAddress** (resolved for user stub) - Native import resolution
- **NtProtectVirtualMemory** (resolved for user stub) - Memory protection manipulation

**Malware Family Resemblance:**  
- **Derusbi** - APT malware using kernel APC injection
- **FinFisher/FinSpy** - Commercial spyware with kernel APC injection
- **TDL4/TDSS** - Rootkit using section mapping injection
- **BlackLotus** - UEFI bootkit with section mapping injection
- **Equation Group Tools** (leaked NSA tools) - Kernel APC injection in DoublePulsar

Rovnix's technique is considered **APT/nation-state-level** due to the complexity of kernel-mode development and bootkit deployment.

**Detection Opportunities:**  
- Kernel driver loading (PsSetLoadImageNotifyRoutine callback)
- APC queuing from unexpected drivers (ObRegisterCallbacks for thread handle operations)
- Section objects created with executable permissions (PsSetCreateProcessNotifyRoutine)
- Bootkit indicators (VBR/MBR modifications, unsigned drivers loading before boot-start drivers)
- Anomalous APCs in system processes (WinDbg: `!apc` command to inspect thread APC queues)
- Unexpected threads in alertable wait states (NtAlertResumeThread, NtTestAlert calls)

**MITRE ATT&CK Mapping:**  
- **T1055** - Process Injection (Primary)
- **T1055.004** - Process Injection: Asynchronous Procedure Call (Specific Sub-technique)
- **T1014** - Rootkit (Rovnix operates as a rootkit)
- **T1542.003** - Pre-OS Boot: Bootkit (Rovnix infects VBR/MBR)
- **T1547.001** - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder (Bootkit persistence)
- **T1106** - Native API (Direct use of undocumented kernel APIs)
- **T1134** - Access Token Manipulation (Kernel access allows full token manipulation)
- **T1068** - Exploitation for Privilege Escalation (Kernel driver = SYSTEM privileges)
- **T1027** - Obfuscated Files or Information (Bootkit code is heavily obfuscated)
