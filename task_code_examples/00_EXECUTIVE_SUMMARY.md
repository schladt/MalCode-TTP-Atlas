# Windows Scheduled Task Malware Analysis - Executive Summary

## Analysis Overview
**Scope**: Three malware repositories containing Windows malware samples  
**Focus**: MITRE ATT&CK T1053.005 - Scheduled Task/Job: Scheduled Task

## Total Findings: 13 Confirmed Cases

This analysis identified **13 distinct malware samples** that implement Windows Scheduled Task persistence mechanisms. All findings demonstrate Windows-specific code implementing T1053.005 behavior.

---

## Finding Categories

### Category 1: Command-Line schtasks.exe Usage (10 findings)
Most common implementation method using `schtasks.exe` command-line utility.

**Findings**: 1-7, 10-12

### Category 2: COM API Implementation (2 findings)
Advanced implementations using native Windows Task Scheduler COM APIs.

**Findings**: 8, 9

### Category 3: WMI Event Subscription (1 finding)
Alternative persistence using WMI timers (functional equivalent to scheduled tasks).

**Finding**: 13

---

## Key Findings Summary

| # | Malware Family | Type | Schedule Type | Privilege | Stealth Level |
|---|---------------|------|---------------|-----------|---------------|
| 1 | Prynt Stealer | RAT/Stealer | ONLOGON | HIGHEST | Medium |
| 2 | RedLine Stealer | Stealer | DAILY (1min repeat) | Normal | High |
| 3 | Predator Miner | Cryptominer | ONCE (9999h, 1min) | Normal | Medium |
| 4 | Pentagon RAT | RAT | MINUTE (every 1) | Normal | Low |
| 5 | Comet RAT | RAT | Configurable | Normal | High |
| 6 | AsyncRAT | RAT | ONLOGON | HIGHEST | High |
| 7 | Quasar RAT | RAT | ONLOGON | HIGHEST | High |
| 8 | Carberp Botnet | Banking Trojan | LOGON (COM API) | INTERACTIVE_TOKEN | Very High |
| 9 | Carberp MS10-092 | Privilege Escalation | LOGON (UAC Bypass) | SYSTEM | Very High |
| 10 | APT34 PoisonFrog | APT Dropper | MINUTE (dual tasks) | USER + SYSTEM | High |
| 11 | WIPE32 (PowerShell) | Wiper | DAILY (timed) | HIGHEST | Medium |
| 12 | WIPE32 (Batch) | Wiper | ONLOGON | HIGHEST | High |
| 13 | WMIGhost | Backdoor | WMI Timer | SYSTEM | Very High |

---

## Common Techniques Observed

### Schedule Triggers
- **ONLOGON** (5 cases): Triggers when any user logs on - most common for RATs
- **MINUTE** (3 cases): Runs every N minutes - aggressive persistence
- **DAILY** (3 cases): Runs once per day with optional repeat intervals
- **ONCE + Long Duration** (1 case): Runs "once" but for 9999 hours with repeat - stealthy
- **WMI Timer** (1 case): Alternative to scheduled tasks using WMI events

### Privilege Escalation
- **`/rl highest`** (7 cases): Runs with highest available privileges
- **`/RU "SYSTEM"`** (2 cases): Explicit SYSTEM-level execution
- **COM API with INTERACTIVE_TOKEN** (2 cases): Current user context via API
- **UAC Bypass** (1 case): MS10-092 exploit for privilege escalation

### Naming Conventions (Masquerading)
- **System Update Names**: "StUpdate", "JavaUpdates", "GoogleUpdateschecker"
- **Microsoft/IIS**: "MicrosoftIIS_CheckInstalledUpdater", "Microsоft" (Cyrillic)
- **Generic Service**: "wp32Service", "My"
- **Dynamic/Random**: Hash-based names, filename-derived names

---

## Most Sophisticated Implementations

### 🥇 1st Place: Carberp MS10-092 UAC Bypass (Finding #9)
**Sophistication Score: 10/10**
- Exploits CVE-2010-3338 for UAC bypass
- Uses Task Scheduler COM API programmatically
- Creates benign task, modifies XML directly, executes with elevated privileges
- Demonstrates deep understanding of Task Scheduler internals

### 🥈 2nd Place: Carberp COM API Implementation (Finding #8)
**Sophistication Score: 9/10**
- Native COM API usage bypasses command-line monitoring
- Dual compatibility (Task Scheduler 1.0 + 2.0)
- Professional code with proper error handling and memory management
- Packaged as injectable DLL

### 🥉 3rd Place: WMIGhost Event Subscription (Finding #13)
**Sophistication Score: 9/10**
- Uses WMI Event Subscriptions instead of scheduled tasks
- Harder to detect (hidden in WMI repository)
- Fileless execution via WMI service
- Requires specialized tools to identify

---

## Most Aggressive Persistence

### 🏆 RedLine Stealer (Finding #2)
- **Re-creation interval**: Every 50 seconds
- **Task execution**: Every 1 minute
- **Duration**: 9999 hours (essentially unlimited)
- **Result**: Near-impossible to remove without stopping malware process

### 🏆 APT34 PoisonFrog (Finding #10)
- **Dual tasks**: Creates both USER and SYSTEM level tasks
- **Frequency**: Every 1 minute execution
- **Redundancy**: If one task removed, other continues
- **State-sponsored**: Professional APT-level implementation

---

## Malware Family Distribution

### RATs (Remote Access Trojans) - 5 samples
- Prynt Stealer, Pentagon RAT, Comet RAT, AsyncRAT, Quasar RAT
- **Common pattern**: ONLOGON trigger with highest privileges
- **Goal**: Persistent remote access for espionage/control

### Stealers - 2 samples  
- RedLine Stealer, Prynt Stealer
- **Common pattern**: Frequent execution (minute/daily with repeats)
- **Goal**: Continuous credential/data harvesting

### Banking Trojans - 2 samples
- Carberp Botnet (2 implementations)
- **Common pattern**: Advanced COM API usage
- **Goal**: Stealthy persistence for financial fraud

### Wipers - 2 samples
- WIPE32 (2 implementations)
- **Common pattern**: Time-delayed execution + anti-recovery
- **Goal**: Coordinated destructive attacks

### Cryptominers - 1 sample
- Predator The Miner
- **Common pattern**: Long duration with frequent repeats
- **Goal**: Maximize mining time

### APT Droppers - 1 sample
- APT34 PoisonFrog
- **Common pattern**: Multi-stage delivery with dual persistence
- **Goal**: Deploy additional payloads

---

## Evasion Techniques Summary

### Naming Masquerading (12/13 samples)
- Legitimate-sounding names mimicking Windows/Microsoft services
- Examples: "JavaUpdates", "MicrosoftIIS", "GoogleUpdateschecker", "wp32Service"

### Hidden Execution (13/13 samples)
- All samples use `CreateNoWindow`, `WindowStyle.Hidden`, or equivalent
- No visible windows during task creation or execution

### Privilege Escalation (9/13 samples)
- `/rl highest` or SYSTEM-level execution
- Some include UAC bypass techniques

### Dual Persistence (7/13 samples)
- Scheduled task + Registry Run key
- Scheduled task + Startup folder
- Multiple scheduled tasks (USER + SYSTEM)

### Dynamic Configuration (5/13 samples)
- Task names derived from filenames or system properties
- Random/hash-based naming
- C2-configurable parameters

### Anti-Removal (2/13 samples)
- Continuous re-creation loops
- Anti-recovery registry modifications

---

## Repository Distribution

### MalwareSourceCode-main: 7 findings
- Prynt Stealer, RedLine Stealer, Predator Miner, Pentagon RAT, Comet RAT
- Various Carberp implementations

### theZoo-master: 5 findings
- AsyncRAT, Quasar RAT, APT34 PoisonFrog, WIPE32 (2x), WMIGhost

### Malware-Collection-master: 2 findings  
- Carberp Botnet (COM API + MS10-092)

---

## Detection Recommendations

### Windows Event Logs
- **Event ID 4698**: Scheduled task created
- **Event ID 4702**: Scheduled task updated
- **Event ID 4699**: Scheduled task deleted
- **Event ID 4700/4701**: Scheduled task enabled/disabled
- **Event ID 5861**: WMI permanent event consumer registration (WMI persistence)

### Command-Line Monitoring
Monitor for `schtasks.exe` with suspicious parameters:
- `/rl highest` with unusual task names
- `/sc minute` or `/sc onlogon` from non-standard processes
- Task paths pointing to `%TEMP%`, `%APPDATA%`, or unusual directories
- Tasks created by scripting interpreters (powershell.exe, cscript.exe, wscript.exe)

### File System Monitoring
- `C:\Windows\System32\Tasks\` - monitor for new/modified task XML files
- Unusual directories containing executables referenced by tasks

### Registry Monitoring
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\`
- Monitor for new task registrations

### WMI Monitoring
- Query `root\subscription` namespace for event consumers, filters, and bindings
- Monitor WMI event IDs 5859-5861

### Behavioral Indicators
- Processes creating tasks with random/hash-based names
- Tasks with very short repeat intervals (< 5 minutes)
- Tasks pointing to temporary directories
- Multiple tasks created in rapid succession
- Tasks with typo-squatted Microsoft names (e.g., "Microsоft" with Cyrillic)

---

## MITRE ATT&CK Technique Breakdown

### Primary Technique
**T1053.005**: Scheduled Task/Job: Scheduled Task - **13/13 samples**

### Common Co-Techniques
- **T1547.001**: Registry Run Keys / Startup Folder (7 samples)
- **T1036.005**: Masquerading: Match Legitimate Name (12 samples)
- **T1564.003**: Hide Artifacts: Hidden Window (13 samples)
- **T1548.002**: Bypass User Account Control (4 samples)
- **T1106**: Native API (COM API - 2 samples)
- **T1070.004**: File Deletion / Cleanup (8 samples)
- **T1059.001/.003/.005**: Command/Scripting Interpreters (13 samples)

### Advanced Techniques
- **T1068**: Exploitation for Privilege Escalation (MS10-092 - 1 sample)
- **T1546.003**: WMI Event Subscription (1 sample)
- **T1485/T1490/T1561**: Data Destruction / Inhibit Recovery (Wipers - 2 samples)

---

## Threat Actor Attribution

### State-Sponsored APT
- **APT34 (OilRig)**: Iranian state-sponsored group targeting Middle East
  - Finding #10: PoisonFrog Dropper with DNS tunneling

### Cybercriminal Groups
- **Carberp Gang**: Sophisticated banking trojan operators
  - Findings #8-9: Advanced COM API implementations

### Commodity Malware
- **AsyncRAT, Quasar RAT**: Open-source RATs used by various actors
  - Findings #6-7: Well-engineered persistence with fallback mechanisms

### Unknown/Multiple Actors
- **RedLine, Prynt, Pentagon, Comet**: Sold as MaaS (Malware-as-a-Service)
  - Findings #1-5: Varying sophistication, sold on underground forums

---

## Key Takeaways

1. **Scheduled tasks are ubiquitous**: All 13 samples use scheduled tasks or functional equivalents
2. **Command-line is dominant**: 10/13 use `schtasks.exe` command-line utility
3. **Masquerading is universal**: 12/13 use legitimate-sounding names
4. **Privilege escalation is common**: 9/13 attempt elevated execution
5. **Dual persistence is popular**: 7/13 use backup persistence mechanisms
6. **Advanced malware uses COM**: Most sophisticated samples use native APIs
7. **APT techniques differ**: State-sponsored actors show unique patterns (dual tasks, DNS tunneling)
8. **Wipers are distinctive**: Include anti-recovery and time-delayed execution
9. **RATs prefer ONLOGON**: Remote access trojans typically use logon triggers
10. **Detection requires multiple layers**: File, registry, WMI, and event log monitoring all necessary

---

## No Matches / False Positives Noted

During analysis, the following were examined but excluded:

### Linux/Unix Scheduling
- Cron job references in cross-platform malware (ignored as non-Windows)
- Systemd timer references (Linux-specific)

### Benign Scheduled Task Usage
- Task name "schtasks.exe" in process kill lists (anti-analysis, not task creation)
- Querying tasks for reconnaissance (`schtasks /query`) without creation

### Mobile/Android
- Android AlarmManager and JobScheduler references (non-Windows)

### Build/Development Artifacts
- Project names containing "schtasks" (e.g., Carberp project files)
- Readme and documentation files

All excluded items were non-Windows or did not involve actual scheduled task creation for persistence.

---

## Files Generated

This analysis produced 14 markdown files:
- `01_PryntStealer_schtasks_onlogon.md`
- `02_RedlineStealer_persistent_daily_task.md`
- `03_PredatorTheMiner_aggressive_repeat.md`
- `04_PentagonRAT_minute_persistence.md`
- `05_CometRAT_configurable_schedules.md`
- `06_AsyncRAT_privileged_onlogon.md`
- `07_QuasarRAT_fallback_mechanism.md`
- `08_Carberp_COM_API_implementation.md`
- `09_Carberp_MS10092_UAC_bypass.md`
- `10_APT34_PoisonFrog_dual_tasks.md`
- `11_WIPE32_scheduled_wiper.md`
- `12_WIPE32_anti_recovery_persistence.md`
- `13_WMIGhost_event_subscription.md`
- `00_EXECUTIVE_SUMMARY.md` (this file)

Each finding includes:
- Complete code snippets with context
- Detailed technical analysis
- MITRE ATT&CK mapping
- Evasion techniques
- Detection recommendations
- Real-world context

---

**End of Executive Summary**
