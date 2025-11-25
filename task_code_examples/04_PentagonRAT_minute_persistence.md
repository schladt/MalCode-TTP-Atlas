# Finding 4: Pentagon RAT - Every-Minute Task Persistence

## Metadata
- **Repository**: MalwareSourceCode-main
- **File Path**: `Win32/Win32.PentagonRAT.Builder/Win32.PentagonRAT.Builder/Security/Stub/SooftT.cs`
- **Language**: C# (Visual Basic .NET style)
- **Malware Family**: Pentagon RAT (Remote Access Trojan)

## Code Snippet

```csharp
try
{
    if (Operators.CompareString(AtivarAgendarServidor, "True", false) == 0)
    {
        // Copy malware to temp directory with specific name
        string text2 = ((ServerComputer)MyProject.Computer).FileSystem.SpecialDirectories.Temp + "/StUpdate.exe";
        ((ServerComputer)MyProject.Computer).FileSystem.WriteAllBytes(text2, File.ReadAllBytes(Application.ExecutablePath), true);
        
        // *** SCHEDULED TASK CREATION - LINE 4305 ***
        Interaction.Shell("schtasks /create /sc minute /mo 1 /tn StUpdate /tr " + text2, (AppWinStyle)0, false, -1);
        
        Thread.Sleep(50);
    }
}
catch (Exception ex19)
{
    ProjectData.SetProjectError(ex19);
    Exception ex20 = ex19;
    ProjectData.ClearProjectError();
}
```

## Analysis

**What it does:**
Pentagon RAT creates a scheduled task that runs every minute to ensure the RAT payload maintains persistent access to the compromised system. The malware copies itself to the temp directory before creating the task.

**How it uses Windows Scheduled Tasks (T1053.005):**
- **Schedule**: `/sc minute` - runs on a minute schedule
- **Modifier**: `/mo 1` - runs every 1 minute
- **Task name**: `/tn StUpdate` - named "StUpdate" to appear like a system update
- **Target**: `/tr {path}` - points to copy in temp directory (e.g., `C:\Users\[User]\AppData\Local\Temp\StUpdate.exe`)
- **No privilege elevation specified**: Runs with user's current privileges

**Evasion/Stealth Techniques:**
1. **Benign-sounding name**: "StUpdate" suggests a legitimate system or software update process
2. **Temp directory usage**: Stores payload in `%TEMP%` folder where many legitimate temporary files exist
3. **Configuration-driven**: `AtivarAgendarServidor` flag allows C2 operator to enable/disable persistence feature
4. **Hidden window**: `AppWinStyle = 0` (hidden window style)
5. **Error suppression**: Exceptions are caught and cleared without notification
6. **Self-copy**: Creates separate copy to avoid detection if original process is monitored

**RAT Context:**
Remote Access Trojans require:
- Persistent access even after system reboot
- Regular beacon/callback capability to C2
- Ability to restart if process is terminated
- Stealthy operation to avoid user detection

The every-minute execution ensures the RAT can quickly re-establish C2 connection if terminated.

**Weaknesses:**
- Task name "StUpdate" is relatively generic and may trigger suspicion
- Every minute execution is aggressive and may be detected by behavioral analysis
- No privilege elevation specified, limiting capabilities on standard user accounts

**MITRE ATT&CK Mapping:**
- **T1053.005**: Scheduled Task/Job: Scheduled Task
- **T1059.003**: Command and Scripting Interpreter: Windows Command Shell
- **T1036.005**: Masquerading: Match Legitimate Name or Location
- **T1564.003**: Hide Artifacts: Hidden Window
