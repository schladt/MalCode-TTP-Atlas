# Credential Theft Techniques: Executive Summary

**Findings Analyzed**: 3 comprehensive case studies  
**MITRE ATT&CK Coverage**: T1555.003, T1539, T1140, T1552.001, T1555.004  
**Malware Families**: Sin Stealer, PryntStealer

---

## Overview

This executive summary synthesizes three detailed analyses of modern credential theft techniques observed in Python-based information stealers active between 2020-2025. The documented techniques demonstrate sophisticated understanding of application-specific encryption schemes, evolving from simple file harvesting to complex cryptographic bypass methods including DPAPI manipulation, LevelDB parsing, and multi-application targeting strategies.

**Key Finding**: Modern stealers have shifted from generic keylogging to application-aware credential harvesting, leveraging detailed knowledge of each target application's storage mechanisms, encryption implementations, and update patterns.

---

## Techniques Summary

### 1. Chrome Credential & Cookie Theft (Sin Stealer)

**File**: `credential_theft_code_examples/01_Sin_Stealer_Chrome_Credential_Cookie_Theft_DPAPI.md`  
**Target**: Google Chrome browser (versions 1.0-present)  
**Technique**: Dual-mode decryption (DPAPI + AES-256-GCM)

**Technical Approach**:
- SQLite database extraction from `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data`
- Magic byte detection (`\x01\x00\x00\x00` for DPAPI, `v10` for AES-GCM)
- Windows DPAPI `CryptUnprotectData()` for Chrome <80
- AES-256-GCM with master key from `Local State` for Chrome 80+
- Cookie theft from `Cookies` SQLite database for session hijacking

**Sysmon Detection**:
- Event ID 11: File access to `Login Data` and `Cookies` databases
- Event ID 1: Process creation with DPAPI API calls
- Event ID 3: Network connection to C2 with exfiltrated credentials

**Impact**: Exposes saved passwords and active sessions for all Chrome-stored accounts (banking, email, social media).

### 2. Discord Token Extraction (Sin Stealer)

**File**: `credential_theft_code_examples/02_Sin_Stealer_Discord_Token_LevelDB_Extraction.md`  
**Target**: Discord desktop application  
**Technique**: LevelDB parsing and token regex extraction

**Technical Approach**:
- Directory traversal of `%APPDATA%\discord\Local Storage\leveldb\`
- Regex pattern matching for Discord tokens: `[\w-]{24}\.[\w-]{6}\.[\w-]{27}` and `mfa\.[\w-]{84}`
- Multi-file search across `.log` and `.ldb` LevelDB files
- Token validation via Discord API before exfiltration

**Sysmon Detection**:
- Event ID 11: Read access to LevelDB files in Discord directory
- Event ID 3: Network connection to Discord API for token validation
- Event ID 13: Registry access to Discord installation paths

**Impact**: Account takeover with full Discord permissions (message history, server access, financial data for Nitro users).

### 3. Telegram Session Harvesting (PryntStealer)

**File**: `credential_theft_code_examples/03_PryntStealer_Telegram_Session_tdata_Directory_Harvesting.md`  
**Target**: Telegram Desktop application  
**Technique**: Recursive session file collection

**Technical Approach**:
- Bulk directory copy of `%APPDATA%\Telegram Desktop\tdata\`
- Targets `key_datas`, `D877F783D5D3EF8C*` (session files), `map*` (metadata)
- No decryption required - files used directly for session import
- Supports multiple Telegram installations (portable versions)

**Sysmon Detection**:
- Event ID 11: Read access and file copy operations in `tdata` directory
- Event ID 1: Process creation (archiving tools like 7z, WinRAR)
- Event ID 3: Network upload to C2 servers

**Impact**: Complete account takeover without 2FA bypass - stolen session files authenticate directly.

---

## Common Attack Patterns

### Pattern 1: Application Storage Awareness

All three techniques demonstrate deep understanding of target application internals:

| Application | Storage Format | Encryption | Stealer Strategy |
|-------------|----------------|------------|------------------|
| Chrome | SQLite + JSON | DPAPI/AES-GCM | Dual-mode decryption |
| Discord | LevelDB | None | Regex token extraction |
| Telegram | Custom binary | None (session-based) | File copy |

**Implication**: Defenses must be application-specific - generic credential protection is insufficient.

### Pattern 2: Database Locking Bypass

**Challenge**: Target applications lock credential databases while running.

**Solution**: All three stealers use file copy operations (`shutil.copy()` in Python, `CopyFile()` in C++) to create temporary database copies, bypassing file locks.

**Detection Opportunity**: Monitor for file copies from application data directories with suspicious process parentage.

### Pattern 3: Backward Compatibility

Sin Stealer's dual-mode Chrome decryption (DPAPI + AES-GCM) ensures success across 7+ years of Chrome versions. This pattern appears across modern stealers:

```python
# Generalized compatibility pattern
if magic_bytes == LEGACY_FORMAT:
    return decrypt_old_method(data)
elif magic_bytes == MODERN_FORMAT:
    return decrypt_new_method(data)
else:
    try_all_methods(data)  # Brute-force for unknown versions
```

**Defensive Implication**: Monitoring must account for both legacy and modern credential storage methods.

### Pattern 4: Silent Failure Handling

All analyzed samples use broad exception handling to suppress errors:

```python
try:
    steal_credentials()
except:
    pass  # Continue to next target
```

**Purpose**: Ensures malware continues operating even if specific applications aren't installed, are running, or have updated storage formats.

**Detection Challenge**: No error messages or crashes alert users to credential theft attempts.

---

## Unified Detection Strategy

### Sysmon Configuration (High-Value Events)

```xml
<Sysmon schemaversion="13.0">
  <EventFiltering>
    <!-- File Access: Credential Databases -->
    <FileCreate onmatch="include">
      <TargetFilename condition="contains">\Google\Chrome\User Data\Default\Login Data</TargetFilename>
      <TargetFilename condition="contains">\Google\Chrome\User Data\Default\Cookies</TargetFilename>
      <TargetFilename condition="contains">\discord\Local Storage\leveldb\</TargetFilename>
      <TargetFilename condition="contains">\Telegram Desktop\tdata\</TargetFilename>
    </FileCreate>
    
    <!-- Process: DPAPI Usage -->
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">crypt32.dll</CommandLine>
      <CommandLine condition="contains">CryptUnprotectData</CommandLine>
    </ProcessCreate>
    
    <!-- Network: Discord API Token Validation -->
    <NetworkConnect onmatch="include">
      <DestinationHostname condition="is">discord.com</DestinationHostname>
      <DestinationPort condition="is">443</DestinationPort>
      <Image condition="excludes">Discord.exe</Image>
    </NetworkConnect>
  </EventFiltering>
</Sysmon>
```

### YARA Rule: Multi-Application Credential Stealer

```yara
rule Multi_Application_Credential_Stealer {
    meta:
        description = "Detects stealers targeting Chrome, Discord, and Telegram"
        author = "TTP Analysis"
        date = "2025-11-24"
        severity = "critical"
        
    strings:
        // Chrome paths
        $chrome1 = "Google\\Chrome\\User Data\\Default\\Login Data" ascii wide
        $chrome2 = "Local State" ascii wide
        $chrome3 = "v10" ascii  // AES-GCM magic byte
        
        // Discord patterns
        $discord1 = "discord\\Local Storage\\leveldb" ascii wide
        $discord2 = /[\w-]{24}\.[\w-]{6}\.[\w-]{27}/ ascii  // Token regex
        $discord3 = "mfa." ascii  // MFA token prefix
        
        // Telegram patterns
        $telegram1 = "Telegram Desktop\\tdata" ascii wide
        $telegram2 = "key_datas" ascii
        $telegram3 = "D877F783D5D3EF8C" ascii  // Session file prefix
        
        // Decryption APIs
        $dpapi = "CryptUnprotectData" ascii
        $aes = "AES-256-GCM" ascii
        
        // Python infostealer indicators
        $py1 = "sqlite3.connect" ascii
        $py2 = "shutil.copy" ascii
        $py3 = "os.environ['LOCALAPPDATA']" ascii
        
    condition:
        uint16(0) == 0x5A4D or uint32(0) == 0x464c457f and  // PE or ELF
        (
            // Strong: All three applications targeted
            (2 of ($chrome*) and 2 of ($discord*) and 2 of ($telegram*)) or
            
            // Medium: Two applications + decryption
            (2 of ($chrome*) and 2 of ($discord*) and ($dpapi or $aes)) or
            
            // Python-specific pattern
            (3 of ($py*) and (2 of ($chrome*) or 2 of ($discord*)))
        )
}
```

---

## Attack Timeline & Forensic Artifacts

### Typical Execution Sequence

```
T+0s:    [Sysmon 1]    Stealer process launch (often from %TEMP%)
T+1s:    [Sysmon 11]   File access: Login Data (Chrome)
T+1s:    [Sysmon 11]   File copy: Login Data → %TEMP%\tmp_<random>.db
T+2s:    [Sysmon 1]    Python subprocess: sqlite3 database query
T+3s:    [Sysmon 11]   File access: leveldb (Discord)
T+4s:    [Sysmon 3]    Network: Discord API token validation
T+5s:    [Sysmon 11]   Directory access: Telegram tdata
T+6s:    [Sysmon 11]   Archive creation: credentials.zip
T+7s:    [Sysmon 3]    Network: C2 exfiltration (HTTP POST)
T+8s:    [Sysmon 23]   File delete: temporary database copies
T+9s:    [Sysmon 5]    Process exit: stealer cleanup
```

### Persistent Forensic Artifacts

**File System**:
- Temporary SQLite database copies in `%TEMP%` (may persist if stealer crashes)
- Archive files (`.zip`, `.rar`, `.7z`) containing stolen credentials
- Stealer executable and associated Python libraries (if PyInstaller bundle)

**Registry**:
- Recent file access: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`
- UserAssist: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist` (stealer execution)

**Event Logs**:
- Sysmon: File access, network connections, process creation
- Security.evtx: Account logon events (if stolen credentials used)
- Application.evtx: SQLite errors (if database locked)

**Network**:
- PCAP data: HTTP POST with credential payloads (often JSON or form-encoded)
- DNS queries: C2 domain resolution
- TLS certificates: Inspect SNI fields for Discord API abuse

---

## Mitigation Strategies

### 1. Application-Level Hardening

**Chrome**:
```bash
# Enable Enhanced Safe Browsing (detects malicious downloads)
chrome://settings/security → Enhanced protection

# Disable credential storage (enterprise policy)
Software\Policies\Google\Chrome\PasswordManagerEnabled = 0
```

**Discord**:
- Enable 2FA with authenticator app (reduces token theft value)
- Use Discord in browser with ephemeral sessions (no local storage)

**Telegram**:
- Set passcode lock on desktop client (encrypts local storage)
- Use web version for sensitive operations

### 2. Endpoint Protection

**Directory Access Monitoring**:
```powershell
# Audit Chrome credential access
$acl = Get-Acl "$env:LOCALAPPDATA\Google\Chrome\User Data\Default"
$auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
    "Everyone", "Read", "Success"
)
$acl.AddAuditRule($auditRule)
Set-Acl "$env:LOCALAPPDATA\Google\Chrome\User Data\Default" $acl
```

**Process Behavioral Analysis**:
- Alert on non-browser processes accessing browser databases
- Monitor Python/PowerShell with DPAPI API calls
- Flag archive creation in application data directories

### 3. Network Controls

**C2 Communication Blocking**:
```
# Proxy/firewall rules
Block: HTTP POST with large payloads (>10KB) from non-browser processes
Block: Base64-encoded data in HTTP bodies from system utilities
Alert: Discord API access from non-Discord executables
```

### 4. User Education

**High-Risk Indicators**:
- Email attachments claiming to be "Chrome security updates"
- Discord bots requesting "verification" via executable download
- Telegram messages with `.scr` or `.pif` file extensions

---

## Conclusions & Recommendations

### Key Takeaways

1. **Encryption ≠ Protection**: All three applications use encryption, yet stealers bypass protections through OS-level APIs (DPAPI), application-aware decryption (Chrome AES-GCM), or session theft (Telegram).

2. **Detection Requires Application Context**: Generic AV signatures fail - effective detection requires monitoring application-specific paths, file formats, and API usage patterns.

3. **Session Theft > Password Theft**: Modern stealers prioritize session cookies/tokens over passwords - 2FA provides limited protection if session data stolen.

4. **Python-Based Stealers Proliferating**: PyInstaller bundles enable rapid development and obfuscation bypass - EDR must inspect Python bytecode and imported libraries.

5. **Backward Compatibility = Longevity**: Sin Stealer's 7+ year Chrome compatibility demonstrates that comprehensive credential theft requires supporting legacy formats - defenders must monitor old and new storage methods.

### Defensive Priority Matrix

| Priority | Action | Effort | Impact |
|----------|--------|--------|--------|
| **Critical** | Enable Sysmon file access monitoring for browser DBs | Low | High |
| **Critical** | Deploy YARA rule for multi-app credential stealers | Low | High |
| **High** | Audit DPAPI usage from non-system processes | Medium | High |
| **High** | Enforce application hardening policies (disable credential storage) | Medium | Medium |
| **Medium** | User training on stealer delivery vectors | Low | Medium |
| **Medium** | Network monitoring for Discord API abuse | High | Medium |

### Emerging Threats

**Trends Observed**:
- Shift toward Electron app targeting (Discord, Slack, Teams) - LevelDB parsing becoming standard
- Increased use of legitimate cloud services for C2 (Discord webhooks, Telegram bots) - harder to block
- Credential-as-a-Service (CaaS) - stolen credentials sold in near real-time on dark web markets

**Future Research Directions**:
- Browser extension-based credential theft (bypasses local encryption entirely)
- Android/iOS credential vault targeting (mobile infostealer emergence)
- AI-assisted credential harvesting (automated phishing with stolen session context)

---

**Analysis Version**: 1.0  
**Contributing Findings**: 3 detailed case studies (Sin Stealer ×2, PryntStealer ×1)  
**Total Documentation**: ~25,000 words across 3 findings + this executive summary
