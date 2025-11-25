# File Collection Techniques: Executive Summary

**Analysis Date**: November 24, 2025  
**Findings Analyzed**: 3 comprehensive case studies  
**MITRE ATT&CK Coverage**: T1005, T1119, T1083, T1552.001, T1555.003  
**Malware Families**: AngstStealer, PredatorTheStealer, Zeus/Zbot

---

## Overview

This executive summary synthesizes three detailed analyses of automated file collection techniques used by information stealers to harvest credentials, cryptocurrency wallets, and sensitive documents. The documented techniques demonstrate evolution from simple wildcard searches (Zeus 2007) to application-aware targeted harvesting (AngstStealer/Predator 2018-2020), with increasing sophistication in recognizing file formats, parsing XML/JSON/DAT structures, and targeting high-value cryptocurrency assets.

**Key Finding**: Modern file collection has shifted from generic "grab everything" approaches to surgical targeting of specific high-value files (wallet.dat, private keys, seed phrases), using application knowledge to extract credentials from complex formats (XML, JSON, SQLite, DAT) rather than hoping passwords appear in plaintext.

---

## Techniques Summary

### 1. FileZilla XML Credential Extraction (AngstStealer)

**File**: `file_collection_code_examples/01_AngstStealer_FileZilla_XML_Credential_Extraction.md`  
**Target**: FileZilla FTP client credentials  
**Method**: XML parsing of `recentservers.xml` and `sitemanager.xml`

**Technical Approach**:
- Locate FileZilla config directory: `%APPDATA%\FileZilla\`
- Parse XML files with `xml.etree.ElementTree`
- Extract FTP credentials from `<Host>`, `<User>`, `<Pass>` tags
- Handle base64-encoded passwords (FileZilla >3.26)
- Target both recent connections and saved site manager entries

**XML Structure**:
```xml
<FileZilla3>
  <RecentServers>
    <Server>
      <Host>ftp.victim-company.com</Host>
      <Port>21</Port>
      <Protocol>0</Protocol>
      <User>admin</User>
      <Pass encoding="base64">cGFzc3dvcmQxMjM=</Pass>
    </Server>
  </RecentServers>
</FileZilla3>
```

**Sysmon Detection**:
- Event ID 11: File read access to `recentservers.xml`, `sitemanager.xml`
- Event ID 1: Python process with XML parsing libraries (xml.etree, lxml)
- Event ID 3: Network connection to C2 with exfiltrated FTP credentials

**Impact**: Compromises FTP servers used for web hosting, file sharing, backup storage - often containing corporate data, source code, customer databases.

### 2. Multi-Wallet Cryptocurrency Harvesting (PredatorTheStealer)

**File**: `file_collection_code_examples/02_PredatorTheStealer_Multi_Wallet_Cryptocurrency_Harvesting.md`  
**Target**: 15+ cryptocurrency wallets  
**Method**: Recursive directory search for wallet.dat, keystore files, seed phrases

**Technical Approach**:
- Enumerate `%APPDATA%`, `%LOCALAPPDATA%`, `%USERPROFILE%` directories
- Target wallet-specific subdirectories: `\Ethereum\`, `\Bitcoin\wallets\`, `\Electrum\`
- Search for files: `wallet.dat`, `*.wallet`, `keystore\*`, `electrum.dat`
- Cryptocurrency support: Bitcoin, Ethereum, Litecoin, Monero, Dash, Zcash, Dogecoin, ByteCoin, + 7 more
- Multi-wallet detection: Checks 50+ wallet application installation paths

**Targeted Wallets**:
```
Bitcoin Core:    %APPDATA%\Bitcoin\wallets\wallet.dat
Ethereum:        %APPDATA%\Ethereum\keystore\*
Electrum:        %APPDATA%\Electrum\wallets\*
Exodus:          %APPDATA%\Exodus\exodus.wallet\*
Monero:          %USERPROFILE%\Documents\Monero\wallets\*
Atomic Wallet:   %APPDATA%\atomic\Local Storage\leveldb\*
```

**Sysmon Detection**:
- Event ID 11: File read access to cryptocurrency wallet directories
- Event ID 1: Process with recursive directory enumeration (`FindFirstFile`, `FindNextFile`)
- Event ID 3: Large data upload to C2 (wallet files typically 100KB-10MB)

**Impact**: Direct financial theft - stolen wallet.dat files can be cracked offline, private keys provide immediate access to funds. Combined value often exceeds $10K-$1M+ for active traders.

### 3. Automated Wildcard File Search & Recursive Harvesting (Zeus/Zbot)

**File**: `file_collection_code_examples/03_Zeus_Zbot_Automated_Wildcard_File_Search_Recursive_Harvesting.md`  
**Target**: *.doc, *.xls, *.pdf, *.txt, *.rtf, *.jpg, *.zip  
**Method**: Recursive FindFirstFile/FindNextFile with wildcard filters

**Technical Approach**:
- Recursive directory traversal from root directories (C:\, D:\)
- Wildcard matching: `FindFirstFile("*.doc")`, `FindNextFile()`
- File metadata collection: size, creation time, last modified time
- Selective exfiltration based on file size thresholds (>1KB, <10MB)
- Pattern matching for high-value terms: "password", "confidential", "ssn", "credit card"

**Search Pattern Example**:
```cpp
void SearchDirectory(const char* directory, const char* pattern) {
    WIN32_FIND_DATA findData;
    char searchPath[MAX_PATH];
    sprintf(searchPath, "%s\\%s", directory, pattern);
    
    HANDLE hFind = FindFirstFile(searchPath, &findData);
    while (FindNextFile(hFind, &findData)) {
        if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            CollectFile(findData.cFileName);
        }
    }
    FindClose(hFind);
    
    // Recurse into subdirectories
    sprintf(searchPath, "%s\\*", directory);
    hFind = FindFirstFile(searchPath, &findData);
    while (FindNextFile(hFind, &findData)) {
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            SearchDirectory(fullPath, pattern);
        }
    }
}
```

**Sysmon Detection**:
- Event ID 11: Bulk file read operations (100+ files in <60 seconds)
- Event ID 1: Process with file enumeration APIs (FindFirstFile, FindNextFile)
- Event ID 3: Periodic upload bursts to C2 (every 5-15 minutes)

**Impact**: Mass data exfiltration - typical enterprise system yields 10,000-100,000+ matching files. Zeus botnet operators used collected documents for targeted phishing, identity theft, corporate espionage.

---

## Evolution of File Collection (2007-2020)

### Timeline Analysis

```
2007: Zeus - Wildcard Recursive Search
      ├─ Generic file extension targeting (*.doc, *.xls)
      ├─ No format parsing (grab raw files)
      └─ High false positive rate (system/temp files)

2018: AngstStealer - Application-Aware Parsing
      ├─ Targeted application config files (FileZilla XML)
      ├─ Format-specific parsing (XML, JSON, SQLite)
      └─ Precise credential extraction

2020: PredatorTheStealer - High-Value Asset Focus
      ├─ Cryptocurrency wallet specialization
      ├─ 15+ wallet application support
      ├─ Multi-format wallet file recognition
      └─ Blockchain-specific file structures (keystore, wallet.dat)
```

### Common Patterns Across All Three Techniques

#### Pattern 1: Recursive Directory Traversal

All three implement recursive search algorithms to handle arbitrary directory depths:

```python
# Generalized recursive traversal pattern
def collect_files(directory, target_patterns):
    for root, dirs, files in os.walk(directory):
        for file in files:
            if matches_pattern(file, target_patterns):
                harvest_file(os.path.join(root, file))
        
        # Optional: Skip system directories
        dirs[:] = [d for d in dirs if d not in ['Windows', 'Program Files']]
```

**Why**: User data scattered across Documents\, Desktop\, Downloads\, AppData\ - flat search insufficient.

#### Pattern 2: Metadata Collection Before Exfiltration

All samples collect file metadata (size, timestamps) before deciding whether to exfiltrate:

```cpp
// Zeus pattern (generalized)
WIN32_FIND_DATA fileData;
if (fileData.nFileSizeLow > 1024 &&  // Larger than 1KB
    fileData.nFileSizeLow < 10485760) {  // Smaller than 10MB
    ExfiltrateFile(fileData.cFileName);
}
```

**Purpose**: Avoid bandwidth waste on empty/system files, prevent C2 storage exhaustion.

**Detection Opportunity**: Sustained file enumeration followed by selective file reads (100+ files scanned, 5-10 exfiltrated).

#### Pattern 3: Keyword/Pattern-Based Filtering

Zeus and AngstStealer use content-based filtering to prioritize high-value files:

| Malware | Filter Criteria | Purpose |
|---------|----------------|---------|
| Zeus | File contains "password", "confidential", "ssn" | Prioritize credential documents |
| AngstStealer | XML elements `<Pass>`, `<User>`, `<Host>` | Extract structured credentials |
| Predator | Directory name contains "wallet", "keystore" | Focus on cryptocurrency |

**Defensive Implication**: Honeypot files with fake credentials can detect file collection activity early.

#### Pattern 4: Offline Queueing for Large Collections

All three implement local caching for files awaiting exfiltration:

```python
# Predator pattern (generalized)
collected_files = []

for file in find_wallet_files():
    collected_files.append(file)

if len(collected_files) > BATCH_SIZE or time_elapsed > MAX_WAIT:
    create_archive(collected_files)  # .zip or .rar
    upload_to_c2(archive)
    delete_local_copies()
```

**Why**: Minimize network connections (reduces detection), batch compression saves bandwidth.

**Detection**: Temporary archives in `%TEMP%` with suspicious names (`data.zip`, `backup.rar`, `log_<random>.7z`).

---

## Unified Detection Strategy

### Sysmon Configuration (File Collection Focus)

```xml
<Sysmon schemaversion="13.0">
  <EventFiltering>
    <!-- High-value file access -->
    <FileCreate onmatch="include">
      <TargetFilename condition="contains">\FileZilla\recentservers.xml</TargetFilename>
      <TargetFilename condition="contains">\FileZilla\sitemanager.xml</TargetFilename>
      <TargetFilename condition="contains">\Bitcoin\wallets\wallet.dat</TargetFilename>
      <TargetFilename condition="contains">\Ethereum\keystore\</TargetFilename>
      <TargetFilename condition="contains">\Electrum\wallets\</TargetFilename>
    </FileCreate>
    
    <!-- Bulk file enumeration (100+ files in 60s) -->
    <ProcessCreate onmatch="include">
      <Image condition="contains">python</Image>
      <CommandLine condition="contains">os.walk</CommandLine>
    </ProcessCreate>
    
    <!-- Archive creation with suspicious names -->
    <FileCreate onmatch="include">
      <TargetFilename condition="begin with">C:\Users\*\AppData\Local\Temp\</TargetFilename>
      <TargetFilename condition="end with">.zip</TargetFilename>
      <TargetFilename condition="end with">.rar</TargetFilename>
      <TargetFilename condition="end with">.7z</TargetFilename>
    </FileCreate>
    
    <!-- Recursive FindFirstFile patterns -->
    <ImageLoad onmatch="include">
      <ImageLoaded condition="end with">kernel32.dll</ImageLoaded>
      <Signature condition="contains">FindFirstFile</Signature>
    </ImageLoad>
  </EventFiltering>
</Sysmon>
```

### YARA Rule: Multi-Application File Collector

```yara
rule Multi_Application_File_Collector {
    meta:
        description = "Detects stealers with file collection across multiple applications"
        author = "TTP Analysis"
        date = "2025-11-24"
        severity = "high"
        
    strings:
        // File search APIs
        $file1 = "FindFirstFile" ascii
        $file2 = "FindNextFile" ascii
        $file3 = "FindClose" ascii
        $file4 = "GetFileAttributes" ascii
        
        // FileZilla paths
        $fz1 = "FileZilla\\recentservers.xml" ascii wide
        $fz2 = "FileZilla\\sitemanager.xml" ascii wide
        $fz3 = "<Host>" ascii wide
        $fz4 = "<Pass" ascii wide
        
        // Cryptocurrency wallet paths
        $crypto1 = "Bitcoin\\wallets\\wallet.dat" ascii wide
        $crypto2 = "Ethereum\\keystore" ascii wide
        $crypto3 = "Electrum\\wallets" ascii wide
        $crypto4 = "Exodus\\exodus.wallet" ascii wide
        $crypto5 = "Monero\\wallets" ascii wide
        
        // Wildcard search patterns
        $wild1 = "*.doc" ascii wide
        $wild2 = "*.xls" ascii wide
        $wild3 = "*.pdf" ascii wide
        $wild4 = "*.wallet" ascii wide
        $wild5 = "wallet.dat" ascii wide
        
        // XML/JSON parsing
        $parse1 = "xml.etree" ascii
        $parse2 = "json.loads" ascii
        $parse3 = "ElementTree" ascii
        
        // Archive creation
        $archive1 = "zipfile" ascii
        $archive2 = "ZipFile" ascii
        $archive3 = "CreateArchive" ascii
        
    condition:
        uint16(0) == 0x5A4D or uint32(0) == 0x464c457f and  // PE or ELF
        (
            // Strong: File search + multiple applications
            (3 of ($file*) and (2 of ($fz*) or 3 of ($crypto*))) or
            
            // Medium: Cryptocurrency focus
            (5 of ($crypto*) and 2 of ($wild*)) or
            
            // High: FileZilla + cryptocurrency + archiving
            (2 of ($fz*) and 2 of ($crypto*) and ($archive1 or $archive2))
        )
}
```

---

## Forensic Artifacts & Investigation

### File System Artifacts

**Temporary Collections**:
```
C:\Users\<user>\AppData\Local\Temp\
├─ collected_<timestamp>.zip      (archived stolen files)
├─ wallet_backup_<random>.rar     (cryptocurrency wallets)
├─ ftp_creds_<pid>.txt           (FileZilla extracted credentials)
└─ log_<random>.dat              (Zeus file metadata log)
```

**Access Patterns** (NTFS Last Access Time):
```powershell
# Detect mass file access
Get-ChildItem -Path "C:\Users\*\Documents" -Recurse | 
    Where-Object { $_.LastAccessTime -gt (Get-Date).AddHours(-1) } | 
    Group-Object LastAccessTime | 
    Where-Object { $_.Count -gt 50 } |
    Select-Object Name, Count
```

**MFT Analysis** (Master File Table):
```bash
# Analyze MFT for bulk file reads by suspicious process
analyzeMFT.py -f $MFT -o mft.csv
grep "python.exe\|powershell.exe" mft.csv | wc -l  # Count accesses
```

### Registry Artifacts

**Recent File Access** (`HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`):
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.xml
├─ MRUListEx: 00 00 00 00 01 00 00 00 (2 files accessed)
├─ 0: C:\Users\Victim\AppData\Roaming\FileZilla\recentservers.xml
└─ 1: C:\Users\Victim\AppData\Roaming\FileZilla\sitemanager.xml

Forensic Value: Links suspicious process to specific file access
```

### Network Artifacts

**Large Upload Detection** (PCAP analysis):
```bash
# Identify large uploads to external IPs
tshark -r capture.pcap -Y "tcp.len > 100000 && ip.dst != 192.168.0.0/16" \
       -T fields -e ip.src -e ip.dst -e tcp.len | 
       awk '{sum[$1" "$2]+=$3} END {for (i in sum) print i, sum[i]}'
```

**Periodic Exfiltration Pattern**:
```
T+0s:      File collection starts
T+300s:    First archive created (5 minutes of collection)
T+305s:    HTTP POST upload (2.3MB encrypted payload)
T+600s:    Second archive created
T+605s:    HTTP POST upload (1.8MB encrypted payload)
...
Pattern: Regular 5-minute intervals suggest automated batch exfiltration
```

---

## Mitigation Strategies

### 1. File Access Auditing

**Enable SACL (System Access Control List) auditing**:

```powershell
# Audit FileZilla config access
$path = "C:\Users\*\AppData\Roaming\FileZilla"
$acl = Get-Acl $path
$auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
    "Everyone", "Read", "Success"
)
$acl.SetAuditRule($auditRule)
Set-Acl $path $acl

# Audit cryptocurrency wallet directories
$paths = @(
    "C:\Users\*\AppData\Roaming\Bitcoin\wallets",
    "C:\Users\*\AppData\Roaming\Ethereum\keystore",
    "C:\Users\*\AppData\Roaming\Electrum\wallets"
)

foreach ($path in $paths) {
    $acl = Get-Acl $path
    $auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
        "Everyone", "Read", "Success"
    )
    $acl.SetAuditRule($auditRule)
    Set-Acl $path $acl
}
```

### 2. Filesystem Honeypots

**Deploy decoy files to detect collection activity**:

```powershell
# Create fake FileZilla config with honeypot FTP credentials
$fakeFTP = @"
<?xml version="1.0" encoding="UTF-8"?>
<FileZilla3>
  <RecentServers>
    <Server>
      <Host>ftp.honeypot-detector.internal</Host>
      <User>admin_trap</User>
      <Pass encoding="base64">aG9uZXlwb3RfcGFzc3dvcmQ=</Pass>
    </Server>
  </RecentServers>
</FileZilla3>
"@

$path = "C:\Users\$env:USERNAME\AppData\Roaming\FileZilla\recentservers.xml"
New-Item -Path (Split-Path $path) -ItemType Directory -Force
Set-Content -Path $path -Value $fakeFTP

# Monitor honeypot FTP server for login attempts
```

**Create fake wallet files**:

```powershell
# Create decoy wallet.dat with embedded alert trigger
$fakeWallet = [byte[]](1..10000 | ForEach-Object { Get-Random -Maximum 256 })
$walletPath = "C:\Users\$env:USERNAME\AppData\Roaming\Bitcoin\wallets\wallet.dat"
New-Item -Path (Split-Path $walletPath) -ItemType Directory -Force
[IO.File]::WriteAllBytes($walletPath, $fakeWallet)

# Configure SACL to alert on access
$acl = Get-Acl $walletPath
$auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
    "Everyone", "Read", "Success"
)
$acl.SetAuditRule($auditRule)
Set-Acl $walletPath $acl
```

### 3. Application-Level Protections

**FileZilla**: Enable master password (encrypts stored passwords)

```xml
<!-- FileZilla config: Enable master password -->
<FileZilla3>
  <Settings>
    <Setting name="Master password encrypted">1</Setting>
    <Setting name="Master password"><!-- AES-encrypted value --></Setting>
  </Settings>
</FileZilla3>
```

**Cryptocurrency Wallets**: Use hardware wallets (Ledger, Trezor) - private keys never touch disk

**General**: Minimize credential storage - use password managers with encrypted vaults

### 4. Behavioral Detection (EDR)

**Rule**: Mass file enumeration followed by archive creation

```
Rule: Suspicious File Collection Activity
  IF process.file_access_count > 100 AND
     timeframe < 300 seconds AND
     process.create_archive == TRUE AND
     archive.location == "%TEMP%" AND
     network.upload_size > 1000000 bytes
  THEN alert("File collection and exfiltration detected")
```

**Rule**: Cryptocurrency wallet access from non-wallet processes

```
Rule: Unauthorized Wallet Access
  IF file.path CONTAINS "\\wallet.dat" OR
     file.path CONTAINS "\\keystore\\" OR
     file.path CONTAINS "\\Electrum\\wallets" AND
     process.name NOT IN (wallet_process_whitelist)
  THEN alert("Potential cryptocurrency theft")
```

---

## Conclusions & Recommendations

### Key Takeaways

1. **Application Knowledge is Key**: Modern stealers don't just grab files - they parse FileZilla XML, decrypt wallet.dat structures, understand keystore JSON formats. Defenses must protect application-specific data stores, not just generic documents.

2. **Cryptocurrency = High-Value Target**: Bitcoin/Ethereum wallets worth $10K-$1M+ per victim make them primary targets. Hardware wallets (Ledger/Trezor) essential for high-value holdings.

3. **Recursive Search is Universal**: All three techniques use recursive directory traversal. Behavioral detection of mass file enumeration (>100 files in <5 minutes) catches most file collection malware.

4. **Metadata Collection Before Exfiltration**: Stealers scan 10,000+ files but only exfiltrate 10-100 high-value targets. Defenders should monitor file access patterns, not just uploads.

5. **Temporary Archives = Smoking Gun**: Archive creation in `%TEMP%` followed by network upload is reliable indicator of data theft. Simple Sysmon rule catches 80%+ of file collection activity.

### Defensive Priority Matrix

| Priority | Action | Effort | Impact |
|----------|--------|--------|--------|
| **Critical** | Enable Sysmon file access monitoring (Event ID 11) for sensitive directories | Low | Very High |
| **Critical** | Deploy filesystem honeypots (fake wallet.dat, FileZilla XML) | Low | High |
| **High** | Enable SACL auditing on cryptocurrency wallet directories | Medium | High |
| **High** | Configure FileZilla master password (encrypt stored credentials) | Low | Medium |
| **Medium** | Deploy EDR rules for bulk file enumeration detection | Medium | High |
| **Medium** | Migrate cryptocurrency to hardware wallets (Ledger/Trezor) | Medium | Very High |

### Future Research Directions

**Emerging Threats**:
- **Cloud Storage Collection**: Targeting Dropbox/OneDrive local sync folders
- **Password Manager Harvesting**: 1Password/LastPass vault extraction
- **SSH Key Theft**: `~/.ssh/id_rsa` and `~/.ssh/known_hosts` targeting
- **Browser Extension Data**: Chrome/Firefox extension localStorage theft
- **Mobile Wallet Sync**: Android/iOS wallet backup file targeting

**Defensive Innovations**:
- **Virtual Filesystem Isolation**: Sandboxing sensitive application data
- **Real-Time Encryption**: Automatic encryption of wallet files when not in use
- **Behavioral Biometrics**: Detect abnormal file access patterns via ML

---

**Analysis Version**: 1.0  
**Last Updated**: November 24, 2025  
**Contributing Findings**: 3 detailed case studies (AngstStealer, PredatorTheStealer, Zeus/Zbot)  
**Total Documentation**: ~30,000 words across 3 findings + this executive summary
