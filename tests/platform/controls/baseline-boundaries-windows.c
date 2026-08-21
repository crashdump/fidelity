// Creates the two hostile baseline boundaries on a Windows process.
//
//     baseline-boundaries-windows.exe writable <program>
//     baseline-boundaries-windows.exe limit <program>
//
// The control creates the process in a suspended state. The initial snapshot
// therefore includes each region that the control adds.

#include <windows.h>
#include <stdio.h>
#include <string.h>

#define REGION_COUNT 1025

static int fail(HANDLE process, const char *operation) {
    fprintf(stderr, "%s failed: %lu\n", operation, GetLastError());
    TerminateProcess(process, 90);
    return 1;
}

static LPVOID reserve_writable(HANDLE process, SIZE_T page_size) {
    LPVOID base = VirtualAllocEx(process, NULL, page_size * 2, MEM_RESERVE,
                                 PAGE_NOACCESS);
    if (base == NULL) {
        return NULL;
    }
    return VirtualAllocEx(process, base, page_size, MEM_COMMIT,
                          PAGE_EXECUTE_READ);
}

static int prepare_limit(HANDLE process, SIZE_T page_size) {
    for (int index = 0; index < REGION_COUNT; index++) {
        if (reserve_writable(process, page_size) == NULL) {
            return fail(process, "VirtualAllocEx for the baseline limit");
        }
    }
    printf("created 1025 separate executable regions before start\n");
    fflush(stdout);
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 3 ||
        (strcmp(argv[1], "writable") != 0 && strcmp(argv[1], "limit") != 0)) {
        fprintf(stderr,
                "usage: baseline-boundaries-windows.exe <writable or limit> <program>\n");
        return 2;
    }

    SYSTEM_INFO system;
    GetSystemInfo(&system);
    SIZE_T page_size = (SIZE_T)system.dwPageSize;

    STARTUPINFOA startup;
    PROCESS_INFORMATION process;
    ZeroMemory(&startup, sizeof(startup));
    startup.cb = sizeof(startup);
    ZeroMemory(&process, sizeof(process));

    if (!CreateProcessA(NULL, argv[2], NULL, NULL, TRUE, CREATE_SUSPENDED,
                        NULL, NULL, &startup, &process)) {
        fprintf(stderr, "CreateProcessA failed: %lu\n", GetLastError());
        return 1;
    }

    LPVOID writable = NULL;
    if (strcmp(argv[1], "writable") == 0) {
        writable = reserve_writable(process.hProcess, page_size);
        if (writable == NULL) {
            return fail(process.hProcess, "VirtualAllocEx for writable code");
        }
    } else if (prepare_limit(process.hProcess, page_size) != 0) {
        return 1;
    }

    if (ResumeThread(process.hThread) == (DWORD)-1) {
        return fail(process.hProcess, "ResumeThread");
    }

    if (writable != NULL) {
        Sleep(3000);
        DWORD old_protection = 0;
        if (!VirtualProtectEx(process.hProcess, writable, page_size,
                              PAGE_EXECUTE_READWRITE, &old_protection)) {
            return fail(process.hProcess, "VirtualProtectEx for writable code");
        }
        printf("made one executable page writable after start\n");
        fflush(stdout);
    }

    WaitForSingleObject(process.hProcess, INFINITE);
    DWORD status = 1;
    GetExitCodeProcess(process.hProcess, &status);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return (int)status;
}
