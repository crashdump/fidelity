// Maps executable memory into a process that already runs.
//
// Two forms, and each one serves a different detector:
//
//     inject-windows.exe <pid>       maps into a process that already runs
//     inject-windows.exe <program>   maps before the program starts, and runs it
//
// The region is private, so no image and no named file accounts for it. The
// first form arrives after the subject captured its baseline, so
// `integrity.runtime_baseline` must report it. The second form is present
// before `start()` runs, which is what `LD_PRELOAD` gives on Linux, so
// `instrumentation.unaccounted_code` must report it.
//
// Windows offers no `LD_PRELOAD` and no `DYLD_INSERT_LIBRARIES`, so the macOS
// and Linux shape does not carry over. An external allocation into another
// process is the shape that a real agent takes here, so the control sits
// closer to the attack rather than further from it.
//
// Build it with the compiler that the runner ships:
//
//     cl /nologo /W4 inject-windows.c
//
// A path in a comment holds no glob. Two of those characters together close a
// comment, and a file that nobody compiles stops compiling.
//
// It exits zero when the allocation succeeded, and non-zero otherwise. The
// second form returns what the program it started returned.

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

// How much executable memory to map. The macOS and Linux baseline controls map
// the same amount, so the three records compare.
#define BYTES 65536

// Maps the region, and reports what it did.
//
// PROCESS_VM_OPERATION is the right that `VirtualAllocEx` documents. The pid
// form asks for that alone, so the control states what an agent really needs.
static int map_into(HANDLE target, DWORD pid) {
    LPVOID mapped = VirtualAllocEx(target, NULL, (SIZE_T)BYTES,
                                   MEM_COMMIT | MEM_RESERVE,
                                   PAGE_EXECUTE_READWRITE);
    if (mapped == NULL) {
        fprintf(stderr, "VirtualAllocEx failed: %lu\n", GetLastError());
        return 1;
    }
    printf("mapped %d bytes of executable memory into pid %lu\n",
           BYTES, (unsigned long)pid);
    fflush(stdout);
    return 0;
}

// Whether the argument is a process identifier rather than a path.
static int all_digits(const char *text) {
    if (*text == '\0') {
        return 0;
    }
    while (*text != '\0') {
        if (*text < '0' || *text > '9') {
            return 0;
        }
        text++;
    }
    return 1;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: inject-windows.exe <program or pid>\n");
        return 2;
    }

    if (all_digits(argv[1])) {
        DWORD pid = (DWORD)strtoul(argv[1], NULL, 10);
        HANDLE target = OpenProcess(PROCESS_VM_OPERATION, FALSE, pid);
        if (target == NULL) {
            fprintf(stderr, "OpenProcess failed: %lu\n", GetLastError());
            return 1;
        }
        int status = map_into(target, pid);
        CloseHandle(target);
        return status;
    }

    STARTUPINFOA startup;
    PROCESS_INFORMATION process;
    ZeroMemory(&startup, sizeof(startup));
    startup.cb = sizeof(startup);
    ZeroMemory(&process, sizeof(process));

    // The subject starts suspended, so the region is in place before its own
    // first instruction. That is what a preloaded library gives on Linux, and
    // it is the only way the memory is present when `start()` reads.
    if (!CreateProcessA(NULL, argv[1], NULL, NULL, TRUE, CREATE_SUSPENDED,
                        NULL, NULL, &startup, &process)) {
        fprintf(stderr, "CreateProcessA failed: %lu\n", GetLastError());
        return 1;
    }

    if (map_into(process.hProcess, process.dwProcessId) != 0) {
        TerminateProcess(process.hProcess, 1);
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
        return 1;
    }

    DWORD status = 1;
    ResumeThread(process.hThread);
    WaitForSingleObject(process.hProcess, INFINITE);
    GetExitCodeProcess(process.hProcess, &status);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return (int)status;
}
