// Redirects one import address table entry of a running process.
//
// This is the Windows hostile control that no memory detector catches. The
// subject maps no new executable region, and no region changes protection that
// the runtime baseline watches, because the import table sits in a data
// section. The imported call still reaches another address. Only a comparison
// of the table against the start of the process reports it, which is the
// `instrumentation.dispatch_targets` detector.
//
// Windows offers no preload variable, so the control redirects the entry from
// outside, after the subject printed its process identifier, which is after
// `start()` captured the baseline. That is the same shape as the tracer and
// injection controls on this platform.
//
// It redirects a startup-only import, such as `GetCommandLineW`, to the address
// that another entry already holds. The replacement is a real function inside a
// loaded module, so the redirect points at code that already exists and maps
// nothing. The subject never calls a startup import in its poll loop, so it
// keeps running until the worker reports.
//
// Build. No path here holds a star, because a star and a slash close a comment:
//   build-control.sh iat-hook-windows
//
// Run:
//   iat-hook-windows.exe <pid>

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Imports that a process calls once at startup and never in a loop. Redirecting
// one of these leaves the subject running until the worker scans.
static const char *STARTUP_IMPORTS[] = {
    "GetCommandLineW", "GetCommandLineA", "GetStartupInfoW",
    "GetModuleHandleW", "SetUnhandledExceptionFilter", "GetEnvironmentStringsW",
};
#define STARTUP_COUNT (int)(sizeof STARTUP_IMPORTS / sizeof STARTUP_IMPORTS[0])

// The base of the main module of a process, which is its executable.
static BYTE *main_module_base(DWORD pid) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return NULL;
    }
    MODULEENTRY32W entry;
    entry.dwSize = sizeof entry;
    BYTE *base = NULL;
    if (Module32FirstW(snapshot, &entry)) {
        base = entry.modBaseAddr;
    }
    CloseHandle(snapshot);
    return base;
}

// Reads `size` bytes from the subject at `address`.
static int rread(HANDLE process, BYTE *address, void *out, SIZE_T size) {
    SIZE_T got = 0;
    return ReadProcessMemory(process, address, out, size, &got) && got == size;
}

// Whether an imported name is a startup-only import.
static int is_startup_import(const char *name) {
    for (int index = 0; index < STARTUP_COUNT; index++) {
        if (strcmp(name, STARTUP_IMPORTS[index]) == 0) {
            return 1;
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: iat-hook-windows.exe <pid>\n");
        return 2;
    }
    DWORD pid = (DWORD)strtoul(argv[1], NULL, 10);
    HANDLE process = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
                                     PROCESS_QUERY_INFORMATION,
                                 FALSE, pid);
    if (process == NULL) {
        fprintf(stderr, "OpenProcess failed: %lu\n", GetLastError());
        return 1;
    }

    BYTE *base = main_module_base(pid);
    if (base == NULL) {
        fprintf(stderr, "the main module of pid %lu did not answer\n", (unsigned long)pid);
        CloseHandle(process);
        return 1;
    }

    LONG e_lfanew = 0;
    DWORD import_rva = 0;
    // The data directory sits at optional header + 112, and the import entry is
    // the second one, so its virtual address is at + 112 + 8.
    if (!rread(process, base + 60, &e_lfanew, sizeof e_lfanew) ||
        !rread(process, base + e_lfanew + 24 + 112 + 8, &import_rva, sizeof import_rva) ||
        import_rva == 0) {
        fprintf(stderr, "the import table of pid %lu did not read\n", (unsigned long)pid);
        CloseHandle(process);
        return 1;
    }

    // A valid function address that another entry already holds, so the hooked
    // entry points at real code inside a loaded module.
    ULONGLONG replacement = 0;
    BYTE *victim_slot = NULL;
    const char *victim_name = NULL;

    for (DWORD offset = 0;; offset += 20) {
        DWORD lookup_rva = 0;
        DWORD address_rva = 0;
        // IMAGE_IMPORT_DESCRIPTOR: OriginalFirstThunk at 0, FirstThunk at 16.
        if (!rread(process, base + import_rva + offset, &lookup_rva, 4) ||
            !rread(process, base + import_rva + offset + 16, &address_rva, 4)) {
            break;
        }
        if (lookup_rva == 0 && address_rva == 0) {
            break;
        }
        DWORD names_rva = lookup_rva != 0 ? lookup_rva : address_rva;

        for (DWORD entry = 0;; entry += 8) {
            ULONGLONG name_entry = 0;
            ULONGLONG address_value = 0;
            if (!rread(process, base + names_rva + entry, &name_entry, 8) ||
                !rread(process, base + address_rva + entry, &address_value, 8)) {
                break;
            }
            if (name_entry == 0) {
                break;
            }
            // The first valid address becomes the replacement.
            if (replacement == 0 && address_value != 0) {
                replacement = address_value;
            }
            // A high bit means an ordinal import, which carries no name.
            if (name_entry & 0x8000000000000000ULL) {
                continue;
            }
            char name[64] = {0};
            // IMAGE_IMPORT_BY_NAME: a two-byte hint, then the name.
            if (!rread(process, base + (DWORD)(name_entry & 0x7fffffff) + 2, name,
                       sizeof name - 1)) {
                continue;
            }
            if (victim_slot == NULL && is_startup_import(name)) {
                victim_slot = base + address_rva + entry;
                victim_name = STARTUP_IMPORTS[0];
                for (int index = 0; index < STARTUP_COUNT; index++) {
                    if (strcmp(name, STARTUP_IMPORTS[index]) == 0) {
                        victim_name = STARTUP_IMPORTS[index];
                    }
                }
            }
        }
    }

    if (victim_slot == NULL || replacement == 0) {
        fprintf(stderr, "no startup import to redirect in pid %lu\n", (unsigned long)pid);
        CloseHandle(process);
        return 1;
    }

    DWORD old = 0;
    if (!VirtualProtectEx(process, victim_slot, sizeof replacement, PAGE_READWRITE, &old)) {
        fprintf(stderr, "VirtualProtectEx failed: %lu\n", GetLastError());
        CloseHandle(process);
        return 1;
    }
    SIZE_T wrote = 0;
    ULONGLONG held = 0;
    rread(process, victim_slot, &held, sizeof held);
    BOOL ok = WriteProcessMemory(process, victim_slot, &replacement, sizeof replacement, &wrote);
    VirtualProtectEx(process, victim_slot, sizeof replacement, old, &old);
    CloseHandle(process);

    if (!ok || wrote != sizeof replacement) {
        fprintf(stderr, "WriteProcessMemory failed: %lu\n", GetLastError());
        return 1;
    }

    printf("hook: redirected %s at %p, held %llx, holds %llx (pid %lu)\n", victim_name,
           (void *)victim_slot, held, replacement, (unsigned long)pid);
    fflush(stdout);
    return 0;
}
