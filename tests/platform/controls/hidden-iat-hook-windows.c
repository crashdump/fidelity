// Hides a redirected import behind a fake terminator, in a running process.
//
// This is the evasion that the import-table reader missed until 2026-08-20. The
// address table and the lookup table hold one entry for each import, and both
// end with a zero entry. The address table is writable by design, so an
// attacker writes zero to one unused entry and ends a walk that counts there.
// Every entry behind that zero in the same library then leaves the snapshot, so
// a redirect among those entries compares against nothing and reports clean.
//
// The reader now counts the lookup table, which nothing writes after the load,
// so every slot stays and the zeroed entry itself reports as a value that
// moved. This control proves that end to end: it zeros one startup-only import,
// which is the fake terminator, and it redirects a later startup-only import in
// the same library, which is the hidden redirect. The fixed reader reports a
// finding, and the address-table walk reported clean.
//
// It redirects and zeros startup-only imports, such as `GetCommandLineW`, so
// the subject never calls either slot in its poll loop and keeps running until
// the worker reports. The replacement is a real address that another entry
// holds, so the redirect points at code that already exists and maps nothing.
//
// Build. No path here holds a star, because a star and a slash close a comment:
//   build-control.sh hidden-iat-hook-windows
//
// Run:
//   hidden-iat-hook-windows.exe <pid>

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Imports that a process calls once at startup and never in a loop. Zeroing or
// redirecting one of these leaves the subject running until the worker scans.
static const char *STARTUP_IMPORTS[] = {
    "GetCommandLineW", "GetCommandLineA", "GetStartupInfoW",
    "GetModuleHandleW", "SetUnhandledExceptionFilter", "GetEnvironmentStringsW",
};
#define STARTUP_COUNT (int)(sizeof STARTUP_IMPORTS / sizeof STARTUP_IMPORTS[0])

// How many startup imports of one library the control tracks. Two is enough:
// the first is the fake terminator, and the last is the hidden redirect.
#define MAX_VICTIMS 16

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

// Writes `size` bytes to the subject at `address`, through a writable window.
static int rwrite(HANDLE process, BYTE *address, const void *in, SIZE_T size) {
    DWORD old = 0;
    if (!VirtualProtectEx(process, address, size, PAGE_READWRITE, &old)) {
        return 0;
    }
    SIZE_T wrote = 0;
    BOOL ok = WriteProcessMemory(process, address, in, size, &wrote);
    VirtualProtectEx(process, address, size, old, &old);
    return ok && wrote == size;
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
        fprintf(stderr, "usage: hidden-iat-hook-windows.exe <pid>\n");
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
    // The two victims must share one library, so the redirect sits behind the
    // fake terminator in the same address table. The search fills these from one
    // descriptor and keeps the first pair it finds.
    BYTE *terminator_slot = NULL;
    BYTE *redirect_slot = NULL;
    const char *terminator_name = NULL;
    const char *redirect_name = NULL;

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

        // The startup-only slots of this one library, in entry order.
        BYTE *victims[MAX_VICTIMS];
        const char *names[MAX_VICTIMS];
        int victim_count = 0;

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
            if (is_startup_import(name) && victim_count < MAX_VICTIMS) {
                victims[victim_count] = base + address_rva + entry;
                for (int index = 0; index < STARTUP_COUNT; index++) {
                    if (strcmp(name, STARTUP_IMPORTS[index]) == 0) {
                        names[victim_count] = STARTUP_IMPORTS[index];
                    }
                }
                victim_count++;
            }
        }

        // A library with two startup-only imports gives the pair. The first is
        // the fake terminator, and the last sits behind it in the same table.
        if (victim_count >= 2) {
            terminator_slot = victims[0];
            terminator_name = names[0];
            redirect_slot = victims[victim_count - 1];
            redirect_name = names[victim_count - 1];
            break;
        }
    }

    if (terminator_slot == NULL || redirect_slot == NULL || replacement == 0) {
        fprintf(stderr, "no library of pid %lu holds two startup imports to hide a redirect\n",
                (unsigned long)pid);
        CloseHandle(process);
        return 1;
    }

    // Read what each slot holds now, for the report.
    ULONGLONG terminator_held = 0;
    ULONGLONG redirect_held = 0;
    rread(process, terminator_slot, &terminator_held, sizeof terminator_held);
    rread(process, redirect_slot, &redirect_held, sizeof redirect_held);

    // The redirect lands first, so the hidden entry already points elsewhere
    // when the fake terminator hides it. The address-table walk would stop at
    // the zero and never reach this slot.
    if (!rwrite(process, redirect_slot, &replacement, sizeof replacement)) {
        fprintf(stderr, "the redirect write failed: %lu\n", GetLastError());
        CloseHandle(process);
        return 1;
    }
    ULONGLONG zero = 0;
    if (!rwrite(process, terminator_slot, &zero, sizeof zero)) {
        fprintf(stderr, "the terminator write failed: %lu\n", GetLastError());
        CloseHandle(process);
        return 1;
    }
    CloseHandle(process);

    printf("hook: zeroed %s at %p, held %llx, is the fake terminator (pid %lu)\n", terminator_name,
           (void *)terminator_slot, terminator_held, (unsigned long)pid);
    printf("hook: redirected %s at %p, held %llx, holds %llx, behind the terminator (pid %lu)\n",
           redirect_name, (void *)redirect_slot, redirect_held, replacement, (unsigned long)pid);
    fflush(stdout);
    return 0;
}
