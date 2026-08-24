// Maps an image section into a suspended process without loader registration.

#include <windows.h>
#include <stdio.h>

typedef LONG NTSTATUS;
typedef NTSTATUS(NTAPI *NtMapViewOfSectionFn)(
    HANDLE, HANDLE, PVOID *, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T,
    DWORD, ULONG, ULONG);

#define VIEW_UNMAP 2

static int map_image(HANDLE process, const char *path) {
    HANDLE file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "CreateFileA failed: %lu\n", GetLastError());
        return 1;
    }
    HANDLE section = CreateFileMappingA(file, NULL, PAGE_READONLY | SEC_IMAGE,
                                        0, 0, NULL);
    if (section == NULL) {
        fprintf(stderr, "CreateFileMappingA failed: %lu\n", GetLastError());
        CloseHandle(file);
        return 1;
    }
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    NtMapViewOfSectionFn map = ntdll == NULL ? NULL :
        (NtMapViewOfSectionFn)GetProcAddress(ntdll, "NtMapViewOfSection");
    if (map == NULL) {
        fprintf(stderr, "NtMapViewOfSection is absent\n");
        CloseHandle(section);
        CloseHandle(file);
        return 1;
    }

    PVOID base = NULL;
    SIZE_T bytes = 0;
    NTSTATUS status = map(section, process, &base, 0, 0, NULL, &bytes,
                          VIEW_UNMAP, 0, PAGE_READONLY);
    CloseHandle(section);
    CloseHandle(file);
    if (status < 0 || base == NULL) {
        fprintf(stderr, "NtMapViewOfSection failed: 0x%08lx\n", (unsigned long)status);
        return 1;
    }
    printf("mapped an image outside the loader at %p\n", base);
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: catalog-map-windows.exe <program>\n");
        return 2;
    }

    STARTUPINFOA startup;
    PROCESS_INFORMATION process;
    ZeroMemory(&startup, sizeof(startup));
    startup.cb = sizeof(startup);
    ZeroMemory(&process, sizeof(process));

    if (!CreateProcessA(NULL, argv[1], NULL, NULL, TRUE, CREATE_SUSPENDED,
                        NULL, NULL, &startup, &process)) {
        fprintf(stderr, "CreateProcessA failed: %lu\n", GetLastError());
        return 1;
    }
    if (map_image(process.hProcess, argv[1]) != 0) {
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
