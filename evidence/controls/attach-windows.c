// A minimal Windows debugger, so the tracer controls need no debugger install.
//
// A GitHub runner ships no `cdb.exe` that this project can depend on, and the
// Linux controls already solved the same problem: `attach.c` is the tracer
// there. This file is the same idea, with the documented Win32 debug loop.
//
// Two forms, the same two that `attach.c` offers:
//
//     attach-windows.exe <program>   traces the program from its own start
//     attach-windows.exe <pid>       attaches to a process that already runs
//
// Build it with the compiler that the runner ships:
//
//     cl /nologo /W4 attach-windows.c
//
// A path in a comment holds no glob. Two of those characters together close a
// comment, and a file that nobody compiles stops compiling.
//
// It exits zero when the debug loop ran and the subject ended, and non-zero
// when the attach failed.

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

// Windows kills a debuggee when its debugger exits, and the driver script
// kills this tracer after it holds the process. Without this call the subject
// dies before it can report what it caught, and the control proves nothing.
static void survive_the_tracer(void) {
    DebugSetProcessKillOnExit(FALSE);
}

// Runs the debug loop until the subject ends.
//
// Every event needs a continue, or the subject stays suspended and the control
// measures a stopped process rather than a traced one.
static int pump(void) {
    DEBUG_EVENT event;

    for (;;) {
        if (!WaitForDebugEvent(&event, INFINITE)) {
            return 0;
        }
        if (event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            // The last event needs a continue as much as any other one. A
            // subject that reports this event is not gone yet: it waits for
            // the debugger to release it, and a debugger that returns here
            // leaves it suspended forever. The wait below then never ends.
            // Measured on 2026-08-15, where the subject printed every line
            // and both processes stayed alive.
            ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE);
            return 0;
        }
        ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE);
    }
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
        fprintf(stderr, "usage: attach-windows.exe <program or pid>\n");
        return 2;
    }

    if (all_digits(argv[1])) {
        DWORD pid = (DWORD)strtoul(argv[1], NULL, 10);
        if (!DebugActiveProcess(pid)) {
            fprintf(stderr, "DebugActiveProcess failed: %lu\n", GetLastError());
            return 1;
        }
        survive_the_tracer();
        return pump();
    }

    STARTUPINFOA startup;
    PROCESS_INFORMATION process;
    ZeroMemory(&startup, sizeof(startup));
    startup.cb = sizeof(startup);
    ZeroMemory(&process, sizeof(process));

    // DEBUG_ONLY_THIS_PROCESS traces the subject and not the children it
    // starts, which is what `DebugActiveProcess` gives the other form. The two
    // forms then differ in when the tracer arrives, and in nothing else.
    //
    // The subject inherits the handles of this process, so what it prints
    // reaches the harness. Without that the subject writes to a handle that
    // this process never gave it, the control reads an empty output, and the
    // finding it must show cannot arrive. `inject-windows.c` inherits for the
    // same reason. Measured on 2026-08-15.
    if (!CreateProcessA(NULL, argv[1], NULL, NULL, TRUE,
                        DEBUG_ONLY_THIS_PROCESS, NULL, NULL,
                        &startup, &process)) {
        fprintf(stderr, "CreateProcessA failed: %lu\n", GetLastError());
        return 1;
    }
    survive_the_tracer();
    pump();

    DWORD status = 1;
    WaitForSingleObject(process.hProcess, INFINITE);
    GetExitCodeProcess(process.hProcess, &status);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return (int)status;
}
