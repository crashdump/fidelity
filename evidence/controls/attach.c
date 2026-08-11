/* The hostile control for the tracer detector, where no debugger is present.
 *
 * A minimal `ptrace` tracer, in the two forms that the detector must report.
 * An Android device carries no `gdb`, so this supplies both.
 *
 *   attach <program>   traces the program from its own exec. The initial scan
 *                      catches this one, because the tracer is already there
 *                      when `start()` runs.
 *   attach <pid>       traces a process that already runs. Only the worker
 *                      catches this one, and it is the realistic attack.
 *
 *   Linux    cc -o attach attach.c
 *   Android  the NDK clang for the device, under
 *            $NDK/toolchains/llvm/prebuilt/<host>/bin/
 *
 * Write no glob in this comment. A path that holds a star and a slash closes
 * the comment, and the file then does not compile. That happened once.
 */
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

/* How long the tracer holds a process that already runs. The worker cycles
 * every few seconds, so this leaves room for several cycles. The caller kills
 * this tracer once the traced process reports, so the wait is a bound and not
 * a cost. */
#define HOLD 20

static int is_number(const char *text) {
    if (*text == 0) return 0;
    for (; *text; text++) {
        if (*text < '0' || *text > '9') return 0;
    }
    return 1;
}

/* Traces a process that already runs.
 *
 * The attach stops the process, and a stopped process runs no worker and
 * reports nothing, so the tracer continues it at once and stays attached. */
static int hold(pid_t target) {
    int status;
    if (ptrace(PTRACE_ATTACH, target, 0, 0) != 0) return 3;
    if (waitpid(target, &status, 0) != target) return 3;
    ptrace(PTRACE_CONT, target, 0, 0);
    sleep(HOLD);
    ptrace(PTRACE_DETACH, target, 0, 0);
    return 0;
}

/* Traces a program from its own exec. */
static int launch(char **argv) {
    pid_t child = fork();
    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        execv(argv[0], argv);
        _exit(127);
    }
    int status;
    while (waitpid(child, &status, 0) == child) {
        if (WIFEXITED(status) || WIFSIGNALED(status)) break;
        ptrace(PTRACE_CONT, child, 0, 0);
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    if (is_number(argv[1])) return hold((pid_t)atoi(argv[1]));
    return launch(&argv[1]);
}
