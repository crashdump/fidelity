/* The hostile control for the runtime baseline.
 *
 * An agent that is already inside the process, and that acts later. It waits
 * until the application runs, then it maps executable memory. That is what a
 * run-time injection leaves behind, and it arrives after `start()` captured
 * the baseline.
 *
 * The delay is what makes the control honest. An agent that mapped its memory
 * at load would sit inside the baseline, and the detector would report
 * nothing.
 *
 *   Linux    gcc -shared -fPIC -o delayed.so delayed.c -lpthread
 *   macOS    clang -dynamiclib -o delayed.dylib delayed.c
 *   iOS sim  clang -arch arm64 -isysroot $(xcrun --sdk iphonesimulator \
 *              --show-sdk-path) -mios-simulator-version-min=18.0 \
 *              -dynamiclib -o delayed.dylib delayed.c
 */
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/mman.h>

static void *act(void *unused) {
    (void)unused;
    sleep(3);
    void *p = mmap(0, 65536, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_ANON, -1, 0);
    fprintf(stderr, "[agent] mapped executable memory at %p after the baseline\n", p);
    return 0;
}

__attribute__((constructor)) static void arrive(void) {
    pthread_t t;
    pthread_create(&t, 0, act, 0);
    pthread_detach(t);
}
