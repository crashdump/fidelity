/* Creates the two hostile baseline boundaries on a POSIX process.
 *
 * FIDELITY_BASELINE_BOUNDARY=writable creates one executable page before
 * start. It adds write access after three seconds.
 *
 * FIDELITY_BASELINE_BOUNDARY=limit creates 1025 separate executable pages
 * before start. A guard page separates each executable page.
 */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

#define REGION_COUNT 1025

static void *writable_page;
static size_t page_size;

static void fail(const char *operation) {
    perror(operation);
    _exit(90);
}

static void *make_writable(void *unused) {
    (void)unused;
    sleep(3);
    if (mprotect(writable_page, page_size,
                 PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        fail("mprotect made no writable code page");
    }
    fprintf(stderr, "[control] made one executable page writable after start\n");
    return NULL;
}

static void prepare_writable(void) {
    int flags = MAP_PRIVATE | MAP_ANONYMOUS;
#ifdef __APPLE__
    flags |= MAP_JIT;
#endif
    writable_page = mmap(NULL, page_size * 2, PROT_NONE,
                         flags, -1, 0);
    if (writable_page == MAP_FAILED) {
        fail("mmap reserved no writable-code subject");
    }
    if (mprotect(writable_page, page_size, PROT_READ | PROT_EXEC) != 0) {
        fail("mprotect made no executable page");
    }

    pthread_t thread;
    if (pthread_create(&thread, NULL, make_writable, NULL) != 0) {
        fail("pthread_create made no control thread");
    }
    if (pthread_detach(thread) != 0) {
        fail("pthread_detach kept the control thread joinable");
    }
}

static void prepare_limit(void) {
    size_t bytes = page_size * 2 * REGION_COUNT;
    void *base = mmap(NULL, bytes, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) {
        fail("mmap reserved no baseline-limit subject");
    }

    for (size_t index = 0; index < REGION_COUNT; index++) {
        void *page = (char *)base + index * page_size * 2;
        if (mprotect(page, page_size, PROT_READ | PROT_EXEC) != 0) {
            fail("mprotect made fewer than 1025 executable regions");
        }
    }
    fprintf(stderr, "[control] created 1025 separate executable regions before start\n");
}

__attribute__((constructor)) static void prepare(void) {
    const char *mode = getenv("FIDELITY_BASELINE_BOUNDARY");
    if (mode == NULL) {
        return;
    }

    long value = sysconf(_SC_PAGESIZE);
    if (value <= 0) {
        fail("sysconf reported no page size");
    }
    page_size = (size_t)value;

    if (strcmp(mode, "writable") == 0) {
        prepare_writable();
    } else if (strcmp(mode, "limit") == 0) {
        prepare_limit();
    } else {
        fprintf(stderr, "unknown FIDELITY_BASELINE_BOUNDARY value: %s\n", mode);
        _exit(91);
    }
}
