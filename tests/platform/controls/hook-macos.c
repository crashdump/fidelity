/* The hostile control for the dispatch detector, on macOS and on iOS.
 *
 * An agent that is already inside the process, and that acts later. It waits
 * until the application runs, then it rewrites one entry of the symbol-pointer
 * table of the main image. The call that entry serves then reaches another
 * function that already exists, so no new executable memory maps and the
 * runtime baseline stays clean. Only a comparison of the table against the
 * start of the process reports it.
 *
 * It points `memcpy` at a forwarder of its own, which calls the real `memcpy`
 * and returns what it returns. That is the shape a real hook takes, and the
 * subject keeps running because the forwarder answers every call.
 *
 * The pair that `hook.c` uses on Linux does not work here. Measured on macOS
 * 26.5.2 on 2026-08-20: `memcpy` and `memmove` resolve to one address in this
 * libSystem, so pointing one at the other rewrites nothing and the control
 * would pass while proving nothing.
 *
 * The forwarder maps no new memory after `start()`, which is what this control
 * needs. The loader maps this library before the subject runs, so its code
 * sits inside the baseline that `start()` captured. The runtime baseline
 * therefore stays clean, and the dispatch detector is the only one that
 * reports.
 *
 * The delay is what makes the control honest. An entry that moved before
 * `start()` read the table would sit inside the baseline, and the detector
 * would report nothing.
 *
 *   macOS    clang -dynamiclib -o hook-macos.dylib hook-macos.c
 *   iOS sim  clang -arch arm64 -isysroot $(xcrun --sdk iphonesimulator \
 *              --show-sdk-path) -mios-simulator-version-min=26.0 \
 *              -dynamiclib -o hook-macos.dylib hook-macos.c
 *
 * Write no glob in this comment. A path that holds a star and a slash closes
 * the comment, and the file then does not compile.
 */
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* The section type that holds pointers which the loader binds at load. */
#define NON_LAZY 0x6

/* Makes the page that holds one address writable, and reports whether it
 * worked. A chained image keeps its symbol pointers in `__DATA_CONST`, which
 * the loader turns read-only once it has bound them. */
static int unlock(void *at) {
    long page = sysconf(_SC_PAGESIZE);
    uintptr_t start = (uintptr_t)at & ~(uintptr_t)(page - 1);
    return mprotect((void *)start, (size_t)page, PROT_READ | PROT_WRITE) == 0;
}

/* Points one symbol pointer of the main image at another function.
 *
 * Returns the address of the entry it rewrote, and zero when the table holds
 * no entry for `from`. */
static uint64_t redirect(uint64_t from, uint64_t to) {
    const struct mach_header_64 *header = 0;
    intptr_t slide = 0;
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const struct mach_header_64 *candidate =
            (const struct mach_header_64 *)_dyld_get_image_header(i);
        if (candidate && candidate->filetype == MH_EXECUTE) {
            header = candidate;
            slide = _dyld_get_image_vmaddr_slide(i);
            break;
        }
    }
    if (!header) return 0;

    const uint8_t *at = (const uint8_t *)(header + 1);
    for (uint32_t i = 0; i < header->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)at;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg =
                (const struct segment_command_64 *)at;
            const struct section_64 *sec = (const struct section_64 *)(seg + 1);
            for (uint32_t s = 0; s < seg->nsects; s++, sec++) {
                if ((sec->flags & SECTION_TYPE) != NON_LAZY) continue;
                uint64_t *slot = (uint64_t *)((uintptr_t)sec->addr + slide);
                for (uint64_t k = 0; k < sec->size / 8; k++) {
                    if (slot[k] != from) continue;
                    if (!unlock(&slot[k])) return 0;
                    slot[k] = to;
                    return (uint64_t)(uintptr_t)&slot[k];
                }
            }
        }
        at += lc->cmdsize;
    }
    return 0;
}

/* The real function, which the forwarder below calls. */
static void *(*real_memcpy)(void *, const void *, size_t);

/* What the rewritten entry reaches. A real hook reads or changes the call and
 * then forwards it, and this one only forwards. */
static void *forwarder(void *to, const void *from, size_t count) {
    return real_memcpy(to, from, count);
}

static void *act(void *unused) {
    (void)unused;
    sleep(3);

    real_memcpy = (void *(*)(void *, const void *, size_t))dlsym(RTLD_DEFAULT,
                                                                "memcpy");
    if (!real_memcpy) {
        fprintf(stderr, "[hook] memcpy did not resolve\n");
        return 0;
    }
    uint64_t from = (uint64_t)(uintptr_t)real_memcpy;
    uint64_t to = (uint64_t)(uintptr_t)forwarder;

    uint64_t slot = redirect(from, to);
    if (slot) {
        fprintf(stderr,
                "[hook] slot for memcpy at 0x%llx held 0x%llx, holds 0x%llx\n",
                (unsigned long long)slot, (unsigned long long)from,
                (unsigned long long)to);
    } else {
        fprintf(stderr, "[hook] the main image holds no entry for memcpy\n");
    }
    return 0;
}

__attribute__((constructor)) static void arrive(void) {
    pthread_t t;
    pthread_create(&t, 0, act, 0);
    pthread_detach(t);
}
