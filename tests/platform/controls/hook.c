// Rewrites one dispatch target of the main image after the subject started.
//
// This is the hostile control that no detector caught before. The subject maps
// no new executable region, and no region changes protection, so the runtime
// baseline reports clean. The table that this control rewrites holds data
// rather than code, so no executable-memory rule reaches it either. The call
// still goes somewhere else.
//
// Both forms keep the subject running, because a hook that stops the process
// proves nothing: a detector needs a live process to report on, and a real
// attacker keeps the function working.
//
// The two forms need two rules:
//
//   outside  the target points at a trampoline that this control maps, which
//            no loaded object accounts for. The trampoline jumps to the
//            address the slot held, so the call still does its work. This is
//            the shape a hook takes when it needs its own code.
//   inside   the target points at a forwarder of this library, which calls the
//            real memcpy and returns what it returns. The loader maps this
//            library before the subject runs, so the forwarder sits inside the
//            baseline that start() captured and no new executable memory
//            arrives. No absolute rule reports this one, and only a comparison
//            against the start of the process does.
//
// The inside form pointed memcpy at memmove until 2026-08-20. Two systems
// resolve both names to one address, so the rewrite wrote back the value the
// slot already held and the control passed while proving nothing. Measured on
// macOS 26.5.2 and on Android 16, both ARM64. A forwarder of this library
// depends on no libc, and hook-macos.c already took that shape.
//
// Build. No path here holds a star, because a star and a slash close a
// comment:
//   cc -O2 -shared -fPIC -o hook.so hook.c -lpthread
//
// Run:
//   LD_PRELOAD=./hook.so FIDELITY_HOOK=outside <subject>
//   LD_PRELOAD=./hook.so FIDELITY_HOOK=inside  <subject>

#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "dispatch.h"

#define PAGE 4096

// Waits, so that the rewrite lands after start() captured the baseline.
#define DELAY_SECONDS 3

static long page_size(void)
{
    long size = sysconf(_SC_PAGESIZE);
    return size > 0 ? size : PAGE;
}

// Makes the page that holds one address writable. Full binding puts the table
// in a read-only segment, so a hook does this first, and doing it changes no
// executable region.
static int make_writable(void *address)
{
    long size = page_size();
    void *page = (void *)((unsigned long)address & ~(unsigned long)(size - 1));
    return mprotect(page, (size_t)size, PROT_READ | PROT_WRITE);
}

// Writes a jump to `destination`, so the hooked call still reaches the code
// that answered it before.
static size_t write_jump(unsigned char *code, ElfW(Addr) destination)
{
#if defined(__aarch64__)
    // ldr x16, [pc, #8] ; br x16 ; then the address
    unsigned int instructions[2] = {0x58000050u, 0xd61f0200u};
    memcpy(code, instructions, sizeof instructions);
    memcpy(code + sizeof instructions, &destination, sizeof destination);
    return sizeof instructions + sizeof destination;
#elif defined(__x86_64__)
    // movabs rax, destination ; jmp rax
    unsigned char instructions[12] = {0x48, 0xb8};
    memcpy(instructions + 2, &destination, sizeof destination);
    instructions[10] = 0xff;
    instructions[11] = 0xe0;
    memcpy(code, instructions, sizeof instructions);
    return sizeof instructions;
#endif
}

static ElfW(Addr) trampoline_to(ElfW(Addr) destination)
{
    unsigned char *page =
        mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        return 0;
    }
    size_t written = write_jump(page, destination);
    if (mprotect(page, PAGE, PROT_READ | PROT_EXEC) != 0) {
        return 0;
    }
    __builtin___clear_cache((char *)page, (char *)page + written);
    return (ElfW(Addr))page;
}

// The real function, which the forwarder below calls.
static void *(*real_memcpy)(void *, const void *, size_t);

// What the rewritten entry reaches in the inside form. A real hook reads or
// changes the call and then forwards it, and this one only forwards.
static void *forwarder(void *to, const void *from, size_t count)
{
    return real_memcpy(to, from, count);
}

// The slot this control rewrites. The inside form needs the memcpy slot, and
// the outside form takes any bound slot of the main image.
static struct slot *choose(int inside)
{
    for (int index = 0; index < slot_count; index++) {
        if (!objects[slots[index].object].is_main || slots[index].value == 0) {
            continue;
        }
        if (!inside) {
            return &slots[index];
        }
        if (strcmp(slots[index].name, "memcpy") == 0) {
            return &slots[index];
        }
    }
    return NULL;
}

static void *hook(void *ignored)
{
    (void)ignored;
    sleep(DELAY_SECONDS);

    const char *form = getenv("FIDELITY_HOOK");
    if (!form) {
        form = "outside";
    }
    int inside = strcmp(form, "inside") == 0;

    fidelity_read_slots();
    struct slot *target = choose(inside);
    if (!target) {
        printf("hook: the main image holds no slot that this form can rewrite\n");
        fflush(stdout);
        return NULL;
    }

    ElfW(Addr) replacement = 0;
    if (inside) {
        // The forwarder answers every memcpy call correctly, so the subject
        // keeps working, and it sits in a library that the loader mapped
        // before the subject ran.
        real_memcpy = (void *(*)(void *, const void *, size_t))dlsym(RTLD_DEFAULT, "memcpy");
        if (real_memcpy) {
            replacement = (ElfW(Addr))forwarder;
        }
    } else {
        replacement = trampoline_to(target->value);
    }
    if (replacement == 0) {
        printf("hook: the replacement did not resolve\n");
        fflush(stdout);
        return NULL;
    }

    if (make_writable(target->where) != 0) {
        printf("hook: the table stayed read-only\n");
        fflush(stdout);
        return NULL;
    }

    ElfW(Addr) held = *target->where;
    *target->where = replacement;
    printf("hook: %s, slot for %s at %p held %p, holds %p\n", form,
           target->name[0] ? target->name : "an unnamed symbol", (void *)target->where,
           (void *)held, (void *)replacement);
    fflush(stdout);
    return NULL;
}

__attribute__((constructor)) static void start_hook(void)
{
    pthread_t thread;
    if (pthread_create(&thread, NULL, hook, NULL) == 0) {
        pthread_detach(thread);
    }
}
