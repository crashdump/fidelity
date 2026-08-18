/* The hostile control for unaccounted code.
 *
 * A minimal stand-in for an injected agent. It maps executable memory that no
 * file accounts for, which is what an agent that a loader never mapped leaves
 * behind.
 *
 * This control acts at load, and `delayed.c` acts later. The two answer
 * different questions: this one is present before `start()` runs, so the
 * unaccounted-code detector must find it from the mapping table alone.
 *
 *   Linux  gcc -shared -fPIC -o agent.so agent.c
 */
#include <stdio.h>
#include <sys/mman.h>

__attribute__((constructor)) static void arrive(void) {
    void *p = mmap(0, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    fprintf(stderr, "[agent] mapped executable memory at %p\n", p);
}
