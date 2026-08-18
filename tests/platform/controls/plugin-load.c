/* The macOS measurement behind the runtime-baseline strength.
 *
 * It counts top-level executable regions before and after two loads, because
 * the two answer different questions: a library the dyld shared cache already
 * holds adds nothing, and a plugin on disk adds one region.
 *
 * Measured on macOS 26 and ARM64 on 2026-08-09: 1 region before, +0 for the
 * cached library, +1 for the plugin. `docs/plan/04-detectors-and-platforms.md`
 * records the conclusion.
 *
 *   echo 'int plugin_entry(void){return 7;}' > plug.c
 *   clang -dynamiclib -o plugin.dylib plug.c
 *   clang -o plugin-load plugin-load.c && ./plugin-load ./plugin.dylib
 */
#include <stdio.h>
#include "regions.h"
#include <dlfcn.h>

int main(int argc, char **argv) {
    unsigned long long b0, b1, b2;
    int r0 = exec_regions(&b0);
    printf("before any load          : %d regions, %llu bytes\n", r0, b0);

    /* A library that already sits in the dyld shared cache. */
    void *cached = dlopen("/usr/lib/libcurl.dylib", RTLD_NOW);
    int r1 = exec_regions(&b1);
    printf("after a shared-cache load: %d regions (%+d), %llu bytes  [%s]\n",
           r1, r1 - r0, b1, cached ? "loaded" : dlerror());

    /* A plugin on disk, which no shared cache holds. This is the real case. */
    const char *path = argc > 1 ? argv[1] : "./plugin.dylib";
    void *plugin = dlopen(path, RTLD_NOW);
    int r2 = exec_regions(&b2);
    printf("after a plugin load      : %d regions (%+d), %llu bytes  [%s]\n",
           r2, r2 - r1, b2, plugin ? "loaded" : dlerror());
    return 0;
}
