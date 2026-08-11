/* The Linux half of the same measurement.
 *
 * Linux has no shared cache, so a system library and a plugin each add one
 * executable mapping. Measured on Debian and ARM64 on 2026-08-09: 4 mappings
 * before, +1 for libm, +1 for the plugin.
 *
 *   gcc -shared -fPIC -o plug.so plug.c
 *   gcc -o plugin-load-linux plugin-load-linux.c -ldl && ./plugin-load-linux ./plug.so
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

static int exec_maps(void) {
    FILE *f = fopen("/proc/self/maps", "r"); char line[512]; int n = 0;
    while (fgets(line, sizeof line, f)) { char *p = strchr(line, ' '); if (p && p[3] == 'x') n++; }
    fclose(f); return n;
}
int main(int argc, char **argv) {
    int r0 = exec_maps();
    printf("before any load          : %d executable mappings\n", r0);
    void *a = dlopen("libm.so.6", RTLD_NOW);
    int r1 = exec_maps();
    printf("after a system library   : %d (%+d)  [%s]\n", r1, r1-r0, a?"loaded":dlerror());
    void *b = dlopen(argc>1?argv[1]:"./plug.so", RTLD_NOW);
    int r2 = exec_maps();
    printf("after a plugin           : %d (%+d)  [%s]\n", r2, r2-r1, b?"loaded":dlerror());
    return 0;
}
