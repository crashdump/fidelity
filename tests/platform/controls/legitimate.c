/* The CLEAN control for the runtime baseline, and the one that decided its
 * strength.
 *
 * This is not a hostile control. The application loads one of its own plugins
 * while it runs, which is the benign case that
 * `docs/plan/04-detectors-and-platforms.md` left open. The detector reports it,
 * and the evidence is the evidence that `delayed.c` produces, so the two cannot
 * be told apart. That is why the runtime baseline stays `Medium`.
 *
 * The plugin path arrives in FIDELITY_PLUGIN, so the same control can load a
 * library that the shared cache already holds, which adds no region, or one
 * from disk, which adds one.
 *
 *   macOS  clang -dynamiclib -o legitimate.dylib legitimate.c
 *          echo 'int plugin_entry(void){return 7;}' > plug.c
 *          clang -dynamiclib -o plugin.dylib plug.c
 *          DYLD_INSERT_LIBRARIES=./legitimate.dylib FIDELITY_PLUGIN=./plugin.dylib \
 *              ./target/debug/examples/late
 *
 *   Linux  gcc -shared -fPIC -o legitimate.so legitimate.c -ldl -lpthread
 *          LD_PRELOAD=./legitimate.so FIDELITY_PLUGIN=./plug.so \
 *              ./target/debug/examples/late
 */
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <dlfcn.h>

static const char *PLUGIN = 0;

static void *act(void *unused) {
    (void)unused;
    sleep(3);
    void *h = dlopen(PLUGIN, RTLD_NOW);
    fprintf(stderr, "[host] loaded its plugin: %s\n", h ? "ok" : dlerror());
    return 0;
}

__attribute__((constructor)) static void arrive(void) {
    PLUGIN = getenv("FIDELITY_PLUGIN");
    if (!PLUGIN) {
        fprintf(stderr, "[host] set FIDELITY_PLUGIN to the plugin to load\n");
        return;
    }
    pthread_t t;
    pthread_create(&t, 0, act, 0);
    pthread_detach(t);
}
