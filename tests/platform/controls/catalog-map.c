// Maps a second executable view of this library without loader registration.
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static void *mapped;

__attribute__((constructor)) static void map_image_outside_loader(void) {
    Dl_info image;
    if (dladdr((void *)&map_image_outside_loader, &image) == 0 || image.dli_fname == NULL) {
        _exit(90);
    }
    int file = open(image.dli_fname, O_RDONLY);
    if (file < 0) {
        _exit(91);
    }
    struct stat status;
    if (fstat(file, &status) != 0 || status.st_size <= 0) {
        close(file);
        _exit(92);
    }
    mapped = mmap(NULL, (size_t)status.st_size, PROT_READ | PROT_EXEC, MAP_PRIVATE, file, 0);
    close(file);
    if (mapped == MAP_FAILED) {
        _exit(93);
    }
}
