#include <stdio.h>
#include <sys/sysctl.h>

int main(void) {
    char name[128] = {0};
    size_t length = sizeof(name);
    if (sysctlbyname("hw.machine", name, &length, NULL, 0) != 0) {
        perror("the kernel did not answer hw.machine");
        return 1;
    }
    printf("hw.machine: %s\n", name);
    return 0;
}
