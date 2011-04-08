#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

#include "inject_dso.h"

int main(int argc, char **argv) {

    pid_t pid;

    if (argc < 2) {
        printf("./test <pid>\n");
        return 0;
    }

    pid = (pid_t)atoi(argv[1]);

    size_t libsys_vm_offset = find_libsystem_start(pid);
    size_t dlopen_offset = find_dlopen_offset();

    printf("pid:\t%d\n", (int)pid);
    printf("libSystem.B.dylib VM offset:\t0x%zX\n", libsys_vm_offset);
    printf("dlopen VM offset:\t\t0x%zX\n", dlopen_offset + libsys_vm_offset);

    printf("Injecting... \n");
    inject_dso(libsys_vm_offset, dlopen_offset, pid, "tmp/event.so");

    return 0;
}
