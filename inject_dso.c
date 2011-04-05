#include <stdio.h>
#include <sys/types.h>
#include <mach/mach.h>
#include <unistd.h>
#include <stdlib.h>

int inject_dso(pid_t pid, char* dso_path) {

    kern_return_t kret;
    mach_port_t task;

    kret = task_for_pid(mach_task_self(), pid, &task);

    if (kret != KERN_SUCCESS) {
        printf("task_for_pid() failed: %s\n", mach_error_string(kret));
        return EXIT_FAILURE;
    } else  {
        printf("Got task for pid %d...\n", pid);
    }

    return EXIT_SUCCESS;
}
