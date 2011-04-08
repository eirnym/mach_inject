#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <mach/mach.h>
#include <unistd.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <signal.h>

/*
 * Important headers:
 * typedef_struct_t mach/i386/_structs.h
 *
 * mach/i386/vm_types.h
 *
 * mach/i386/asm.h
 *
 * mach/i386/ *.h
 * */

void die(const char *s)
{
    perror(s);
    exit(errno);
}


size_t find_libsystem_start(pid_t pid)  {
    /* vmmap method. Same as /proc/pid/maps on Linux. */
    size_t offset;
    char buf[512];
    char cmd[512];
    FILE *pfd;
    snprintf(cmd, sizeof(cmd), "vmmap %d | grep libSystem.B.dylib \
        | grep __TEXT | awk '{print $2}' | awk -F- '{print $1}'", pid);
    pfd = popen(cmd, "r");
    fgets(buf, sizeof(buf), pfd);
    offset = strtouq(buf, NULL, 16);
    if (!offset)  {
        die("Couldn't find libsystem in the target process\n");
    }
    return offset;
}

size_t find_dlopen_offset() {
    size_t offset;
    char buf[512];
    FILE *pfd = popen("nm /usr/lib/libSystem.B.dylib | grep _dlopen$ | \
        awk '{print $1}'", "r");
    fgets(buf, sizeof(buf), pfd); 
    offset = strtouq(buf, NULL, 16);
    if (!offset)  {
        die("Couldn't find our dlopen offset in /usr/lib/\
            libSystem.B.dylib.\n");
    }
    return offset;
}

int inject_dso(size_t libsystem_start, size_t dlopen_offset, pid_t pid,
    char* dso_path) {

    kern_return_t kret;
    int status;
    mach_port_t task;
    i386_thread_state_t regs, saved_regs;
    thread_act_port_array_t thread_list;
    mach_msg_type_number_t thread_count;

    kret = task_for_pid(mach_task_self(), pid, &task);

    if (kret != KERN_SUCCESS)
        die(mach_error_string(kret));

    if (task_suspend(task))
        die("Can't suspend task.");

    if (task_threads(task, &thread_list, &thread_count))
        die("Error retrieving thread data.\n");

    if (task_resume(task))
        die("Can't resume task.");

    return 0;
}
