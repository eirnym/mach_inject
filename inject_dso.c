#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <mach/mach.h>
#include <unistd.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <signal.h>
#include <mach-o/loader.h>

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

    mach_port_t task;
    x86_thread_state64_t regs;
    thread_act_t remote_thread;
    vm_address_t remote_stack_addr = (vm_address_t)NULL;
    vm_address_t remote_dlopen_str_addr = (vm_address_t)NULL;
    size_t remote_stack_contents;
    int remote_stack_size = 8192;

    task_for_pid(mach_task_self(), pid, &task);

    /* Allocate space for the dlopen path string. */
    vm_allocate(task, &remote_dlopen_str_addr, strlen(dso_path), 1);
    vm_write(task, remote_dlopen_str_addr, (pointer_t)dso_path, strlen(dso_path));

    /* Allocate and set up remote stack. */
    vm_allocate(task, &remote_stack_addr, remote_stack_size, 1);
    vm_protect(task, remote_stack_addr, remote_stack_size, 0, VM_PROT_WRITE |
        VM_PROT_READ);

    remote_stack_contents = 0x0000DEADBEA7DAD; /* Invalid return address. */
    size_t rsp; /* Use better 64 bit type for registers / pointers. */
    rsp = (size_t)remote_stack_addr + (remote_stack_size / 2);
    vm_write(task, rsp, (pointer_t)remote_stack_contents, remote_stack_size);

    /* Set the thread state to call dlopen in the remote process. Integer and
     * pointer arguments passed in %rdi and %rsi. Set the instruction pointer to
     * the absolute address (in %rcx) to the VM address of dlopen. */
    regs.__rsp = (size_t)rsp;
    regs.__rdi = (size_t)remote_dlopen_str_addr;
    regs.__rsi = (size_t)RTLD_LAZY;
    regs.__rip = (size_t)dlopen_offset;

    /* Start the remote thread */
    thread_create_running(task, x86_THREAD_STATE64, (thread_state_t) &regs,
        x86_THREAD_STATE64_COUNT, &remote_thread);

    /* Find out how to recover successfully from the segfault without OSX's
     * useless ptrace... */

    return 0;
}
