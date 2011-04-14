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

    int status;
    mach_port_t task;
    i386_thread_state64_t regs;
    thread_act_t remote_thread;
    vm_address_t remote_stack_addr = (vm_address_t)NULL;
    vm_address_t remote_code_addr = (vm_address_t)NULL;
    vm_address_t remote_dlopen_str_addr = (vm_address_t)NULL;
    size_t remote_stack_contents[3];
    int remote_stack_size = 8192;

    task_for_pid(mach_task_self(), pid, &task);

    /* Allocate space for the dlopen path string. */
    vm_allocate(task, &remote_dlopen_str_addr, strlen(dso_path), 1);
    vm_write(task, remote_dlopen_str_addr, (pointer_t)dso_path, strlen(dso_path));

    /* Allocate space for remote code. */
    char remote_code[] = {
        0xff, 0x11,         /* call *(%rcx) */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    vm_allocate(task, &remote_code_addr, sizeof(remote_code), 1);
    vm_protect(task, remote_code_addr, sizeof(remote_code), 0, VM_PROT_EXECUTE |
        VM_PROT_WRITE | VM_PROT_READ);
    vm_write(task, remote_code_addr, (pointer_t)remote_code, sizeof(remote_code));

    /* Allocate and set up remote stack. */
    vm_allocate(task, &remote_stack_addr, remote_stack_size, 1);
    vm_protect(task, remote_stack_addr, remote_stack_size, 0, VM_PROT_WRITE |
        VM_PROT_READ);

    remote_stack_contents[0] = (size_t)0x0000DEADBEA7DAD; //Invalid return addr
    size_t rbp, rsp;
    rbp = (size_t)remote_stack_addr + (remote_stack_size / 2);
    rsp = (size_t)remote_stack_addr + (remote_stack_size / 2);
    vm_write(task, rbp, (pointer_t)remote_stack_contents, remote_stack_size);

    /* Set the thread state to be set up to call dlopen in the remote
     * process */
    regs.__rcx = (size_t)dlopen_offset;
    regs.__ebp = (size_t)rbp;
    regs.__rsp = (size_t)rsp;
    regs.__rdi = (size_t)remote_dlopen_str_addr;
    regs.__rsi = (size_t)RTLD_LAZY;
    regs.__esi = (size_t)RTLD_LAZY;
    regs.__rip = (size_t)remote_code_addr;

    /* Start the remote thread */
    thread_create_running(task, x86_THREAD_STATE64, (thread_state_t) &regs,
        x86_THREAD_STATE64_COUNT, &remoteThread );

/*
    if (task_suspend(task))
        die("inject 3");

    if (task_threads(task, &thread_list, &thread_count))
        die("inject 4");

    if (task_resume(task))
        die("inject 5");
*/
    return 0;
}
