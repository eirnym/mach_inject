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

void get_text(char *lib_path)  {
    DL_info *info;
    void *handle = dlopen(lib_path, RTLD_LAZY);
    dladdr(handle, &info);
    dlclose(handle);
}

int inject_dso(size_t libsystem_start, size_t dlopen_offset, pid_t pid,
    char* dso_path, char *remote_code, int remote_code_size) {

    kern_return_t kret;
    int status;
    mach_port_t task;
    i386_thread_state_t regs;
    thread_act_port_array_t thread_list;
    mach_msg_type_number_t thread_count;
    vm_address_t remote_stack_addr = (vm_address_t)NULL;
    vm_address_t remote_code_addr = (vm_address_t)NULL;
    vm_address_t remote_dlopen_str_addr = (vm_address_t)NULL;
    int remote_stack_size = 8192;

    task_for_pid(mach_task_self(), pid, &task);

    /* Allocate space for the dlopen path string. */
    vm_allocate(task, &remote_dlopen_str_addr, strlen(dso_path), 1);
    vm_write(task, remote_dlopen_str_addr, dso_path, strlen(dso_path));

    /* hack. compile and read this from a mach-o object instead of just
     * hard-coding opcodes etc */
    char remote_code[] = {
        0x55,                                     /* push %rbp */
        0x48, 0x89, 0xe5,                         /* mov %rsp,%rbp */
        0x48, 0x8b, 0x3d, 0x00, 0x00, 0x00, 0x00, /* mov 0x0(%rip),%rdi */
        0xbe, 0x01, 0x00, 0x00, 0x00,             /* mov $0x1,%esi */
        0xe8, 0x00, 0x00, 0x00, 0x00,             /* call <dlopen> */
        0xc9,                                     /* leaveq */
        0xc3                                      /* retq */
    }

    vm_allocate(task, &remote_code_addr, sizeof(remote_code), 1);
    vm_protect(task, remote_code_addr, remote_code_size, 0, VM_PROT_EXECUTE |
        VM_PROT_WRITE | VM_PROT_READ);

    /* manually perform relocation for e8 (%rip relative call) to dlopen
     * offset. */
    vm_address_t offset = remote_code_addr + 21 + dlopen_offset;
    remote_code[17] = offset << 24 >> 24;
    remote_code[18] = offset << 16 >> 16;
    remote_code[19] = offset >> 16 << 16;
    remote_code[20] = offset >> 24 << 24;

    /* set relative pointer to dlopen path string to %rdi */
    //...//

    vm_write(task, remote_code_addr, remote_code, sizeof(remote_code));

    /* Allocate and set up remote stack. */
    vm_allocate(task, &remote_stack_addr, remote_stack_size, 1);
    vm_protect(task, remote_stack_addr, remote_stack_size, 0, VM_PROT_WRITE |
        VM_PROT_READ);

    /* Set the thread state to be set up to call dlopen in the remote
     * process */

    /* Start the remote thread */

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
