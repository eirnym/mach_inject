#include <sys/types.h>

/* Find the virtual memory address of libSystem.B.dylib in the target
 * process. */
size_t find_libsystem_start(pid_t pid);

/* Find the offset of dlopen() in our libSystem.B.dylib. */
size_t find_dlopen_offset();

/* Inject the dynamic shared object into the specified process. */
int inject_dso(size_t libsystem_start, size_t dlopen_offset, pid_t pid,
    char* dso_path);
