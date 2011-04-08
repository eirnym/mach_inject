#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

int main(int argc, char **argv) {
/*
    FILE* pfd = NULL;
    char dso_path[128];
    char buf[128];
    char *process_name;
    pid_t pid;
    char cmd[128];

    inject_dso(atoi(argv[1]), argv[2]);

    process_name = argv[1];
    sprintf(cmd, "ps -ef | grep \"%s\" | awk '{print $3}' | head -n 1",
        process_name);

    if (getuid() != 0)  {
        printf("Must be run as root. Exiting.\n");
        exit(EXIT_FAILURE);
    }

    while (1) {
        if ((pfd = popen(cmd, "r")) != NULL)  {
            fgets(buf, sizeof(buf), pfd); 
            pid = (pid_t)atoi(buf);
            break;
        } else  {
            printf("Couldn't find process %s, exiting.\n", process_name);
            exit(EXIT_FAILURE);
        }
        sleep(1);
    }

    if (inject_dso(pid, dso_path) != EXIT_SUCCESS)  {
        printf("Couldn't inject DSO %s to process %s (%s)\n", dso_path,
            process_name, buf); 
        exit(EXIT_FAILURE);
    }

    */
    return EXIT_SUCCESS;
}
