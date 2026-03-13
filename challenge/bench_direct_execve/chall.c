#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

__attribute__((used))
void run_cmd_execve(void) {
    char *argv[] = {"/bin/sh", NULL};
    char *envp[] = {NULL};
    execve("/bin/sh", argv, envp);
    _exit(127);
}

int main(void) {
    char buf[64];
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    puts("send payload:");
    read(0, buf, 400);
    return 0;
}
