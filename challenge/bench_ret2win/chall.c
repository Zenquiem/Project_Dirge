#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void win(void) {
    puts("DIRGE_RET2WIN_OK");
    fflush(stdout);
    _exit(0);
}

int main(void) {
    char buf[64];
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("name?");
    gets(buf);
    puts("bye");
    return 0;
}
