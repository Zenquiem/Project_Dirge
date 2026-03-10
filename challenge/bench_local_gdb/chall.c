#include <stdio.h>
#include <string.h>

int main(void) {
    char buf[64] = {0};
    if (!fgets(buf, sizeof(buf), stdin)) {
        return 0;
    }
    if (strncmp(buf, "CRASH", 5) == 0) {
        volatile char *p = 0;
        *p = 'A';
    }
    puts("ok");
    return 0;
}
