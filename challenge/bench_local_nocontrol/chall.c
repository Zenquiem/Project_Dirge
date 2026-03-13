#include <stdio.h>
#include <unistd.h>

int main(void) {
    char buf[64];
    ssize_t n = read(0, buf, sizeof(buf));
    if (n <= 0) {
        return 0;
    }
    volatile int *p = NULL;
    *p = 0x41414141;
    return 0;
}
