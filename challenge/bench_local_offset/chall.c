#include <stdio.h>
#include <unistd.h>

int main(void) {
    char buf[64];
    ssize_t n = read(0, buf, 400);
    if (n <= 0) {
        return 0;
    }
    return 0;
}
