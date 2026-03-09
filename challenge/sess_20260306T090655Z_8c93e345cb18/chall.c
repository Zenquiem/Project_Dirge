#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>

#ifdef DEBUG
#define DPRINT(...) do { \
    fprintf(stderr, __VA_ARGS__); \
} while(0)
#else
#define DPRINT(...)
#endif

#define NOTES_SIZE 0x50
#define MAX_NOTE_SIZE 0x100

#define NOTE_ALLOC 1
#define NOTE_FREE 2
#define NOTE_WRITE 3
#define NOTE_READ 4
#define NOTE_MAGIC 5
#define NOTE_EXIT 6


struct note {
    char* data;
    size_t size;
};

struct note notes[NOTES_SIZE] = { {NULL, 0} };

void __attribute__((constructor)) init() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
}

void menu(void) {
    puts("1. Allocate note");
    puts("2. Free note");
    puts("3. Write note");
    puts("4. Read note");
    puts("5. Exit");
    printf("> ");
}

unsigned int get_idx(){
    unsigned int idx;
    
    printf("index: ");

    if(scanf("%u", &idx) != 1)
        errx(1, "invalid input");

    if (idx >= NOTES_SIZE)
        errx(1, "invalid index");

    return idx;
}
    
int main(){
    unsigned int idx, sz, choice, magic_used = 0;
    unsigned long* ptr;
    unsigned long value = 0;


    for(;;){
        menu();
        if (scanf("%u", &choice) != 1) {
            errx(1, "invalid input");
        }

        switch (choice) {
            case NOTE_ALLOC:
                idx = get_idx();
                if (notes[idx].data != NULL) {
                    puts("note already allocated");
                    break;
                }
                
                printf("Enter size: ");
                if(scanf("%u", &sz) != 1)
                    errx(1, "invalid input");
                
                if (sz > MAX_NOTE_SIZE) {
                    puts("invalid size");
                    break;
                }

                notes[idx].data = malloc(sz);
                notes[idx].size = sz;
                
                DPRINT("malloc: %p\n", notes[idx].data);

                if (notes[idx].data == NULL)
                    errx(1, "failed to allocate memory");
                
                break;
            case NOTE_FREE:
                idx = get_idx();

                if (notes[idx].data == NULL) {
                    puts("note not allocated");
                    break;
                }
                
                free(notes[idx].data);
                notes[idx].data = NULL;
                notes[idx].size = 0;
                break;
            case NOTE_WRITE:
                idx = get_idx();
                
                if(notes[idx].data == NULL) {
                    puts("note not allocated");
                    break;
                }

                printf("size: ");
                if (scanf("%u", &sz) != 1)
                    errx(1, "invalid input");

                if (sz > notes[idx].size) {
                    puts("invalid size");
                    break;
                }

                printf("data: ");
                read(0, notes[idx].data, sz);

                break;
            case NOTE_READ:
                idx = get_idx();
                
                printf("size: ");
                if (scanf("%u", &sz) != 1)
                    errx(1, "invalid input");
                
                if (sz > MAX_NOTE_SIZE) {
                    puts("invalid size");
                    break;
                }

                if (notes[idx].data == NULL) {
                    puts("note not allocated");
                    break;
                }
                write(1, notes[idx].data, sz);

                break;
            case NOTE_MAGIC:
                if(!magic_used)
                    magic_used = 1;
                
                printf("address: ");
                scanf("%p", &ptr);

                if(((unsigned long)ptr & 7) != 0)
                    errx(1, "invalid address");

                printf("value: ");
                scanf("%lu", &value);

                *ptr = value;
                break;
            case NOTE_EXIT:
                exit(0);
            default:
                puts("Invalid choice");
        }
    }
    return 0;
}