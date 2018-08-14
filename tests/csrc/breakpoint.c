/*
 * Make 0xCC instruction length larger then 1
 */
#include <stdio.h>
#include <sys/mman.h>
#include <stdlib.h>

typedef void(*FUN)(void);
char * myFunc;

char *allocExecutablePages (int pages)
{
    char *t = valloc (getpagesize() * pages);
    if (mprotect (t, getpagesize(),  PROT_READ|PROT_EXEC|PROT_WRITE) == -1) {
        fprintf (stderr, "mprotect");
    }
    return t;
}

void main(void) {
    myFunc = allocExecutablePages(1);
    myFunc[0] = 0x67; // add redundant prefix
    myFunc[1] = 0x67; // add redundant prefix
    myFunc[2] = 0x67; // add redundant prefix
    myFunc[3] = 0xcc; // breakpoint
    ((FUN)myFunc)();
}
