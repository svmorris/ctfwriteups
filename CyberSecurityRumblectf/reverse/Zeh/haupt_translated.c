#include <stdio.h>
#include <stdlib.h>
// #include "fahne.h"

void main(void) {
    int i = 1804289383;
    int k = 13;
    int e;
    int *p = &i;

    printf("%d\n", i);
    fflush(stdout);
    scanf("%d %d", &k, &e);

    for(int i = 7; i--;)
        k = (*p) >> (k%3);
    printf("\n\n%d", k);
    k = (k)^(e); // e needs to be 0 if k = 53225
    printf("\n%d\n\n", k);
    if(k == 53225)
        // puts(Fahne);
        puts("HERE");
    else
        puts("War wohl void!");
}
