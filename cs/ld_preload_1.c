#include <stdio.h>
#include <string.h>
 
int main(int argc, char **argv) {
    char a[7] = "hacker";
    int *b;
    printf("Enter your password: ");
     b = &argv[1] ;
    if(strcmp(a, *b) == 0) {
        printf("Win!\n");
    } else {
        printf("Fail...\n");
    }
    return 0;
}
