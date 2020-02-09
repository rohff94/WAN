#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[])

{

    char *buff1, *buff2;



    buff1 = malloc(40);

    buff2 = malloc(40);

    strcpy(buff1,argv[1]);

    free(buff1);

    exit(0);

}
