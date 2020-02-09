#include <stdio.h>
#include <stdarg.h>

static int i;
void main (int argc, char *argv[])
{
char str[256];
i = 10;
if (argc <2)
{
printf("usage: %s <text for printing>\n", argv[0]);
exit(0);
}
strcpy(str, argv[1]);
printf("The good way of calling printf: ");
printf("%s", str);
printf("\nvariable i now %d = %p at %p \n", i,i,&i);
printf("The bad way of calling printf: ");
printf(str);
printf("\nvariable i is now %d = %p at %p \n", i,i,&i);
}
