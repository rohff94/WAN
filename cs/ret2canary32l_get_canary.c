#include <stdio.h>
#include <string.h>

int fun(char *arg)
{
int i;
char p[10];
strcpy(p,arg);
printf("Canary = 0x");
for(i=13;i>9;i--)
printf("%02x",(unsigned char)*(p+i));
printf("\n");
}

void main(int argc,char **argv)
{
if(argc>1)
fun(argv[1]);
}
