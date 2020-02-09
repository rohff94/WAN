#include <stdio.h>
#include <string.h>

#define set() \
asm volatile("mov %0, %%gs:(0x14)" :: "r" (0x42424242));
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
int main(int argc,char **argv)
{
if(argc>1)
{ set();
fun(argv[1]); }
return 0;
}
