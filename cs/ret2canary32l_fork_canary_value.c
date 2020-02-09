#include <stdio.h>
#include <string.h>
#define BUFFER_SIZE 10

typedef unsigned long can_t;
#define can_fmt "%0lx"
#define get_canary(can) \
asm volatile("mov %%gs:(0x14), %0" : "=r" (can));

int fun(char *arg)
{
can_t can;
int i;
char p[BUFFER_SIZE];
get_canary(can);
printf("Register GS at offset 0x14 : " can_fmt "\n", can);
printf("\tTake: \033[36;1m%d\033[0m (Max DATA) From Argv and copy it on \033[36;1m%d\033[0m \n", strlen(arg),BUFFER_SIZE);
strcpy(p,arg);
printf("Canary = 0x");
for(i=13;i>9;i--)
printf("%02x",(unsigned char)*(p+i));
printf("\n");
}

void main(int argc,char **argv){
int i, status, pid;
for (i = 0; i < 10; i++)
{
pid = fork();
if (!pid)
break;
wait(&status);
}
printf("\tArgument Size: \033[41;1m%d\033[0m bytes \n", strlen(argv[1]));
fun(argv[1]);
}
