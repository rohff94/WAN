#include <stdio.h>
#include <string.h>

typedef unsigned long can_t;
#define can_fmt "%0lx"
#define get_canary(can) \
asm volatile("mov %%gs:(0x14), %0" : "=r" (can));


int fun(char *arg){
 int i;
 char p[10];
strcpy(p,arg);
printf("Canary = 0x");
for(i=13;i>9;i--)
printf("%02x",(unsigned char)*(p+i));
printf("\n"); 
}

int main(int argc,char **argv){ 
can_t can;
get_canary(can);
printf("Register GS at offset 0x14 : " can_fmt "\n", can);
if(argc>1) fun(argv[1]);
return 0;}
