#include <stdio.h>
int overflow(char *tmp)
{
char buff[1024];
strcpy(buff,tmp);
printf("%s\r\n",buff);
}
int main(int argc, char *argv[])
{
if(strlen(argv[1])>1024){
printf("Buffer Overflow Attempt!!!\r\n");
return 1;}
overflow(argv[1]);
return 0;
}
