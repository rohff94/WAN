#include <stdio.h>
unsigned char *shellcode ;

int main(int argc, char **argv)
{
shellcode = argv[1];
int (*func)();
func = (int (*)()) shellcode;
(int)(*func)();
}
