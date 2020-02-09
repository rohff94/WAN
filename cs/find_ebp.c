#include <stdio.h>

unsigned int getEBP(void) {
asm("movl %ebp ,%eax") ;
}
int main (void) {
printf ("\tEBP: 0x%08x\n", getEBP(), getEBP() ) ;
return 0;
}

