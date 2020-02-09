#include <stdio.h>
long find_esp() {
__asm__("movl %esp, %eax");
}
int main() {
printf("\tESP: 0x%08x\n", find_esp());
return 0;
}

