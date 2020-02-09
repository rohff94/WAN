#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#define	BUFFER_LEN	16
#define	ADDR_LEN	4

int main(int argc, char **argv)
{
u_long diff;
static char buffer[BUFFER_LEN];
static char *ptr;

ptr = buffer;
diff = (u_long) buffer - (u_long) &ptr;
printf("Before ptr: (%p) = %p\n\t\tbuffer = %p   diff = 0x%x (%d) octets\n", &ptr, ptr, buffer, diff, diff);
printf("\tRemplir le buffer avec A*%d \n", (u_int) (diff + ADDR_LEN));
memset(buffer, 'A', (u_int) (diff + ADDR_LEN));
printf("After ptr: (%p) = %p\n\t\tbuffer = %p   diff = 0x%x (%d) octets\n", &ptr, ptr, buffer, diff, diff);
return (0);
}
