#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
	char *ptr;
	if (argc != 3) {printf("Usage: %s <env var name> <Path Programme Name>\n",argv[0]);exit(0);}

	ptr = getenv(argv[1]) + (strlen(argv[0]) - strlen(argv[2]));

	printf("%p\n",ptr);

	return 0;
}
