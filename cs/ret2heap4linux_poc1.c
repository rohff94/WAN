#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[])
{
	char *first, *second;

	first = malloc(666);
	second = malloc(128);

	strcpy(first, argv[1]);

	free(first);
	free(second);

	return(0);
}
