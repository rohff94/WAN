#include <stdio.h>
#include <string.h>
#define BUFFER_SIZE 1024

	void overflow(char *tmp)
		{
	char buffer[BUFFER_SIZE]  ;
	printf("\tTake: \033[36;1m%d\033[0m (Max DATA) From Argv and copy it on \033[36;1m%d\033[0m onto buffer\n", strlen(tmp),BUFFER_SIZE);
	strcpy(buffer,tmp);
		}

	int main(int argc, char **argv)
		{
	printf("\tArgument Size: \033[41;1m%d\033[0m bytes \n", strlen(argv[1]));
	printf("Address of argv[1]: %08x \n", &argv[1]);
	overflow(argv[1]);
	return (0) ;
	}
