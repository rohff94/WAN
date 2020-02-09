#include <stdio.h>
#include <string.h>
#include <unistd.h>
#define BUFFER_SIZE 4


	int main(int argc, char **argv)
		{
	printf("\tArgument Size: \033[41;1m%d\033[0m bytes \n", strlen(argv[1]));
	overflow(argv[1]);
	return (0) ;
	}

	void overflow(char *tmp)
		{
	char buffer[BUFFER_SIZE]  ;
	strcpy(buffer,tmp);
		}


