#include <stdio.h>
#include <string.h>
#define BUFFER_SIZE 512

	void overflow(char *tmp)
		{
	char buffer[BUFFER_SIZE]  ;
	printf("\tTake: \033[36;1m%d\033[0m (Max DATA) From Argv and copy it on \033[36;1m%d\033[0m \n", strlen(tmp),BUFFER_SIZE);
	strcpy(buffer,tmp);
		}

	int main(int argc, char **argv)
		{
	char buf[2048]  ;
	printf("\tArgument Size: \033[41;1m%d\033[0m bytes \n", strlen(argv[1]));
	strncpy(buf,argv[1],sizeof(buf));
	overflow(buf);
	return (0) ;
	}
