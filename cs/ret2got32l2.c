#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define BUFFER_SIZE 4
// une phrase /bin/sh 

extern char **envp;

	int main(int argc, char **argv, char **envp)
		{
	char buf[24]  ;
	printf("\tArgument Size: \033[41;1m%d\033[0m bytes \n", strlen(argv[1]));
	overflow(argv[1]);
	puts("end\n");
	return (0) ;
	}

	void overflow(char *tmp)
		{
	char test[4];
	char buffer[BUFFER_SIZE]  ;
	fprintf(stdout,"Overflow Function\n");
	printf("\tTake: \033[36;1m%d\033[0m (Max DATA) From Argv and copy it on \033[36;1m%d\033[0m \n", strlen(tmp),BUFFER_SIZE);
	printf("buffer is at %p\n", buffer);    // debugging
	strcpy(buffer,tmp);
		}


