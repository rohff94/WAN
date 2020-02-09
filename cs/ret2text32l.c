// AAAA AAAA AAAA BBBB CCCC -> AAAAAAAAAAAABBBBCCCC
// $./ret2text `echo -e "AAAAAAAAAAAAAAAA\x6e\x84\x04\x08"`


#include <stdio.h>
#include <string.h>

	void serial(char *txt)
		{
	    char buffer[12];
 	   strcpy(buffer,txt);
	   printf("Fin Execution de la fonction serial \n");
	}

	void secret(void)
		{
	    printf("\033[41;1m\tExecution de la fonction secret\033[0m\n");
	}


	int main(int argc, char **argv)
		{
 	   if (argc > 1)
	        {
	printf("Argument: %s\n",argv[1]);
	serial(argv[1]);
void (*ptr)(char *txt);	ptr = &secret;printf("Addr de la fonction secret: 0x%08x\n",ptr);
		}
	    else
	        printf("Entrez un argument svp\n");
	    return(0);
	}
