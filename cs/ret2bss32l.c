#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

	char globalbuf[256];

	void fonction(char *txt)
		{
	    char localbuf[256];
 	   strcpy(localbuf,txt);
 	   strcpy(globalbuf,localbuf);
	}

	int main(int argc, char **argv)
		{
 	   if (argc > 1)
	        {
	printf("Argument: %s\n",argv[1]);
	fonction(argv[1]);
	char *ptr;
	ptr = globalbuf;
	printf("Addr de variable globale: 0x%08x\n",ptr);
		}
	    else
	        printf("Entrez un argument svp\n");
	    return(0);
	}
