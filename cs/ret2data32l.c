#include <stdio.h>
#include <string.h>

	// CMD=date
	char shellcode_data[67] = "\xb8\xe7\xc2\xdf\xef\xda\xd8\xd9\x74\x24\xf4\x5d\x29\xc9\xb1\x0b\x31\x45\x12\x83\xc5\x04\x03\xa2\xcc\x3d\x1a\x46\xda\x99\x7c\xc4\xba\x71\x52\x8b\xcb\x65\xc4\x64\xbf\x01\x15\x12\x10\xb0\x7c\x8c\xe7\xd7\x2d\xb8\xfd\x17\xd2\x38\x9a\x76\xa6\x5d\x62\x2e\x15\x14\x83\x1d\x19" ;

	void fonction(char *txt)
		{
	    char localbuf[12];
 	   strcpy(localbuf,txt);
	}

	int main(int argc, char **argv)
		{
 	   if (argc > 1)
	        {
	printf("Argument: %s\n",argv[1]);
	fonction(argv[1]);
	char *ptr;
	ptr = shellcode_data;
	printf("Addr de la variable shellcode_data: 0x%08x\n",ptr);
		}
	    else
	        printf("Entrez un argument svp\n");
	    return(0);
	}
