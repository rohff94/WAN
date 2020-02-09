#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char *argv[])  
{
    char *buf1, *buf2, *buf3;
	long diff;
	int i;

    if (argc != 4) return;

    buf1 = malloc(256);
    strcpy(buf1, argv[1]);

    buf2 = malloc(strtoul(argv[2], NULL, 16));

    buf3 = malloc(256);
    strcpy(buf3, argv[3]);

  	diff =  (long)buf2 -  (long)buf1;
  	printf("buf1 = %p\nbuf2 = %p\ndiff %d\n",buf1,buf2,diff);
	diff =  (long)buf3 -  (long)buf2;
  	printf("buf2 = %p\nbuf3 = %p\ndiff %d\n",buf2,buf3,diff);
	diff =  (long)buf3 -  (long)buf1;
  	printf("buf1 = %p\nbuf3 = %p\ndiff %d\n",buf1,buf3,diff);


	printf("\targv[1] Size: \033[41;1m%d\033[0m bytes \n", strlen(buf1));
	fprintf(stderr, "argv[1]: %s\n", argv[1]);
 	printf("buf1: ");
	for (i = 0; i<strlen(buf1); i++)
	{
		printf("\\x%02x", buf1[i]);
	}
	printf("\n");

	printf("\tbuf2 Size: \033[41;1m%d\033[0m bytes \n", strlen(buf2));
	fprintf(stderr, "buf2: %s\n", buf2);
	printf("buf2: ");
	for (i = 0; i<strlen(buf2); i++)
	{
		printf("\\x%02x", buf2[i]);
	}
	printf("\n");

	printf("\tbuf3 Size: \033[41;1m%d\033[0m bytes \n", strlen(buf3));
	fprintf(stderr, "buf3: %s\n", buf3);
	printf("buf3: ");
	for (i = 0; i<strlen(buf3); i++)
	{
		printf("\\x%02x", buf3[i]);
	}
	printf("\n");


    free(buf3);
    free(buf2);
    free(buf1);

    return 0;
} 
