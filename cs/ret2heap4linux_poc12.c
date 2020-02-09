#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>

extern char **envp;
void start(void) __attribute__ ((constructor));
void end(void) __attribute__ ((destructor));
int helloWorld();
int accessForbidden();
int (*ptrf)();
void shell_system();

int main(int argc, char **argv, char **envp)
{
	int i;
	char *buf1, *buf2, *buf3,*buf4, *buf5, *buf6,*buf7, *ptr;
	long diff;

	buf1 = malloc(12);
	buf2 = malloc(12);
	buf3 = malloc(12);
	buf4 = malloc(12);
	buf5 = malloc(12);
	buf6 = malloc(12);
	buf7 = malloc(12);

  	diff =  (long)buf2 -  (long)buf1;
  	printf("buf2 = %p\nbuf1 = %p\ndiff %d\n",buf2,buf1,diff);
	diff =  (long)buf3 -  (long)buf2;
  	printf("buf3 = %p\nbuf2 = %p\ndiff %d\n",buf3,buf2,diff);
	diff =  (long)buf4 -  (long)buf3;
  	printf("buf4 = %p\nbuf3 = %p\ndiff %d\n",buf4,buf3,diff);
	diff =  (long)buf5 -  (long)buf4;
  	printf("buf5 = %p\nbuf4 = %p\ndiff %d\n",buf5,buf4,diff);
	diff =  (long)buf6 -  (long)buf5;
  	printf("buf6 = %p\nbuf5 = %p\ndiff %d\n",buf6,buf5,diff);
	diff =  (long)buf7 -  (long)buf6;
  	printf("buf7 = %p\nbuf6 = %p\ndiff %d\n",buf7,buf6,diff);
	diff =  (long)buf7 -  (long)buf1;
  	printf("buf7 = %p\nbuf1 = %p\ndiff %d\n",buf7,buf1,diff);

	

	printf("\targv[1] Size: \033[41;1m%d\033[0m bytes \n", strlen(argv[1]));
	fprintf(stderr, "argv[1]: %s\n", argv[1]);
 	printf("buf1: ");
	for (i = 0; i<12; i++)
	{
		buf1[i] = 'B';
		printf("\\x%02x", buf1[i]);
	}
	printf("\n");

	printf("\tbuf2 Size: \033[41;1m%d\033[0m bytes \n", strlen(buf2));
	fprintf(stderr, "buf2: %s\n", buf2);
	printf("buf2: ");
	for (i = 0; i<12; i++)
	{
		buf2[i] = argv[1][i];
		printf("\\x%02x", buf2[i]);
	}
	printf("\n");

	printf("\tbuf3 Size: \033[41;1m%d\033[0m bytes \n", strlen(buf3));
	fprintf(stderr, "buf3: %s\n", buf3);
	printf("buf3: ");
	for (i = 0; i<12; i++)
	{
		buf3[i] = 'C';
		printf("\\x%02x", buf3[i]);
	}
	printf("\n");
	strcpy(buf4, argv[1]);

	printf("\tbuf4 Size: \033[41;1m%d\033[0m bytes \n", strlen(buf4));
	fprintf(stderr, "buf4: %s\n", buf4);
	printf("buf4: ");
	for (i = 0; i<12; i++)
	{
		printf("\\x%02x", buf4[i]);
	}
	printf("\n");

	printf("\tbuf5 Size: \033[41;1m%d\033[0m bytes \n", strlen(buf5));
	fprintf(stderr, "buf5: %s\n", buf5);
	printf("buf5: ");
	for (i = 0; i<12; i++)
	{
		buf5[i] = 'D';
		printf("\\x%02x", buf5[i]);
	}
	printf("\n");


	printf("\tbuf6 Size: \033[41;1m%d\033[0m bytes \n", strlen(buf6));
	fprintf(stderr, "buf6: %s\n", buf6);
	printf("buf6: ");
	for (i = 0; i<12; i++)
	{
		printf("\\x%02x", buf6[i]);
	}
	printf("\n");

	printf("\tbuf7 Size: \033[41;1m%d\033[0m bytes \n", strlen(buf7));
	fprintf(stderr, "buf7: %s\n", buf7);
	printf("buf7: ");
	for (i = 0; i<12; i++)
	{
		buf7[i] = 'E';
		printf("\\x%02x", buf7[i]);
	}
	printf("\n");


	free(buf2);
	free(buf3);
	free(buf1);
	free(buf4);
	free(buf5);
	free(buf7);
	free(buf6);


	printf("pwd\n"); //
	puts("uname -a"); 

	return(0);
}




void start(void) {
  printf("in start()\n");
}

void end(void) {
  printf("in end()\n");
}

int helloWorld()
{
  printf("\t\033[36;1mWelcome in \"helloWorld Fonction\"\033[0m\n");
  return 0;
}

int accessForbidden()
{
  printf("\t\033[41;1mYou shouldn't be here \"accesForbidden Fonction\"\033[0m\n");
  return 0;
}

void shell_system()
{
  printf("\t\033[40;1mShell\"\033[0m\n");
  system("/bin/sh");
  exit(0);
}
