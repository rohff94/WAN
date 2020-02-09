#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <signal.h>

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
	char *buf1, *buf2, *ptr;
	long diff;


	buf1 = malloc(666);
	buf2 = malloc(12);

  	diff =  (long)buf2 -  (long)buf1;
  	printf("buf1 = %p\nbuf2 = %p\ndiff %d\n",buf1,buf2,diff);


	strcpy(buf1, argv[1]);


	printf("\targv[1] Size: \033[41;1m%d\033[0m bytes \n", strlen(argv[1]));
	fprintf(stderr, "@argv[1]: %p\n", argv[1]);
	fprintf(stderr, "argv[1]: %s\n", argv[1]);
	fprintf(stderr, "@buf1: %p\n", buf1);
 	printf("buf1: ");
	for (i = 0; buf1[i] != '\0'; i++)
	{
		printf("\\x%X", buf1[i]);
	}

	printf("\n");

	printf("\tbuf2 Size: \033[41;1m%d\033[0m bytes \n", strlen(buf2));
	fprintf(stderr, "@buf2: %p\n", buf2);
	fprintf(stderr, "buf2: %s\n", buf2);
	printf("buf2: ");
	for (i = 0; buf2[i] != '\0'; i++)
	{
		printf("\\x%X", buf2[i]);
	}


	printf("\n");

	free(buf1);	
	free(buf2);

	


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
