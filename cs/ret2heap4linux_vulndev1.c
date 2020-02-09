// vulndev1.c
// vuln-dev mailing list security challenge #1
// by Aaron Adams <aadams@securityfocus.com>
// Spot the error in this program.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>

#define SIZE	252

extern char **envp;
void start(void) __attribute__ ((constructor));
void end(void) __attribute__ ((destructor));
int helloWorld();
int accessForbidden();
int (*ptrf)();
void shell_system();

int main(int argc, char **argv, char **envp) {
	int	i;
	char	*p1, *p2;
	char	*buf1 = malloc(SIZE);
	char	*buf2 = malloc(SIZE);
	long diff;

	if (argc != 3)
		exit(1);

  	diff =  (long)buf2 -  (long)buf1;
  	printf("buf1 = %p\nbuf2 = %p\ndiff %d\n",buf1,buf2,diff);

	p1 = argv[1], p2 = argv[2];
	strcpy(buf1, p1);
	strcpy(buf2, p2);

	printf("\targv[1] Size: \033[41;1m%d\033[0m bytes \n", strlen(argv[1]));
	fprintf(stderr, "argv[1]: %s\n", argv[1]);
 	printf("buf1: ");
	for (i = 0; i <= SIZE && buf1[i] != '\0'; i++)
	{
		//buf1[i] = p1[i];
		printf("\\x%02x", buf1[i]);
	}

	 printf("\n");

	printf("\targv[2] Size: \033[41;1m%d\033[0m bytes \n", strlen(argv[2]));
	fprintf(stderr, "argv[2]: %s\n", argv[2]);
	printf("buf2: ");
	for (i = 0; i <= SIZE && buf2[i] != '\0'; i++)
	{
		printf("\\x%02x", buf2[i]);
	}

	 printf("\n");


	free(buf1);
	free(buf2);

	printf("pwd\n"); //
	puts("uname -a"); 
	exit(0);
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
