#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <malloc.h>

extern char **envp;
void start(void) __attribute__ ((constructor));
void end(void) __attribute__ ((destructor));
int helloWorld();
int accessForbidden();
int (*ptrf)();
void shell_system();


struct data {
  char name[64];
};

struct fp {
  int (*fp)();
};

void winner()
{
  printf("level passed\n");
}

void nowinner()
{
  printf("level has not been passed\n");
}

int main(int argc, char **argv, char **envp){
	int i;
	long diff;

  struct data *d;
  struct fp *f;

  d = malloc(sizeof(struct data));
  f = malloc(sizeof(struct fp));
  f->fp = nowinner;

  printf("data is at %p, fp is at %p\n", d, f);

  	diff =  (long)f -  (long)d;
  	printf("f = %p\nd = %p\ndiff: %d\n",f,d,diff);


  strcpy(d->name, argv[1]);
  

	printf("\targv[1] Size: \033[41;1m%d\033[0m bytes \n", strlen(argv[1]));
	fprintf(stderr, "argv[1]: %s\n", argv[1]);
 	printf("d->name: ");
	for (i = 0; d->name[i] != '\0'; i++)
	{
		printf("\\x%02x", d->name[i]);
	}

	printf("\n");



  f->fp();


	printf("pwd\n"); //
	puts("uname -a"); 
	return 0 ;
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
