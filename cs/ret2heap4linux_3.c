/* A simple demonstration of a heap based overflow */
#include <stdio.h>


void start(void) __attribute__ ((constructor));
void end(void) __attribute__ ((destructor));
int helloWorld();
int accessForbidden();
int (*ptrf)();
void shell_system();


int main()
{
  long diff,size = 8;
  char *buf1;
  char *buf2;

  buf1 = (char *)malloc(size);
  buf2 = (char *)malloc(size);
  if(buf1 == NULL || buf2 == NULL)
  {
	perror("malloc");
	exit(-1);
  }

  diff =  (long)buf2 -  (long)buf1;
  printf("buf1 = %p\nbuf2 = %p\ndiff %d\n",buf1,buf2,diff);
  puts("Remplir le buf2 avec 2*4 ");
  memset(buf2,'2',size);
  printf("BEFORE: buf2 = %s\n",buf2);
  printf("Remplir le buf1 avec 1*(%d+4) - We overwrite 4 chars\n",diff);
  memset(buf1,'1',diff+4);  /* We overwrite 3 chars */
  printf("AFTER:  buf2 = %s\n",buf2);

	
	printf("pwd\n"); //
	puts("uname -a"); 
	exit(0);
  return 0;
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
