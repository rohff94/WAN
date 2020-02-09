#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void bye(void) __attribute__ ((destructor));
int helloWorld();
int accessForbidden();
int (*ptrf)();
void shell_system();

extern char **envp;
static char *sc="\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80"; // 21 char

int vuln(const char *format)
{
  char buffer[128];
  memset(buffer, 0, sizeof(buffer));
  printf("helloWorld() = %p\n", helloWorld);
  printf("accessForbidden() = %p\n", accessForbidden);
  ptrf = helloWorld;
  printf("before : ptrf() = %p # %p \n", ptrf, &ptrf);
  (*ptrf)();
  snprintf(buffer, sizeof(buffer), format); // notre vulnerabilite, GOT: tout ce qui vient apres snprintf sont exploitable avant non (printf, snprintf)
  //strcpy(buffer, format);
  printf("buffer = [%s] (size=%d)\n", buffer, strlen(buffer));
  printf("after : ptrf() = %p (%p) \n", ptrf, &ptrf);
  (*ptrf)();
  fflush(stdout);
  return 0;
}

int main(int argc, char **argv,char **envp) {
  int i;
  if (argc <= 1) {
    fprintf(stderr, "Usage: %s <buffer>\n", argv[0]);
    exit(-1);
  }
  for(i=0;i<argc;i++)
    printf("\targv[%d] at %p\n",i,argv[i]);
  vuln(argv[1]);
  exit(0);
}

void bye()
{
	fprintf(stdout,"\tBye\n");
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

