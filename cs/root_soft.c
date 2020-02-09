#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

char buf[4096], * args[] = { buf, "dummyArg", 0 };
 
int main(int argc, char *argv[], char **envp)
{
  if (argc < 2) {
    readlink("/proc/self/exe", buf, sizeof(buf));
    usleep(1000);
    execve(args[0], args, 0);
  }
  printf("argc %d\n", argc);
  return 0;
}
