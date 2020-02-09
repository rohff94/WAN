#include <stdio.h>
char *args[] = { "/bin/bash", 0 };
int main()
{
  int i = 0, j = geteuid();
  if (j == 0) {
    setuid(0);
    i = execv(args[0], args);
  }
  printf("euid %d i %d\n", j, i);
  return i;
}
