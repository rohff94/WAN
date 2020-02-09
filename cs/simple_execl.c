#include <unistd.h>

void main() {
  execl("/bin/sh","/bin/sh",0);
}
