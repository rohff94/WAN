#include <stdio.h>

void start(void) __attribute__ ((constructor));
void end(void) __attribute__ ((destructor));

int main() {
  printf("in main()\n");
}

void start(void) {
  printf("in start()\n");
}

void end(void) {
  printf("in end()\n");
}
