#include <stdio.h>

  int main(int argc, char *argv[]) {
    int num;

    printf("%s%n\n", argv[1], &num);
    printf("Bytes written: %p\n", num);
  }
