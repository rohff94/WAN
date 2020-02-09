#include <stdio.h>

main(int argc, char **argv) {

  int cpt1 = 0;
  int cpt2 = 0;
  int addr_cpt1 = &cpt1;
  int addr_cpt2 = &cpt2;

  printf(argv[1]);
  printf("\ncpt1 = %d\n", cpt1);
  printf("cpt2 = %d\n", cpt2);
}
