#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv)
{
  char *first_buf;
  char *second_buf;

  first_buf = (char *)malloc(78 * sizeof(char));
  second_buf = (char *)malloc(20 * sizeof(char));

  strcpy(first_buf, argv[1]);
  free(first_buf);
  free(second_buf);

  return 0;
}
