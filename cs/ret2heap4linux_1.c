/* A simple demonstration of a heap based overflow */
#include <stdio.h>

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
  puts("Remplir le buf2 avec 2*8 ");
  memset(buf2,'2',size);
  printf("BEFORE: buf2 = %s\n",buf2);
  printf("Remplir le buf1 avec 1*(%d+3) - We overwrite 3 chars\n",diff);
  memset(buf1,'1',diff+3);  /* We overwrite 3 chars */
  printf("AFTER:  buf2 = %s\n",buf2);

  return 0;
}
