#include <stdio.h>

int main()
{
  long diff;
  static char buf1[16], *buf2;

  buf2 = buf1;
  diff =  (long)buf1 -  (long)&buf2;
  printf("buf1 = %p & buf2 = %p & diff %d\n",buf1,&buf2,diff);
  printf("BEFORE: buf2 = %p\n",&buf2);
  /* An address is 4 long, so we overwrite 4 chars */
  printf("Size buf1 = 16 -> remplir buf1 avec A*%d\n",diff+4);
  memset(buf1,'A',diff+4);  
  printf("AFTER:  buf2 = %p\n",buf2);

  return 0;
}
