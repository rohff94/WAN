/*
 * bof3.c
 *
 *  Created on: 27 déc. 2010
 *      Author: rohff-r6h4ck3r
 *  Evolution des adresses dans la pile ( adresses Basses vers Adresses Hautes )
 */
#include <stdio.h>
#include <stdlib.h>

main() {
char *name1,*name2,*name3,*name4,*name5;

name1 = (char *)malloc(10);
name2 = (char *)malloc(10);
name3 = (char *)malloc(10);
name4 = (char *)malloc(10);
name5 = (char *)malloc(10);

printf("App  : Hex addr : Int addr <diff addr between name1>\n");
printf("name1  : 0x%08x : %d <+%d>\n", name1,name1,(name1-name1));
printf("name2  : 0x%08x : %d <+%d>\n", name2,name2,(name2-name1));
printf("name3  : 0x%08x : %d <+%d>\n", name3,name3,(name3-name1));
printf("name4  : 0x%08x : %d <+%d>\n", name4,name4,(name4-name1));
printf("name5  : 0x%08x : %d <+%d>\n", name5,name5,(name5-name1));
}
