#include <stdio.h>

void main(int argc, char **argv)
	{
        char *chaine = (char *) malloc (1024);
     strcpy (chaine, "Hello World");
     printf ("\n\tRETLOC (Adresse de chaine) -> 0x%x\n", (int)chaine);
     printf ("\tchaine avant attaque -> %s\n", chaine);
     printf (argv[1]); 
     printf ("\n\tchaine apres attaque -> %s\n", chaine); 
	exit(0);
	}
