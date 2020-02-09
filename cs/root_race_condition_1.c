#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
    
int     main (int argc, char * argv [])
    {
   struct stat st;
   FILE * fp;

   if (argc != 3) {
  printf ("usage : %s fichier message\n", argv [0]);
  exit(EXIT_FAILURE);
   }
   if (stat (argv [1], & st) < 0) {
  printf ("%s introuvable\n", argv [1]);
  exit(EXIT_FAILURE);
   }
   if (st . st_uid != getuid ()) {
  printf ("%s ne vous appartient pas !\n", argv [1]);
  exit(EXIT_FAILURE);
   }
   if (! S_ISREG (st . st_mode)) {
  printf ("%s n'est pas un fichier normal\n", argv[1]);
  exit(EXIT_FAILURE);
   }
   
	sleep (20);

   if ((fp = fopen (argv [1], "w")) == NULL) {
  printf ("Ouverture impossible\n");
  exit(EXIT_FAILURE);
   }
   fprintf (fp, "%s\n", argv [2]);
   fclose (fp);
   printf ("Écriture Ok\n");
   exit(EXIT_SUCCESS);
    }
