#include <stdio.h>
int main(int argc, char **argv)
		{
	int i;
	int j;
	char **ptr;
	extern char **environ;

	printf("\tNombre D arguments %d\n",argc);
	for(i=0;i<argc;i++)
	printf("\targv[%d] at %p = %s \n",i,argv[i],argv[i]);
	j = 0 ;
	for(ptr=environ;*ptr!=0;ptr++){	
	printf("\tenviron[%d] at %p = %s \n",j,*ptr,*ptr);
	j++ ;
	}

	return 0 ;
	}
