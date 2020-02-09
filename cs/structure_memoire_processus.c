#include <malloc.h>
#include <stdio.h>
	
//(gdb) print &indice
//(gdb) info symbol 0x804959c
	
int i; //dans bss
char c = 'A'; //dans data
	
int main(int argc, char** argv, char** env) {
int j; // stack -> dans la pile
/* Réservation de 50 caractères dans le tas */
char* k = (char *)malloc(50*sizeof(char));
printf("		PID : %d"\
"	.text (main): 0x%08x"\
"	.data (&c):   0x%08x"\
"	.bss (&i):    0x%08x"\
"	heap k:       0x%08x"\
"	stack &k:     0x%08x"\
"	stack &j:     0x%08x"\
"	argv :        0x%08x"\
"	&argv[0] :    0x%08x"\
"	&argv[1] :    0x%08x"\
"	*env :        0x%08x"\
"	*argv :       0x%08x"\
	
, getpid(), main, &c, &i, k, &k, &j, argv, &argv[0], &argv[1], *env, *argv);
}
	
