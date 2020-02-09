#include <stdio.h>
#include <stdlib.h>

main(int argc, char **argv) {
char *name;
char *dangerous_system_command;

name = (char *)malloc(10);
dangerous_system_command = (char *)malloc(256);

printf("Address of name is 0x%x : %d \n", name,name);
printf("Address of command is 0x%x : %d \n", dangerous_system_command, dangerous_system_command);
printf("Diff : %d chars\n", (dangerous_system_command - name) );

sprintf(dangerous_system_command, "echo %s", "`date`");
printf("votre nom svp\n");
gets(name);
printf("\nAcces %s at Time : \n",name);
system(dangerous_system_command);
}
