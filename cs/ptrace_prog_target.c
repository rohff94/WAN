#include <stdio.h>
#include <string.h>

void main(){
	printf("Test Program Ptrace - Inject into Memory Process\nPress Enter");
	printf("%s : Spawned process: pid = %d\tppid = %d\n", "Victim", getpid(), getppid());
	while (1==1) ; // Simulate Still executing Process
}
