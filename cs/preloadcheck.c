#define _GNU_SOURCE

#include <stdio.h>
#include <dlfcn.h>

#define LIBC "/lib/i386-linux-gnu/libc.so.6" // 64 bit -> "/lib/x86_64-linux-gnu/libc.so.6"

int main(int argc, char *argv[]) {
 void *libc = dlopen(LIBC, RTLD_LAZY); // Open up libc directly
 char *syscalls[] = {"open", "readdir", "read", "accept", "access","unlink","strcmp","setsid","getpid",
"execve","chroot","setuid","kill","getsid","fopen","lstat","rmdir","xstat","bind","fstat","readdir64","write",
"unlinkat","opendir","link","fdopendir","unlinkat","pam_authenticate","pam_open_session","readlink"
"pcap_loop","getpwnam","lxstat","listen","socket","signal","perror","chdir","umask","dup2","puts","fork","strncmp"};
 int i;
 void *(*libc_func)();
 void *(*next_func)();

 for (i = 0; i < 43; ++i) {
  printf("[+] Checking %s syscall.\n", syscalls[i]);
  libc_func = dlsym(libc, syscalls[i]);
  next_func = dlsym(RTLD_NEXT, syscalls[i]);
  if (libc_func != next_func) {
   printf("\t\033[37;41;1;1m[!] Preload hooks detected!\033[0m\n");
   printf("\t\tLibc address: \033[32;1;1m%p\033[0m\n", libc_func);
   printf("\t\tNext address: \033[36;1;1m%p\033[0m\n", next_func);
  }
 }

 return 0;
}
