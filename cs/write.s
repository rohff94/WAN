xor %eax,%eax          # eax à zéro 
xor %ebx,%ebx          # ebx à zéro 
xor %edx,%edx          # edx à zéro 
xor %ecx,%ecx          # ecx à zéro 
                       # on fait tout ça pour éviter 
                       # l'erreur de segment après compilation 
movb 0x4,%al          # syscall _write 
movb 0x1,%bl          # unisgned int 
pushl 0x0a            # line feed (retour Ã la ligne) 
push 0x6e616874       # naht 
push 0x616e6f6a       # anoj 
movl %esp,%ecx         # on place esp dans ecx 
movb 0x9,%dl          # size (ici la taille du mot jonathan + \n
                       # soit 8 + 1 = 9) 
int $0x80 
movb 0x1,%al          # syscall _exit 
xor %ebx,%ebx          # ou exclusif pour éviter les zéros 
int $0x80
