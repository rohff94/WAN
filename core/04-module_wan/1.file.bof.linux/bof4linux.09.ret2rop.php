<?php

/*
 * Output Format (default is python):
 *
 * -pysyn Use Python syntax.
 * -perlsyn Use Perl syntax.
 * -csyn Use C syntax.
 * -phpsyn Use PHP syntax.
 *
 * Steps in creating ROP Shellcode
 * 1 Setting the system call index in %eax;
 * 2 Setting the path of the program to run in %ebx.
 * 3 Setting the argument vector argv in %ecx.
 * 4 Setting the environment vector envp in %edx.
 *
 * Ret statement = pop+jmp = go to the location stored on top of the stack
 *
 * $opcode = shellcode_asm2hex("mov ebx,esp");
 * requette("ROPgadget --opcode \"$opcode\" --binary $programme "); // "prog_bin2asm()|objdump -d file" | grep "mov ebx,esp"
 * requette("ROPgadget --string \"/bin/sh\" --binary $programme ");
 * requette("ROPgadget --memstr \"/bin/sh\" --binary $programme ");
 * pause();
 *
 * gras("On remarque que ces adresses se trouvent dans la section .text\n");
 * pause();
 * //net("http://www.shell-storm.org/project/ROPgadget/");
 * article("Le Return-oriented programming"," est une technique qui permet de prendre le contrôle de la pile mémoire pour exécuter de manière des instructions machines juste après l'instruction return.
 * On n'a juste besoin de séquences de bits utilisables dans les pages de la mémoire exécutable.
 *
 * Vu que toutes les instructions exécutées appartiennent au programme original il n'y a pas besoin de faire d'injection de code. 
 * Un ensemble d'instructions combinées forme un gadget, ils permettent de faire des actions de haut niveau comme écrire dans la mémoire, faire des calcules (ADD/SUB/AND/XOR/OR) sur des valeurs à une adresse mémoire et aussi appeler une fonction sur des bibliothèques partagées.
 * 
 * L'avantage d'une telle technique c'est qu'elle fait usage de zone exécutable et donc bypasse le DEP sans problème.
 * L'inconvénient majeur est qu'on doit hard coder pas mal d'addresses, on doit connaître ces addresses d'avance et donc en cas d'ASLR ça devient déjà plus difficile.
 * L'une des méthodes utilisées est de travailler avec des offsets, en effet, avec l'ASLR, l'address space layout change mais pas les offsets entre chaque éléments.
 * remarque("\txor a,b si a=b => xor a,b=0\n\txor ecx,ecx=0 (pour éviter les NULL BYTES)\n");
 *
 */

/*
 * push ebp ; MOV EBP,ESP != POP EBP; MOV ESP,EBP
Le prologue: 
	push ebp
	mov ebp,esp
l'épilogue:
	  mov esp,ebp
	  pop ebp
 Rôles des registres d'offset
Registre	Nom	Description
esi	Source Index	Utilisé lors des opérations sur les chaînes de caractères
edi	Destination Index	Comme esi, ce registre sert lors des opérations sur des chaînes de caractères.
ebp	Base Pointer	Référence la base de la pile
eip	Istruction Pointer	Ce registre est particulier car il ne peut pas être manipulé directement. Il pointe en permanence sur la prochaine opération à exécuter.
esp	Stack Pointer	Pointe vers le dernier élément déposé sur la pile (l'élément courant)

push ebp ; empile la valeur originale de ebp
mov ebp, esp ; ebp = esp
sub esp, 8 ; 2 variables locales de 4 octets
...
mov esp, ebp ; désalloue les variables locales
pop ebp ; restaure la valeur de ebp
ret

 l'instruction CALL va empiler la valeur d'EIP - le pointeur d'instruction - pour sauvegarder la "progression" dans le code. Cela va permettre à la routine principale de revenir à son cours une fois la procédure/fonction terminée. Un "call MaProcedure" consiste en fait à faire :
Code : asm
push eip
jmp MaProcedure
when ebp = esp alors : mov eax, [esp+8] == mov eax, [ebp-8]

existe un registre qui contient en permanence l'offset du sommet de la pile : ebp . Donc notre programme, pour savoir ou commence la pile, se fie toujours à ce registre. Ce que nous faisons à l'entrée de notre fonction permet de déplacer la base du nouvel espace de notre pile à la fin de la pile effectivement utilisée par le programme appelant, en nous fiant à esp qui pointe la dernière valeur empilée par l'appelant. 

il faut montrer que esp = ebp au moment du crash ou avant (info frame, i r ebp,esp)
 

  
 ROP variants :
JOP : JUMP Oriented Programming.
SOP: String Oriented Programming.
BROP: Blind Return Oriented Programming.
SROP: Signal Return Oriented Programming. 
data-oriented  programming  (DOP)  [81],  
crash-resistant  oriented programming (CROP) [68], 
or printf-oriented programming [25].

 */




class ret2rop4linux extends bin4linux{


	public function __construct($bin_bof) {
		parent::__construct($bin_bof);
		$name = __CLASS__;
		$rep_path = "$this->dir_tmp/$name";
		if (!file_exists($rep_path)) $this->create_folder($rep_path);
	}
	
// $programme = prog_compile("ret2rop","-fno-pie -z norelro -z execstack -fno-stack-protector -m32 -mtune=i386 -static ");
function countermeasure_rop() {
	$this->article ( "ASLR", "ASLR is implemented and enabled by default into important operating systems.
			ASLR is implemented in Linux since kernel 2.6.12, which has been published in June 2005. Microsoft
			implemented ASLR in Windows Vista Beta 2, which has been published in June 2006	" );
	$this->pause ();
	$this->requette ( "cat /proc/self/maps;cat /proc/self/maps" );
	$this->remarque ( "On remarque que l’adressage est aléatoire, à part 3 plages mémoires:
			r-xp -> segment de CODE
			r--p -> segment DATA read only
			rw-p -> segment DATA read/write" );
	$this->requette ( "cat /proc/self/maps | grep '/usr/bin/cat';cat /proc/self/maps | grep '/usr/bin/cat'" );
	$this->pause ();
	
	$this->article ( "PIE Position Independant Executable", "Un programme compilé avec PIE peut être mappé en mémoire à une adresse variable, à la manière des bibliothèques partagées. Il s’agit d’une protection très efficace contre le Return Oriented Programming, étant donné qu’il devient compliqué de prédire l’adresse d’une portion de code." );
	$this->requette ( "" );
	$programme = prog_compile ( "rop_counter", "-fpie -fno-stack-protector -m32 -mtune=i386" );
	
	$this->requette ( "cat /proc/self/maps | grep '/usr/bin/cat';cat /proc/self/maps | grep '/usr/bin/cat'" );
	$this->remarque ( "On remarque que tout l’adressage est aléatoire maintenant, aucune plage memoire n'est laissée cette fois" );
	$this->pause ();
	
	$this->article ( "Analyse comportementale d'une application", "
			L'ASLR et W^X ayant réussi à restreindre grandement le champ des exploitations possibles, les
			attaquants sont obligés de se rabattre sur des techniques d'exploitation basées sur les faiblesses,
			notamment de l'ASLR, dont nous avons déjà parlé : la stabilité en mémoire de la section .text.
			Lutter contre le Ret2Code est un sujet de recherche actif.
			Des propositions d'analyses comportementales furent faites telles que :
			• Si une application exécute une proportion d'appels à l'instruction RET trop importante dans un
			court lapse de temps, alors l'application est peut-être en train d'être abusé par un Ret2Code (c.f.
			section du rapport sur la programmation orientée (par retour) ;
			• Une autre analyse comportementale a été proposée, retenant le nombre d'appels à l'instruction
			CALL et ceux à l'instruction RET : si le ratio devient déséquilibré, alors l'application ne respecte
			plus le schéma : appel de fonction => Retour de fonction, ce qui peut révéler une exploitation.
			Les deux techniques de protection ont cependant été invalidées pour l'architecture x86 récemment
			(2010) car une étude a illustré une méthode permettant d'effectuer de la programmation orientée
			(par retour) sans appel à l'instruction RET via des gadgets exécutant successivement un POP puis
			un JMP à l'adresse pointée par le registre ayant reçu la valeur dépilée (chose qui semble être
			fréquente, au moins sur l'architecture x86).
			// JUMP ROP
			" );
}

// ====================== RETURN ORIENTED PROGRAMMING ========================================

// ==========================================================================================


public function ret2rop4linux_payload($offset){
	$this->requette ( "ROPgadget --ropchain --binary $this->file_path  " );
	$this->requette ( "gedit $this->file_dir/$this->file_name.py" );$this->pause();
	$this->requette ( "$this->file_path `python $this->file_dir/$this->file_name.py`" );
	$this->pause();
}

public function payload_ret2rop4linux_jop($offset){
}
public function payload_ret2rop4linux_sop($offset){
	/*
	   SOP uses a format string bug to get the control flow. 
  SOP uses two scenario to get the control of the application
– Direct control flow redirect
 ● Erase the return address on the stack
	– Jump on a gadget which adjusts the stack frame to the attacker-controlled buffer
		● If the buffer is on the stack → we can use the ROP
		● If the buffer is on the heap → we cabn use the JOP
– Indirect control flow redirect
  ● Erase a GOT entry
		– Jump on a gadget (ROP scenario)
		– Jump on a gadgets dispatcher (JOP scenario)
	 */
}
public function payload_ret2rop4linux_brop($offset){
	/*
	 ● BROP deals with the ROP and “timing attack”
● Constraints:
– The vulnerability must be a stack buffer overflow
– The target binary (server) must restart after the crash
● Scan the memory byte-by-byte to find potential gadgets
– Try to execute the _write_ function/syscall to leak more gadget from the .text section

	 */
}
public function payload_ret2rop4linux_srop($offset){
	/*
	SROP: Uses the SIGRETURN Linux signal to load values from the stack to the registers
– Store the values on the stack then raise the SIGRETURN syscall
● Your registers will be initialized with the stack values
	 */
}
public function payload_ret2rop4linux_data($offset){
}
public function payload_ret2rop4linux_printf($offset){
}













}
?>