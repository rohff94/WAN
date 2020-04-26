<?php

/*
rsync -zvhru -progress /home/rohff/EH /media/rohff/2E1C24C31C2487C3/EH

 */
 


class CONFIG {
	

	
    var $cmd_unix ;
    var $cmd_unix_tab ;
    var $cmd_commun ;
    var $cmd_win ;
    var $racine ;
    var $dir_tools ;
    var $dir_vm ;
    var $dir_tmp ;
    var $dir_c ;
    var $dir_php ;
    var $dir_iso ;
    var $dir_doc ;
    var $dir_vdo ;
    var $dir_img ;
    var $dir_install ;
    var $dico_web;
    var $dico_web_file;
    var $dico_web_directories;
    var $dico_word;
    var $dico_password;
    var $dico_users;
    var $dico_ports;
    
    
    var $shells;
    var $vm_tmp_win;
    var $vm_tmp_lin;
    var $yara_file;
    var $user2local ;
    
    var $display_xml ;
    var $display_cli ;
    
    var $time_start ;
    var $log_error_path ;
    var $log_succes_path ;
	
	public function __construct() {
	

	#========= Shells Strings ============
	$this->shells = array("/bin/sh","sh","/bin/bash","bash","/bin/dash","dash");
	#======== Files =========================
	$this->yara_file = "$this->dir_tools/yara/malware.yar";
	$this->cmd_unix = "id && pwd && uname -a && uname -srp && cat /etc/lsb-release /etc/issue && netstat -r && cat /etc/hosts /etc/resolv.conf /etc/network/interfaces /etc/rsyslog.conf /etc/exports /etc/inetd.conf /proc/version /etc/sudoers /etc/profile /etc/shells && ifconfig && ip link && ls -alR /etc/cron.d/ && history && env && grep -n -i pass /var/log/*.log 2>/dev/null && ps aux | grep root  && lsb_release -a && lspci && lsusb && lshw && hostnamectl && exit";
	// 
	$this->cmd_unix_tab = array("help","/usr/bin/id","/usr/bin/date","/bin/pwd","/bin/uname -a","/bin/uname -srp","lsof -Pin","pstree ","cat /etc/passwd","cat /etc/shadow","ps aux","netstat -tupan","cat /etc/lsb-release","cat  /etc/issue","netstat -r","netstat -an","route","cat /etc/hosts","cat  /etc/resolv.conf","cat  /etc/network/interfaces","cat  /etc/rsyslog.conf","cat  /etc/exports","cat  /etc/inetd.conf","cat  /proc/version","cat  /etc/sudoers","cat  /etc/profile","cat  /etc/shells","/sbin/ifconfig","/bin/ip link","/bin/ls -alR /etc/cron.d/","history","/usr/bin/env","/bin/grep -n -i pass /var/log/*.log 2>/dev/null","/bin/ps aux | grep root ","/usr/bin/lsb_release -a","/usr/bin/lspci","/usr/bin/lsusb","/usr/bin/lshw","/usr/bin/hostnamectl","locate authorized_keys","/usr/bin/find / -type f -perm -04000 -ls","lsattr -va","w","lastlog","find / -type f -name .bash_history","which wget curl w3m lynx fetch lwp-download","cat /proc/version","cat /proc/cpuinfo","whereis gcc","arp -a","php -r 'phpinfo();'","crontab -l","/usr/bin/find / -type f -name \"config*\" ","find / -perm -u=s -type f 2>/dev/null","find / -perm -g=s -type f 2>/dev/null","find / -type f -name .htpasswd 2>/dev/null","find / -type f -name authorized_keys 2>/dev/null","find / -type f -name service.pwd","find / -type f -name .mysql_history","find / -type f -name .fetchmailrc","grep -l -i pass /var/log/*.log 2>/dev/null","dpkg -l");
	//$this->cmd_unix_tab = array("id");
	$this->cmd_commun = "date";
	$this->cmd_win = "";
	$this->vm_tmp_win = 'C:\WINDOWS\Temp';
	$this->vm_tmp_lin = '/tmp';
	exec("pwd",$tmp1);
	$this->racine = trim($tmp1[0]);
	
	exec("whoami",$tmp2);
	$this->user2local = trim($tmp2[0]);

	$this->dir_tools = "$this->racine/tools";
	$this->dir_vm = "$this->racine/../Hack.vlan";
	$this->dir_tmp = "$this->racine/../TMP";
	$this->dir_c = "$this->racine/cs";
	$this->dir_vdo = "$this->racine/VDO";
	$this->dir_img = "$this->racine/../IMG";
	$this->dir_install = "$this->racine/install";
	
	$this->dico_web = "$this->dir_tools/dico/web.dico";
	$this->dico_web_directories = "$this->dir_tools/dico/web.directories.dico";
	$this->dico_web_file = "$this->dir_tools/dico/web.file.dico";
	$this->dico_word = "$this->dir_tools/dico/word.dico";
	$this->dico_password = "$this->dir_tools/dico/password.dico";
	$this->dico_users = "$this->dir_tools/dico/users.dico";
	$this->dico_ports = "$this->dir_tools/dico/ports.dico";
	
	$this->log_error_path = "/tmp/log.error.wan.log";
	$this->log_succes_path = "/tmp/log.succes.wan.log";
	$this->time_start = microtime(TRUE);
}




public function pdf($file,$page){
	system("cp $this->dir_php/pdf/$file $this->dir_tmp/$file");
	$this->requette("evince $this->dir_tmp/$file -i $page");
}


public function parchment($chaine){
    $query = "echo '$chaine' | boxes -d parchment -a c";
    system($query);
}

// notification fenetre -> comme MSN
public function notify($chaine) {
	
	//system("espeak  \"Look screen\" ");	
	//system("flite -t '$chaine' 2> /dev/null");
    $this->rouge($chaine);
	system("notify-send -i $this->dir_img/hacker.png \"$chaine\"");
    //$query = "echo '".$this->rouge($chaine)."' | boxes -d parchment -a c";
	//system($query);	sleep(1);	
	//system("zenity --notification --text '$chaine' --window-icon=$this->dir_img/hacker.png 2> /dev/null");
}


public function screenshot($seconde){
	$this->requette("scrot -d $seconde -c '%T.png' -u -e \"notify-send -i $this->dir_img/hacked.png 'Capture Ecran realisee'  \" ");
}






	public function start($chaine,$sommaire){
		system("clear");
		echo("\n\t\t[#] Title: $chaine\n\t\t[#] Version: 0.8\n\t\t[#] Date: ".date('l jS \of F Y h:i:s A')."\n\t\t[#] Author: Mr. Rafik GUEHRIA\n\t\t[#] Job: Trainer Ethical Hacking.\n\t\t[#] \t( CEH, ECSA, LPT, CHFI, SEC760 )\n\t\t[#] CV: https://www.linkedin.com/in/rguehria/\n\t\t[#] VDO: https://www.youtube.com/user/rof94\n\t\t[#] Website Perso: http://www.pentesting.eu\n\t\t[#] Email Perso: r.guehria@pentesting.eu\n\t\t[#] GitHub: https://github.com/rohff94/WAN.git\n");
		//system("figlet '\033[36;1;1m".strtoupper($chaine)."\033[0m' | /usr/games/cowsay -f '/usr/share/cowsay/cows/ghostbusters.cow' ");
		//$display = "\n\t\t[#] Title: $chaine\n\t\t[#] Version: 0.8\n\t\t[#] Date: ".date('l jS \of F Y h:i:s A')."\n\t\t[#] Author: Mr. Rafik GUEHRIA\n\t\t[#] Job: Trainer Ethical Hacking.\n\t\t[#] \t( CEH, ECSA, LPT, CHFI, SEC760 )\n\t\t[#] CV: https://www.linkedin.com/in/rguehria/\n\t\t[#] VDO: https://www.youtube.com/user/rof94\n\t\t[#] Website Perso: http://www.pentesting.eu\n\t\t[#] Email Perso: r.guehria@pentesting.eu\n\t\t[#] GitHub: https://github.com/rohff94/WAN.git\n";
		//system(" /usr/games/cowsay -f '/usr/share/cowsay/cows/ghostbusters.cow' \"$display\" ");
		echo "\n";
	}

	// Blanc gras sur fond rouge sousligné
	public function chapitre($chaine){
		system("figlet -c \"$chaine\" | lolcat");
		sleep(1);
		$timestamp_debut = microtime(true);
		return $timestamp_debut;
	}

	public function rouge($chaine){
	    $display_cli = "\t\t\033[37;41;1;1m".$chaine."\033[0m\n";
	    $display_xml = "<rouge>$chaine</rouge>\n";
	    echo $display_cli;
	    //system("echo '$display_cli' | pv -qL 10 ");
	    //if ($this->flag_poc) sleep(1);
	     
	    //return $display_cli;
	}
	



	function isIPv4($ip) {
		return (preg_match( '/^([0-9]{1,3}).([0-9]{1,3}).([0-9]{1,3}).([0-9]{1,3})$/', $ip )) ? true : false;
	}
	function isIPv6($ip) {
		$ipv6 = false;
		if (preg_match( '/^([a-f0-9]{1,4}):([a-f0-9]{1,4}):([a-f0-9]{1,4}):([a-f0-9]{1,4}):([a-f0-9]{1,4}):([a-f0-9]{1,4}):([a-f0-9]{1,4}):([a-f0-9]{1,4})$/', $ip ))
			$ipv6 = true;
			if (preg_match( '/^([a-f0-9]{1,4}):([a-f0-9]{1,4}):([a-f0-9]{1,4}):([a-f0-9]{1,4}):([a-f0-9]{1,4}):([a-f0-9]{1,4}):([0-9]{1,3}).([0-9]{1,3}).([0-9]{1,3}).([0-9]{1,3})$/', $ip ))
				$ipv6 = true;
				return $ipv6;
	}


	public function color4dispay(){
		for ($i=29;$i<50;$i++)
			echo "$i : \033[01;".$i."m couleur \033[0m\n";
	}





	function dot2diagram($diagram){
		$tab_replace = array("'",'(',')','`',';','\\x','//','>>','<<','&');
		$diagram = str_replace($tab_replace, "", $diagram);
		$diagram = strip_tags($diagram);
		$chaine = "echo '$diagram' | grep -v -i \"nmap\" | grep -v -i \"^NSE\" |  sed \"s/[|?*:]/ /g\" | grep -v '^$' ";
		exec($chaine,$tmp);
		$display = $this->chaine($tmp);
		$display = str_replace("\n","<BR />\n", $display);
		return $display;
		//return wordwrap($display, 120, "<BR />\n");
	}




	// Blanc gras sur fond rouge sousligné
	public function gtitre($chaine){
	    //$display = "\n".system("figlet \"$chaine\" ");
	    //echo $display."\n";
	    system("echo '$chaine' | toilet -f mono12 -F metal -t ");
	    if ($this->flag_poc) sleep(1);
		//	echo  "\t\t\t\033[36;40;1;1m".strtoupper($chaine)."\033[0m\n";	    
	}

	// Bleu gras sousligné
	public function titre($chaine){
		$display_cli =  "\t\t\033[34;40;1;1m ☣ ".strtoupper($chaine)." ☣ \033[0m\n";
		$display_xml = "<titre>".strtoupper($chaine)."</titre>\n";
		echo  $display_cli;
		if ($this->flag_poc) sleep(1);
		return $display_xml;
		//pause();
	}

	// Vert gras sous ligné
	public function ssTitre($chaine){
	    $display_cli = "\t\033[32;40;1;1m$chaine\033[0m\n";
	    $display_xml = "<ssTitre>$chaine</ssTitre>";
	    echo  $display_cli;
	    return $display_xml;
	}

	// titre: bleu gras -> texte: blanc gras
	public function article($titre,$texte){
	    $display = "\t\033[36;40;1;1m".strtoupper($titre).":\033[0m\033[37;40;1;1m ".$texte."\033[0m\n";
		echo  $display;
		return $display;
	}

	public function service2thread($max_iter){
	    $thread = 1 ;
	    $max = (int)trim($max_iter) ;
	    switch ($max) {
	        case ( $max < 10 && $max >=2 ) :
	            $thread = 2;
	            break;
	        case ( $max < 50 ) :
	            $thread = 8;
	            break;
	        case ( $max < 100 && $max >=50 ) :
	            $thread = 8;
	            break;
	        case ( $max < 100 && $max >=150 ) :
	            $thread = 10;
	            break;
	        case ( $max < 200 && $max >=100 ) :
	            $thread = 15;
	            break;
	        case ( $max < 400 && $max >=200 ) :
	            $thread = 20;
	            break;
	        case ( $max < 800 && $max >=400 ) :
	            $thread = 30;
	            break;
	        case ( $max < 1500 && $max >=800 ) :
	            $thread = 50;
	            break;
	        case ( $max < 3000 && $max >=1500 ) :
	            $thread = 20;
	            break;
	        case ( $max < 6000 && $max >=3000 ) :
	            $thread = 60;
	            break;
	        case (  $max >= 6000 ) :
	            $thread = 100;
	            break; }
	            
	            return $thread;
	}
	
	
	
	function check2url($url)
	{
		$pattern = '/^(([\w]+:)?\/\/)?(([\d\w]|%[a-fA-f\d]{2,2})+(:([\d\w]|%[a-fA-f\d]{2,2})+)?@)?([\d\w][-\d\w]{0,253}[\d\w]\.)+[\w]{2,4}(:[\d]+)?(\/([-+_~.\d\w]|%[a-fA-f\d]{2,2})*)*(\?(&amp;?([-+_~.\d\w]|%[a-fA-f\d]{2,2})=?)*)?(#([-+_~.\d\w]|%[a-fA-f\d]{2,2})*)?$/';
		return preg_match($pattern, $url);
	}









	// blanc gras
	public function gras($texte){
	    $display = "\033[37;45;1;7m$texte\033[0m";
		echo  $display;
		return $display;
	}

	
	// jaune gras
	public function jaune($chaine){
	    echo  "\t\033[33;40;1;1m$chaine\033[0m\n";
	}
	
	// bleu gras
	public function question($chaine){
	    $display = "\t\033[31;47;1;5mQuestion:\033[0m \033[30;47;1;5m$chaine\033[0m \n";
		echo  $display;
		return $display;
	}

	public function remarque($chaine){
	    $display = "\t\033[31;43;1;1mRemarque:\033[0m \033[37;43;5;1m$chaine\033[0m \n";
		echo  $display;
		return $display;
	}

	public function note($chaine){
	    $display = "\t\033[33;46;1;5mNote:\033[0m \033[37;46;1;5m$chaine\033[0m \n";//pause();
		echo  $display;

		//if ($this->flag_poc) sleep(1);
		//return $display;
	}


	// Blanc gras sur fond rouge sousligné
	public function important($chaine){
		system("echo '$chaine' | toilet -f term -F border --gay");		
	}


	
	public function time2laps($start,$end){	    
	    $time = $end - $start;
	    
	    $sec = intval($time);
	    //$micro = $time - $sec;

	    //$final = strftime('%T', mktime(0, 0, $sec)) . str_replace('0.', '.', sprintf('%.3f', $micro));
	    $final = strftime('%T', mktime(0, 0, $sec));
	    
	    $this->note("Spending Time $final");
	}
	
	// blanc sur fond rouge
	public function pause(){
	    if($this->flag_poc){

		echo "\t\t\t\t\t\033[33;41;1;1mPress Enter\033[0m";
		fgets(STDIN);
		echo "\n";
	    }
	    else {
	        //var_dump($this->flag_poc);
	        //$this->note("No Pause");
	        $end = microtime(TRUE);
	        $this->time2laps($this->time_start, $end);
	    }
	}


	public function fun($chaine){
		// cmatrix
		system($chaine);
	}


	public function img($name){
		$name = trim($name);
		//$this->requette("eog $name 2> /dev/null");
	}

	public function net($site){
	    $site = trim($site);
		if (!empty($site)) $this->requette("firefox --new-tab \"$site\" 2> /dev/null ");
	}

	public function todo($chaine){
		echo "\t\033[35;1m$chaine\033[0m\n";
	}

	function create_folder($rep_path){
		if (!is_dir($rep_path)) system("mkdir $rep_path");
		//if(!file_exists($rep_path)) system("mkdir $rep_path");
		//else system("rm $rep_path/*");
		return $rep_path;
	}

	// Videos
	public function vdo($vdo,$start,$duree){
		$this->requette("vlc-wrapper file://$this->dir_vdo/$vdo --start-time $start --run-time $duree --play-and-exit 2> /dev/null");
	}






	// Affiche Tableau
	public function tab($tab) {
		$chaine = "";
		if (empty($tab)) return "";
		$tab = array_filter($tab);
		
		foreach($tab as $val){
			//echo $val."\n" ;
			$chaine .= $val."\n" ;
		}
		return $chaine;
	}





	// Affiche Tableau
	public function chaine($tab) {
		$chaine = "";
		if (empty($tab)) return "";
		foreach($tab as $val){
			//echo $val."\n" ;
			$chaine .= $val."\n" ;
		}
		return trim($chaine);
	}

















	// ===== MAP ===============================
	function map($map) {
		// 0
		$shellcode_env_no_ASLR = <<<SENA

	   ===========
    ENV-> | SHELLCODE |
	   ===========

     <---- OFFSET ---->
      ====================================================
     | ANYTHING Offset) |  EIP  (addr addr2ShellCode_env) |
      ====================================================
\n
SENA;

		// 1
		$shellcode_env_with_ASLR = <<<SEWA

	   ========================
    ENV-> | Nops x MAX | SHELLCODE |
	   ========================

     <---- OFFSET ---->
      ====================================================
     | NOTHING Offset) |  EIP  (addr addr2ShellCode_env) |
      ====================================================
\n
SEWA;

		// 2
		/*
		* digraph structs {
		* node [shape=record];
		* struct1 [label="<f0> NOPs x (SC-Offset) MIN|<f1> SHELLCODE MAX|<f2> EIP (addr2SC)"];
		* struct1:f2 -> struct1:f0;
		* }
		*/
		$shellcode_before_eip_no_ASLR = <<<SBNA

	   <---------  OFFSET ---------------->
            ==========================================================
    ESP->  | NOPs x (SC-Offset) MIN | SHELLCODE MAX |  EIP  (addr2SC) |
            ==========================================================
\n
SBNA;

		// 3
		$shellcode_before_eip_with_ASLR = <<<SBWA

        <------------  OFFSET -------------->
         ===================================================================================
 ESP->  | NOPs x (SC-Offset) MAX | SHELLCODE MIN |  EIP  (addr jump2nops = esp + addr2nops) |
         ===================================================================================
\n
SBWA;

		// 4
		$shellcode_after_eip_no_ASLR = <<<SFNA

   <---- OFFSET ---->
   =======================================================================
  | NOTHING x OFFSET |  EIP  (addr jump2esp) | NOPS x MIN | SHELLCODE MAX |
   =======================================================================
\n
SFNA;

		// 5
		$shellcode_after_eip_with_ASLR = <<<SFWA

   <---- OFFSET ---->
   =======================================================================
  | NOTHING x OFFSET |  EIP  (addr jump2esp) | NOPS x MAX | SHELLCODE MIN |
   =======================================================================
\n
SFWA;

		// 6
		$shellcode_after_max_with_ASLR = <<<SFXWA
Buffer Overflow Simple:

// /usr/include/linux/binfmts.h -> MAX_ARG_STRLEN (PAGE_SIZE * 32) -> 4096 * 32 = 131072
Max 131072 bytes= (buffer 1024bytes + 4bytes ebp = 1028bytes (Offset)+ 4bytes EIP jump2esp + nops + Shellcode + 1 byte \\0|<-ESP
            ============================================= =========================== =============== ============== ====
 SPLOIT =  |(nothing (\\x90 or AAAA or ABCD) x Offset= ?) |  EIP  (addr jump2esp = ?) | NOPs x 100000 | SHELLCODE = ?| \\0 |<-ESP
            ============================================= =========================== =============== ============== ====
\n
SFXWA;

		// 7
		$shellcode_libc = <<<SLIBC
	Return To Libc Payload N° 2/2
  ======================================================
  | NOTHING x OFFSET |  &system | &exit | &cmd | CMD |
  ======================================================

\n
SLIBC;

		// 8
		$shellcode_libc2 = <<<SLIBC2
	Return To Libc Payload N° 1
  ===============================================
  | NOTHING x OFFSET |  &system | &exit | &CMD |
  ===============================================
\n
SLIBC2;

		if ($map == 0)
			return $shellcode_env_no_ASLR;
			if ($map == 1)
				return $shellcode_env_with_ASLR;
				if ($map == 2)
					return $shellcode_before_eip_no_ASLR;
					if ($map == 3)
						return $shellcode_before_eip_with_ASLR;
						if ($map == 4)
							return $shellcode_after_eip_no_ASLR;
							if ($map == 5)
								return $shellcode_after_eip_with_ASLR;
								if ($map == 6)
									return $shellcode_after_max_with_ASLR;
									if ($map == 7)
										return $shellcode_libc;
										if ($map == 8)
											return $shellcode_libc2;
	}
	// ==========================================


	
	
	

	
	
	

}



?>
