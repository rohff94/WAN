<?php




/*
 * http://sourceforge.net/projects/spiderfoot/?source=typ_redirect

 * 
 * nmap -sP 192.168.x.0/24 --disable-arp-ping -oX -
 * 
 */

/*
 Session splicing is an IDS evasion technique in which an attacker delivers data in multiple small- sized packets to the target computer. Hence, it becomes very
 difficult for an IDS to detect the attack signatures of such attacks. Which of the following tools can be used to perform session splicing attacks?
 Each correct answer represents a complete solution. Choose all that apply.
 A. Whisker
 B. Fragroute
 C. Nessus
 D. Y.A.T.

 Correct Answer: AC


 Packet filters forward the original packet through the other side, while proxy firewalls create a new packet before forwarding it.

 */ 

class IP extends DOMAIN{

    var $ip;
    var $ip2id ;
    var $ip2where ;
    var $tab_open_ports_tcp ;
    var $tab_open_ports_udp ;
    var $tab_open_ports_all;
    var $tab_cve_source ;
    
    var $path_xmlstarlet ;
    var $path_elinks ;
    var $path_faraday ;
    var $path_openvas ;
    

	
    public function __construct($eth,$domain,$ip) {	
		$ip_addr = trim($ip);
		$this->tab_open_ports_tcp = array();
		$this->tab_open_ports_udp = array();
		$this->tab_open_ports_all = array();
		$this->tab_cve_source = array();

		if (empty($ip)) return $this->rouge("EMPTY IP");
		if ( ($this->isIPv4($ip_addr)) || ($this->isIPv6($ip_addr)) ) {
		    $this->ip = $ip_addr;
		   }
		if ( (!$this->isIPv4($ip_addr)) && (!$this->isIPv6($ip_addr)) ) 
		{
			$ip_tab = $this->host4ip($ip_addr);
			if (!empty($ip_tab)) $ip_tmp = $ip_tab[0];
			else $ip_tmp = "";
			if ( (!empty($ip_tmp)) && ($this->isIPv4($ip_tmp)) || ($this->isIPv6($ip_tmp)) ) $this->ip = $ip_tmp;
			else {
			    var_dump($ip_tmp);
			    $this->article("IP", $ip_addr);
			    $this->rouge("No IP");	
			    exit();
			}
		    
		}
		
		parent::__construct($eth,$domain);
		$this->ip2where = "id8eth = $this->eth2id AND ip = '$this->ip'";
		
		$sql_r = "SELECT ip FROM ".__CLASS__." WHERE $this->ip2where ORDER BY ladate DESC LIMIT 1";
		if (!$this->checkBD($sql_r)) {
		$sql_w = "INSERT  INTO ".__CLASS__." (id8domain,id8eth,ip) VALUES ('$this->domain2id','$this->eth2id','$this->ip'); ";
		$this->mysql_ressource->query($sql_w);	
		echo $this->note("Working on IP:$this->ip for the first time");
		$this->watching();
		}

		$sql_r = "SELECT id FROM ".__CLASS__." WHERE $this->ip2where ";
		$this->ip2id = $this->mysql_ressource->query($sql_r)->fetch_assoc()['id'];
		
		if ($this->ip4priv($this->ip)) $this->article("Private IP", $this->ip);
		
		if (!$this->ip4priv($this->ip)) {
		    $ip_wan = $this->ip4net();
		    if ($this->isIPv4($ip_wan)) {
		        $this->article("WAN IP Attacker", $ip_wan);
		        //$this->article("WAN IP Attacker GeoLoc", $this->ip2geo($ip_wan));
		    }
		    if (empty($ip_wan)) {
		        $chaine = "Lost Connexion to the net";
		        $this->rouge($chaine);
		        exit();
		    }
		}

	}
	
	
	public function watching(){
	    $chaine = "Monitors your environment";
	    $this->rouge($chaine);
	    if ($this->ip4priv($this->ip)){
	        $cidr = trim($this->ip2cidr());
	        $query = "echo '$this->root_passwd' | sudo -S arpwatch -dN -i $this->eth -a -n $cidr.0/24";
	        $this->cmd("localhost", $query);
	        $query = "echo '$this->root_passwd' | sudo -S nmap -sn --reason $cidr.0/24 -e $this->eth ";
	        $this->cmd("localhost", $query);
	        $query = "echo '$this->root_passwd' | sudo -S arp -av -i $this->eth";
	        $this->cmd("localhost", $query);
	    }
	    
	    $query = "echo '$this->root_passwd' | sudo -S top";
	    $this->cmd("localhost", $query);
	    $query = "echo '$this->root_passwd' | sudo -S ps aux";
	    $this->cmd("localhost", $query);
	    $query = "echo '$this->root_passwd' | sudo -S snort -A console -q -c /etc/snort/snort.conf -i $this->eth  'not host $this->ip'";
	    $this->cmd("localhost", $query);	    
	    $query = "mysql --user=$this->mysql_login --password=$this->mysql_passwd --database=bot";
	    $this->cmd("localhost", $query);
	    $query = "cd $this->dir_tmp; php -S $this->ip:$this->port_rfi";
	    $this->cmd("localhost", $query);
	    $query = "tail -f /var/log/syslog";
	    $this->cmd("localhost", $query);
	    $query = "tail -f /var/log/auth.log";
	    $this->cmd("localhost", $query);
	    $query = "tail -f /var/log/kern.log";
	    $this->cmd("localhost", $query);
	    $query = "tail -f /var/log/mail.log";
	    $this->cmd("localhost", $query);
	    $query = "watch -n 5 -e \"grep -i segfault /var/log/kern.log\"";
	    $this->cmd("localhost", $query);
	}
	
	public function ip2dot4port(){
	    $this->ssTitre(__FUNCTION__);
	    $this->ip2port();
	    $dot = "";
	    $dot_header = "digraph structs {
	    label = \"".__FUNCTION__."\";
		graph [rankdir = \"TB\" layout = dot];
		node [fontsize = \"16\" shape = \"circle\"];
		edge [penwidth=2.0 ];\n	";
	    
	    $this->ssTitre(__FUNCTION__);
	    $file_output = "/tmp/$this->ip.".__FUNCTION__.".dot";
	    $dot .= $dot_header;
	    $dot .= "label = \"$this->ip\";
		graph [rankdir = \"TB\" layout = dot];
		node [fontsize = \"16\" shape = \"plaintext\"];
		edge [penwidth=2.0 ];\n	";
	    $dot .= $this->ip2dot();
	    
	    var_dump($this->tab_open_ports_all);$this->pause();
	    foreach ($this->tab_open_ports_all as $port){
	        if (!empty($port))  {
	            foreach ($port as $port_num => $protocol){
	                if (!empty($port_num)){
	                    $obj_port = new PORT($this->eth,$this->domain,$this->ip,$port_num,$protocol);
	                    $dot .= "\"$this->ip:$obj_port->port\" [label=<<TABLE BORDER=\"0\" CELLBORDER=\"1\" CELLSPACING=\"0\" ALIGN=\"LEFT\" >";
	                    $dot .= $obj_port->port2dot();
	                    $dot .= "</TABLE>>];\n";
	                    $dot .= " \"$obj_port->ip\":ip2port -> \"$obj_port->ip:$obj_port->port\":port [color=\"green4\"]; \n ";
	                    $this->pause();
	                }
	            }
	        }
	    }
	    $dot_footer = "
}
";
	    
	    $ip2dot4port = $dot.$dot_footer;
	    
	    
	    $this->dot4make($file_output,$ip2dot4port);
	    $this->requette("gedit $file_output");
	    return $dot;
	}
	
	
	
	public function ip2dot4port2(){
	    $this->ssTitre(__FUNCTION__);
	    $this->ip2port();
	    $dot = "";
	    $dot_header = "digraph ".__FUNCTION__."{";
 
	    
	  
	   $file_output = "/tmp/$this->ip.".__FUNCTION__.".dot";
	   $dot .= $dot_header;
	   $dot .= "label = \"$this->ip\";
		graph [rankdir = \"TB\" layout = dot];
		node [fontsize = \"16\" shape = \"plaintext\"];
		edge [penwidth=2.0 ];\n	"; 
	   $dot .= $this->ip2dot();

	   var_dump($this->tab_open_ports_all);$this->pause();
	   foreach ($this->tab_open_ports_all as $port){
	       if (!empty($port))  {
	           foreach ($port as $port_num => $protocol){
	               if (!empty($port_num)){
	               $obj_port = new PORT($this->eth,$this->domain,$this->ip,$port_num,$protocol);
	               $dot .= "\"$this->ip:$obj_port->port\" [label=<<TABLE BORDER=\"0\" CELLBORDER=\"1\" CELLSPACING=\"0\" ALIGN=\"LEFT\" >";	               
	               //$dot .= $obj_port->port2dot();
	               $dot .= "</TABLE>>];\n";
	               $dot .= " \"$obj_port->ip\":ip2port -> \"$obj_port->ip:$obj_port->port\":port [color=\"green4\"]; \n ";
	               $this->pause();
	               }
	           }
	       }
	   }
	   $dot_footer = "
}
";

	   $ip2dot4port = $dot.$dot_footer;
	   
	   
	   $this->dot4make($file_output,$ip2dot4port);
	   $this->requette("gedit $file_output");
	   return $dot;
	}
	
	public function ip2dot(){
	    $this->gtitre(__FUNCTION__);
	    
	    $file_output = "$this->dir_tmp/$this->ip.".__FUNCTION__.".dot";
	    $color_ip = "greenyellow";$color_host = "greenyellow";$color_domain = "greenyellow";$color_arrow = "darkgreen";
	    if ($this->ip2malw()==TRUE) {$color_ip = "red";$color_host = "orange";$color_domain = "orange";$color_arrow = "red";}
	    
	    
	    $ip2dot_header = "digraph structs {
	label = \"".__FUNCTION__.":$this->ip\";
	 	graph [rankdir = \"LR\" layout = dot];
	 	node [fontsize = \"16\" shape = \"plaintext\"];
	 	edge [penwidth=2.0 ];";
	    
	    /*
	    <TR><TD>PROTOCOL</TD><TD PORT=\"ip2protocol\" ALIGN=\"LEFT\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->ip2protocol()))."</TD></TR>
		<TR><TD>VIRUSTOTAL</TD><TD PORT=\"ip2vt\" ALIGN=\"LEFT\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->ip2vt()))."</TD></TR>
		<TR><TD>TRACEROUTE</TD><TD PORT=\"ip2tracert\" ALIGN=\"LEFT\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->ip2tracert()))."</TD></TR>
		<TR><TD>IP NEIGHBORDS</TD><TD PORT=\"ip2vhost\" ALIGN=\"LEFT\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->ip2vhost()))."</TD></TR>
		<TR><TD>ISP</TD><TD PORT=\"ip2asn\" ALIGN=\"LEFT\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->ip2asn()))."</TD></TR>
		<TR><TD>NET RANGE</TD><TD PORT=\"ip2range\" ALIGN=\"LEFT\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->ip2range()))."</TD></TR>
		<TR><TD>GEOIP</TD><TD PORT=\"ip2geoip\" ALIGN=\"LEFT\"  > ".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->ip2geoip()))."</TD></TR>
		<TR><TD>FIREWALL</TD><TD PORT=\"ip2fw\" ALIGN=\"LEFT\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->ip2fw()))."</TD></TR>
		<TR><TD>USERS</TD><TD PORT=\"ip2users\" ALIGN=\"LEFT\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->ip2users()))."</TD></TR>
		<TR><TD>OS</TD><TD PORT=\"ip2os\" ALIGN=\"LEFT\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->ip2os()))."</TD></TR>		
	     
	     */

	    
	    $ip2root = $this->ip2root8db($this->ip2id);
	    $ip2shell = $this->ip2shell8db($this->ip2id);
	    $ip2write = $this->ip2write8db($this->ip2id);
	    $ip2read = $this->ip2read8db($this->ip2id);
	    
	    $ip2dot_ip = "\"$this->ip\" [label=<<TABLE BORDER=\"0\" CELLBORDER=\"1\" CELLSPACING=\"0\" ALIGN=\"LEFT\" >";
	    if ( ($ip2root) || ($ip2shell) || ($ip2write) || ($ip2read) ) {
	        $ip2dot_ip .= "<TR><TD PORT=\"ip\"><IMG SRC=\"$this->dir_img/ico/ip.png\" /></TD><TD bgcolor=\"red\" >$this->ip</TD></TR>";	        
	    }
	    else $ip2dot_ip .= "<TR><TD PORT=\"ip\"><IMG SRC=\"$this->dir_img/ico/ip.png\" /></TD><TD bgcolor=\"$color_ip\" >$this->ip</TD></TR>";
	    
	    $ip2dot_ip .= "<TR><TD>HOSTNAME</TD><TD PORT=\"ip2host\" ALIGN=\"LEFT\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->ip2host("")))."</TD></TR>
		<TR><TD>PORTS OPEN</TD><TD PORT=\"ip2port\" ALIGN=\"LEFT\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->ip2port()))."</TD></TR>
		<TR><TD>HONEY</TD><TD PORT=\"ip2honey\" ALIGN=\"LEFT\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->ip2honey()))."</TD></TR>
";
	    if ($ip2root) $ip2dot_ip .= "<TR><TD>ROOT</TD><TD  bgcolor=\"red\" PORT=\"ip2root\" ALIGN=\"LEFT\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$ip2root))."</TD></TR>";
	    if ($ip2shell) $ip2dot_ip .= "<TR><TD>SHELL</TD><TD  bgcolor=\"red\" PORT=\"ip2shell\" ALIGN=\"LEFT\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$ip2shell))."</TD></TR>";
	    if ($ip2write) $ip2dot_ip .= "<TR><TD>WRITE</TD><TD  bgcolor=\"red\" PORT=\"ip2write\" ALIGN=\"LEFT\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$ip2write))."</TD></TR>";
	    if ($ip2read) $ip2dot_ip .= "<TR><TD>READ</TD><TD  bgcolor=\"red\" PORT=\"ip2read\" ALIGN=\"LEFT\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$ip2read))."</TD></TR>";
	    
	    $ip2dot_ip .= "</TABLE>>];\n";
	    
	    
	    $ip2dot_footer = "
						}";
	    
	    $ip2dot = $ip2dot_header.$ip2dot_ip.$ip2dot_footer;
	    $ip2dot4body = $ip2dot_ip;
	    
	    //$this->requette("gedit $file_output");
	    //$this->dot4make($file_output,$ip2dot);
	    
	    return $ip2dot4body;
	}
	
	
	
	

	public function ip2armitage8openvas2msf(){
	    // http://z.cliffe.schreuders.org/edu/DSL/Post-exploitation.pdf
	}
	
	


	

	



	
	
	
	
	
	public function ip2port4service($service){
	    $this->ssTitre("Searching service $service recorded on Database for this IP");
	    $port = "";
	    $service = trim($service);
	    //$this->ip4service();
	    $sql_r = "SELECT port FROM PORT WHERE id8ip = '$this->ip2id' AND id IN (SELECT id8port FROM SERVICE WHERE service2name LIKE \"%$service%\") ";
	    $conn = $this->mysql_ressource->query($sql_r);
	    
	    $row = $conn->fetch_assoc();
	    if (isset($row["port"])) $port = trim($row["port"]);
	    return $port;
	}
	
	
	public function ip2cidr(){
		$this->ssTitre(__FUNCTION__);
		return trim($this->req_ret_str("echo '$this->ip' | grep -Po \"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\" | grep -Po \"^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\" "));
	}
	
	public function ip2cve(){
	    $result = "";
	    //msf5 > search cve:2019 
	    // msf > search cve:2011 author:jduck platform:linux
	    // http://cve.mitre.org/data/downloads/index.html
	    // https://nvd.nist.gov/vuln/categories
	    /*
	 $search = "CVE-2017-7494" ;
$query = "grep -l -i \"$search\" $test->dir_tmp/*.xml ";
$filenames = explode("\n",$test->req_ret_str($query));
	     */
	    $this->ssTitre(__FUNCTION__);
	    // mysql -u rohff --password=hacker -b bot -e "select ip,port,from_base64(service2vuln) FROM PORT where from_base64(service2vuln) LIKE \"%VULNERABLE%\" ;" | grep -v -i "not bulnerable" | grep -A5 -B5 -i "vulnerable" | sed "s/\\\n/\n/g" | more
	    $result .= $this->openvas($this->ip);$this->pause();
	    $result .= $this->ip2cve4nmap();$this->pause();
	    return $result;
	}
	

	
	public function ip2cve4nmap(){
	    $this->ssTitre(__FUNCTION__);
	    // https://null-byte.wonderhowto.com/how-to/easily-detect-cves-with-nmap-scripts-0181925/
	    $filename = "/usr/share/nmap/scripts/vulners.nse";
	    if(!file_exists($filename)) $this->requette("echo '$this->root_passwd' | sudo -S wget https://raw.githubusercontent.com/Vulnerability-scanner/nmap-vulners/master/vulners.nse -O $filename");
	    $query = "echo '$this->root_passwd' | sudo -S nmap -sV --script vulners $this->ip -Pn -n -e $this->eth -oX -";
	    return $this->req2BD(__FUNCTION__,__CLASS__,"$this->ip2where ",$query);
	}
	


	

	


	public function ip2vt(){
	    $result = "";
	    $result .= $this->titre(__FUNCTION__);
	    if ($this->ip4priv($this->ip)) return $result."Private IP";
		$lien_virustotal = "https://www.virustotal.com/fr/ip-address/$this->ip/information/";
		//net($lien_virustotal);
		$this->ssTitre(__FUNCTION__);
		$query = "wget -qO- $lien_virustotal  | grep '$this->ip' | grep -v 'virustotal' | grep '/'| sed \"s/&/&amp;/g\" | sed \"s/</&lt;/g\" | sed \"s/>/&gt;/g\" | grep -v '$this->ip/information/' | grep -v 'IP address information' ";
		return $this->req2BD(__FUNCTION__,__CLASS__,"$this->ip2where ",$query);
	}
	
	
	public function ip2malw4blacklist(){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__);
		if ($this->ip4priv($this->ip)) return $result."Private IP";
		$query = "Automater.py -t $this->ip ";
		$result .= $this->cmd("localhost",$query);
		$result .= $this->req_ret_str($query);
		return $result;
	
	}
	

	
	public function ip2crack($crack_str){
	    $this->titre(__FUNCTION__);
	    $sql_r_1 = "SELECT ".__FUNCTION__." FROM ".__CLASS__." WHERE $this->ip2where  AND ".__FUNCTION__." IS NOT NULL";
	    if ($this->checkBD($sql_r_1) ) return  base64_decode($this->req2BD4out(__FUNCTION__,__CLASS__,"$this->ip2where "));
	    else {
	        $result = base64_encode($crack_str);
	        return base64_decode($this->req2BD4in(__FUNCTION__,__CLASS__,"$this->ip2where ",$result));
	    }
	}
	
	public function ip2crack4check(){
	    $this->titre(__FUNCTION__);
	    $sql_r_1 = "SELECT ip2crack FROM ".__CLASS__." WHERE $this->ip2where  AND ip2crack IS NOT NULL";
	    return $this->checkBD($sql_r_1) ;
	}
	
	public function ip2asn(){
		if ($this->ip4priv($this->ip)) return "Private IP";
		$result = "";
		$sql_r_1 = "SELECT ".__FUNCTION__." FROM ".__CLASS__." WHERE $this->ip2where  AND ".__FUNCTION__." IS NOT NULL";
		if ($this->checkBD($sql_r_1) ) {
		    return  base64_decode($this->req2BD4out(__FUNCTION__,__CLASS__,"$this->ip2where "));
		}
		else {
		    $result .= $this->titre(__FUNCTION__);
		   
		// https://www.tcpiputils.com/browse/ip-address/80.88.14.75
		    $result .= $this->article("BGP Hijacking","Autonomous System Numbers (ASNs) define which IP addresses a router is responsible for.
				If there is an overlap between two ASN ranges, routers will route to the more specific ASN
	• An attacker who either has compromised an ISP or can inject routes (think nation-states) can broadcast malicious routes and reroute
traffic through their network");
		$this->note("In order to defend against these attacks you have to first know what is normal in relation to traffic being routed
to and through your network. We recommend running and recording what normal traceroute information looks
like by using a service like traceroute.org.
Please keep in mind that routes do change. However, if you see traffic making a drastic change (i.e. being
routed halfway around the world) you may want to work with your ISP to investigate.");
		$result .= $this->ip2asn4db();
		$this->pause();
		$result .= $this->ip2asn4nmap();
		$this->pause();
		$result = base64_encode($result);
		return base64_decode($this->req2BD4in(__FUNCTION__,__CLASS__,"$this->ip2where ",$result));
		}
	}
	
	public function ip2asn4db(){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__);
		if ($this->ip4priv($this->ip)) return $result."Private IP";
		$query = "mysql --user=root --password=hacker --database=geoip --execute=\"CALL ip2asn(\\\"$this->ip\\\");\" 2> /dev/null | grep -Po \"AS[0-9]{1,}.*\" ";
		$result .= $this->cmd("localhost",$query);
		$result .= $this->req_ret_str($query);
		return $result;
	}
	
	public function ip2asn4nmap(){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__);
		if ($this->ip4priv($this->ip)) return $result."Private IP";
		$query = "nmap --script asn-query $this->ip -Pn -sn -e $this->eth -oX -  ";
		$result .= $this->cmd("localhost",$query);
		$result .= $this->req_ret_str($query);
		return $result;
	}
	

	public function ip2cidr4range(){
		$this->ssTitre(__FUNCTION__);
		$query = "echo \"`echo '$this->ip' | grep -Po \\\"^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\\\"`.0-255\" ";
		return $this->req_ret_str($query);
	}
	
	
	public function ip2os4arch($result){
	    $this->ssTitre(__FUNCTION__);
	    $sql_r = "SELECT ip2os4arch FROM IP WHERE $this->ip2where AND ip2os4arch IS NOT NULL";
	    
	    if ($this->checkBD($sql_r)) {
	        
	        $result = $this->mysql_ressource->query($sql_r)->fetch_assoc()['ip2os4arch'];
	        return $result;
	        
	    }
	    
	    $OS =  "cisco";
	    if (stristr($result,$OS))
	    {
	        $this->article("OS", $OS);
	        $sql_w = "UPDATE IP set ip2os4arch='$OS' WHERE ip = '$this->ip' ; ";
	        $this->mysql_ressource->query($sql_w);
	        return $OS;
	    }
	    

	    
	    
	    $OS =  "citrix";
	    if (stristr($result,$OS))
	    {
	        $this->article("OS", $OS);
	        $sql_w = "UPDATE IP set ip2os4arch='$OS' WHERE ip = '$this->ip' ; ";
	        $this->mysql_ressource->query($sql_w);
	        return $OS;
	    }

	    
	    $OS =  "oracle";
	    if (stristr($result,$OS))
	    {
	        $this->article("OS", $OS);
	        $sql_w = "UPDATE IP set ip2os4arch='$OS' WHERE ip = '$this->ip' ; ";
	        $this->mysql_ressource->query($sql_w);
	        return $OS;
	    }
	    
	    if (stristr($result, "debian") OR stristr($result, "ubuntu") OR stristr($result, "linux") OR stristr($result, "unix") OR stristr($result, "freebsd") OR stristr($result, "redhat") OR stristr($result, "centos") OR stristr($result, "openbsd")   )
	    {
	        $OS = "linux";
	        $this->article("OS", $OS);
	        $sql_w = "UPDATE IP set ip2os4arch='$OS' WHERE ip = '$this->ip' ; ";
	        $this->mysql_ressource->query($sql_w);
	        return $OS;
	    }

	    if (stristr($result, "freebsd") OR stristr($result, "openbsd")   )
	    {
	        $OS = "openBSD";
	        $this->article("OS", $OS);
	        $sql_w = "UPDATE IP set ip2os4arch='$OS' WHERE ip = '$this->ip' ; ";
	        $this->mysql_ressource->query($sql_w);
	        return $OS;
	    }
	    
	    if (stristr($result, "redhat") OR stristr($result, "centos") )
	    {
	        $OS = "redhat";
	        $this->article("OS", $OS);
	        $sql_w = "UPDATE IP set ip2os4arch='$OS' WHERE ip = '$this->ip' ; ";
	        $this->mysql_ressource->query($sql_w);
	        return $OS;
	    }
	    
	    if (stristr($result, "debian") OR stristr($result, "ubuntu") )
	    {
	        $OS = "debian";
	        $this->article("OS", $OS);
	        $sql_w = "UPDATE IP set ip2os4arch='$OS' WHERE ip = '$this->ip' ; ";
	        $this->mysql_ressource->query($sql_w);
	        return $OS;
	    }

	    $OS =  "linux";
	    if (stristr($result,$OS))
	    {
	        $this->article("OS", $OS);
	        $sql_w = "UPDATE IP set ip2os4arch='$OS' WHERE ip = '$this->ip' ; ";
	        $this->mysql_ressource->query($sql_w);
	        return $OS;
	    }
	    
	    $OS =  "unix";
	    if (stristr($result,$OS))
	    {
	        $this->article("OS", $OS);
	        $sql_w = "UPDATE IP set ip2os4arch='$OS' WHERE ip = '$this->ip' ; ";
	        $this->mysql_ressource->query($sql_w);
	        return $OS;
	    }
	    
	    $OS =  "router";
	    if (stristr($result,$OS))
	    {
	        $this->article("OS", $OS);
	        $sql_w = "UPDATE IP set ip2os4arch='$OS' WHERE ip = '$this->ip' ; ";
	        $this->mysql_ressource->query($sql_w);
	        return $OS;
	    }
	    
	    if (stristr($result, "windows") OR stristr($result, "microsoft") OR stristr($result, "win32")  OR stristr($result, "IIS")  OR stristr($result, "msrpc")   OR stristr($result, "ms-")  OR stristr($result, "win-")  )
	    {
	        $OS = "windows";
	        $this->article("OS", $OS);
	        $sql_w = "UPDATE IP set ip2os4arch='$OS' WHERE ip = '$this->ip' ; ";
	        $this->mysql_ressource->query($sql_w);
	        return $OS;
	    }
	    
	    
	}
	
	
	public function ip2os(){
	    $result = "";
	    $sql_r_1 = "SELECT ".__FUNCTION__." FROM ".__CLASS__." WHERE $this->ip2where  AND ".__FUNCTION__." IS NOT NULL";
	    if ($this->checkBD($sql_r_1) ) return  base64_decode($this->req2BD4out(__FUNCTION__,__CLASS__,"$this->ip2where "));
	    else {
	        $this->titre(__FUNCTION__);
	        $result .= $this->note("Putting all hosts behind a proxy filter will prevent passive OS Fingerprinting.");
	        $result .= $this->note("In which of the following scanning methods do Windows operating systems send only RST packets irrespective of whether the port is open or closed?
				TCP FIN");
		
		//$result .= $this->ip2os2xprobe();
		$result .= $this->ip2os2nmap();
		$this->ip2os4arch($result);
		//$result .= $this->ip2os4win2fin();	
		
		$result = base64_encode($result);
		return base64_decode($this->req2BD4in(__FUNCTION__,__CLASS__,"$this->ip2where ",$result));
	    }
	}
	
	


	public function ip2os4win2fin(){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__);
		$query = "echo '$this->root_passwd' | echo '$this->root_passwd' | sudo -S -S nmap -sF -Pn -n --reason --top-ports 5 $this->ip -e $this->eth  ";
		$result .= $this->cmd("localhost",$query);
		$result .= $this->req_ret_str($query);
		return $result;
	}
	
	public function ip2os2xprobe(){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__);
		$query = "echo '$this->root_passwd' | sudo -S xprobe2 $this->ip  | grep -v 'Xprobe2' ";
		$result .= $this->cmd("localhost",$query);
		$result .= $this->req_ret_str($query);
		return $result;
	}
	
	
	public function ip2os2nmap(){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__);
		$query = "echo '$this->root_passwd' | sudo -S nmap -n --reason -O --osscan-guess $this->ip -F -sSU -Pn -e $this->eth -oX - ";
		$result .= $this->cmd("localhost",$query);
		$result .= $this->req_ret_str($query);
		return $result;
	}

	
	
	public function ip2geoip4country(){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__);
		if ($this->ip4priv($this->ip)) return $result."Private IP";
		$query = "mysql --user=root --password=hacker --database=geoip --execute=\"CALL ip2country(\\\"$this->ip\\\");\" 2> /dev/null  | grep -v lepays ";
		$result .= $this->cmd("localhost",$query);
		$result .= $this->req_ret_str($query);
		return $result;
	}
	

	
		
	public function ip2port(){	 
	    $this->ssTitre(__FUNCTION__);
	    $result = "";
	    $tab_open_ports_tcp = array();
	    $tab_open_ports_udp = array();
	    $this->tab_open_ports_all = array();
	    
	    $sql_r_1 = "SELECT ".__FUNCTION__." FROM ".__CLASS__." WHERE $this->ip2where  AND ".__FUNCTION__." IS NOT NULL";
	    if ($this->checkBD($sql_r_1) ) {
	        
	        $db =  base64_decode($this->req2BD4out(__FUNCTION__,__CLASS__,"$this->ip2where "));
	        $this->article("ip2port B64", base64_encode($db));
	        echo $db ;
	        //$this->pause();	        
	        $xml=simplexml_load_string($db);
	        //$this->pause();
	        $tab_open_ports_tcp = explode(",", $xml->open_ports_tcp);
	        $tab_open_ports_udp = explode(",", $xml->open_ports_udp);
	        $sum_tcp = count($tab_open_ports_tcp)  ;
	        $sum_udp = count($tab_open_ports_udp)  ;

	        for($i=0;$i<$sum_tcp;$i++){
	            if(!empty($tab_open_ports_tcp[$i])){
	                $this->tab_open_ports_tcp[$i] = $tab_open_ports_tcp[$i];
	                $this->tab_open_ports_all[]  = [$tab_open_ports_tcp[$i] => 'T'];
	            }
	        }
	        for($i=0;$i<$sum_udp;$i++){
	            if(!empty($tab_open_ports_udp[$i])){
	                $this->tab_open_ports_udp[$i] = $tab_open_ports_udp[$i];
	                $this->tab_open_ports_all[] = [$tab_open_ports_udp[$i] => 'U'];
	            }
	        }
	        
	        $this->article("TCP ".count($this->tab_open_ports_tcp), implode(",", $this->tab_open_ports_tcp));
	        $this->article("UDP ".count($this->tab_open_ports_udp), implode(",", $this->tab_open_ports_udp));
	        $this->article("ALL ", count($this->tab_open_ports_all));
	        
	        
	        return $db ;
	    }
	    else {
	        $result .= "<?xml version='1.0' encoding='UTF-8'?>\n";
	        $result .= "<".__FUNCTION__.">\n";
	        //$result .= $this->titre(__FUNCTION__);
	        if ($this->ip4priv($this->ip)) {
	            /*
	            $tab_open_ports_tcp = $this->ip2tcp4web();
	            $tab_open_ports_tcp += $this->ip2tcp4select();	            
	            $tab_open_ports_udp += $this->ip2udp4top1000();
	            $tab_open_ports_tcp += $this->ip2tcp4all();

	            */
	            $tab_open_ports_tcp = $this->ip2tcp4select();
	            $tab_open_ports_tcp += $this->ip2tcp4first1000();
	            $tab_open_ports_tcp += $this->ip2tcp4top4000();
	            $tab_open_ports_udp = $this->ip2udp4top200();
	            
	            //if (empty($tab_open_ports_tcp)) $tab_open_ports_tcp += $this->ip2tcp4top2000();
	        }
	        else {
	            //
	            $tab_open_ports_tcp = $this->ip2tcp4select();
	            $tab_open_ports_tcp +=  $this->ip2tcp4web();
	            $tab_open_ports_udp += $this->ip2udp4top200();
	            //if (empty($tab_open_ports_tcp)) $tab_open_ports_tcp += $this->ip2tcp4top2000();
	            	    	            
	        }
	        $rst_tcp = implode(",",$tab_open_ports_tcp);
	        $rst_udp = implode(",",$tab_open_ports_udp);
	        $result .= "<open_ports_tcp>$rst_tcp</open_ports_tcp>\n";
	        $result .= "<open_ports_udp>$rst_udp</open_ports_udp>\n";
	        $result .= "</".__FUNCTION__.">\n";
	       
	        $sum_tcp = count($tab_open_ports_tcp) ;
	        $sum_udp = count($tab_open_ports_udp) ;

	        for($i=0;$i<$sum_tcp;$i++){
	            if(!empty($tab_open_ports_tcp[$i])){
	                $this->tab_open_ports_tcp[$i] = $tab_open_ports_tcp[$i];
	                $this->tab_open_ports_all[]  = [$tab_open_ports_tcp[$i] => 'T'];
	            }
	        }
	        for($i=0;$i<$sum_udp;$i++){
	            if(!empty($tab_open_ports_udp[$i])){
	                $this->tab_open_ports_udp[$i] = $tab_open_ports_udp[$i];
	                $this->tab_open_ports_all[] = [$tab_open_ports_udp[$i] => 'U'];
	            }
	        }
	        
	        $this->article("TCP ".count($this->tab_open_ports_tcp), $rst_tcp);
	        $this->article("UDP ".count($this->tab_open_ports_udp), $rst_udp);
	        $this->article("ALL ",count($this->tab_open_ports_all));
	        
	        //var_dump($this->tab_open_ports_all);
	        echo $result;
		$result = base64_encode($result);
		return base64_decode($this->req2BD4in(__FUNCTION__,__CLASS__,"$this->ip2where ",$result));
	    }
	}
	


	public function ip2tcp4all(){
	    $this->ssTitre(__FUNCTION__);
		$query = "echo '$this->root_passwd' | sudo -S nmap -sS -Pn -n --reason -p 1-65535 --open $this->ip -e $this->eth -oX - ";
		$query = $query." | xmlstarlet sel -t -v /nmaprun/host/ports/port/@portid ";
		return $this->req_ret_tab($query);
	}
	

	
	public function ip2tcp4top4000(){
	    $this->ssTitre(__FUNCTION__);
		$query = "echo '$this->root_passwd' | sudo -S nmap -sS -Pn -n --host-timeout 15m --reason --top-ports 4000 --open $this->ip -e $this->eth -oX - ";
		$query = $query." | xmlstarlet sel -t -v /nmaprun/host/ports/port/@portid ";
		return $this->req_ret_tab($query);
	}
	
	public function ip2tcp4first1000(){
	    $this->ssTitre(__FUNCTION__);
		$query = "echo '$this->root_passwd' | sudo -S nmap -sS -Pn -n --reason -p1-1024 --open $this->ip --min-parallelism 10 -e $this->eth -oX - ";
		$query = $query." | xmlstarlet sel -t -v /nmaprun/host/ports/port/@portid ";
		return $this->req_ret_tab($query);
	} 
	
	public function ip2tcp4select(){  // 615 ports
	    $this->ssTitre(__FUNCTION__);

		$query = "echo '$this->root_passwd' | sudo -S nmap -sS -Pn -n --reason -p \
1,7,9,13,18,19,21-23,25,27,35,37,42,43,49,53,56,57,66,69,75,77,79-81,85,87,88,92,94,97,101,102,105,107-111,113,115,118,119,\
123,129,135,137-139,143,144,156,161,175,179,193,217,220,222,264,280,384,389,402,407,422,443-446,454,455,457,464,465,500,502,\
512-515,524,540,548,554,563,585,587,591,593,617,623,626,631,636,647,655,689,705,771,783,831,873,875,888,902,910,912,921,969,990,\
993,995,998-1000,1024-1043,1067,1080,1090,1098-1103,1128-1129,1158,1194,1199,1211,1220,1221,1234,1241,\
1270,1300,1311,1337,1352,1433-1435,1440,1471,1494,1521,1530,1533,1581-1582,1604,1670,1720,1723,1745,1755,1801,1811,1863,1900,\
1944,2000-2002,2010,2049,2067,2100,2101,2103,2105,2107,2121,2171-2173,2175,2199,2207,2221-2222,2280,2301,2323,2362,2380-2381,2394,\
2401,2525,2533,2598,2638,2701,2702,2725,2869,2809,2905,2906,2947,2967,3000,3001,3037,3050,3057,3128,3200,3217,3268,3269,\
3273,3299,3306,3310,3333,3343,3372,3389,3460,3465,3500,3628,3632,3690,3780,3790,3817,3847,3872,3900,4000-4002,4016,4020,4100,\
4322,4333,4353,4355,4433,4444-4445,5000,5009,5038,5040,5051,5060-5061,5093,5168,5222,5227,5247,5250,5351,5353,5355,5400,5405,\
5432-5433,5466,5498,5520-5521,5554-5555,5560,5580,5631-5632,5666,5722,5800-5803,5814,5900-5903,5920,5984-5986,5999-6002,\
6050,6060,6070,6080,6101,6103,6106,6161,6262,6346,6347,6379,6405,6502-6504,6542,6557,6660-6661,6667,6789,6889,6905,6988,\
6996,7000-7010,7021,7071,7080,7144,7181,7210,7272,7400,7414,7426,7443,7510,7547,7551,7579-7580,7597,7680,7681,7700-7701,\
7777-7778,7787,7800-7801,7878-7879,7890,7902,7980,8000-8001,8008-8009,8014,8020,8023,8028,8030,8050-8051,8080-8082,\
8085-8088,8090-8091,8095,8098,8101,8118,8161,8180,8205,8222,8300,8303,8333,8400,8443-8444,8503,8642,8686,8701,8787,\
8799,8800,8812,8834,8880,8888-8890,8899,8901-8903,8980,8999-9005,9010,9050,9080-9081,9084,9090,9099-9100,9111,9152,\
9160,9200-9201,9256,9300,9389,9390-9391,9443,9495,9500,9711,9788,9809-9815,9855,9875,9910,9991,9999-10001,10008,10021,\
10050-10051,10080,10098-10099,10162,10202-10203,10443,10616,10628,11000-11001,11099,11211,11234,11333,11460,12000,12174,\
12203,12221,12345,12346,12397,12401,13013,13364,13500,13838,14000,14330,15000-15001,15200,16000,16102,16959,17185,17200,\
17300,18881,18980,19300,19810,20000,20010,20031,20034,20101,20111,20171,20222,22222,23472,23791,23943,25000,25025,26000,\
26122,26256,27000,27015,27017,27374,27888,27900,27960,28222,28784,30000,30718,30821,31001,31099,32764,32913,33000,34205,\
34443,37337,37718,37777,38080,38292,40007,41025,41080,41523-41524,42424,44334,44818,45230,46823-46824,47001-47002,48080,\
48899,49152-49159,50000-50004,50013,50050,50500-50504,52302,52869,53413,53770,55553,55555,57399,57772,62078,62514,65301,65535\
 --open $this->ip -e $this->eth -oX -"; // --scan-delay 1
		
		$firewall = $this->ip2fw4enable();
		
		if (!$firewall) $query = $query." --scan-delay 1 | xmlstarlet sel -t -v /nmaprun/host/ports/port/@portid ";
		else $query = $query." | xmlstarlet sel -t -v /nmaprun/host/ports/port/@portid ";
		
		
		$rst = array();
		$rst = $this->req_ret_tab($query);
		return $rst;
	}	
	



	
	public function ip2tcp4web(){
	    $this->ssTitre(__FUNCTION__);
	    $query = "echo '$this->root_passwd' | sudo -S nmap -Pn -n --reason -p http* --open $this->ip -e $this->eth -oX - ";
	    $firewall = $this->ip2fw4enable();	
	    if (!$firewall) $query = $query." --scan-delay 1 | xmlstarlet sel -t -v /nmaprun/host/ports/port/@portid ";
	    else $query = $query." | xmlstarlet sel -t -v /nmaprun/host/ports/port/@portid ";
	    $rst = array();
	    $rst = $this->req_ret_tab($query);
	    return $rst;
	}
	

	public function ip2udp4select(){
	    $this->ssTitre(__FUNCTION__);
		$query = "echo '$this->root_passwd' | sudo -S nmap -sU -Pn -n --reason --open -e $this->eth -p 53,68,69,111,135,137,138,139,161,631,1020,2049,4569,5060,5353,33485,54269 $this->ip -oX - ";
		$firewall = $this->ip2fw4enable();
		if (!$firewall) $query = $query." --scan-delay 1 | xmlstarlet sel -t -v /nmaprun/host/ports/port/@portid ";
		else $query = $query." | xmlstarlet sel -t -v /nmaprun/host/ports/port/@portid ";
		$rst = array();
		$rst = $this->req_ret_tab($query);
		return $rst;
	}

	public function ip2udp4top200(){
	    $this->ssTitre(__FUNCTION__);
		$query = "echo '$this->root_passwd' | sudo -S nmap -sU -Pn -n --reason --top-ports 200 $this->ip --open -e $this->eth -oX -  ";		
		$firewall = $this->ip2fw4enable();		
		if (!$firewall) $query = $query." --scan-delay 1 | xmlstarlet sel -t -v /nmaprun/host/ports/port/@portid ";
		else $query = $query." | xmlstarlet sel -t -v /nmaprun/host/ports/port/@portid ";		
		
		return $this->req_ret_tab($query);
	}
	
	
	public function ip2udp4top1000(){
	    $this->ssTitre(__FUNCTION__);
	    $query = "echo '$this->root_passwd' | sudo -S nmap -sU -Pn -n --reason --top-ports 1000 $this->ip --open -e $this->eth -oX -  ";
	    $query = $query." | xmlstarlet sel -t -v /nmaprun/host/ports/port/@portid ";
	    return $this->req_ret_tab($query);
	}
	

	
	
	public function ip2fw4nmap2fk(){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__);
		$this->article("Defense Firewalk","Disallow ICMP Time Exceeded messages
Explanation : When attempting to defend against Firewalk, the containment phase involves blocking offending source IP addresses. The identification phase
involves the use IDS signatures that detect TTL shenanigans. The preparation phase involves three options: 1) just live with it. 2) disallow ICMP Time Exceeded
messages from leaving your internal network and 3) use a proxy server instead of a packet filter.");
		$query = "echo '$this->root_passwd' | sudo -S nmap --script=\"firewalk\" --traceroute -n --top-ports 5 --reason -Pn $this->ip -e $this->eth -oX -  | xmlstarlet sel -t -v /nmaprun/host/ports/port/state/@state";
		$result .= $this->req_ret_str($query);
		return $result;
	}
	
	public function ip2fw4nmap2fw(){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__);
		$query = "echo '$this->root_passwd' | sudo -S nmap --script=\"firewall-bypass\" -Pn -n --top-ports 5 --reason  $this->ip -e $this->eth -oX -  | xmlstarlet sel -t -v /nmaprun/host/ports/port/state/@state";
		$result .= $this->req_ret_str($query);
		return $result;
	}
	
	
	public function ip2fw4sw(){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__);
		$query = "echo '$this->root_passwd' | sudo -S nmap -sW -Pn -n --reason --top-ports 5 $this->ip -e $this->eth -oX -  | xmlstarlet sel -t -v /nmaprun/host/ports/port/state/@state";
		$result .= $this->cmd("localhost",$query);
		$result .= $this->req_ret_str($query);		
		return $result;
	}
	
	public function ip2fw4ack(){
	    $result = "";
	    $sql_r_1 = "SELECT ".__FUNCTION__." FROM ".__CLASS__." WHERE $this->ip2where  AND ".__FUNCTION__." IS NOT NULL";
	    if ($this->checkBD($sql_r_1) ) {
	        $result = $this->req2BD4out(__FUNCTION__,__CLASS__,"$this->ip2where ");
	        echo $result."\n";
	        if ($result=="filtered") { $chaine = "This Host is Protected By Firewall";$this->note($chaine);}
	        if ($result=="unfiltered") {$chaine = "This Host is not Protected By Firewall";$this->rouge($chaine);}
	        
	        return $result;
	    }
	    else {
		$query = "echo '$this->root_passwd' | sudo -S nmap -sA -Pn -n --reason -p 80 $this->ip -e $this->eth -oX - | xmlstarlet sel -t -v /nmaprun/host/ports/port/state/@state";
        $result = trim($this->req_ret_str($query));
        if ($result=="filtered") { $chaine = "This Host is Protected By Firewall";$this->note($chaine);}
        if ($result=="unfiltered") {$chaine = "This Host is not Protected By Firewall";$this->rouge($chaine);}
        
        return $this->req2BD4in(__FUNCTION__,__CLASS__,"$this->ip2where ",$result);
	    }
	}
	
	public function ip2fw4enable(){
	    $this->ssTitre(__FUNCTION__);
	    if(stristr($this->ip2fw4ack(),"unfiltered")) return TRUE;
	    else return FALSE ;
	}
	
	public function ip2protocol(){
		$query = "echo '$this->root_passwd' | sudo -S nmap -sO -n --reason -F $this->ip -e $this->eth -oX -";
	    return $this->req2BD(__FUNCTION__,__CLASS__,"$this->ip2where ",$query);
	}
	
	public function ip2fw4frag(){
	    $result = "";
	    $this->ssTitre(__FUNCTION__);
		$query = "echo '$this->root_passwd' | sudo -S nmap -f -Pn -n --reason  --top-ports 5 $this->ip -e $this->eth -oX - ";
		$this->req_ret_str($query);		
		return $result;
	}
	
	public function  ip2host($hostname){
	    $result = "";
	    //$this->titre(__FUNCTION__);
	    $hostname = trim($hostname);
	    $sql_r_1 = "SELECT ".__FUNCTION__." FROM ".__CLASS__." WHERE $this->ip2where  AND ".__FUNCTION__." IS NOT NULL";
	    if ($this->checkBD($sql_r_1) ) return $this->req2BD4out(__FUNCTION__,__CLASS__,$this->ip2where);
	    else {
	        if (empty($hostname)) $result = trim($this->tab($this->ip2host4nslookup($this->ip)));
	        else $result = $hostname;
		return $this->req2BD4in(__FUNCTION__,__CLASS__,$this->ip2where,$result);
	    }
	}
	



	

	
	
	
	public function ip2tracert4local(){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__);
		$query = "echo '$this->root_passwd' | sudo -S traceroute $this->ip ";
		$result .= $this->cmd("localhost",$query);
		$result .= $this->req_ret_str($query);
		return $result;
	}


	// #################################### ICMP ECHO ##############################
	public function ip2icmpECHO() {
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__);
		$this->note("ICMP: ECHO 		(Request (Type 08), Reply (Type 00)) " );
		$query = "echo '$this->root_passwd' | sudo -S nmap -PE -n $this->ip -T 2 -e $this->eth -Pn -oX - ";
		$result .= $this->cmd("localhost",$query);
		$result .= $this->req_ret_str($query);
		return $result;
	}
	// ##############################################################################
	
	// ####################################### ICMP TIME ############################
	public function ip2icmpTIME() {
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__);
		$this->note("IDEAL INTO LAN - ICMP: Time Stamp 	(Request (Type 13), Reply (Type 14))" );
		$query = "echo '$this->root_passwd' | sudo -S nmap -PP -n $this->ip -T 2 -e $this->eth -Pn -oX - ";
		$result .= $this->cmd("localhost",$query);
		$result .= $this->req_ret_str($query);
		return $result;
	}
	// ##############################################################################
	
	// ##################################### ICMP INFO #############################
	public function ip2icmpINFO() {
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__); // echo '$this->root_passwd' | sudo -S icmpush -vv  -info
		$this->note("ICMP: Information	(Request (Type 15), Reply (Type 16))" );
		$query = "echo '$this->root_passwd' | sudo -S nmap -PA -n $this->ip -T 2 -e $this->eth -Pn -oX -";
		$result .= $this->cmd("localhost",$query);
		$result .= $this->req_ret_str($query);
		return $result;
	}
	// ##############################################################################
	
	// ###################################### ICMP MASK #############################
	public function ip2icmpMASK() {
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__);
		$this->note("ICMP: Address Mask 	(Request (Type 17), Reply (Type 18))" );
		$query = "echo '$this->root_passwd' | sudo -S nmap -PM -n $this->ip -T 2 -e $this->eth -Pn -oX -";
		$result .= $this->cmd("localhost",$query);
		$result .= $this->req_ret_str($query);
		return $result;
	}
	// #############################################################################
	
	// ######################################IP 2 ICMP  #############################
	public function ip2icmp() {
	    $result = "";
	    $sql_r_1 = "SELECT ".__FUNCTION__." FROM ".__CLASS__." WHERE $this->ip2where  AND ".__FUNCTION__." IS NOT NULL";
	    if ($this->checkBD($sql_r_1) ) return  base64_decode($this->req2BD4out(__FUNCTION__,__CLASS__,"$this->ip2where "));
	    else {
	        $result .= $this->titre(__FUNCTION__);
	    $result = "ECHO: ".$this->ip2icmpECHO();
		$result .= "\nTIME: ".$this->ip2icmpTIME();
		$result .= "\nINFO: ".$this->ip2icmpINFO();
		$result .= "\nMASK: ".$this->ip2icmpMASK();
		
		$this->pause();
		$result = base64_encode($result);
		return base64_decode($this->req2BD4in(__FUNCTION__,__CLASS__,"$this->ip2where ",$result));
	    }
	}
	// #############################################################################
	
	
	

	
	public function ip2geoip(){
	   if ($this->ip4priv($this->ip)) return "Private IP";
	   $sql_r_1 = "SELECT ".__FUNCTION__." FROM ".__CLASS__." WHERE $this->ip2where  AND ".__FUNCTION__." IS NOT NULL";
	   if ($this->checkBD($sql_r_1) ) return  $this->req2BD4out(__FUNCTION__,__CLASS__,"$this->ip2where ");
	   else {
	    $this->titre(__FUNCTION__);
	    $query = "mysql --user=$this->mysql_login --password=$this->mysql_passwd --database=geoip --execute=\"CALL ip2city(\\\"$this->ip\\\");\"  2>/dev/null | grep -v loc ";
		//$result .= $this->cmd("localhost",$query);
	    $result = trim($this->req_ret_str($query));	
		return $this->req2BD4in(__FUNCTION__,__CLASS__,"$this->ip2where ",$result);
	    }
	}
	
	
	public function ip2whois(){
	    $this->titre(__FUNCTION__);
		if ($this->ip4priv($this->ip)) return "Private IP";
		$query = "whois $this->ip | grep -v -i -E \"(^Comment|abuse|^%|^#)\" | egrep -i \"(route|Address|PostalCode|City|StateProv|country)\" | sort -u ";
		return $this->req2BD(__FUNCTION__,__CLASS__,"$this->ip2where ",$query);
	}
	
	
	public function ip2honey(){
	    $this->ssTitre(__FUNCTION__);

	    $this->ip2port();$this->pause();
	    $port_sum = count($this->tab_open_ports_all);
	    $this->article("ALL PORT SUM",$port_sum);
	    if ($port_sum > 50 ) { $this->rouge("HONEYPOT DETECTED"); return true ;}
	    else return false ;
	}
	
	public function ip2port4scan8xml($result_scan_xml){
	    $this->titre(__FUNCTION__);
	    $port = array();
	    $tab_ports = array();
	    if (!empty($result_scan)) {
	        
	        $ports = explode("\n",$result_scan);
	        
	        
	        foreach($ports as $val)
	            if (preg_match('/(?<port>\d+)\/(?<protocol>\w+)([[:space:]]{1,5})open/',$val,$port))
	            {
	                $tab_ports +=  [$port['port'] => strtoupper(substr($port['protocol'], 0,1))];
	            }
	    }
	    return $tab_ports;
	}
	
	public function ip2port4scan($result_scan){
	    $this->titre(__FUNCTION__);
	    $port = array();
	    $tab_ports = array();
	    if (!empty($result_scan)) {
	        
	        $ports = explode("\n",$result_scan);
	        
	        
	        foreach($ports as $val)
	            if (preg_match('/(?<port>\d+)\/(?<protocol>\w+)([[:space:]]{1,5})open/',$val,$port))
	            {
	                $tab_ports +=  [$port['port'] => strtoupper(substr($port['protocol'], 0,1))];
	            }
	    }
	    return $tab_ports;
	}
	
	

	
	
	

	
	public function ip2vuln(){
	    // https://github.com/radenvodka/SVScanner

		$this->titre(__FUNCTION__);
		$result = "";
		$resu = "";
		$this->requette("mysql --user=$this->mysql_login --password=$this->mysql_passwd --database=$this->mysql_database --execute=\"select service2vuln from PORT where service2vuln like '%vulnerable%' AND ip = '$this->ip' ;\"  2>/dev/null   | sed \"s/\\\\\\n/\\n/g\" | grep -i -E \"vulnerable\" -A1 | grep 'IDs' | cut -d':' -f3 ");
		
		$sql_r = "SELECT vuln2cve FROM VULN WHERE ip = '$this->ip' AND vuln2cve IS NOT NULL";
		$sql_r2 = "SELECT vuln2cve FROM VULN WHERE ip = '$this->ip' ";

		
		if (!$this->checkBD($sql_r2)) {
		    $sql_w = "INSERT INTO VULN (ip) VALUES ('$this->ip'); ";
		    $this->mysql_ressource->query($sql_w);
		}
		
		
		if ($this->checkBD($sql_r)) {
			$ip2auth = $this->mysql_ressource->query($sql_r);
			$rows = $ip2auth->fetch_array(MYSQLI_NUM);
			mysqli_free_result($ip2auth);
			foreach ($rows as $row)
				$resu .= "$row\n";
				echo $resu;
		
		}
		else {
   
		$sql_r = "SELECT port,protocol,service2vuln FROM PORT WHERE service2vuln LIKE '%vulnerable%' AND ip = '$this->ip' ;";
		if ($service2vuln = $this->mysql_ressource->query($sql_r)) {
			while ($row = $service2vuln->fetch_assoc()) {
				$query = "echo '".$row['service2vuln']."' | grep -i -E \"vulnerable\" -A1 | grep 'IDs' | cut -d':' -f3 | grep -Po \"(CVE-[0-9]{4}-[0-9]{4}|OSVDB-[0-9]{3-5})\" ";
				exec($query,$cves);
				if (!empty($cves))
				foreach ($cves as $cve){
					$result .= $this->exploitdb($cve)."\n";
					$result .= $this->ip2cve8msf($cve)."\n";
				}
			}
		}
		
		return $this->req2BD4in("vuln2cve","VULN","$this->ip2where ",$result);
		}
	}
	
	public function ip2auth(){
	    $result = "";
	    $this->titre(__FUNCTION__);
	    $sql_r_1 = "SELECT ".__FUNCTION__." FROM ".__CLASS__." WHERE $this->ip2where  AND ".__FUNCTION__." IS NOT NULL";
	    if ($this->checkBD($sql_r_1) ) {
	        return  base64_decode($this->req2BD4out(__FUNCTION__,__CLASS__,"$this->ip2where "));
	    }
	    else {
	        
	        $sql_service = "select DISTINCT service2name,port,protocol from PORT where id8port = '$this->port2id' AND (service2name = 'asterisk' OR service2name LIKE '%ftp%'  OR service2name = 'icq' OR service2name = 'imap' OR service2name = 'imaps' OR service2name = 'ldap2' OR service2name = 'ldap2s' OR service2name = 'ldap3' OR service2name = 'mssql' OR service2name = 'mysql' OR service2name = 'nntp' OR service2name = 'oracle-listener' OR service2name = 'oracle-sid' OR service2name = 'pcanywhere' OR service2name = 'postgres' OR service2name = 'rlogin'  OR service2name LIKE '%rdp%' OR service2name = 'sip' OR service2name = 'ssh' OR service2name LIKE '%smb%' OR service2name LIKE '%samba%' OR service2name = 'snmp' OR service2name = 'smtp' OR service2name = 'smtps' OR service2name = 'vnc' OR service2name = 'xmpp') ORDER BY port  ;";
		    $this->req_ret_str("mysql --user=$this->mysql_login --password=$this->mysql_passwd --database=$this->mysql_database --execute=\"$sql_service\"  2>/dev/null ");
		    
		    $this->titre("AUTH ");
		    $sql_auth = "select DISTINCT port,protocol,user2name,user2pass,user2info from AUTH where id8port = '$this->port2id' ORDER BY port;";
		    $this->req_ret_str("mysql --user=$this->mysql_login --password=$this->mysql_passwd --database=$this->mysql_database --execute=\"$sql_auth\"  2>/dev/null ");

		    if ( ($user2auth = $this->mysql_ressource->query($sql_auth)) && ($service = $this->mysql_ressource->query($sql_service)) ) {
		        while ($auth_row = $user2auth->fetch_assoc()) {
		            while ($service_row = $service->fetch_assoc()) {
		                $this->titre("Attack Authentication By Dictionnary ");
		                $obj_port = new PORT($this->ip, $service_row['port'],$service_row['protocol']);
		                $obj_port->port2auth4pass4hydra($service_row['service2name'], $auth_row['user2name'],$auth_row['user2pass']);
		                $obj_port->port2auth4dico4hydra($service_row['service2name'],$auth_row['user2name']);
		                		            }
		            }
		    }
		    $this->pause();
		    $result = base64_encode($result);
		return $this->req2BD4in(__FUNCTION__,__CLASS__,"$this->ip2where ",$result);
	}
}



	
	public function ip2vhost(){
	    $result = "";
	    $sql_r_1 = "SELECT ".__FUNCTION__." FROM ".__CLASS__." WHERE $this->ip2where  AND ".__FUNCTION__." IS NOT NULL";
	    if ($this->checkBD($sql_r_1) ) return  base64_decode($this->req2BD4out(__FUNCTION__,__CLASS__,"$this->ip2where "));
	    else {
	        $result .= $this->titre(__FUNCTION__);
	       $result .= $this->ip2vhost4nmap();
		//$result .= $this->ip2vhost4web();
		$result .= $this->req_ret_str("echo '$result' | grep -Po \"[a-z0-9_\-]{1,}\.[a-z_\-]{1,}\.[a-z]{1,5}\" | sort -u  ");
		
		$result = base64_encode($result);
		return base64_decode($this->req2BD4in(__FUNCTION__,__CLASS__,"$this->ip2where ",$result));
		}
	}
	
	public function ip2vhost4nmap(){
	    $result = "";
	    $result .= $this->titre(__FUNCTION__);
		if ($this->ip4priv($this->ip)) return $result."Private IP";
		$query = "nmap --script hostmap-ip2hosts -sn -Pn $this->ip -e $this->eth | grep -v -i \"nmap\" | grep -v -i \"csv.php\" | grep  -i -Po \"([0-9a-zA-Z\.\-_]{1,})\.[a-zA-Z]{1,4}\" | sort -u ";
		$result .= $this->cmd("localhost",$query);
		$result .= $this->req_ret_str($query);
		return $result;
	}
	
	public function ip2vhost4web(){
	    $result = "";
	    $result .= $this->titre(__FUNCTION__);
		if ($this->ip4priv($this->ip)) return $result."Private IP";
		$result = $this->ip2vhost4web4online();
		$result .= $this->ip2vhost4web4bfk();
		$result .= $this->ip2vhost4web4sameip();
		$result .= $this->ip2vhost4web4ipadress();
		$result .= $this->ip2vhost4web4youg();
		$result .= $this->ip2vhost4web4dnsdigger();
		return $result;
	}
	
	
	public function ip2vhost4web4bfk(){
	    $result = "";
	    $result .= $this->titre(__FUNCTION__);
		if ($this->ip4priv($this->ip)) return $result."Private IP";
		$query = "wget -qO- \"http://www.bfk.de/bfk_dnslogger.html?query=$this->ip\" | grep '$this->ip'  | grep '  A  ' | grep  -i -Po \"([0-9a-zA-Z\.\-_]{1,})\.[a-zA-Z]{1,4}\"  ";
		$result .= $this->cmd("localhost",$query);
		$result .= $this->req_ret_str($query);
		return $result;
	}
	
	public function ip2vhost4web4sameip(){
	    $result = "";
	    $result .= $this->titre(__FUNCTION__);
		if ($this->ip4priv($this->ip)) return $result."Private IP";
		$query = "wget -qO- \"http://www.sameip.org/$this->ip\" | grep -Po -i \"([0-9a-zA-Z\.\-_]{1,})\.[a-zA-Z]{1,4}\" | grep -v -i -E \"(sameip\.org|interserver\.net|bluehost\.com|mltdcoupon\.com|coupondeer\.com)\" | grep  -i -Po \"([0-9a-zA-Z\.\-_]{1,})\.[a-zA-Z]{1,4}\"   ";
		$result .= $this->cmd("localhost",$query);
		$result .= $this->req_ret_str($query);
		return $result;
	}
	
	public function ip2vhost4web4ipadress(){
	    $result = "";
	    $result .= $this->titre(__FUNCTION__);
		if ($this->ip4priv($this->ip)) return $result."Private IP";
		$query = "wget -qO- \"http://www.ip-adress.com/reverse_ip/$this->ip\" | grep '\[Whois\]' | grep  -i -Po \"([0-9a-zA-Z\.\-_]{1,})\.[a-zA-Z]{1,4}\"  ";
		$result .= $this->cmd("localhost",$query);
		$result .= $this->req_ret_str($query);
		return $result;
	}
	
	public function ip2vhost4web4youg(){
	    $result = "";
	    $result .= $this->titre(__FUNCTION__);
		if ($this->ip4priv($this->ip)) return $result."Private IP";
		$query = "wget -qO- \"http://domains.yougetsignal.com/domains.php\" --post-data \"remoteAddress=$this->ip\" | grep  -i -Po \"([0-9a-zA-Z\.\-_]{1,})\.[a-zA-Z]{1,4}\"  ";
		$result .= $this->cmd("localhost",$query);
		$result .= $this->req_ret_str($query);
		return $result;
	}
	
	
	public function ip2vhost4web4dnsdigger(){
	    $result = "";
	    $result .= $this->titre(__FUNCTION__);
		if ($this->ip4priv($this->ip)) return $result."Private IP";
		$query = "wget --no-proxy --save-cookies $this->dir_tmp/$this->ip.dnsdigger.cookie.wget --keep-session-cookies \"http://www.dnsdigger.com/\" > /dev/null 
		cat $this->dir_tmp/$this->ip.dnsdigger.cookie.wget | grep -Po \"[0-9a-zA-Z]{40}\"  | tee $this->dir_tmp/$this->ip.dnsdigger.cookie.wget.token ;
		wget --no-proxy --load-cookies $this->dir_tmp/$this->ip.dnsdigger.cookie.wget \"http://www.dnsdigger.com/hostcollision.php?host=$this->ip&token=`cat $this->dir_tmp/$this->ip.dnsdigger.cookie.wget.token`\" -O $this->dir_tmp/$this->ip.ip2vhost.dnsdigger ;
		elinks -no-numbering --dump \"file://$this->dir_tmp/$this->ip.ip2vhost.dnsdigger\"  | grep '$this->ip'  | grep  -i -Po \"([0-9a-zA-Z\.\-_]{1,})\.[a-zA-Z]{1,4}\"  ;	";
		$result .= $this->cmd("localhost",$query);
		$result .= $this->req_ret_str($query);
		return $result;
	}
	


	
	public function ip2range(){
	    $result = "";
	    $sql_r_1 = "SELECT ".__FUNCTION__." FROM ".__CLASS__." WHERE $this->ip2where  AND ".__FUNCTION__." IS NOT NULL";
	    if ($this->checkBD($sql_r_1) ) return  base64_decode($this->req2BD4out(__FUNCTION__,__CLASS__,"$this->ip2where "));
	    else {
	        $result .= $this->titre(__FUNCTION__);
	    $result .= "LOCAL:\n".$this->ip2range4local();
		$result .= "\nWHOIS:\n".$this->ip2range4whois();
		$result .= "\nWEB:\n".$this->ip2range4web();
		
		$result = base64_encode($result);
		return base64_decode($this->req2BD4in(__FUNCTION__,__CLASS__,"$this->ip2where ",$result));
		}
		}
	
		public function ip2range4web(){
		    $result = "";
		    $result .= $this->ssTitre(__FUNCTION__);
			if ($this->ip4priv($this->ip)) return $result."Private IP";
			$query = "  ";
			$result .= $this->cmd("localhost",$query);
			$result .= $this->req_ret_str($query);
			return $result;
		}
		
	public function ip2range4whois(){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__);
		if ($this->ip4priv($this->ip)) return $result."Private IP";
		$query = "echo '".$this->ip2whois()."' | egrep -i \"(NetRange|CIDR|Parent|inetnum)\" ";
		$result .= $this->cmd("localhost",$query);
		$result .= $this->req_ret_str($query);
		return $result;
	}
	
	
	public function ip2range4local(){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__);
		if ($this->ip4priv($this->ip)) return $result."Private IP";
		$query = "mysql --user=$this->mysql_login --password=$this->mysql_passwd --database=geoip --execute=\"CALL geoipbloc(\\\"$this->ip\\\");\" 2> /dev/null | tail -1 ";
		$result .= $this->cmd("localhost",$query);
		$result .= $this->req_ret_str($query);
		return $result;
	}
	
	
	public function ip2malw(){
	    // https://kalilinuxtutorials.com/sipi-simple-ip-information-tools/
	    $result = "";
	    $sql_r_1 = "SELECT ".__FUNCTION__." FROM ".__CLASS__." WHERE $this->ip2where  AND ".__FUNCTION__." IS NOT NULL";
	    if ($this->checkBD($sql_r_1) ) return  base64_decode($this->req2BD4out(__FUNCTION__,__CLASS__,"$this->ip2where "));
	    else {
	        $result .= $this->titre(__FUNCTION__);
	        $result = base64_encode($result);
		    return base64_decode($this->req2BD4in(__FUNCTION__,__CLASS__,"$this->ip2where ",$result));
		}
		$file_output = "$this->dir_tmp/$this->ip.".__FUNCTION__;
		// nmap --script dns-blacklist --script-args='dns-blacklist.ip=<ip>'
		if (!$this->ip4priv($this->ip)) {$this->article("IP", "Local");return 0;}
		$this->net("http://www.ipvoid.com/scan/$this->ip/");
		$this->net("https://www.robtex.com/ip/$this->ip.html");
		$this->net("http://www.tcpiputils.com/browse/ip-address/$this->ip");
		$this->net("http://www.infobyip.com/ip-$this->ip.html");
		$this->net("http://www.whatmyip.co/info/whois/$this->ip");
		$this->ip_base64 = base64_encode($this->ip);
		$this->net("https://www.metascan-online.com/en/ipscan/$this->ip_base64"); // ne detecte rien
		$this->net("http://www.abuseipdb.com/check/$this->ip"); // ne detecte rien
		$this->net("http://www.malwareurl.com/listing-urls.php"); // captcha pas utils
		$this->net("http://www.malwaredomainlist.com/mdl.php?search=$this->ip&colsearch=All&quantity=50"); // ne detecte rien
		$this->ip2malw4blacklist();
		$this->pause();
	}

	
	
	public function ip2vhost4web4online(){
	    $result = "";
	    $result .= $this->titre(__FUNCTION__);
		//$this->net("http://whois.webhosting.info/$this->ip");
		//$this->net("http://www.bfk.de/bfk_dnslogger.html?query=$this->ip");
		//$this->net("http://sameip.org/ip/$this->ip");
		//$this->net("http://www.ip-adress.com/reverse_ip/$this->ip");
		//$this->net("http://www.dnsdigger.com/hostcollision.php?host=$this->ip");
		//$this->net("http://www.yougetsignal.com/tools/Web-sites-on-web-server/php/get-web-sites-on-web-server-json-data.php?remoteAddress=$this->ip");
		//$this->net("http://www.websiteneighbors.com/results.php?output=php&ip_host=$this->ip");
		//$this->net("http://www.my-ip-neighbors.com/?domain=$this->ip");
		//$this->pause();
		
	}
	
	public function ip2tracert(){
	    $result = "";
	    $sql_r_1 = "SELECT ".__FUNCTION__." FROM ".__CLASS__." WHERE $this->ip2where  AND ".__FUNCTION__." IS NOT NULL";
	    if ($this->checkBD($sql_r_1) ) return  base64_decode($this->req2BD4out(__FUNCTION__,__CLASS__,"$this->ip2where "));
	    else {
	        $result .= $this->titre(__FUNCTION__);
	    $result .= $this->ip2tracert4local();
		$result .= $this->ip2tracert4online();
		
		$result = base64_encode($result);
		return base64_decode($this->req2BD4in(__FUNCTION__,__CLASS__,"$this->ip2where ",$result));
	    }
	}
	
	
	public function ip2tracert4online(){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__);
		
		// http://www.monitis.com/traceroute/
		// http://ping.eu/traceroute/
		if ($this->ip4priv($this->ip)) return $result."Private IP";
		$query = "wget -qO- \"https://api.hackertarget.com/mtr/?q=$this->ip\"  ";
		$result .= $this->cmd("localhost",$query);
		$result .= $this->req_ret_str($query);
		return $result;
		
	}
	
	
	
	public function ip2maltego(){
	    $result = "";
	    $result .= $this->titre(__FUNCTION__);
		$this->cmd("localhost", "maltego_chlorine_ce");
		$this->pause();
	}
	
	
	public function ip2fw(){
	    $this->titre(__FUNCTION__);
	    $result = "";
	    $sql_r_1 = "SELECT ".__FUNCTION__." FROM ".__CLASS__." WHERE $this->ip2where  AND ".__FUNCTION__." IS NOT NULL";
	    if ($this->checkBD($sql_r_1) ) return  base64_decode($this->req2BD4out(__FUNCTION__,__CLASS__,"$this->ip2where "));
	    else {

	        if (!$this->ip2fw4enable()){
	       $result .= "SW:\n".$this->ip2fw4sw();
		$result .= "\nFRAG:\n".$this->ip2fw4frag();
		$result .= "\nFWLK:\n".$this->ip2fw4nmap2fk();
		$result .= "\nFW:\n".$this->ip2fw4nmap2fw();
		$this->pause();
	        }
	        else $result = $this->ip2fw4ack();
		$result = base64_encode($result);
		return base64_decode($this->req2BD4in(__FUNCTION__,__CLASS__,"$this->ip2where ",$result));
		}
	}
	
	public function ip4service(){
	    $result = "";
	    echo "=============================================================================\n";
	    $this->gtitre(__FUNCTION__);
	    if(!$this->ip2honey()){	    
	        if (!empty($this->tab_open_ports_all)){
	        $max_iter = count($this->tab_open_ports_all);
	        $this->rouge("ITER PORT $max_iter");
	        $gauche_iter = intval($max_iter/2);
	        $droite_iter = intval($max_iter-$gauche_iter);
	        $file_path = "/tmp/$this->eth.$this->domain.$this->ip.".__FUNCTION__;
	        $fp = fopen($file_path, 'w+');
	        
	        foreach ($this->tab_open_ports_all as $port){
	            if (!empty($port))  {
	                
	                foreach ($port as $port_num => $protocol){
                    
                    $data = "$this->eth $this->domain $this->ip $port_num $protocol port4service FALSE";
	                $data = $data."\n";
	                fputs($fp,$data);
	                         }
	                
	                }
	            }
	        
	            fclose($fp);
	            $this->requette("cat $file_path");
	            if ( (1<$max_iter) && (30>$max_iter) && ($this->ip2fw4enable()) ) $this->requette("php parallel.php \"cat  $file_path | awk 'FNR>0 && FNR<=$gauche_iter' | parallel --progress --no-notice -k -j$gauche_iter php pentest.php PORT {} \" \"cat  $file_path | awk 'FNR>$gauche_iter && FNR<=$max_iter' | parallel --progress --no-notice -k -j$droite_iter php pentest.php PORT {} \" 0 ");
	        
	        foreach ($this->tab_open_ports_all as $port){
	            if (!empty($port))  {
	                foreach ($port as $port_num => $protocol)
	                    if (!empty($port_num)) {
	                        $obj_port = new PORT($this->eth,$this->domain,$this->ip,$port_num, $protocol);
	                        $obj_port->poc($this->flag_poc);
	                        list($service_name,$service_version,$service_product,$service_extrainfo) = $obj_port->port2version4run($obj_port->port2version());
	                        $obj_service = new SERVICE($obj_port->eth,$obj_port->domain,$obj_port->ip,$obj_port->port, $obj_port->protocol,$service_name,$service_version,$service_product,$service_extrainfo);
	                        $obj_service->poc($this->flag_poc);
	                        $obj_service->service4info();
	                    }
	            }
	        }

	        }

	    }
	    echo "END IP4SERVICE:$this->ip =============================================================================\n";
	    $this->pause();
	    return $result;
	}

	public function ip4pentest(){ // OK

	    $this->gtitre(__FUNCTION__);
	    $result = "";
	    echo "=============================================================================\n";
	    
	    if(!$this->ip4priv($this->ip)){
	    $this->rouge("Determining DOMAIN RANGE");
	    $this->ip2asn();$this->pause();
	    $this->ip2whois();$this->pause();
	    $this->ip2range();$this->pause();
	    $this->ip2geoip();$this->pause();
	    $this->rouge("Searching what happened In the PAST");$this->pause();
	    $this->ip2vt();$this->pause();
	    $this->ip2malw();$this->pause();
	    $this->ip2vhost();$this->pause();
	    }
	    $this->rouge("Determining IP SERVICES");	    
	    $this->ip2protocol();$this->pause();
	    $this->ip2port();$this->pause();
	    $this->ip2os();$this->pause();
		
	    $this->rouge("Determining Firewall Rules");
	    $this->ip2fw();$this->pause();
	    $this->ip2tracert();$this->pause();
	    //$this->ip2icmp();$this->pause();
	    //$this->ip2cve();$this->pause();
	    
	    $this->rouge("Enumeration");

	    
	    
	    if(!$this->ip2honey()){
	        if (!empty($this->tab_open_ports_all)){
	            $max_iter = count($this->tab_open_ports_all);
	            $this->rouge("ITER PORT $max_iter");
	            $gauche_iter = intval($max_iter/2);
	            $droite_iter = intval($max_iter-$gauche_iter);
	            $file_path = "/tmp/$this->eth.$this->domain.$this->ip.".__FUNCTION__;
	            $fp = fopen($file_path, 'w+');
	            
	                foreach ($this->tab_open_ports_all as $port){
	                    if (!empty($port))  {
	                        
	                        foreach ($port as $port_num => $protocol){
	                            
	                            $data = "$this->eth $this->domain $this->ip $port_num $protocol port4pentest FALSE";
	                            $data = $data."\n";
	                            fputs($fp,$data);
	                        }
	                        
	                    }
	                }
	            
	                fclose($fp);
	            $this->requette("cat $file_path");
	            //if ( (1<$max_iter) && (30>$max_iter) && ($this->ip2fw4enable()) ) $this->requette("php parallel.php \"cat  $file_path | awk 'FNR>0 && FNR<=$gauche_iter' | parallel --progress --no-notice -k -j$gauche_iter php pentest.php PORT {} \" \"cat  $file_path | awk 'FNR>$gauche_iter && FNR<=$max_iter' | parallel --progress --no-notice -k -j$droite_iter php pentest.php PORT {} \" 0 ");
	            
	            foreach ($this->tab_open_ports_all as $port){
	                if (!empty($port))  {
	                    foreach ($port as $port_num => $protocol)
	                        if (!empty($port_num)) {
	                            $obj_port = new PORT($this->eth,$this->domain,$this->ip,$port_num, $protocol);
	                            $obj_port->poc($this->flag_poc);
	                            list($service_name,$service_version,$service_product,$service_extrainfo) = $obj_port->port2version4run($obj_port->port2version());
	                            $obj_service = new SERVICE($obj_port->eth,$obj_port->domain,$obj_port->ip,$obj_port->port, $obj_port->protocol,$service_name,$service_version,$service_product,$service_extrainfo);
	                            $obj_service->poc($obj_port->flag_poc);
	                            $obj_service->service4info();
	                            $obj_service->port4pentest();
	                        }
	                }
	            }
	            
	        }
	        
	    }
	     
		

		

		//$result .=  $this->ip2auth();$this->pause();
		//$result .=  $this->ip2vuln();$this->pause();
        echo $result;
		echo "END IP4PENTEST:$this->ip =============================================================================\n";
		$this->pause();
		return $result;
		
	}
	

	
	
	
	
	public function ip2users4shell(){
	    $this->ssTitre(__FUNCTION__);
	    $tab_ip2users4shell = array("root");
	    $sql_r_2 = "SELECT distinct(user2name) FROM USERS WHERE id8port IN (select id from PORT where id8ip = '$this->ip2id' ) AND ( user2name != '' AND user2methode = 'cat /etc/passwd' AND ( from_base64(user2infos) LIKE \"%/bin/sh%\" OR from_base64(user2infos) LIKE \"%/bin/bash%\") ) ORDER by user2name ASC ";
	    //echo "$sql_r_2\n";
	    $conn = $this->mysql_ressource->query($sql_r_2);
	    while($row = $conn->fetch_assoc()){
	        $user2name = trim($row["user2name"]);
	        $tab_ip2users4shell[] = $user2name ;
	    }
	    $tab_ip2users4shell = array_filter(array_unique($tab_ip2users4shell));
	    return $tab_ip2users4shell;
	}
	
	public function ip2users4passwd(){
	    $this->ssTitre(__FUNCTION__);
	    $tab_ip2users4passwd = array();
	    $sql_r_2 = "SELECT distinct(user2name),user2pass FROM AUTH WHERE id8port IN (select id from PORT where id8ip = '$this->ip2id' ) AND ( user2name != '' AND user2pass != '' )  ";
	    echo "$sql_r_2\n";
	    $conn = $this->mysql_ressource->query($sql_r_2);
	    $j=1;
	    while($row = $conn->fetch_assoc()){	     	        
	        $user2name = trim($row["user2name"]);
	        $user2pass = trim($row["user2pass"]);
	        if(!empty($user2name)){
	        $tab_ip2users4passwd += [ $user2name => $user2pass ];
	        $this->article("$j-UserName/UserPass", "$user2name/$user2pass");
	        $j++;
	        }
	    }
	    $tab_ip2users4passwd = array_filter(array_unique($tab_ip2users4passwd));
	    return $tab_ip2users4passwd;
	}
	
	
	
	public function ip2users(){
	    $this->ssTitre(__FUNCTION__);
	    $tab_ip2users = array();
	    $sql_r_2 = "SELECT distinct(user2name) FROM USERS WHERE id8port IN (select id from PORT where id8ip = '$this->ip2id' ) AND ( user2name != '' ) ORDER by user2name ASC ";
	    $conn = $this->mysql_ressource->query($sql_r_2);
	    while($row = $conn->fetch_assoc()){
	        $user2name = trim($row["user2name"]);
	        $tab_ip2users[] = $user2name ;
	    }
	    return $tab_ip2users;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	

}
?>
