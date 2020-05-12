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
    

	
    public function __construct($stream,string $eth,string $domain,string $ip) {	
        $ip = (string)$ip;
		$ip_addr = trim($ip);
		$this->tab_open_ports_tcp = array();
		$this->tab_open_ports_udp = array();
		$this->tab_open_ports_all = array();
		$this->tab_cve_source = array();

		if (empty($ip)) return $this->log2error("EMPTY IP");
		if ( ($this->isIPv4($ip_addr)) || ($this->isIPv6($ip_addr)) ) {
		    $this->ip = $ip_addr;
		   }
		if ( (!$this->isIPv4($ip_addr)) && (!$this->isIPv6($ip_addr)) ) 
		{
			$ip_tab = $this->host4ip($ip_addr);
			if (!empty($ip_tab)) $ip_tmp = $ip_tab[0];
			else $ip_tmp = "";
			if ( (!empty($ip_tmp)) && ($this->isIPv4($ip_tmp)) || ($this->isIPv6($ip_tmp)) ) {

			    $this->ip = $ip_tmp;
			    
			}
			else {
			    var_dump($ip_tmp);
			    $this->article("IP", $this->ip);
			    $this->log2error("No IP");	
			    exit();
			}
			
			if ( ($this->ip ==="127.0.0.1") && ($this->eth !== "lo") ) {
			    $this->log2error("localhost IP from $this->eth interface");
			    exit();
			}
		    
		}
		
		
		 
		 
		if ($this->ip4priv($this->ip)) {
		    $this->article("Private IP", $this->ip);
		    if (strstr($this->eth, "vmnet"!==FALSE)){
		        $chaine = "Private IP on NO LAN INTERFACE $this->eth";
		        $this->log2error($chaine);
		        exit();
		    }
		  }
		    	
		    	
		
		
		  parent::__construct($stream,$eth,$domain);
		$this->ip2where = "id8domain = $this->domain2id AND ip = '$this->ip'";
		
		$sql_r = "SELECT ip FROM ".__CLASS__." WHERE $this->ip2where ORDER BY ladate DESC LIMIT 1";
		if (!$this->checkBD($sql_r)) {
		$sql_w = "INSERT  INTO ".__CLASS__." (id8domain,ip) VALUES ('$this->domain2id','$this->ip'); ";
		$this->mysql_ressource->query($sql_w);	
		echo $this->note("Working on IP:$this->ip for the first time");
		//$this->watching();
		}

		$sql_r = "SELECT id FROM ".__CLASS__." WHERE $this->ip2where ";
		$this->ip2id = $this->mysql_ressource->query($sql_r)->fetch_assoc()['id'];
		
		
		// ============================================================
		
		if (!$this->ip4priv($this->ip)) {
		    //var_dump($this->flag_poc);
		    if ($this->flag_poc!==FALSE){
		    $ip_wan = $this->ip4net();
		    if (!$this->isIPv4($ip_wan)) {
		        $chaine = "Lost Connexion to the net $this->domain:$this->ip";
		        $this->log2error($chaine);
		        exit();
		    }		    
		    }
		}
		// ============================================================
		
    
	}
	

	
	
	
	public function  ip4dns($ip){
	    $this->ssTitre(__FUNCTION__);
	    $query = "nslookup -query=ptr $ip 2> /dev/null | grep 'name' | cut -d'=' -f2 | sed \"s/\.$//g\" | tr -d ' ' | grep  -i -Po \"([0-9a-zA-Z_-]{1,}\.)+[a-zA-Z]{1,4}\" ";
	    return $this->req_ret_str($query);
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
	                    $obj_port = new PORT($this->stream,$this->eth,$this->domain,$this->ip,$port_num,$protocol);
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
	                   $obj_port = new PORT($this->stream,$this->eth,$this->domain,$this->ip,$port_num,$protocol);
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
	    
	    $file_output = "/tmp/$this->ip.".__FUNCTION__.".dot";
	    $color_ip = "greenyellow";$color_host = "greenyellow";$color_domain = "greenyellow";$color_arrow = "darkgreen";
	    if ($this->ip2malw()==TRUE) {$color_ip = "greenyellow";$color_host = "orange";$color_domain = "orange";$color_arrow = "red";}
	    
	    
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
		<TR><TD>FIREWALL</TD><TD PORT=\"ip2fw\" ALIGN=\"LEFT\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->ip2fw()))."</TD></TR>
		<TR><TD>USERS</TD><TD PORT=\"ip2users\" ALIGN=\"LEFT\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->ip2users()))."</TD></TR>
		<TR><TD>OS</TD><TD PORT=\"ip2os\" ALIGN=\"LEFT\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->ip2os()))."</TD></TR>		
	     
	     */

	    
	    $ip2root = $this->ip2root8db($this->ip2id);

	    
	    $ip2dot_ip = "\"$this->ip\" [label=<<TABLE BORDER=\"0\" CELLBORDER=\"1\" CELLSPACING=\"0\" ALIGN=\"LEFT\" >";
	    if ( ($ip2root) ) {
	        $ip2dot_ip .= "<TR><TD PORT=\"ip\"><IMG SRC=\"$this->dir_img/ico/ip.png\" /></TD><TD bgcolor=\"red\" >$this->ip</TD></TR>";	        
	    }
	    else $ip2dot_ip .= "<TR><TD PORT=\"ip\"><IMG SRC=\"$this->dir_img/ico/ip.png\" /></TD><TD bgcolor=\"$color_ip\" >$this->ip</TD></TR>";
	    
	    $ip2dot_ip .= "<TR><TD>HOSTNAME</TD><TD PORT=\"ip2host\" ALIGN=\"LEFT\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->ip2host("")))."</TD></TR>
		<TR><TD>PORTS OPEN</TD><TD PORT=\"ip2port\" ALIGN=\"LEFT\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->ip2port()))."</TD></TR>
		<TR><TD>HONEY</TD><TD PORT=\"ip2honey\" ALIGN=\"LEFT\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->ip2honey()))."</TD></TR>
";
	    if ($ip2root) $ip2dot_ip .= "<TR><TD>ROOT</TD><TD  bgcolor=\"red\" PORT=\"ip2root\" ALIGN=\"LEFT\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$ip2root))."</TD></TR>";
	    
	    $ip2dot_ip .= "</TABLE>>];\n";
	    
	    
	    $ip2dot_footer = "
						}";
	    
	    $ip2dot = $ip2dot_header.$ip2dot_ip.$ip2dot_footer;
	    $ip2dot4body = $ip2dot_ip;
	    
	    if ($this->flag_poc) {
	        //$this->requette("gedit $file_output");
	        $this->dot4make($file_output,$ip2dot);
	    }
	    
	    
	    return $ip2dot4body;
	}
	
	
	
	

	public function ip2armitage8openvas2msf(){
	    // http://z.cliffe.schreuders.org/edu/DSL/Post-exploitation.pdf
	}
	
	


	

	



	
	
	
	
	
	public function ip2ports4service(string $service){
	    $this->ssTitre("Searching service $service recorded on Database for this IP");
	    $this->ip4service();
	    $ports = array();

	    $service = trim($service);
	    //$this->ip4service();
	    $sql_r = "SELECT port FROM PORT WHERE id8ip = '$this->ip2id' AND id IN (SELECT id8port FROM SERVICE WHERE service2name LIKE \"%$service%\") ";
	    $conn = $this->mysql_ressource->query($sql_r);
	    echo "$sql_r\n";
	    while ($row = $conn->fetch_assoc()) {
	        $ports[] = trim($row["port"]);
	    }

	    
	    return $ports;
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
	    $result .= $this->ip2cve4openvas($this->ip);$this->pause();
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
	

	
	
	
	
	
	public function ip2domain($ip){
	    $ip = trim($ip);
	    if (empty($ip)) $this->log2error("Empty IP");
	    
	    $tab_hosts = $this->ip2host4nslookup($ip);
	    if(!empty($tab_hosts)){
	        foreach ($tab_hosts as $host){
	            if (!empty($host)){
	                return $this->host2domain($host);
	            }
	        }
	    }
	}
	
	
	public function  ip2host4nslookup($ip){
	    $this->ssTitre(__FUNCTION__);
	    $query = "nslookup -query=ptr $ip 2> /dev/null | grep 'name' | cut -d'=' -f2 | sed \"s/\.$//g\" | tr -d ' ' | grep  -i -Po \"([0-9a-zA-Z_-]{1,}\.)+[a-zA-Z]{1,4}\" ";
	    return $this->req_ret_tab($query);
	}
	
	
	
	public function ip2port8php(string $ip,array $tab_port2scan,string $protocol) : array
	{
	    $tab_port2open = array();
	    $protocol = trim($protocol);
	    if (!empty($tab_port2scan)){
	        foreach ($tab_port2scan as $port2scan){
	            if (!empty($port2scan)){
	                $port2scan = intval($port2scan);
	                $this->article("Test Protocol:Port Number", "$protocol:$port2scan");
	                if ($protocol==='T'){
	                    if ($this->isPortOpen4tcp($ip, $port2scan)) {
	                        $this->rouge("Valid Protocol:Port Number $protocol:$port2scan");
	                        $tab_port2open[] = $port2scan;
	                    }
	                }
	                if ($protocol==='U'){
	                    if ($this->isPortOpen4udp($ip, $port2scan)) {
	                        $this->rouge("Valid Protocol:Port Number $protocol:$port2scan");
	                        $tab_port2open[] = $port2scan;
	                    }
	                }
	            }
	        }
	    }
	    return $tab_port2open;
	}
	
	
	
	
	public function isPortOpen4udp(string $host, int $port) : bool
	{
	    $socket = stream_socket_client("udp://$host:$port", $errno, $errstr,5);
	    if (!$socket) return FALSE ;
	    else return TRUE;
	}
	
	public function isPortOpen4tcp(string $host, int $port) : bool
	{
	    $socket = @stream_socket_client("tcp://$host:$port", $errno, $errstr,1);
	    if (!$socket) return FALSE ;
	    else return TRUE;
	}
	
	
	public function ip4cidr2port($ip,$port,$protocol){
	    $this->ssTitre(__FUNCTION__);
	    $cidr = trim($this->ip4cidr($ip)).".0/24";
	    return $this->req_ret_tab("echo '$this->root_passwd' | sudo -S nmap -s$protocol -T 3 -Pn -v -n -p $port --open $cidr | grep '$port/' | grep -Po \"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\" ");
	}
	
	public function ip4cidr($ip){
	    $this->ssTitre(__FUNCTION__);
	    $cidr = $this->req_ret_str("echo '$ip' | grep -Po \"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\" | grep -Po \"^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\" ");
	    return $cidr;
	}
	
	
	public function ip4local(){
	    $this->ssTitre(__FUNCTION__);
	    // ifconfig | grep -Po "inet (adr:)?([0-9]*\.){3}[0-9]*" | grep -Po "([0-9]*\.){3}[0-9]*" | grep -v '127.0.0.1' | grep '$filter_cidr'
	    $query = "hostname --all-ip-addresses";
	    return $this->req_ret_str($query);
	}
	
	public function ip4addr4target($target_ip){
	    $target_ip = trim($target_ip);
	    if($this->isIPv4($target_ip)){
	        $query = "ip -o route get to $target_ip 2> /dev/null | grep -Po \"src [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\" | grep -Po \"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\"";
	        return trim(exec($query));
	    }
	    else $this->log2error("$target_ip IS NOT IPv4");
	}
	
	public function ip4eth4target($target_ip){
	    $target_ip = trim($target_ip);
	    if($this->isIPv4($target_ip)){
	        $query = "ip -o route get to $target_ip 2> /dev/null | grep -Po \"dev [[:print:]]{1,} src\" | sed \"s/dev//g\"  | sed \"s/src//g\" ";
	        exec($query,$tmp);
	        return trim($tmp[0]);
	    }
	    else $this->log2error("$target_ip IS NOT IPv4");
	}
	
	
	
	public function ip4net(){
	    $this->ssTitre(__FUNCTION__);
	    $ip = "";
	    $tmp = array();
	    $filter = "| grep -Po \"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\"";
	    //$url = "http://ifconfig.me/ip";
	    $url = "http://www.pentesting.eu/ip.php";
	    $query = "curl -s '$url' $filter 2> /dev/null";
	    //$this->requette($query);
	    $ip = exec($query,$tmp);
	    if (isset($tmp[0])) {$ip = $tmp[0];}
	    return $ip;
	    
	}
	
	
	
	public function  ip8host($host){
	    $this->ssTitre(__FUNCTION__);
	    $host = trim($host);
	    $query = "dig $host a +short 2> /dev/null | grep -Po \"^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\" | sort -u";
	    return $this->req_ret_tab($query);
	}
	
	public function ip2cve4openvas(){
	    // ADD certificat lsl credentials
	    
	    // watch -n60 "omp -u rohff -w hacker --get-tasks | grep -E '(Running|New)'"
	    
	    // https://github.com/archerysec/archerysec#openvas-setting
	    // https://github.com/OpenSCAP/openscap
	    // https://github.com/vulnersCom/nmap-vulners
	    
	    // watch -n 5 "omp -u rohff -w hacker --get-tasks  | grep -v 'Done' "
	    // omp --get-report-formats
	    // https://docs.greenbone.net/API/OMP/omp-7.0.html
	    
	    // https://docs.greenbone.net/API/OMP/omp-7.0.html#command_create_alert
	    
	    /*
	     https://docs.greenbone.net/API/OMP/omp-7.0.html#command_empty_trashcan
	     https://docs.greenbone.net/API/OMP/omp-7.0.html#command_get_alerts
	     https://docs.greenbone.net/API/OMP/omp-7.0.html#command_get_credentials
	    
	     for i in $(omp -u rohff -w hacker --get-tasks | cut -d ' ' -f1);do echo "delete $i "; omp -u rohff -w hacker --delete-task $i ;done
	     omp -u rohff -w hacker -iX "<empty_trashcan/>"
	     omp -u rohff -w hacker -iX "<delete_target target_id='6c40d599-38d2-4bab-9804-1300b9b75155' />"
	     for i in $(omp -u rohff -w hacker --get-targets | cut -d ' ' -f1);do echo "delete $i "; omp -u rohff -w hacker -iX "<delete_target target_id='$i' />"  ;done
	     */
	    
	    
	    $result = "";
	    
	    $port_list_uuid = $this->ip2cve4openvas2port_list_uuid();
	    
	    $result .= $this->article("PORT LIST", $port_list_uuid);
	    $this->pause();
	    
	    
	    
	    $creds_snmp_uuid = "";
	    
	    
	    $sql_r_2 = "SELECT user2name,user2pass FROM AUTH WHERE id8port IN (select id from PORT where id8ip = '$this->ip2id' AND (port = 22 OR service2name LIKE \"%ssh%\")) AND ( user2name != '' AND user2pass != '' ) ORDER by user2gid ASC,user2uid ASC ";
	    echo "$sql_r_2 \n"; $this->pause();
	    $conn = $this->mysql_ressource->query($sql_r_2);
	    while($row = $conn->fetch_assoc()){
	        $user2name = trim($row["user2name"]);
	        $user2pass = trim($row["user2pass"]);
	        $ports_ssh = $this->ip2ports4service("ssh");
	        $creds_ssh_uuid = $this->ip2cve4openvas2creds4ssh_uuid($user2name,$user2pass);
	        //var_dump($this->ip2cve4openvas2creds4ssh_uuid());  $this->pause();
	        $result .= $this->article("SSH UUID", $creds_ssh_uuid);
	        $result .= $this->article("SSH PORT", $port_ssh);
	        $result .= $this->ip2cve4openvas2exec($port_list_uuid,$creds_ssh_uuid, $port_ssh, "","", $creds_snmp_uuid);
	        $this->pause();
	    }
	    
	    
	    
	    $sql_r_1 = "SELECT user2name,user2pass FROM AUTH WHERE id8ip IN (select id from PORT where id8ip = '$this->ip2id' AND (port = 445 OR port = 137 OR service2name LIKE \"%smb%\" OR service2name LIKE \"%samba%\")) AND ( user2name != '' AND user2pass != '' ) ORDER by user2gid ASC,user2uid ASC";
	    //echo "$sql_r_2\n";
	    $conn1 = $this->mysql_ressource->query($sql_r_1);
	    while($row = $conn1->fetch_assoc()){
	        $port = trim($row["port"]);
	        $protocol = trim($row["protocol"]);
	        $user2name = trim($row["user2name"]);
	        $user2pass = trim($row["user2pass"]);
	        list($creds_smb_port,$creds_smb_uuid) = explode(',',$this->ip2cve4openvas2creds4smb_uuid($ip,$port, $protocol, $user2name, $user2pass));
	        $result .= $this->article("SMB UUID", $creds_smb_uuid);
	        $result .= $this->article("SMB PORT", $creds_smb_port);
	        $result .= $this->ip2cve4openvas2exec($port_list_uuid,"", "", $creds_smb_uuid,$creds_smb_port, $creds_snmp_uuid);
	        
	        $this->pause();
	    }
	    
	    
	    
	    $creds_snmp_uuid = $this->ip2cve4openvas2creds4snmp_uuid();
	    $this->article("SNMP UUID", $creds_snmp_uuid);
	    $this->pause();
	    
	    
	    
	    /*
	     *
	     load openvas
	     //  you need to use the port for the OpenVAS manager server, openvasmd, which defaults to 9390.
	     openvas_connect $this->openvas_login $this->openvas_passwd 127.0.0.1 9390
	     [+] OpenVAS connection successful
	     
	     
	     $query = "echo -e \"db_status\nload nexpose\ndb_import $this->dir_tmp/rsm_nexpose.xml\ndb_hosts -c address,svcs,vulns\ndb_autopwn -p -x -e -t -r\n\" > $this->dir_tmp/rsm_nexpose.rc; cat $this->dir_tmp/rsm_nexpose.rc";
	     $this->requette($query);
	     */
	    
	    return $result ;
	}
	
	
	public function ip2cve4openvas2exec($port_list_uuid,$creds_ssh_uuid, $creds_ssh_port, $creds_smb_uuid,$creds_smb_port, $creds_snmp_uuid){
	    $result = "";
	    $target_name = "$this->ip:ssh_uuid:$creds_ssh_uuid:smb_uuid:$creds_smb_uuid:snmp_uuid:$creds_snmp_uuid";
	    $report_uuid = trim($this->req_ret_str("grep -l '$target_name' $this->dir_tmp/*.xml | grep -Po \"[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}\" "));
	    if(!empty($report_uuid)){
	        $result .= $this->article("Report UUID", $report_uuid);
	        $check_done = $this->req_ret_str("cat $this->dir_tmp/$report_uuid"."_faraday_openvas.xml  | grep -v '<?xml version=' ");
	        $target_uuid = trim($this->req_ret_str("cat $this->dir_tmp/$report_uuid"."_faraday_openvas.xml | xmlstarlet sel -t -v '/report/report/task/target/@id' "));
	        $result .= $this->article("Target UUID", $target_uuid);
	        $task_uuid = trim($this->req_ret_str("cat $this->dir_tmp/$report_uuid"."_faraday_openvas.xml | xmlstarlet sel -t -v '/report/report/task/@id' "));
	        $result .= $this->article("Task UUID", $task_uuid);
	        
	        $report_uuid_result_xml = $this->ip2cve4openvas2report2get($report_uuid);
	        $result .= $report_uuid_result_xml ;
	        
	        $this->ip2cve4openvas2report2result($report_uuid_result_xml);
	        $this->pause();
	        if(!empty($check_done)){
	            $this->log2succes("ALL DONE");
	            $this->pause();
	            
	            //$this->requette("omp -u rohff -w hacker --delete-task $task_uuid ");
	            //$this->requette("omp -u rohff -w hacker -iX \"<delete_target target_id='$target_uuid' />\" ");
	            $this->pause();
	        }
	    }
	    else {
	        $target_uuid = $this->ip2cve4openvas2target2uuid($target_name,$port_list_uuid,$creds_ssh_uuid,$creds_ssh_port,$creds_smb_uuid,$creds_smb_port,$creds_snmp_uuid);
	        $result .= $this->article("Target UUID", $target_uuid);
	        $this->pause();
	        
	        $this->note("config ID "); $this->cmd("localhost","omp -u $this->openvas_login -w $this->openvas_passwd -g");
	        
	        $task_uuid = $this->ip2cve4openvas2task2uuid($target_name,$target_uuid);
	        $result .= $this->article("Task UUID", $task_uuid);
	        $this->pause();
	        
	        $report_uuid = $this->ip2cve4openvas2report2uuid($target_name, $task_uuid);
	        $result .= $this->article("Report UUID", $report_uuid);
	        $this->pause();
	        
	        
	        $report_uuid_result_xml = $this->ip2cve4openvas2report2get($report_uuid);
	        $result .= $report_uuid_result_xml ;
	        
	        $this->ip2cve4openvas2report2result($report_uuid_result_xml);
	        
	        $this->ip2cve4openvas2report2faraday($report_uuid);
	        $this->pause();
	    }
	    return $result;
	}
	
	
	public function ip2cve4openvas2creds4ssh_uuid($user2name,$user2pass){
	    $this->ssTitre(__FUNCTION__);
	    
	    $creds_ssh_uuid = "";
	    
	    
	    if (!empty($user2name) && !empty($user2pass)) {
	        $this->ssTitre("Credentials SSH");
	        $query = "omp -u $this->openvas_login -w $this->openvas_passwd -X \"<create_credential><name>$this->ip $user2name:$user2pass</name><login>$user2name</login><password>$user2pass</password><comment></comment></create_credential>\" | xmlstarlet sel -t -v /create_credential_response/@id";
	        $this->cmd("localhost",$query);
	        
	        
	        while (TRUE)   {
	            if (!empty($creds_ssh_uuid = $this->ip2cve4openvas2credentials4check($user2name,$user2pass))) break;
	            if (!empty($creds_ssh_uuid = trim($this->req_ret_str($query))) ) break;
	            sleep(2);
	        }
	        
	    }
	    
	    return "$creds_ssh_uuid" ;
	}
	
	
	public function ip2cve4openvas2creds4snmp_uuid(){
	    $this->ssTitre(__FUNCTION__);
	    $creds_snmp_uuid = "";
	    $sql_r_2 = "SELECT user2name,user2pass FROM AUTH WHERE id8port='$this->' AND (port = 161 OR user2info LIKE \"%snmp%\") AND ( user2name != '' AND user2pass != '' ) ORDER by user2gid ASC,user2uid ASC LIMIT 1 ";
	    $conn = $this->mysql_ressource->query($sql_r_2);
	    while($row = $conn->fetch_assoc()){
	        $port = trim($row["port"]);
	        $protocol = trim($row["protocol"]);
	        $user2name = trim($row["user2name"]);
	        $user2pass = trim($row["user2pass"]);
	        
	        if (!empty($user2name) && !empty($user2pass)) {
	            $this->ssTitre("Credentials SNMP");
	            $query = "omp -u $this->openvas_login -w $this->openvas_passwd -X \"<create_credential><name>$this->ip $port $protocol $user2name:$user2pass</name><login>$user2name</login><password>$user2pass</password><comment></comment></create_credential>\" | xmlstarlet sel -t -v /create_credential_response/@id";
	            $this->cmd("localhost",$query);
	            
	            
	            while ( TRUE )   {
	                if (!empty($creds_snmp_uuid = $this->ip2cve4openvas2credentials4check($ip,$port,$protocol,$user2name,$user2pass))) break;
	                if (!empty($creds_snmp_uuid = trim($this->req_ret_str($query)))) break;
	                sleep(2);
	            }
	        }
	    }
	    return $creds_snmp_uuid;
	}
	
	
	public function ip2cve4openvas2creds4smb_uuid($ip,$port,$protocol,$user2name,$user2pass){
	    $this->ssTitre(__FUNCTION__);
	    if (!empty($user2name) && !empty($user2pass)) {
	        $this->ssTitre("Create Credentials SMB");
	        $query = "omp -u $this->openvas_login -w $this->openvas_passwd -X \"<create_credential><name>$this->ip $port $protocol $user2name:$user2pass</name><login>$user2name</login><password>$user2pass</password><comment></comment></create_credential>\" | xmlstarlet sel -t -v /create_credential_response/@id";
	        $this->cmd("localhost",$query);
	        
	        
	        while ( TRUE )   {
	            if (!empty($creds_smb_uuid = $this->ip2cve4openvas2credentials4check($this->ip,$port,$protocol,$user2name,$user2pass))) break;
	            if (!empty($creds_smb_uuid = trim($this->req_ret_str($query)))) break;
	            sleep(2);
	        }
	        
	    }
	    
	    
	    return "$port,$creds_smb_uuid";
	}
	
	public function ip2cve4openvas2port_list_uuid(){
	    $this->ssTitre("PORT LIST");
	    $port_list_uuid = "";
	    
	    
	    $result_scan = $this->ip2port();
	    if (!empty($result_scan)) {
	        
	        
	        
	        $query = "omp -u $this->openvas_login -w $this->openvas_passwd -X \"<create_port_list><name>Open Port List $this->ip</name><comment>Open Ports</comment><port_range>T:".implode(",",$this->tab_open_ports_tcp)." U:".implode(",",$this->tab_open_ports_udp)."</port_range></create_port_list>\" | xmlstarlet sel -t -v /create_port_list_response/@id";
	        $this->cmd("localhost",$query);
	        
	        if( (empty($this->tab_open_ports_tcp)) AND (empty($this->tab_open_ports_udp)) ) return $this->log2error("No PORT open found ");
	        while ( TRUE )   {
	            if (!empty($port_list_uuid = $this->ip2cve4openvas2port_list2check())) break;
	            if (!empty($port_list_uuid = trim($this->req_ret_str($query))) ) break;
	            sleep(2);
	            
	        }
	        
	    }
	    return $port_list_uuid;
	}
	
	
	public function ip2cve4openvas2target2uuid($target_name,$port_list_uuid,$creds_ssh_uuid,$creds_ssh_port,$creds_smb_uuid,$creds_smb_port,$creds_snmp_uuid){
	    $this->ssTitre(__FUNCTION__);
	    
	    $query = "omp -u $this->openvas_login -w $this->openvas_passwd -X \"<create_target><name>$target_name</name><hosts>$this->ip</hosts>";
	    
	    if(!empty($creds_ssh_uuid)) $query .= "<ssh_credential id='$creds_ssh_uuid' ><port>$creds_ssh_port</port></ssh_credential>";
	    if(!empty($creds_smb_uuid)) $query .= "<smb_credential id='$creds_smb_uuid' ></smb_credential>";
	    if(!empty($creds_snmp_uuid)) $query .= "<snmp_credential id='$creds_snmp_uuid'></snmp_credential>";
	    $query .= "<port_list id='$port_list_uuid' ></port_list>";
	    $query .= "</create_target>\" | xmlstarlet sel -t -v /create_target_response/@id";
	    $this->cmd("localhost",$query);
	    
	    while ( TRUE )   {
	        if (!empty($target_uuid = $this->ip2cve4openvas2target4check($target_name))) break;
	        if (!empty($target_uuid = trim($this->req_ret_str($query)))) break;
	        sleep(2);
	    }
	    return $target_uuid ;
	}
	
	public function ip2cve4openvas2task2uuid($target_name,$target_uuid){
	    $this->ssTitre(__FUNCTION__);
	    $query = "omp -u $this->openvas_login -w $this->openvas_passwd -X \"<create_task><name>Scan $target_name</name><preferences><preference><scanner_name>source_iface</scanner_name><value>".$this->ip4eth4target($this->ip)."</value></preference></preferences><config id='74db13d6-7489-11df-91b9-002264764cea' /><target id='$target_uuid' /></create_task>\" | xmlstarlet sel -t -v /create_task_response/@id";
	    $this->cmd("localhost",$query);
	    
	    while ( TRUE )   {
	        if (!empty($task_uuid = $this->ip2cve4openvas2task4check($target_name))) break;
	        if (!empty($task_uuid = trim($this->req_ret_str($query)))) break;
	        sleep(2);
	    }
	    return $task_uuid;
	}
	
	
	public function ip2cve4openvas2credentials4check($user2name,$user2pass){
	    // -iX \"<get_credentials/>\"
	    return trim($this->req_ret_str("omp -u $this->openvas_login -w $this->openvas_passwd -iX '<get_credentials/>' | grep '$this->ip $user2name:$user2pass' -B4 -A18 |  xmlstarlet sel -t -v /credential/@id 2> /dev/null "));
	}
	
	public function ip2cve4openvas2target4check($target_name){
	    return trim($this->req_ret_str("omp -u $this->openvas_login -w $this->openvas_passwd --get-targets | grep '$target_name'  | cut -d' ' -f1  | tail -1 "));
	}
	
	public function ip2cve4openvas2task4check($target_name){
	    return trim($this->req_ret_str("omp -u $this->openvas_login -w $this->openvas_passwd --get-tasks | grep '$target_name'  | cut -d' ' -f1  | tail -1"));
	}
	
	public function ip2cve4openvas2task4check4run4new($target_name){
	    return trim($this->req_ret_str("omp -u $this->openvas_login -w $this->openvas_passwd --get-tasks | grep '$target_name'  | grep 'New' | cut -d' ' -f1 | tail -1"));
	}
	
	public function ip2cve4openvas2task4check4run($target_name){
	    return trim($this->req_ret_str("omp -u $this->openvas_login -w $this->openvas_passwd --get-tasks | grep '$target_name'  | tail -1 "));
	}
	
	public function ip2cve4openvas2task4check4run2done($target_name){
	    return trim($this->req_ret_str("omp -u $this->openvas_login -w $this->openvas_passwd --get-tasks | grep '$target_name'  | grep  'Done' | cut -d' ' -f1  | tail -1"));
	}
	
	public function ip2cve4openvas2port_list2check(){
	    return trim($this->req_ret_str("omp -u $this->openvas_login -w $this->openvas_passwd -iX '<get_port_lists/>' | grep '<name>Open Port List $this->ip</name>' -B4 -A19 |  xmlstarlet sel -t -v /port_list/@id 2> /dev/null "));
	}
	
	public function ip2cve4openvas2report2uuid($target_name,$task_uuid){
	    $this->ssTitre(__FUNCTION__);
	    $query = "omp -u $this->openvas_login -w $this->openvas_passwd -iX  \"<start_task task_id='$task_uuid' />\"  | grep -Po \"<report_id>[0-9a-z_-]{1,40}</report_id>\" | cut -d'>' -f2 | cut -d'<' -f1 ";
	    $this->cmd("localhost",$query);
	    while ( TRUE )   {
	        if (!empty($report_uuid = $this->ip2cve4openvas2task4check4run2done($target_name))) break;
	        if (!empty($report_uuid = $this->ip2cve4openvas2task4check4run4new($target_name))) {$this->req_ret_str($query);}
	        if (!empty($report_uuid = trim($this->req_ret_str($query)))) break;
	        
	        $this->ssTitre("Progression");$this->requette("omp -u $this->openvas_login -w $this->openvas_passwd --get-tasks \"$task_uuid\"  | grep '$target_name' ");
	        sleep(120);
	    }
	    return $report_uuid;
	}
	
	public function ip2cve4openvas2report2get($report_uuid){
	    $report_uuid = trim($report_uuid);
	    $report_uuid_result_xml = "";
	    $this->ssTitre("Reports");
	    if(!empty($report_uuid)){
	        $this->cmd("localhost","omp -u $this->openvas_login -w $this->openvas_passwd --get-report-formats ");
	        $file_path_xml = "$this->dir_tmp/$report_uuid"."_faraday_openvas.xml";
	        $query = "omp -u $this->openvas_login -w $this->openvas_passwd --get-report '$report_uuid' --format a994b278-1f62-11e1-96ac-406186ea4fc5 2> /dev/null ";
	        $tmp = "";
	        while (empty($tmp)) {
	            $tmp = $this->req_ret_str($query);
	            sleep(10);
	        }
	        
	        $report_uuid_result_xml = $tmp ;
	        if(!file_exists($file_path_xml)) {
	            $this->requette("echo '<?xml version=\"1.0\" encoding=\"UTF-8\"?> ' > $file_path_xml");
	            $fd = fopen($file_path_xml, "a");
	            fwrite($fd,$report_uuid_result_xml);
	            fclose($fd);
	        }
	    }
	    //$this->req_ret_str("cat $file_path_xml");
	    return $report_uuid_result_xml;
	}
	
	public function ip2cve4openvas2faraday($file_path_xml){
	    $file_path_xml = trim($file_path_xml);
	    if(!empty($file_path_xml)){
	        $obj_file = new FILE($this->stream,$file_path_xml);
	        $size = $obj_file->file_file2size();
	        if( ($size != 40) || ($size > 40) ){
	            $query = "python /usr/share/python-faraday/faraday.py --cli --workspace $this->faraday_workspace_name --report $file_path_xml > /dev/null ";
	            $this->requette($query);
	        }
	    }
	}
	
	
	
	public function ip2cve4openvas2report2result4cve($cve,$report_uuid_result_xml){
	    $cve = trim($cve);
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__);
	    $xml=simplexml_load_string($report_uuid_result_xml);
	    foreach ($xml->report->results->children() as $service ){
	        if ( (stristr($service->nvt->cve,$cve)) || (stristr($service->nvt->tags,$cve)) ) {
	            $result .= $this->article("Host", $service->host);
	            $result .= $this->article("Port Number", $service->port);
	            $result .= $this->article("Severity", $service->severity);
	            $result .= $this->article("Qod", $service->qod->value);
	            $result .= $this->article("Description", $service->description);
	            $result .= $this->article("CVE", $service->nvt->cve);
	            $result .= $this->article("Tags", $service->nvt->tags);
	            $result .= "\n\n";
	            echo "\n\n";
	        }
	    }
	    return $result;
	}
	
	
	public function ip2cve4openvas2report2result($report_uuid_result_xml){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__);
	    $xml=simplexml_load_string($report_uuid_result_xml);
	    foreach ($xml->report->results->children() as $service ){
	        $result .= $this->article("Port Number", $service->port);
	        $result .= $this->article("Severity", $service->severity);
	        $result .= $this->article("Qod", $service->qod->value);
	        $result .= $this->article("Description", $service->description);
	        $result .= $this->article("CVE", $service->nvt->cve);
	        $result .= "\n";
	    }
	    return $result;
	}
	
	public function ip2cve4openvas2report2faraday($report_uuid){
	    $this->ssTitre(__FUNCTION__);
	    $file_path_xml = "$this->dir_tmp/$report_uuid"."_faraday_openvas.xml";
	    $this->ssTitre("Send To faraday");
	    $this->pause();
	    $this->ip2cve4openvas2faraday($file_path_xml);
	    
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
		return $this->req_ret_str($query);
		
	
	}
	

	
	public function ip2crack(string $unshadow_file,string $dico){
	    $this->titre(__FUNCTION__);

	        $user = array();
	        $unshadow_file = trim($unshadow_file);
	        $obj_file = new FILE($this->stream,$unshadow_file);
	        
	        $this->requette("/opt/john/john $obj_file->file_path --wordlist:\"$dico\" ");
	        
	        $tab_user2pass = $this->req_ret_tab("/opt/john/john --show $obj_file->file_path | grep ':' ");
	        if (!empty($tab_user2pass))
	            foreach ($tab_user2pass as $user2tmp){
	                if (preg_match('|^(?<user2name>[a-zA-Z0-9\-\_]{1,}):(?<user2cpw>[[:print:]]{1,}):(?<user2uid>[0-9]{1,}):(?<user2gid>[0-9]{1,}):(?<user2full_name>[[:print:]]{0,}):(?<user2home>[[:print:]]{1,}):(?<user2shell>[[:print:]]{1,})|',$user2tmp,$user))
	                {
	                   $this->yesAUTH($this->port2id, $user['user2name'], $user['user2cpw'],"crack etc_passwd and shadow with john ");
	                   //$this->req2BD4in(__FUNCTION__,__CLASS__,"$this->ip2where ",1);
	                   //$this->ip2auth();
	                }
	        }

	}
	
	public function ip2crack4check(): bool{
	    $this->titre(__FUNCTION__);
	    $sql_r_1 = "SELECT ip2crack FROM ".__CLASS__." WHERE $this->ip2where  AND ip2crack <> 0";
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
		   
		// https://www.tcpiputils.com/browse/ip-address/80.88.14.75
		    //https://bgp.he.net/ip/213.186.33.4
		    $this->article("BGP Hijacking","Autonomous System Numbers (ASNs) define which IP addresses a router is responsible for.
				If there is an overlap between two ASN ranges, routers will route to the more specific ASN
	• An attacker who either has compromised an ISP or can inject routes (think nation-states) can broadcast malicious routes and reroute
traffic through their network");
		$this->note("In order to defend against these attacks you have to first know what is normal in relation to traffic being routed
to and through your network. We recommend running and recording what normal traceroute information looks
like by using a service like traceroute.org.
Please keep in mind that routes do change. However, if you see traffic making a drastic change (i.e. being
routed halfway around the world) you may want to work with your ISP to investigate.");
		$result .= $this->ip2asn4db()."\n";
		$result .= $this->ip2asn4nmap();
		$result .= $this->ip2whois4asn();
		$result = base64_encode($result);
		return base64_decode($this->req2BD4in(__FUNCTION__,__CLASS__,"$this->ip2where ",$result));
		}
	}
	
	public function ip2asn4db(){
	    $this->ssTitre(__FUNCTION__);
		if ($this->ip4priv($this->ip)) return "Private IP";
		$query = "mysql --user=root --password=hacker --database=geoip --execute=\"CALL ip2asn(\\\"$this->ip\\\");\" 2> /dev/null | grep -Po \"AS[0-9]{1,}.*\" ";
		return $this->req_ret_str($query);
		
	}
	
	public function ip2asn4nmap(){
	    $this->ssTitre(__FUNCTION__);
		if ($this->ip4priv($this->ip)) return "Private IP";
		$query = "nmap --script asn-query $this->ip -Pn -sn -e $this->eth -oX - | xmlstarlet sel -t -v /nmaprun/host/hostscript/script/@output | strings  ";
		return $this->req_ret_str($query);
		
	}
	

	public function ip2cidr4range(){
		$this->ssTitre(__FUNCTION__);
		$query = "echo \"`echo '$this->ip' | grep -Po \\\"^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\\\"`.0-255\" ";
		return $this->req_ret_str($query);
	}
	
	
	public function ip2os4arch(string $result){
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
	    $this->titre(__FUNCTION__);
	    $result = "";
	    $sql_r_1 = "SELECT ".__FUNCTION__." FROM ".__CLASS__." WHERE $this->ip2where  AND ".__FUNCTION__." IS NOT NULL";
	    if ($this->checkBD($sql_r_1) ) return  base64_decode($this->req2BD4out(__FUNCTION__,__CLASS__,"$this->ip2where "));
	    else {
	        
	        $this->note("Putting all hosts behind a proxy filter will prevent passive OS Fingerprinting.");
	        
		
		//$result .= $this->ip2os2xprobe();
		$result .= $this->ip2os2nmap();
		$this->ip2os4arch($result);
		//$this->note("In which of the following scanning methods do Windows operating systems send only RST packets irrespective of whether the port is open or closed? TCP FIN");
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
		return $this->req_ret_str($query);
		
	}
	
	public function ip2os2xprobe(){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__);
		$query = "echo '$this->root_passwd' | sudo -S xprobe2 $this->ip  | grep -v 'Xprobe2' ";
		$result .= $this->cmd("localhost",$query);
		return $this->req_ret_str($query);
		
	}
	
	
	public function ip2os2nmap(){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__);
		$query = "echo '$this->root_passwd' | sudo -S nmap -n --reason -O --osscan-guess $this->ip -F -sSU -Pn -e $this->eth -oX - ";
		$result .= $this->cmd("localhost",$query);
		return $this->req_ret_str($query);
		
	}

	
	
	public function ip2geoip4country(){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__);
		if ($this->ip4priv($this->ip)) return $result."Private IP";
		$query = "mysql --user=root --password=hacker --database=geoip --execute=\"CALL ip2country(\\\"$this->ip\\\");\" 2> /dev/null  | grep -v lepays ";
		$result .= $this->cmd("localhost",$query);
		return $this->req_ret_str($query);
		
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
	        if ($this->ip4priv($this->ip)) {
	            $tab_open_ports_tcp = $this->ip2tcp4select();
	            $tab_open_ports_udp = $this->ip2udp4top200();
	            $tab_open_ports_tcp += $this->ip2tcp4first1000();
	            $tab_open_ports_tcp += $this->ip2tcp4top10000();	            
	            if (empty($tab_open_ports_tcp)) $tab_open_ports_tcp += $this->ip2tcp4all();
	        }
	        else {
	            
	            $tab_open_ports_tcp = $this->ip2tcp4select();
	            $tab_open_ports_udp = $this->ip2udp4top200();
	            if (empty($tab_open_ports_tcp)) $tab_open_ports_tcp += $this->ip2tcp4top4000();

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
	


	public function ip2tcp4all(): array{
	    $this->ssTitre(__FUNCTION__);
		$query = "echo '$this->root_passwd' | sudo -S nmap -sS -Pn -n --reason -p 1-65535 --open $this->ip -e $this->eth -oX - ";
		$query = $query." | xmlstarlet sel -t -v /nmaprun/host/ports/port/@portid ";
		return $this->req_ret_tab($query);
	}
	

	
	public function ip2tcp4top10000(): array{
	    $this->ssTitre(__FUNCTION__);
		$query = "echo '$this->root_passwd' | sudo -S nmap -sS -Pn -n --host-timeout 30m --reason --top-ports 10000 --open $this->ip -e $this->eth -oX - ";
		$query = $query." | xmlstarlet sel -t -v /nmaprun/host/ports/port/@portid ";
		return $this->req_ret_tab($query);
	}
	
	
	
	public function ip2tcp4top4000(): array{
	    $this->ssTitre(__FUNCTION__);
	    $query = "echo '$this->root_passwd' | sudo -S nmap -sS -Pn -n --host-timeout 30m --reason --top-ports 4000 --open $this->ip -e $this->eth -oX - ";
	    $query = $query." | xmlstarlet sel -t -v /nmaprun/host/ports/port/@portid ";
	    return $this->req_ret_tab($query);
	    $rst = array();
	    $protocol = 'T';
	    $this->cmd("localhost", $query);
	    $filename = "$this->dir_tools/dico/ports.dico.4000";
	    $tab_port2scan = file($filename);
	    $rst = $this->ip2port8php($this->ip, $tab_port2scan, $protocol);
	    
	    echo $this->tab($rst);
	    return $rst;
	}
	
	public function ip2tcp4first1000(): array{
	    $this->ssTitre(__FUNCTION__);
		$query = "echo '$this->root_passwd' | sudo -S nmap -sS -Pn -n --reason -p1-1024 --open $this->ip --min-parallelism 10 -e $this->eth -oX - ";
		$query = $query." | xmlstarlet sel -t -v /nmaprun/host/ports/port/@portid ";
		return $this->req_ret_tab($query);
		$rst = array();
		$protocol = 'T';
		$this->cmd("localhost", $query);
		for ($i=1;$i<=1000;$i++)
		    $tab_port2scan[] = $i;
		$rst = $this->ip2port8php($this->ip, $tab_port2scan, $protocol);
		
		echo $this->tab($rst);
		return $rst;
	} 
	
	public function ip2tcp4select(): array{  // 617 ports
	    $this->ssTitre(__FUNCTION__);

		$query = "echo '$this->root_passwd' | sudo -S nmap -sS -Pn -n --reason -p \
1,7,9,13,18,19,21-23,25,27,35,37,42,43,49,53,56,57,66,69,75,77,79-81,85,87,88,92,94,97,101,102,105,107-111,113,115,118,119,\
123,129,135,137-139,143,144,156,161,175,179,193,217,220,222,264,280,384,389,402,407,422,443-446,454,455,457,464,465,500,502,\
512-515,524,540,548,554,563,585,587,591,593,617,623,626,631,636,647,655,689,705,771,783,831,873,875,888,902,910,912,921,969,990,\
993,995,998-1000,1024-1043,1067,1080,1090,1098-1103,1128-1129,1158,1194,1199,1211,1220,1221,1234,1241,\
1270,1300,1311,1337,1352,1433-1435,1440,1471,1494,1521,1530,1533,1581-1582,1604,1670,1720,1723,1745,1755,1801,1811,1863,1900,\
1944,2000-2002,2010,2049,2067,2100,2101,2103,2105,2107,2121,2171-2173,2175,2199,2207,2221-2222,2280,2301,2323,2362,2375,2380-2381,2394,\
2401,2525,2533,2598,2638,2701,2702,2725,2869,2809,2905,2906,2947,2967,3000,3001,3037,3050,3057,3128,3200,3217,3268,3269,\
3273,3299,3306,3310,3333,3343,3372,3389,3460,3465,3500,3628,3632,3690,3780,3790,3817,3847,3872,3900,4000-4002,4016,4020,4100,\
4322,4333,4353,4355,4422,4433,4444-4445,5000,5009,5038,5040,5051,5060-5061,5093,5168,5222,5227,5247,5250,5351,5353,5355,5400,5405,\
5432-5433,5466,5498,5520-5521,5554-5555,5560,5580,5631-5632,5666,5722,5800-5803,5814,5900-5903,5920,5984-5986,5999-6002,\
6050,6060,6070,6080,6101,6103,6106,6161,6262,6346,6347,6379,6405,6502-6504,6542,6557,6660-6661,6667,6789,6889,6905,6988,\
6996,7000-7010,7021,7071,7080,7144,7181,7210,7272,7400,7414,7426,7443,7510,7547,7551,7579-7580,7597,7680,7681,7700-7701,\
7777-7778,7787,7800-7801,7878-7879,7890,7902,7980,8000-8001,8008-8009,8014,8020,8023,8028,8030,8050-8051,8080-8082,\
8085-8088,8090-8091,8095,8098,8101,8118,8161,8180,8205,8222,8300,8303,8333,8400,8443-8444,8503,8642,8686,8701,8787,\
8799,8800,8812,8834,8880,8888-8890,8899,8901-8903,8980,8999-9005,9010,9050,9080-9081,9084,9090,9099-9100,9111,9152,\
9160,9200-9201,9256,9300,9389,9390-9391,9443,9495,9500,9711,9788,9809-9815,9855,9875,9910,9991,9999-10002,10008,10021,\
10050-10051,10080,10098-10099,10162,10202-10203,10443,10616,10628,11000-11001,11099,11211,11234,11333,11460,12000,12174,\
12203,12221,12345,12346,12397,12401,13013,13364,13500,13838,14000,14330,15000-15001,15200,16000,16102,16959,17185,17200,\
17300,18881,18980,19300,19810,20000,20010,20031,20034,20101,20111,20171,20222,22222,23472,23791,23943,25000,25025,26000,\
26122,26256,27000,27015,27017,27374,27888,27900,27960,28222,28784,30000,30718,30821,31001,31099,32764,32913,33000,34205,\
34443,37337,37718,37777,38080,38292,40007,41025,41080,41523-41524,42424,44444,44334,44818,45230,46823-46824,47001-47002,48080,\
48899,49152-49159,50000-50004,50013,50050,50500-50504,52302,52869,53413,53770,55553,55555,57399,57772,62078,62514,65301,65535\
 --open $this->ip -e $this->eth  -oX -"; // --scan-delay 1
		
		$firewall = $this->ip2fw4enable();
		
		if (!$firewall) $query = $query." --scan-delay 1 | xmlstarlet sel -t -v /nmaprun/host/ports/port/@portid ";
		else $query = $query." | xmlstarlet sel -t -v /nmaprun/host/ports/port/@portid ";
		
		return $this->req_ret_tab($query);
		$rst = array();
		$protocol = 'T';
		$this->cmd("localhost", $query);
		$filename = "$this->dir_tools/dico/ports.dico.615";
		$tab_port2scan = file($filename);
		$rst = $this->ip2port8php($this->ip, $tab_port2scan, $protocol);
		
		echo $this->tab($rst);
		return $rst;
	}	
	

	
	public function ip2port2tcp(): array{  
	    $this->ssTitre(__FUNCTION__);
	    
	    $rst = array();
	    $protocol = 'T';
	    $filename = "$this->dir_tools/dico/ports.dico.tcp";
	    $tab_port2scan = file($filename);
	    //$tab_port2scan = array(21,22,25,80,443,8080);
	    $rst = $this->ip2port8php($this->ip, $tab_port2scan, $protocol);
	    
	    echo $this->tab($rst);
	    return $rst;
	}	

	
	public function ip2tcp4web(): array{
	    $this->ssTitre(__FUNCTION__);
	    $query = "echo '$this->root_passwd' | sudo -S nmap -Pn -n --reason -p http* --open $this->ip -e $this->eth -oX - ";
	    $firewall = $this->ip2fw4enable();	
	    if (!$firewall) $query = $query." --scan-delay 1 | xmlstarlet sel -t -v /nmaprun/host/ports/port/@portid ";
	    else $query = $query." | xmlstarlet sel -t -v /nmaprun/host/ports/port/@portid ";
	    $rst = array();
	    $rst = $this->req_ret_tab($query);
	    return $rst;
	}
	

	public function ip2udp4select(): array{
	    $this->ssTitre(__FUNCTION__);
		$query = "echo '$this->root_passwd' | sudo -S nmap -sU -Pn -n --reason --open -e $this->eth -p 53,68,69,111,135,137,138,139,161,631,1020,2049,4569,5060,5353,33485,54269 $this->ip -oX - ";
		$firewall = $this->ip2fw4enable();
		if (!$firewall) $query = $query." --scan-delay 1 | xmlstarlet sel -t -v /nmaprun/host/ports/port/@portid ";
		else $query = $query." | xmlstarlet sel -t -v /nmaprun/host/ports/port/@portid ";
		$rst = array();
		$rst = $this->req_ret_tab($query);
		return $rst;
	}

	public function ip2udp4top200(): array{
	    $this->ssTitre(__FUNCTION__);
	    
		$query = "echo '$this->root_passwd' | sudo -S nmap -sU -Pn -n --reason --top-ports 60 $this->ip --open -e $this->eth -oX -  ";		
		
		$firewall = $this->ip2fw4enable();		
		if (!$firewall) $query = $query." --scan-delay 1 | xmlstarlet sel -t -v /nmaprun/host/ports/port/@portid ";
		else $query = $query." | xmlstarlet sel -t -v /nmaprun/host/ports/port/@portid ";		
		
		return $this->req_ret_tab($query);
		
		$rst = array();
		$protocol = 'U';
		$this->cmd("localhost", $query);
		$filename = "$this->dir_tools/dico/ports.dico.200";
		$tab_port2scan = file($filename);
		$rst = $this->ip2port8php($this->ip, $tab_port2scan, $protocol);
		
		echo $this->tab($rst);
		return $rst;
	}
	
	
	public function ip2udp4top1000(): array{
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
		return $this->req_ret_str($query);
		
	}
	
	public function ip2fw4nmap2fw(){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__);
		$query = "echo '$this->root_passwd' | sudo -S nmap --script=\"firewall-bypass\" -Pn -n --top-ports 5 --reason  $this->ip -e $this->eth -oX -  | xmlstarlet sel -t -v /nmaprun/host/ports/port/state/@state";
		return $this->req_ret_str($query);
		
	}
	
	
	public function ip2fw4sw(){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__);
		$query = "echo '$this->root_passwd' | sudo -S nmap -sW -Pn -n --reason --top-ports 5 $this->ip -e $this->eth -oX -  | xmlstarlet sel -t -v /nmaprun/host/ports/port/state/@state";
		$result .= $this->cmd("localhost",$query);
		return $this->req_ret_str($query);		
		
	}
	
	public function ip2fw4ack(){
	    $result = "";
	    $sql_r_1 = "SELECT ".__FUNCTION__." FROM ".__CLASS__." WHERE $this->ip2where  AND ".__FUNCTION__." IS NOT NULL";
	    if ($this->checkBD($sql_r_1) ) {
	        $result = $this->req2BD4out(__FUNCTION__,__CLASS__,"$this->ip2where ");
	        echo $result."\n";
	        if ($result=="filtered") { $chaine = "This Host is Protected By Firewall";$this->note($chaine);}
	        if ($result=="unfiltered") {$chaine = "This Host is not Protected By Firewall Statefull Rules";$this->rouge($chaine);}
	        
	        return $result;
	    }
	    else {
		$query = "echo '$this->root_passwd' | sudo -S nmap -sA -Pn -n --reason -p 80 $this->ip -e $this->eth -oX - | xmlstarlet sel -t -v /nmaprun/host/ports/port/state/@state";
        $result = trim($this->req_ret_str($query));
        if ($result=="filtered") { $chaine = "This Host is Protected By Firewall";$this->note($chaine);}
        if ($result=="unfiltered") {$chaine = "This Host is not Protected By Firewall Statefull Rules";$this->rouge($chaine);}
        
        return $this->req2BD4in(__FUNCTION__,__CLASS__,"$this->ip2where ",$result);
	    }
	}
	
	public function ip2fw4enable(): bool{
	    $this->ssTitre(__FUNCTION__);
	    if(!stristr($this->ip2fw4ack(),"unfiltered")) return FALSE;
	    else return TRUE ;
	}
	
	public function ip2protocol(){
		$query = "echo '$this->root_passwd' | sudo -S nmap -sO -n --reason -F $this->ip -e $this->eth -oX -";
	    return $this->req2BD(__FUNCTION__,__CLASS__,"$this->ip2where ",$query);
	}
	
	public function ip2fw4frag(){
	    $result = "";
	    $this->ssTitre(__FUNCTION__);
		$query = "echo '$this->root_passwd' | sudo -S nmap -f -Pn -n --reason  --top-ports 5 $this->ip -e $this->eth -oX - ";
		return $this->req_ret_str($query);		
		
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
	




	public function ip2tracert4local8traceroute(){
	    $this->ssTitre(__FUNCTION__);
	    $query = "traceroute $this->ip "; 
	    $result = $this->req_ret_str($query);

	    return $result;
	}
	
	
	public function ip2tracert4local8nmap(){
	    $this->ssTitre(__FUNCTION__);
	    $this->note("In a traceroute operation, a series of packets gets sent to a destination with very low Time-to-Live (TTL) values, starting at one up incrementing from
there. As each packet dies, an ICMP Time Exceeded message gets sent back to the sender.
Thus, the source and destination addresses stay the same, as well
as the header options; the TTL changes.");
	    $query = "echo '$this->root_passwd' | sudo -S nmap --traceroute --reason $this->ip -sn -e $this->eth -Pn -oX - | grep 'hop'"; // xmlstarlet sel -t -v /nmaprun/host/trace/hop/@ttl
	    
	    $result = $this->req_ret_str($query);
	    $result = $this->parse4traceroute($result);
	    return $result;
	}


	// #################################### ICMP ECHO ##############################
	public function ip2icmpECHO(){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__);
		$this->note("ICMP: ECHO 		(Request (Type 08), Reply (Type 00)) " );
		$query = "echo '$this->root_passwd' | sudo -S nmap -PE -n $this->ip -T 2 -e $this->eth -Pn -oX - ";
		$result .= $this->cmd("localhost",$query);
		return $this->req_ret_str($query);
		
	}
	// ##############################################################################
	
	// ####################################### ICMP TIME ############################
	public function ip2icmpTIME(){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__);
		$this->note("IDEAL INTO LAN - ICMP: Time Stamp 	(Request (Type 13), Reply (Type 14))" );
		$query = "echo '$this->root_passwd' | sudo -S nmap -PP -n $this->ip -T 2 -e $this->eth -Pn -oX - ";
		$result .= $this->cmd("localhost",$query);
		return $this->req_ret_str($query);
		
	}
	// ##############################################################################
	
	// ##################################### ICMP INFO #############################
	public function ip2icmpINFO(){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__); // echo '$this->root_passwd' | sudo -S icmpush -vv  -info
		$this->note("ICMP: Information	(Request (Type 15), Reply (Type 16))" );
		$query = "echo '$this->root_passwd' | sudo -S nmap -PA -n $this->ip -T 2 -e $this->eth -Pn -oX -";
		$result .= $this->cmd("localhost",$query);
		return $this->req_ret_str($query);
		
	}
	// ##############################################################################
	
	// ###################################### ICMP MASK #############################
	public function ip2icmpMASK(){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__);
		$this->note("ICMP: Address Mask 	(Request (Type 17), Reply (Type 18))" );
		$query = "echo '$this->root_passwd' | sudo -S nmap -PM -n $this->ip -T 2 -e $this->eth -Pn -oX -";
		$result .= $this->cmd("localhost",$query);
		return $this->req_ret_str($query);
		
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
	    $result = "";
	   if ($this->ip4priv($this->ip)) return "Private IP";
	   $sql_r_1 = "SELECT ".__FUNCTION__." FROM ".__CLASS__." WHERE $this->ip2where  AND ".__FUNCTION__." IS NOT NULL";
	   if ($this->checkBD($sql_r_1) ) return  $this->req2BD4out(__FUNCTION__,__CLASS__,"$this->ip2where ");
	   else {	    
	    $query = "mysql --user=$this->mysql_login --password=$this->mysql_passwd --database=geoip --execute=\"CALL ip2city(\\\"$this->ip\\\");\"  2>/dev/null | grep -v loc ";
	    $result .= $this->req_ret_str($query);	
	    $result .= $this->ip2whois4geoip();
		return $this->req2BD4in(__FUNCTION__,__CLASS__,"$this->ip2where ",$result);
	    }
	}
	
	
	public function ip2whois(): string{
	    $tmp = array();
	    $sql_r_1 = "SELECT ".__FUNCTION__." FROM ".__CLASS__." WHERE $this->ip2where  AND ".__FUNCTION__." IS NOT NULL";
	    if ($this->checkBD($sql_r_1) ) return  base64_decode($this->req2BD4out(__FUNCTION__,__CLASS__,"$this->ip2where "));
	    else {
	        
	        $query = "whois $this->ip | grep -v -i -E \"(^Comment|abuse|^%|^#)\"";
	        $this->cmd("localhost", $query);
	        $result = $this->req_ret_str($query);
	        
	        /*
	        $port = 43;
	        $timeout = 10;
	        $fp = @fsockopen("whois.arin.net", $port, $errno, $errstr, $timeout) or die("Socket Error " . $errno . " - " . $errstr);
	        fputs($fp, "n + $this->ip\r\n");
	        $out = "";
	        while(!feof($fp)){
	            $out .= fgets($fp);
	        }
	        fclose($fp);
	        
	        exec("echo '$out' | grep -v -i -E \"(^Comment|abuse|^%|^#)\" ",$tmp);
	        $result = $this->tab($tmp);
	        */
	        echo $result;
	        $result = base64_encode($result);
	        return base64_decode($this->req2BD4in(__FUNCTION__,__CLASS__,"$this->ip2where ",$result));
	    }
	    
	}
	
	public function ip2whois4asn(){
	    $this->titre(__FUNCTION__);
	    if ($this->ip4priv($this->ip)) return "Private IP";
	    $query = "echo '".$this->ip2whois()."' | egrep -i \"(NetRange|CIDR|Parent|inetnum|NetType|OriginAS|Organization)\" ";
	    $tmp= array();
	    exec($query,$tmp);	    
	    return $this->tab($tmp);
	}
	
	public function ip2whois4geoip(){
	    $this->titre(__FUNCTION__);
	    if ($this->ip4priv($this->ip)) return "Private IP";
	    $query = "echo '".$this->ip2whois()."' | egrep -i \"(Organization|route|Address|PostalCode|City|StateProv|country)\" | sort -u";
	    $tmp= array();
	    exec($query,$tmp);
	    return $this->tab($tmp);
	}
	
	public function ip2honey():bool{
	    $this->ssTitre(__FUNCTION__);

	    $this->ip2port();$this->pause();
	    $port_sum = count($this->tab_open_ports_all);
	    $this->article("ALL PORT SUM",$port_sum);
	    if ($port_sum > 50 ) { $this->log2error("HONEYPOT DETECTED");return true ;}
	    else return false ;
	}
	
	public function ip2port4scan8xml(string $result_scan_xml):array{
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
	
	public function ip2port4scan(string $result_scan): array{
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
	
	

	
	
	

	public function ip2auth(){
	    $this->titre(__FUNCTION__);
	$sql_service = "select id8port,service2name FROM SERVICE WHERE id8port IN (SELECT id FROM PORT WHERE id8ip= '$this->ip2id') AND (service2name = 'asterisk' OR service2name LIKE '%ftp%'  OR service2name = 'icq' OR service2name = 'imap' OR service2name = 'imaps' OR service2name = 'ldap2' OR service2name = 'ldap2s' OR service2name = 'ldap3' OR service2name = 'mssql' OR service2name = 'mysql' OR service2name = 'nntp' OR service2name = 'oracle-listener' OR service2name = 'oracle-sid' OR service2name = 'pcanywhere' OR service2name = 'postgres' OR service2name = 'rlogin'  OR service2name LIKE '%rdp%' OR service2name = 'sip' OR service2name = 'ssh' OR service2name LIKE '%smb%' OR service2name LIKE '%samba%' OR service2name = 'snmp' OR service2name = 'smtp' OR service2name = 'smtps' OR service2name = 'vnc' OR service2name = 'xmpp')  ;";
	$this->parchment($this->req_ret_str("mysql --user=$this->mysql_login --password=$this->mysql_passwd --database=$this->mysql_database --execute=\"$sql_service\"  2>/dev/null "));
		    if ( $service = $this->mysql_ressource->query($sql_service) ) {
		        
		        
		        $users = $this->ip2users4passwd();
		        if (!empty($users))
		            while ($service_row = $service->fetch_assoc()) {
		                foreach ($users as $user2name => $user2pass){
		                    if (!empty($user2name)) {
		                $service2name = $service_row['service2name'];
		                $this->titre("Try Authentication By Username-Password ");
		                $query = "select port FROM PORT WHERE id = '".$service_row['id8port']."' ;";
		                $port = trim($this->req_ret_str("mysql --user=$this->mysql_login --password=$this->mysql_passwd --database=$this->mysql_database --execute=\"$query\"  2>/dev/null | grep -v port "));
		                $query = "select protocol FROM PORT WHERE id = '".$service_row['id8port']."' ;";
		                $protocol = trim($this->req_ret_str("mysql --user=$this->mysql_login --password=$this->mysql_passwd --database=$this->mysql_database --execute=\"$query\"  2>/dev/null | grep -v protocol "));
		                $obj_port = new AUTH($this->stream,$this->eth,$this->domain,$this->ip, $port,$protocol);
		                
		                if ($service2name==="ssh"){
		                    $test = new SERVICE($obj_port->stream,$obj_port->eth,$obj_port->domain,$obj_port->ip, $obj_port->port,$obj_port->protocol);
		                    $test->poc($this->flag_poc);
		                    $test->stream8ssh8passwd($test->ip, $test->port, $user2name,$user2pass);

		                }
		                
		                else $obj_port->port2auth4pass4hydra($service2name, $user2name,$user2pass);
		                
		         
		                		            }
		            }
		    }
		        $users = $this->ip2users4shell();
		        var_dump($users);
		        if (!empty($users))
		                    while ($service_row = $service->fetch_assoc()) {
		                        $service2name = $service_row['service2name'];
		                        foreach ($users as $user2name ){
		                            if (!empty($user2name)) {
		                        $this->titre("Try Authentication By Dictionnary ");
		                        $query = "select port FROM PORT WHERE id = '".$service_row['id8port']."' ;";
		                        $port = trim($this->req_ret_str("mysql --user=$this->mysql_login --password=$this->mysql_passwd --database=$this->mysql_database --execute=\"$query\"  2>/dev/null | grep -v port "));
		                        $query = "select protocol FROM PORT WHERE id = '".$service_row['id8port']."' ;";
		                        $protocol = trim($this->req_ret_str("mysql --user=$this->mysql_login --password=$this->mysql_passwd --database=$this->mysql_database --execute=\"$query\"  2>/dev/null | grep -v protocol "));
		                        $obj_port = new AUTH($this->stream,$this->eth,$this->domain,$this->ip, $port,$protocol);
		                        $obj_port->port2auth4dico4hydra($service2name,$user2name);
		                }
		        }
		        }
	    }
	    
}



public function ip2vhost8tab(array $tab_vhosts){
    $this->titre(__FUNCTION__);
    $result = "";
    $tmp = "";

        $size = count($tab_vhosts);
        for ($i=0;$i<$size;$i++){
            $vhost = trim($tab_vhosts[$i]);
            if (!empty($vhost)){
                $vhost = $this->host2norme($vhost);
                $this->article("$i/$size: Try to Found IP from", $vhost);
                $tab_vhost_ip = array();
                $tab_vhost_ip = $this->host4ip($vhost);
                if (!empty($tab_vhost_ip)){
                    foreach ($tab_vhost_ip as $ip){
                        $ip = trim($ip);
                        if ($this->isIPv4($ip)){
                            if ($ip===$this->ip){
                                $query = "php pentest.php WEB \"$this->eth $this->domain $vhost web2check_200 FALSE\" ";
                                $this->requette($query);
                                $this->rouge("Compatible IP from $vhost:$ip to ".$this->ip2host("").":$this->ip");
                                $result .= "$vhost\n";
                            }
                            else {
                                $this->note("Not Compatible IP from $vhost:$ip to ".$this->ip2host("").":$this->ip");
                            }
                        }
                        
                    }
                }
            }
        }
        
        return $result;
}

	
public function ip2vhost(){
	    $result = "";
	    $tmp = "";
	   
	    $tab_vhosts = array();

	    $sql_r_1 = "SELECT ".__FUNCTION__." FROM ".__CLASS__." WHERE $this->ip2where  AND ".__FUNCTION__." IS NOT NULL";
	    if ($this->checkBD($sql_r_1) ) return  base64_decode($this->req2BD4out(__FUNCTION__,__CLASS__,"$this->ip2where "));
	    else {
	    //$tmp .= $this->ip2vhost4nmap();$this->pause(); // not usefull
	    
	    $tab_vhosts = $this->ip2vhost4web();$this->pause();
		//$tab_vhosts = $this->req_ret_tab("echo '$tmp' $this->filter_host "); // | grep -i -Po \"([0-9a-z\-_]{1,}\.)+$this->domain\"
	    //$tab_vhosts = file("$this->dir_tmp/vhosts.all");
		$result = $this->ip2vhost8tab($tab_vhosts);
		echo $result;
		$result = base64_encode($result);
		return base64_decode($this->req2BD4in(__FUNCTION__,__CLASS__,"$this->ip2where ",$result));
		}
	}
	
	public function ip2vhost4nmap(){
	    $this->titre(__FUNCTION__);
		if ($this->ip4priv($this->ip)) return "Private IP";
		//$query = "nmap --script hostmap-ip2hosts -sn -Pn $this->ip -e $this->eth | grep -v -i \"nmap\" | grep -v -i \"csv.php\" $this->filter_host | grep -v 'huanqiucaipiaotouzhupingtai.com' | sort -u ";
		$query = "nmap --script hostmap-ip2hosts -sn -Pn $this->ip -e $this->eth -oX - ";
		return $this->req_ret_str($query);
	}
	
	public function ip2vhost4web():array{
	    $result = "";
	    $this->titre(__FUNCTION__);
	    if (!$this->ip4priv($this->ip)) {

	        $query = "curl 'https://domains.yougetsignal.com/domains.php' -H 'User-Agent: $this->user2agent' -H 'Accept: text/javascript, text/html, application/xml, text/xml, */*' -H 'Accept-Language: en-GB,en;q=0.5' --compressed -H 'X-Requested-With: XMLHttpRequest' -H 'X-Prototype-Version: 1.6.0' -H 'Content-type: application/x-www-form-urlencoded; charset=UTF-8' -H 'Origin: https://www.yougetsignal.com' -H 'Connection: keep-alive' -H 'Referer: https://www.yougetsignal.com/tools/web-sites-on-web-server/' -H 'TE: Trailers' --data 'remoteAddress=$this->ip&key=' $this->filter_host  ";
	        $result .= $this->req_ret_str($query);
	        $this->pause();
	        
	        $query = "curl 'https://www.dnsqueries.com/en/ip_neighbors.php' -H 'User-Agent: $this->user2agent' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H 'Accept-Language: en-GB,en;q=0.5' --compressed -H 'Content-Type: application/x-www-form-urlencoded' -H 'Origin: https://www.dnsqueries.com' -H 'Connection: keep-alive' -H 'Referer: https://www.dnsqueries.com/en/ip_neighbors.php' -H 'Upgrade-Insecure-Requests: 1' --data 'host=$this->ip' | grep ' nofollow=\"true\" target=\"_blank\">' $this->filter_host  ";
	        //$result .= $this->req_ret_str($query);
	        $this->pause();	        
	        
	        $query = "wget  --user-agent='$this->user2agent' --no-check-certificate --timeout=60 --tries=2 -qO- \"https://tools.tracemyip.org/lookup/$this->ip\" | grep '.tracemyip.org/lookup/' | grep -v -E \"(tracemyip\.org|www\.mobiletracker\.org)\" $this->filter_host ";
            $result .= $this->req_ret_str($query);
            $this->pause();

            $query = "wget --user-agent='$this->user2agent' --no-check-certificate --timeout=60 --tries=2 -qO- \"http://www.ip-neighbors.com/hostsearch/$this->ip/ipneighbors_page/1\" | grep 'Page:' | grep -Po \"1/[0-9]{1,5}\" | cut -d'/' -f2 ";
            $max = intval($this->req_ret_str($query));
            for ($i=2;$i<=$max;$i++){
            $query = "wget --user-agent='$this->user2agent' --no-check-certificate --timeout=60 --tries=2 -qO- \"http://www.ip-neighbors.com/hostsearch/$this->ip/ipneighbors_page/$i\" $this->filter_host ";
            $result .= $this->req_ret_str($query);
            }
            $this->pause();
            
            $query = "curl -X POST -d \"theinput=$this->ip&thetest=reverseiplookup&name_of_nonce_field=b6b2d9c9ef&_wp_http_referer=%2Freverse-ip-lookup%2F\" \"https://hackertarget.com/reverse-ip-lookup/\" | grep -v '<' $this->filter_host | grep -v -E \"a\.async|a\.src|m\.parentnode.inser|s\.creat|s\.getel|www\.google-analytics\.com\"  ";
            $result .= $this->req_ret_str($query);
            $this->pause();
 
	    }
	    return explode("\n", $result);
	}
	

	

	
	public function ip2range(){
	    $result = "";
	    $sql_r_1 = "SELECT ".__FUNCTION__." FROM ".__CLASS__." WHERE $this->ip2where  AND ".__FUNCTION__." IS NOT NULL";
	    if ($this->checkBD($sql_r_1) ) return  base64_decode($this->req2BD4out(__FUNCTION__,__CLASS__,"$this->ip2where "));
	    else {
	    $result .= $this->ip2range4local();
		
		$result = base64_encode($result);
		return base64_decode($this->req2BD4in(__FUNCTION__,__CLASS__,"$this->ip2where ",$result));
		}
		}
	

		

	
	
		public function ip2range4local(){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__);
		if ($this->ip4priv($this->ip)) return $result."Private IP";
		$query = "mysql --user=$this->mysql_login --password=$this->mysql_passwd --database=geoip --execute=\"CALL geoipbloc(\\\"$this->ip\\\");\" 2> /dev/null | tail -1 ";
		
		return $this->req_ret_str($query);
		
	}
	
	
	public function ip2malw(){
	    // https://kalilinuxtutorials.com/sipi-simple-ip-information-tools/
	    $result = "";
	    $sql_r_1 = "SELECT ".__FUNCTION__." FROM ".__CLASS__." WHERE $this->ip2where  AND ".__FUNCTION__." IS NOT NULL";
	    if ($this->checkBD($sql_r_1) ) return  base64_decode($this->req2BD4out(__FUNCTION__,__CLASS__,"$this->ip2where "));
	    else {
	        $this->titre(__FUNCTION__);
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

	

	
	public function ip2tracert(){
	    $result = "";
	    $sql_r_1 = "SELECT ".__FUNCTION__." FROM ".__CLASS__." WHERE $this->ip2where  AND ".__FUNCTION__." IS NOT NULL";
	    if ($this->checkBD($sql_r_1) ) return  base64_decode($this->req2BD4out(__FUNCTION__,__CLASS__,"$this->ip2where "));
	    else {
	    $result .= $this->ip2tracert4local8nmap();
	    //$result .= $this->ip2tracert4local8traceroute();
		//$result .= $this->ip2tracert4online();
		
		$result = base64_encode($result);
		return base64_decode($this->req2BD4in(__FUNCTION__,__CLASS__,"$this->ip2where ",$result));
	    }
	}
	
	
	public function ip2tracert4online(){
	    $this->ssTitre(__FUNCTION__);
		
		// http://www.monitis.com/traceroute/
		// http://ping.eu/traceroute/
		if ($this->ip4priv($this->ip)) return $result."Private IP";
		$query = "wget -qO- \"https://api.hackertarget.com/mtr/?q=$this->ip\"  ";
		
		return $this->req_ret_str($query);
		
		
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
	
	public function ip4service2display(){
	    $this->titre("Determining IP SERVICES");
	    if(!$this->ip2honey()){	 	        
	        if (!empty($this->tab_open_ports_all)){
	        $max_iter = count($this->tab_open_ports_all);
	        $this->rouge("ITER PORT $max_iter");
	        foreach ($this->tab_open_ports_all as $port){
	            if (!empty($port))  {
	                foreach ($port as $port_num => $protocol)
	                    if (!empty($port_num)) {
	                        $obj_service = new SERVICE($this->stream,$this->eth,$this->domain,$this->ip,$port_num, $protocol);
	                        $obj_service->service4info();
	                    }
	            }
	        }
	        }

	    }
	 }

	 
	 public function ip4enum2users(){
	     $this->titre(__FUNCTION__);
	     $tab_users = array();
	     $this->ip2port();
	     foreach ($this->tab_open_ports_all as $port){
	         if (!empty($port))  {
	             foreach ($port as $port_num => $protocol)
	                 if (!empty($port_num)) {
	                     $obj_service = new SERVICE($this->stream,$this->eth,$this->domain,$this->ip,$port_num, $protocol);
	                     //$obj_service->service4info();
	                     switch ($obj_service->service_name) {
	                         case "ssh" :
	                             $obj_service->ssh2enum($this->dico_users);
	                             break ;
	                         case "netbios-ssn" :
	                             // auxiliary/scanner/smb/smb_enumusers
	                             $obj_service->service2smb4enum2users();
	                             break ;
	                         case "smtp" :
	                           //  $obj_service->service2smtp2users();
	                             break ;
	                         case "snmp" : 
	                             //auxiliary/scanner/snmp/snmp_enumusers
	                             break ;
	                             
	                     }
	                 }
	         }
	     }
	     
	    $tab_users = $this->ip2users();
	    $this->parchment($this->tab($tab_users));
	 }
	
	
	public function ip4info2display(){ 
	    $this->article("ID IP", $this->ip2id);
	    $this->article("IP", $this->ip);
	    if(!$this->ip4priv($this->ip)){
	        $ip2geoip = trim($this->ip2geoip());$this->article("IP GEOLOC",$ip2geoip);
	        $ip2asn = trim($this->ip2asn());$this->article("IP ASN",$ip2asn);
	        $ip2range = trim($this->ip2range());$this->article("IP RANGE",$ip2range);
	        $ip2whois = trim($this->ip2whois());$this->article("IP WHOIS",$ip2whois);
	        $ip2fw = $this->ip2fw4ack();$this->article("IP FIREWALL",$ip2fw);
	        //$this->titre("Determining Firewall Rules");
	        //$this->ip2fw();$this->pause();
	        //$ip2icmp = $this->ip2icmp();$this->article("IP ICMP",$ip2icmp);
	        //$this->titre("Searching what happened In the PAST");$this->pause();
	        //$this->ip2vt();$this->pause();
	        //$this->ip2malw();$this->pause();
	    }
	    

	    $ip2root = $this->ip2root8db($this->ip2id);
	    if ($ip2root) $this->article("ip2root",$ip2root);

	    
	    if (!$this->ip4priv($this->ip)) {
	        $vhosts = trim($this->ip2vhost());$this->article("ALL vHosts", $vhosts);
	    }
	    $ip2tracert = trim($this->ip2tracert());$this->article("IP TraceRoute",$ip2tracert);
	    
	}
	public function ip4info(){ 	 
	    echo " =============================================================================\n";
	    $this->gtitre(__FUNCTION__);
	    if  (!$this->ip4info8db($this->ip2id) ) {	    
	        $this->ip4info2display();
	    $sql_ip = "UPDATE IP SET ip4info=1 WHERE id = $this->ip2id  ";
	    $this->mysql_ressource->query($sql_ip);
	    }
	    else  {
	        if ($this->flag_poc)  {
	            $this->ip4info2display();
	            $this->ip2dot();
	        }
	    }
	    echo "End ".__FUNCTION__.":$this->domain:$this->ip =============================================================================\n";	    
	}
	
	
	public function ip4service(){
	    echo "=============================================================================\n";
	    
	    if  (!$this->ip4service8db($this->ip2id) ) {
	        $this->ip4service2display();
	        //$this->ip4enum2users();
	        $this->ip2os();$this->pause();	        
	        //$this->ip2auth();$this->pause();
	        $sql_ip = "UPDATE IP SET ip4service=1 WHERE id = $this->ip2id  ";
	        $this->mysql_ressource->query($sql_ip);
	    }
	    else  {
	        if ($this->flag_poc)  $this->ip4service2display();
	    }
	    echo "End ".__FUNCTION__.":$this->domain:$this->ip =============================================================================\n";
	}
	
	
	public function ip4pentest(){
	    echo "=============================================================================\n";
	    $this->gtitre(__FUNCTION__);
	    if  (!$this->ip4pentest8db($this->ip2id) ) {
	        $this->ip4pentest2display();
	        $sql_ip = "UPDATE IP SET ip4pentest=1 WHERE id = $this->ip2id  ";
	        $this->mysql_ressource->query($sql_ip);
	    }
	    else  {
	        if ($this->flag_poc)  $this->ip4pentest2display();
	    }
	    echo "End ".__FUNCTION__.":$this->domain:$this->ip =============================================================================\n";
	}
	
	public function ip4pentest2display(){ // OK
	    echo "=============================================================================\n";
	    $this->gtitre(__FUNCTION__);
	    $this->ip4info();$this->pause();
	    $this->ip4service();$this->pause();

		//$this->ip2cve();$this->pause();
		//$result .=  $this->ip2vuln();$this->pause();
	    
	    if(!$this->ip2honey()){
	        if (!empty($this->tab_open_ports_all)){
	          
	            foreach ($this->tab_open_ports_all as $port){
	                if (!empty($port))  {
	                    foreach ($port as $port_num => $protocol)
	                        if (!empty($port_num)) {
	                            $obj_service = new SERVICE($this->stream,$this->eth,$this->domain,$this->ip,$port_num, $protocol);
	                            $obj_service->poc($this->flag_poc);
	                            //$obj_service->port4pentest();
	                        }
	                }
	            }
	            
	        }
	        
	    }
	    

	    
		echo "END IP4PENTEST:$this->ip =============================================================================\n";
		
	}
	

	
	
	
	
	public function ip2users4shell():array{
	    $this->ssTitre(__FUNCTION__);
	    $tab_ip2users4shell = array("root");
	    $sql_r_2 = "SELECT distinct(user2name) FROM USERS WHERE id8port IN (select id from PORT where id8ip = '$this->ip2id' ) AND ( user2name != '' AND ( from_base64(user2infos) LIKE \"%/bin/sh%\" OR from_base64(user2infos) LIKE \"%/bin/bash%\") ) ORDER by user2name ASC ";
	    //echo "$sql_r_2\n";
	    $conn = $this->mysql_ressource->query($sql_r_2);
	    while($row = $conn->fetch_assoc()){
	        $user2name = trim($row["user2name"]);
	        $tab_ip2users4shell[] = $user2name ;
	    }
	    $tab_ip2users4shell = array_reverse(array_filter(array_unique($tab_ip2users4shell)));
	    return $tab_ip2users4shell;
	}
	
	public function ip2users4passwd():array{
	    $this->ssTitre(__FUNCTION__);
	    $tab_ip2users4passwd = array();
	    $sql_r_2 = "SELECT distinct(user2name),user2pass FROM AUTH WHERE id8port IN (select id from PORT where id8ip = '$this->ip2id' ) AND ( user2name != '' )  ";
	    //echo "$sql_r_2\n";
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
	    $tab_ip2users4passwd = array_unique($tab_ip2users4passwd);
	    //var_dump($tab_ip2users4passwd);
	    return $tab_ip2users4passwd;
	}
	
	
	
	public function ip2users():array{
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
	
	
	
	
	
	
	public function  ip4info8db():bool{
	    $sql_w = "SELECT ip4info FROM IP WHERE $this->ip2where AND ip4info = 1 ";
	    return $this->checkBD($sql_w);
	}
	
	public function  ip4service8db():bool{
	    $sql_w = "SELECT ip4service FROM IP WHERE $this->ip2where AND ip4service = 1 ";
	    return $this->checkBD($sql_w);
	}
	
	
	public function  ip4pentest8db():bool{
	    $sql_w = "SELECT ip4pentest FROM IP WHERE $this->ip2where AND ip4pentest = 1 ";
	    return $this->checkBD($sql_w);
	}
	
	public function  ip2backdoor8db():bool{
	    $sql_w = "SELECT ip2backdoor FROM IP WHERE $this->ip2where AND ip2backdoor = 1 ";
	    return $this->checkBD($sql_w);
	}
	
	public function  ip2root8db():bool{
	    $this->ssTitre(__FUNCTION__);
	    $sql_w = "SELECT ip2root FROM IP WHERE $this->ip2where AND ip2root = 1 ";
	    return $this->checkBD($sql_w);
	}
	

	
	
	
	
	
	
	
	

}
?>
