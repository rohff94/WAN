<?php



/*
C:\> nslookup
server 10.10.10.45
> ls -d target.tgt
• Linux:
# dig @10.10.10.45 target.tgt —t AXFR


	// /opt/metasploit/common/share/nmap/scripts/
	// /usr/share/nmap/scripts/

 */

class PORT extends IP{
    var $port ;
    var $protocol ;
    var $port2id;
    var $port2where ;

    
    var $date_rec ;
    


    




    public function __construct($stream,$eth,$domain,$ip,$port,$protocol) {
        if(empty($port)) return $this->log2error("EMPTY PORT");

	// /usr/share/nmap/scripts/
        if($this->isIPv4($ip)) parent::__construct($stream,$eth,$domain,$ip);
        if(!$this->isIPv4($ip)) parent::__construct($stream,$eth,$domain,gethostbyname($ip));
	
	    $port_check = intval($port,10);
	    if ( ($port_check>0) && ($port_check<65535) ){
	        $this->port = trim($port);
	    }
	    else {
	        $this->log2error("Error on Port Numer");
	    }
	    
    
    $this->protocol = trim($protocol) ;
    $this->port2where = "id8ip = '$this->ip2id' AND port = '$this->port' AND protocol = '$this->protocol' ";
    

    
	$sql_r = "SELECT port,protocol FROM ".__CLASS__." WHERE $this->port2where ";
	if (!$this->checkBD($sql_r)) {
		$sql_w = "INSERT  INTO ".__CLASS__." (id8ip,port,protocol) VALUES ('$this->ip2id','$this->port','$this->protocol'); ";
		$this->mysql_ressource->query($sql_w);
		//$this->cmd("localhost","echo '$this->root_passwd' | sudo -S tshark -i $this->eth_wlan  host $this->ip -w $this->dir_tmp/$this->ip.pcap");
		echo $this->note("Working on PORT:$this->port for the first time");
		
	}

	    $sql_r = "SELECT id,ladate FROM ".__CLASS__." WHERE $this->port2where ";
	    //echo "$sql_r\n";$this->pause();
	    

	    $this->port2id = $this->mysql_ressource->query($sql_r)->fetch_assoc()['id'];
	    $this->date_rec = $this->mysql_ressource->query($sql_r)->fetch_assoc()['ladate'];
	   // $this->article("Date Rec", $this->date_rec);$this->pause();
	}
	
	
	
	public function port2auth4dico4hydra($service,$username){
	    $result = "";
	    
	    $this->ssTitre(__FUNCTION__.": $service://'$username':Dico");
	    $service = trim($service);
	    $username = trim($username);
	    $query_hydra = "hydra -l \"$username\" -P \"$this->dico_password.1000\" $this->ip $service -f -t 8 -e sr -s $this->port -w 5s 2>/dev/null  | grep -i 'login:'   ";
	    return  $this->auth2login4hydra($this->req_ret_str($query_hydra));
	}
	
	public function port2auth4dico4medusa($service,$username){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__.": $service://'$username':Dico");
	    $service = trim($service);
	    $username = trim($username);
	    $query_medusa = "medusa -u \"$username\" -P \"$this->dico_password.1000\" -h '$this->ip' -M $service -f -t 8 -e s -n $this->port  2>/dev/null | grep '\[SUCCESS\]' ";
	    $result .= $this->cmd("localhost",$query_medusa);
	    return  $result.$this->auth2login4medusa($this->req_ret_str($query_medusa));
	}
	
	public function port2auth4dico4ncrack($username){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__.": $this->port//'$username':Dico");
	    $username = trim($username);
	    $query_ncrack = "ncrack -u \"$username\" -P \"$this->dico_password.1000\" $this->ip:$this->port  2>/dev/null | grep \"$this->port:\"   ";
	    $result .= $this->cmd("localhost",$query_ncrack);
	    return  $result.$this->auth2login4ncrack($this->req_ret_str($query_ncrack));
	}
	
	
	public function port2auth4pass4hydra($service,$username,$userpass){
	    $this->ssTitre(__FUNCTION__.": $service://'$username':'$userpass'");
	    $service = trim($service);
	    $username = trim($username);
	    $query_hydra = "hydra -l \"$username\" -p \"$userpass\" $this->ip $service -f -t 8 -e sr -s $this->port -w 5s 2>/dev/null  | grep -i 'login:'  ";
	    return  $this->auth2login4hydra($this->req_ret_str($query_hydra));
	    
	}
	
	public function port2auth4pass4medusa($service,$username,$userpass){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__.": $service://'$username':'$userpass'");
	    $service = trim($service);
	    $username = trim($username);
	    $query_medusa = "medusa -u \"$username\" -p \"$userpass\" -h '$this->ip' -M $service -f -t 8 -e s -n $this->port  2>/dev/null | grep '\[SUCCESS\]' ";
	    $result .= $this->cmd("localhost",$query_medusa);
	    return  $result.$this->auth2login4medusa($this->req_ret_str($query_medusa));
	    
	}
	public function port2auth4pass4ncrack($username,$userpass){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__.": $this->port://'$username':'$userpass'");
	    $username = trim($username);
	    $query_ncrack = "ncrack -u \"$username\" -p \"$userpass\" $this->ip:$this->port  2>/dev/null | grep \"$this->port:\"  ";
	    $result .= $this->cmd("localhost",$query_ncrack);
	    return  $result.$this->auth2login4ncrack($this->req_ret_str($query_ncrack));
	}
	
	

		
	public function port2dot(){
		$this->ssTitre(__FUNCTION__);
		$file_output = "$this->dir_tmp/$this->ip.$this->port.".__FUNCTION__.".dot";
		$color_port = "orange";$color_arrow = "darkorange";
		
		list($service_name,$service_version,$service_product,$service_extrainfo,$service_hostname,$service_conf) = $this->port2version4run($this->port2version());
		$service = new SERVICE($this->stream,$this->eth,$this->domain,$this->ip,$this->port,$this->protocol);
		$service->poc($this->flag_poc);
		
		
		$port2dot_header = "digraph structs {
		label = \"".__FUNCTION__.":$this->ip:PORT\";
		graph [rankdir = \"LR\" layout = dot];
		node [fontsize = \"16\" shape = \"plaintext\"];
		edge [penwidth=2.0 ];

\"$this->ip:$this->port\" [label=<<TABLE BORDER=\"0\" CELLBORDER=\"1\" CELLSPACING=\"0\" ALIGN=\"LEFT\" >
		";

		// 		<TR><TD PORT=\"port2service\" >SERVER</TD><TD>".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->service2type()))."</TD></TR>
		//    <TR><TD PORT=\"service4cve\" >CVE</TD><TD>$service4cve</TD></TR>
		
		$port2dot_port = "
		<TR><TD>PORT NUMBER</TD><TD PORT=\"port\" bgcolor=\"$color_port\" >$this->port</TD></TR>
        <TR><TD PORT=\"date_rec\" >DATE REC</TD><TD>$date_rec</TD></TR>
        <TR><TD PORT=\"service2name\" >SERVICE NAME</TD><TD>$service->service_name</TD></TR>
        <TR><TD PORT=\"service2version\" >SERVICE VERSION</TD><TD>$service->service_version</TD></TR>
        <TR><TD PORT=\"service2product\" >SERVICE PRODUCT</TD><TD>$service->service_product</TD></TR>
        <TR><TD PORT=\"service2extrainfo\" >SERVICE EXTRA INFOS</TD><TD>$service->service_extrainfo</TD></TR>                
        ";			
		$size = count($tab_whois8lan);
		for ($i=0;$i<$size;$i++)
		    if (!empty($tab_whois8lan[$i]))
		        foreach ($tab_whois8lan[$i] as $lan2whois => $templateB64_id ){
		            $port2dot_port .= "<TR><TD PORT=\"ip2users\" >$lan2whois</TD><TD>".$this->dot2diagram(str_replace("\n","<BR/>\n",$templateB64_id))."</TD></TR>\n";
		          		    }
		$port2dot_footer = "
</TABLE>>];
							}";
		$port2dot = $port2dot_header.$port2dot_port.$port2dot_footer;
		$port2dot4body = $port2dot_port ;
		//system("echo '$port2dot' > $file_output ");
		//$this->requette("gedit $file_output");
		//$this->dot2xdot("$file_output ");
		//$this->dot4make($file_output,$port2dot);
		return $port2dot4body;
	}
	

		
	public function port2version4run(string $version_resu_xml):array{
	    $service_name = "";
	    $service_version = "";
	    $service_product = "";
	    $service_extrainfo = "";
	    $service_hostname = "";
	    $service_conf = "";
	    $service_ostype = "";
	    //$this->article("XML", $version_resu_xml);
	    if(!empty($version_resu_xml)){
	        if ($this->port2version2check($version_resu_xml)==TRUE){
	    $xml=simplexml_load_string($version_resu_xml);
	    if (isset($xml->host->ports->port->service['name'])) $service_name = $xml->host->ports->port->service['name'];
	    if (isset($xml->host->ports->port->service['version'])) $service_version = $xml->host->ports->port->service['version'];
	    if (isset($xml->host->ports->port->service['product'])) $service_product = $xml->host->ports->port->service['product'];
	    if (isset($xml->host->ports->port->service['extrainfo'])) $service_extrainfo = $xml->host->ports->port->service['extrainfo'];
	    if (isset($xml->host->ports->port->service['hostname'])) $service_hostname = $xml->host->ports->port->service['hostname'];
	    if (isset($xml->host->ports->port->service['conf'])) $service_conf = $xml->host->ports->port->service['conf'];
	    if (isset($xml->host->ports->port->service['ostype'])) $service_ostype = $xml->host->ports->port->service['ostype'];
	        }
	    }
	    
	    return array($service_name,$service_version,$service_product,$service_extrainfo,$service_hostname,$service_conf,$service_ostype);
	}
	
	
	public function port2version2check(string $xml):bool{
	    //$this->ssTitre(__FUNCTION__);
	    if (stristr("</nmaprun>",$xml)===FALSE) return TRUE;
	    else {$this->log2error("No End Tag nmaprun");return FALSE ;}
	}
	
	public function port2version(){
	    //$this->ssTitre(__FUNCTION__);
	    $sql_r_1 = "SELECT ".__FUNCTION__." FROM ".__CLASS__." WHERE $this->port2where  AND ".__FUNCTION__." IS NOT NULL";
	    if ($this->checkBD($sql_r_1) ) {
	        $xml = base64_decode($this->req2BD4out(__FUNCTION__,__CLASS__,"$this->port2where "));
	        //$this->port2version4run($xml);
	        //echo $xml;
	        return $xml;
	    }
	    else {

	        $flag_ok = FALSE;
	  while ($flag_ok==FALSE){
	$query = "echo '$this->root_passwd' | sudo -S nmap -n -Pn -sV --version-all $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
	$xml = $this->req_ret_str($query);
	if ($this->port2version2check($xml)==TRUE){
	    $flag_ok = TRUE;
	}
	$this->pause();
	        }
    
    //echo $xml;
    
	$result = base64_encode($xml);
	return base64_decode($this->req2BD4in(__FUNCTION__,__CLASS__,"$this->port2where ",$result));
	
	    }
	}
	
	public function port4service(){
	    $this->titre(__FUNCTION__);
	    echo $this->port2version();	    
	}
	

	public function port2fake($version_resu):bool{
		$this->ssTitre(__FUNCTION__);
		$resu = array();
		$resu2 = array();
		$resu3 = array();
		if (empty($version_resu)) return FALSE;

		if(preg_match("/".$this->port."\/(?<protocol>\w+)([[:space:]]{1,})filtered([[:space:]]{1,})(?<service>\w+)([[:space:]]{1,})/", $version_resu,$resu));
		{
			if (isset($resu['service']))
			    if (!empty($resu['service'])) {$this->rouge("Firewall SERVICE");return FALSE;}
		}
		if(preg_match("/".$this->port."\/..p([[:space:]]{1,})closed([[:space:]]{1,})(?<service>[[:print:]]+)/", $version_resu,$resu2));
		{
		    if (isset($resu2['service'])) {$this->rouge("Fake SERVICE");return FALSE;}
		}
		if(preg_match("/".$this->port."\/..p([[:space:]]{1,})open([[:space:]]{1,})(?<service>[[:print:]]+)/", $version_resu,$resu3));
		{
			if (isset($resu3['service'])) {
			    $this->ip2os4arch($resu3['service']);
				return TRUE;
			}
		}
		
		if(preg_match("/".$this->port."\/..p([[:space:]]{1,})open|filtered([[:print:]]{0,})([[:space:]]{1,})(?<service>[[:print:]]+)/", $version_resu,$resu3));
		{
		    if (isset($resu2['service'])) {return TRUE;}
		}
		return TRUE;
	}
	
	public function port4type8xml(string $version_resu_xml):array{
	    $this->ssTitre(__FUNCTION__);
	    $service_name = "";
	    $service_version = "";
	    $service_product = "";
	    $service_extrainfo = "";

	    $xml=simplexml_load_string($version_resu_xml);
	    $this->article("Hosts", count($xml->children()));
	    
	    if (isset($xml->host->ports->port->service['name'])) $service_name = $xml->host->ports->port->service['name'];
	    if (isset($xml->host->ports->port->service['version'])) $service_name = $xml->host->ports->port->service['version'];

	    
	    $this->article("SERVICE",$service_name);
	    $this->article("VERSION",$service_version);
	    $this->pause();
	    return array($service_name,$service_version);
	}
	

	public function port4type8raw(string $version_resu):array{
		$this->ssTitre(__FUNCTION__);
		$service_name = "";
		$service_version = "";
		$resu0 = array();

		//var_dump($version_resu);$this->pause();
		if (empty($version_resu)) return array($service_name,$service_version); // ([[:print:]]\w+)
		if(preg_match("#(?P<port>[[:digit:]]\d+)/(?P<protocol>[[:print:]]\w+)([[:space:]]{1,})open([[:space:]]{1,}+)(?P<service>[a-zA-Z0-9_\-]{1,})([[:space:]]{0,})(?P<version>[[:print:]]{0,})#", $version_resu,$resu0));
		{
		    //var_dump($resu0);$this->pause();
			if (isset($resu0['service'])) {$service_name = trim($resu0['service']);}
			if (isset($resu0['version'])) {$service_version = trim($resu0['version']);}
		}
		
		if(preg_match("#(?P<port>[[:digit:]]\d+)/(?P<protocol>[[:print:]]\w+)([[:space:]]{1,})open\|filtered([[:space:]]{1,}+)(?P<service>[a-zA-Z_\-]{1,})([[:space:]]{0,})(?P<version>[[:print:]]{0,})#", $version_resu,$resu0));
		{
		    //var_dump($resu0);$this->pause();
		    if (isset($resu0['service'])) {$service_name = trim($resu0['service']);}
			if (isset($resu0['version'])) {$service_version = trim($resu0['version']);}
		}
		//var_dump($resu0);$this->pause();
		//$str_replace = array("|","`","'","$","\n\n\n",";","/","\\");
		$service_version = str_replace($this->clean_indb, "", $service_version);
		$this->article("SERVICE",$service_name);
		$this->article("VERSION",$service_version);
		$this->pause();
		return array($service_name,$service_version);
	}
	
	
	

	
	public function port4pentest(){
	    
	    $result = "";
	    $this->gtitre(__FUNCTION__);
		
	        
	    
	        $service = new SERVICE($this->stream,$this->eth,$this->domain,$this->ip,$this->port,$this->protocol);
	    $service->poc($this->flag_poc);

	    
	    if ($service->protocol==='T') {
	        if ($service->tcp2open($service->ip, $service->port)===FALSE){
	            return $this->log2error("Port Not Open, Maybe User Desktop OR Server using redondancy in Cloud");
	        }
	    }
	    

			$this->pause();
			
			
			switch ($this->port)
			{
			
				
				
				case 21 :
				case 990 :
				    $result .= $service->service2ftp();$this->pause();
					break ;
					
				case 22 :
				    $result .= $service->service2ssh();$this->pause();
					break;						
					
				case 23 :
				    $result .= $service->service2telnet();$this->pause();
					break ;
					
				case 25 :
				case 465 :
				case 587 :
				    $result .= $service->service2smtp();$this->pause();
					break ;
					
				case 53 :
				case 5353 :
				    $result .= $service->dns4service($this->ip);$this->pause();
					break ;
					
				case 67 :
				case 68 :
				    $result .= "dhcp";$this->pause();
					break ;		
					
				case 69 :
				    $result .= $service->service2tftp();$this->pause();
					break ;	
					
				case 79 :
				    $result .= $service->service2finger();$this->pause();
					break ;	
					
					
				case 443 :
				case 80 :
				case 280 :				
				case 591 :
				case 593 :
				case 8000 :
				case 8008 :
				case 8080 :
				case 8443 :
				    $result .= $service->service2web();$this->pause();
					break ;
					
				case 110 :
				case 995 :
				    $result .= $service->service2pop3();$this->pause();
					break ;
					
				case 113 :
				    $result .= $service->service2ident();$this->pause();
				    break ;
				    

				case 1025 :
				case 2049 :
				    $result .= $service->service2nfs();$this->pause();
					break ;
						
				case 143 :
				case 993 :
				    $result .= $service->service2imap();$this->pause();
					break ;
				
				case 111 :
				    $result .= $service->service2rpc();$this->pause();
				    $result .= $service->service2nfs();$this->pause();
	               break ;
	               
				case 135 :					
				case 137 :
				case 138 :                    
				case 139 :
				case 445 :
				    $result .= $service->service2netbios();$this->pause();
				    $result .= $service->service2smb();$this->pause();
					break ;

				case 161 :
				    $result .= $service->service2snmp();$this->pause();
					break ;
					
				case 389 :
				case 636 :
				case 3268 :
				case 11711 :
				    $result .= $service->service2ldap();$this->pause();
					break ;
					
				case 443 :
				    $result .= $service->service2https();$this->pause();
					break ;

				case 500 :
				    $result .= $service->service2vpn();$this->pause();
					break ;
					
				case 513 :
				    $result .= $service->service2rlogin();$this->pause();
					break ;
					
				case 514 :
				    $result .= $service->service2shell();$this->pause();
					break ;
					
				case 523 :
				    $result .= $service->service2db2();$this->pause();
					break;
					
				case 50000 :
				    $result .= $service->service2drda();$this->pause();
					break;
										
				case 548 :
				    $result .= $service->service2afp();$this->pause();
					break ;
					
				case 623 :
				    $result .= $service->service2ipmi();$this->pause();
				    break ;
				    
				case 873 :
				    $result .= $service->service2rsync();$this->pause();
					break ;
				
				case 902 :
				    $result .= $service->service2vmauth();$this->pause();
					break ;
									
				case 1080 :
				    $result .= $service->service2sock();$this->pause();
					break ;
					
				case 1433 :
				case 27900 :
				    $result .= $service->service2mssql();$this->pause();
					break ;

				case 1521 :
				    $result .= $service->service2oracle();$this->pause();
					break ;
					
				case 1524 :
				    $result .= $service->service2shell();$this->pause();
					break ;
					
				case 2002 :
				    $result .= $service->service2rpcap();$this->pause();
					break ;
					
				case 2010 :
				    $result .= $service->service2jdwp();$this->pause();
					break ;						
					
				case 2049 :
				    $result .= $service->service2nfs();$this->pause();
					break ;					
					
				case 2050 :
				    $result .= $service->service2domcon();$this->pause();
					break ;	
		
				case 3260 :	
				    $result .= $service->service2iscsi();$this->pause();
					break ;					
					
				case 3306 :
				    $result .= $service->service2mysql();$this->pause();
					break ;
					
				case 3389 :
				    $result .= $service->service2rdp();$this->pause();
					break ;	
					
				case 4569 :
				    $result .= $service->service2iax2();$this->pause();
					break ;
					
				case 5038 :
				    $result .= $service->service2asterisk();$this->pause();
					break ;
					
				case 5060 :
				case 5061 :
				    $result .= $service->service2sip();$this->pause();
					break ;
						

					
				case 5432 :
				case 5433 :
				    $result .= $service->service2pgsql();$this->pause();
					break ;
					
				case 5631 :
				    $result .= $service->service2pcanywhere();$this->pause();
					break ;
					
				case 5803 :
				case 5802 :
				case 5801 :
				case 5800 :					
				case 5903 :
				case 5902 :
				case 5901 :
				case 5900 :
				    $result .= $service->service2vnc();$this->pause();
					break ;

					
				case 5984 :
				    $result .= $service->service2couchdb();$this->pause();
					break ;
				
				case 6000 :
				    $result .= $service->service2x11();$this->pause();
					break;
					
				case 5985 :
				case 5986 :
				    $result .= $service->service2winrm();$this->pause();
				    break;
				    
				case 6379 :	
				    $result .= $service->service2redis();$this->pause();
					break ;
					
				case 8009 :
				    $result .= $service->service2ajp();$this->pause();
					break ;
					
				case 9088 :
				    $result .= $service->service2informix();$this->pause();
					break ;					
					
				case 9160 :
				    $result .= $service->service2cassandra();$this->pause();
					break ;

					    
				case 27017 :
				    $result .= $service->service2mongodb();$this->pause();
					break ;
								
			
				default: 
				    $result .= $service->service4switch();$this->pause();
					break ;
			}


	
		echo $result;
		return $result;

	    
	}
	
	public function port2os4ttl(){
	    $this->ssTitre(__FUNCTION__);
	    /*
	    TTL Fingerprinting
Operating System 	TTL Size
Windows 	128
Linux 	64
Solaris 	255
Cisco / Network 	255
	     */

	}


	

	
	


	public function port2severity(string $severity){
	    $this->ssTitre(__FUNCTION__);
	    $severity = trim($severity);
	    return $this->req2BD(__FUNCTION__,__CLASS__,"$this->port2where",$severity);
	}
	
	public function port2refs(string $severity){
	    $this->ssTitre(__FUNCTION__);
	    $severity = trim($severity);
	    return $this->req2BD(__FUNCTION__,__CLASS__,"$this->port2where",$severity);
	}
	
	public function port2confirmed(string $severity){
	    $this->ssTitre(__FUNCTION__);
	    $severity = trim($severity);
	    return $this->req2BD(__FUNCTION__,__CLASS__,"$this->port2where",$severity);
	}
	
	public function port2resolution(string $severity){
	    $this->ssTitre(__FUNCTION__);
	    $severity = trim($severity);
	    return $this->req2BD(__FUNCTION__,__CLASS__,"$this->port2where",$severity);
	}
	
	public function port2status(string $severity){
	    $this->ssTitre(__FUNCTION__);
	    $severity = trim($severity);
	    return $this->req2BD(__FUNCTION__,__CLASS__,"$this->port2where",$severity);
	}
	
	public function port2policy_violation(string $severity){
	    $this->ssTitre(__FUNCTION__);
	    $severity = trim($severity);
	    return $this->req2BD(__FUNCTION__,__CLASS__,"$this->port2where",$severity);
	}
		
	
	
}



?>