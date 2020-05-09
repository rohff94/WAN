<?php 



/*
   auxiliary/gather/corpwatch_lookup_id                                                normal     CorpWatch Company ID Information Search
   auxiliary/gather/corpwatch_lookup_name                                              normal     CorpWatch Company Name Information Search
   post/multi/gather/ping_sweep
 */
class DOMAIN extends ETH{


	var $domain;
	var $tab_dns ;
	var $domain2id ;
	var $domain2where ;
	
	var $path_theHarvester ;
	var $path_sublist3r ;
	var $path_fping ;
	var $path_nmap ;
	var $path_whois ;
	var $path_dig ;
	var $path_nslookup;


	public function __construct($stream,$eth,$domain) {
	    $this->domain = trim($domain);	
	    

		//$this->domain = $this->req_ret_str("echo '$this->host' | sed \"s/\.$//g\" | grep -Po -i \"[0-9a-z]{1,}\.[0-9a-z]{2,5}\$\" ");
	    exec("echo '$this->domain' | grep -Po -i \"[0-9a-z_\-]{1,}\.[a-z]{2,5}$\" ",$tmp);
	    //var_dump($tmp);$this->pause();
		if(!isset($tmp[0])) $this->domain = "";
		else $this->domain = $tmp[0] ;

			
		parent::__construct($stream,$eth);
		$this->domain2where = "id8eth = '$this->eth2id' AND domain = '$this->domain' ";
		
		
		if(!empty($this->domain)){
		    
		$sql_r = "SELECT domain FROM ".__CLASS__." WHERE $this->domain2where ";
		if (!$this->checkBD($sql_r)) {
			$sql_w = "INSERT  INTO ".__CLASS__." (id8eth,domain) VALUES ('$this->eth2id','$this->domain'); ";
			$this->mysql_ressource->query($sql_w);
			echo $this->note("Working on DOMAIN:$this->domain for the first time");
		}

		
		$sql_r = "SELECT id FROM ".__CLASS__." WHERE $this->domain2where ";
		$this->domain2id = $this->mysql_ressource->query($sql_r)->fetch_assoc()['id'];
		
		}
		
		
	}

	
	public function domain2dot4service(){
	    $this->gtitre(__FUNCTION__);
	    // twopi 
	}
	
	
	public function domain2dot(){
	    $this->gtitre(__FUNCTION__);
	    // twopi 
	    
	    $file_output = "/tmp/$this->eth.$this->domain.dot";
	    $color_dns = "steelblue";$color_host = "steelblue";$color_domain = "steelblue";$color_arrow = "steelblue";
	    
	    $domain2dot_header = "digraph structs {
	label = \"".__FUNCTION__.":$this->domain\";
			graph [rankdir = \"LR\" layout = dot];
			node [fontsize = \"16\" shape = \"plaintext\"];
			edge [penwidth=2.0 ];";
	    /*
	    <TR><TD>IPs</TD><TD PORT=\"domain2ip\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->domain2ip()))."</TD></TR>
		<TR><TD>HOSTS</TD><TD PORT=\"domain2host\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->domain2host()))."</TD></TR>
		<TR><TD>DOMAIN WHOIS</TD><TD PORT=\"domain2whois\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->domain2whois()))."</TD></TR>
		
	     */
	    $domain2dot_domain = "
			\"$this->domain\" [label=<<TABLE BORDER=\"0\" CELLBORDER=\"1\" CELLSPACING=\"0\">
		<TR><TD><IMG SRC=\"$this->dir_img/ico/domain.png\" /></TD><TD PORT=\"domain\" bgcolor=\"$color_domain\">$this->domain</TD></TR>
		<TR><TD>DNS</TD><TD PORT=\"domain2ns\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->domain2ns()))."</TD></TR>
		<TR><TD>EMAIL</TD><TD PORT=\"domain2mail\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->domain2mail()))."</TD></TR>
				</TABLE>>];
				";
	    
	    $domain2dot_footer = "
		}";
	    
	    $domain2dot = $domain2dot_header.$domain2dot_domain.$domain2dot_footer;
	    $domain2dot4body = $domain2dot_domain;
	    //system("echo '$domain2dot' > $file_output ");
	    //$this->requette("gedit $file_output");
	    $this->dot4make($file_output,$domain2dot);
	    return $domain2dot4body;
	}
	
	
	
	public function domain2services(string $service_name,string $protocol_search,string $fonction2run){

	    $id8ports = array();
	    $id8ips = array();
	    $id8services = array();
	    $fonction2run = trim($fonction2run);
	    
	    $this->article("Service Target", $service_name);
	    $this->article("Function 2 run", $fonction2run);
	    

	    
	    $sql_r = "SELECT id FROM IP WHERE id8domain = '$this->domain2id'  ";
	    //echo "$sql_r\n";
	    $req = $this->mysql_ressource->query($sql_r);
	    while ($row = $req->fetch_assoc()) {
	        $id8ips[] = $row['id'];
	    }
	    
	    $id8ips_search = implode(",", $id8ips);
	    //$this->article("ID8IPS", $this->tab($id8ips));
	    
	    $sql_r = "SELECT id FROM PORT WHERE id8ip IN ($id8ips_search)  ";
	    //echo "$sql_r\n";
	    $req = $this->mysql_ressource->query($sql_r);
	    while ($row = $req->fetch_assoc()) {
	        $id8ports[] = $row['id'];
	    }
	    //$this->article("ID8PORTS", $this->tab($id8ports));
	    
	    $id8ports_search = implode(",", $id8ports);
	    $sql_r = "SELECT id8port FROM SERVICE WHERE service2name LIKE \"%$service_name%\" AND id8port IN ($id8ports_search) ";
	    //echo "$sql_r\n";
	    $req = $this->mysql_ressource->query($sql_r);
	    while ($row = $req->fetch_assoc()) {
	        $id8services[] = $row['id8port'];
	    }
	    $this->article("ID8SERVICE", $this->tab($id8services));
	    $max = count($id8services);
	    
	    $file_path = "/tmp/$this->eth.$this->domain.services.$service_name";
	    $fp = fopen($file_path, 'w+');
	    
	    for ($i=0;$i<$max;$i++){
	        $this->article("DOMAIN8SERVICES $i/$max", $id8services[$i]);
	    $sql_r = "SELECT id8ip,port,protocol FROM PORT WHERE id = '$id8services[$i]' ";
	    //echo "$sql_r\n";
	    $req = $this->mysql_ressource->query($sql_r);

	    while ($row = $req->fetch_assoc()) {
	        $id8ip = $row['id8ip'];
	        $sql_r = "SELECT ip FROM IP WHERE id = '$id8ip'";
	        $ip = $this->mysql_ressource->query($sql_r)->fetch_assoc()['ip'];
	        $port = $row['port'];
	        $protocol = $row['protocol'];
	        $this->article("IP", $ip);
	        $this->article("PORT", $port);
	        $this->article("PROTOCOL", $protocol);
	        
	        $data = "$ip $port $protocol";
	        $data = $data."\n";
	        fputs($fp,$data);
	
	        }
	        
	    }
	    fclose($fp);
	    
	    $query = "gedit $file_path";
	    //$this->requette($query);
	    
	    $runs = file($file_path);
	    //var_dump($runs);
	    
	    foreach ($runs as $run){
	        var_dump($run);
	        if (!empty($run))  list($ip, $port, $protocol) = explode(" ", $run);
	        $protocol = trim($protocol);
	        $this->article("IP", $ip);
	        $this->article("PORT", $port);
	        $this->article("PROTOCOL", $protocol);
	        $this->article("FUNCTION", $fonction2run);
	    if (!empty($protocol_search)){
	        if ($protocol_search===$protocol){
	            $this->note("found protocol $protocol_search");
	            $obj_port = new PORT($this->stream,$this->eth, $this->domain, $ip, $port, $protocol_search);
	            $obj_port->poc($this->flag_poc);
	            echo $obj_port->$fonction2run();
	            $this->pause();
	        }
	    }
	    else {
	        $obj_port = new PORT($this->stream,$this->eth, $this->domain, $ip, $port, $protocol);
	        $obj_port->poc($this->flag_poc);
	        echo $obj_port->$fonction2run();
	    }
	    }
	    
	}
	  
	public function domain4all(){
	    $this->gtitre(__FUNCTION__);
	    $this->domain4info();
	    $this->domain4service();
	    $this->domain4pentest();
	}
	
	
	public function domain2ip8db(): array{
	    $sql_r = "SELECT ip FROM IP WHERE id8domain = '$this->domain2id'  ";
	    //echo "$sql_r\n";
	    $req = $this->mysql_ressource->query($sql_r);
	    $tab_ips = array();
	    while ($row = $req->fetch_assoc()) {
	        $tab_ips[] = $row['ip'];
	    }
	    return $tab_ips;
	}
	public function domain4pentest(){
	    $this->gtitre(__FUNCTION__);
	    
	    $tab_ips = $this->domain2ip8db();
	    $file_path = "/tmp/$this->eth.$this->domain.ip4pentest";
	    $fp = fopen($file_path, 'w+');
	    foreach ($tab_ips as $ip){
	        $ip = trim($ip);
	        if(!empty($ip) ){
	            $data = "$this->eth $this->domain $ip ip4pentest FALSE";
	            $data = $data."\n";
	            fputs($fp,$data);
	        }
	    }
	    fclose($fp);
	    
	    $this->requette("wc -l  $file_path");$this->pause();
	    $this->requette("cat  $file_path | parallel --progress -k php pentest.php IP {} "); // -j$max_iter

	}
	
	
	public function domain2dot4host(){
	    $result = "";
	    $this->titre(__FUNCTION__);
	    $dot = "";
	    $ips = array();
	    $file_output = "/tmp/$this->domain.".__FUNCTION__.".dot";
	    // http://www.yosbits.com/wordpress/?page_id=6182
	    $host2dot_header = "digraph ".__FUNCTION__." {
	    graph [rankdir = \"LR\",layout = twopi]
        node [shape = circle,style = filled,color = grey,fixedsize=true]
        node [fillcolor = \"#65d1f9\",label = \"$this->domain\"]\n\"$this->domain\"\n";
	    
	    $sql_r = "SELECT distinct(ip2host) FROM IP WHERE id8domain = '$this->domain2id' AND ip2host IS NOT NULL ";
	    echo "$sql_r\n";
	    $req = $this->mysql_ressource->query($sql_r);
	    while ($row = $req->fetch_assoc()) {
	        $ip2host = $row['ip2host'];
	        $obj_host = new HOST($this->stream,$this->eth, $this->domain, $ip2host);
	        $dot .= "node [fillcolor = \"#f9f765\",label = \"$obj_host->host\"]\n\"$obj_host->host\"\n";
	        $dot .= "edge [color = grey,len=2]\n\"$this->domain\" -> \"$obj_host->host\"\n";
	        $dot .= $obj_host->host2dot4port();
	    }
	    
	    
	    $host2dot_footer = "\n}\n";
	    $host2dot = $host2dot_header.$dot.$host2dot_footer;
	    $host2dot4body = $dot;
	    
	    $this->dot4make($file_output,$host2dot);
	    $this->dot2xdot($file_output);
	    //$this->requette("gedit $file_output");
	    return $host2dot4body;
	}
	
	
	public function domain4service(){
	    $this->gtitre(__FUNCTION__);
	    $tab_ips = $this->domain2ip8db();
	    $file_path = "/tmp/$this->eth.$this->domain.ip4service";
	    $fp = fopen($file_path, 'w+');
	    foreach ($tab_ips as $ip){
	        $ip = trim($ip);
	        if(!empty($ip) ){
	            $data = "$this->eth $this->domain $ip ip4service FALSE";
	            $data = $data."\n";
	            fputs($fp,$data);

	        }
	    }
	    fclose($fp);
	    
	    $this->requette("wc -l  $file_path");$this->pause();
	    //$this->requette("cat  $file_path | parallel --progress -k php pentest.php IP {} "); // -j$max_iter

	    foreach ($tab_ips as $ip){
	        $ip = trim($ip);
	        if( (!empty($ip)) && (!$this->ip4priv($ip)) ){
	            $query = "php pentest.php IP \"$this->eth $this->domain $ip ip4service FALSE\" ";
	            $this->requette($query);
	            $obj_ip = new IP($this->stream,$this->eth, $this->domain, $ip);
	            $obj_ip->poc($this->flag_poc);
	            $obj_ip->ip4service();
	        }
	    }
	}
	
	
	
	public function domain2host2check4info(string $host_check,int $iter){
	    $this->ssTitre(__FUNCTION__);
	    $results = array();
	    $host_check = trim($host_check);
	    
	    $iter = intval($iter);
	    $this->article("Host2CHECK", $host_check);
	    if (preg_match("/(?<hostname>[0-9a-z_\-\.]{1,})(?<number>[0-9]{1})\.$this->domain/",$host_check,$results))
	    {
	        $host_filtred = "";
	        $hostname = $results['hostname'];
	        $number = $results['number'];
	        for ($i=0;$i<$iter;$i++){
	            $host_filtred = "$hostname$i.$this->domain";
	            $this->article("HOST8DOMAIN CHECK", $host_filtred);
	            $this->pause();
	            $obj_host_filtred = new HOST($this->stream,$this->eth, $this->domain,$host_filtred);
	            //$obj_host_filtred->poc($this->flag_poc);
	            $obj_host_filtred->host4info();$this->pause();
	            
	        }
	        
	    }
	}
	

	
	

	public function domain2maltego(){
		$this->ssTitre(__FUNCTION__);
		$this->cmd("localhost", "maltego_chlorine_ce");
		$this->pause();
	}
	
	public function domain2file(){
	    $this->titre(__FUNCTION__);
	    $result = "";
	    $sql_r_1 = "SELECT ".__FUNCTION__." FROM ".__CLASS__." WHERE $this->domain2where AND ".__FUNCTION__." IS NOT NULL";
	    if ($this->checkBD($sql_r_1) ) return  base64_decode($this->req2BD4out(__FUNCTION__,__CLASS__,$this->domain2where));
	    else {
	        $result .= $this->domain2file2search4doc();
	        $result .= $this->domain2file2search4pdf();
	        
	        $result = base64_encode($result);
	        return base64_decode($this->req2BD4in(__FUNCTION__,__CLASS__,$this->domain2where,$result));
	    }
	}
	
	public function domain2host(): array{
	    // https://github.com/s0md3v/ReconDog
	    // https://kalilinuxtutorials.com/subscraper/
	    // python3 subscraper.py example.com
	$this->titre(__FUNCTION__);
	$tab_hosts = array();
	$file_path = "$this->dir_tmp/$this->domain.search";
	if(!file_exists($file_path)){
	    $search = $this->domain2search();
	    $this->str2file($this->stream,$search, $file_path);
	}
	$query = "cat $file_path | grep -i -Po \"([0-9a-z\-_]{1,}\.)+$this->domain\" | tr '[:upper:]' '[:lower:]' | sort -u ";
	exec($query,$tab_hosts);
	$tab_hosts = array_filter($tab_hosts);
	$this->article("ALL HOSTs", $this->tab($tab_hosts));
	return $tab_hosts;
	}
	
	public function domain2search(){
	    $this->titre(__FUNCTION__);
	    $result = "";
	    $tab_cidr = array();
	    $tmp = array();
	    $sql_r_1 = "SELECT ".__FUNCTION__." FROM ".__CLASS__." WHERE $this->domain2where AND ".__FUNCTION__." IS NOT NULL";
	    if ($this->checkBD($sql_r_1) ) return  base64_decode($this->req2BD4out(__FUNCTION__,__CLASS__,$this->domain2where));
	    else {
	    //$result .= $this->domain2search4harvest();$this->pause();
	    $result .= $this->domain2search4sublister();$this->pause();
	    $result .= $this->domain2search4web();$this->pause();
	    $result .= $this->domain2ns();$this->pause();
	    //
	    $result = str_replace($this->clean_indb, "", $result);
	    exec("echo '$result' | grep -Po \"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\" | grep -Po \"^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\" | grep -v '192.168' | grep -v '127.0' | sort -u ",$tmp);
	    //echo $this->tab($tab_cidr);
	    $size = count($tmp);
	    if($size<20){
	        //$dico = $this->domain2dico();echo $dico;     $result .= $dico ;$this->pause();
	        exec("echo '$result' | grep -Po \"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\" | grep -Po \"^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\" | grep -v '192.168' | grep -v '127.0' | sort -u ",$tab_cidr);
	        $size = count($tab_cidr);
	        if($size<50){
	    for ($i=0;$i<$size;$i++){
	        $cidr = trim($tab_cidr[$i]);
	        
	        if (!empty($cidr)){
	            $obj_cidr = new CIDR($this->stream,$this->eth,$cidr);
                $result .=	$obj_cidr->cidr2ns();
	        }
	    }

	    }
	    }
	    $result = base64_encode($result);
	    return base64_decode($this->req2BD4in(__FUNCTION__,__CLASS__,$this->domain2where,$result));
	    
	    }
	    
	}
	
	public function domain2ip():array{
		$this->titre(__FUNCTION__);
		$file_path = "$this->dir_tmp/$this->domain.search";
		if(!file_exists($file_path)){
		    $search = $this->domain2search();
		    $this->str2file($search, $file_path);
		}
		$query = "cat $file_path | grep -Po \"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\" | sort -u ";
		return array_filter($this->req_ret_tab($query));
	}
	
	public function domain2search4web(){
	    $this->titre(__FUNCTION__);
	    // https://dnsdumpster.com/
	    // https://www.nmmapper.com/sys/tools/subdomainfinder/
	    $result = "";
	    $result .= $this->domain2search4web8hackertarget();$this->pause();
	    //$result .= $this->domain2search4web8spyse();$this->pause();
	    $result .= $this->domain2search4web8netcraft();$this->pause();
	    $result .= $this->domain2search4web8censys();$this->pause();
	    return $result ;
	}
	
	public function domain2search4web8hackertarget(){
	    $this->ssTitre(__FUNCTION__);
		$query = "wget -qO- \"https://api.hackertarget.com/hostsearch/?q=$this->domain\" --timeout=60 --tries=2 --no-check-certificate | grep '\.$this->domain' | sed 's/ /\\n/g' | sort -u";
		return $this->req_ret_str($query);
	}
	
	
	public function domain2search4web8censys(){
	    $this->ssTitre(__FUNCTION__);
	    $query = "wget -qO- \"https://censys.io/ipv4?q=$this->domain\" --timeout=60 --tries=2 --no-check-certificate | grep '\.$this->domain' | grep -Po -i \"([a-z0-9\-\_\.]{1,})\.$this->domain\" | sed 's/ /\\n/g' | sort -u";
	    return $this->req_ret_str($query);
	}
	
	public function domain2search4web8netcraft(){
	    $this->ssTitre(__FUNCTION__);
	    $query = "wget -qO- \"https://searchdns.netcraft.com/?restriction=site+contains&host=$this->domain\" --timeout=60 --tries=2 --no-check-certificate  | grep '\.$this->domain' | grep -Po -i \"([a-z0-9\-\_\.]{1,})\.$this->domain\" | sed 's/ /\\n/g' | sort -u";
	    return $this->req_ret_str($query);
	}
	
	public function domain2search4web8spyse(){
	    $this->ssTitre(__FUNCTION__);
	    $query = "wget -qO- \"https://spyse.com/search/subdomain?q=$this->domain\" --timeout=60 --tries=2 --no-check-certificate  | grep '\.$this->domain' | grep -Po -i \"([a-z0-9\-\_\.]{1,})\.$this->domain\" | sed 's/ /\\n/g' | sed 's#c-domain__target--##g' | sort -u";
	    return $this->req_ret_str($query);
	}
	
	
	
	
	public function domain2search4sublister(){
	    $this->ssTitre(__FUNCTION__);
		$query = "python3 /opt/sublist3r/sublist3r.py -d $this->domain --no-color  2> /dev/null  | grep -Po -i \"([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})|([0-9a-z\-\_\.]{1,}\.$this->domain)\" | sort -u ";
		return $this->req_ret_str($query);		
	}
	
	


	
	
	public function domain2file2search4pdf(){
	    $result = "";
	    $this->ssTitre(__FUNCTION__);
	    $query = "";

	    $result .= $this->req_ret_str($query);
	    return $result;
		
	}
	
	public function domain2file2search4doc(){
	    $result = "";
	    $this->ssTitre(__FUNCTION__);
	    $query = "";
	    $result .= $this->cmd("localhost",$query);
	    $result .= $this->req_ret_str($query);
	    return $result;
	}
		


	public function domain2search4harvest(){
	    $this->ssTitre(__FUNCTION__);
		$query = "python3.8 /opt/theharvester/theHarvester.py -d $this->domain -l 200 -b all -v 2> /dev/null | grep -E \"([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|[0-9a-zA-Z\-_]{1,}\.$this->domain)\"  | sort -u ";
		return $this->req_ret_str($query);
	}
	


	
	
	public function domain2mail4msf(){
	    $this->ssTitre(__FUNCTION__);
		system("echo  \"db_status\nuse gather/search_email_collector\nset DOMAIN $this->domain\nrun\nexit\n\" > $this->dir_tmp/".__FUNCTION__.".rc");
		$query = "msfconsole -q -r $this->dir_tmp/".__FUNCTION__.".rc | grep -Po -i \"([0-9a-zA-Z\.\-_]{1,})@$this->domain\" ";
		return $this->req_ret_str($query);
	}

	public function domain2mail4harvest(){
	    $this->ssTitre(__FUNCTION__);
		$file_path = "$this->dir_tmp/$this->domain.search";
		if(!file_exists($file_path)){
		    $search = $this->domain2search();
		    $this->str2file($search, $file_path);
		}
		$query = "cat $file_path | grep -Po \"([0-9a-zA-Z\.\-_]{1,})@$this->domain\" | sort -u ";
		return $this->req_ret_str($query);

	}

	
	public function domain2mail(){
	    $this->ssTitre(__FUNCTION__);
	    $result = "";
	    $sql_r_1 = "SELECT ".__FUNCTION__." FROM ".__CLASS__." WHERE $this->domain2where AND ".__FUNCTION__." IS NOT NULL";
	    if ($this->checkBD($sql_r_1) ) return  base64_decode($this->req2BD4out(__FUNCTION__,__CLASS__,$this->domain2where));
	    else {
    	$result .= $this->domain2mail4msf()."\n";
		$result .= $this->domain2mail4harvest()."\n";
		$tab_rst = array();
		$command = "echo '$result' | grep -Po \"([0-9a-zA-Z\.\-_]{1,})@$this->domain\" | sort -u";
		exec($command,$tab_rst);
		$tab_rst = array_filter($tab_rst);
		$result .= $this->tab($tab_rst);
		
		$result = base64_encode($result);
		return base64_decode($this->req2BD4in(__FUNCTION__,__CLASS__,$this->domain2where,$result));
	}
	}
	
	public function dns4service(string $dns){
	    $result = "";
	    $tmp = array();
	    $dns = trim($dns);
	        $this->note(" A Records - An address record that allows a computer name to be translated to an IP address.
				Each computer has to have this record for its IP address to be located via DNS.");
	        $query = "dig @$dns $this->domain A +short | grep -v '^;' ";
	        $result .= "$query\n";
	        exec($query,$tmp);$result .= $this->tab($tmp);unset($tmp);
	        $query = "dig @$dns $this->domain AAAA +short | grep -v '^;' ";
	        $result .= "$query\n";
	        exec($query,$tmp);$result .= $this->tab($tmp);unset($tmp);
	        $query = "dig @$dns $this->domain AXFR +short | grep -v '^;' ";
	        $result .= "$query\n";
	        exec($query,$tmp);$result .= $this->tab($tmp);unset($tmp);
	        $query = "dig @$dns $this->domain CNAME +short | grep -v '^;' ";
	        $result .= "$query\n";
	        exec($query,$tmp);$result .= $this->tab($tmp);unset($tmp);
	        $query = "dig @$dns $this->domain HINFO +short | grep -v '^;' ";
	        $result .= "$query\n";
	        exec($query,$tmp);$result .= $this->tab($tmp);unset($tmp);
	        $query = "dig @$dns $this->domain MX +short | grep -v '^;' ";
	        $result .= "$query\n";
	        exec($query,$tmp);$result .= $this->tab($tmp);unset($tmp);
	        $query = "echo '$this->root_passwd' | sudo -S nmap --script dns-nsid -p 53 $dns -Pn -n ";
	        exec($query,$tmp);$result .= $this->tab($tmp);unset($tmp);
	        $query = "nslookup -query=ptr ".gethostbyname($dns)." | grep 'name' | cut -d'=' -f2 | sed \"s/\.$//g\" | tr -d ' ' | grep  -i -Po \"([0-9a-zA-Z_-]{1,}\.)+[a-zA-Z]{1,4}\"  | sort -u  ";
	        $result .= "$query\n";
	        exec($query,$tmp);$result .= $this->tab($tmp);unset($tmp);
	        $query = "dig @$dns $this->domain RP +short | grep -v '^;' ";
	        $result .= "$query\n";
	        exec($query,$tmp);$result .= $this->tab($tmp);unset($tmp);
	        $query = "dig @$dns $this->domain SOA +short | grep -v '^;' ";
	        $result .="$query\n";
	        exec($query,$tmp);$result .= $this->tab($tmp);unset($tmp);
	        $query = "dig @$dns $this->domain SRV +short | grep -v '^;' ";
	        $result .= "$query\n";
	        exec($query,$tmp);$result .= $this->tab($tmp);unset($tmp);
	        
	        
	        $query = "dig @$dns $this->domain TXT +short  ";
	        $result .= "$query\n";
	        exec("$query | grep -v '^;'  | sed 's#/##g'  | sed \"s#\'##g\" | sed 's/\"//g' ",$tmp);

	        $result .= $this->tab($tmp);unset($tmp);
	        $result = str_replace($this->clean_indb, " ", $result);
	    return $result ;
	}
	
	public function  domain2info(){	    
	    $this->article("ID Domain", $this->domain2id);
	    $this->article("Domain", $this->domain);
	}
	
	public function  domain4info(){
	    $this->gtitre(__FUNCTION__);
	    /*
	    $cidr = $this->domain2cidr() ;
	    echo $this->tab($cidr);$this->pause();
	    
	    $mails = $this->domain2mail() ;
	    echo $mails;$this->pause();
	    
	    $files = $this->domain2file() ;
	    echo $files;$this->pause();
	    
	    $traces = $this->domain2trace() ;
	    echo $traces;$this->pause();
	    
	    	    
	    //$result .= $this->domain2asn() ;$this->pause(); // NOT YET 
	    */
	    $whois = $this->domain2whois() ;
	    echo $whois;$this->pause();

	    
	    $hosts = $this->domain2host() ;
	   	    
	    if(!empty($hosts)){
	        
	        $tab_tmp_host = array();
	        
	        $size = count($hosts);
	        for($i=0;$i<$size;$i++){
	            echo "\n\n$i/$size : $hosts[$i] =======================================================\n";
	            $host = $hosts[$i];
	            $obj_host = new HOST($this->stream,$this->eth, $this->domain,$host);
	            $obj_host->poc($this->flag_poc);
	            $obj_host->host4info();
	            
	            $tmp_host = str_replace(".$this->domain","", $host);
	            $tab_tmp_host = explode(".", $tmp_host);
	            if (!empty($tab_tmp_host)){
	                $tab_hosts_check = array_reverse(array_filter($tab_tmp_host));
	                $host_check_tmp = "";
	                foreach ($tab_hosts_check as $prefix_check){
	                    $prefix_check = trim($prefix_check);
	                    $host_check_tmp = "$prefix_check.$host_check_tmp";
	                    $host_check = "$host_check_tmp$this->domain";
	                    $obj_host2 = new HOST($this->stream,$this->eth, $this->domain,$host_check);
	                    $obj_host2->poc($this->flag_poc);
	                    $this->pause();
	                    $obj_host2->host4info();
	                    $this->domain2host2check4info($host_check,10);
	                    $this->pause();
	                }
	            }
	            echo "END $host =====================================================================\n";
	        }
	    }
	}
	
	
	
	
	
	
	public function  domain2ns(){
	    $this->titre(__FUNCTION__);
	    $result = "";
	    $sql_r_1 = "SELECT ".__FUNCTION__." FROM ".__CLASS__." WHERE $this->domain2where AND ".__FUNCTION__." IS NOT NULL";
	    if ($this->checkBD($sql_r_1) ) return  base64_decode($this->req2BD4out(__FUNCTION__,__CLASS__,$this->domain2where));
	    else {
	    $query = "nslookup -query=ns $this->domain | grep '$this->domain' | cut -d'=' -f2 | sed \"s/\.$//g\" ";
	    $tab_dns = $this->req_ret_tab($query);
	    $size = count($tab_dns);
	    if (!empty($tab_dns)){
	        $result .= $this->tab($tab_dns);
	        for($i=0;$i<$size;$i++){
	            
	            $dns = trim($tab_dns[$i]);
	            if (!empty($dns)){
	                $this->article("$i/$size DNS", $dns);
	                $obj_dns = new HOST($this->stream,$this->eth, $this->domain, $dns);
	                $tab_ip_dns = $this->host4ip($obj_dns->host);
	                foreach ($tab_ip_dns as $ip_dns){
	                    $this->article($dns, $ip_dns);
	                    $result .= $this->dns4service($ip_dns);
	                }
	            }
	        }
	    }
	    $result = base64_encode($result);
	    return base64_decode($this->req2BD4in(__FUNCTION__,__CLASS__,$this->domain2where,$result));
	    }
	}
	

	public function domain2trace(){
		$this->ssTitre(__FUNCTION__);
		$query = "dig $this->domain a +trace ";
		
		return $this->req2BD(__FUNCTION__,__CLASS__,$this->domain2where,$query);
	}
	
	public function domain2whois(){
		$this->ssTitre(__FUNCTION__);
		$sql_r_1 = "SELECT ".__FUNCTION__." FROM ".__CLASS__." WHERE $this->domain2where AND ".__FUNCTION__." IS NOT NULL";
		if ($this->checkBD($sql_r_1) ) return  base64_decode($this->req2BD4out(__FUNCTION__,__CLASS__,$this->domain2where));
		else {
		    
		$query = "whois $this->domain | grep ':' | grep -v '#' ";
		$result = $this->req_ret_str($query);
		$result = base64_encode($result);
		return base64_decode($this->req2BD4in(__FUNCTION__,__CLASS__,$this->domain2where,$result));
	}

	}
	
	public function domain2asn(){
		$this->ssTitre(__FUNCTION__);
		
		// https://www.tcpiputils.com/browse/as/33779
		// https://bgpview.io/asn/33779#prefixes-v4
		$query = " ";
		return $this->req2BD(__FUNCTION__,__CLASS__,$this->domain2where,$query);		
	}
	



	
	public function domain2cidr(): array{
	    $this->titre(__FUNCTION__);	    
        $file_path = "$this->dir_tmp/$this->domain.search";
        if(!file_exists($file_path)){
        $search = $this->domain2search();
        $this->str2file($search, $file_path);
        }
        $query = "cat $file_path | grep -Po \"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\" | grep -Po \"^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\" | grep -v '192.168' | grep -v '127.0' | sort -u ";
        return array_filter($this->req_ret_tab($query));
	}
	

	
	public function domain2dico(){
	    $this->titre(__FUNCTION__);
	    $result = "";
	    $sql_r_1 = "SELECT ".__FUNCTION__." FROM ".__CLASS__." WHERE $this->domain2where AND ".__FUNCTION__." IS NOT NULL";
	    if ($this->checkBD($sql_r_1) ) return  base64_decode($this->req2BD4out(__FUNCTION__,__CLASS__,$this->domain2where));
	    else {
			$this->requette("cat $this->dico_word | wc -l ");
			$query = "cat $this->dico_word | parallel --progress -j24  dig +noall {}.$this->domain +answer | grep -v \";;\" ";
			$result .= $this->req_ret_str($query);
		
		$result = base64_encode($result);
		return base64_decode($this->req2BD4in(__FUNCTION__,__CLASS__,$this->domain2where,$result));
		}
		//$query = "nmap --script dns-brute --script-args dns-brute.domain=$this->domain,dns-brute.threads=14,dns-brute.hostlist=$this->dico_word -oX -";
			
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	/*
	
	*   auxiliary/fuzzers/dns/dns_fuzzer                                         normal   DNS and DNSSEC Fuzzer
	auxiliary/gather/dns_bruteforce                                          normal   DNS Brutefoce Enumeration
	auxiliary/gather/dns_cache_scraper                                       normal   DNS Non-Recursive Record Scraper
	auxiliary/gather/dns_info                                                normal   DNS Basic Information Enumeration
	auxiliary/gather/dns_reverse_lookup                                      normal   DNS Reverse Lookup Enumeration
	auxiliary/gather/dns_srv_enum                                            normal   DNS Common Service Record Enumeration
	auxiliary/gather/enum_dns                                                normal   DNS Record Scanner and Enumerator
	auxiliary/scanner/dns/dns_amp                                            normal   DNS Amplification Scanner
	auxiliary/server/dns/spoofhelper                                         normal   DNS Spoofing Helper Service
	auxiliary/server/fakedns                                                 normal   Fake DNS Service
	payload/windows/dns_txt_query_exec
	post/multi/gather/dns_bruteforce                                         normal   Multi Gather DNS Forward Lookup Bruteforce
	post/multi/gather/dns_reverse_lookup                                     normal   Multi Gather DNS Reverse Lookup Scan
	post/multi/gather/dns_srv_lookup
	
	
	https://toolbox.googleapps.com/apps/dig/
	*
	*/	
	
	
	
	

	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
?>
