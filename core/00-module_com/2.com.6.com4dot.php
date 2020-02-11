<?php
class com4dot extends com4bin{
	var $diagram ;
	var $header ;
	var $body ;
	var $footer ;
	var $file_dot ;
	
	var $path_xdot ;



	public function __construct() {
		parent::__construct();
		
	}
	
	
	
	public function cidr2dot($ip){
	    $this->titre(__FUNCTION__);
	    $ip = trim($ip);
	    $cidr2dot_scan = "";
	    $cidr2dot_cidr = "";
	    $cidr2dot_edge = "";
	    $cidr2dot4body = "";
	    
	    $file_output = "$this->dir_tmp/$ip.".__FUNCTION__.".dot";
	    $color_scan = "violet";$color_cidr = "violet";$color_arrow = "violet";
	    $cidr2dot_header = "digraph structs {
	label = \"".__FUNCTION__.":$this->cidr\";
		graph [rankdir = \"LR\" layout = dot];
		node [fontsize = \"16\" shape = \"plaintext\"];
		edge [penwidth=2.0 ];";
	    
	    // <TR><TD>ALIVE HOST ALL</TD><TD PORT=\"cidr2scan\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->cidr2scan()))."</TD></TR>
	    // <TR><TD>ALIVE HOST PORT</TD><TD PORT=\"cidr2scan4port\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->cidr2scan4port()))."</TD></TR>
	    
	    $cidr2dot_cidr .= "
		\"$this->cidr\" [label=<<TABLE BORDER=\"0\" CELLBORDER=\"1\" CELLSPACING=\"0\">
	<TR><TD>CIDR</TD><TD PORT=\"cidr\" bgcolor=\"$color_cidr\">$this->cidr</TD></TR>
	<TR><TD>ALIVE HOST NMAP</TD><TD PORT=\"cidr2scan4nmap\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->cidr2scan4nmap()))."</TD></TR>
	<TR><TD>ALIVE HOST FPING</TD><TD PORT=\"cidr2scan4fping\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->cidr2scan4fping()))."</TD></TR>
		</TABLE>>];
				";
	    
	    $cidr2dot_footer = "
		}";
	    
	    $cidr2dot = $cidr2dot_header.$cidr2dot_cidr.$cidr2dot_edge.$cidr2dot_footer;
	    $cidr2dot4body = $cidr2dot_cidr;
	    //system("echo '$cidr2dot' > $file_output ");
	    //$this->requette("gedit $file_output");
	    $this->dot4make($file_output,$cidr2dot);
	    
	    return $cidr2dot4body;
	    
	}
	

	
	
	public function domain2dot4all(){
	    $this->gtitre(__FUNCTION__);
	    $domain2dot_domain = "";
	    $domain2dot_host = "";
	    $domain2dot_ip = "";
	    $domain2dot_edge = "";
	    
	    $file_output = "$this->dir_tmp/$this->domain.".__FUNCTION__.".dot";
	    $domain2dot_header = "digraph structs {
	label = \"".__FUNCTION__.":$this->domain\";
			graph [rankdir = \"LR\" layout = dot];
			node [fontsize = \"16\" shape = \"plaintext\"];
			edge [penwidth=2.0 ];";
	    
	    $domain2dot_domain .= $this->domain2dot();
	    
	    $host_list = $this->req_ret_str("mysql --user=$this->mysql_login --password=$this->mysql_passwd --database=$this->mysql_database --execute=\"select domain2host from DOMAIN WHERE $this->domain2where\"  2>/dev/null | grep -v 'domain2host' ");
	    $tab_host = explode("\n", $host_list);
	    $count_host = count($tab_host);
	    for ($i=0;$i<$count_host;$i++){
	        $host = trim($tab_host[$i]);
	        $this->titre("$i/$count_host: $host");
	        //$obj_host = new HOST( $host);$domain2dot_host .= $obj_host->host2dot4all();
	    }
	    
	    $tab_ips = $this->req_ret_tab("mysql --user=$this->mysql_login --password=$this->mysql_passwd --database=$this->mysql_database --execute=\"select DISTINCT (host2ip) from HOST where host2domain = '$this->domain'\"  2>/dev/null | grep -Po \"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\" | sort -u ");
	    $count_ips = count($tab_ips);
	    for ($i=0;$i<$count_ips;$i++){
	        $ip = trim($tab_ips[$i]);
	        $this->titre("$i/$count_ips: $ip");
	        if(!empty($ip)) {
	            $obj_ip = new IP( $ip);
	            if (!$this->ip4priv($ip)) $domain2dot_ip .= $obj_ip->ip2dot4all();
	        }
	    }
	    $domain2dot_footer = "
		}";
	    $domain2dot = $domain2dot_header.$domain2dot_domain.$domain2dot_host.$domain2dot_ip.$domain2dot_edge.$domain2dot_footer;
	    $domain2dot4body = $domain2dot_domain.$domain2dot_host.$domain2dot_ip.$domain2dot_edge;
	    
	    $fp = fopen($file_output, 'w+');
	    fputs($fp,$domain2dot);
	    fclose($fp);
	    
	    //system("echo '$domain2dot' > $file_output ");
	    //$this->requette("gedit $file_output");
	    $this->dot2xdot($file_output);
	    return $domain2dot4body;
	}
	
	
	
	public function cidr2dot4all(){
	    $this->titre(__FUNCTION__);
	    $cidr2dot_ip = "";
	    $cidr2dot_scan = "";
	    $cidr2dot_cidr = "";
	    $cidr2dot_edge = "";
	    $cidr2dot4body = "";
	    
	    $file_output = "$this->dir_tmp/$this->cidr.".__FUNCTION__.".dot";
	    $color_scan = "violet";$color_cidr = "violet";$color_arrow = "violet";
	    $cidr2dot_header = "digraph structs {
	label = \"".__FUNCTION__."$this->ip:$this->cidr\";
		graph [rankdir = \"LR\" layout = dot];
		node [fontsize = \"16\" shape = \"plaintext\"];
		edge [penwidth=2.0 ];";
	    //$obj_ip = new ip($this->ip);
	    $cidr2dot_ip .= $obj_ip->ip2dot();
	    $cidr2dot_cidr .= $this->cidr2dot($obj_ip->ip);
	    $cidr2dot_edge .= "
		\"$obj_ip->ip\":ip2cidr4range -> \"$obj_ip->ip:$this->cidr\":cidr [color=\"$color_arrow\"];
		";
	    
	    $cidr2dot_footer = "
		}";
	    
	    $cidr2dot = $cidr2dot_header.$cidr2dot_ip.$cidr2dot_cidr.$cidr2dot_edge.$cidr2dot_footer;
	    $cidr2dot4body = $cidr2dot_ip.$cidr2dot_cidr.$cidr2dot_edge;
	    system("echo '$cidr2dot' > $file_output ");
	    //$this->requette("gedit $file_output");
	    $this->dot2xdot("$file_output ");
	    return $cidr2dot4body;
	}
	
	
	
	
	public function port2dot4web(){
	    $port2dot_port = "";
	    $port2dot_ip = "";
	    $port2dot_web = "";
	    $port2dot_edge = "";
	    $port2dot4body = "";
	    
	    $file_output = "$this->dir_tmp/$this->ip.".__FUNCTION__.".dot";
	    $color_port = "orange";$color_host = "darkturquoise";$color_domain = "darkturquoise";$color_arrow = "darkorange";
	    $port2dot_header = "digraph structs {
		label = \"".__FUNCTION__.":$this->ip:PORT\";
			graph [rankdir = \"LR\" layout = dot];
			node [fontsize = \"16\" shape = \"plaintext\"];
			edge [penwidth=2.0 ];";
	    
	    //$obj_ip = new IP($this->ip);
	    $port2dot_ip .= $obj_ip->ip2dot();
	    $ports_user = $obj_ip->ip2port();
	    
	    if (!empty($ports_user)) {
	        //$user->ip2discovery();
	        $ports = explode("\n", $ports_user);
	        foreach($ports as $val)
	            if (preg_match('/(?<port>\d+)\/tcp([[:space:]]{1,5})open/',$val,$port))
	            {
	                $obj_port = new PORT( $obj_ip->host, $port['port']);
	                
	                $port2dot_port .= $obj_port->port2dot();
	                
	                if ($obj_port->port=='80' || $obj_port->port=='443' || $obj_port->port=='8080') {
	                    $tab_vhost = explode("\n", $obj_port->ip2host(""));
	                    $tab_vhost = array_map("trim",$tab_vhost);
	                    $count_vhost = count($tab_vhost);
	                    for ($i=0;$i<$count_vhost;$i++){
	                        $vhost = trim($tab_vhost[$i]);
	                        if(!empty($vhost)){
	                            $this->titre("$i/$count_vhost: $vhost");
	                            $obj_web = new WEB( $obj_port->ip, $obj_port->port, $vhost);
	                            $port2dot_web .= $obj_web->web2dot();
	                            $port2dot_edge .= "
		\"$obj_port->ip:$obj_port->port\":port2pentest -> \"$obj_web->ip.$obj_web->vhost.$obj_web->port\":vhost [color=\"green4\"];
							";
	                        }
	                    }
	                }
	                $port2dot_edge .= "
		\"$obj_ip->ip\":ip2port -> \"$obj_ip->ip:$obj_port->port\":port [color=\"$color_arrow\"];
		";
	            }
	    }
	    
	    $port2dot_footer = "
	        
}";
	    
	    $port2dot = $port2dot_header.$port2dot_ip.$port2dot_port.$port2dot_web.$port2dot_edge.$port2dot_footer;
	    $port2dot4body = $port2dot_ip.$port2dot_port.$port2dot_edge ;
	    //system("echo '$port2dot' > $file_output ");
	    //$this->requette("gedit $file_output");
	    //$this->dot2xdot("$file_output ");
	    $this->dot4make($file_output,$port2dot);
	    return $port2dot4body;
	}
	
	
	
	

	

	
	public function dot4host2all($rep_path,$titre){
		$this->chapitre($titre);
		$file_output = "$rep_path/".__FUNCTION__.".dot";
		$diagram_header = "digraph structs {
		label = \"$titre\";
		graph [rankdir = \"TB\" layout = dot];
		node [fontsize = \"16\" shape = \"plaintext\"];
		edge [penwidth=2.0 ];\n	";
		$diagram_footer = "\n}";
		$this->requette("cat $rep_path/*.".__FUNCTION__.".dot | grep '>' > $rep_path/".__FUNCTION__.".corp");
	
		$this->requette("echo '$diagram_header' > $file_output");
		$this->requette("cat $rep_path/".__FUNCTION__.".corp >> $file_output");
		$this->requette("echo '$diagram_footer' >> $file_output");
		$this->requette("gedit $file_output");$this->dot2xdot($file_output);
	}
	
	

	public function dot2xdot($file_dot){
		$this->requette("xdot $file_dot 2> /dev/null "); //2> /dev/null
		return $file_dot;
	}
	
	public function dot2png($file_dot){
	    $this->requette("dot -Tpng $file_dot > $file_dot.png 2> /dev/null ");
	}
	
	public function dot4all2all($rep_path,$famille){
		$famille = trim($famille);
		$titre = "Display by $famille";
		$this->chapitre($titre);
		$file_output = "$rep_path/".__FUNCTION__.".dot";
		$diagram_header = "digraph structs {
		label = \"$titre\";
		graph [rankdir = \"TB\" layout = dot];
		node [fontsize = \"16\" shape = \"plaintext\"];
		edge [penwidth=2.0 ];\n	";
		$diagram_footer = "\n}";
		$this->requette("cat $rep_path/*.$famille.dot | grep '>' | grep -v \"\->\" > $rep_path/".__FUNCTION__.".corp");
		$this->requette("cat $rep_path/*.$famille.dot | grep \"\->\" | sort -u >> $rep_path/".__FUNCTION__.".corp");
		$this->requette("echo '$diagram_header' > $file_output");
		$this->requette("cat $rep_path/".__FUNCTION__.".corp >> $file_output");
		$this->requette("echo '$diagram_footer' >> $file_output");
		$this->requette("gedit $file_output");$this->dot2xdot($file_output);
	}
	
	

	function dot4make($fileout_path,$diagram) {
		$fp = fopen($fileout_path, 'w+');
		fputs($fp,$diagram);
		fclose($fp);
		// echo "graph G {Hello--World}" | neato -Tpng >hello2.png
		// requette("dot -Tjpg $this->dir_tmp/$titre.dot -o $this->dir_tmp/$titre.jpg");
	//$this->dot2xdot($fileout_path);
		$this->dot2png($fileout_path);
	
	}
	

	public function dot4ip2all($rep_path,$titre){
		$this->chapitre($titre);
		$file_output = "$rep_path/".__FUNCTION__.".dot";
		$diagram_header = "digraph structs {
		label = \"$titre\";
		graph [rankdir = \"TB\" layout = dot];
		node [fontsize = \"16\" shape = \"plaintext\"];
		edge [penwidth=2.0 ];\n	";
		$diagram_footer = "\n}";
		$this->requette("cat $rep_path/*.*2dot.dot | grep '>' > $rep_path/".__FUNCTION__.".corp");
	
		$this->requette("echo '$diagram_header' > $file_output");
		$this->requette("cat $rep_path/".__FUNCTION__.".corp >> $file_output");
		$this->requette("echo '$diagram_footer' >> $file_output");
	
		$this->requette("gedit $file_output");
		$this->dot2xdot($file_output);
	}

	// graphic_payload_env()
	function dot4payload_eip_jmp2env() {
		$graph_bof_env = "digraph structs {
	label = \"Shellcode ENV EIP\";
	fontcolor=blue;
	node [shape=plaintext];
	\"Shellcode in *envp\" [shape=box,color=gold, style=filled];
	
	struct1 [label=<<TABLE BORDER=\"0\" CELLBORDER=\"1\" CELLSPACING=\"0\"> <TR><TD PORT=\"f0\">ANYTHING x (Offset)</TD><TD PORT=\"f1\" bgcolor=\"#FFcc00\">EIP</TD><TD PORT=\"f2\">...</TD></TR> </TABLE>>];
	struct1:\"f1\" -> \"Shellcode in *envp\" [label=\"Exec Instruction\" style=dashed];}";
		$this->dot4make("graphic_payload_eip_jmp2env", $graph_bof_env );
	}
	
	// graphic_payload_stack_linux_jmp_esp_sc_after_only()
	function dot4payload_eip_jmp2esp_sc_after_eip_simple() {
		$graph_bof_after = "digraph structs {
label = \"Shellcode After EIP\";
fontcolor=blue;
node [shape=plaintext];
struct1 [label=<<TABLE BORDER=\"0\" CELLBORDER=\"1\" CELLSPACING=\"0\"> <TR><TD PORT=\"f0\">ANYTHING x OFFSET</TD><TD PORT=\"f1\" bgcolor=\"#FFcc00\">EIP</TD><TD PORT=\"f2\">NOP*Rep</TD><TD>SHELLCODE</TD></TR> </TABLE>>];
struct1:f1 -> struct1:f2 [label=\"Stack: Addr Low <- High\" style=dashed];}";
		$this->dot4make("graphic_payload_eip_jmp2esp_sc_after_eip_simple", $graph_bof_after );
	}
	function dot4payload_eip_jmp2esp_sc_after_eip_egghunter() {
		$graph_bof_after = "digraph structs {
label = \"Shellcode After EIP with egg hunter \";
fontcolor=blue;
node [shape=plaintext];
struct1 [label=<<TABLE BORDER=\"0\" CELLBORDER=\"1\" CELLSPACING=\"0\"> <TR><TD PORT=\"f0\">ANYTHING x OFFSET</TD><TD PORT=\"f1\" bgcolor=\"#FFcc00\">EIP</TD><TD PORT=\"f2\">NOP*Rep</TD><TD>EGG HUNTER</TD><TD>NOP*Rep</TD><TD>EGG</TD><TD>EGG</TD><TD>SHELLCODE</TD></TR> </TABLE>>];
struct1:f1 -> struct1:f2 [label=\"Stack: Addr Low <- High\" style=dashed];}";
		$this->dot4make("graphic_payload_eip_jmp2esp_sc_after_eip_egghunter", $graph_bof_after );
	}
	function dot4payload_eip_jmp2esp_sc_before_eip_egghunter() {
		$graph_bof_after = "digraph structs {
label = \"Shellcode Before EIP with egg hunter \";
fontcolor=blue;
node [shape=plaintext];
struct1 [label=<<TABLE BORDER=\"0\" CELLBORDER=\"1\" CELLSPACING=\"0\"> <TR><TD>HEADER</TD><TD>JUNK</TD><TD PORT=\"f3\" >EGG</TD><TD PORT=\"f5\">EGG</TD><TD PORT=\"f6\" bgcolor=\"orange\">SHELLCODE</TD><TD>JUNK</TD><TD PORT=\"f1\" bgcolor=\"#FFcc00\">EIP</TD><TD PORT=\"f2\">NOP*Rep</TD><TD PORT=\"f4\" bgcolor=\"green\">EGG HUNTER</TD><TD>FOOTER</TD></TR></TABLE>>];
struct1:f1 -> struct1:f2 [label=\"  \" style=dashed color=\"#FFcc00\"];
struct1:f4 -> struct1:f3 [label=\"  \" style=dashed color=green];
struct1:f3 -> struct1:f5 [label=\"  \" style=dashed color=orange];
struct1:f5 -> struct1:f6 [label=\"  \" style=dashed color=\"orange\"];
}";
		$this->dot4make("graphic_payload_eip_jmp2esp_sc_before_eip_egghunter", $graph_bof_after );
	}
	
	// graphic_payload_before()
	function dot4payload_eip_jmp2StartBuffer_sc_before_eip() {
		$graph_bof_before = "digraph structs {
	label = \"Shellcode Before EIP\";
	fontcolor=blue;
	node [shape=plaintext];
	struct1 [label=<<TABLE BORDER=\"0\" CELLBORDER=\"1\" CELLSPACING=\"0\"> <TR><TD PORT=\"f0\">NOPs x (SC-Offset) MIN</TD><TD PORT=\"f1\">SHELLCODE MAX</TD><TD PORT=\"f2\" bgcolor=\"#FFcc00\">EIP (JMP NOPs|Shellcode Addr)</TD></TR> </TABLE>>];
	struct1:f2 -> struct1:f0 [label=\"Addr Low <- High\" style=dashed];}";
		$this->dot4make("graphic_payload_eip_jmp2StartBuffer_sc_before_eip", $graph_bof_before );
	}
	function dot4payload_eip_jmp2reg_sc_before_eip() {
		$graph_bof_before = "digraph structs {
	label = \"Shellcode Before EIP\";
	fontcolor=blue;
	node [shape=plaintext];
	struct1 [label=<<TABLE BORDER=\"0\" CELLBORDER=\"1\" CELLSPACING=\"0\"> <TR><TD PORT=\"f0\">NOPs x (SC-Offset) MIN</TD><TD PORT=\"f1\">SHELLCODE MAX</TD><TD PORT=\"f2\" bgcolor=\"#FFcc00\">EIP (JMP2REG EAX|EBX|ECX|EDX)</TD></TR> </TABLE>>];
	struct1:f2 -> struct1:f0 [label=\"Addr Low <- High\" style=dashed];}";
		$this->dot4make("graphic_payload_eip_jmp2reg_sc_before_eip", $graph_bof_before );
	}
	function dot4payload_ret2lib_libc_methode1_system_exit_cmd_string() {
		$graph_bof_libc_string = "digraph structs {
	label = \"Shellcode Libc Chainning\";
	fontcolor=blue;
	node [shape=plaintext];
	struct1 [label=<<TABLE BORDER=\"0\" CELLBORDER=\"1\" CELLSPACING=\"0\"> <TR><TD PORT=\"f0\">ANYTHING x OFFSET</TD><TD PORT=\"f1\" bgcolor=\"#FFcc00\">EIP (Addr System)</TD><TD PORT=\"f2\">Addr Exit</TD><TD PORT=\"f3\">Addr String (/bin/sh)</TD><TD>...</TD></TR></TABLE>>];
	struct1:f1 -> struct1:f3 [label=\"(1)\",labelfontcolor=red,labelloc=c,color=orange];
	struct1:f3 -> struct1:f2 [label=\"(2)\",labelfontcolor=green,labelloc=r,color=green];
}";
		$this->dot4make("graph_bof_libc_string", $graph_bof_libc_string );
	}
	function dot4payload_ret2lib_libc_methode2_system_exit_cmd_addr() {
		$graph_bof_libc_addr = "digraph structs {
	label = \"Shellcode Libc Chainning\";
	fontcolor=blue;
	node [shape=plaintext];
	struct1 [label=<<TABLE BORDER=\"0\" CELLBORDER=\"1\" CELLSPACING=\"0\"> <TR><TD PORT=\"f0\">ANYTHING x OFFSET</TD><TD PORT=\"f1\" bgcolor=\"#FFcc00\">EIP (Addr System)</TD><TD PORT=\"f2\">Addr Exit</TD><TD PORT=\"f3\">Jump to Addr String (/bin/sh) in argv[1]</TD><TD>...</TD><TD PORT=\"f4\">/bin/sh in argv[1]</TD><TD>...</TD></TR></TABLE>>];
	struct1:f1 -> struct1:f3 [label=\"Addr Low -> High\" color=orange];
	struct1:f3 -> struct1:f4 [color=green];
	struct1:f4 -> struct1:f2 [color=yellow];
}";
		$this->dot4make("graph_bof_libc_addr", $graph_bof_libc_addr );
	}
	
	
	function dot4apt() {
		// consomme trop de CPU
		ssTitre("Dependency Package" );
		$this->requette("apt-cache dotty > $this->dir_tmp/dep.dot" );
		$this->requette("xdot $this->dir_tmp/dep.dot" );
	}
	

	function dot4step_1_gathering_info() {
		$this->titre("Gathering Info Graphic" );
		// shape=diamond | rounded | ellipse | plaintext
		// style=dashed
	
		$diagram = <<<MAP
			digraph {
	label = \"Gathering Information\";
	//	rankdir=LR;
	
	subgraph cluster1{
	\"1- Gathering Info\" [shape=box,color=lightblue2, style=filled];
	\"2- Transfert Zone\" [shape=box,color=lightblue2, style=filled];
	\"3.0- OK\" [shape=box,color=lightblue2, style=filled];
	\"3.0- NO\" [shape=box,color=lightblue2, style=filled];
	\"4- List IPs Target\" [shape=box,color=lightblue2, style=filled,image=\"$this->dir_img/ico/list.png\"];
	\"3.1- DNS-type A-DICO\" [shape=box,color=lightblue2, style=filled];
	\"3.2- IP Range\" [shape=box,color=lightblue2, style=filled];
	\"3.2.1- Whois\" [shape=box,color=lightblue2, style=filled];
	\"3.2.2- GeoIP\" [shape=box,color=lightblue2, style=filled];
	\"3.3- Filter IPs\" [shape=box,color=lightblue2, style=filled];
	\"3.4.1- Ping Sweep\" [shape=box,color=lightblue2, style=filled];
	\"3.4.2- DNS-type PTR\" [shape=box,color=lightblue2, style=filled];
	\"3.4.3- ICMP Types\" [shape=box,color=lightblue2, style=filled];
	\"3.4.4- Port 80/443 - nmap\"  [shape=box,color=lightblue2, style=filled];
}
	
	\"1- Gathering Info\" -> \"2- Transfert Zone\" -> \"3.0- OK\" -> \"4- List IPs Target\";
	\"2- Transfert Zone\" -> \"3.0- NO\";
	\"3.0- NO\" -> \"3.1- DNS-type A-DICO\" -> \"3.2- IP Range\";
	\"3.2- IP Range\"  -> \"3.2.1- Whois\";
	\"3.2- IP Range\"  -> \"3.2.2- GeoIP\";
	\"3.2.1- Whois\" -> \"3.3- Filter IPs\";
	\"3.2.2- GeoIP\" -> \"3.3- Filter IPs\";
	
	\"3.3- Filter IPs\" -> \"3.4.1- Ping Sweep\";
	\"3.3- Filter IPs\" -> \"3.4.2- DNS-type PTR\";
	\"3.3- Filter IPs\" -> \"3.4.3- ICMP Types\";
	\"3.3- Filter IPs\" -> \"3.4.4- Port 80/443 - nmap\";
	\"3.4.1- Ping Sweep\" -> \"4- List IPs Target\";
	\"3.4.2- DNS-type PTR\" -> \"4- List IPs Target\";
	\"3.4.3- ICMP Types\" -> \"4- List IPs Target\";
	\"3.4.4- Port 80/443 - nmap\" -> \"4- List IPs Target\";
}
MAP;
	
		$this->dot4make("graphic_step_1_gathering_info", $diagram );
	}
	
	
	

	function dot4step_blackbox_web() {
		$this->titre("Gathering Info Graphic" );
		// shape=diamond | rounded | ellipse | plaintext
		// style=dashed
	
		$diagram = <<<MAP
			digraph {
	label = \"Gathering Information\";
	//	rankdir=LR;
	
	subgraph cluster1{
	\"1- Gathering Info\" [shape=box,color=lightblue2, style=filled];
	\"2- Transfert Zone\" [shape=box,color=lightblue2, style=filled];
	\"3.0- OK\" [shape=box,color=lightblue2, style=filled];
	\"3.0- NO\" [shape=box,color=lightblue2, style=filled];
	\"4- List IPs Target\" [shape=box,color=lightblue2, style=filled,image=\"$this->dir_img/ico/list.png\"];
	\"3.1- DNS-type A-DICO\" [shape=box,color=lightblue2, style=filled];
	\"3.2- IP Range\" [shape=box,color=lightblue2, style=filled];
	\"3.2.1- Whois\" [shape=box,color=lightblue2, style=filled];
	\"3.2.2- GeoIP\" [shape=box,color=lightblue2, style=filled];
	\"3.3- Filter IPs\" [shape=box,color=lightblue2, style=filled];
	\"3.4.1- Ping Sweep\" [shape=box,color=lightblue2, style=filled];
	\"3.4.2- DNS-type PTR\" [shape=box,color=lightblue2, style=filled];
	\"3.4.3- ICMP Types\" [shape=box,color=lightblue2, style=filled];
	\"3.4.4- Port 80/443 - nmap\"  [shape=box,color=lightblue2, style=filled];
}
	
	\"1- Gathering Info\" -> \"2- Transfert Zone\" -> \"3.0- OK\" -> \"4- List IPs Target\";
	\"2- Transfert Zone\" -> \"3.0- NO\";
	\"3.0- NO\" -> \"3.1- DNS-type A-DICO\" -> \"3.2- IP Range\";
	\"3.2- IP Range\"  -> \"3.2.1- Whois\";
	\"3.2- IP Range\"  -> \"3.2.2- GeoIP\";
	\"3.2.1- Whois\" -> \"3.3- Filter IPs\";
	\"3.2.2- GeoIP\" -> \"3.3- Filter IPs\";
	
	\"3.3- Filter IPs\" -> \"3.4.1- Ping Sweep\";
	\"3.3- Filter IPs\" -> \"3.4.2- DNS-type PTR\";
	\"3.3- Filter IPs\" -> \"3.4.3- ICMP Types\";
	\"3.3- Filter IPs\" -> \"3.4.4- Port 80/443 - nmap\";
	\"3.4.1- Ping Sweep\" -> \"4- List IPs Target\";
	\"3.4.2- DNS-type PTR\" -> \"4- List IPs Target\";
	\"3.4.3- ICMP Types\" -> \"4- List IPs Target\";
	\"3.4.4- Port 80/443 - nmap\" -> \"4- List IPs Target\";
}
MAP;
	
		$this->dot4make("graphic_step_1_gathering_info", $diagram );
	}
	
	
	
	
	
	
	function dot4step_all_hacking() {
		/*
		 * \\\"Security Defensive\\\" -> \\\"0- Security Offensive\\\" [style=bold,color=blue,label=\\\"CISSP - Certified Information Systems Security Professional\\\",URL=\\\"https://www.isc2.org/CISSP/Default.aspx\\\"];
		 * \\\"0- Security Offensive\\\" -> \\\"1- Gathering Info\\\";
		 * \\\"1- Gathering Info\\\" -> \\\"2- Ports Scanning\\\" ;
		 * \\\"1- Gathering Info\\\" -> \\\"4- Ident Vulns\\\" [style=bold,color=blue,label=\\\"CISA - Certified Information Systems Auditor\\\",URL=\\\"http://www.isaca.org/Certification/CISA-Certified-Information-Systems-Auditor/Pages/default.aspx\\\" ];
		 * \\\"2- Ports Scanning\\\" -> \\\"3- Enum Services\\\";
		 * \\\"3- Enum Services\\\" -> \\\"4- Ident Vulns\\\" ;
		 * \\\"4- Ident Vulns\\\" -> \\\"5- Exploit Vuln\\\" ;
		 * \\\"4- Ident Vulns\\\" -> \\\"9- Botnet\\\" [style=bold,color=blue,label=\\\"CEH - Certified Ethical Hacker\\\",URL=\\\"http://www.eccouncil.org/Certification/certified-ethical-hacker\\\"];
		 * \\\"5- Exploit Vuln\\\" -> \\\"6- backdooring\\\";
		 * \\\"6- backdooring\\\" -> \\\"7- Be Root\\\";
		 * \\\"7- Be Root\\\" -> \\\"8- Erase Track\\\";
		 * \\\"4- Ident Vulns\\\" -> \\\"7- Be Root\\\"[style=bold,color=blue,label=\\\"GREM - GIAC Reverse Engineering Malware\\\",URL=\\\"http://www.giac.org/certification/reverse-engineering-malware-grem\\\" ];
		 * \\\"7- Be Root|Administrator\\\" -> \\\"8- Erase Track\\\"[style=bold,color=blue,label=\\\"CHFI - Computer Hacking Forensic Investigator\\\",URL=\\\"https://www.eccouncil.org/certification/computer-hacking-forensics-investigator\\\" ];
		 * \\\"8- Erase Track\\\" -> \\\"9- Botnet\\\"
		 * \\\"9- Botnet\\\" -> \\\"Hacker/Pentester\\\" [style=bold,color=blue,label=\\\"ECSA/LPT - Licensed Penetration Tester\\\",URL=\\\"https://www.eccouncil.org/security-analyst-and-penetration-testing-program\\\" ];
		 *
		 */
		$this->titre("les etapes des Cybercriminels" );
		// shape=diamond | rounded | ellipse | plaintext
		// style=dashed
	
		$diagram = "digraph {
		label = \\\"Etapes Hacking\\\";
		//	rankdir=LR;
	
		subgraph cluster1{
		label=\\\"CISSP - Certified Information Systems Security Professional\\\";
		\\\"Security Defensive\\\" ;
	}
	
	\\\"0- Security Offensive\\\";
	
	subgraph cluster2{
	label=\\\"CEH - Certified Ethical Hacker\\\";
	//fontcolor=green;
	//fontsize=10;
	// fillcolor=orange
	// rankdir=LR; // Left to Right, instead of Top to Bottom
	color=orange;
	style=filled;
	
	subgraph cluster3{
	label=\\\"CISA - Certified Information Systems Auditor\\\";
	color=lightyellow2;
	penwidth=2;
	style = filled;
	\\\"1- Gathering Info\\\" [shape=box,color=lightblue2, style=filled];
	\\\"2- Ports Scanning\\\" [shape=box,color=lightblue2, style=filled];
	\\\"3- Enum Services\\\" [shape=box,color=lightblue2, style=filled];
	\\\"4- Ident Vulns\\\" [shape=box,color=lightblue2, style=filled];
	}
	
	subgraph cluster4{
	label=\\\"GREM - GIAC Reverse Engineering Malware\\\";
	color=lightyellow2;
	\\\"4- Ident Vulns\\\"	[shape=box,color=lightblue2, style=filled];
	\\\"5- Exploit Vuln\\\"	[shape=box,color=lightblue2, style=filled];
	\\\"6- backdooring\\\" [shape=box,color=lightblue2, style=filled];
	\\\"7- Be Root|Administrator\\\" [shape=box,color=lightblue2, style=filled];
	}
	subgraph cluster5{
	label=\\\"CHFI - Computer Hacking Forensic Investigator\\\";
	color=lightyellow2
	\\\"8- Erase Track\\\" [shape=box,color=lightblue2, style=filled];
	}
	\\\"9- Botnet\\\" [shape=box,color=lightblue2, style=filled];
	}
	
	subgraph cluster6{
	label=\\\"ECSA/LPT - Licensed Penetration Tester\\\";
	labelloc=b;
	\\\"Hacker/Pentester\\\" [shape=box,style=filled,color=white,image=\\\"$this->dir_img/hacker.png\\\"];
	}
	
	\\\"Security Defensive\\\" -> \\\"0- Security Offensive\\\" -> \\\"1- Gathering Info\\\" -> \\\"2- Ports Scanning\\\" -> \\\"3- Enum Services\\\" -> \\\"4- Ident Vulns\\\" -> \\\"5- Exploit Vuln\\\" -> \\\"6- backdooring\\\" -> \\\"7- Be Root|Administrator\\\" -> \\\"8- Erase Track\\\" -> \\\"9- Botnet\\\" -> \\\"Hacker/Pentester\\\" ;
	}";
		$this->dot4make("graphic_step_all_hacking", $diagram );
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
