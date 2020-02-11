<?php



class service2dns extends SERVICE {


    public function __construct($eth,$domain,$ip,$port,$service_protocol,$service_name,$service_version,$service_product,$service_extrainfo) {
        parent::__construct($eth,$domain,$ip,$port,$service_protocol,$service_name,$service_version,$service_product,$service_extrainfo);
    }


public function service2dns4exec(){
    $this->ssTitre(__FUNCTION__);
    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"dns-service-discovery\" $this->ip -s$this->protocol -p $this->port -e $this->eth -oX -  ";
    return $this->req2BD($this->colonne,$this->table,"$this->port2where AND service2name = '$this->service_name' AND service2version = '$this->service_version' ",$query);
    
}



public function dns2dot(){
    $dir_img = "./IMG";
    $dns2dot_ns = "";
    $dns2dot_domain = "";
    $dns2dot_edge = "";
    
    $file_output = "$this->dir_tmp/$this->domain.".__FUNCTION__.".dot";
    $color_dns = "darkturquoise";$color_host = "darkturquoise";$color_domain = "darkturquoise";$color_arrow = "darkturquoise";
    $dns2dot_header = "digraph structs {
	label = \"".__FUNCTION__.":$this->domain:DNS\";
		graph [rankdir = \"LR\" layout = dot];
		node [fontsize = \"16\" shape = \"plaintext\"];
		edge [penwidth=2.0 ];";
    
    $dns2dot_ns .= "
		\"$this->dns\" [label=<<TABLE BORDER=\"0\" CELLBORDER=\"1\" CELLSPACING=\"0\" ALIGN=\"LEFT\" >
		<TR><TD>DNS</TD><TD PORT=\"dns\" bgcolor=\"$color_dns\" >$this->dns</TD></TR>
		<TR><TD>MX</TD><TD PORT=\"dns2mx\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->dns2mx()))."</TD></TR>
		<TR><TD>SOA</TD><TD PORT=\"dns2soa\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->dns2soa()))."</TD></TR>
		<TR><TD>TXT</TD><TD PORT=\"dns2txt\"  >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->dns2txt()))."</TD></TR>
		<TR><TD>AXFR</TD><TD PORT=\"dns2axfr\"  >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->dns2axfr()))."</TD></TR>
		<TR><TD>CNAME</TD><TD PORT=\"dns2cname\"  >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->dns2cname()))."</TD></TR>
		<TR><TD>AAAA</TD><TD PORT=\"dns2aaaa\"  >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->dns2aaaa()))."</TD></TR>
		<TR><TD>NSID</TD><TD PORT=\"dns2nsid\"  >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->dns2nsid()))."</TD></TR>
		<TR><TD>HINFO</TD><TD PORT=\"dns2hinfo\"  >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->dns2hinfo()))."</TD></TR>
		<TR><TD>A</TD><TD PORT=\"dns2a\"  >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->dns2a()))."</TD></TR>
		<TR><TD>PTR</TD><TD PORT=\"dns2ptr\"  >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->dns2ptr()))."</TD></TR>
	    <TR><TD>RP</TD><TD PORT=\"dns2rp\"  >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->dns2rp()))."</TD></TR>
	   	<TR><TD>SRV</TD><TD PORT=\"dns2srv\"  >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->dns2srv()))."</TD></TR>
				</TABLE>>];
	   	    
				";
    
    $dns2dot_edge .= "
				";
    
    
    $dns2dot_footer = "
}";
    
    $dns2dot = $dns2dot_header.$dns2dot_domain.$dns2dot_ns.$dns2dot_edge.$dns2dot_footer;
    $dns2dot4body = $dns2dot_domain.$dns2dot_ns.$dns2dot_edge ;
    //system("echo '$dns2dot' > $file_output ");
    //$this->requette("gedit $file_output");
    //$this->dot2xdot("$file_output ");
    $this->dot4make($file_output,$dns2dot);
    return $dns2dot4body;
}








public function dns2mx(){
    $this->ssTitre(__FUNCTION__." MX Records - List of a host’s or domain’s mail exchanger server(s).");
    $query = "dig @$this->dns $this->domain MX +short | grep -v '^;' ";
    return $this->req2BD(__FUNCTION__,__CLASS__,"domain = '$this->domain' AND dns = '$this->dns'",$query);
    
}


public function dns2soa(){
    $this->ssTitre(__FUNCTION__." SOA Records - Indicates the server that has authority for the domain.");
    $query = "dig @$this->dns $this->domain SOA +short | grep -v '^;' ";
    return $this->req2BD(__FUNCTION__,__CLASS__,"domain = '$this->domain' AND dns = '$this->dns'",$query);
}


public function dns2txt(){
    $this->ssTitre(__FUNCTION__." TXT Records - Generic text record.");
    $query = "dig @$this->dns $this->domain TXT +short | grep -v '^;' ";
    return $this->req2BD(__FUNCTION__,__CLASS__,"domain = '$this->domain' AND dns = '$this->dns'",$query);
}


public function dns2cname(){
    $this->ssTitre(__FUNCTION__." CNAME - A host’s canonical name allows additional names/ aliases to be used to locate a computer.");
    $query = "dig @$this->dns $this->domain CNAME +short | grep -v '^;' ";
    return $this->req2BD(__FUNCTION__,__CLASS__,"domain = '$this->domain' AND dns = '$this->dns'",$query);
}


public function dns2aaaa(){
    $this->ssTitre(__FUNCTION__);
    $query = "dig @$this->dns $this->domain AAAA +short | grep -v '^;' ";
    return $this->req2BD(__FUNCTION__,__CLASS__,"domain = '$this->domain' AND dns = '$this->dns'",$query);
}

public function dns2a(){
    $this->ssTitre(__FUNCTION__." A Records - An address record that allows a computer name to be translated to an IP address.
				Each computer has to have this record for its IP address to be located via DNS.");
    $query = "dig @$this->dns $this->domain A +short | grep -v '^;' ";
    return $this->req2BD(__FUNCTION__,__CLASS__,"domain = '$this->domain' AND dns = '$this->dns'",$query);
}

public function dns2ptr(){
    $this->ssTitre(__FUNCTION__." PTR Records - Lists a host’s domain name, host identified by its IP address.");
    $query = "nslookup -query=ptr ".gethostbyname($this->dns)." | grep 'name' | cut -d'=' -f2 | sed \"s/\.$//g\" | tr -d ' ' | grep  -i -Po \"([0-9a-zA-Z_-]{1,}\.)+[a-zA-Z]{1,4}\"  ";
    return $this->req2BD(__FUNCTION__,__CLASS__,"domain = '$this->domain' AND dns = '$this->dns'",$query);
}


public function dns2axfr(){
    $this->ssTitre(__FUNCTION__);
    $query = "dig @$this->dns $this->domain axfr +short | grep -v '^;' ";
    return $this->req2BD(__FUNCTION__,__CLASS__,"domain = '$this->domain' AND dns = '$this->dns'",$query);
}


public function dns2hinfo(){
    $this->ssTitre(__FUNCTION__." HINFO Records - Host information record with CPU type and operating system.");
    $query = "dig @$this->dns $this->domain HINFO +short | grep -v '^;' ";
    return $this->req2BD(__FUNCTION__,__CLASS__,"domain = '$this->domain' AND dns = '$this->dns'",$query);
}


public function dns2srv(){
    $this->ssTitre(__FUNCTION__." SRV Records - Service location record.");
    $query = "dig @$this->dns $this->domain SRV +short | grep -v '^;' ";
    return $this->req2BD(__FUNCTION__,__CLASS__,"domain = '$this->domain' AND dns = '$this->dns'",$query);
}


public function dns2rp(){
    $this->ssTitre(__FUNCTION__." Responsible person for the domain.");
    $query = "dig @$this->dns $this->domain RP +short | grep -v '^;' ";
    return $this->req2BD(__FUNCTION__,__CLASS__,"domain = '$this->domain' AND dns = '$this->dns'",$query);
}

public function dns2nsid(){
    $this->ssTitre(__FUNCTION__);
    $query = "echo '$this->root_passwd' | sudo -S nmap --script dns-nsid -p 53 $this->dns -Pn -n  -oX - ";
    return $this->req2BD(__FUNCTION__,__CLASS__,"domain = '$this->domain' AND dns = '$this->dns'",$query);
}

public function dns4pentest(){ // OK
    $result = "";
    $result .= $this->gtitre(__FUNCTION__);
    $result .= $this->dns2a();
    $result .= $this->dns2aaaa();
    $result .= $this->dns2axfr();
    $result .= $this->dns2cname();
    $result .= $this->dns2hinfo();
    $result .= $this->dns2mx();
    $result .= $this->dns2nsid();
    $result .= $this->dns2ptr();
    $result .= $this->dns2rp();
    $result .= $this->dns2soa();
    $result .= $this->dns2srv();
    $result .= $this->dns2txt();
    return $result;
}



  }
?>
