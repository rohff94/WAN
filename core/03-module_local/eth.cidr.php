<?php

class CIDR extends ETH{
    
    var $cidr ;
    var $cidr2id ;
    var $cidr2where ;
    
    
    public function __construct($stream,$eth,$cidr) {
        $cidr = trim($cidr);
        $eth = trim($eth);
        $this->cidr = "$cidr.0/24";
        $this->cidr2where = "cidr = '$this->cidr'";
        
        
        parent::__construct($stream,$eth);
        
        if(!empty($this->cidr)){
            
            $sql_r = "SELECT cidr FROM ".__CLASS__." WHERE $this->cidr2where ";
            if (!$this->checkBD($sql_r)) {
                $sql_w = "INSERT  INTO ".__CLASS__." (cidr) VALUES ('$this->cidr'); ";
                $this->mysql_ressource->query($sql_w);
                echo $this->note("Working on CIDR $this->cidr for the first time");
            }
            
            $sql_r = "SELECT id FROM ".__CLASS__." WHERE $this->cidr2where ";
            $query = "mysql --user=$this->mysql_login --password=$this->mysql_passwd --database=$this->mysql_database --execute=\"$sql_r\"  2>/dev/null \n";
            $this->cidr2id = $this->req_ret_str($query);
            //$this->cidr2id = $this->mysql_ressource->query($sql_r)->fetch_assoc()['id'];
            
            
        }
        
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
    
    
    
    public function cidr2scan($cidr,$eth){
        $this->titre(__FUNCTION__);
        $cidr = trim($cidr);
        if (!empty($cidr)) return $this->cidr2scan4nmap($cidr,$this->eth);
        //$this->cidr2scan4fping($cidr);
    }
    
    public function cidr2scan4nmap($cidr,$eth){
        $this->ssTitre(__FUNCTION__);
        $cidr = trim($cidr);
        $query = " nmap -sn --reason $cidr -e $eth | grep 'Nmap scan report for' | sed \"s/Nmap scan report for//g\"  " ; // | grep -Po \"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\"
        if (!empty($cidr)) return $this->req_ret_str($query);
    }
    
    public function cidr2scan4fping($cidr){
        $this->ssTitre(__FUNCTION__);
        $cidr = trim($cidr);
        $query = " echo '$this->root_passwd' | sudo -S fping -a -n -g $cidr 2> /dev/null | grep -v -E \"(Unreachable|error)\" ";
        if (!empty($cidr)) return $this->req_ret_str($query);
    }
    
    
  
    
    
    
    public function cidr2live(){
        $this->titre(__FUNCTION__);
        $result = "";
        $sql_r_1 = "SELECT ".__FUNCTION__." FROM ".__CLASS__." WHERE $this->cidr2where AND ".__FUNCTION__." IS NOT NULL";
        if ($this->checkBD($sql_r_1) ) return  base64_decode($this->req2BD4out(__FUNCTION__,__CLASS__,$this->cidr2where));
        else {
            $result .= $this->cidr2scan4nmap($this->cidr,$this->eth);
            $result .= $this->cidr2scan4fping($this->cidr);
            
            $result = base64_encode($result);
            return base64_decode($this->req2BD4in(__FUNCTION__,__CLASS__,$this->cidr2where,$result));
        }
    }
    
    
    public function cidr2owner(){
        $this->titre(__FUNCTION__);
        $result = "";
        $sql_r_1 = "SELECT ".__FUNCTION__." FROM ".__CLASS__." WHERE $this->cidr2where AND ".__FUNCTION__." IS NOT NULL";
        if ($this->checkBD($sql_r_1) ) return  base64_decode($this->req2BD4out(__FUNCTION__,__CLASS__,$this->cidr2where));
        else {
            // 
            
            $result = base64_encode($result);
            return base64_decode($this->req2BD4in(__FUNCTION__,__CLASS__,$this->cidr2where,$result));
        }
    }
    
    
    public function cidr2range(){
        $this->titre(__FUNCTION__);
        $result = "";
        $sql_r_1 = "SELECT ".__FUNCTION__." FROM ".__CLASS__." WHERE $this->cidr2where AND ".__FUNCTION__." IS NOT NULL";
        if ($this->checkBD($sql_r_1) ) return  base64_decode($this->req2BD4out(__FUNCTION__,__CLASS__,$this->cidr2where));
        else {
            //
            
            $result = base64_encode($result);
            return base64_decode($this->req2BD4in(__FUNCTION__,__CLASS__,$this->cidr2where,$result));
        }
    }
    
    
    
    
}

?>