<?php


class HOST extends DOMAIN{
    
    
    var $host;
    var $path_dmitry ;

    
    
    public function __construct($eth,$domain,$host) {
        parent::__construct($eth,$domain);
        
        $this->host = trim($host);	
        if (empty($this->host)) {
            $this->log2error("Empty Host",__FILE__,__CLASS__,__FUNCTION__,__LINE__,"","");
            exit();
        }
    }
    
    
    public function host2dot4port(){
        $this->gtitre(__FUNCTION__);
        $dot = "";
        $ips = array();
        $file_output = "/tmp/$this->host.".__FUNCTION__.".dot";
        // http://www.yosbits.com/wordpress/?page_id=6182
        $host2dot_header = "digraph ".__FUNCTION__." {
	    graph [rankdir = \"LR\",layout = neato]
        node [shape = circle,style = filled,color = grey,fixedsize=true]
        node [fillcolor =  \"#65d1f9\",label = \"$this->host\"]\n\"$this->host\"\n";
         
        $sql_r = "SELECT ip FROM IP WHERE ip2host = '$this->host'  ";
        echo "$sql_r\n";
        $req = $this->mysql_ressource->query($sql_r);
        while ($row = $req->fetch_assoc()) {
            $ip = $row['ip'];
            $dot .= "node [fillcolor = \"#f9f765\",label = \"$ip\"]\n\"$ip\"\n";
            $dot .= "edge [color = grey,len=2]\n\"$this->host\" -> \"$ip\"\n";
            $sql_r2 = "SELECT id,port,protocol FROM PORT WHERE id8ip IN (SELECT id FROM IP WHERE ip2host = '$this->host' AND ip = '$ip')";
            //echo "$sql_r\n";
            $req2 = $this->mysql_ressource->query($sql_r2);
            while ($row2 = $req2->fetch_assoc()) {
                $port = $row2['port'];
                $protocol = $row2['protocol'];
                $dot .= "node [fillcolor = \"#86f94e\",label = \"$port:$protocol\"]\n\"$port:$protocol\"\n";
                $dot .= "edge [color = grey]\n\"$ip\" -> \"$port:$protocol\"\n";
            }
        }


        
        
        
        $host2dot_footer = "\n}\n";
        $host2dot = $host2dot_header.$dot.$host2dot_footer;
        $host2dot4body = $dot;
        
        $this->dot4make($file_output,$host2dot);
        
        //$this->requette("gedit $file_output");
        return $host2dot4body;
    }
    
    
    public function host2dot(){
        $this->gtitre(__FUNCTION__);
        
        $file_output = "$this->dir_tmp/$this->host.".__FUNCTION__.".dot";
        $color_host = "yellow";$color_arrow = "gold";
        
        $host2dot_header = "digraph structs {
	    label = \"".__FUNCTION__.":$this->host\";
		graph [rankdir = \"LR\" layout = dot];
		node [fontsize = \"16\" shape = \"plaintext\"];
		edge [penwidth=2.0 ];";
        
        
        $host2dot_host = "
		\"$this->host\" [label=<<TABLE BORDER=\"0\" CELLBORDER=\"1\" CELLSPACING=\"0\">
		<TR><TD><IMG SRC=\"$this->dir_img/ico/hostname.png\" /></TD><TD PORT=\"host\" bgcolor=\"$color_host\">$this->host</TD></TR>
		<TR><TD>HOST2IP</TD><TD PORT=\"host2ip\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->host2ip()))."</TD></TR>
		<TR><TD>HOST2HOST</TD><TD PORT=\"host2host\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->host2host()))."</TD></TR>
		<TR><TD>DOMAIN</TD><TD PORT=\"host2domain\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->host2domain()))."</TD></TR>
		</TABLE>>];
				";
        // <TR><TD>ZONE-H</TD><TD PORT=\"host2zoneh\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->host2zoneh()))."</TD></TR>
        // <TR><TD>BLACKLIST</TD><TD PORT=\"host2malw\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->host2malw()))."</TD></TR>
        
        
        $host2dot_footer = "
		}";
        
        $host2dot = $host2dot_header.$host2dot_host.$host2dot_footer;
        $host2dot4body = $host2dot_host;
        
        //$this->dot4make($file_output,$host2dot);
        return $host2dot4body;
    }
    
    
    
    
    public function host2malw(){
        $this->ssTitre(__FUNCTION__);
        $query = "dmitry -n $this->host";
        return $this->req2BD(__FUNCTION__,__CLASS__,"host = '$this->host'",$query);
    }
    
    
    public function host2host(){
        $this->ssTitre(__FUNCTION__);
        // update HOST set host2host = NULL where host2host IS NOT NULL ;
        $query = "nslookup -query=ptr ".gethostbyname($this->host)."  | cut -d'=' -f2 | grep -v '$this->host' | grep -Po \"[a-z0-9_\-]{1,}\.[a-z_\-]{1,}\.[a-z]{1,5}\"  ";
        return $this->req2BD(__FUNCTION__,__CLASS__,"host = '$this->host'",$query);
    }
    
    public function host4service() {
        $this->gtitre(__FUNCTION__);
       
        $host_ips = $this->host4ip($this->host);
        if(!empty($host_ips)){
            $ips = $host_ips;
            if (!empty($ips)) {
                $max_iter = count($ips);
                $this->rouge("ITER IP $max_iter");

                $file_path = "/tmp/$this->eth.$this->host.ip4service";
                $fp = fopen($file_path, 'w+');
                foreach ($ips as $ip_addr) {
                    if( (!empty($ip_addr)) && (!$this->ip4priv($ip_addr)) ){
                        $data = "$this->eth $this->domain $ip_addr ip4service FALSE";
                        $data = $data."\n";
                        fputs($fp,$data);
                    }
                }
                fclose($fp);
                
                if ( (1<$max_iter) && (20>$max_iter)) $this->requette("cat  $file_path | parallel --progress -k php pentest.php IP {} "); // -j$max_iter
                
            }
            
            foreach ($host_ips as $ip){
                if ($this->ip4priv($ip)) {
                    $query = "dig $this->host a +trace | grep '$this->domain'";
                    $trace = $this->req_ret_str($query);
                    echo $trace;
                    $this->log2error("response IP LOCAL from DNS SERVER $this->eth:$this->host:$ip", __FILE__,__CLASS__,__FUNCTION__, __LINE__, "$this->eth:$this->domain:$this->host:$ip", "$trace");
                    
                }
                if( (!empty($ip)) && (!$this->ip4priv($ip)) ){
                $obj_ip = new IP($this->eth, $this->domain, $ip);
                $obj_ip->poc($this->flag_poc);
                $obj_ip->ip2host($this->host);
                $obj_ip->ip4service();
                }
            }
            
            
        }
    
    }
    
    
    
    public function host4info() {
        $this->gtitre(__FUNCTION__);        
        $host_ips = $this->host4ip($this->host);
        if(!empty($host_ips)){
            foreach ($host_ips as $ip){
                if ($this->ip4priv($ip)) {
                    $this->rouge("response IP LOCAL from DNS SERVER $this->eth:$this->host:$ip");                    
                }
                if( (!empty($ip)) && (!$this->ip4priv($ip)) ){
                    $obj_ip = new IP($this->eth, $this->domain, $ip);
                    $obj_ip->poc($this->flag_poc);
                    $obj_ip->ip2host($this->host);
                    $obj_ip->ip4info();
                }
            }
        }    
    }
    
    
    
    
    
    
}
?>