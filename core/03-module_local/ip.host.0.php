<?php


class HOST extends IP{
    
    
    var $host;
    var $path_dmitry ;
    var $host2where;

    
    
    public function __construct($stream,$eth,$domain,$ip,$host) {

        parent::__construct($stream,$eth,$domain,$ip);
        
        $host = trim($host);
        $host = $this->host2norme($host);
        $tmp = array();
        $query = "echo '$host' $this->filter_host ";
        exec($query,$tmp);
        if ( (isset($tmp[0])) && (!empty($tmp)) && ($this->isIPv4($ip)) ){
            $this->host = $tmp[0];
            $this->host2where = "id8domain = $this->domain2id AND host = '$this->host' AND host2ip = '$ip' ";
            
            $sql_r = "SELECT host FROM ".__CLASS__." WHERE $this->host2where ORDER BY ladate DESC LIMIT 1";
            if (!$this->checkBD($sql_r)) {
                $sql_w = "INSERT  INTO ".__CLASS__." (id8domain,host,host2ip) VALUES ('$this->domain2id','$this->host','$ip') ";
                //echo "$sql_w;\n";
                $this->mysql_ressource->query($sql_w);
                echo $this->note("Working on HOST:$this->host:$ip:$domain for the first time");
                //$this->watching();
                $this->pause();
            }
            
            
        }
        
        else {
            $this->requette($query);
            $this->log2error("Empty Host");
            exit();
        }
        
    }
    
    
    
    
    
    
    public function host2domain($host){
        $tmp = array();
        $rst = "";
        exec("echo '$host' | grep -Po -i \"[0-9a-z_\-]{1,}\.[a-z]{2,5}$\" ",$tmp);
        //var_dump($tmp);$this->pause();
        if(!isset($tmp[0])) $rst = "";
        else $rst = $tmp[0] ;
        return $rst;
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
         
        $sql_r = "SELECT distinct(host2ip) FROM HOST WHERE host = '$this->host'  ";
        echo "$sql_r\n";
        $req = $this->mysql_ressource->query($sql_r);
        while ($row = $req->fetch_assoc()) {
            $ip = $row['host2ip'];
            $dot .= "node [fillcolor = \"#f9f765\",label = \"$ip\"]\n\"$ip\"\n";
            $dot .= "edge [color = grey,len=2]\n\"$this->host\" -> \"$ip\"\n";
            $sql_r2 = "SELECT id,port,protocol FROM PORT WHERE id8ip IN (SELECT id FROM IP WHERE ip = '$ip')";
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
        
        //$this->dot4make($file_output,$host2dot);
        
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
		<TR><TD>HOST2IP</TD><TD PORT=\"ip\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->ip))."</TD></TR>
		<TR><TD>HOST2HOST</TD><TD PORT=\"host2host\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->tab($this->host2host())))."</TD></TR>
		<TR><TD>DOMAIN</TD><TD PORT=\"host2domain\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->host2domain($this->host)))."</TD></TR>
		</TABLE>>];
				";
        // <TR><TD>ZONE-H</TD><TD PORT=\"host2zoneh\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->host2zoneh()))."</TD></TR>
        // <TR><TD>BLACKLIST</TD><TD PORT=\"host2malw\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->host2malw()))."</TD></TR>
        
        
        $host2dot_footer = "
		}";
        
        $host2dot = $host2dot_header.$host2dot_host.$host2dot_footer;
        $host2dot4body = $host2dot_host;
        
        $this->dot4make($file_output,$host2dot);
        return $host2dot4body;
    }
    
    
    
    
    public function host2malw(){
        $this->ssTitre(__FUNCTION__);
        $query = "dmitry -n $this->host";
        return $this->req2BD(__FUNCTION__,__CLASS__,"host = '$this->host'",$query);
    }
    
    
    public function host2host():array{
        $this->ssTitre(__FUNCTION__);
        $tab_hosts = array();
        // update HOST set host2host = NULL where host2host IS NOT NULL ;
        $query = "nslookup -query=ptr ".gethostbyname($this->host);
        $filter = "  | cut -d'=' -f2 | grep -v '$this->host' | grep -v 'arpa' | grep -Po \"[a-z0-9_\-]{1,}\.[a-z_\-]{1,}\.[a-z]{1,5}\"  ";
        $tab_hosts = $this->req_tab($this->stream, $query, $this->stream_timeout, $filter);
        $this->article("Host2host", $this->tab($tab_hosts));
        return $tab_hosts;
          }
 

    
    public function host4info() {
        $this->gtitre(__FUNCTION__);     

        
        
        
        $host_ips = $this->host4ip($this->host);
        if(!empty($host_ips)){
            
            $max_iter = count($host_ips);
                    $this->rouge("ITER IP $max_iter");
                    
                    $file_path = "/tmp/$this->eth.$this->host.ip4info";
                    $fp = fopen($file_path, 'w+');
                    foreach ($host_ips as $ip_addr) {
                        if( (!empty($ip_addr)) && (!$this->ip4priv($ip_addr)) ){
                            $data = "$this->eth $this->domain $ip_addr ip4info FALSE";
                            $data = $data."\n";
                            fputs($fp,$data);

                        }
                    }
                    fclose($fp);
                    
                   
                   // if ( (1<$max_iter) && (20>$max_iter) && (!$this->flag_poc) ) $this->requette("cat  $file_path | parallel --progress -k php pentest.php IP {} "); // -j$max_iter
                    
                }
            
            
            foreach ($host_ips as $ip){
                if ($this->ip4priv($ip)) {
                    $this->rouge("response IP LOCAL from DNS SERVER $this->eth:$this->host:$ip");                    
                }
                if( (!empty($ip)) && (!$this->ip4priv($ip)) ){
                    $query = "php pentest.php IP \"$this->eth $this->domain $ip ip4info FALSE\" ";
                    if (!$this->flag_poc) $this->requette($query);
                    $obj_ip = new IP($this->stream,$this->eth, $this->domain, $ip);
                    $obj_ip->poc($this->flag_poc);
                    $obj_ip->ip4info();
                    $this->pause();
                }
            }
            
    }
    
    
    
    
    
    
}
?>