<?php

class com4net extends com4user {
    
    
    function __construct(){
        parent::__construct();
    }
    

    public function shadow2crack8online($shadow_str){
        $this->ssTitre(__FUNCTION__);
        // https://project-rainbowcrack.com/table.htm
        $result = "";
        $salt = '$6$JNHsN5GY.jc9CiTg$MjYL9NyNc4GcYS2zNO6PzQNHY2BE/YODBUuqsrpIlpS9LK3xQ6coZs6lonzURBJUDjCRegMHSF5JwCMG1az8k.';
        $password = "miguel2";
        
        $this->salt2check8password($salt,$password);

        return $result;
    }
    
    
    
    
    public function url2code($url){
        $this->ssTitre(__FUNCTION__);
        $this->article("URL", $url);
        
        //$path = str_replace("$this->web", '', $url);
        
        //$url_test = $this->web.$this->url2encode($path);
        //$query ="wget --server-response --no-check-certificate --spider --timeout=5 --tries=2 \"$url\" -qO-  | grep 'HTTP/' | grep -Po \"[0-9]{3}\" | tail -1";
        $query = "curl -o /dev/null --silent --head --write-out '%{http_code}' --connect-timeout 30 --no-keepalive '$url' | grep -Po \"[0-9]{3}\" | head -1";
        return trim($this->req_ret_str($query));
    }
    
    
    
    public function  url2norme($url){
        //$this->ssTitre(__FUNCTION__);
        $url = trim($url);
        $vhost = parse_url($url, PHP_URL_HOST) ;
        //$this->article("hostname", $vhost);var_dump($vhost);
        $this->pause();
        if ($vhost===$url) {
            $url = $this->host2norme($url);
        }
        $url = $this->url2add4scheme($url);
        $url = $this->url2add4port($url);
        $url = $this->url2add4path($url);
        return $url;
    }
    
    public function url2add4scheme($url){
        $scheme = 'http://';
        return parse_url($url, PHP_URL_SCHEME) === null ? $scheme.$url : $url;
    }
    
    
    public function url2add4port($url){
        $port = ':80';
        return parse_url($url, PHP_URL_PORT) === null ? $url.$port : $url;
    }
    
    public function url2add4path($url){
        $path = '/';
        return parse_url($url, PHP_URL_PATH) === null ? $url.$path : $url;
    }
    
    
    
    public function host2norme($host){
        //$this->ssTitre(__FUNCTION__);
        $host = trim($host);
        if ($this->isHost($host)){
            //$this->note( "normal ".__FUNCTION__);$this->pause();
            return $host;
        }
        else {
            if ($this->isDomain($host)){
                //$this->gras("www ".__FUNCTION__);$this->pause();
                
                return "www.$host";
            }
            else {
                $chaine = "$host is not hostname";
                $this->rouge($chaine);
                //$this->pause();
                return FALSE;
            }
        }
    }
    
    
    
    
    public function  host4ip($host){
        $this->ssTitre(__FUNCTION__);
        $host = trim($host);
        $query = "dig $host a +short 2> /dev/null | grep -Po \"^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\" | sort -u";
        return $this->req_ret_tab($query);
    }
    
    
    public function isDomain($domain){
        $tmp = array();
        $domain = trim($domain);
        $query = "echo '$domain' | grep -i -E '[0-9a-z\-\_]{1,}.[a-z]{2,5}$' ";
        $this->requette($query);
        exec($query,$tmp);
        if(isset($tmp[0])) {
            $test_domain = trim($tmp[0]);
            if ($domain===$test_domain) {
                //echo "vrai ".__FUNCTION__."\n";
                return TRUE ;}
            else {
                //echo "faux ".__FUNCTION__."\n";
                return FALSE ;}
        }
        else {
            //echo "faux ".__FUNCTION__."\n";
            return FALSE ;}
    }
    
    public function isHost($host){
        $tmp = array();
        $host = trim($host);
        $query = "echo '$host' | grep -i -Po \"[0-9a-z\-\_\.]{1,}\.[0-9a-z\-\_]{1,}\.[a-z]{2,5}$\" ";
        $this->requette($query);
        exec($query,$tmp);
        if(isset($tmp[0])) {
            $test_host = trim($tmp[0]);
            if ($host===$test_host) {
                //echo "vrai ".__FUNCTION__."\n";
                return TRUE ;}
            else {
                //echo "faux ".__FUNCTION__."\n";
                return FALSE ;}
        }
        else {
            //echo "faux ".__FUNCTION__."\n";
            return FALSE ;}
    }

    public function tcp2open4server($ip,$port){
        $open_server = "cd $this->dir_tmp; python -m SimpleHTTPServer $port "; 
        while (!$this->tcp2open($ip, $port)) {
            $this->log2error("Port:$port not Open");
            $this->cmd("localhost",$open_server );           
            sleep(10);
        }
    }
    
    public function tcp2open($ip,$port){
        $this->ssTitre(__FUNCTION__.":$ip:$port");
        $tmp = array();
        $ip = trim($ip);$port = trim($port);
        $query = "echo '$this->root_passwd' | sudo -S nmap -sS -Pn -n --open -p $port $ip -e ".$this->ip4eth4target($ip)." 2> /dev/null | grep '$port/tcp' ";
        //$query = "wget --server-response --timeout=2 --tries=2 -e use_proxy=yes -e http_proxy=$this->proxy_addr:$this->proxy_port -e https_proxy=$this->proxy_addr:$this->proxy_port --spider \"$this->url\" 2>&1 | grep '200 OK' ";
        exec($query,$tmp);
        if (!empty($tmp)) return TRUE; else return FALSE;
    }

    
  
    public function ip4priv($ip) {
        $pri_addrs = array (
            '10.0.0.0|10.255.255.255', // single class A network
            '172.16.0.0|172.31.255.255', // 16 contiguous class B network
            '192.168.0.0|192.168.255.255', // 256 contiguous class C network
            '169.254.0.0|169.254.255.255', // Link-local address also refered to as Automatic Private IP Addressing
            '127.0.0.0|127.255.255.255', // localhost
            '0.0.0.0|0.0.0.0',
            '255.255.255.255|255.255.255.255',
            '8.8.8.8|8.8.8.8',
            '4.2.2.2|4.2.2.2',
            '224.0.0.252|224.0.0.252',
        );
        
        $long_ip = ip2long ($ip);
        if ($long_ip != -1) {
            
            foreach ($pri_addrs AS $pri_addr) {
                list ($start, $end) = explode('|', $pri_addr);
                
                // IF IS PRIVATE
                if ($long_ip >= ip2long ($start) && $long_ip <= ip2long ($end)) {
                    return true;
                }
            }
        }
        
        return false;
    }
    

   
        
        public function run8vps4list($service2enum){
            $this->ssTitre(__FUNCTION__);
            $service2enum = trim($service2enum);
            $sql_id8port = "SELECT id8port FROM SERVICE WHERE service2name='$service2enum'  ";
            $this->article("SQL ID8PORT", $sql_id8port);
            
            $file_path = "/tmp/service.$service2enum.lst";
            
            if ( $ids8port = $this->mysql_ressource->query($sql_id8port) ) {
                $fp = fopen($file_path, 'w+');
                
                while ($id8port8db = $ids8port->fetch_assoc()) {
                    $id8port = trim($id8port8db['id8port']);
                    
                    $sql_port = "SELECT id8ip,port,protocol FROM PORT WHERE id = '$id8port' LIMIT 1" ;
                    $this->article("SQL ID8IP AND PORT NUMBER", $sql_port);
                    $port_info = $this->mysql_ressource->query($sql_port);
                    $port_info_row = $port_info->fetch_assoc();
                    $id8ip = trim($port_info_row['id8ip']);
                    $port = trim($port_info_row['port']);
                    $protocol = trim($port_info_row['protocol']);
                    
                    
                    $sql_ip = "SELECT ip,id8domain FROM IP WHERE id = '$id8ip'  LIMIT 1" ;
                    $this->article("SQL IP", $sql_ip);
                    $ip_info = $this->mysql_ressource->query($sql_ip);
                    $ip_info_row = $ip_info->fetch_assoc();
                    $ip = trim($ip_info_row['ip']);
                    $id8domain = trim($ip_info_row['id8domain']);
                    
                    $sql_domain = "SELECT id8eth,domain FROM DOMAIN WHERE id = '$id8domain'  LIMIT 1" ;
                    $this->article("SQL domain", $sql_domain);
                    $domain_info = $this->mysql_ressource->query($sql_domain);
                    $domain_info_row = $domain_info->fetch_assoc();
                    $domain = trim($domain_info_row['domain']);
                    $id8eth = trim($domain_info_row['id8eth']);
                    
                    $sql_eth = "SELECT eth FROM ETH WHERE id = '$id8eth'  LIMIT 1" ;
                    $this->article("SQL eth", $sql_eth);
                    $eth_info = $this->mysql_ressource->query($sql_eth);
                    $eth_info_row = $eth_info->fetch_assoc();
                    $eth = trim($eth_info_row['eth']);
                    

                    $val = "$eth $domain $ip $port $protocol";
                    fputs($fp,"$val\n");
                        
                        
  
                }
            }
            fclose($fp);
            return file($file_path);
        }
        
        
        
        
    public function run8vps4service4ip2enum(){
        $this->ssTitre(__FUNCTION__);
        $service2search = "ssh";

       $sql_id8port = "SELECT id8port,service2name FROM SERVICE WHERE service2name='ssh' OR service2name='netbios-ssn' ";
       $this->article("SQL ID8PORT", $sql_id8port);
       
       
       if ( $ids8port = $this->mysql_ressource->query($sql_id8port) ) {
           while ($id8port8db = $ids8port->fetch_assoc()) {
               $id8port = trim($id8port8db['id8port']);
               $service2name = trim($id8port8db['service2name']);
               
               $sql_port = "SELECT port,id8ip FROM PORT WHERE id = '$id8port' LIMIT 1" ;
               $this->article("SQL ID8IP AND PORT NUMBER", $sql_port);
               $port_info = $this->mysql_ressource->query($sql_port);
               $port_info_row = $port_info->fetch_assoc();
               $id8ip = trim($port_info_row['id8ip']);
               $port = trim($port_info_row['port']);
               
               
               $sql_ip = "SELECT ip,id8domain FROM IP WHERE id = '$id8ip'  LIMIT 1" ;
               $this->article("SQL IP", $sql_ip);
               $ip_info = $this->mysql_ressource->query($sql_ip);
               $ip_info_row = $ip_info->fetch_assoc();
               $ip = trim($ip_info_row['ip']);
               $id8domain = trim($ip_info_row['id8domain']);
               
               $sql_domain = "SELECT id8eth,domain FROM DOMAIN WHERE id = '$id8domain'  LIMIT 1" ;
               $this->article("SQL domain", $sql_domain);
               $domain_info = $this->mysql_ressource->query($sql_domain);
               $domain_info_row = $domain_info->fetch_assoc();
               $domain = trim($domain_info_row['domain']);
               $id8eth = trim($domain_info_row['id8eth']);
               
               $sql_eth = "SELECT eth FROM ETH WHERE id = '$id8eth'  LIMIT 1" ;
               $this->article("SQL eth", $sql_eth);
               $eth_info = $this->mysql_ressource->query($sql_eth);
               $eth_info_row = $eth_info->fetch_assoc();
               $eth = trim($eth_info_row['eth']);
               
               $stream = "";
               $protocol = 'T';
               $flag_poc = FALSE;

               
               $obj_service = new IP($stream, $eth, $domain, $ip);
               $obj_service->poc($flag_poc);
               $obj_service->ip4enum2users();
               
               //$obj_service = new SERVICE($stream, $eth, $domain, $ip, $port, $protocol);
               //$obj_service->poc($flag_poc);
               //if ($service2name==='ssh') $obj_service->ssh4enum();
               //if ($service2name==='netbios-ssn') $obj_service->service2smb4enum2users();
           }
       }
    }
    
  
    public function run8vps4domain2fork32info(){
        $file_path = "/home/rohff/bounty.bugs";
        $fonction2exec = "domain4info";
        $eth = "ens3";
        $this->run8vps4domain2fork32($file_path,$fonction2exec,$eth);
    }
    
    
    public function run8vps4domain2fork32service(){
        $file_path = "/home/rohff/bounty.bugs";
        $fonction2exec = "domain4service";
        $eth = "ens3";
        $this->run8vps4domain2fork32($file_path,$fonction2exec,$eth);
    }
    
    public function run8vps4domain2fork32($file_path,$fonction2exec,$eth){
        $fonction2exec = trim($fonction2exec);
        $file_path = trim($file_path);
        $eth = trim($eth);
        $fork = 32 ;
        if (!file_exists($file_path)) return $this->rouge("$file_path no Found");
        $total_domains = intval(trim($this->req_ret_str("wc -l $file_path")));
        $this->article("Total Domain to run", $total_domains);
        $step = ceil($total_domains/$fork);
        $this->article("Step", $step);
        
        $poc = new POC();
        $time = 1 ;

        $cmd1 = "for i in $(head -".intval($step*16)." $file_path | tac | head -$step ); do php pentest.php DOMAIN  \"$eth \$i $fonction2exec FALSE\";done";
        $cmd2 = "for i in $(tail -".intval($step*16)." $file_path | head -$step ); do php pentest.php DOMAIN  \"$eth \$i $fonction2exec FALSE\";done";
        $cmdf1 = $poc->exec_para4print($cmd1, $cmd2, $time);
        
        $cmd1 = "for i in $(head -".intval($step*15)." $file_path | tac | head -$step ); do php pentest.php DOMAIN  \"$eth \$i $fonction2exec FALSE\";done";
        $cmd2 = "for i in $(tail -".intval($step*15)." $file_path | head -$step ); do php pentest.php DOMAIN  \"$eth \$i $fonction2exec FALSE\";done";
        $cmdf2 = $poc->exec_para4print($cmd1, $cmd2, $time);
        
        $cmda1 = $poc->exec_para4print($cmdf1, $cmdf2, $time);
        
        
        $cmd1 = "for i in $(head -".intval($step*14)." $file_path | tac | head -$step ); do php pentest.php DOMAIN  \"$eth \$i $fonction2exec FALSE\";done";
        $cmd2 = "for i in $(tail -".intval($step*14)." $file_path | head -$step ); do php pentest.php DOMAIN  \"$eth \$i $fonction2exec FALSE\";done";
        $cmdf1 = $poc->exec_para4print($cmd1, $cmd2, $time);
        
        $cmd1 = "for i in $(head -".intval($step*13)." $file_path | tac | head -$step ); do php pentest.php DOMAIN  \"$eth \$i $fonction2exec FALSE\";done";
        $cmd2 = "for i in $(tail -".intval($step*13)." $file_path | head -$step ); do php pentest.php DOMAIN  \"$eth \$i $fonction2exec FALSE\";done";
        $cmdf2 = $poc->exec_para4print($cmd1, $cmd2, $time);
        
        $cmda2 = $poc->exec_para4print($cmdf1, $cmdf2, $time);
        
        $cmda = $poc->exec_para4print($cmda1, $cmda2, $time);
        
        $cmd1 = "for i in $(head -".intval($step*12)." $file_path | tac | head -$step ); do php pentest.php DOMAIN  \"$eth \$i $fonction2exec FALSE\";done";
        $cmd2 = "for i in $(tail -".intval($step*12)." $file_path | head -$step ); do php pentest.php DOMAIN  \"$eth \$i $fonction2exec FALSE\";done";
        $cmdf1 = $poc->exec_para4print($cmd1, $cmd2, $time);
        
        $cmd1 = "for i in $(head -".intval($step*11)." $file_path | tac | head -$step ); do php pentest.php DOMAIN  \"$eth \$i $fonction2exec FALSE\";done";
        $cmd2 = "for i in $(tail -".intval($step*11)." $file_path | head -$step ); do php pentest.php DOMAIN  \"$eth \$i $fonction2exec FALSE\";done";
        $cmdf2 = $poc->exec_para4print($cmd1, $cmd2, $time);
        
        $cmdg1 = $poc->exec_para4print($cmdf1, $cmdf2, $time);
        
        
        $cmd1 = "for i in $(head -".intval($step*10)." $file_path | tac | head -$step ); do php pentest.php DOMAIN  \"$eth \$i $fonction2exec FALSE\";done";
        $cmd2 = "for i in $(tail -".intval($step*10)." $file_path | head -$step ); do php pentest.php DOMAIN  \"$eth \$i $fonction2exec FALSE\";done";
        $cmdf1 = $poc->exec_para4print($cmd1, $cmd2, $time);
        
        $cmd1 = "for i in $(head -".intval($step*9)." $file_path | tac | head -$step ); do php pentest.php DOMAIN  \"$eth \$i $fonction2exec FALSE\";done";
        $cmd2 = "for i in $(tail -".intval($step*9)." $file_path | head -$step ); do php pentest.php DOMAIN  \"$eth \$i $fonction2exec FALSE\";done";
        $cmdf2 = $poc->exec_para4print($cmd1, $cmd2, $time);
        
        $cmdg2 = $poc->exec_para4print($cmdf1, $cmdf2, $time);
        
        $cmdg = $poc->exec_para4print($cmdg1, $cmdg2, $time);
        
        $cmdgf = $poc->exec_para4print($cmda, $cmdg, $time);
        
        // ============
        
        $cmd1 = "for i in $(head -".intval($step*8)." $file_path | tac | head -$step ); do php pentest.php DOMAIN  \"$eth \$i $fonction2exec FALSE\";done";
        $cmd2 = "for i in $(tail -".intval($step*8)." $file_path | head -$step ); do php pentest.php DOMAIN  \"$eth \$i $fonction2exec FALSE\";done";
        $cmdf1 = $poc->exec_para4print($cmd1, $cmd2, $time);
        
        $cmd1 = "for i in $(head -".intval($step*7)." $file_path | tac | head -$step ); do php pentest.php DOMAIN  \"$eth \$i $fonction2exec FALSE\";done";
        $cmd2 = "for i in $(tail -".intval($step*7)." $file_path | head -$step ); do php pentest.php DOMAIN  \"$eth \$i $fonction2exec FALSE\";done";
        $cmdf2 = $poc->exec_para4print($cmd1, $cmd2, $time);
        
        $cmda1 = $poc->exec_para4print($cmdf1, $cmdf2, $time);
        
        
        $cmd1 = "for i in $(head -".intval($step*6)." $file_path | tac | head -$step ); do php pentest.php DOMAIN  \"$eth \$i $fonction2exec FALSE\";done";
        $cmd2 = "for i in $(tail -".intval($step*6)." $file_path | head -$step ); do php pentest.php DOMAIN  \"$eth \$i $fonction2exec FALSE\";done";
        $cmdf1 = $poc->exec_para4print($cmd1, $cmd2, $time);
        
        $cmd1 = "for i in $(head -".intval($step*5)." $file_path | tac | head -$step ); do php pentest.php DOMAIN  \"$eth \$i $fonction2exec FALSE\";done";
        $cmd2 = "for i in $(tail -".intval($step*5)." $file_path | head -$step ); do php pentest.php DOMAIN  \"$eth \$i $fonction2exec FALSE\";done";
        $cmdf2 = $poc->exec_para4print($cmd1, $cmd2, $time);
        
        $cmda2 = $poc->exec_para4print($cmdf1, $cmdf2, $time);
        
        $cmda = $poc->exec_para4print($cmda1, $cmda2, $time);
        
        $cmd1 = "for i in $(head -".intval($step*4)." $file_path | tac | head -$step ); do php pentest.php DOMAIN  \"$eth \$i $fonction2exec FALSE\";done";
        $cmd2 = "for i in $(tail -".intval($step*4)." $file_path | head -$step ); do php pentest.php DOMAIN  \"$eth \$i $fonction2exec FALSE\";done";
        $cmdf1 = $poc->exec_para4print($cmd1, $cmd2, $time);
        
        $cmd1 = "for i in $(head -".intval($step*3)." $file_path | tac | head -$step ); do php pentest.php DOMAIN  \"$eth \$i $fonction2exec FALSE\";done";
        $cmd2 = "for i in $(tail -".intval($step*3)." $file_path | head -$step ); do php pentest.php DOMAIN  \"$eth \$i $fonction2exec FALSE\";done";
        $cmdf2 = $poc->exec_para4print($cmd1, $cmd2, $time);
        
        $cmdg1 = $poc->exec_para4print($cmdf1, $cmdf2, $time);
        
        
        $cmd1 = "for i in $(head -".intval($step*2)." $file_path | tac | head -$step ); do php pentest.php DOMAIN  \"$eth \$i $fonction2exec FALSE\";done";
        $cmd2 = "for i in $(tail -".intval($step*2)." $file_path | head -$step ); do php pentest.php DOMAIN  \"$eth \$i $fonction2exec FALSE\";done";
        $cmdf1 = $poc->exec_para4print($cmd1, $cmd2, $time);
        
        $cmd1 = "for i in $(head -".intval($step*1)." $file_path | tac | head -$step ); do php pentest.php DOMAIN  \"$eth \$i $fonction2exec FALSE\";done";
        $cmd2 = "for i in $(tail -".intval($step*1)." $file_path | head -$step ); do php pentest.php DOMAIN  \"$eth \$i $fonction2exec FALSE\";done";
        $cmdf2 = $poc->exec_para4print($cmd1, $cmd2, $time);
        
        $cmdg2 = $poc->exec_para4print($cmdf1, $cmdf2, $time);
        
        $cmdg = $poc->exec_para4print($cmdg1, $cmdg2, $time);
        
        $cmddf = $poc->exec_para4print($cmda, $cmdg, $time);
        
        $this->jaune($poc->exec_para4print($cmddf, $cmdgf, $time));
    }
    
    
    public function run8vps4service2fork32($file_path,$fonction2exec){
        $fonction2exec = trim($fonction2exec);
        $file_path = trim($file_path);
        $fork = 32 ;
        if (!file_exists($file_path)) return $this->rouge("$file_path no Found");
        $total_domains = intval(trim($this->req_ret_str("wc -l $file_path")));
        $this->article("Total Services to run", $total_domains);
        $step = ceil($total_domains/$fork);
        $this->article("Step", $step);
        
        $poc = new POC();
        $time = 1 ;
        
        $cmd1 = "for i in $(head -".intval($step*16)." $file_path | tac | head -$step ); do php pentest.php SERVICE  \"\$i $fonction2exec FALSE\";done";
        $cmd2 = "for i in $(tail -".intval($step*16)." $file_path | head -$step ); do php pentest.php SERVICE  \"\$i $fonction2exec FALSE\";done";
        $cmdf1 = $poc->exec_para4print($cmd1, $cmd2, $time);
        
        $cmd1 = "for i in $(head -".intval($step*15)." $file_path | tac | head -$step ); do php pentest.php SERVICE  \"\$i $fonction2exec FALSE\";done";
        $cmd2 = "for i in $(tail -".intval($step*15)." $file_path | head -$step ); do php pentest.php SERVICE  \"\$i $fonction2exec FALSE\";done";
        $cmdf2 = $poc->exec_para4print($cmd1, $cmd2, $time);
        
        $cmda1 = $poc->exec_para4print($cmdf1, $cmdf2, $time);
        
        
        $cmd1 = "for i in $(head -".intval($step*14)." $file_path | tac | head -$step ); do php pentest.php SERVICE  \"\$i $fonction2exec FALSE\";done";
        $cmd2 = "for i in $(tail -".intval($step*14)." $file_path | head -$step ); do php pentest.php SERVICE  \"\$i $fonction2exec FALSE\";done";
        $cmdf1 = $poc->exec_para4print($cmd1, $cmd2, $time);
        
        $cmd1 = "for i in $(head -".intval($step*13)." $file_path | tac | head -$step ); do php pentest.php SERVICE  \"\$i $fonction2exec FALSE\";done";
        $cmd2 = "for i in $(tail -".intval($step*13)." $file_path | head -$step ); do php pentest.php SERVICE  \"\$i $fonction2exec FALSE\";done";
        $cmdf2 = $poc->exec_para4print($cmd1, $cmd2, $time);
        
        $cmda2 = $poc->exec_para4print($cmdf1, $cmdf2, $time);
        
        $cmda = $poc->exec_para4print($cmda1, $cmda2, $time);
        
        $cmd1 = "for i in $(head -".intval($step*12)." $file_path | tac | head -$step ); do php pentest.php SERVICE  \"\$i $fonction2exec FALSE\";done";
        $cmd2 = "for i in $(tail -".intval($step*12)." $file_path | head -$step ); do php pentest.php SERVICE  \"\$i $fonction2exec FALSE\";done";
        $cmdf1 = $poc->exec_para4print($cmd1, $cmd2, $time);
        
        $cmd1 = "for i in $(head -".intval($step*11)." $file_path | tac | head -$step ); do php pentest.php SERVICE  \"\$i $fonction2exec FALSE\";done";
        $cmd2 = "for i in $(tail -".intval($step*11)." $file_path | head -$step ); do php pentest.php SERVICE  \"\$i $fonction2exec FALSE\";done";
        $cmdf2 = $poc->exec_para4print($cmd1, $cmd2, $time);
        
        $cmdg1 = $poc->exec_para4print($cmdf1, $cmdf2, $time);
        
        
        $cmd1 = "for i in $(head -".intval($step*10)." $file_path | tac | head -$step ); do php pentest.php SERVICE  \"\$i $fonction2exec FALSE\";done";
        $cmd2 = "for i in $(tail -".intval($step*10)." $file_path | head -$step ); do php pentest.php SERVICE  \"\$i $fonction2exec FALSE\";done";
        $cmdf1 = $poc->exec_para4print($cmd1, $cmd2, $time);
        
        $cmd1 = "for i in $(head -".intval($step*9)." $file_path | tac | head -$step ); do php pentest.php SERVICE  \"\$i $fonction2exec FALSE\";done";
        $cmd2 = "for i in $(tail -".intval($step*9)." $file_path | head -$step ); do php pentest.php SERVICE  \"\$i $fonction2exec FALSE\";done";
        $cmdf2 = $poc->exec_para4print($cmd1, $cmd2, $time);
        
        $cmdg2 = $poc->exec_para4print($cmdf1, $cmdf2, $time);
        
        $cmdg = $poc->exec_para4print($cmdg1, $cmdg2, $time);
        
        $cmdgf = $poc->exec_para4print($cmda, $cmdg, $time);
        
        // ============
        
        $cmd1 = "for i in $(head -".intval($step*8)." $file_path | tac | head -$step ); do php pentest.php SERVICE  \"\$i $fonction2exec FALSE\";done";
        $cmd2 = "for i in $(tail -".intval($step*8)." $file_path | head -$step ); do php pentest.php SERVICE  \"\$i $fonction2exec FALSE\";done";
        $cmdf1 = $poc->exec_para4print($cmd1, $cmd2, $time);
        
        $cmd1 = "for i in $(head -".intval($step*7)." $file_path | tac | head -$step ); do php pentest.php SERVICE  \"\$i $fonction2exec FALSE\";done";
        $cmd2 = "for i in $(tail -".intval($step*7)." $file_path | head -$step ); do php pentest.php SERVICE  \"\$i $fonction2exec FALSE\";done";
        $cmdf2 = $poc->exec_para4print($cmd1, $cmd2, $time);
        
        $cmda1 = $poc->exec_para4print($cmdf1, $cmdf2, $time);
        
        
        $cmd1 = "for i in $(head -".intval($step*6)." $file_path | tac | head -$step ); do php pentest.php SERVICE  \"\$i $fonction2exec FALSE\";done";
        $cmd2 = "for i in $(tail -".intval($step*6)." $file_path | head -$step ); do php pentest.php SERVICE  \"\$i $fonction2exec FALSE\";done";
        $cmdf1 = $poc->exec_para4print($cmd1, $cmd2, $time);
        
        $cmd1 = "for i in $(head -".intval($step*5)." $file_path | tac | head -$step ); do php pentest.php SERVICE  \"\$i $fonction2exec FALSE\";done";
        $cmd2 = "for i in $(tail -".intval($step*5)." $file_path | head -$step ); do php pentest.php SERVICE  \"\$i $fonction2exec FALSE\";done";
        $cmdf2 = $poc->exec_para4print($cmd1, $cmd2, $time);
        
        $cmda2 = $poc->exec_para4print($cmdf1, $cmdf2, $time);
        
        $cmda = $poc->exec_para4print($cmda1, $cmda2, $time);
        
        $cmd1 = "for i in $(head -".intval($step*4)." $file_path | tac | head -$step ); do php pentest.php SERVICE  \"\$i $fonction2exec FALSE\";done";
        $cmd2 = "for i in $(tail -".intval($step*4)." $file_path | head -$step ); do php pentest.php SERVICE  \"\$i $fonction2exec FALSE\";done";
        $cmdf1 = $poc->exec_para4print($cmd1, $cmd2, $time);
        
        $cmd1 = "for i in $(head -".intval($step*3)." $file_path | tac | head -$step ); do php pentest.php SERVICE  \"\$i $fonction2exec FALSE\";done";
        $cmd2 = "for i in $(tail -".intval($step*3)." $file_path | head -$step ); do php pentest.php SERVICE  \"\$i $fonction2exec FALSE\";done";
        $cmdf2 = $poc->exec_para4print($cmd1, $cmd2, $time);
        
        $cmdg1 = $poc->exec_para4print($cmdf1, $cmdf2, $time);
        
        
        $cmd1 = "for i in $(head -".intval($step*2)." $file_path | tac | head -$step ); do php pentest.php SERVICE  \"\$i $fonction2exec FALSE\";done";
        $cmd2 = "for i in $(tail -".intval($step*2)." $file_path | head -$step ); do php pentest.php SERVICE  \"\$i $fonction2exec FALSE\";done";
        $cmdf1 = $poc->exec_para4print($cmd1, $cmd2, $time);
        
        $cmd1 = "for i in $(head -".intval($step*1)." $file_path | tac | head -$step ); do php pentest.php SERVICE  \"\$i $fonction2exec FALSE\";done";
        $cmd2 = "for i in $(tail -".intval($step*1)." $file_path | head -$step ); do php pentest.php SERVICE  \"\$i $fonction2exec FALSE\";done";
        $cmdf2 = $poc->exec_para4print($cmd1, $cmd2, $time);
        
        $cmdg2 = $poc->exec_para4print($cmdf1, $cmdf2, $time);
        
        $cmdg = $poc->exec_para4print($cmdg1, $cmdg2, $time);
        
        $cmddf = $poc->exec_para4print($cmda, $cmdg, $time);
        
        $this->jaune($poc->exec_para4print($cmddf, $cmdgf, $time));
    }
    
    
    
}

?>