<?php

class com4net extends com4user {
    
    
    function __construct(){
        parent::__construct();
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
    
    
    public function gpg2remove($stream,$user_id){
        $this->ssTitre(__FUNCTION__);
        $data = "gpg --delete-secret-keys $user_id"; // private 
        $data = "gpg --delete-keys $user_id"; // pub
        return $this->req_str($stream,$data,$this->stream_timeout,"");
    }
    
    public function gpg2info8mail($stream,$mail){
        $this->ssTitre(__FUNCTION__);
        $data = "gpg --fingerprint $mail";
        return $this->req_str($stream,$data,$this->stream_timeout,"");
    }
    
    public function gpg2crypt($stream,$file_path,$user_id){
        $this->ssTitre(__FUNCTION__);
        $data = "gpg --recipient '$user_id' --armor --encrypt --output $file_path.asc $file_path ";
        $data = "gpg --recipient '$user_id' --encrypt --output $file_path.gpg $file_path ";
        //gpg --encrypt --sign --armor -r $mail
        return $this->req_str($stream,$data,$this->stream_timeout,"");
    }
    
    public function gpg2decrypt($stream,$file_enc){
        $this->ssTitre(__FUNCTION__);
        $data = "gpg --decrypt --$file_enc";
        return $this->req_str($stream,$data,$this->stream_timeout,"");
    }
    
    
    public function gpg2priv($stream,$keytype,$keysize,$realname,$email,$expire_date,$pub_name,$priv_name,$passphrase){
        $data = "%echo Generating a basic OpenPGP key
     Key-Type: DSA
     Key-Length: 1024
     Subkey-Type: ELG-E
     Subkey-Length: 1024
     Name-Real: Joe Tester
     Name-Comment: with stupid passphrase
     Name-Email: joe@foo.bar
     Expire-Date: 2021-07-01
     Passphrase: abc
     %pubring foo.pub
     %secring foo.sec
     # Do a commit here, so that we can later print \"done\" :-)
     %commit
     %echo done";
        $data = "gpg --batch --genkey";
        $this->req_str($stream,$data,$this->stream_timeout,"");
    }
    
    public function gpg2priv4list($stream){
        $this->ssTitre(__FUNCTION__);
        $data = "gpg --list-secret-keys --keyid-format LONG";
        return $this->req_str($stream,$data,$this->stream_timeout,"");
    }
    
    
    public function gpg2version($stream){
        $this->ssTitre(__FUNCTION__);
        $data = "gpg --version";
        return $this->req_str($stream,$data,$this->stream_timeout,"");
    }
    
    
    public function gpg2dir($stream){
        $this->ssTitre(__FUNCTION__);
        $home = $this->gpg2version($stream);
        $data = "echo '$home' ";
        $filter = "| grep 'Home:' | cut -d':' -f2 ";
        return $this->req_str($stream,$data,$this->stream_timeout,$filter);
    }
    
    
    public function gpg2priv4list2id($stream):array{
        $this->ssTitre(__FUNCTION__);
        $str_list = $this->gpg2priv4list($stream);
        $data = "echo '$str_list'";
        $filter = "| grep 'sec'  | grep '/' | cut -d '/' -f2 | cut -d ' ' | grep -Po \"[A-Z0-9]{8}\" ";
        return $this->req_tab($stream,$data,$this->stream_timeout,$filter);
    }
    
    
    public function gpg2pub8id($stream,$imported_keypriv_id,$outputpath_asc){
        $this->ssTitre(__FUNCTION__);
        // gpg --output rohff2.gpg --export rafik.guehria@mbis-inc.net
        // gpg --output rohff2.asc --armor --export rafik.guehria@mbis-inc.net
        // gpg --output rohff.asc --armor --export '424C7AF1'
        $data = "gpg --armor --export $imported_keypriv_id > $outputpath_asc";
        return $this->req_str($stream,$data,$this->stream_timeout,"");
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
        $query = "curl -o /dev/null --silent --head --write-out '%{http_code}' --connect-timeout 3 --no-keepalive '$url'  | grep -Po \"[0-9]{3}\" | head -1";
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
    
    
    
    
    public function  host4ip($host):array{
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
            
            $sql = "select eth,domain,ip,port,protocol FROM PORT JOIN IP ON IP.id = PORT.id8ip JOIN DOMAIN ON DOMAIN.id = IP.id8domain JOIN ETH ON ETH.id = DOMAIN.id8eth where PORT.id IN (select id8port FROM SERVICE where service2name = '$service2enum') ORDER BY domain ;";
            $this->article("SQL ", $sql);
            
            $file_path = "/tmp/services.$service2enum.lst";
            
            if ( $ids = $this->mysql_ressource->query($sql) ) {
                $fp = fopen("$file_path.tmp", 'w+');
                
                while ($id = $ids->fetch_assoc()) {

                    $port = trim($id['port']);
                    $protocol = trim($id['protocol']);
                    $ip = trim($id['ip']);
                    $domain = trim($id['domain']);
                    $eth = trim($id['eth']);
                    

                    $val = "$eth $domain $ip $port $protocol";
                    fputs($fp,"$val\n");
                }
            }
            fclose($fp);
            $query = "cat $file_path.tmp | sort -u | tee $file_path";
            $this->requette($query);
            $query = "wc -l $file_path";
            $this->requette($query);
            return file($file_path);
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
        
        $poc = new com4code();
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
        
        $fin = $poc->exec_para4print($cmddf, $cmdgf, $time);
        $this->jaune($fin);
        
        return $fin;
    }
    
 
 
    
    
}

?>