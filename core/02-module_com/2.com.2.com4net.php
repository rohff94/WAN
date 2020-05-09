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
    
    
    
    
    
    
    
}

?>