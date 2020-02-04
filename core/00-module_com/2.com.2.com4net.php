<?php

class com4net extends com4user {
    
    
    function __construct(){
        parent::__construct();
    }
    
    
    function ssh($host,$port,$login,$mdp,$command) {
        $result = "";
        $query = "sshpass -p '$mdp' ssh $login@$host -p $port -o ConnectTimeout=15 -o StrictHostKeyChecking=no  -o UserKnownHostsFile=/dev/null -C \"$command\" ";
        
        //$this->req_ret_str($query);
        
        echo "\t\033[37;41;1;1mHost:\033[0m\033[37;40;1;4m$login:$mdp@$host/:$:\033[0m \033[33;40;1;1m$command\033[0m\n";
        $con = ssh2_connect( $host, $port );
        ssh2_auth_password( $con, $login, $mdp );
        $stream = ssh2_exec($con, $command);
        stream_set_blocking($stream, true);
        stream_set_timeout($stream,60);
        $stream_out = ssh2_fetch_stream($stream, SSH2_STREAM_STDIO);
        $result = stream_get_contents($stream_out);
        if (!empty($result)) $this->article("RESULT", $result);
        else fclose($stream);
        
        
        /*
         if (!($con = ssh2_connect($host, $port))) {
         echo "fail: unable to establish connection\n";
         } else {
         // try to authenticate with username root, password secretpassword
         if (!ssh2_auth_password($con, $login, $mdp)) {
         echo "fail: unable to authenticate\n";
         } else {
         if (!($stream = ssh2_shell($con, 'vt102', null, 80, 40, SSH2_TERM_UNIT_CHARS))) {
         echo "fail: unable to establish shell\n";
         } else {
         //ssh2_exec($con, $command);
         stream_set_blocking($stream, true);
         stream_set_timeout($stream,5);
         $stream_out = ssh2_fetch_stream($stream, SSH2_STREAM_STDIO);
         $result = stream_get_contents($stream_out);
         if (!empty($result)) $this->article("RESULT", $result);
         else fclose($stream);
         }
         }
         }
         */
        
        
        return $result;
    }
    
    
    public function  ip4dns($ip){
        $this->ssTitre(__FUNCTION__);
        $query = "nslookup -query=ptr $ip 2> /dev/null | grep 'name' | cut -d'=' -f2 | sed \"s/\.$//g\" | tr -d ' ' | grep  -i -Po \"([0-9a-zA-Z_-]{1,}\.)+[a-zA-Z]{1,4}\" ";
        return $this->req_ret_str($query);
    }
    
    public function url2search($user2agent,$url,$filter){
        $this->ssTitre(__FUNCTION__);
        $query = "wget --user-agent='$user2agent' \"$url\" --timeout=40 --tries=2 --no-check-certificate -qO- $filter 2> /dev/null";
        return $this->req_ret_str($query);
    }
    
    public function url2check($user2agent,$url,$filter){
        $this->ssTitre(__FUNCTION__);
        if (empty($this->url2search($user2agent, $url, $filter))) return FALSE ;
        else return TRUE;
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
    
    public function  host4ip($host){
        $this->ssTitre(__FUNCTION__);
        $host = trim($host);
        $query = "dig $host a +short 2> /dev/null | grep -Po \"^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\" ";
        return $this->req_ret_tab($query);
    }
    
    
    
    
    public function url2code($url){
        $this->ssTitre(__FUNCTION__);
        //$query ="wget --server-response --no-check-certificate --spider --timeout=5 --tries=2 \"$url\" -qO-  | grep 'HTTP/' | grep -Po \"[0-9]{3}\" | tail -1";
        $query = "curl -o /dev/null --silent --head --write-out '%{http_code}' --connect-timeout 2 --no-keepalive \"$url\" | grep -Po \"[0-9]{3}\" ";
        return trim($this->req_ret_str($query));
       }
    
    
    
    
    public function ip2domain($ip){
        $ip = trim($ip);
        if (empty($ip)) $this->rouge("Empty IP");
        
        $tab_hosts = $this->ip2host4nslookup($ip);
        if(!empty($tab_hosts)){
        foreach ($tab_hosts as $host){
            if (!empty($host)){
                return $this->host2domain($host);
            }
        }
        }
    }
    
    
    public function  ip2host4nslookup($ip){
        $this->ssTitre(__FUNCTION__);
        $query = "nslookup -query=ptr $ip 2> /dev/null | grep 'name' | cut -d'=' -f2 | sed \"s/\.$//g\" | tr -d ' ' | grep  -i -Po \"([0-9a-zA-Z_-]{1,}\.)+[a-zA-Z]{1,4}\" ";
        return $this->req_ret_tab($query);
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
    
    public function url2cookies($url){
        $this->ssTitre(__FUNCTION__);
        // 
        $query = "wget --user-agent='$this->user2agent' --server-response --spider --keep-session-cookies \"$url\" -qO-  ";
        $this->requette($query);
        $query = "curl --silent --output /dev/null --connect-timeout 10 --no-keepalive --head \"$url\" | grep -i 'Set-Cookie' | cut -d'=' -f2 | cut -d';' -f1 | grep -Po \"[a-z0-9]{32,}\"  ";
        
        return $this->req_ret_str($query);
    }
    
    
    public function ip4cidr2port($ip,$port,$protocol){
        $this->ssTitre(__FUNCTION__);
        $cidr = trim($this->ip4cidr($ip)).".0/24";        
        return $this->req_ret_tab("echo '$this->root_passwd' | sudo -S nmap -s$protocol -T 3 -Pn -v -n -p $port --open $cidr | grep '$port/' | grep -Po \"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\" ");
    }
    
    public function ip4cidr($ip){
        $this->ssTitre(__FUNCTION__);
        $cidr = $this->req_ret_str("echo '$ip' | grep -Po \"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\" | grep -Po \"^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\" ");
        return $cidr;
    }
    
    
    public function ip4local(){
        $this->ssTitre(__FUNCTION__);
        // ifconfig | grep -Po "inet (adr:)?([0-9]*\.){3}[0-9]*" | grep -Po "([0-9]*\.){3}[0-9]*" | grep -v '127.0.0.1' | grep '$filter_cidr'
        $query = "hostname --all-ip-addresses";
        return $this->req_ret_str($query);
    }
    
    public function ip4addr4target($target_ip){
        $target_ip = trim($target_ip);
        if($this->isIPv4($target_ip)){
            $query = "ip -o route get to $target_ip 2> /dev/null | grep -Po \"src [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\" | grep -Po \"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\"";
            return trim(exec($query));
        }
        else $this->rouge("$target_ip IS NOT IPv4");
    }
    
    public function ip4eth4target($target_ip){
        $target_ip = trim($target_ip);
        if($this->isIPv4($target_ip)){
            $query = "ip -o route get to $target_ip 2> /dev/null | grep -Po \"dev [[:print:]]{1,} src\" | sed \"s/dev//g\"  | sed \"s/src//g\" ";
            exec($query,$tmp);
            return trim($tmp[0]);
        }
        else $this->rouge("$target_ip IS NOT IPv4");
    }
    
    public function tcp2open4server($ip,$port){
        $open_server = "cd $this->dir_tmp; python -m SimpleHTTPServer $port "; 
        while (!$this->tcp2open($ip, $port)) {
            $this->rouge("Port:$port not Open");
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
    public function url2form($url){
        $this->ssTitre(__FUNCTION__); // --proxy=http://$this->proxy_addr:$this->proxy_port  --output-dir=$this->rep_path -t $this->rep_path/$this->vhost.http.log.sqlmap --dump-format=SQLITE | tee $file_output
        $query = "wget --user-agent='$this->user2agent' \"$url\" --timeout=2 --tries=2 --no-check-certificate -qO- 2> /dev/null   | perl $this->dir_tools/web/formfind.pl ";
        return $this->req_ret_str($query);
    }
    
    public function url2encode($chaine){
        $uri_encoded = "";
        for($i = 0; $i < strlen($chaine); $i ++)
            $uri_encoded .= "%" . dechex(ord($chaine [$i]));
            return $uri_encoded ;
    }
    
  
    
    
    
    public function ip4net(){
        $this->ssTitre(__FUNCTION__);
        $filter = "| grep -Po \"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\"";
        $url = "http://ifconfig.me/ip"; 
        return $this->url2search($this->user2agent, $url, $filter);
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