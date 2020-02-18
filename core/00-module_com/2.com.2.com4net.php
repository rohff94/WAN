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
        $this->article("URL", $url);
        
        $path = str_replace("$this->web", '', $url);
        
        $url_test = $this->web.$this->url2encode($path);
        //$query ="wget --server-response --no-check-certificate --spider --timeout=5 --tries=2 \"$url\" -qO-  | grep 'HTTP/' | grep -Po \"[0-9]{3}\" | tail -1";
        $query = "curl -o /dev/null --silent --head --write-out '%{http_code}' --connect-timeout 3 --no-keepalive '$url_test' | grep -Po \"[0-9]{3}\" ";
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
        $ip = "";
        $tmp = array();
        $filter = "| grep -Po \"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\"";
        $url = "http://ifconfig.me/ip"; 
        $query = "wget --user-agent='$this->user2agent' \"$url\" --timeout=40 --tries=2 --no-check-certificate -qO- $filter 2> /dev/null";
        $ip = exec($query,$tmp);
        if (isset($tmp[0])) $ip = $tmp[0];
        return $ip;

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
    
    
    
    
    
    public function openvas(){
        // ADD certificat lsl credentials
        
        // watch -n60 "omp -u rohff -w hacker --get-tasks | grep -E '(Running|New)'"
        
        // https://github.com/archerysec/archerysec#openvas-setting
        // https://github.com/OpenSCAP/openscap
        // https://github.com/vulnersCom/nmap-vulners
        
        // watch -n 5 "omp -u rohff -w hacker --get-tasks  | grep -v 'Done' "
        // omp --get-report-formats
        // https://docs.greenbone.net/API/OMP/omp-7.0.html
        
        // https://docs.greenbone.net/API/OMP/omp-7.0.html#command_create_alert
        
        /*
         https://docs.greenbone.net/API/OMP/omp-7.0.html#command_empty_trashcan
         https://docs.greenbone.net/API/OMP/omp-7.0.html#command_get_alerts
         https://docs.greenbone.net/API/OMP/omp-7.0.html#command_get_credentials
         
         for i in $(omp -u rohff -w hacker --get-tasks | cut -d ' ' -f1);do echo "delete $i "; omp -u rohff -w hacker --delete-task $i ;done
         omp -u rohff -w hacker -iX "<empty_trashcan/>"
         omp -u rohff -w hacker -iX "<delete_target target_id='6c40d599-38d2-4bab-9804-1300b9b75155' />"
         for i in $(omp -u rohff -w hacker --get-targets | cut -d ' ' -f1);do echo "delete $i "; omp -u rohff -w hacker -iX "<delete_target target_id='$i' />"  ;done
         */
        
        
        $result = "";
        
        $port_list_uuid = $this->openvas2port_list_uuid();
        
        $result .= $this->article("PORT LIST", $port_list_uuid);
        $this->pause();
        
        
        
        $creds_snmp_uuid = "";
        
        
        $sql_r_2 = "SELECT user2name,user2pass FROM AUTH WHERE id8port IN (select id from PORT where id8ip = '$this->ip2id' AND (port = 22 OR service2name LIKE \"%ssh%\")) AND ( user2name != '' AND user2pass != '' ) ORDER by user2gid ASC,user2uid ASC ";
        echo "$sql_r_2 \n"; $this->pause();
        $conn = $this->mysql_ressource->query($sql_r_2);
        while($row = $conn->fetch_assoc()){
            $user2name = trim($row["user2name"]);
            $user2pass = trim($row["user2pass"]);
            $port_ssh = $this->ip2port4service("ssh");
            $creds_ssh_uuid = $this->openvas2creds4ssh_uuid($user2name,$user2pass);
            //var_dump($this->openvas2creds4ssh_uuid());  $this->pause();
            $result .= $this->article("SSH UUID", $creds_ssh_uuid);
            $result .= $this->article("SSH PORT", $port_ssh);
            $result .= $this->openvas2exec($port_list_uuid,$creds_ssh_uuid, $port_ssh, "","", $creds_snmp_uuid);
            $this->pause();
        }
        
        
        
        $sql_r_1 = "SELECT user2name,user2pass FROM AUTH WHERE id8ip IN (select id from PORT where id8ip = '$this->ip2id' AND (port = 445 OR port = 137 OR service2name LIKE \"%smb%\" OR service2name LIKE \"%samba%\")) AND ( user2name != '' AND user2pass != '' ) ORDER by user2gid ASC,user2uid ASC";
        //echo "$sql_r_2\n";
        $conn1 = $this->mysql_ressource->query($sql_r_1);
        while($row = $conn1->fetch_assoc()){
            $port = trim($row["port"]);
            $protocol = trim($row["protocol"]);
            $user2name = trim($row["user2name"]);
            $user2pass = trim($row["user2pass"]);
            list($creds_smb_port,$creds_smb_uuid) = explode(',',$this->openvas2creds4smb_uuid($ip,$port, $protocol, $user2name, $user2pass));
            $result .= $this->article("SMB UUID", $creds_smb_uuid);
            $result .= $this->article("SMB PORT", $creds_smb_port);
            $result .= $this->openvas2exec($port_list_uuid,"", "", $creds_smb_uuid,$creds_smb_port, $creds_snmp_uuid);
            
            $this->pause();
        }
        
        
        
        $creds_snmp_uuid = $this->openvas2creds4snmp_uuid();
        $this->article("SNMP UUID", $creds_snmp_uuid);
        $this->pause();
        
        
        
        /*
         *
         load openvas
         //  you need to use the port for the OpenVAS manager server, openvasmd, which defaults to 9390.
         openvas_connect $this->mysql_login $this->mysql_passwd 127.0.0.1 9390
         [+] OpenVAS connection successful
         
         
         $query = "echo -e \"db_status\nload nexpose\ndb_import $this->dir_tmp/rsm_nexpose.xml\ndb_hosts -c address,svcs,vulns\ndb_autopwn -p -x -e -t -r\n\" > $this->dir_tmp/rsm_nexpose.rc; cat $this->dir_tmp/rsm_nexpose.rc";
         $this->requette($query);
         */
        
        return $result ;
    }
    
    
    public function openvas2exec($port_list_uuid,$creds_ssh_uuid, $creds_ssh_port, $creds_smb_uuid,$creds_smb_port, $creds_snmp_uuid){
        $result = "";
        $target_name = "$this->ip:ssh_uuid:$creds_ssh_uuid:smb_uuid:$creds_smb_uuid:snmp_uuid:$creds_snmp_uuid";
        $report_uuid = trim($this->req_ret_str("grep -l '$target_name' $this->dir_tmp/*.xml | grep -Po \"[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}\" "));
        if(!empty($report_uuid)){
            $result .= $this->article("Report UUID", $report_uuid);
            $check_done = $this->req_ret_str("cat $this->dir_tmp/$report_uuid"."_faraday_openvas.xml  | grep -v '<?xml version=' ");
            $target_uuid = trim($this->req_ret_str("cat $this->dir_tmp/$report_uuid"."_faraday_openvas.xml | xmlstarlet sel -t -v '/report/report/task/target/@id' "));
            $result .= $this->article("Target UUID", $target_uuid);
            $task_uuid = trim($this->req_ret_str("cat $this->dir_tmp/$report_uuid"."_faraday_openvas.xml | xmlstarlet sel -t -v '/report/report/task/@id' "));
            $result .= $this->article("Task UUID", $task_uuid);
            
            $report_uuid_result_xml = $this->openvas2report2get($report_uuid);
            $result .= $report_uuid_result_xml ;
            
            $this->openvas2report2result($report_uuid_result_xml);
            $this->pause();
            if(!empty($check_done)){
                $this->rouge("ALL DONE");
                $this->pause();
                
                //$this->requette("omp -u rohff -w hacker --delete-task $task_uuid ");
                //$this->requette("omp -u rohff -w hacker -iX \"<delete_target target_id='$target_uuid' />\" ");
                $this->pause();
            }
        }
        else {
            $target_uuid = $this->openvas2target2uuid($target_name,$port_list_uuid,$creds_ssh_uuid,$creds_ssh_port,$creds_smb_uuid,$creds_smb_port,$creds_snmp_uuid);
            $result .= $this->article("Target UUID", $target_uuid);
            $this->pause();
            
            $this->note("config ID "); $this->cmd("localhost","omp -u $this->mysql_login -w $this->mysql_passwd -g");
            
            $task_uuid = $this->openvas2task2uuid($target_name,$target_uuid);
            $result .= $this->article("Task UUID", $task_uuid);
            $this->pause();
            
            $report_uuid = $this->openvas2report2uuid($target_name, $task_uuid);
            $result .= $this->article("Report UUID", $report_uuid);
            $this->pause();
            
            
            $report_uuid_result_xml = $this->openvas2report2get($report_uuid);
            $result .= $report_uuid_result_xml ;
            
            $this->openvas2report2result($report_uuid_result_xml);
            
            $this->openvas2report2faraday($report_uuid);
            $this->pause();
        }
        return $result;
    }
    
    
    public function openvas2creds4ssh_uuid($user2name,$user2pass){
        $this->ssTitre(__FUNCTION__);
        
        $creds_ssh_uuid = "";
        
        
        if (!empty($user2name) && !empty($user2pass)) {
            $this->ssTitre("Credentials SSH");
            $query = "omp -u $this->mysql_login -w $this->mysql_passwd -X \"<create_credential><name>$this->ip $user2name:$user2pass</name><login>$user2name</login><password>$user2pass</password><comment></comment></create_credential>\" | xmlstarlet sel -t -v /create_credential_response/@id";
            $this->cmd("localhost",$query);
            
            
            while (TRUE)   {
                if (!empty($creds_ssh_uuid = $this->openvas2credentials4check($user2name,$user2pass))) break;
                if (!empty($creds_ssh_uuid = trim($this->req_ret_str($query))) ) break;
                sleep(2);
            }
            
        }
        
        return "$creds_ssh_uuid" ;
    }
    
    
    public function openvas2creds4snmp_uuid(){
        $this->ssTitre(__FUNCTION__);
        $creds_snmp_uuid = "";
        $sql_r_2 = "SELECT user2name,user2pass FROM AUTH WHERE id8port='$this->' AND (port = 161 OR user2info LIKE \"%snmp%\") AND ( user2name != '' AND user2pass != '' ) ORDER by user2gid ASC,user2uid ASC LIMIT 1 ";
        $conn = $this->mysql_ressource->query($sql_r_2);
        while($row = $conn->fetch_assoc()){
            $port = trim($row["port"]);
            $protocol = trim($row["protocol"]);
            $user2name = trim($row["user2name"]);
            $user2pass = trim($row["user2pass"]);
            
            if (!empty($user2name) && !empty($user2pass)) {
                $this->ssTitre("Credentials SNMP");
                $query = "omp -u $this->mysql_login -w $this->mysql_passwd -X \"<create_credential><name>$this->ip $port $protocol $user2name:$user2pass</name><login>$user2name</login><password>$user2pass</password><comment></comment></create_credential>\" | xmlstarlet sel -t -v /create_credential_response/@id";
                $this->cmd("localhost",$query);
                
                
                while ( TRUE )   {
                    if (!empty($creds_snmp_uuid = $this->openvas2credentials4check($ip,$port,$protocol,$user2name,$user2pass))) break;
                    if (!empty($creds_snmp_uuid = trim($this->req_ret_str($query)))) break;
                    sleep(2);
                }
            }
        }
        return $creds_snmp_uuid;
    }
    
    
    public function openvas2creds4smb_uuid($ip,$port,$protocol,$user2name,$user2pass){
        $this->ssTitre(__FUNCTION__);
        if (!empty($user2name) && !empty($user2pass)) {
            $this->ssTitre("Create Credentials SMB");
            $query = "omp -u $this->mysql_login -w $this->mysql_passwd -X \"<create_credential><name>$this->ip $port $protocol $user2name:$user2pass</name><login>$user2name</login><password>$user2pass</password><comment></comment></create_credential>\" | xmlstarlet sel -t -v /create_credential_response/@id";
            $this->cmd("localhost",$query);
            
            
            while ( TRUE )   {
                if (!empty($creds_smb_uuid = $this->openvas2credentials4check($this->ip,$port,$protocol,$user2name,$user2pass))) break;
                if (!empty($creds_smb_uuid = trim($this->req_ret_str($query)))) break;
                sleep(2);
            }
            
        }
        
        
        return "$port,$creds_smb_uuid";
    }
    
    public function openvas2port_list_uuid(){
        $this->ssTitre("PORT LIST");
        $port_list_uuid = "";
        
        
        $result_scan = $this->ip2port();
        if (!empty($result_scan)) {
            
            
            
            $query = "omp -u $this->mysql_login -w $this->mysql_passwd -X \"<create_port_list><name>Open Port List $this->ip</name><comment>Open Ports</comment><port_range>T:".implode(",",$this->tab_open_ports_tcp)." U:".implode(",",$this->tab_open_ports_udp)."</port_range></create_port_list>\" | xmlstarlet sel -t -v /create_port_list_response/@id";
            $this->cmd("localhost",$query);
            
            if( (empty($this->tab_open_ports_tcp)) AND (empty($this->tab_open_ports_udp)) ) return $this->rouge("No PORT open found ");
            while ( TRUE )   {
                if (!empty($port_list_uuid = $this->openvas2port_list2check())) break;
                if (!empty($port_list_uuid = trim($this->req_ret_str($query))) ) break;
                sleep(2);
                
            }
            
        }
        return $port_list_uuid;
    }
    
    
    public function openvas2target2uuid($target_name,$port_list_uuid,$creds_ssh_uuid,$creds_ssh_port,$creds_smb_uuid,$creds_smb_port,$creds_snmp_uuid){
        $this->ssTitre(__FUNCTION__);
        
        $query = "omp -u $this->mysql_login -w $this->mysql_passwd -X \"<create_target><name>$target_name</name><hosts>$this->ip</hosts>";
        
        if(!empty($creds_ssh_uuid)) $query .= "<ssh_credential id='$creds_ssh_uuid' ><port>$creds_ssh_port</port></ssh_credential>";
        if(!empty($creds_smb_uuid)) $query .= "<smb_credential id='$creds_smb_uuid' ></smb_credential>";
        if(!empty($creds_snmp_uuid)) $query .= "<snmp_credential id='$creds_snmp_uuid'></snmp_credential>";
        $query .= "<port_list id='$port_list_uuid' ></port_list>";
        $query .= "</create_target>\" | xmlstarlet sel -t -v /create_target_response/@id";
        $this->cmd("localhost",$query);
        
        while ( TRUE )   {
            if (!empty($target_uuid = $this->openvas2target4check($target_name))) break;
            if (!empty($target_uuid = trim($this->req_ret_str($query)))) break;
            sleep(2);
        }
        return $target_uuid ;
    }
    
    public function openvas2task2uuid($target_name,$target_uuid){
        $this->ssTitre(__FUNCTION__);
        $query = "omp -u $this->mysql_login -w $this->mysql_passwd -X \"<create_task><name>Scan $target_name</name><preferences><preference><scanner_name>source_iface</scanner_name><value>".$this->ip4eth4target($this->ip)."</value></preference></preferences><config id='74db13d6-7489-11df-91b9-002264764cea' /><target id='$target_uuid' /></create_task>\" | xmlstarlet sel -t -v /create_task_response/@id";
        $this->cmd("localhost",$query);
        
        while ( TRUE )   {
            if (!empty($task_uuid = $this->openvas2task4check($target_name))) break;
            if (!empty($task_uuid = trim($this->req_ret_str($query)))) break;
            sleep(2);
        }
        return $task_uuid;
    }
    
    
    public function openvas2credentials4check($user2name,$user2pass){
        // -iX \"<get_credentials/>\"
        return trim($this->req_ret_str("omp -u $this->mysql_login -w $this->mysql_passwd -iX '<get_credentials/>' | grep '$this->ip $user2name:$user2pass' -B4 -A18 |  xmlstarlet sel -t -v /credential/@id 2> /dev/null "));
    }
    
    public function openvas2target4check($target_name){
        return trim($this->req_ret_str("omp -u $this->mysql_login -w $this->mysql_passwd --get-targets | grep '$target_name'  | cut -d' ' -f1  | tail -1 "));
    }
    
    public function openvas2task4check($target_name){
        return trim($this->req_ret_str("omp -u $this->mysql_login -w $this->mysql_passwd --get-tasks | grep '$target_name'  | cut -d' ' -f1  | tail -1"));
    }
    
    public function openvas2task4check4run4new($target_name){
        return trim($this->req_ret_str("omp -u $this->mysql_login -w $this->mysql_passwd --get-tasks | grep '$target_name'  | grep 'New' | cut -d' ' -f1 | tail -1"));
    }
    
    public function openvas2task4check4run($target_name){
        return trim($this->req_ret_str("omp -u $this->mysql_login -w $this->mysql_passwd --get-tasks | grep '$target_name'  | tail -1 "));
    }
    
    public function openvas2task4check4run2done($target_name){
        return trim($this->req_ret_str("omp -u $this->mysql_login -w $this->mysql_passwd --get-tasks | grep '$target_name'  | grep  'Done' | cut -d' ' -f1  | tail -1"));
    }
    
    public function openvas2port_list2check(){
        return trim($this->req_ret_str("omp -u $this->mysql_login -w $this->mysql_passwd -iX '<get_port_lists/>' | grep '<name>Open Port List $this->ip</name>' -B4 -A19 |  xmlstarlet sel -t -v /port_list/@id 2> /dev/null "));
    }
    
    public function openvas2report2uuid($target_name,$task_uuid){
        $this->ssTitre(__FUNCTION__);
        $query = "omp -u $this->mysql_login -w $this->mysql_passwd -iX  \"<start_task task_id='$task_uuid' />\"  | grep -Po \"<report_id>[0-9a-z_-]{1,40}</report_id>\" | cut -d'>' -f2 | cut -d'<' -f1 ";
        $this->cmd("localhost",$query);
        while ( TRUE )   {
            if (!empty($report_uuid = $this->openvas2task4check4run2done($target_name))) break;
            if (!empty($report_uuid = $this->openvas2task4check4run4new($target_name))) {$this->req_ret_str($query);}
            if (!empty($report_uuid = trim($this->req_ret_str($query)))) break;
            
            $this->ssTitre("Progression");$this->requette("omp -u $this->mysql_login -w $this->mysql_passwd --get-tasks \"$task_uuid\"  | grep '$target_name' ");
            sleep(120);
        }
        return $report_uuid;
    }
    
    public function openvas2report2get($report_uuid){
        $report_uuid = trim($report_uuid);
        $report_uuid_result_xml = "";
        $this->ssTitre("Reports");
        if(!empty($report_uuid)){
            $this->cmd("localhost","omp -u $this->mysql_login -w $this->mysql_passwd --get-report-formats ");
            $file_path_xml = "$this->dir_tmp/$report_uuid"."_faraday_openvas.xml";
            $query = "omp -u $this->mysql_login -w $this->mysql_passwd --get-report '$report_uuid' --format a994b278-1f62-11e1-96ac-406186ea4fc5 2> /dev/null ";
            $tmp = "";
            while (empty($tmp)) {
                $tmp = $this->req_ret_str($query);
                sleep(10);
            }
            
            $report_uuid_result_xml = $tmp ;
            if(!file_exists($file_path_xml)) {
                $this->requette("echo '<?xml version=\"1.0\" encoding=\"UTF-8\"?> ' > $file_path_xml");
                $fd = fopen($file_path_xml, "a");
                fwrite($fd,$report_uuid_result_xml);
                fclose($fd);
            }
        }
        //$this->req_ret_str("cat $file_path_xml");
        return $report_uuid_result_xml;
    }
    
    public function openvas2faraday($file_path_xml){
        $file_path_xml = trim($file_path_xml);
        if(!empty($file_path_xml)){
            $obj_file = new FILE($file_path_xml);
            $size = $obj_file->file_file2size();
            if( ($size != 40) || ($size > 40) ){
                $query = "python /usr/share/python-faraday/faraday.py --cli --workspace $this->faraday_workspace_name --report $file_path_xml > /dev/null ";
                $this->requette($query);
            }
        }
    }
    
    
    
    public function openvas2report2result4cve($cve,$report_uuid_result_xml){
        $cve = trim($cve);
        $result = "";
        $result .= $this->ssTitre(__FUNCTION__);
        $xml=simplexml_load_string($report_uuid_result_xml);
        foreach ($xml->report->results->children() as $service ){
            if ( (stristr($service->nvt->cve,$cve)) || (stristr($service->nvt->tags,$cve)) ) {
                $result .= $this->article("Host", $service->host);
                $result .= $this->article("Port Number", $service->port);
                $result .= $this->article("Severity", $service->severity);
                $result .= $this->article("Qod", $service->qod->value);
                $result .= $this->article("Description", $service->description);
                $result .= $this->article("CVE", $service->nvt->cve);
                $result .= $this->article("Tags", $service->nvt->tags);
                $result .= "\n\n";
                echo "\n\n";
            }
        }
        return $result;
    }
    
    
    public function openvas2report2result($report_uuid_result_xml){
        $result = "";
        $result .= $this->ssTitre(__FUNCTION__);
        $xml=simplexml_load_string($report_uuid_result_xml);
        foreach ($xml->report->results->children() as $service ){
            $result .= $this->article("Port Number", $service->port);
            $result .= $this->article("Severity", $service->severity);
            $result .= $this->article("Qod", $service->qod->value);
            $result .= $this->article("Description", $service->description);
            $result .= $this->article("CVE", $service->nvt->cve);
            $result .= "\n";
        }
        return $result;
    }
    
    public function openvas2report2faraday($report_uuid){
        $this->ssTitre(__FUNCTION__);
        $file_path_xml = "$this->dir_tmp/$report_uuid"."_faraday_openvas.xml";
        $this->ssTitre("Send To faraday");
        $this->pause();
        $this->openvas2faraday($file_path_xml);
        
    }
    
    
    
    
    
    
    
}

?>