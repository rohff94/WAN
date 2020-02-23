<?php

class check4linux8users extends check4linux{

    var $uid_pass ;
    var $sudoers_str ;

    
    
    public function __construct($eth,$domain,$ip,$port,$protocol,$stream,$templateB64_id,$templateB64_cmd,$templateB64_shell,$uid,$uid_name,$gid,$gid_name,$context,$uid_pass) {
        parent::__construct($eth,$domain,$ip,$port,$protocol,$stream,$templateB64_id,$templateB64_cmd,$templateB64_shell,$uid,$uid_name,$gid,$gid_name,$context);
        $this->uid_pass = trim($uid_pass);
        $this->sudoers_str = $this->users2sudoers2list($this->uid_name,$this->uid_pass);
        
    }
    

    
       

}
?>