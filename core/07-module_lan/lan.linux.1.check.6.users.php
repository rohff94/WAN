<?php

class check4linux8users8pass extends lan4linux{

    var $uid_pass ;


    
    
    public function __construct($eth,$domain,$ip,$port,$protocol,$stream,$templateB64_id,$templateB64_shell,$id8b64,$uid_pass) {
        parent::__construct($eth,$domain,$ip,$port,$protocol,$stream,$templateB64_id,$templateB64_shell,$id8b64);
        $this->uid_pass = trim($uid_pass);
            
    }
    

    
       

}
?>