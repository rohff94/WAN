<?php

class check4linux extends tunnel4linux{
    
    
    
    
    
    
    
    
    public function __construct($eth,$domain,$ip,$port,$protocol) {
        parent::__construct($eth,$domain,$ip,$port,$protocol);
        
    }
  
    
   
   
   public function lan2brief(){
       $this->rouge("Brief");
       $sql = "select uid_name,from_base64(templateB64_id),from_base64(templateB64_shell),ladate FROM LAN where id8port=$this->port2id ORDER BY ladate ASC ;";
       
       $req = $this->mysql_ressource->query($sql);
       $chaine = "===========================================================================================================";
       $this->jaune($chaine);
       while ($row = $req->fetch_assoc()) {
           echo "\n";
           $this->jaune($row['uid_name']);
           $date = $row['ladate'];
           $this->article("Date", $date);
           $uid_name = $row['uid_name'];
           $this->article("Username",$uid_name );
           $template_id = $row['from_base64(templateB64_id)'];
           $template_id = str_replace("echo '$this->root_passwd' | sudo -S", "sudo", $template_id);
           $this->article("ID", $template_id);
           $template_shell = $row['from_base64(templateB64_shell)'];
           $template_shell = str_replace("echo '$this->root_passwd' | sudo -S", "sudo", $template_shell);
           $this->article("SHELL", $template_shell);
           
       }
       $this->rouge("END of ".__FUNCTION__);
       $this->jaune($chaine);
       
       $this->pause();
   }

   public function lan2done(){
       $sql = "UPDATE LAN set lan2done = 1 where $this->lan2where";
       $this->mysql_ressource->query($sql);
   }
   
   
   
    
}
?>
