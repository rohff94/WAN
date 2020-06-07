<?php

class com4user extends DATA {
    var $tab_sudo8app2shell;
    var $tab_sudo8app2read;
    var $tab_sudo8app2write;
    
    var $path_ssh ;
    var $path_sshpass ;
    
    function __construct(){
        parent::__construct();
        $this->tab_sudo8app2shell = array("apt","apt-get","aria2c","ash","awk","bash","busybox","chsh","convert","cpan","cpulimit","crontab","csh","curl","dash","dmesg","dmsetup","dnf","docker","dpkg","easy_install","ed","elinks","emacs","env","env_keep","except","exec","expect","facter","fifo","find","finger","flock","ftp","gawk","gdb","gimp","git","go","ht","ionice","irb","java","jjs","journalctl","jrunscript","ksh","ldconfig","LD_PRELOAD","ld.so","less","logsave","ltrace","lua","lynx","mail","make","man","media_android","media_ios","more","mount","mssql","mv","mysql","nano","nc","ncat","netcat","nice","nmap","node","nodejs","ocaml","openssl","opt","oracle","path","perl","php","pic","pico","pinfo","pip","powershell","puppet","python","python1","python2","python3","red","rlogin","rlwrap","rpm","rpmquery","rsync","ruby","ruby1","run-parts","rvim","scp","screen","script","sed","service","setarch","sftp","sh","smbclient","socat","sqlite3","ssh","start-stop-daemon","stdbuf","strace","stty","su","systemctl","tar","taskset","tclsh","tcpdump","tee","telnet","tftp","time","timeout","tmux","unexpand","unshare","vi","vim","watch","wget","whoami","whois","wine","wish","xargs","xterm","yum","zip","zsh","zypper");
        $this->tab_sudo8app2read = array("arp","base64","cancel","chmod","chown","cp","cut","date","dd","diff","expand","file","fmt","fold","grep","head","ip","jq","mtr","nl","od","pg","readelf","run-mailcap","shuf","sort","tail","ul","uniq","vim","xxd");
        $this->tab_sudo8app2write = array("cat","vim");
        
    }
    
    public function salt2check8password($salt,$password):bool{
        $this->ssTitre(__FUNCTION__);
        print_r( password_get_info( $salt ) );
        if (password_verify($password, $salt)) {
            $this->rouge('Password is valid!');
            return TRUE;
        } else {
            $this->rouge('Invalid password.');
            return FALSE;
        }
    }

    
    
    public function user2pass2salt4etc_passwd($username,$userpass){
        $this->ssTitre(__FUNCTION__);
        $query = "mkpasswd -m SHA-512 $userpass";
        $user_pass_crypt = trim($this->req_ret_str($query));
        $query = "openssl passwd -1 -salt $username $userpass";
        $user_pass_crypt = trim($this->req_ret_str($query));
        $this->article("user_pass_crypt",$user_pass_crypt);
        $salt = "$username:$user_pass_crypt:0:0:root:/root:/bin/sh";
        return $salt;
    }
    
   
    public function parse4id($id_result){
        $this->ssTitre(__FUNCTION__);
        $results = array();
        $id_tst = "";
        $uid = "";
        $uid_name = "";
        $gid = "";
        $gid_name = "";
        $euid = "";
        $euid_name = "";
        $egid = "";
        $egid_name = "";
        $groups = "";
        $context = "";
        $id_result = trim($id_result);
        $query = "echo '$id_result'|  grep -Po \"uid=[[:print:]]{1,}$\" ";
        exec($query,$tmp);
        if (isset($tmp[0])) $id_tst = $tmp[0];
        $chaine = "===========================================================================================================";
        $this->jaune($chaine);
        if (preg_match('/uid=(?<uid>[0-9]{1,5})\((?<uid_name>[[:print:]]{1,})\)([[:space:]]{1})gid=(?<gid>[0-9]{1,5})\((?<gid_name>[[:print:]]{1,})\)([[:space:]]{1})euid=(?<euid>[0-9]{1,5})\((?<euid_name>[[:print:]]{1,})\)([[:space:]]{1})egid=(?<egid>[0-9]{1,5})\((?<egid_name>[[:print:]]{1,})\)([[:space:]]{1})groups=(?<groups>[0-9]{1,5})\(([[:print:]]{1,})\)([[:space:]]{1})context=(?<context>[[:print:]]{1,})/',$id_tst,$results))
        {
            
            $this->jaune( $id_tst);          
            $this->rouge("Found EUID with context");
            $uid = $results['uid'];
            $this->article("UID",$uid);
            $uid_name = $results['uid_name'];
            $this->article("UID NAME",$uid_name);
            $gid = $results['gid'];
            $this->article("GID",$gid);
            $gid_name = $results['gid_name'];
            $this->article("GID NAME",$gid_name);            
            $euid = $results['euid'];
            $this->article("EUID",$euid);
            $euid_name = $results['euid_name'];
            $this->article("EUID NAME",$euid_name);
            $egid = $results['egid'];
            $this->article("EGID",$egid);
            $egid_name = $results['egid_name'];
            $this->article("EGID NAME",$egid_name);
            $groups = $results['groups'];
            $this->article("GROUPS",$groups);
            $context = $results['context'];
            $this->article("context",$context);
            return array($uid,$uid_name,$gid,$gid_name,$euid,$euid_name,$egid,$egid_name,$groups,$context,$id_tst);
            
        }

        
        if (preg_match('/uid=(?<uid>[0-9]{1,5})\((?<uid_name>[[:print:]]{1,})\)([[:space:]]{1})gid=(?<gid>[0-9]{1,5})\((?<gid_name>[[:print:]]{1,})\)([[:space:]]{1})euid=(?<euid>[0-9]{1,5})\((?<euid_name>[[:print:]]{1,})\)([[:space:]]{1})egid=(?<egid>[0-9]{1,5})\((?<egid_name>[[:print:]]{1,})\)([[:space:]]{1})groups=(?<groups>[0-9]{1,5})([[:print:]]{1,})/',$id_tst,$results))
        {
            $this->jaune( $id_tst);
            $chaine = "Found EUID Without context";
            $this->rouge($chaine);
            $uid = $results['uid'];
            $this->article("UID",$uid);
            $uid_name = $results['uid_name'];
            $this->article("UID NAME",$uid_name);
            $gid = $results['gid'];
            $this->article("GID",$gid);
            $gid_name = $results['gid_name'];
            $this->article("GID NAME",$gid_name);
            
            $euid = $results['euid'];
            $this->article("EUID",$euid);
            $euid_name = $results['euid_name'];
            $this->article("EUID NAME",$euid_name);
            $egid = $results['egid'];
            $this->article("EGID",$egid);
            $egid_name = $results['egid_name'];
            $this->article("EGID NAME",$egid_name);
            $groups = $results['groups'];
            $this->article("GROUPS",$groups);
            $context = "";
            $this->article("context",$context);
            return array($uid,$uid_name,$gid,$gid_name,$euid,$euid_name,$egid,$egid_name,$groups,$context,$id_tst);
            
        }
        
        
        if (preg_match('/uid=(?<uid>[0-9]{1,5})\((?<uid_name>[[:print:]]{1,})\)([[:space:]]{1})gid=(?<gid>[0-9]{1,5})\((?<gid_name>[[:print:]]{1,})\)([[:space:]]{1})groups=(?<groups>[0-9]{1,5})([[:print:]]{1,})([[:space:]]{1})context=(?<context>[[:print:]]{1,})/',$id_tst,$results))
        {
            $this->jaune( $id_tst);
            $chaine = "Found UID With context";
            $this->rouge($chaine);
            $uid = $results['uid'];
            $this->article("UID",$uid);
            $uid_name = $results['uid_name'];
            $this->article("UID NAME",$uid_name);
            $gid = $results['gid'];
            $this->article("GID",$gid);
            $gid_name = $results['gid_name'];
            $this->article("GID NAME",$gid_name);
            $groups = $results['groups'];
            $this->article("GROUPS",$groups);
            $context = $results['context'];
            $this->article("context",$context);
            return array($uid,$uid_name,$gid,$gid_name,$euid,$euid_name,$egid,$egid_name,$groups,$context,$id_tst);
        }

        
        if (preg_match('/uid=(?<uid>[0-9]{1,5})\((?<uid_name>[[:print:]]{1,})\)([[:space:]]{1})gid=(?<gid>[0-9]{1,5})\((?<gid_name>[[:print:]]{1,})\)([[:space:]]{1})groups=(?<groups>[0-9]{1,5})([[:print:]]{1,})/',$id_tst,$results))
        {
            $this->jaune( $id_tst);
            $chaine = "Found UID Without context";
            $this->rouge($chaine);
            $uid = $results['uid'];
            $this->article("UID",$uid);
            $uid_name = $results['uid_name'];
            $this->article("UID NAME",$uid_name);
            $gid = $results['gid'];
            $this->article("GID",$gid);
            $gid_name = $results['gid_name'];
            $this->article("GID NAME",$gid_name);
            $groups = $results['groups'];
            $this->article("GROUPS",$groups);
            $context = "";
            $this->article("context",$context);
            return array($uid,$uid_name,$gid,$gid_name,$euid,$euid_name,$egid,$egid_name,$groups,$context,$id_tst);
        }
        
        
        if (preg_match('/uid=(?<uid>[0-9]{1,5})\((?<uid_name>[[:print:]]{1,})\)([[:space:]]{1})gid=(?<gid>[0-9]{1,5})\((?<gid_name>[[:print:]]{1,})\)([[:space:]]{1})/',$id_tst,$results))
        {
            $this->jaune( $id_tst);
            $chaine = "Found UID Without context";
            $this->rouge($chaine);
            $uid = $results['uid'];
            $this->article("UID",$uid);
            $uid_name = $results['uid_name'];
            $this->article("UID NAME",$uid_name);
            $gid = $results['gid'];
            $this->article("GID",$gid);
            $gid_name = $results['gid_name'];
            $this->article("GID NAME",$gid_name);
            $groups = "";
            $this->article("GROUPS",$groups);
            $context = "";
            $this->article("context",$context);
            return array($uid,$uid_name,$gid,$gid_name,$euid,$euid_name,$egid,$egid_name,$groups,$context,$id_tst);
        }
        
        
        
        
        if (preg_match('/uid=(?<uid>[0-9]{1,5})\((?<uid_name>[[:print:]]{1,})\)([[:space:]]{1})gid=(?<gid>[0-9]{1,5})\((?<gid_name>[[:print:]]{1,})\)([[:space:]]{1})euid=(?<euid>[0-9]{1,5})\((?<euid_name>[[:print:]]{1,})\)([[:space:]]{1})groups=(?<groups>[0-9]{1,5})([[:print:]]{1,})/',$id_tst,$results))
        {
            $this->jaune( $id_tst);
            $chaine = "Found EUID Without EGID & CONTEXT";
            $this->rouge($chaine);
            $uid = $results['uid'];
            $this->article("UID",$uid);
            $uid_name = $results['uid_name'];
            $this->article("UID NAME",$uid_name);
            $gid = $results['gid'];
            $this->article("GID",$gid);
            $gid_name = $results['gid_name'];
            $this->article("GID NAME",$gid_name);
            
            $euid = $results['euid'];
            $this->article("EUID",$euid);
            $euid_name = $results['euid_name'];
            $this->article("EUID NAME",$euid_name);
            $egid = "";
            $this->article("EGID",$egid);
            $egid_name = "";
            $this->article("EGID NAME",$egid_name);
            $groups = $results['groups'];
            $this->article("GROUPS",$groups);
            $context = "";
            $this->article("context",$context);
            return array($uid,$uid_name,$gid,$gid_name,$euid,$euid_name,$egid,$egid_name,$groups,$context,$id_tst);
            
        }
    }
    
    
    public function monitor(){
        //$this->monitor8fw();$this->pause();
        $this->monitor8service();$this->pause();
        $this->monitor8db();$this->pause();
        $this->monitor8malw();$this->pause();
        $this->monitor8bot();$this->pause();
        
        //$this->monitor8lan($ip)
    }
    
    public function monitor8bot(){
        $data = "echo '$this->root_passwd' | sudo -S grep 'Failed password for invalid user' /var/log/auth.log $this->filter_ip | sort -u ";
        $tab_bot = $this->req_ret_tab($data);
        $this->article("ALLBots", $this->tab($tab_bot));
        foreach ($tab_bot as $bot){
            if (!empty($bot) && $this->isIPv4($bot)){
                $this->article("Bot", $bot);
                $data = "echo '$this->root_passwd' | sudo -S grep '$bot' /var/log/auth.log | grep -i -E \"(succes|accept|authoriz)\" ";
                $this->requette($data);
                $data = "echo '$this->root_passwd' | sudo -S grep '$bot' /var/log/auth.log | wc -l ";
                $this->requette($data);
                
                $ip = $bot ;
                $eth = "ens3";
                $domain = "malw.bot";
                $obj_ip = new IP("", $eth, $domain, $ip);
                $obj_ip->poc(TRUE);
                $obj_ip->ip4info();$this->pause();
                $obj_ip->ip4service();$this->pause();
                //$obj_ip->ip4enum2users();$this->pause();
                
                $query = "php pentest.php IP \"$eth $domain $ip ip4enum2users FALSE\" ";
                $this->cmd("localhost", $query);
                
                $query = "echo '$this->root_passwd' | sudo -S fail2ban-client set sshd banip $ip";
                $this->requette($query);
                $this->pause();
            }
        }
    }
    public function monitor8malw(){
        //$this->requette("top");
        //$this->requette("echo '$this->root_passwd' | sudo -S ps axjf");
        //$this->requette("echo '$this->root_passwd' | sudo -S cat /var/log/auth.log");
        $this->requette("echo '$this->root_passwd' | sudo -S tail -20 /var/log/syslog");$this->pause();
        $this->requette("echo '$this->root_passwd' | sudo -S grep -i -E \"(fail|error)\" /var/log/auth.log");$this->pause();
        $this->requette("echo '$this->root_passwd' | sudo -S tail -20 /var/log/kern.log");$this->pause();
        $this->requette("echo '$this->root_passwd' | sudo -S tail -20 /var/log/mail.log");$this->pause();
        $this->requette("echo '$this->root_passwd' | sudo -S tail -20 $this->log_succes_path");$this->pause();
        $this->requette("echo '$this->root_passwd' | sudo -S tail -20 $this->log_error_path");$this->pause();
        $this->requette("echo '$this->root_passwd' | sudo -S grep -i -E \"(segfault|error|fail|crash)\" /var/log/kern.log");$this->pause();
   $this->requette("echo '$this->root_passwd' | sudo -S fail2ban-client status");
   $this->requette("echo '$this->root_passwd' | sudo -S fail2ban-client status sshd");
   $this->requette("echo '$this->root_passwd' | sudo -S tail -40 /var/log/fail2ban.log");
    }
  
    
    public function monitor8service(){
        $this->requette("ps aux | grep pentest | grep domain | grep 4service | wc -l");$this->pause();
        $this->requette("ps aux | grep pentest | grep domain | grep 4service");$this->pause();
        $this->requette("ps aux | grep pentest | grep domain | grep 4service | awk '{print $15}' | sort -u $this->filter_domain");$this->pause();
        $this->requette("ps aux | grep pentest | grep domain | grep 4info | wc -l");$this->pause();
        $this->requette("ps aux | grep pentest | grep domain | grep 4info");$this->pause();
        $this->requette("ps aux | grep pentest | grep domain | grep 4info | awk '{print $15}' | sort -u $this->filter_domain");$this->pause();
        $this->requette("screen -r ");$this->pause();
        
    }
    
    
    public function monitor8fw(){
        $this->ssTitre("Scan TCP");
        
        $this->requette("echo '$this->root_passwd' | sudo -S iptables -L -nv");
        $this->requette("echo '$this->root_passwd' | sudo -S iptables -F;sudo iptables -X");
        
        /*
        $this->requette("echo '$this->root_passwd' | sudo -S iptables -L -nv");
        $this->requette("echo '$this->root_passwd' | sudo -S iptables -N synScan");
        $this->requette("echo '$this->root_passwd' | sudo -S iptables -A synScan -p TCP -m state --state NEW -m limit --limit 1/s --limit-burst 1 -j RETURN");
        $this->requette("echo '$this->root_passwd' | sudo -S iptables -A synScan -p TCP -j LOG --log-prefix \"ROHFF SYN SCAN Reject: \"");
        $this->requette("echo '$this->root_passwd' | sudo -S iptables -A synScan -p TCP -j REJECT --reject-with tcp-reset");
        $this->requette("echo '$this->root_passwd' | sudo -S iptables -A INPUT -p TCP --syn -j synScan");
        $this->pause();
        
        
        $this->ssTitre("Scan UDP");
        $this->requette("echo '$this->root_passwd' | sudo -S iptables -N udpScan");
        $this->requette("echo '$this->root_passwd' | sudo -S iptables -A udpScan -p UDP -m state --state NEW -m limit --limit 1/s --limit-burst 1 -j RETURN");
        $this->requette("echo '$this->root_passwd' | sudo -S iptables -A udpScan -p UDP -j LOG --log-prefix \"ROHFF UDP SCAN Reject: \"");
        $this->requette("echo '$this->root_passwd' | sudo -S iptables -A udpScan -p UDP -j REJECT --reject-with port-unreach");
        $this->requette("echo '$this->root_passwd' | sudo -S iptables -A INPUT -p UDP -j udpScan");
        $this->pause();
        
                $this->ssTitre("Block BruteForce SSH user");
        $this->requette("echo '$this->root_passwd' | sudo -S iptables -N SSHSCAN");
        $this->requette("echo '$this->root_passwd' | sudo -S iptables -A INPUT -i lo -p tcp -m tcp --dport 22 -m state --state NEW -j SSHSCAN");
        $this->requette("echo '$this->root_passwd' | sudo -S iptables -A SSHSCAN -m recent --set --name SSH_BRUTEFORCE --rsource");
        $this->requette("echo '$this->root_passwd' | sudo -S iptables -A SSHSCAN -m recent --update --seconds 360 --hitcount 10 --name SSH_BRUTEFORCE --rsource -j LOG --log-prefix \"Anti SSH-Bruteforce: \" ");
        $this->requette("echo '$this->root_passwd' | sudo -S iptables -A SSHSCAN -m recent --update --seconds 360 --hitcount 10 --name SSH_BRUTEFORCE --rsource -j DROP");
        $this->requette("echo '$this->root_passwd' | sudo -S iptables -A SSHSCAN -m recent --rcheck --name SSH_BRUTEFORCE -j ACCEPT");
        $this->requette("echo '$this->root_passwd' | sudo -S iptables -L -nv");
        $this->pause();
        

        
        $this->ssTitre("Block BruteForce SSH user");
        $this->requette("echo '$this->root_passwd' | sudo -S iptables -N SSHSCAN");
        $this->requette("echo '$this->root_passwd' | sudo -S iptables -A INPUT -i lo -p tcp -m tcp --dport 22 -m state --state NEW -j SSHSCAN");
        $this->requette("echo '$this->root_passwd' | sudo -S iptables -A SSHSCAN -m recent --set --name SSH_BRUTEFORCE --rsource");
        $this->requette("echo '$this->root_passwd' | sudo -S iptables -A SSHSCAN -m recent --update --seconds 360 --hitcount 10 --name SSH_BRUTEFORCE --rsource -j LOG --log-prefix \"Anti SSH-Bruteforce: \" ");
        $this->requette("echo '$this->root_passwd' | sudo -S iptables -A SSHSCAN -m recent --update --seconds 360 --hitcount 10 --name SSH_BRUTEFORCE --rsource -j DROP");
        $this->requette("echo '$this->root_passwd' | sudo -S iptables -A SSHSCAN -m recent --rcheck --name SSH_BRUTEFORCE -j ACCEPT");
        $this->requette("echo '$this->root_passwd' | sudo -S iptables -L -nv");
        $this->pause();
        $query = "medusa -u \"root\" -P \"$this->dico_password.1000\" -h '127.0.0.1' -M ssh -f -t 8 -e s -n 22  ";
        $query = "hydra -l \"root\" -P \"$this->dico_password.100\" 127.0.0.1 ssh -f -t 8 -e sr -s 22 -w 5s";
        $this->requette($query);
        */
    }
    
    
    public function monitor8db(){
        
        $sql = "select distinct(service2name) FROM SERVICE ORDER BY service2name ASC";
        $query = "mysql --user=$this->mysql_login --password=$this->mysql_passwd --database=$this->mysql_database --execute=\"$sql\"  2>/dev/null ";
        $this->requette($query);$this->pause();
        $sql = "select distinct(service2product) FROM SERVICE ORDER BY service2product ASC";
        $query = "mysql --user=$this->mysql_login --password=$this->mysql_passwd --database=$this->mysql_database --execute=\"$sql\"  2>/dev/null ";
        $this->requette($query);$this->pause();
        $sql = "select distinct(service2name),service2version,service2product,service2extrainfo FROM SERVICE ORDER BY service2name ASC";
        $query = "mysql --user=$this->mysql_login --password=$this->mysql_passwd --database=$this->mysql_database --execute=\"$sql\"  2>/dev/null ";
        $this->requette($query);$this->pause();
        
        $sql = "select ladate,user2name,user2pass,from_base64(user2info) FROM AUTH";
        $query = "mysql --user=$this->mysql_login --password=$this->mysql_passwd --database=$this->mysql_database --execute=\"$sql\"  2>/dev/null ";
        $this->requette($query);$this->pause();
        
        $sql = "select ladate,user2name,user2methode,from_base64(user2infos) FROM USERS";
        $query = "mysql --user=$this->mysql_login --password=$this->mysql_passwd --database=$this->mysql_database --execute=\"$sql\"  2>/dev/null ";
        $this->requette($query);$this->pause();
        
        $sql = "select * FROM LAN";
        $query = "mysql --user=$this->mysql_login --password=$this->mysql_passwd --database=$this->mysql_database --execute=\"$sql\"  2>/dev/null ";
        $this->requette($query);$this->pause();
    }
    public function monitor8lan($ip){
        $chaine = "Monitors your environment";
        $this->rouge($chaine);
        if ($this->ip4priv($this->ip)){
            $cidr = trim($this->ip2cidr());
            $query = "echo '$this->root_passwd' | sudo -S arpwatch -dN -i $this->eth -a -n $cidr.0/24";
            $this->cmd("localhost", $query);
            $query = "echo '$this->root_passwd' | sudo -S nmap -sn --reason $cidr.0/24 -e $this->eth ";
            $this->cmd("localhost", $query);
            $query = "echo '$this->root_passwd' | sudo -S arp -av -i $this->eth";
            $this->cmd("localhost", $query);
        }
        

        $query = "echo '$this->root_passwd' | sudo -S snort -A console -q -c /etc/snort/snort.conf -i $this->eth  'not host $this->ip'";
        $this->cmd("localhost", $query);
        $query = "mysql --user=$this->mysql_login --password=$this->mysql_passwd --database=bot";
        $this->cmd("localhost", $query);
        $query = "cd $this->dir_tmp; php -S $this->ip:$this->port_rfi";
        $this->cmd("localhost", $query);

    }
    
    
    public  function parse4traceroute(string $traceroute_str){
        $result = "";
        $results = array();
        
        $ttl = array();
        $ipaddr = array();
        $geoip = array();
        
        $tab_lines = explode("\n", $traceroute_str);
        foreach ($tab_lines as $line){
            $line = trim($line);
            if (!empty($line)){
                $ttl = "";
                $ipaddr = "";
                $geoip = "";
                if (preg_match('#<hop ttl=\"(?<ttl>[0-9]{1,5})\"([[:space:]]{1})ipaddr=\"(?<ipaddr>[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\"([[:space:]]{1})rtt=\"(?<rtt>[[:print:]]{1,})\"/>#',$line,$results))
                {
                    $ttl = $results['ttl'];
                    $ipaddr  = $results['ipaddr'];
                    $geoip = $this->ip2geo($ipaddr);
                    $result .= "ttl=$ttl ipaddr=$ipaddr geoip=$geoip\n";
                }
            }
        }
        return $result;
    }
    

    
    public  function parse4crontab($crontab_str){
        $result_tmp = array();
        $results = array();
        $minute = array();$hour = array();$day = array();$month = array();$day8week = array();
        $user = array();$exec_file = array();
        $tmp = base64_encode($crontab_str);
        $query = "echo '$tmp' | base64 -d | strings  | grep -v -e '^$' | grep -v '^#' | grep -v 'run-parts' | grep '/'";
        exec($query,$result_tmp);
        $size = count($result_tmp);
        for ($i=0;$i<$size;$i++){
            $exec_tmp_path = $result_tmp[$i];
            //if (preg_match('/(?<minute>[0-9\*\-\/]{1,2})([[:space:]]{1,})(?<hour>[0-9\*\-\/]{1,2})([[:space:]]{1,})(?<day>[0-9\*\-\/]{1,2})([[:space:]]{1,})(?<month>[0-9a-z\*\-\/]{1,3})([[:space:]]{1,})(?<day8week>[0-9a-z\*\-\/]{1,3})([[:space:]]{1,})(?<user>[[:print:]]{1,})([[:space:]]{1,})(?<exec_file>[[:print:]]{1,})/',$exec_tmp_path,$results))
           if (preg_match('/(?<minute>[0-9\*\-\/]{1,5})([[:space:]]{1,})(?<hour>[0-9\*\-\/]{1,5})([[:space:]]{1,})(?<day>[0-9\*\-\/]{1,5})([[:space:]]{1,})(?<month>[0-9a-z\*\-]{1,5})([[:space:]]{1,})(?<day8week>[0-9a-z\*\-]{1,5})([[:space:]]{1,})(?<user>[[:print:]]{1,})([[:space:]]{1,})(?<exec_file>[[:print:]]{1,})/',$exec_tmp_path,$results))
                {
                $tmp = $results['minute'];
                $tmp = str_replace(array("*","/","-"), "", $tmp);
                if (empty($tmp)) $tmp = "1";               
                $minute[] = $tmp;
                $this->article("minute",$tmp);
                
                $hour[] = $results['hour'];
                $this->article("hour",$results['hour']);
                
                $day[] = $results['day'];
                $this->article("day",$results['day']);
                
                $month[] = $results['month'];
                $this->article("month",$results['month']);
                
                $day8week[] = $results['day8week'];
                $this->article("day8week",$results['day8week']);
                
                $user[] = $results['user'];
                $this->article("user",$results['user']);
                
                $exec_file[] = $results['exec_file'];
                $this->article("exec_file",$results['exec_file']);
            }
        }
        $this->pause();
        return array($minute,$hour,$day,$month,$day8week,$user,$exec_file);
    }
    
    
}

?>
