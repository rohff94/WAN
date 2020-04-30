<?php

class SERVICE4COM extends AUTH {
    
    var $created_user_name;
    var $created_user_pass;
    
    public function __construct($eth,$domain,$ip,$port,$protocol) {
        parent::__construct($eth,$domain,$ip,$port,$protocol);	
        $this->created_user_name = "syslog_admin";
        $this->created_user_pass = "admin123456789";
    }
    


    public function service4lan($cmd_rev,$templateB64_shell,$lport,$lprotocol,$type){
        $templateB64_id = base64_encode("%ID%");
        $cmd1 = "php pentest.php LAN '$this->eth $this->domain $this->ip $this->port $this->protocol $lport $lprotocol $templateB64_id $templateB64_shell $type 30 listening_Server' ";
        $this->article("cmd1", $cmd1);
        $this->article("cmd2", $cmd_rev);
        
        $time = $this->stream_timeout*3 ;       
        if ($type=="client") $this->exec_parallel($cmd_rev, $cmd1, $time);
        if ($type=="server") $this->exec_parallel($cmd1, $cmd_rev, $time);
    }
    

    
    public function parse4etc_passwd($strings_etc_passwd){
        $this->ssTitre(__FUNCTION__);
        $user = array();
        $lines_tab = explode("\n", $strings_etc_passwd);
        foreach ($lines_tab as $line){
            if (preg_match('|^(?<user2name>[a-zA-Z0-9\-\_]{1,}):(?<user2cpw>[[:print:]]{0,}):(?<user2uid>[0-9]{1,}):(?<user2gid>[0-9]{1,}):(?<user2full_name>[[:print:]]{0,}):(?<user2home>[[:print:]]{1,}):(?<user2shell>[[:print:]]{1,})|',$line,$user))
            {
                $this->yesUSERS($this->port2id, $user['user2name'], "cat /etc/passwd", $line);                
                $where = "id8port = '$this->port2id' AND user2name = '$user[user2name]' ";
                $query = "UPDATE AUTH SET user2uid='$user[user2uid]',user2gid='$user[user2gid]',user2def='$user[user2full_name]',user2home='$user[user2home]',user2shell='$user[user2shell]' WHERE $where ;";
                $this->mysql_ressource->query($query);
                $this->tab_users_etc_passwd[] = $user['user2name'];
            }
            
            if (preg_match('|^(?<user2name>[a-zA-Z0-9\-\_]{1,}):(?<user2cpw>[[:print:]]{0,}):(?<user2uid>[0-9]{1,}):(?<user2gid>[0-9]{1,}):(?<user2full_name>[[:print:]]{0,}):(?<user2home>[[:print:]]{1,}):/bin/bash|',$line,$user))
            {
                $this->tab_users_shell[] = $user['user2name'];
            }
            if (preg_match('|^(?<user2name>[a-zA-Z0-9\-\_]{1,}):(?<user2cpw>[[:print:]]{0,}):(?<user2uid>[0-9]{1,}):(?<user2gid>[0-9]{1,}):(?<user2full_name>[[:print:]]{0,}):(?<user2home>[[:print:]]{1,}):/bin/sh|',$line,$user))
            {
                $this->tab_users_shell[] = $user['user2name'];
            }
            
            
        }
        
        //sort($this->tab_users_etc_passwd);
        if (!empty($this->tab_users_etc_passwd)) $this->tab_users_etc_passwd = array_filter(array_unique($this->tab_users_etc_passwd));
        $this->article("All Users /etc/passwd","\n".$this->tab($this->tab_users_etc_passwd));
        
        //sort($this->tab_users_shell);
        if (!empty($this->tab_users_shell)) $this->tab_users_shell = array_filter(array_unique($this->tab_users_shell));
        $this->article("All Users SHELL","\n".$this->tab($this->tab_users_shell));        
    }

    
    public function yesUSERS($id8port,$user2name,$user2methode,$user2infos) {
        $id8port = trim($id8port);
        $user2name = trim($user2name);
        $user2methode = trim($user2methode);
        $user2infosB64 = base64_encode($user2infos);
        $user = array();
        
        if (preg_match('/(?<user2name>[[:print:]]{1,})/',$user2name,$user))
        {
            $user2name =  $user['user2name'];
            
        }
        else return $this->log2error("No User : $user2name");
        
        $sql_r = "SELECT id8port,user2name,user2methode,user2infos FROM USERS WHERE id8port = $id8port AND user2name = '$user2name' AND user2methode = '$user2methode' AND user2infos = '$user2infosB64' ";
        //echo "$sql_r\n";
        if (!$this->checkBD($sql_r)) {
            $sql_w = "INSERT INTO USERS (id8port,user2name,user2methode,user2infos) VALUES ($id8port,'$user2name','$user2methode','$user2infosB64');";
            $this->mysql_ressource->query($sql_w);
            $chaine = "YES USERS = $id8port:$user2name:$user2methode:$user2infos";
            $this->note($chaine) ;
            //$this->notify($chaine);
            //echo "$sql_w\n";$this->pause();
        }
    }
    
    
    
    public function  port2root($template_b64){
        $this->ssTitre(__FUNCTION__);
        $chaine = base64_decode($template_b64);
        $this->log2succes($chaine);
        $sql_ip = "UPDATE IP SET ip2root=1 WHERE $this->ip2where  ";
        $this->mysql_ressource->query($sql_ip);  
        $this->port2shell($template_b64);
    }
    
    public function  port2read($template_b64){
        $this->ssTitre(__FUNCTION__);
        $chaine = base64_decode($template_b64);
            $this->log2succes($chaine);
            $sql_ip = "UPDATE IP SET ip2read=1 WHERE $this->ip2where  ";
            $this->mysql_ressource->query($sql_ip);
    }
    
    public function  port2write($template_b64){      
        $this->ssTitre(__FUNCTION__);
        $chaine = base64_decode($template_b64);
        $this->log2succes($chaine);
        $sql_ip = "UPDATE IP SET ip2write=1 WHERE $this->ip2where  ";
        $this->mysql_ressource->query($sql_ip);
        $this->port2read($template_b64);
       }
    
    
    public function  port2shell($template_b64){
        $this->ssTitre(__FUNCTION__);

            $chaine = base64_decode($template_b64);
            $this->log2succes($chaine);
            $sql_ip = "UPDATE IP SET ip2shell=1 WHERE $this->ip2where  ";
            $this->mysql_ressource->query($sql_ip);
            //$this->port2write($template_b64);

        
    }
    
 

    

    
    
}

?>