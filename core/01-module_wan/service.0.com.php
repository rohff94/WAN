<?php



class SERVICE extends SERVICE4COM {
    var $service_name ;
    var $service_version ;
    var $service_product ;
    var $service_extrainfo ;
    var $service_banner ;
    var $service2where ;
    
    var $path_patator ;
    var $path_ident_user_enum ;
    var $path_OracleScanner ;
    var $path_sidguess ;
	
    public function __construct($eth,$domain,$ip,$port,$protocol,$service_name,$service_version,$service_product,$service_extrainfo) {
            parent::__construct($eth,$domain,$ip,$port,$protocol);	
            $this->service_name = trim($service_name);
            $this->service_version = trim($service_version);
            $this->service_product = trim($service_product);
            $this->service_extrainfo = trim($service_extrainfo);
            
            $this->service2where = "id8port = '$this->port2id' AND service2name = '$this->service_name' AND service2version = '$this->service_version' AND service2product = '$this->service_product' AND service2extrainfo = '$this->service_extrainfo' ";
            
            $sql_r = "SELECT service2name,service2version,service2product,service2extrainfo FROM ".__CLASS__." WHERE $this->service2where ";
            if (!$this->checkBD($sql_r)) {
                $sql_w = "INSERT  INTO ".__CLASS__." (id8port,service2name,service2version,service2product,service2extrainfo) VALUES ('$this->port2id','$this->service_name','$this->service_version','$this->service_product','$this->service_extrainfo'); ";
                $this->mysql_ressource->query($sql_w);
                //$this->cmd("localhost","echo '$this->root_passwd' | sudo -S tshark -i $this->eth_wlan  host $this->ip -w $this->dir_tmp/$this->ip.pcap");
                echo $this->note("Working on SERVICE for the first time");
                
            }
	}
	
	
	
	public function service2banner(){
	    $query = "echo '$this->root_passwd' | sudo -S nmap -n -Pn --reason --script \"banner\" $this->ip -p $this->port -s$this->protocol -e $this->eth -oX - | xmlstarlet sel -t -v /nmaprun/host/ports/port/script/@output | strings";
	    return trim($this->req2BD(__FUNCTION__,__CLASS__,"$this->service2where",$query));
	}
	
	public function service4cve(){
	    //return "not checked";
	    $sql_r_1 = "SELECT service2cve FROM SERVICE WHERE $this->service2where AND service2cve IS NOT NULL";
	    if ($this->checkBD($sql_r_1) ) {
	        return base64_decode($this->req2BD4out("service2cve","SERVICE",$this->service2where ));
	    }
	    else {
	        $result = $this->service2exploitdb();
	        $result = base64_encode($result);
	        return base64_decode($this->req2BD4in("service2cve","SERVICE",$this->service2where,$result));
	    }
	}
	

	public function service2afp(){
	    $this->ssTitre(__FUNCTION__);
	    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"afp-*\" $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
	    return $this->auth2login4nmap($this->req2BD($this->colonne,$this->table,"$this->port2where AND service2name = '$this->service_name' AND service2version = '$this->service_version' ",$query),__FUNCTION__);
	}
		
	public function service2vpn(){
	    $obj = new service2vpn($this->eth,$this->domain,$this->ip,$this->port,$this->protocol,$this->service_name,$this->service_version,$this->service_product,$this->service_extrainfo);
	        $obj->poc($this->flag_poc);
	    return $obj->service2vpn4exec();
	}
	public function service2ssh(){
	    $obj = new service2ssh($this->eth,$this->domain,$this->ip,$this->port,$this->protocol,$this->service_name,$this->service_version,$this->service_product,$this->service_extrainfo);
	        $obj->poc($this->flag_poc);
	    return $obj->service2ssh4exec();
	}
	public function service2ssl(){
	    $obj = new service2ssl($this->eth,$this->domain,$this->ip,$this->port,$this->protocol,$this->service_name,$this->service_version,$this->service_product,$this->service_extrainfo);
	        $obj->poc($this->flag_poc);
	    return $obj->service2ssl4exec();
	}
	public function service2sip(){
	    $obj = new service2sip($this->eth,$this->domain,$this->ip,$this->port,$this->protocol,$this->service_name,$this->service_version,$this->service_product,$this->service_extrainfo);
	        $obj->poc($this->flag_poc);
	    return $obj->service2sip4exec();
	}
	public function service2asterisk(){
	    $obj = new service2asterisk($this->eth,$this->domain,$this->ip,$this->port,$this->protocol,$this->service_name,$this->service_version,$this->service_product,$this->service_extrainfo);
	        $obj->poc($this->flag_poc);
	    return $obj->service2asterisk4exec();
	}
	public function service2ftp(){
	    $obj = new service2ftp($this->eth,$this->domain,$this->ip,$this->port,$this->protocol,$this->service_name,$this->service_version,$this->service_product,$this->service_extrainfo);
	        $obj->poc($this->flag_poc);
	    return $obj->service2ftp4exec();
	}
	public function service2nfs(){
	    $obj = new service2nfs($this->eth,$this->domain,$this->ip,$this->port,$this->protocol,$this->service_name,$this->service_version,$this->service_product,$this->service_extrainfo);
	    $obj->poc($this->flag_poc);
	    return $obj->service2nfs4exec();
	}
	public function service2smtp(){
	    $obj = new service2smtp($this->eth,$this->domain,$this->ip,$this->port,$this->protocol,$this->service_name,$this->service_version,$this->service_product,$this->service_extrainfo);
	        $obj->poc($this->flag_poc);
	    return $obj->service2smtp4exec();
	}
	public function service2smb(){
	    $obj = new service2smb($this->eth,$this->domain,$this->ip,$this->port,$this->protocol,$this->service_name,$this->service_version,$this->service_product,$this->service_extrainfo);
	        $obj->poc($this->flag_poc);
	    return $obj->service2smb4exec();
	}
	public function service2exploitdb(){
	    $this->ssTitre(__FUNCTION__);
	    $obj = new service2exploitdb($this->eth,$this->domain,$this->ip,$this->port,$this->protocol,$this->service_name,$this->service_version,$this->service_product,$this->service_extrainfo);
	        $obj->poc($this->flag_poc);
	    return $obj->service2exploitdb4exec();
	}

	

	
	public function service2couchdb(){
	    $this->ssTitre(__FUNCTION__);
	    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"couchdb-*\" $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
	    return $this->auth2login4nmap($this->req2BD($this->colonne,$this->table,"$this->port2where AND service2name = '$this->service_name' AND service2version = '$this->service_version' ",$query),__FUNCTION__);
	}
	

	public function service2db2(){
	    $this->ssTitre(__FUNCTION__);
	    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"db2-*\" $this->ip -s$this->protocol -p $this->port -e $this->eth -oX -  ";
	    return $this->auth2login4nmap($this->req2BD($this->colonne,$this->table,"$this->port2where AND service2name = '$this->service_name' AND service2version = '$this->service_version' ",$query),__FUNCTION__);
	    
	}
	

	public function service2jdwp(){
	    $this->ssTitre(__FUNCTION__);
	    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"jdwp-*\" $this->ip -s$this->protocol -p $this->port -e $this->eth | grep -v -i 'nmap' ";
	    return $this->auth2login4nmap($this->req2BD($this->colonne,$this->table,"$this->port2where AND service2name = '$this->service_name' AND service2version = '$this->service_version' ",$query),__FUNCTION__);
	    
	}
	
	
	public function service2ldap(){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__);
	    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"ldap-*\" $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
	    $result .= $this->cmd("localhost",$query);
	    $result .= $this->auth2login4nmap($this->req_ret_str($query),__FUNCTION__);
	    
	    $users_test = array("mail","anonymous","ftp","cisco","root","admin","administrator","guest","user","test","voip");
	    foreach ($users_test as $user_test){
	        $result .= $this->port2auth4dico4hydra("ldap2",$user_test);
	        $result .= $this->port2auth4dico4hydra("ldap3",$user_test);
	    }
	    
	    $query = "patator ldap_login host=$this->ip port=$this->port binddn='cn=Directory Manager' bindpw=FILE1  1=$this->dico_password.1000 -x ignore:mesg='ldap_bind: Invalid credentials (49)' ";
	    //$result .= $this->cmd("localhost",$query); $result .= $this->req_ret_str($query);
	    // ldap_login host=10.0.0.1 binddn='cn=Directory Manager' bindpw=FILE0 0=passwords.txt -x ignore:mesg='ldap_bind: Invalid credentials (49)'
	    //ldapsearch -H ldap://IP -x -LLL -s base -b  supportedSASLMechanisms
	    
	    return $result;
	    
	}
	
	public function service2ajp(){
	    $result = "";
	    
	    $result .= $this->ssTitre(__FUNCTION__);
	    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"ajp-*\" $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
	    $result .= $this->cmd("localhost",$query);
	    $result .= $this->auth2login4nmap($this->req_ret_str($query),__FUNCTION__);
	    
	    $query = "patator ajp_fuzz $this->ip -p $this->port -e $this->eth -oX - ";
	    //$result .= $this->cmd("localhost",$query);$result .= $this->req_ret_str($query);
	    
	    return $result;
	}

	public function service2domcon(){
	    $this->ssTitre(__FUNCTION__);
	    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"domcon-*\" $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
	    return $this->auth2login4nmap($this->req2BD($this->colonne,$this->table,"$this->port2where AND service2name = '$this->service_name' AND service2version = '$this->service_version' ",$query),__FUNCTION__);
	}
	
	

	public function service2cassandra(){
	    $result = "";
	    
	    
	    $result .= $this->ssTitre(__FUNCTION__);
	    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"cassandra-*\" $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
	    $result .= $this->cmd("localhost",$query);
	    $result .= $this->auth2login4nmap($this->req_ret_str($query),__FUNCTION__);
	    
	    $users_test = array("root","admin","administrator","guest","user","test");
	    foreach ($users_test as $user_test){
	        //$result .= $this->port2auth4dico4ncrack($user_test);
	    }
	    
	    
	    
	    return $result;
	}
	

	
	public function service2iscsi(){
	    $this->ssTitre(__FUNCTION__);
	    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"iscsi-*\" $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
	    return $this->auth2login4nmap($this->req2BD($this->colonne,$this->table,"$this->port2where AND service2name = '$this->service_name' AND service2version = '$this->service_version' ",$query),__FUNCTION__);
	    
	}
	

	

	
	public function service2mongodb(){
	    $result = "";
	    
	    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"mongodb-*\" $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
	    $result .= $this->cmd("localhost",$query);
	    $result .= $this->auth2login4nmap($this->req_ret_str($query),__FUNCTION__);
	    
	    $users_test = array("root","admin","administrator","guest","user","test");
	    foreach ($users_test as $user_test){
	        //$result .= $this->port2auth4dico4ncrack($user_test);
	    }
	    
	    
	    return $result;
	}
	


	

	public function service2cisco(){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__);
	    $query = "CAT -h $this->ip -p $this->port -a $this->dico_password ";
	    $result .= $this->cmd("localhost",$query);
	    $result .= $this->req_ret_str($query);
	    
	    $users_test = array("cisco","root","admin","administrator","guest","user","test","voip");
	    foreach ($users_test as $user_test){
	        $result .= $this->port2auth4dico4hydra("cisco",$user_test);
	    }
	    
	    
	    
	    $sql_r = "select user2name,user2pass FROM AUTH where ip='$this->ip' ORDER BY user2name;";
	    $conn = $this->mysql_ressource->query($sql_r);
	    while ($row = $conn->fetch_assoc()){
	        $user2name = trim($row['user2name']);
	        $user2pass = trim($row['user2pass']);
	        $result .= $this->article("USER/PASS FOUND FOR TEST", "$user2name/$user2pass");
	        if (!empty($user2name)) $result .= $this->port2auth4pass4hydra("cisco", $user2name, $user2pass);
	    }
	    
	    return $result;
	}
	
	public function service2snmp(){
	    $obj = new service2snmp($this->eth,$this->domain,$this->ip,$this->port,$this->protocol);
	        $obj->poc($this->flag_poc);
	    return $obj->service2snmp4exec();
	}

	

	
	public function service2vnc(){
	    $obj = new service2vnc($this->eth,$this->domain,$this->ip,$this->port,$this->protocol);
	        $obj->poc($this->flag_poc);
	    return $obj->service2vnc4exec();
	}

	
	public function service2rlogin(){
	    $obj = new service2rlogin($this->eth,$this->domain,$this->ip,$this->port,$this->protocol);
	        $obj->poc($this->flag_poc);
	    return $obj->service2rlogin4exec();
	}

	

	public function service2ipmi(){
	    $obj = new service2ipmi($this->eth,$this->domain,$this->ip,$this->port,$this->protocol);
	        $obj->poc($this->flag_poc);
	    return $obj->service2ipmi4exec();
	}
	
	public function service2ident(){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__);
	    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"auth-owners\" $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
	    $result .= $this->cmd("localhost",$query);
	    $result .= $this->auth2login4nmap($this->req_ret_str($query),__FUNCTION__);
	    
	    
	    $query = "perl /opt/ident-user-enum/ident-user-enum.pl $this->ip $this->port";
	    $result .= $this->cmd("localhost",$query);  $result .= $this->req_ret_str($query);
	    
	    return $result;
	}
	
	
	
	public function service2informix(){
	    $this->ssTitre(__FUNCTION__);
	    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"informix-*\" $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
	    return $this->auth2login4nmap($this->req2BD($this->colonne,$this->table,"$this->port2where AND service2name = '$this->service_name' AND service2version = '$this->service_version' ",$query),__FUNCTION__);
	    
	}
	
	public function service2imap(){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__);
	    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"imap-*\" $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
	    $result .= $this->cmd("localhost",$query);
	    $result .= $this->auth2login4nmap($this->req_ret_str($query),__FUNCTION__);
	    
	    $users_test = array("mail","mail-daemon","anonymous","ftp","cisco","root","admin","administrator","guest","user","test","voip");
	    foreach ($users_test as $user_test){
	        $result .= $this->port2auth4dico4hydra("imap",$user_test);
	        $query = "patator imap_login host=$this->ip port=$this->port user=$user_test password=FILE1 1=$this->dico_password.1000 -x ignore:fgrep='no such user'   ";
	        //$result .= $this->cmd("localhost",$query);$result .= $this->req_ret_str($query);
	    }
	    
	    
	    $sql_r = "select user2name,user2pass FROM AUTH where ip='$this->ip' ORDER BY user2name;";
	    $conn = $this->mysql_ressource->query($sql_r);
	    while ($row = $conn->fetch_assoc()){
	        $user2name = trim($row['user2name']);
	        $user2pass = trim($row['user2pass']);
	        $result .= $this->article("USER/PASS FOUND FOR TEST", "$user2name/$user2pass");
	        if (!empty($user2name)) $result .= $this->port2auth4pass4hydra("imap", $user2name, $user2pass);
	    }
	    
	    return $result;
	}
	
	

	
	public function service2drda(){
	    $this->ssTitre(__FUNCTION__);
	    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"drda-*\" $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
	    return $this->auth2login4nmap($this->req2BD($this->colonne,$this->table,"$this->port2where AND service2name = '$this->service_name' AND service2version = '$this->service_version' ",$query),__FUNCTION__);
	    
	}

	

	
	

	
	public function service2finger(){
	    $afficheUSER = array();
	    $result = "";
	    
	    $result .= $this->ssTitre(__FUNCTION__);
	    
	    $users_tmp = file("$this->dico_users");
	    foreach ($users_tmp as $user_tmp){
	        $user_tmp = trim($user_tmp);
	        $query = "finger $user_tmp@$this->ip | grep -v '???' | grep -v 'Idle' ";
	        $check = $this->req_ret_tab($query);
	        if(!empty($check))
	            foreach ($check as $ligne){
	                if(!empty($ligne))  {
	                    if (preg_match("/(?<login>[[:print:]]\w+)([[:space:]]{1,})(?<info>[[:print:]]{1,})/", $ligne, $afficheUSER) ) {
	                        //var_dump($afficheUSER);
	                        if (isset($afficheUSER['login'])){ // faire pour plusieurs resultat
	                            $result .= $this->yesUSERS($this->port2id,$afficheUSER['login'],__FUNCTION__ ,$afficheUSER['info']);
	                        }
	                    }
	                }
	        }
	    }
	    
	    
	    //$query = "patator finger_lookup host=$this->ip port=$this->port user=FILE0 0=$this->dico_users -x ignore:fgrep='no such user'   ";
	    //$result .= $this->cmd("localhost",$query);$result .= $this->req_ret_str($query);
	    
	    return $result;
	}
	
	
	public function service2iax2(){
	    $this->ssTitre(__FUNCTION__);
	    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"iax2-*\" $this->ip -s$this->protocol -p $this->port -e $this->eth -oX -";
	    return $this->auth2login4nmap($this->req2BD($this->colonne,$this->table,"$this->port2where AND service2name = '$this->service_name' AND service2version = '$this->service_version' ",$query),__FUNCTION__);
	    
	}
	
	

	
	public function service2netbios(){
	    $obj = new service2netbios($this->eth,$this->domain,$this->ip,$this->port,$this->protocol);
	        $obj->poc($this->flag_poc);
	    return $obj->service2netbios4exec();
	}

	

	
	public function service2rdp(){
	    $result = "";
	    
	    $result .= $this->ssTitre(__FUNCTION__);
	    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"rdp-enum-encryption,rdp-vuln-ms12-020\" $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
	    $result .= $this->cmd("localhost",$query);
	    $result .= $this->auth2login4nmap($this->req_ret_str($query),__FUNCTION__);
	    
	    
	    $users_test = array("root","admin","administrator","guest","user","test");
	    foreach ($users_test as $user_test){
	        //$result .= $this->port2auth4dico4ncrack($user_test);
	    }
	    
	    
	    $users_test = array("root","admin","administrator","guest","user","test");
	    foreach ($users_test as $user_test){
	        $result .= $this->port2auth4dico4hydra("rdp",$user_test);
	        $query = "patator rdp_login host=$this->ip port=$this->port user=$user_test password=FILE1  1=$this->dico_password.1000 -x ignore:fgrep='no such user'   ";
	        // $result .= $this->cmd("localhost",$query);$result .= $this->req_ret_str($query);
	    }
	    
	    
	    $sql_r = "select user2name,user2pass FROM AUTH where ip='$this->ip' ORDER BY user2name;";
	    $conn = $this->mysql_ressource->query($sql_r);
	    while ($row = $conn->fetch_assoc()){
	        $user2name = trim($row['user2name']);
	        $user2pass = trim($row['user2pass']);
	        $result .= $this->article("USER/PASS FOUND FOR TEST", "$user2name/$user2pass");
	        if (!empty($user2name)) $result .= $this->port2auth4pass4hydra("rdp", $user2name, $user2pass);
	    }
	    
	    return $result;
	}
	
	
	public function service2rpc(){
	    $this->ssTitre(__FUNCTION__);
	    // https://bitvijays.github.io/LFF-IPS-P3-Exploitation.html
	    $query = "echo '$this->root_passwd' | sudo -S nmap --script rpcinfo -Pn -n --reason $this->ip -s$this->protocol -p $this->port | grep -v -i 'nmap' ";
	    return $this->auth2login4nmap($this->req2BD($this->colonne,$this->table,"$this->port2where AND service2name = '$this->service_name' AND service2version = '$this->service_version' ",$query),__FUNCTION__);
	    
	}
	
	
	public function service2sctp(){
	    $this->ssTitre(__FUNCTION__);
	    $query = "echo '$this->root_passwd' | sudo -S nmap -n -Pn --reason -PY -sY $this->ip -p $this->port -e $this->eth ";
	    return $this->auth2login4nmap($this->req2BD($this->colonne,$this->table,"$this->port2where AND service2name = '$this->service_name' AND service2version = '$this->service_version' ",$query),__FUNCTION__);
	    
	}
	
	
	
	public function service2shell(){
	    $result = "";
	    
	    $result .= $this->ssTitre(__FUNCTION__);
	    
	    
	    $users_test = array("root","admin","administrator","guest","user","test");
	    foreach ($users_test as $user_test){
	        $result .= $this->port2auth4dico4hydra("rsh",$user_test);
	    }
	    
	    
	    $query = "echo '$this->cmd_unix' | nc $this->ip $this->port -q 60 -v -".strtolower($this->protocol) ;
	    $result .= $this->cmd("localhost",$query);
	    $result .= $this->req_ret_str($query);
	    
	    
	    $sql_r = "select user2name,user2pass FROM AUTH where ip='$this->ip' ORDER BY user2name;";
	    $conn = $this->mysql_ressource->query($sql_r);
	    while ($row = $conn->fetch_assoc()){
	        $user2name = trim($row['user2name']);
	        $user2pass = trim($row['user2pass']);
	        $result .= $this->article("USER/PASS FOUND FOR TEST", "$user2name/$user2pass");
	        if (!empty($user2name)) $result .= $this->port2auth4pass4hydra("rsh", $user2name, $user2pass);
	    }
	    
	    
	    return $result;
	}
	
	
	public function service2tftp(){
	    $this->ssTitre(__FUNCTION__);
	    $query = "echo \"db_status\nuse auxiliary/scanner/tftp/tftpbrute\nset RHOSTS $this->ip\nset RPORT $this->port\nset THREADS 8\nrun\nexit\n \" > $this->dir_tmp/".__FUNCTION__.".rc && echo '$this->root_passwd' | sudo -S msfconsole -q -r $this->dir_tmp/".__FUNCTION__.".rc "; // "; // -y /usr/share/metasploit-framework/config/database.yml" ;
	    return $this->auth2login4nmap($this->req2BD($this->colonne,$this->table,"$this->port2where AND service2name = '$this->service_name' AND service2version = '$this->service_version' ",$query),__FUNCTION__);
	    
	}
	
	
	
	public function service2x11(){
	    $this->ssTitre(__FUNCTION__);
	    // xdpyinfo
	    $query = "echo \"db_status\nuse auxiliary/scanner/x11/open_x11\nset RHOSTS $this->ip\nset RPORT $this->port\nrun\nexit\n \" > $this->dir_tmp/".__FUNCTION__.".rc && echo '$this->root_passwd' | sudo -S msfconsole -q -r $this->dir_tmp/".__FUNCTION__.".rc "; // -y /usr/share/metasploit-framework/config/database.yml" ;
	    return $this->auth2login4nmap($this->req2BD($this->colonne,$this->table,"$this->port2where AND service2name = '$this->service_name' AND service2version = '$this->service_version' ",$query),__FUNCTION__);
	    
	}
	
	public function service2vmauth(){
	    $result = "";
	    
	    $result .= $this->ssTitre(__FUNCTION__);
	    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"vmauthd-*\" $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
	    $result .= $this->cmd("localhost",$query);
	    $result .= $this->auth2login4nmap($this->req_ret_str($query),__FUNCTION__);
	    
	    $users_test = array("root","admin","administrator","guest","user","test");
	    foreach ($users_test as $user_test){
	        $result .= $this->port2auth4dico4hydra("vmauthd",$user_test);
	        $query = "patator vmauthd_login host=$this->ip port=$this->port user=$user_test password=FILE1  1=$this->dico_password.1000 -x ignore:fgrep='no such user'   ";
	        //$result .= $this->cmd("localhost",$query); $result .= $this->req_ret_str($query);
	    }
	    
	    
	    $sql_r = "select user2name,user2pass FROM AUTH where ip='$this->ip' ORDER BY user2name;";
	    $conn = $this->mysql_ressource->query($sql_r);
	    while ($row = $conn->fetch_assoc()){
	        $user2name = trim($row['user2name']);
	        $user2pass = trim($row['user2pass']);
	        $result .= $this->article("USER/PASS FOUND FOR TEST", "$user2name/$user2pass");
	        if (!empty($user2name)) $result .= $this->port2auth4pass4hydra("vmauthd", $user2name, $user2pass);
	    }
	    
	    
	}
	
	
	
	public function service2tls1(){
	    $this->ssTitre(__FUNCTION__);
	    $query = "echo \"x\" | openssl s_client -connect $this->ip:$this->port -cipher NULL,LOW -tls1  ";
	    return $this->req_ret_str($query);
	    
	}
	
	public function service2sock5(){
	    $result = "";
	    
	    $result .= $this->ssTitre(__FUNCTION__);
	    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"socks-*\" $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
	    $result .= $this->cmd("localhost",$query);
	    $result .= $this->auth2login4nmap($this->req_ret_str($query),__FUNCTION__);
	    
	    $users_test = array("root","admin","administrator","guest","user","test");
	    foreach ($users_test as $user_test){
	        $result .= $this->port2auth4dico4hydra("socks5",$user_test);
	    }
	    
	    
	    return $result;
	}
	
	
	
	public function service2rpcap(){
	    $result = "";
	    
	    $result .= $this->ssTitre(__FUNCTION__);
	    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"rpcap-*\" $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
	    $result .= $this->cmd("localhost",$query);
	    $result .= $this->auth2login4nmap($this->req_ret_str($query),__FUNCTION__);
	    
	    $users_test = array("root","admin","administrator","guest","user","test");
	    foreach ($users_test as $user_test){
	        $result .= $this->port2auth4dico4hydra("rpcap",$user_test);
	    }
	    return $result;
	}
	
	
	public function service2rsync(){
	    $this->ssTitre(__FUNCTION__);
	    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"rsync-*\" --script-args 'rsync-brute.module=www' $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
	    return $this->auth2login4nmap($this->req2BD($this->colonne,$this->table,"$this->port2where AND service2name = '$this->service_name' AND service2version = '$this->service_version' ",$query),__FUNCTION__);
	    
	}
	
	public function service2redis(){
	    $result = "";
	    
	    $result .= $this->ssTitre(__FUNCTION__);
	    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"redis-*\" $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
	    $result .= $this->cmd("localhost",$query);
	    $result .= $this->auth2login4nmap($this->req_ret_str($query),__FUNCTION__);
	    
	    $users_test = array("root","admin","administrator","guest","user","test");
	    foreach ($users_test as $user_test){
	        $result .= $this->port2auth4dico4hydra("redis",$user_test);
	    }
	    
	    
	    $sql_r = "select user2name,user2pass FROM AUTH where ip='$this->ip' ORDER BY user2name;";
	    $conn = $this->mysql_ressource->query($sql_r);
	    while ($row = $conn->fetch_assoc()){
	        $user2name = trim($row['user2name']);
	        $user2pass = trim($row['user2pass']);
	        $result .= $this->article("USER/PASS FOUND FOR TEST", "$user2name/$user2pass");
	        if (!empty($user2name)) $result .= $this->port2auth4pass4hydra("redis", $user2name, $user2pass);
	    }
	    
	    return $result;
	}
	
	
	public function service2pop3(){
	    $result = "";
	    
	    $result .= $this->ssTitre(__FUNCTION__);
	    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"pop3-*\" $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
	    $result .= $this->cmd("localhost",$query);
	    $result .= $this->auth2login4nmap($this->req_ret_str($query),__FUNCTION__);
	    
	    $users_test = array("mail","mail-daemon","anonymous","ftp","cisco","root","admin","administrator","guest","user","test","voip");
	    foreach ($users_test as $user_test){
	        $result .= $this->port2auth4dico4hydra("pop3",$user_test);
	        $query = "patator pop_login host=$this->ip port=$this->port user=$user_test password=FILE1  1=$this->dico_password.1000 -x ignore:fgrep='no such user'   ";
	        //$result .= $this->cmd("localhost",$query); $result .= $this->req_ret_str($query);
	    }
	    
	    
	    $sql_r = "select user2name,user2pass FROM AUTH where ip='$this->ip' ORDER BY user2name;";
	    $conn = $this->mysql_ressource->query($sql_r);
	    while ($row = $conn->fetch_assoc()){
	        $user2name = trim($row['user2name']);
	        $user2pass = trim($row['user2pass']);
	        $result .= $this->article("USER/PASS FOUND FOR TEST", "$user2name/$user2pass");
	        if (!empty($user2name)) $result .= $this->port2auth4pass4hydra("pop3", $user2name, $user2pass);
	    }
	    
	    return $result;
	}
	
	public function service2pgsql(){
	    $result = "";
	    
	    $result .= $this->ssTitre(__FUNCTION__);
	    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"pgsql-*\" $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
	    $result .= $this->cmd("localhost",$query);
	    $result .= $this->auth2login4nmap($this->req_ret_str($query),__FUNCTION__);
	    
	    $users_test = array("pgsql","postgres","mail","anonymous","ftp","cisco","root","admin","administrator","guest","user","test","voip");
	    foreach ($users_test as $user_test){
	        $result .= $this->port2auth4dico4hydra("postgres",$user_test);
	        $query = "patator pgsql_login host=$this->ip port=$this->port user=$user_test password=FILE1  1=$this->dico_password.1000 -x ignore:fgrep='password authentication failed for user'  ";
	        //$result .= $this->cmd("localhost",$query); $result .= $this->req_ret_str($query);
	    }
	    
	    
	    $sql_r = "select user2name,user2pass FROM AUTH where ip='$this->ip' ORDER BY user2name;";
	    $conn = $this->mysql_ressource->query($sql_r);
	    while ($row = $conn->fetch_assoc()){
	        $user2name = trim($row['user2name']);
	        $user2pass = trim($row['user2pass']);
	        $result .= $this->article("USER/PASS FOUND FOR TEST", "$user2name/$user2pass");
	        if (!empty($user2name)) $result .= $this->port2auth4pass4hydra("postgres", $user2name, $user2pass);
	    }
	    
	    return $result;
	}
	
	public function service2pcanywhere(){
	    $result = "";
	    
	    $result .= $this->ssTitre(__FUNCTION__);
	    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"pcanywhere-*\" $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
	    $result .= $this->cmd("localhost",$query);
	    $result .= $this->auth2login4nmap($this->req_ret_str($query),__FUNCTION__);
	    
	    $users_test = array("root","admin","administrator","guest","user","test");
	    foreach ($users_test as $user_test){
	        $result .= $this->port2auth4dico4hydra("pcanywhere",$user_test);
	    }
	    
	    $sql_r = "select user2name,user2pass FROM AUTH where ip='$this->ip' ORDER BY user2name;";
	    $conn = $this->mysql_ressource->query($sql_r);
	    while ($row = $conn->fetch_assoc()){
	        $user2name = trim($row['user2name']);
	        $user2pass = trim($row['user2pass']);
	        $result .= $this->article("USER/PASS FOUND FOR TEST", "$user2name/$user2pass");
	        if (!empty($user2name)) $result .= $this->port2auth4pass4hydra("pcanywhere",$user2name,$user2pass);
	    }
	    
	    return $result;
	}
	
	
	public function service2oracle(){
	    $result = "";
	    
	    $result .= $this->ssTitre(__FUNCTION__);
	    
	    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"oracle-*\" $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
	    $result .= $this->cmd("localhost",$query);
	    $result .= $this->req_ret_str($query);
	    
	    $query = "OracleScanner -s $this->ip -P $this->port ";
	    $result .= $this->cmd("localhost",$query);
	    $result .= $this->req_ret_str($query);
	    
	    $query = "sidguess -i $this->ip -p $this->port ";
	    //$result .= $this->cmd("localhost",$query);$result .= $this->req_ret_str($query);
	    
	    /*
	     oracle_login host=10.0.0.1 sid=FILE0 0=sids.txt -x ignore:code=ORA-12505
	     oracle_login host=10.0.0.1 user=SYS password=FILE0 0=passwords.txt -x ignore:code=ORA-01017
	     
	     */
	    $users_test = array("SYS","oracle","ftp","cisco","root","admin","administrator","guest","user","test","voip");
	    foreach ($users_test as $user_test){
	        $query = "patator oracle_login host=$this->ip port=$this->port user=$user_test password=FILE1  1=$this->dico_password.1000 -x ignore:code=ORA-01017";
	        //$result .= $this->cmd("localhost",$query);$result .= $this->req_ret_str($query);
	    }
	    
	    
	    return $result;
	}
	
	
	public function service2msrpc(){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__);
	    $query = "echo '$this->root_passwd' | sudo -S nmap  -Pn -n --script msrpc-enum.nse -s$this->protocol -p $this->port $this->ip -e $this->eth -oX -";
	    $result .= $this->cmd("localhost",$query);
	    $result .= $this->req_ret_str($query);
	    return $result;
	}
	
	
	public function service2mssql(){
	    $result = "";
	    
	    $result .= $this->ssTitre(__FUNCTION__);
	    $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"ms-sql-*\" $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
	    $result .= $this->cmd("localhost",$query);
	    $result .= $this->auth2login4nmap($this->req_ret_str($query),__FUNCTION__);
	    
	    $users_test = array("mssql","mail","anonymous","ftp","cisco","root","admin","administrator","guest","user","test","voip");
	    foreach ($users_test as $user_test){
	        $result .= $this->port2auth4dico4hydra("mssql",$user_test);
	    }
	    
	    $query = "patator mssql_login host=$this->ip port=$this->port user=$user_test password=FILE1  1=$this->dico_password.1000 -x ignore:fgrep='no such user'   ";
	    //$result .= $this->cmd("localhost",$query); $result .= $this->req_ret_str($query);
	    
	    return $result;
	}
	

	public function service4info(){
	    $result = "";
	    echo "\n====START SERVICE4INFO:$this->port=======================================================\n";
	    $this->titre(__FUNCTION__);
	    $date_now = date('Y-m-d H:i:s');
	    $this->article("Date Now", $date_now);
	    $this->article("Date Rec", $this->date_rec);

	    //$this->article("HOST", $this->ip2host(""));
	    
	    
	    

	    
	    $this->article("ID PORT", $this->port2id);
	    $this->article("PORT NUMBER", $this->port);
	    $this->article("PROTOCOL", $this->protocol);
	    $this->article("NAME",$this->service_name);
	    $this->article("VERSION",$this->service_version);
	    $this->article("PRODUCT",$this->service_product);
	    $this->article("extrainfo",$this->service_extrainfo);
	    $service2banner = trim($this->service2banner());$this->article("Banner",$service2banner);
	    $service4traceroute = trim($this->port2traceroute());$this->article("Traceroute Port",$service4traceroute);
	    $service4cve = trim($this->service4cve());$this->article("CVE",$service4cve);
	    
	    
	    $port2root = $this->port2root8db($this->port2id);
	    if ($port2root) $this->article("port2root",$port2root );
	    	    
	    $port2shell = $this->port2shell8db($this->port2id);
	    if ($port2shell) $this->article("port2shell",$port2shell );
	    
	    $port2write = $this->port2write8db($this->port2id);
	    if ($port2write) $this->article("port2write",$port2write );
	    	    
	    $port2read = $this->port2read8db($this->port2id);
	    if ($port2read) $this->article("port2read",$port2read );
	    
	    $tab_whois8lan = array();
	    
	    if ( ($port2root) || ($port2shell) || ($port2write) || ($port2read) ) {
	       // var_dump($tab_whois8lan);
	        $tab_whois8lan = $this->service8lan();
	        $size = count($tab_whois8lan);
	        for ($i=0;$i<$size;$i++)
	            if (!empty($tab_whois8lan[$i]))
	            foreach ($tab_whois8lan[$i] as $lan2whois => $templateB64_id ){
	            //var_dump($lan2whois);
	            //var_dump($templateB64_id);
	            $this->article($lan2whois, base64_decode($templateB64_id));
	        }
	        
	    }
	    echo "====END SERVICE4INFO:$this->port=======================================================\n\n";
	    return array($this->date_rec,$service2banner,$service4cve,$port2root,$port2shell,$port2write,$port2read,$tab_whois8lan);
	    
	    	} 


	
	public function service4switch(){
	    // https://kalilinuxtutorials.com/metateta-scanning-exploiting-network/
	    
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__);
		
	    $service = "tftp";
	    if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service))) return $result .= $this->service2tftp();
		$service = "ftp";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service))) return $result .= $this->service2ftp();
		$service = "auth";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service))) return $result .= $this->service2ident();
		$service = "ssh";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service))) return $result .= $this->service2ssh();
		$service = "ajp";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service))) return $result .= $this->service2ajp();
		$service = "asterisk";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service))) return $result .= $this->service2asterisk();
		$service = "cisco";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service))) return $result .= $this->service2cisco();
		$service = "couchdb";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service))) return $result .= $this->service2couchdb4nmap();
		$service = "db2";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service))) return $result .= $this->service2db2nmap();
		$service = "dns";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service)) || (stristr($this->service_name,"domain" )) ) return $result .= $this->service2dns();
		$service = "finger";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service))) return $result .= $this->service2finger();
		$service = "http";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service))) return $result .= $this->service2web();
		$service = "ident";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service))) return $result .= $this->service2ident();
		$service = "imap";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service))) return $result .= $this->service2imap();
		$service = "jdwp";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service))) return $result .= $this->service2jdwp();
		$service = "ldap";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service))) return $result .= $this->service2ldap();
		$service = "mongodb";
		if( (stristr($this->service_name,$service )) || (stristr($this->service_version,$service)) || (stristr($this->service_name,"mongod" )) ) return $result .= $this->service2mongodb();
		$service = "ms-sql";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service)) || (stristr($this->service_name,"mssql" )) ) return $result .= $this->service2mssql();
		$service = "mysql";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service))) return $result .= $this->service2mysql();
		$service = "netbios";
		if(((stristr($this->service_name,$service )) || (stristr($this->service_version,$service)))   ) return $result .= $this->service2netbios();
		$service = "nfs";
		if( (stristr($this->service_name,$service )) || (stristr($this->service_version,$service)) || (stristr($this->service_name,"mountd" ))  ) return $result .= $this->service2nfs();
		$service = "rdp";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service))) return $result .= $this->service2rdp();
		$service = "msrpc";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service))) return $result .= $this->service2msrpc();
		$service = "rpc";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service)) || (stristr($this->service_name,"status" )) || (stristr($this->service_name,"rpcbind" ))  ) return $result .= $this->service2rpc();
		$service = "shell";
		if( (stristr($this->service_name,$service )) || (stristr($this->service_version,$service)) || (stristr($this->service_name,"rshd" ))  ) return $result .= $this->service2shell();
		$service = "sip";if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service))) return $result .= $this->service2sip();
		$service = "smb";
		if( (stristr($this->service_name,$service)) || (stristr($this->service_version,$service)) || (stristr($this->service_name,"samba")) || (stristr($this->service_name,"netbios-ssn")) || (stristr($this->service_name,"microsoft-ds")) ) return $result .= $this->service2smb();
		$service = "smtp";
		if((stristr($this->service_name,$service)) || (stristr($this->service_version,$service)) || (stristr($this->service_name,"submission" )) ) return $result .= $this->service2smtp();
		$service = "snmp";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service)) || (stristr($this->service_name,"smux" )) ) return $result .= $this->service2snmp();
		$service = "telnet";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service))) return $result .= $this->service2telnet();
		$service = "vpn";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service)) || (stristr($this->service_name,"isakmp" )) ) return $result .= $this->service2vpn();
		$service = "x11";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service))) return $result .= $this->service2x11();
		$service = "web";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service))) return $result .= $this->service2web();
		$service = "iis";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service))) return $result .= $this->service2web();
		$service = "login";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service))) return $result .= $this->service2rlogin();
		$service = "winrm";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service))) return $result .= $this->service2winrm();		
		$service = "vmware-auth";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service))) return $result .= $this->service2vmauth();
		$service = "asf-rmcp";
		if((stristr($this->service_name,$service )) || (stristr($this->service_version,$service))) return $result .= $this->service2ipmi();
		
		
		
		
		return $result;
		
	}

	// #################################################################################

	

	public function service2web(){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__);
	    
		$obj_web = new WEB($this->eth,$this->domain,"http://$this->ip:$this->port/");
		$obj_web->poc($this->flag_poc);
		if($obj_web->web2check_200()) $result .= $obj_web->web4pentest();
		$obj_web = new WEB($this->eth,$this->domain,"https://$this->ip:$this->port/");
		$obj_web->poc($this->flag_poc);
		if($obj_web->web2check_200()) $result .= $obj_web->web4pentest();
		
		return $result;
	}
	
	

	
    













}
?>
