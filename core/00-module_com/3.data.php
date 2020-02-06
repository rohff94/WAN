<?php


class DATA extends com4for {
	var $mysql_ressource ;
	var $clean_indb ;
	var $flag_poc ;


	
	/*
mysql> update PORT set port2version=NULL WHERE from_base64(port2version) NOT LIKE "%</nmaprun>%" ;
mysql> update IP set ip2port=NULL WHERE ip2port="PD94bWwgdmVyc2lvbj0nMS4wJyBlbmNvZGluZz0nVVRGLTgnPz4KPGlwMnBvcnQ+CjxvcGVuX3BvcnRzX3RjcD48L29wZW5fcG9ydHNfdGNwPgo8b3Blbl9wb3J0c191ZHA+PC9vcGVuX3BvcnRzX3VkcD4KPC9pcDJwb3J0Pgo=" ;
mysql> select id,ip from IP WHERE ip IN (SELECT ip FROM IP GROUP BY ip HAVING COUNT(*) > 1) ORDER BY ip;
	 * 
	 * 
	 * 
	 */
	
	public function __construct() {
	    // set global max_connections = 2000 ;
		parent::__construct();
		$this->flag_poc = FALSE ;
		//$this->requette("ulimit -n 9192");
		$this->clean_indb = array("|","`","'","$","\n\n\n",";","\\",")","(");
	$this->mysql_ressource = new mysqli($this->mysql_host, $this->mysql_login, $this->mysql_passwd, $this->mysql_database);
	if ($this->mysql_ressource == FALSE) {$this->rouge("Connexion to Mysql $this->mysql_database Failled");exit();}
	
	}
	
	

public function poc($flag_poc){
    //var_dump($flag_poc);
    
    if (stristr($flag_poc,"true")) return $this->flag_poc = TRUE;
    if (stristr($flag_poc,"false")) return $this->flag_poc = FALSE;
    if ($flag_poc) return $this->flag_poc = TRUE;
    if (!$flag_poc) return $this->flag_poc = FALSE;
    if ($flag_poc==1) return $this->flag_poc = TRUE;
    if (!$flag_poc==0) return $this->flag_poc = FALSE;
}

public function  req2BD($colonne,$table,$where,$query){
	$colonne = trim($colonne);$table = trim($table);$where = trim($where);
	$result = "";

	$sql_r_1 = "SELECT $colonne FROM $table WHERE $where AND $colonne IS NOT NULL";
	if ($this->checkBD($sql_r_1) ) {
	    $result_db = $this->req2BD4out($colonne,$table,$where);
	    $result .= base64_decode($result_db);
	    //echo $result;
	    return "$result\n";
	}
	
	else {
	    $this->ssTitre($colonne);
	    $query = trim($query);
	    //$query = "$query  | sed \"s/'//g\" | sed 's/\"//g' ";
	    //$result .= $this->cmd("localhost",$query);
	    $result .= $this->req_ret_str($query);
	    
	    
	    $result = base64_encode($result);
	    return base64_decode($this->req2BD4in($colonne, $table, $where, $result));
	}
}


public function  req2BD4out($colonne,$table,$where){
    $colonne = trim($colonne);$table = trim($table);$where = trim($where);
    $sql_r2 = "SELECT $colonne FROM $table WHERE $where ";
    //echo "$sql_r2\n";
    $conn = $this->mysql_ressource->query($sql_r2);
    $row = $conn->fetch_assoc();
    $result = $row["$colonne"];    

    $sql_d = "UPDATE $table set $colonne=NULL WHERE $where ";
    $texte = "mysql --user=$this->mysql_login --password=$this->mysql_passwd --database=$this->mysql_database --execute=\"$sql_d;\"  2>/dev/null \n";
    $this->article("IF YOU WANT TO DELETE THIS RECORD", $texte);
    return $result;
}

public function  req2BD4in($colonne,$table,$where,$result){
	$colonne = trim($colonne);$table = trim($table);$where = trim($where);
	    
		//$query = str_replace($this->clean_indb, "", $query);
		//echo  "\t\033[33;40;1;1m$result\033[0m\n";
		
		$sql_w = "UPDATE $table SET $colonne='$result' WHERE $where  ";
		//$sql_w = $this->mysql_ressource->real_escape_string($sql_w);		
		$this->mysql_ressource->query($sql_w);
		//echo "$sql_w\n";
		$this->pause();
		return $result;
}







public function  ip2backdoor8db($ip2id){
    $sql_w = "SELECT ip2backdoor FROM IP WHERE id = $ip2id AND ip2backdoor = 1 ";
    return $this->checkBD($sql_w);
}

public function  ip2root8db($ip2id){
    $sql_w = "SELECT ip2root FROM IP WHERE id = $ip2id AND ip2root = 1 ";
    //return $this->checkBD($sql_w);
    return FALSE;
}


public function  ip2shell8db($ip2id){
    $sql_w = "SELECT ip2shell FROM IP WHERE id = $ip2id AND ip2shell = 1 ";
    return $this->checkBD($sql_w);
}

public function  ip2read8db($ip2id){
    $sql_w = "SELECT ip2read FROM IP WHERE id = $ip2id AND ip2read = 1 ";
    return $this->checkBD($sql_w);
}

public function  ip2write8db($ip2id){
    $sql_w = "SELECT ip2write FROM IP WHERE id = $ip2id AND ip2write = 1 ";
    return $this->checkBD($sql_w);
}


public function  port2root8db($port2id){
    $sql_w = "SELECT port2root FROM PORT WHERE id = $port2id AND port2root IS NOT NULL ";
    if ($this->checkBD($sql_w)!==FALSE){
        return trim(base64_decode($this->mysql_ressource->query($sql_w)->fetch_assoc()['port2root']));
    }
    return FALSE;
}


public function  port2shell8db($port2id){
    $sql_w = "SELECT port2shell FROM PORT WHERE id = $port2id AND port2shell IS NOT NULL ";
    if ($this->checkBD($sql_w)!==FALSE){
        return trim(base64_decode($this->mysql_ressource->query($sql_w)->fetch_assoc()['port2shell']));
    }
    return FALSE;
}

public function  port2read8db($port2id){
    $sql_w = "SELECT port2read FROM PORT WHERE id = $port2id AND port2read IS NOT NULL ";
    if ($this->checkBD($sql_w)!==FALSE){
        return trim(base64_decode($this->mysql_ressource->query($sql_w)->fetch_assoc()['port2read']));
    }
    return FALSE;
}

public function  port2write8db($port2id){
    $sql_w = "SELECT port2write FROM PORT WHERE id = $port2id AND port2write IS NOT NULL ";
    if ($this->checkBD($sql_w)!==FALSE){
        return trim(base64_decode($this->mysql_ressource->query($sql_w)->fetch_assoc()['port2write']));
    }
    return FALSE;
}

public function checkBD($sql){
	//echo "$sql;\n";
	//echo "mysql --user=$this->mysql_login --password=$this->mysql_passwd --database=$this->mysql_database --execute=\"SELECT EXISTS($sql);\"  2>/dev/null \n";
	//echo "mysql --user=$this->mysql_login --password=$this->mysql_passwd --database=$this->mysql_database --execute=\"$sql;\"  2>/dev/null \n";
	//$this->pause();
	
	$result = $this->mysql_ressource->query("SELECT EXISTS($sql)");
	if (is_bool($result)) return FALSE ;
	$row = $result->fetch_array(MYSQLI_NUM);
	

	
	if ($row[0]==1) {return TRUE;}
	else return FALSE;
}


public function faraday2cve(){
    /*
 psql --username=rohff --password -l
 psql -U rohff -l 
 psql -h localhost --username=pgadmin --list  
 psql -h localhost -p port_number -d database_name -U user2name -W
     */
    $query = "echo 'host_name,host_description,host_owned,host_os,interface_name,interface_description,interface_hostnames,interface_mac,interface_network_segment,interface_ipv4_address,interface_ipv4_gateway,interface_ipv4_mask,interface_ipv4_dns,interface_ipv6_address,interface_ipv6_gateway,interface_ipv6_prefix,interface_ipv6_dns,service_name,service_description,service_owned,service_port,service_protocol,service_version,service_status,vulnerability_name,vulnerability_desc,vulnerability_data,vulnerability_severity,vulnerability_refs,vulnerability_confirmed,vulnerability_resolution,vulnerability_status,vulnerability_policyviolations,vulnerability_web_name,vulnerability_web_desc,vulnerability_web_data,vulnerability_web_severity,vulnerability_web_refs,vulnerability_web_confirmed,vulnerability_web_status,vulnerability_web_website,vulnerability_web_request,vulnerability_web_response,vulnerability_web_method,vulnerability_web_pname,vulnerability_web_params,vulnerability_web_query,vulnerability_web_resolution,vulnerability_web_policyviolations,vulnerability_web_path' > $this->dir_tmp/faraday_ooredoo.csv ";
    $this->req_ret_str($query);
    $sql_auth = "SELECT ip,port,protocol,user2name,user2pass FROM AUTH WHERE port=22 ";
    $this->article("SQL AUTH", $sql_auth);
    
    
    if ( $user2auth = $this->mysql_ressource->query($sql_auth) ) {
        while ($auth_row = $user2auth->fetch_assoc()) {
            $ip = trim($auth_row['ip']);
            $port = trim($auth_row['port']);
            $user2name = trim($auth_row['user2name']);
            $user2pass = trim($auth_row['user2pass']);
            
            $sql_ip = "SELECT ip2eth,ip2os4arch,ip2host FROM IP WHERE ip = '$ip' LIMIT 1" ;
            $this->article("SQL IP", $sql_ip);
            $ip_info = $this->mysql_ressource->query($sql_ip);
            $ip_info_row = $ip_info->fetch_assoc();
            
            $sql_port = "SELECT service2name,service2version,port2version FROM PORT WHERE ip = '$ip' AND port = '$port' LIMIT 1" ;
            $this->article("SQL AUTH", $sql_port);
            $port_info = $this->mysql_ressource->query($sql_port);
            $port_info_row = $port_info->fetch_assoc();
             
            $host_name = $ip;
            $host_description = "";
            $host_owned = "true" ;
            $host_os = trim($ip_info_row['ip2os4arch']);
            $interface_name = trim($ip_info_row['ip2eth']);
            $interface_description = "";
            $interface_hostnames = ""; // trim(base64_decode($ip_info_row['ip2host']));
            $interface_mac = "";
            $interface_network_segment = "";
            $interface_ipv4_address = $ip ;
            $interface_ipv4_gateway = "";
            $interface_ipv4_mask = "";
            $interface_ipv4_dns = "";
            $interface_ipv6_address = "";
            $interface_ipv6_gateway = "";
            $interface_ipv6_prefix = "";
            $interface_ipv6_dns = "";
            $service_name = trim($port_info_row['service2name']);
            $service_description = ""; // trim($port_info_row['service2version']); // trim(base64_decode($port_info_row['port2version']));
            $service_owned = "true";
            $service_port = $port;
            $service_protocol = trim($port_info_row['service2name']);
            $service_version = "";// trim($port_info_row['service2version']);
            $service_status = "open" ;
            
            $vulnerability_name = "Default credentials";
            $vulnerability_desc = "Default credentials in user";
            $vulnerability_data = "$user2name:$user2pass";
            $vulnerability_severity = "critical";
            $vulnerability_refs = "https://cwe.mitre.org/data/definitions/255.html, https://cwe.mitre.org/data/definitions/798.html";
            $vulnerability_confirmed = "true" ;
            $vulnerability_resolution = "Reset password" ;
            $vulnerability_status = "re-opened";
            $vulnerability_policyviolations = "PCI";
            $vulnerability_web_name = "";
            $vulnerability_web_desc = "";
            $vulnerability_web_data = "";
            $vulnerability_web_severity = "";
            $vulnerability_web_refs = "";
            $vulnerability_web_confirmed = "";
            $vulnerability_web_status = "";
            $vulnerability_web_website = "";
            $vulnerability_web_request = "";
            $vulnerability_web_response = "";
            $vulnerability_web_method = "";
            $vulnerability_web_pname = "";
            $vulnerability_web_params = "";
            $vulnerability_web_query = "";
            $vulnerability_web_resolution = "";
            $vulnerability_web_policyviolations = "";
            $vulnerability_web_path = "";
            
            $query = "echo '$host_name,$host_description,$host_owned,$host_os,$interface_name,$interface_description,$interface_hostnames,$interface_mac,$interface_network_segment,$interface_ipv4_address,$interface_ipv4_gateway,$interface_ipv4_mask,$interface_ipv4_dns,$interface_ipv6_address,$interface_ipv6_gateway,$interface_ipv6_prefix,$interface_ipv6_dns,$service_name,$service_description,$service_owned,$service_port,$service_protocol,$service_version,$service_status,$vulnerability_name,$vulnerability_desc,$vulnerability_data,$vulnerability_severity,$vulnerability_refs,$vulnerability_confirmed,$vulnerability_resolution,$vulnerability_status,$vulnerability_policyviolations,$vulnerability_web_name,$vulnerability_web_desc,$vulnerability_web_data,$vulnerability_web_severity,$vulnerability_web_refs,$vulnerability_web_confirmed,$vulnerability_web_status,$vulnerability_web_website,$vulnerability_web_request,$vulnerability_web_response,$vulnerability_web_method,$vulnerability_web_pname,$vulnerability_web_params,$vulnerability_web_query,$vulnerability_web_resolution,$vulnerability_web_policyviolations,$vulnerability_web_path' >> $this->dir_tmp/faraday_ooredoo.csv  ";
            $this->req_ret_str($query);
            $this->pause();
        }
        mysqli_free_result($ip_info);
        mysqli_free_result($port_info);
    }   
        mysqli_free_result($user2auth);

    $this->requette("");
 
}



}

?>