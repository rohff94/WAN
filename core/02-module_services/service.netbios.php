<?php


class service2netbios extends SERVICE {


    public function __construct($eth,$domain,$ip,$port,$service_protocol,$service_name,$service_version,$service_product,$service_extrainfo,$service_hostname,$service_conf) {
        parent::__construct($eth,$domain,$ip,$port,$service_protocol,$service_name,$service_version,$service_product,$service_extrainfo,$service_hostname,$service_conf);
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

  }
?>
