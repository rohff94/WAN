<?php


class service2snmp extends service2smtp {


    public function __construct($eth,$domain,$ip,$port,$service_protocol,$stream) {
        parent::__construct($eth,$domain,$ip,$port,$service_protocol,$stream);
    }
/*
 auxiliary/scanner/snmp/snmp_enum                                                          normal  Yes    SNMP Enumeration Module
   auxiliary/scanner/snmp/snmp_enum_hp_laserjet                                              normal  Yes    HP LaserJet Printer SNMP Enumeration
   auxiliary/scanner/snmp/snmp_enumshares                                                    normal  Yes    SNMP Windows SMB Share Enumeration
   auxiliary/scanner/snmp/snmp_enumusers                                                     normal  Yes    SNMP Windows Username Enumeration
   auxiliary/scanner/snmp/snmp_login                                                         normal  Yes    SNMP Community Login Scanner
   
 */

public function service2snmp4exec(){
    $result = "";

        $result .= $this->ssTitre(__FUNCTION__);
        $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"snmp-*\" $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
        $result .= $this->cmd("localhost",$query); $result .= $this->auth2login4nmap($this->req_ret_str($query),__FUNCTION__);
        
        $query_hydra = "hydra -P \"$this->dico_users\" $this->ip snmp -f -t 12 -e nsr -s $this->port -w 5s 2>/dev/null  | grep $this->ip  | grep 'password:'   ";
        $result .= $this->cmd("localhost",$query_hydra);  $result .= $this->auth2login4hydra($this->req_ret_str($query_hydra));
        
        
        return $result;
}



  }
?>
