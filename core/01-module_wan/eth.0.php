<?php

class ETH extends DATA{
    
    var $eth ;
    var $eth2id ;
    var $eth2where ;

    
    public function __construct($eth) {
        $this->eth = trim($eth);
        $this->eth2where = "eth = '$this->eth'";
        
        parent::__construct();
        
        if(!empty($this->eth)){
            
            $sql_r = "SELECT eth FROM ".__CLASS__." WHERE $this->eth2where ";
            if (!$this->checkBD($sql_r)) {
                $sql_w = "INSERT  INTO ".__CLASS__." (eth) VALUES ('$this->eth'); ";
                $this->mysql_ressource->query($sql_w);
                echo $this->note("Interface $this->eth");
            }

            $sql_r = "SELECT id FROM ".__CLASS__." WHERE $this->eth2where ";
            $this->eth2id = $this->mysql_ressource->query($sql_r)->fetch_assoc()['id'];
            
            
        }
        
    }
    
    
    
    public function cidr2scan($cidr,$eth){
        $this->titre(__FUNCTION__);
        $eth = trim($eth);
        $cidr = trim($cidr);
        if (!empty($cidr)) return $this->cidr2scan4nmap($cidr,$this->eth);
        //$this->cidr2scan4fping($cidr);
    }
    
    public function cidr2scan4nmap($cidr,$eth){
        $this->ssTitre(__FUNCTION__);
        $eth = trim($eth);
        $cidr = trim($cidr);
        $query = " nmap -sn --reason $cidr -e $eth | grep 'Nmap scan report for' | sed \"s/Nmap scan report for//g\"  " ; // | grep -Po \"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\"
        if (!empty($cidr)) return $this->req_ret_str($query);
    }
    
    public function cidr2scan4fping($cidr){
        $this->ssTitre(__FUNCTION__);
        $cidr = trim($cidr);
        $query = " echo '$this->root_passwd' | sudo -S fping -a -n -g $cidr 2> /dev/null | grep -v -E \"(Unreachable|error)\" ";
        if (!empty($cidr)) return $this->req_ret_str($query);
    }
    
    
}

?>
