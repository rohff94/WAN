<?php

class CIDR extends ETH{
    
    var $cidr ;
    var $cidr2id ;
    var $cidr2where ;
    
    
    public function __construct($cidr,$eth) {
        $cidr = trim($cidr);
        $eth = trim($eth);
        $this->cidr = "$cidr.0/24";
        $this->cidr2where = "cidr = '$this->cidr'";
        
        
        parent::__construct($eth);
        
        if(!empty($this->cidr)){
            
            $sql_r = "SELECT cidr FROM ".__CLASS__." WHERE $this->cidr2where ";
            if (!$this->checkBD($sql_r)) {
                $sql_w = "INSERT  INTO ".__CLASS__." (cidr) VALUES ('$this->cidr'); ";
                $this->mysql_ressource->query($sql_w);
                echo $this->note("Working on CIDR $this->cidr for the first time");
            }
            
            $sql_r = "SELECT id FROM ".__CLASS__." WHERE $this->cidr2where ";
            $query = "mysql --user=$this->mysql_login --password=$this->mysql_passwd --database=$this->mysql_database --execute=\"$sql_r\"  2>/dev/null \n";
            //$this->requette($query);
            $this->cidr2id = $this->mysql_ressource->query($sql_r)->fetch_assoc()['id'];
            
            
        }
        
    }
    
    
    
    
    public function cidr2ns(){
        $this->titre("Searching Hostname with resolution DNS on $this->cidr");
        $result = "";
        
        $sql_r_1 = "SELECT ".__FUNCTION__." FROM ".__CLASS__." WHERE $this->cidr2where AND ".__FUNCTION__." IS NOT NULL";
        if ($this->checkBD($sql_r_1) ) {
            $cidr2ns =  base64_decode($this->req2BD4out(__FUNCTION__,__CLASS__,$this->cidr2where));
            echo $cidr2ns;
            return $cidr2ns;
        }
        else {
            $result = $this->cidr2scan4nmap($this->cidr,$this->eth);
            
            $result = base64_encode($result);
            return base64_decode($this->req2BD4in(__FUNCTION__,__CLASS__,$this->cidr2where,$result));
        }
    }
    
    
    
    public function cidr2live(){
        $this->titre(__FUNCTION__);
        $result = "";
        $sql_r_1 = "SELECT ".__FUNCTION__." FROM ".__CLASS__." WHERE $this->cidr2where AND ".__FUNCTION__." IS NOT NULL";
        if ($this->checkBD($sql_r_1) ) return  base64_decode($this->req2BD4out(__FUNCTION__,__CLASS__,$this->cidr2where));
        else {
            $result .= $this->cidr2ns();
            $result .= $this->cidr2scan4fping($this->cidr);
            
            $result = base64_encode($result);
            return base64_decode($this->req2BD4in(__FUNCTION__,__CLASS__,$this->cidr2where,$result));
        }
    }
    
    
    public function cidr2owner(){
        $this->titre(__FUNCTION__);
        $result = "";
        $sql_r_1 = "SELECT ".__FUNCTION__." FROM ".__CLASS__." WHERE $this->cidr2where AND ".__FUNCTION__." IS NOT NULL";
        if ($this->checkBD($sql_r_1) ) return  base64_decode($this->req2BD4out(__FUNCTION__,__CLASS__,$this->cidr2where));
        else {
            // 
            
            $result = base64_encode($result);
            return base64_decode($this->req2BD4in(__FUNCTION__,__CLASS__,$this->cidr2where,$result));
        }
    }
    
    
    public function cidr2range(){
        $this->titre(__FUNCTION__);
        $result = "";
        $sql_r_1 = "SELECT ".__FUNCTION__." FROM ".__CLASS__." WHERE $this->cidr2where AND ".__FUNCTION__." IS NOT NULL";
        if ($this->checkBD($sql_r_1) ) return  base64_decode($this->req2BD4out(__FUNCTION__,__CLASS__,$this->cidr2where));
        else {
            //
            
            $result = base64_encode($result);
            return base64_decode($this->req2BD4in(__FUNCTION__,__CLASS__,$this->cidr2where,$result));
        }
    }
    
    
    
    
}

?>