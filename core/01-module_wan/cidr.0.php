<?php

class CIDR extends DATA{
    
    var $cidr ;
    var $cidr2id ;
    var $cidr2where ;
    
    
    public function __construct($cidr) {
        $cidr = trim($cidr);
        $this->cidr = "$cidr.0/24";
        $this->cidr2where = "cidr = '$this->cidr'";
        
        
        parent::__construct();
        
        if(!empty($this->cidr)){
            
            $sql_r = "SELECT cidr FROM ".__CLASS__." WHERE $this->cidr2where ";
            if (!$this->checkBD($sql_r)) {
                $sql_w = "INSERT  INTO ".__CLASS__." (cidr) VALUES ('$this->cidr'); ";
                $this->mysql_ressource->query($sql_w);
                echo $this->note("Working on CIDR $this->cidr for the first time");
            }
            
            $sql_r = "SELECT id FROM ".__CLASS__." WHERE $this->cidr2where ";
            $this->cidr2id = $this->mysql_ressource->query($sql_r)->fetch_assoc()['id'];
            
            
        }
        
    }
    
    
    public function cidr2ns(){
        $this->ssTitre("Searching Hostname with resolution DNS");
        $result = "";
        
        $sql_r_1 = "SELECT ".__FUNCTION__." FROM ".__CLASS__." WHERE $this->cidr2where AND ".__FUNCTION__." IS NOT NULL";
        if ($this->checkBD($sql_r_1) ) return  base64_decode($this->req2BD4out(__FUNCTION__,__CLASS__,$this->cidr2where));
        else {
            $result = $this->cidr2scan4nmap($this->cidr);
            
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