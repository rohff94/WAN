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
                $sql_r = "SELECT id FROM ".__CLASS__." WHERE $this->eth2where ";
                $this->eth2id = $this->mysql_ressource->query($sql_r)->fetch_assoc()['id'];
                
            }
            else {
                $sql_r = "SELECT id FROM ".__CLASS__." WHERE $this->eth2where ";
                $this->eth2id = $this->mysql_ressource->query($sql_r)->fetch_assoc()['id'];
                
            }
            
            
        }
        
    }
    
    
    
    
}

?>
