<?php
class XML extends SQLI{
    
    
    
    
    public function __construct($stream,$eth,$domain,$ip,$url,$param,$value,$methode_http) {
        parent::__construct($stream,$eth,$domain,$ip,$url,$param,$value,$methode_http);
        
    }
    
    
    
    public function xml4pentest(){
        $result = "";
        $sql_r_1 = "SELECT param2xml FROM URI WHERE $this->uri2where AND param2xml IS NOT NULL";
        if ($this->checkBD($sql_r_1) ) return  base64_decode($this->req2BD4out("param2xml","URI",$this->uri2where));
        else {
            $result .= $this->titre(__FUNCTION__);
           $result .= $this->xml2xml();
        $result .= $this->xml2ldap();
        

        $result = base64_encode($result);
        return base64_decode($this->req2BD4in("param2xml","URI",$this->uri2where,$result));
        }
    }
    
    
    
    public function xml2xml(){
        $result = "";
        $result .= $this->ssTitre(__FUNCTION__);
        $query = "";
        $result .= $this->cmd("localhost",$query);
        $result .= $this->req_ret_str($query);
        return $result;
    }
    
    
    public function xml2ldap(){
        $result = "";
        $result .= $this->ssTitre(__FUNCTION__);
        $query = "";
        $result .= $this->cmd("localhost",$query);
        $result .= $this->req_ret_str($query);
        return $result;
    }
    
}

?>