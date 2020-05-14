<?php

class PARAM extends XSS{
    
    
    
    
    
    public function __construct($stream,$url,$param,$value,$methode_http) {
        parent::__construct($stream,$url,$param,$value,$methode_http);
        $this->article("Param", $this->param);
        $this->article("Value", $this->value);
    }
    

    
 
    
    public function param4pentest($OS){
        // https://kalilinuxtutorials.com/sawef-send-attack/
        // /Windows/system.in
        $this->gtitre(__FUNCTION__);
        $attacker_ip = $this->ip4addr4target($this->ip);
        $this->tcp2open4server($attacker_ip, $this->port_rfi);
        //$result .=  $this->param2hash();
  
        $this->fi4pentest($OS);$this->pause();
        $this->ce4pentest($OS);$this->pause();
        $this->xss4pentest();$this->pause();
        //if (!empty($this->value)) $this->sqli4pentest();$this->pause();
       
    }
    
    
}
