<?php

class PARAM extends XSS{
    
    
    
    
    
    public function __construct($eth,$domain,$url,$param,$value,$methode_http) {
        parent::__construct($eth,$domain,$url,$param,$value,$methode_http);
        $this->article("Param", $this->param);
        $this->article("Value", $this->value);
    }
    

    
 
    
    public function param4pentest($OS){
        // https://kalilinuxtutorials.com/sawef-send-attack/
        // /Windows/system.in
        $this->gtitre(__FUNCTION__);
        
        $port = $this->port_rfi;
        $open_server = "cd $this->dir_tmp; python -m SimpleHTTPServer $port ";
        //$this->cmd("localhost",$open_server );
        if (!$this->tcp2open($this->ip4addr4target($this->ip), $port)) {$this->rouge($open_server);exit();}
        
        //$result .=  $this->param2hash();
  
        $this->fi4pentest($OS);$this->pause();
        $this->ce4pentest($OS);$this->pause();
        $this->xss4pentest();$this->pause();
        if (!empty($this->value)) $this->sqli4pentest();$this->pause();
       
    }
    
    
}
