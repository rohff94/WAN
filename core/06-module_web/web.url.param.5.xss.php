<?php
class XSS extends XML{
    
    
    
    
    public function __construct($stream,$eth,$domain,$ip,$url,$param,$value,$methode_http) {
        parent::__construct($stream,$eth,$domain,$ip,$url,$param,$value,$methode_http);
        
    }

    public function xss4pentest(){
        // https://kalilinuxtutorials.com/xxrf-shots-ssrf-vulnerability/
        // https://kalilinuxtutorials.com/xsspy-web-application/
        // https://kalilinuxtutorials.com/xss-payload-list/
        
        $result = "";
        
        $sql_r_1 = "SELECT param2xss FROM URI WHERE $this->uri2where AND param2xss IS NOT NULL";
        if ($this->checkBD($sql_r_1) ) return  base64_decode($this->req2BD4out("param2xss","URI",$this->uri2where));
        else {
            $result .= $this->titre(__FUNCTION__);
        $result .= $this->xss2reflected();
        $result .= $this->xss2stored();
        $result .= $this->xss2dom();
        //$result .= $this->xss2xsser();
        //$result .= $this->xss2xsstrike();
        
        
        $result = base64_encode($result);
        //return base64_decode($this->req2BD4in("param2xss","URI",$this->uri2where,$result));
        }
    }
   
    public function xss2xsstrike(){        
        $result = "";
        $result .= $this->ssTitre(__FUNCTION__);
        if (!is_dir("/opt/XSStrike")) $this->install_web2scan4cli4xss();
        $query = "cd /opt/XSStrike; python3 xsstrike.py -u \"$this->url\" 2>&1 ";
        $result .= $this->cmd("localhost",$query);
        $result .= $this->req_ret_str($query);
        return $result;
    }
    
    public function xss2xsser(){
        $result = "";
        $result .= $this->ssTitre(__FUNCTION__);
        $query = "xsser -u \"$this->url\" 2>&1 ";
        $result .= $this->cmd("localhost",$query);
        $result .= $this->req_ret_str($query);
        return $result;
    }
    
    public function xss2stored(){
        $result = "";
        $result .= $this->ssTitre(__FUNCTION__);
        $query = "";
        $result .= $this->cmd("localhost",$query);
        $result .= $this->req_ret_str($query);
        return $result;
    }
    
    public function xss2dom(){
        $result = "";
        $result .= $this->ssTitre(__FUNCTION__);
        $query = "";
        $result .= $this->cmd("localhost",$query);
        $result .= $this->req_ret_str($query);
        return $result;
    }
    
      
    public function xss2reflected(){
        $result = "";
        $result .= $this->ssTitre(__FUNCTION__);

        $hash = trim($this->req_ret_str("echo '$this->user2agent' | sha256sum | sed \"s/ -//g\" | grep -Po \"[0-9a-z]{64}\" "));
        
        $cmds = file("$this->dir_tools/dico/xss.dico");
        foreach ($cmds as $cmd){
            $cmd = addcslashes(trim($cmd), "\"");

        $this->article("FILTER");$this->pause();
        if (!empty($this->param2check($this->user2agent,$cmd,$filter))) {
            
           }
        }
        

        return $result;
    }

/*
 
 */

}
?>
