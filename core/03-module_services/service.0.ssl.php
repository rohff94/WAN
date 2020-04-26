<?php


class service2ssl extends service2ssh {


    public function __construct($eth,$domain,$ip,$port,$service_protocol) {
        parent::__construct($eth,$domain,$ip,$port,$service_protocol);
    }


    
    function service2ssl4check2poodle(){
        $this->ssTitre(__FUNCTION__);
        $this->service2ssl3();
        $this->service2ssl4check2sslv3();
    }
    
    function service2ssl4check2all(){
        $this->ssTitre(__FUNCTION__);
        $this->net("https://cryptoreport.websecurity.symantec.com/checker/views/certCheck.jsp");
    }
    
    function service2ssl4exec(){
        $result = "";
        $result .= $this->ssTitre(__FUNCTION__);
        $https = "";
        
        
        
        $query = "sslscan $this->ip:$this->port | grep 'Accepted'   ";
        $https .= $this->req_ret_str($query);
        $https .= $this->service2ssl4check2poodle()."\n";
        $https .= $this->service2tls1()."\n";
        //$https .= $this->service2ssl4check2crime()."\n";
        $https .= $this->service2ssl4check2pubkey()."\n";
        $https .= $this->service2ssl4check2sslv2()."\n";
        //$https .= $this->service2ssl4check2sslyze()."\n";
        $https .= $this->service2ssl4chiper2null()."\n";
        $https .= $this->service2ssl4chiper2test()."\n";
        
        //$https .= $this->service2ssl2enum()."\n";
        return $https;
        
    }
    



  }
?>
