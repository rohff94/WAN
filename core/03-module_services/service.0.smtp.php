<?php


class service2smtp extends service2smb {


    public function __construct($eth,$domain,$ip,$port,$service_protocol) {
        parent::__construct($eth,$domain,$ip,$port,$service_protocol);
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
            
            
            
            if (!$this->ip4priv($this->ip)){
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
            }
            
            
            //$result .= $this->service2smtp4nmap();

             
            
            $users_passwd = $this->ip2users4passwd();
            foreach ($users_passwd as $user2name => $user2pass){
                if (!empty($user2name)){
                        $result .= $this->port2auth4pass4medusa("smtp", $user2name, $user2pass);
                        $query = "swaks --to $this->user2email --from=$this->user2email --auth --auth-user=$user2name --auth-password=$user2pass --server $this->ip:$this->port --body \"test $this->ip $date\" --header \"Subject: test mail server by $this->user2agent\" -tls ";
                        $result .= $this->cmd("localhost", $query);
                        $result .= $this->req_ret_str($query);                       
           }
            }
            
            $tab_users_shell = $this->ip2users4shell();
            foreach ($tab_users_shell as $user2name_shell){
               $result .= $this->article("USER FOUND FOR TEST", $user2name_shell);
               $result .= $this->port2auth4pass4medusa("smtp", $user2name_shell, "password");                      
            }
            
            $this->pause();
            
   

            
            $query = "hydra -L $this->dico_users $this->ip smtp-enum -e nsr -t 8 -w 5s -s $this->port  2>/dev/null | grep -i  'login:' | cut -d':' -f3 ";
            //$result .= $this->cmd("localhost", $query); $result .= $this->auth2login4hydra($this->req_ret_str($query));
            
            return $result;
        
    }
    
    
    
    
    public function service2smtp2users(){
        $this->ssTitre(__FUNCTION__);
        $query = "perl $this->dir_tools/smtp-user-enum.pl -t $this->ip -p $this->port -M VRFY -U $this->dico_users | grep 'exists'  | sed  \"s/ exists//g\" | cut -d':' -f2 ";
        $users = $this->req_ret_str($query);
        if(!empty(trim($users))) {
            $users_tab = explode("\n", $users);
            foreach ($users_tab as $user2name) if (!empty($user2name)) $this->yesUSERS($this->port2id, $user2name, "smtp-user-enum -M VRFY","");
        }
        
        $query = "perl $this->dir_tools/smtp-user-enum.pl -t $this->ip -p $this->port -M EXPN -U $this->dico_users | grep 'exists'  | sed  \"s/ exists//g\" | cut -d':' -f2 ";
        $users = $this->req_ret_str($query);
        if(!empty(trim($users))) {
            $users_tab = explode("\n", $users);
            foreach ($users_tab as $user2name) $this->yesUSERS($this->port2id, $user2name, "smtp-user-enum -M EXPN","");
        }
        
        $query = "perl $this->dir_tools/smtp-user-enum.pl -t $this->ip -p $this->port -M RCPT -U $this->dico_users | grep 'exists'  | sed  \"s/ exists//g\" | cut -d':' -f2 ";

        $users = $this->req_ret_str($query);
        if(!empty(trim($users))) {
            $users_tab = explode("\n", $users);
            foreach ($users_tab as $user2name) $this->yesUSERS($this->port2id, $user2name, "smtp-user-enum -M RCPT","");
        }
    }
    
    
    
    
    function service2smtp4nmap(){
        $this->ssTitre(__FUNCTION__);
        $query = "echo '$this->root_passwd' | sudo -S nmap  --script \"smtp-commands,smtp-enum-users,smtp-brute,smtp-vuln-*\" --script-args \"smtp-enum-users.methods={EXPN,RCPT,VRFY},smtp-brute.userdb=$this->dico_users,smtp-brute.passdb=$this->dico_password.1000\"  -s$this->protocol -p $this->port -e $this->eth $this->ip -Pn  -oX -  ";
        return $this->auth2login4nmap($this->req_ret_str($query),__FUNCTION__);
    }
    



  }
?>
