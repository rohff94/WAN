<?php

// uname -a && cat /etc/issue




/*
 *
 * $this->net("http://trtpost.wpengine.netdna-cdn.com/files/2014/04/Figure-16-frequency-incident-classification-patterns.jpg");
 * $this->net("www.verizonenterprise.com/DBIR/2014/reports/rp_Verizon-DBIR-2014_en_xg.pdf");
 * http://sebug.net/chart/
 */

class POC extends poc4web{
    var $msf2;
    var $owasp;
    var $xvwa;
    var $dvl;
    var $xp;
    var $fw;
    var $dsl;
    var $voip;
    var $prof;
    var $k2 ;
    
	
		public function __construct() {
		parent::__construct();
		$this->prof = "10.60.10.1";
		$this->owasp = "10.60.10.129";
		$this->msf2 = "10.60.10.130";
		$this->k2 = "10.60.10.131"; // k2  boot2root - root8users 

		
		$sql = "update IP set ip2backdoor=0 where ip2backdoor=1 ;" ;
		$query = "mysql --user=$this->mysql_login --password=$this->mysql_passwd --database=$this->mysql_database --execute=\"$sql\"  2>/dev/null \n";
		$this->requette($query);
		$sql = "update IP set ip2root=0 where ip2root=1 ;";
		$query = "mysql --user=$this->mysql_login --password=$this->mysql_passwd --database=$this->mysql_database --execute=\"$sql\"  2>/dev/null \n";
		$this->requette($query);
		$this->pause();
		$sql = "select uid_name,from_base64(templateB64_id),from_base64(templateB64_cmd),from_base64(templateB64_shell) FROM LAN ;";
		$query = "mysql --user=$this->mysql_login --password=$this->mysql_passwd --database=$this->mysql_database --execute=\"$sql\"  2>/dev/null \n";
		//$this->requette($query);
		$this->pause();
		}
		
		
		
		public function poc4intro(){
			$this->start("Hacking","");
		$this->chapitre("le monde du hacking");
		intro::def_hacker();$this->pause();
		intro::def_pirate();$this->pause();
		intro::culture_hacker();$this->pause();
		intro::cyber_espionnage();$this->pause();
		intro::victimes();$this->pause();
		intro::attack_country_live();$this->pause();
		intro::malware_challenges_hacking();$this->pause();
		intro::graphic_step_all_hacking();$this->pause();
		intro::hosts();intro::labs_hacking();
		$this->notify("END $module");
		}
		
			// #####################################################
		

			
		
		
		function poc4crypto() {
			
		$this->chapitre("CRYPTOGRAPHY");
		$this->article("Cryptographie", "L'art et la science de garder le secret des messages");
		$cleartext = "j'ai des informations tres confidentielles a vous confier, appelez moi a 19h precise au 012345";
		$this->titre("0x050501 Intro");
		intro::introCrypto($cleartext);
		$this->pause();
		$this->titre("0x050502 Symetrique");
		intro::symetrique($cleartext);
		$this->pause();
		$this->titre("0x050503 Asymetrique");
		intro::asymetrique($cleartext);
		$this->pause();
		$this->titre("0x050504 Hashage");
		hashage($cleartext);
		$this->pause();
		$this->titre("0x050505 Hybride");
		hybride($cleartext);
		$this->pause();
		ssh ();
		$this->titre("0x050506 Certificat");
		certificat ();
		$this->pause();
		// titre("0x050507 Stegnographie");stegnographie();pause();
		$this->notify("END CRYPTOGRAPHY");
		// tunnel_tcp2tcp4ssh();

		}


		// ===================================================================================
		
		// #################################### SHELLCODE #######################################################
		
		
		
		

	
	
	
	
	
	
	
	
	
	public function vuln2scan(){
	    $this->vuln2scan4gui4nessus();
	    $this->vuln2scan4gui4nexpose();
	    $this->vuln2scan4gui4openvas();
	}
	
	
	public function vuln2scan4gui4nessus(){
	    $this->ssTitre(__FUNCTION__);
	    $file_output = "$this->rep_path/$this->ip.$this->vhost.$this->port.".__FUNCTION__;
	    $this->article("login/password","rohff/rohff");
	    $this->ssTitre("Mise a jours de Nessus");
	    $this->cmd("localhost","echo '$this->root_passwd' | sudo -S /opt/nessus/sbin/nessuscli update");pause();
	    $this->ssTitre("Start Nessus");
	    $this->cmd("localhost","echo '$this->root_passwd' | sudo -S /etc/init.d/nessusd start");pause();
	    $this->net("https://localhost:8834/nessus6.html");pause();
	}
	
	
	public function vuln2scan4gui4nexpose(){
	    $this->ssTitre(__FUNCTION__);
	    $this->cmd("localhost","cd /opt/rapid7/nexpose/nsc; sudo ./nsc.sh");
	    $this->article("login/password","rohff/rafik3615#");
	    $this->net("http://localhost:3780/manager/html");
	    $this->pause();
	}
	
	
	public function vuln2scan4gui4openvas(){
	    $this->ssTitre(__FUNCTION__);
	    $this->cmd("localhost","echo '$this->root_passwd' | sudo -S service openvas-server start");
	    $this->requette("echo -e \"Waiting 120s\" ");
	    sleep(60);
	    $this->requette("echo '$this->root_passwd' | sudo -S netstat -anp | grep LISTEN | grep -i 'openvas'");
	    $this->requette("echo -e \"Connect to openvas-server via openvas-client\" ");
	    $this->cmd("localhost","openvas-client");
	    $this->pause();
	}
	
	

	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
?>

