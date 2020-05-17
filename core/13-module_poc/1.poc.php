<?php

// uname -a && cat /etc/issue




/*
 *
 * $this->net("http://trtpost.wpengine.netdna-cdn.com/files/2014/04/Figure-16-frequency-incident-classification-patterns.jpg");
 * $this->net("www.verizonenterprise.com/DBIR/2014/reports/rp_Verizon-DBIR-2014_en_xg.pdf");
 * http://sebug.net/chart/
 */

class POC extends poc4malware{
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
		$sql = "select uid_name,from_base64(templateB64_id),from_base64(templateB64_shell) FROM LAN ;";
		$query = "mysql --user=$this->mysql_login --password=$this->mysql_passwd --database=$this->mysql_database --execute=\"$sql\"  2>/dev/null \n";
		//$this->requette($query);
		$this->pause();
		}
		
		
		
		public function poc4intro(){
			$this->start("Hacking","");
		$this->chapitre("le monde du hacking");
		$this->def_hacker();$this->pause();
		$this->def_pirate();$this->pause();
		$this->culture_hacker();$this->pause();
		$this->cyber_espionnage();$this->pause();
		$this->victimes();$this->pause();
		$this->attack_country_live();$this->pause();
		$this->malware_challenges_hacking();$this->pause();
		$this->graphic_step_all_hacking();$this->pause();
		$this->hosts();$this->labs_hacking();
		$this->notify("END $module");
		}
		
			// #####################################################
		

			
		
		
		function poc4crypto() {
			
		$this->chapitre("CRYPTOGRAPHY");
		$this->article("Cryptographie", "L'art et la science de garder le secret des messages");
		$cleartext = "j'ai des informations tres confidentielles a vous confier, appelez moi a 19h precise au 012345";
		$this->titre("0x050501 Intro");
		$this->introCrypto($cleartext);
		$this->pause();
		$this->titre("0x050502 Symetrique");
		$this->symetrique($cleartext);
		$this->pause();
		$this->titre("0x050503 Asymetrique");
		$this->asymetrique($cleartext);
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
		
		
		
		
		public function tp4bof2root(){
		    $this->chapitre("BE ROOT");
		    // Covfefe bof2stack OR heap
		    
		    
		}
	
	
	
	
		public function poc4vdo(){
		   $ip = "10.60.10.183"; // Billu_box2 OK exploit/unix/webapp/drupal_drupalgeddon2
		   $ip = "10.60.10.134"; // covfefe
		   $ip = "10.60.10.137"; // DC1 
		   $ip = "10.60.10.0"; // Zico2 
		   $ip = "10.60.10.0"; // WinterMute One
		   $ip = "10.60.10.0"; // WebDeveloper 1 
		   $ip = "10.60.10.0"; // NightMare
		   $ip = "10.60.10.0"; // wakanda 1 
		   $ip = "10.60.10.161"; // W1R3S
		   $ip = "10.60.10.0"; // VulnOS2
		   $ip = "10.60.10.132"; // Vulnix
		   $ip = "10.60.10.0"; // Violator
		   $ip = "10.60.10.147"; // OK typhoon 1.02 
		   $ip = "10.60.10.0"; // library1
		   $ip = "10.60.10.0"; // The Ether EvilScience
		   $ip = "10.60.10.0"; // temple of doom
		   $ip = "10.60.10.0"; // ted1
		}
	

	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
?>

