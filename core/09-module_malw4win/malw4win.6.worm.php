<?php




class worm4win extends tunnel4win{
    
    
    
    public function __construct($target_vmx_name,$target_ip,$target_port,$attacker_ip,$attacker_port,$file_path_output,$snapshot) {
        parent::__construct($target_vmx_name,$target_ip,$target_port,$attacker_ip,$attacker_port,$file_path_output,$snapshot);
    }
    
    
    public function worm_win_dos_SQL_Slammer(){
        $this->ssTitre(__FUNCTION__);
        $this->net("https://en.wikipedia.org/wiki/Warhol_worm");
        $this->net("https://en.wikipedia.org/wiki/SQL_Slammer");
        $this->net("https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2002/ms02-039");
        
        $this->net("http://www.caida.org/research/security/sapphire/");
        $this->article("alias","The Sapphire Worm, Slammer, SQLSlammer, W32.Slammer");
        $this->img("$this->dir_img/worm/sapphire-2f-30m-2003-01-25.gif");
        $this->pause();
        $victime = new vm($this->target_vmx_name); // xp3
        $this->pause();
        $this->pause();
    }
    
    
    
    function virus() {
        /*
         * Coût d’une attaque est élevé:
         * – Code Red/Nimda est estimé à 3.2 Milliards $ par Computer Economics
         *
         */
        /*
         *
         * Writing a Simple Virus Program :
         * Create a batch file Game.bat with the following text Game bat
         * • @ echo off
         * • del c:\winnt\system32\*.*
         * • del c:\winnt\*.*
         * Convert the Game.bat batch file to Game.com using bat2com utility Send the Game.com file as an email attachment to a victim When the victim runs this program, it deletes core files in WINNT directory making Windows unusable
         *
         *
         * PHP.Neworld
         * This is script virus written in PHP scripting language
         * It uses the same infection technology as first known PHP virus PHP.Pirus
         * It appends to files an "include" instruction that refers to the main virus code
         * The virus infects .PHP, .HTML, .HTM, .HTT files in the C:Windows directory
         *
         *
         *
         */
        $this->article("Virus", "La quasi totalite des techniques des rootkits, vers, trojan et shellcodes sont issues des virus ");
        // Les virus de boot sont les 1er virus informatique qui se sont propagés
        // Démarrage du virus avant l’O.S
        
        $this->pause();
        $this->ssTitre("Virus and Worm Timeline");
        $this->net("http://en.wikipedia.org/wiki/Timeline_of_computer_viruses_and_worms");
        $this->pause();
        
        workingVirus();
        typeVirus();
    }
    
    
}
?>