<?php
/*
 * The crontab file stores information about programs that are supposed to run at specific times. The RootKit Trojan horse version of crontab allows an
 attacker to scheduel specific programs to run without the system administrator being able to see that those programs are scheduled.

 *The most reliable method of detecting a rootkit that has been installed on a system is to install a file integrity checker program like Tripwire or AIDE
 before a system is put on the network, and create a database of signatures to be stored off-line in read-only format. Then run the integrity checker periodically to
 create the signature of the files and compare them against the off-line database of signatures to determine if a file was changed.
 */

class for4linux extends bin4linux{
    var $profile_vmem;
    
    public function __construct($vmem,$profile_vmem) {
        parent::__construct($vmem);
        $this->profile_vmem = trim($profile_vmem);
	}

	public function for4linux_Malware_diff($vmem_clean){
		$vmem_clean = trim($vmem_clean);
		$this->requette("python linux_mem_diff.py -c $vmem_clean -i $this->file_path -p $this->profile | tee $this->file_path.diff ");
		
	}
	/*
	 *
	 *
	 * refaire les PIDs comme Windows
	 *
	 *
	 * linux_lsmod -S
	 * linux_tmpfs -S 1 -D OUTPUT
	 *
	 *
	 * The below doesn't work:
	 * "
	 * export HISTFILESIZE=0
	 * export HISTSIZE=0
	 * unset HISTFILE
	 * "
	 *
	 * So, the security baseline for history_bash shoud be like:
	 * #Prevent unset of histfile, /etc/profile
	 * export HISTSIZE=1500
	 * readonly HISTFILE
	 * readonly HISTFILESIZE
	 * readonly HISTSIZE
	 *
	 * #Set .bash_history as attr +a(append only)
	 * find / -maxdepth 3|grep -i bash_history|while read line; do chattr +a
	 * "$line"; done
	 *
	 *
	 *
	 * automating generate profiles:
	 * https://github.com/halpomeranz/lmg
	 *
	 *
	 *
	 *
	 * Getting some information of kernel data structures:
	 * cd volatility-read-only/tools/linux
	 * make
	 *
	 * Creating our profile:
	 * cd volatility-read-only
	 * sudo zip volatility/plugins/overlays/linux/mint15.zip tools/linux/module.dwarf /boot/System.map-3.2.0-51-generic
	 *
	 * Locate the addr of history_list:
	 * shawn@fortress8609 /volatility-read-only $ gdb /bin/bash
	 * (gdb) disassemble history_list
	 * Dump of assembler code for function history_list:
	 * 0x00000000004a53f0 <+0>: mov 0x2490c9(%rip),%rax # 0x6ee4c0
	 * 0x00000000004a53f7 <+7>: retq
	 * End of assembler dump.
	 *
	 * Analyzing the coredump:
	 * python vol.py -f ../lime-forensics-read-only/mint15.lim --profile=Linuxmint15x64 plugin_name for4linux_bash -H 0x6ee4c0
	 * .................................
	 * 4478 bash 2013-09-06 14:04:17 UTC+0000 ssh root@192.168.0.137
	 * 4478 bash 2013-09-06 14:04:17 UTC+0000 su
	 * 4478 bash 2013-09-06 14:04:17 UTC+0000 cat > log
	 * 4478 bash 2013-09-06 14:04:17 UTC+0000 vim log
	 * 4478 bash 2013-09-06 14:04:17 UTC+0000 shawn@192.168.0.19
	 * 4478 bash 2013-09-06 14:04:17 UTC+0000 cd /info_security/repos/
	 * 4478 bash 2013-09-06 14:04:17 UTC+0000 ls
	 * 4478 bash 2013-09-06 14:04:17 UTC+0000 cd SUSE/upstream/
	 * 4478 bash 2013-09-06 14:04:17 UTC+0000 ls
	 * 4478 bash 2013-09-06 14:04:17 UTC+0000 cd gnutls/
	 * .................................
	 *
	 * -------------------------------------------------------------------------------------
	 *
	 */

	public function for4linux_all($filter){
		$this->for4linux_Information($filter);
		$this->for4linux_Networking($filter);
		$this->for4linux_Process($filter);
		$this->for4linux_Malware($filter);
		$this->notify("END Forensics ALL Linux");
	}
	public function for4linux_Process($filter) {
	$this->chapitre("Process");
	$this->for4linux_Process_dynamic_env($filter); // $this->pause();
	$this->for4linux_Process_file_open_lsof($filter); // $this->pause();
	$this->for4linux_Process_find_elf_binary($filter); // $this->pause();
	$this->for4linux_Process_getcwd($filter); // $this->pause();
	$this->for4linux_Process_hollow($filter); // $this->pause();
	$this->for4linux_Process_maps($filter); // $this->pause();
	$this->for4linux_Process_memory_map($filter); // $this->pause();
	$this->for4linux_Process_pidhashtable($filter); // $this->pause();
	$this->for4linux_Process_procdump($filter); // $this->pause();
	$this->for4linux_Process_psaux_prog_argv($filter); // $this->pause();
	$this->for4linux_Process_psenv($filter); // $this->pause();
	$this->for4linux_Process_pslist($filter); // $this->pause();
	$this->for4linux_Process_pslist_kmem_cache($filter); // $this->pause();
	$this->for4linux_Process_pstree($filter); // $this->pause();
	$this->for4linux_Process_psxview($filter); // $this->pause();
	$this->for4linux_Process_stack($filter); // $this->pause();
	//$this->for4linux_Process_strings($pid_param, $filter); // $this->pause();
	$this->for4linux_Process_structure($filter); // $this->pause();
	$this->for4linux_Process_structure_rb($filter); // $this->pause();
	$this->for4linux_Process_syscall($filter); // $this->pause();
	$this->for4linux_Process_vma_cache($filter); // $this->pause();
	//$this->for4linux_Process_graphic($filter); // $this->pause();
	
	}

	public function for4linux_Process_strings($pid_param, $filter) {
	$cmd = "linux_strings";
	$this->vol2exec4txt("$cmd --pid=$pid_param", $filter);
	}
	public function for4linux_Process_syscall($filter) {
	$cmd = "linux_Process_syscall";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Process_stack($filter) {
	$cmd = "linux_Process_stack";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Process_psenv($filter) {
	$cmd = "linux_psenv";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Process_hollow($filter) {
	$cmd = "linux_Process_hollow";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Process_procdump($filter) {
	$cmd = "linux_procdump";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Information_file_enum($filter) {
	$cmd = "linux_enumerate_files";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Process_find_elf_binary($filter) {
	$cmd = "linux_elfs";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Process_getcwd($filter) {
	$cmd = "linux_getcwd";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Process_pslist($filter) {
	$cmd = "linux_pslist";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Process_pstree($filter) {
	$this->ssTitre("prints a parent/child relationship tree");
	$cmd = "linux_pstree";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Process_structure($filter) {
	$cmd = "linux_proc_maps";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Process_structure_rb($filter) {
	$cmd = "linux_proc_maps_rb";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Process_psaux_prog_argv($filter) {
	$this->ssTitre("show the command-line arguments");
	$cmd = "linux_psaux";
	return $this->vol2exec($cmd,$this->profile_vmem, "| grep  \"0               0\" $filter");
	}
	public function for4linux_Process_pslist_kmem_cache($filter) {
	$cmd = "linux_pslist_cache";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Process_pidhashtable($filter) {
	$cmd = "linux_pidhashtable";
	return $this->vol2exec($cmd,$this->profile_vmem,"| grep  \"0               0\" $filter");
	}
	public function for4linux_Process_psxview($filter) {
	$cmd = "linux_psxview";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Process_file_open_lsof($filter) {
	$cmd = "linux_lsof";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Process_dynamic_env($filter) {
	$cmd = "linux_dynamic_env";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Process_memory_map($filter) {
	$this->ssTitre("The virtual and physical addresses are shown.");
	$cmd = "linux_memmap";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Process_maps($filter) {
	$this->ssTitre("prints details of process memory, including heaps, stacks, and shared libraries");
	$this->note("You can then specify that base address as the -s/--vma option to for4linux_dump_map to acquire the data in that memory segment.
	Use it with the -O/--output-file parameter to save to disk. ");
	$cmd = "linux_proc_maps";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Dump_process_map($pid, $filter) {
	$this->todo("filter: -s addr -> hexdump -C file");
	$cmd = "linux_dump_map";
	$query = "python /opt/volatility/vol.py --location=file://$this->file_path --profile=$this->profile $cmd --pid=$pid --dump-dir=$this->file_dir/ $filter";
	$this->requette($query);
	}
	
	public function for4linux_Dump_process_heap($pid, $filter) {
	$this->ssTitre("Dump HEAP zone for PID=$pid");
	$this->todo("filter: -s addr -> hexdump -C file");
	$tmp = $this->for4linux_Process_maps("--pid=$pid | grep heap | cut -d'x' -f2 | cut -d' ' -f1 | grep -Po \"[0-9a-fA-F]{4,16}\" ");
	$addr_heap = $tmp [0];
	unset($tmp);
	$addr_heap = "0x$addr_heap";
	$tmp = $this->for4linux_Dump_process_map($pid, "-s $addr_heap | grep -Po \"task\.[0-9]{1,6}\.0x[0-9a-fA-F]{4,16}\.vma$\" ");
	$heap_file = $tmp [0];
	unset($tmp);
	$this->requette("strings $this->file_dir/$heap_file $filter ");
	return $heap_file;
	}
	public function for4linux_Dump_process_stack($pid, $filter) {
	$this->todo("filter: -s addr -> hexdump -C file");
	$this->ssTitre("Dump STACK zone for PID=$pid");
	$tmp = $this->for4linux_Process_maps("--pid=$pid | grep stack | cut -d'x' -f2 | cut -d' ' -f1 | grep -Po \"[0-9a-fA-F]{4,16}\" ");
	$addr_stack = $tmp [0];
	unset($tmp);
	$addr_stack = "0x$addr_stack";
	$tmp = $this->for4linux_Dump_process_map($pid, "-s $addr_stack | grep -Po \"task\.[0-9]{1,6}\.0x[0-9a-fA-F]{4,16}\.vma$\" ");
	$stack_file = $tmp [0];
	unset($tmp);
	$this->requette("strings $this->file_dir/$stack_file $filter ");
	return $stack_file;
	}
	public function for4linux_Information_bash_history($filter) {
	$this->article(".bash_history", " is a file on disk that stores all the commands run by a user directly on the bash command line.
	This file is a forensics goldmine when populated as the investigator can recreate everything done by a logged in user.
	Due to its importance to forensics, any reasonable attacker is going to make every effort to avoid having commands logged to this file.
	Common methods to accomplish this include:
	
    	Logging in with ssh –T, which does not allocate a pseudo terminal and therefore does not spawn bash
    	Setting HISTFILE to /dev/null or unsetting it from the process environment, which effectively stops logging
    	Setting HISTSIZE to 0 which prevents any logging
	
The exclusion of these commands to disk makes traditional disk forensics much more difficult and means we have to rely on in-memory information.");
	$cmd = "linux_bash";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Information_kernel_loaded_modules($filter) {
	$this->ssTitre("Listing Modules");
	$cmd = "linux_lsmod";
	$this->article("lsmod", " uses the /proc/modules output as its source of information about loaded modules");
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Information_kernel_filesystems_recovers($filter) {
	$cmd = "linux_tmpfs";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Dump_Module_Kernel($inode, $filter) {
	$cmd = "linux_moddump";
	$this->note("tester a la main avec -i en cas ou -b ne donne rien ");
	return $this->vol2exec("$cmd -b $inode --dump-dir=$this->file_dir/",$this->profile_vmem, $filter);
	}
	public function for4linux_Networking($filter) {
	$this->chapitre("Networking");
	$this->for4linux_Networking_arp_table($filter); // $this->pause();
	$this->for4linux_Networking_connexion_netstat($filter); // $this->pause();
	$this->for4linux_Networking_ifconfig($filter); // $this->pause();
	$this->for4linux_Networking_list_app($filter); // $this->pause();
	$this->for4linux_Networking_packet($filter); // $this->pause();
	$this->for4linux_Networking_packet_pkt($filter); // $this->pause();
	$this->for4linux_Networking_route($filter); // $this->pause();
	}
	public function for4linux_Networking_pid($pid, $filter) {
	$pid_egrep = str_replace(" ", "|", $pid);
	$pid_param = str_replace(" ", ",", $pid);
	$this->for4linux_Networking(" | egrep \"($pid_egrep)\" $filter");
	}
	public function for4linux_Networking_arp_table($filter) {
	$cmd = "linux_arp";
	$this->note("ARP cache, to find if none of these MAC addr are valid");
	//$this->net("https://www.wireshark.org/tools/oui-lookup.html");
	//$this->net("http://www.macvendorlookup.com/");
	$this->todo("ADD script MAC into my databases ");
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Networking_ifconfig($filter) {
	$cmd = "linux_ifconfig";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Networking_connexion_netstat($filter) {
	$this->titre("Search hidden Connection");
	//$this->net("https://github.com/mfontanini/Programs-Scripts/blob/master/rootkit/rootkit.c#L550"); // $this->pause();
	$this->article("Hiding connection", "hooking fopen and fopen64 and monitoring for reads of the tcp file.
	If the file is read, then malware opens a temporary file, reads the actual file in itself, and filters out connections on the hidden ports.
	All non-filtered connections are written to the temporary file and the calling application is returned a handle to the temporary file instead of the real /proc/net/tcp.");
	$cmd = "linux_netstat";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Networking_route($filter) {
	$cmd = "linux_route_cache -R";
	$this->note("route cache and DNS");
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Networking_packet_pkt($filter) {
	$cmd = "linux_pkt_queues";
	$this->note("retrieve inet_socket of each sd");
	$this->vol2exec("$cmd --dump-dir=$this->file_dir/",$this->profile_vmem, $filter);
	//$this->remarque("check: python vol.py --profile=LinuxDebianx86 -f network.lime for4linux_pkt_queues -D recovered_packets");
	}
	public function for4linux_Networking_packet($filter) {
	$cmd = "linux_sk_buff_cache";
	
	$this->vol2exec("$cmd --dump-dir=$this->file_dir/",$this->profile_vmem, $filter);
	//$this->requette("strings $this->file_dir/");
	}
	public function for4linux_Malware($filter) {
	$this->chapitre("Malware");
	
	$this->for4linux_Malware_check_afinfo($filter); // $this->pause();
	$this->for4linux_Malware_check_evt_arm($filter); // $this->pause();
	$this->for4linux_Malware_check_file_operation_structures($filter); // $this->pause();
	$this->for4linux_Malware_check_hidden_modules_and_dump($filter); // $this->pause();
	$this->for4linux_Malware_check_hidden_file($filter); // $this->pause();
	$this->for4linux_Malware_check_hidden_privilege_escalator($filter); // $this->pause();
	$this->for4linux_Malware_check_hidden_process($filter); // $this->pause();
	$this->for4linux_Malware_check_hidden_process_and_module($filter); // $this->pause();
	$this->for4linux_Malware_check_hidden_user($filter); // $this->pause();
	$this->for4linux_Malware_erase_track($filter);
	$this->for4linux_Malware_check_idt($filter); // $this->pause();
	$this->for4linux_Malware_check_inline_kernel($filter); // $this->pause();
	$this->for4linux_Malware_check_kernel_rootkit($filter); // $this->pause();
	$this->for4linux_Malware_check_keylogger($filter); // $this->pause();
	$this->for4linux_Malware_check_modules($filter); // $this->pause();
	$this->for4linux_Malware_check_syscall($filter); // $this->pause();
	// for4linux_Malware_check_syscall_arm($this->file_dir,$vmem, $profile, $filter);//$this->pause();
	$this->for4linux_Malware_check_tty($filter); // $this->pause();
	$this->for4linux_Malware_check_userland_rootkit($filter); // $this->pause();
	$this->for4linux_Malware_hidden_modules($filter); // $this->pause();
	$this->for4linux_Malware_kernel_stack($filter); // $this->pause();
	$this->for4linux_Malware_ldpreload($filter); // $this->pause();
	$this->for4linux_Malware_linux_hollow_process($filter); // $this->pause();
	$this->for4linux_Malware_malfind($filter); // $this->pause();
	$this->for4linux_Malware_netfilter($filter); // $this->pause();
	$this->for4linux_Malware_plthook($filter); // $this->pause();
	$this->for4linux_Malware_processes_sharing_credential_structures($filter); // $this->pause();
	$this->for4linux_Malware_scan_yarascan($this->yara_file, $filter); // $this->pause();
	$this->for4linux_Malware_threads($filter); // $this->pause();
	$this->for4linux_Malware_tmpfs($filter); // $this->pause(); // trop long
	$this->for4linux_Malware_apihooks($filter); // $this->pause(); // trop long
	}
	public function for4linux_Malware_check_hidden_file($filter) {
	$this->chapitre("Check hidden temp file");
	
	$file = $this->for4linux_Malware_tmpfs($filter);
	$reps = $this->req_ret_tab("cat $file | grep -Po \"/[[:print:]]{1,}\" | wc -l ");
	for($i = 1; $i <= $reps [0]; $i ++)
	    $this->vol2exec("linux_tmpfs -S $i --dump-dir=$this->file_dir/",$this->profile_vmem, $filter);
	$this->requette("ls -LR $this->file_dir/");
	$this->for4linux_Information_dentry_cache($filter);
	}
	public function for4linux_Malware_check_userland_rootkit($filter) {
	$this->chapitre("Check USERLAND ROOTKIT");
	$this->for4linux_Malware_malfind($filter);
	$this->for4linux_Malware_linux_hollow_process($filter);
	$this->for4linux_Malware_linux_Process_hollow($filter);
	$this->for4linux_Malware_linux_ldrmodules($filter);
	$this->for4linux_Malware_ldpreload($filter);
	$this->for4linux_Malware_plthook($filter);
	$this->for4linux_Malware_apihooks($filter);
	}
	public function for4linux_Malware_check_kernel_rootkit($filter) {
	$this->chapitre("Check KERNEL LAND ROOTKIT");
	$this->note("How to detect a rootkit hide only from modules list not from sysfs?");
	$this->for4linux_Malware_check_modules($filter);
	$this->for4linux_Malware_check_hidden_modules_and_dump($filter);
	$this->for4linux_Malware_check_tty($filter);
	$this->for4linux_Information_kernel_opened_files($filter);
	$this->for4linux_Malware_check_hidden_privilege_escalator($filter);
	$this->for4linux_Malware_check_hidden_process_and_module($filter);
	$this->for4linux_Malware_check_syscall($filter);
	$this->for4linux_Malware_check_inline_kernel($filter);
	$this->for4linux_Information_library_list($filter); // $this->pause();
	$this->for4linux_Information_kernel_loaded_modules($filter); // $this->pause();
	$this->for4linux_Malware_check_afinfo($filter);
	$this->for4linux_Malware_netfilter($filter);
	}
	public function for4linux_Malware_linux_hollow_process($filter) {
	$cmd = "linux_hollow_process";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Malware_linux_ldrmodules($filter) {
	$cmd = "linux_ldrmodules";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Malware_linux_Process_hollow($filter) {
	$cmd = "linux_Process_hollow";
	$this->todo("linux_Process_hollow -p pid -b map_addr -P real_binary_path => find hollowing action");
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Malware_pid($pid, $filter) {
	$pid_egrep = str_replace(" ", "|", $pid);
	$pid_param = str_replace(" ", ",", $pid);
	
	$this->for4linux_Malware("| egrep \"($pid_egrep)\" $filter");
	$this->for4linux_Malware_apihooks("--pid=$pid_param $filter"); // $this->pause(); // trop long
	$this->for4linux_Malware_plthook("--pid=$pid_param $filter"); // $this->pause(); // FOR ELF FILE
	}
	public function for4linux_Malware_check_hidden_user($filter) {
	$this->chapitre("Check hidden User");
	
	$this->article("Hide User", "To hide users, Rootkit hooks the readmember of /var/run/utmp in the kerne lin order to hide logged in users from applications such as w and who.
	This effectively hides logged in users from network administrators and incident response members working from userland on a live computer.
	Rootkit does this by calling the kernel’s path_lookup function on /var/run/utmp in order to find the inode structure of the file.
	The path_lookup function works by enumerating the filesystem’s directory structure and then locating the file of interest.
	Average Coder wants the inode structure because its i_fop member is a pointer to the particular file’s file_operations structure.
	Once the i_fop member is found, it can simply be overwritten with the rootkit’s function that filters users from utmp on demand.");
	
	$this->article("How to detect this", "To detect this part of the rootkit, we need to verify that the file operations function pointers for /var/run/utmp are valid.
	Valid in this case means that the function pointers point to a function inside the base kernel or within a known kernel module.
	If the function pointers are invalid, we report them so they can be investigated.");
	
	$utmp_name = "utmp";
	$this->ssTitre("Searching $utmp_name Path");
	$tmp = $this->for4linux_Information_file_enum(" | grep -Po \"/[[:print:]]{1,}/$utmp_name$\" ");
	$utmp_path = $tmp [0];
	unset($tmp);
	
	$file_name_utmp = trim(str_replace("/", "_", $utmp_path));
	$file_utmp = $this->for4linux_Dump_file($utmp_path, "");
	$this->requette("who $file_utmp | tee $this->file_dir/$this->file_name.utmp.strings ");
	
	$file = "/var/log/wtmp";
	$file_name_wtmp = trim(str_replace("/", "_", $file));
	$file_wtmp = $this->for4linux_Dump_file($file, "");
	$this->requette("who $file_wtmp | tee $this->file_dir/$this->file_name.wtmp.strings ");
	$this->requette("paste $this->file_dir/$this->file_name.wtmp.strings $this->file_dir/$this->file_name.utmp.strings");
	$this->requette("diff $this->file_dir/$this->file_name.utmp.strings $this->file_dir/$this->file_name.wtmp.strings");
	$this->note("we know now which user was logged in, how they were logged in (tty1, pts/0), and the time they logged in.");
	}
	public function for4linux_Malware_check_hidden_process_and_module($filter) {
	$this->todo("Hidden process detection?
   for4linux_psxview => check 'pslist' & 'pid_hash'(where threads only exists => for4linux_threads), 'kmem_cache': SLAB=Y, SLUB=N");
	
	$this->article("hidden Process", "Processes are hidden by hooking the readdir member of the root of the /proc filesystem.
	Every active process in Linux has a corresponding directory under /proc whose name is the PID of the process (e.g init has a directory of /proc/1/).
	To hide processes, the hijacked readdir function simply filters out the directories that correspond to hidden processes.
	This effectively hides the process from a number of userland tools.");
	
	$this->article("hidden Module", "Kernel modules are hidden from lsmod by hooking the read member of /proc/modules.
	The modules file is the only source used by lsmod to list loaded modules, so this effectively hides it from the application.
	Again, we will see in a future post how to find hidden modules on both a live system and from a memory image by leveraging sysfs.");
	$this->for4linux_Malware_check_file_operation_structures("");
	}
	public function for4linux_Malware_threads($filter) {
	$cmd = "linux_threads";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Malware_check_hidden_process($filter) {
	
	$this->chapitre("Check hidden Process");
	
	$file_pslist = $this->for4linux_Process_pslist($filter);
	$this->note(" It can assist with detecting hidden processes");
	$file_pidhashtable = $this->for4linux_Process_pidhashtable($filter);
	$this->requette("cat $file_pslist | sort | tee $this->file_dir/$this->file_name.linux_pslist.sort");
	$this->requette("cat $file_pidhashtable | sort | tee $this->file_dir/$this->file_name.linux_pidhashtable.sort");
	$this->requette("diff $this->file_dir/$this->file_name.linux_pslist.sort $this->file_dir/$this->file_name.linux_pidhashtable.sort");
	}
	public function for4linux_Malware_check_hidden_privilege_escalator($filter) {
	$this->article("Privilege Escalator", "On older 2.6 kernels, the user ID and group ID of a process were kept as simple integers in memory.
For a rootkit to elevate the privileges of a process, it simply set these two values to zero.
This simplicity also made it very difficult to use only the information in the process structure itself to detect which processes had been elevated and which were simply spawned by root.
This changed in later versions of 2.6 as the kernel adopted a cred structure to hold all information related to the privileges of a process.
This structure is fairly complicated and forced rootkits to adapt their process elevation methods.
Although the kernel provides the prepare_creds and commit_creds functions to allocate and store new credentials, a number of rootkits choose not to use this functionality.
	
Instead, they simply find another process that has the privileges of root and that never exits, usually PID 1, and set the cred pointer of the target process to that of PID 1’s.
This effectively gives the attacker’s process full control and the rootkit does not have to attempt the non-trivial task of allocating its own cred structure.
	
The borrowing of cred structures leads to an inconsistency that Volatility can leverage to find elevated processes.
In the normal workings of the kernel, every process gets a unique cred structure and they are never shared or borrowed.
The for4linux_check_creds plugin utilizes this by building a mapping of processes and their cred structures and then reports any processes that share them.");
	$this->for4linux_Malware_processes_sharing_credential_structures("");
	}
	public function for4linux_Malware_plthook($filter) {
	$cmd = "linux_plthook";
	$this->note("GOT/PLT hook detection");
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Malware_ldpreload($filter) {
	
	$file = $this->for4linux_Dump_file("/etc/ld.so.preload", $filter);
	if (! empty($file)) {
	$this->requette("cp -v $file $this->file_dir/$this->file_name.ld.so.preload");
	$this->ssTitre("ld.so.preload recovered");
	$this->requette("cat $this->file_dir/$this->file_name.ld.so.preload");
	}
	$this->ssTitre("which process use LD_PRELOAD");
	$this->for4linux_Process_psenv("| grep -i \"LD_PRELOAD\" ");
	}
	public function for4linux_Dump_file($file, $filter) {
	$this->ssTitre("Find File ($file) and dump IT");
	$tmp = $this->for4linux_Information_find_file_name($file, "| grep -Po \"0x[0-9a-fA-F]{4,16}\" ");
	$inode = $tmp [0];unset($tmp);
	if (empty($inode)) return $this->note("empty inode");
	return $this->for4linux_Information_find_file_inode($inode, $filter);
	}
	public function for4linux_Malware_netfilter($filter) {
	$cmd = "linux_netfilter";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Malware_malfind($filter) {
	$cmd = "linux_malfind";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Malware_hidden_modules($filter) {
	$cmd = "linux_hidden_modules";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Malware_check_hidden_modules_and_dump($filter) {

	$this->titre("Search hidden Module and Dump");
	$file = $this->for4linux_Malware_hidden_modules("");
	$tmp = $this->req_ret_tab("grep -Po \"0x[0-9a-fA-F]{4,16}\"  $file ");
	if (! empty($tmp))
	foreach($tmp as $inode_module)
	if (! empty($inode_module)) {
	    $this->vol2exec("linux_lsmod -b $inode_module",$this->profile_vmem, $filter);
	$this->for4linux_Dump_Module_Kernel($inode_module, $filter);
	}
	}
	public function for4linux_Malware_check_inline_kernel($filter) {
	$cmd = "linux_check_inline_kernel";
	$this->note("check whether some objects were hooked");
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Malware_apihooks($filter) {
	$cmd = "linux_apihooks";
	$this->note("Inline hook detection");
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Malware_tmpfs($filter) {
	$cmd = "linux_tmpfs -L";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Malware_check_afinfo($filter) {
	$cmd = "linux_check_afinfo";
	$this->note("check tcp/udp_seq_afinfo hooked");
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Malware_processes_sharing_credential_structures($filter) {
	$cmd = "linux_check_creds";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Malware_check_file_operation_structures($filter) {
	$this->article("--inode Option", "--inode option, reads the inode at the given address and verifies each member of its i_fop pointer");
	$cmd = "linux_check_fop";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Malware_check_idt($filter) {
	$cmd = "linux_check_idt";
	return  $this->vol2exec($cmd,$this->profile_vmem,"| grep -i hooked $filter");
	}
	
	public function for4linux_Malware_erase_track($filter) {
	$cmd = "linux_psenv";
	$this->vol2exec($cmd,$this->profile_vmem,"| grep -i -E \"history|/dev/null|histfile\" $filter");
	$cmd = "linux_dynamic_env";
	$this->vol2exec($cmd,$this->profile_vmem,"| grep -i -E \"history|/dev/null|histfile\" $filter");
	}
	
	public function for4linux_Malware_check_modules($filter) {
	$this->ssTitre("Find Hiding the Kernel Module");
	$this->note("The sysfs enumeration code works by finding the module_kset variable, of type kset, that holds all information for /sys/module.
	The plugin then walks each member of the kset’s entry list which is of type kobject.
	Each of these kobject structures represents a module and its subdirectory immediately under /sys/module.
	The names of these directories are then gathered to be compared with the module list names.");
	$cmd = "linux_check_modules";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Malware_check_syscall($filter) {
	$this->ssTitre("Hooking System Call Table");
	$this->note(" System calls are the main mechanism for userland code to trigger event handling by the kernel.
	Reading and writing files, sending network data, spawning and exiting processes, etc are all done through system calls.
	The system call table is an array of function pointers, in which each pointer corresponds to a system call handler (i.e. sys_read handles the read system call).
	Rootkits often target this table due to the power it gives them over the control flow of the running kernel.
	KBeast hooks a number of entries in this table in order to hide files, processes, and more.");
	$cmd = "linux_check_syscall";
	$this->todo("linux_check_syscall -i /usr/include/x86_64-linux-gnu/asm/unistd_32.h, check \"HOOKED\" ");
	return $this->vol2exec($cmd,$this->profile_vmem,"| grep -i hooked $filter");
	
	}
	public function for4linux_Malware_check_keylogger($filter) {
	$this->ssTitre("Check Keylogger");
	$this->for4linux_Malware_check_tty($filter);
	$this->for4linux_Information_keyboard_notifier($filter);
	}
	public function for4linux_Malware_check_tty($filter) {
	$cmd = "linux_check_tty";
	return $this->vol2exec($cmd,$this->profile_vmem,"| grep -i hooked $filter");
	}
	public function for4linux_Malware_check_evt_arm($filter) {
	$cmd = "linux_check_evt_arm";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Malware_check_syscall_arm($filter) {
	$cmd = "linux_check_syscall_arm";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Information($filter) {
	$this->gtitre("Information");
	
	    //$this->for4linux_Information_mem_diff("PATH 2 VMEM CLEAN"); // $this->pause();
	$this->for4linux_Information_banner($filter); // $this->pause();
	$this->for4linux_Information_bash_env($filter); // $this->pause();
	$this->for4linux_Information_bash_hash($filter); // $this->pause();
	$this->for4linux_Information_bash_history($filter); // $this->pause();
	$this->for4linux_Information_cpuinfo($filter); // $this->pause();
	$this->for4linux_Information_dentry_cache($filter); // $this->pause();
	$this->for4linux_Information_dmesg($filter); // $this->pause();
	$this->for4linux_Information_file_enum($filter); // $this->pause();
	$this->for4linux_Information_find_file($filter);
	$this->for4linux_Information_info_regs($filter); // $this->pause();
	$this->for4linux_Information_iomem($filter); // $this->pause();
	$this->for4linux_Information_kernel_filesystems_recovers($filter); // $this->pause();
	$this->for4linux_Information_kernel_loaded_modules($filter); // $this->pause();
	$this->for4linux_Information_kernel_opened_files($filter); // $this->pause();
	$this->for4linux_Information_keyboard_notifier($filter); // $this->pause();
	$this->for4linux_Information_ldrmodules($filter); // $this->pause();
	$this->for4linux_Information_library_list($filter); // $this->pause();
	$this->for4linux_Information_mount($filter); // $this->pause();
	$this->for4linux_Information_mount_cache_kernel($filter); // $this->pause();
	$this->for4linux_Information_patcher($filter); // $this->pause();
	$this->for4linux_Information_recover_filesystem($filter); // $this->pause();
	$this->for4linux_Information_slabinfo($filter); // $this->pause();
	$this->for4linux_Information_truecrypt_passphrase($filter); // $this->pause();// rajouter les autres
	// rajouter celui de facebook et autre
	}
	
	public function for4linux_Information_mem_diff($vmem_clean){
	$this->ssTitre(__FUNCTION__);
	$file_output = "$this->file_dire/$this->file_name.".__FUNCTION__;
	$query = "python $this->dir_tools/for/linux_mem_diff.py -c $vmem_clean -i $this->file_path -p $this->profile | tee $file_output";
	if (file_exists($file_output)) $this->cmd("localhost", $query);else return $this->req_ret_str($query);
	return $this->req_ret_str("cat $file_output 2> /dev/null ");
	}
	public function for4linux_Information_pid($pid, $filter) {
	$pid_egrep = str_replace(" ", "|", $pid);
	$pid_param = str_replace(" ", ",", $pid);
	$this->for4linux_Information("egrep \"($pid_egrep)\" $filter");
	}
	public function for4linux_vmwareinfo($filter) {
	$cmd = "vmwareinfo";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Information_patcher($filter) {
	$cmd = "patcher";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Information_truecrypt_passphrase($filter) {
	$cmd = "linux_truecrypt_passphrase";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Networking_list_app($filter) {
	$cmd = "linux_list_raw";
	$this->note("find which programs are sniffing");
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Dump_library($filter) {
	$cmd = "linux_librarydump";
	return $this->vol2exec("$cmd --dump-dir=$this->file_dir/",$this->profile_vmem, $filter);
	}
	public function for4linux_Information_library_list($filter) {
	$cmd = "linux_library_list";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Information_info_regs($filter) {
	$cmd = "linux_info_regs";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Information_keyboard_notifiers($filter) {
	$cmd = "linux_keyboard_notifiers";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Information_bash_hash($filter) {
	$this->ssTitre("Detecting the Fake Binary");
	$cmd = "linux_bash_hash";
	$this->note("suspicious binary path(eg. rm /tmp/rm)");
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Information_bash_env($filter) {
	$cmd = "linux_bash_env";
	$this->note("looking for suspicious env path(eg. PATH=/tmp:\$PATH)");
	return $this->vol2exec($cmd,$this->profile_vmem,"grep -i 'PATH' $filter");
	}
	public function for4linux_Information_banner($filter) {
	$cmd = "linux_banner";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Information_ldrmodules($filter) {
	$cmd = "linux_kernel_ldrmodules";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Information_kernel_opened_files($filter) {
	$cmd = "linux_kernel_opened_files";
	$this->note("list which files were openned by kernel/LKM");
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Information_cpuinfo($filter) {
	$cmd = "linux_cpuinfo";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Information_dmesg($filter) {
	$cmd = "linux_dmesg";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Information_iomem($filter) {
	$this->ssTitre("Hardware Resources - RAM STRUCTURE");
	$this->note("cat /proc/iomem");
	$cmd = "linux_iomem";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Information_mount($filter) {
	$cmd = "linux_mount";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Information_recover_filesystem($filter) {
	$cmd = "linux_recover_filesystem";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Information_mount_cache_kernel($filter) {
	$cmd = "linux_mount_cache";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Information_slabinfo($filter) {
	$cmd = "linux_slabinfo";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Information_dentry_cache($filter) {
	$cmd = "linux_dentry_cache";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Information_find_file_name($file_name, $filter) { // -F capture.pcap or file.pdf ...etc
	$cmd = "linux_find_file";
	$query = "python /opt/volatility/vol.py --location=file://$this->file_path --profile=$this->profile $cmd -F '$file_name' $filter ";
	return $this->req_ret_tab($query);
	}
	
	
	public function for4linux_Information_find_file($filter) { 
		$cmd = "linux_find_file -L";
		return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	
	public function for4linux_Information_find_file_inode($file_inode, $filter) { // -F capture.pcap or file.pdf ...etc
	$cmd = "linux_find_file";
	$query = "python /opt/volatility/vol.py --location=file://$this->file_path --profile=$this->profile $cmd --inode $file_inode -O $this->file_dir/$file_inode.inode ";
	$this->requette($query);
	return "$this->file_dir/$file_inode.inode";
	}
	public function for4linux_Process_vma_cache($filter) {
	$cmd = "linux_vma_cache";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Malware_kernel_stack($filter) {
	$cmd = "linux_kstackps";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_Information_keyboard_notifier($filter) {
	$cmd = "linux_keyboard_notifier";
	$file = $this->vol2exec($cmd,$this->profile_vmem, "grep -i hooked $filter");
	}
	public function for4linux_volshell($filter) {
	$cmd = "linux_volshell";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4linux_search_strings($chaine, $filter) {
	$cmd = "linux_yarascan";
	return $this->vol2exec("$cmd -Y \"$chaine\"", $this->profile_vmem,$filter);
	}
	public function for4linux_Malware_scan_yarascan($yara_file, $filter) {
	$cmd = "linux_yarascan";
	return $this->vol2exec("$cmd --yara-file=$yara_file ",$this->profile_vmem, $filter);
	}
	
	public function for4linux_Process_graphic($filter) { // on doit affiner la recherche dans les PID pour avoir le graphe
	$this->ssTitre("Representation graphique");
	$this->for4linux_Process_pstree("--output=dot --output-file=$this->file_dir/pstree_$this->file_name.dot");
	$this->requette("xdot $this->file_dir/pstree_$this->file_name.dot $filter");
	$this->for4linux_Process_maps("--output=dot --output-file=$this->file_dir/maps_$this->file_name.dot");
	$this->requette("xdot $this->file_dir/maps_$this->file_name.dot $filter");
	$this->for4linux_Process_pslist("--output=dot --output-file=$this->file_dir/pslist_$this->file_name.dot");
	$this->requette("xdot $this->file_dir/pslist_$this->file_name.dot $filter");
	$this->for4linux_Process_memory_map("--output=dot --output-file=$this->file_dir/memory_map_$this->file_name.dot");
	$this->requette("xdot $this->file_dir/memory_map_$this->file_name.dot $filter");
	$this->for4linux_Process_psxview("--output=dot --output-file=$this->file_dir/psxview_$this->file_name.dot");
	$this->requette("xdot $this->file_dir/psxview_$this->file_name.dot $filter");
	$this->for4linux_Process_structure("--output=dot --output-file=$this->file_dir/structure_$this->file_name.dot");
	$this->requette("xdot $this->file_dir/structure_$this->file_name.dot $filter");
	// $this->pause();
	}
	
	
	public function for4linux_Process_pstree_dot() { // on doit affiner la recherche dans les PID pour avoir le graphe
	$this->ssTitre(__FUNCTION__);
	$cmd = "linux_pstree";
	$query = "python /opt/volatility/vol.py --location=file://$this->file_path --profile=$this->profile $cmd --output=dot --output-file=$this->file_dir/$this->file_name.$cmd.dot ";
	$this->requette($query);
	$this->dot2xdot("$this->file_dir/$this->file_name.$cmd.dot");
	return "$this->file_dir/$this->file_name.$cmd.dot";
	}
	
	public function for4linux_Process_pslist_dot() { // on doit affiner la recherche dans les PID pour avoir le graphe
		$this->ssTitre(__FUNCTION__);
		$cmd = "linux_pslist";
		$query = "python /opt/volatility/vol.py --location=file://$this->file_path --profile=$this->profile $cmd --output=dot --output-file=$this->file_dir/$this->file_name.$cmd.dot ";
		$this->requette($query);
		$this->dot2xdot("$this->file_dir/$this->file_name.$cmd.dot");
		return "$this->file_dir/$this->file_name.$cmd.dot";
	}
	
	public function for4linux_Process_psxview_dot() { // on doit affiner la recherche dans les PID pour avoir le graphe
		$this->ssTitre(__FUNCTION__);
		$cmd = "linux_psxview";
		$query = "python /opt/volatility/vol.py --location=file://$this->file_path --profile=$this->profile $cmd --output=dot --output-file=$this->file_dir/$this->file_name.$cmd.dot ";
		$this->requette($query);
		$this->dot2xdot("$this->file_dir/$this->file_name.$cmd.dot");
		return "$this->file_dir/$this->file_name.$cmd.dot";
	}
	
	

	public function for4linux_commandes() {
	$this->ssTitre("Volatility commandes for linux");
	//$this->net("https://code.google.com/p/volatility/wiki/LinuxCommandReference23");
	$this->requette("python /opt/volatility/vol.py --info | grep -i linux");
	}
	
	

	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
?>