<?php
class for4win extends bin4win{
    var $profile_vmem;
	
	public function __construct($vmem,$profile_vmem) {
	    parent::__construct($vmem);
	    $this->profile_vmem = trim($profile_vmem);
	}
	
	// tasklist /fi "pid eq [ReeordedPidj" /m
	// tasklist /fi "imagename eq calc.exe"
	// Load!plugins!from!an!external!directory:!
	// #!vol.py!HHplugins=[path]![plugin]!!
	
	
	/*
	 * tools IceSword
	 *
	 * $this->chapitre("Trojan AKA R2D2");
	 * $vmem = "$this->dir_tools/memory/WinXPSP2x86_0zapftis.vmem";
	 * $profile = "WinXPSP2x86";
	 * investigation_win_connection($this->file_dir,$vmem, $profile);
	 * $this->note("One active connection to the IP address 172.16.98.1 on port 6666 is listed.
	 * According to the process list, the process ID 1956 don’t belong to a browser process, such as Iexplore.exe or Firefox.exe, but rather to Explorer.exe.
	 * What is this system process doing on the internet?");
	 *
	 *
	 */
	
	public function for4win_all($filter){
	$this->for4win_commandes();	
	$this->for4win_Information($filter);	
	$this->for4win_Networking($filter);	
	$this->for4win_Process($filter);
	$this->for4win_Malware($filter);
	$this->notify("END Forensics ALL Win");	
	}
	
	public function for4win_commandes() {
	$this->ssTitre("Volatility commandes for Windows");
	$this->requette("vol.py --info | grep -i windows");
	}

	public function for4win_Malware_persistence_mz($filter) {
	
	$file_persistance = $this->for4win_Malware_persistence($filter);
	
	$file_mz = $this->for4win_Malware_search_injection($filter);
	
	$files_injected_mz = $this->req_ret_tab("cat $file_mz | cut -d' ' -f1 | sort -u ");
	
	$this->titre("Correspondance entre MZ et persistance ");
	if (! empty($files_injected_mz)) {
	foreach($files_injected_mz as $file_injected_mz)
	$this->requette("cat  $file_persistance | strings | grep -i '$file_injected_mz' ");
	}
	}
	
	
	
	public function for4win_Networking_facebook($filter) {
	$cmd = "facebook";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	
	
	public function for4win_Networking_facebook_extractor($filter) {
	$cmd = "facebook_extractor";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	
	
	
	
	
	public function for4win_Networking_twitter($filter) {
	$cmd = "twitter";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Process_vadimm($filter) {
	$cmd = "vadimm";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Information_windows($filter) {
	$cmd = "windows";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Information_wintree($filter) {
	$cmd = "wintree";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Information_wndscan($filter) {
	$cmd = "wndscan";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Malware_malfinddeep($filter) {
	$cmd = "malfinddeep";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Malware_malprocfind($filter) {
	$cmd = "malprocfind";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Networking_netstat_invest($filter) {
	$this->titre("Connection investigation");
	$this->ssTitre("Looking for connection to outside");
	
	$this->article("Trojan", "we know that malware mostly have a command and control structure, once they infect a system they need to connect back to the command center. Knowing that, we now need to look at the network connections established by the malware. We can find out about any established connections");
	$this->article("connections List", "Hunting for the C&C server");
	$file_net = $this->for4win_Networking_netstat($filter);
	$this->requette("cat $file_net | cut -d: -f2 | grep -Po \"[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$\" | sort -n | uniq | tee $this->file_dir/$this->file_name.ip");
	$this->requette("cat $file_net | grep -Po \" [0-9]{1,5}$\" | sort -n | uniq | tee $this->file_dir/$this->file_name.pid");
	$IPs = file("$this->file_dir/$this->file_name.ip");
	$PIDs = file("$this->file_dir/$this->file_name.pid");
	if (! empty($IPs [0]))
	foreach($IPs as $ip){
	$ip_addr = new ip($ip);
	$ip_addr->ip2malw();
	}
	$this->ssTitre("Process Name which need a Connection to outside");
	if (! empty($PIDs [0]))
	foreach($PIDs as $pid_check){
	$pid_check = trim($pid_check);
	$this->vol2exec("pslist",$this->profile_vmem, "--pid=$pid_check");
	}
	}
	public function for4win_Information_privileges($filter) {
	$cmd = "privileges";
	$this->vol2exec($cmd,$this->profile_vmem, $filter);;
	$this->for4win_Information_env_vars($filter);
	$this->for4win_Malware_check_process_priv($filter);
	}
	public function for4win_Information_dlllist($filter) {
	$cmd = "dlllist";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Dump_dll($filter) {
	$cmd = "dlldump";
	$query = "python /opt/volatility/vol.py --location=file://$this->file_path --profile=$this->profile $cmd  --dump-dir=$this->file_dir/ $filter";
	return $this->req_ret_tab("$query  | grep -Po \"module[.]{1}[0-9]{1,5}.*.dll$\" ");
	}
	public function for4win_Dump_dll_name($dll_name, $filter) {
	return $this->for4win_Dump_dll("-r $dll_name ", $filter);
	}
	public function for4win_Dump_dll_name_and_analysis($dll_name, $filter) {
	$file_dlls = $this->for4win_Dump_dll_name($dll_name, $filter);
	if (empty($file_dlls))
	return $this->note("Empty Result");
	// $dlls = file("$this->file_dir/$file_dlls");
	foreach($file_dlls as $dll){
	$check = new file("$this->file_dir/$dll"); $check->file_file2virus2vt();
	}
	
	return $file_dlls;
	}
	public function for4win_Dump_dll_addr($dll_addr, $filter) {
	return $this->for4win_Dump_dll("--base=$dll_addr", $filter);
	}
	public function for4win_Dump_dll_addr_and_analysis($dll_addr, $filter) {
	$dlls = $this->for4win_Dump_dll_addr($dll_addr, $filter);
	if (empty($dlls))
	return;
	foreach($dlls as $dll){
	$check = new file("$this->file_dir/$dll"); $check->file_file2virus2vt();	}
	}
	public function for4win_Malware_handles($filter) {
	$cmd = "handles";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Information_run_start($filter) {
	$this->ssTitre("See What Process running at start -> Userinit");
	$this->article("Notice", "Userinit is a program that restores our profile, fonts, colors, etc. for our Username.
	It is possible to add further programs that will launch from this key by separating the programs with a comma.
	It’s is a common place for trojans. ");
	$this->todo("File dump and analyse in init suspect ");
	$this->for4win_Information_registre_value("Microsoft\Windows NT\CurrentVersion\Winlogon", "");
	$this->for4win_Malware_hivelist($filter);
	$this->ssTitre("check AppInit_DLLs entries");
	$this->for4win_Information_registre_value("Microsoft\Windows NT\CurrentVersion\windows", "");
	}
	public function for4win_Malware_cmdline($filter) {
	$cmd = "cmdline";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Information_cmd_history($filter) {
	$this->ssTitre("Listing CMD commandes history");
	$this->for4win_Information_cmd_history_consoles($filter);
	$this->for4win_Information_cmd_history_cmdscan($filter);
	}
	public function for4win_Information_cmd_history_consoles($filter) {
	$cmd = "consoles";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Information_cmd_history_cmdscan($filter) {
	$cmd = "cmdscan";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Networking_scan_xp_2003_connections($filter) {
	$cmd = "connections";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Malware_scan_device_tree($filter) {
	$cmd = "devicetree";
	$this->article($cmd, "Windows utilise une architecture de pilote en couche, ou une chaîne de pilote de sorte que plusieurs pilotes peuvent inspecter ou de répondre à un IRP.
	Rootkits insérer souvent des pilotes (ou dispositifs) dans cette chaîne à des fins de filtrage (pour cacher les fichiers, masquer les connexions réseau, voler frappes ou mouvements de la souris).
	Le plugin devicetree montre la relation entre un objet conducteur de ses appareils (en marchant _DRIVER_OBJECT.DeviceObject.NextDevice)et tous les périphériques connectés(_DRIVER_OBJECT.DeviceObject.AttachedDevice).");
	$file = $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	$this->requette("grep -i unknown $file");
	return $file;
	}
	public function for4win_Information_drivermodule($filter) {
	$cmd = "drivermodule";
	$file = $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	$this->requette("grep -i unknown $file ");
	return $file;
	}
	public function for4win_Information_symlinkscan($filter) {
	$cmd = "symlinkscan";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Information_scan_driver($filter) {
	$cmd = "driverscan";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Information_scan_driverirp($filter) {
	$cmd = "driverirp -v";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Information_scan_modscan($filter) {
	$cmd = "modscan";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Information_scan_modules($filter) {
	$cmd = "modules";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Malware_multiscan($filter) {
	$cmd = "multiscan";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Information_computer_name($filter) {
	$this->titre("Useful Information");
	$this->for4win_Information_registre_value("ControlSet001\Control\ComputerName\ActiveComputerName", $filter);
	$file = $this->for4win_Information_env_vars($filter);
	$this->ssTitre("Computer name");
	$this->requette("grep COMPUTERNAME  $file ");
	$this->ssTitre("OS Type");
	$this->requette("grep OS  $file ");
	$this->ssTitre("Path");
	$this->requette("grep PATH  $file ");
	}
	public function for4win_Information_env_vars($filter) {
	$cmd = "envars";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Malware_eventHooks($filter) {
	$cmd = "eventhooks";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Process_scan_pslist($filter) {
	$this->article("pslist", "print all running processes by following the EPROCESS lists, processes were running on the computer when the memory dump was recorder");
	$cmd = "pslist";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Process_scan_pstree($filter) {
	$this->article("pstree", "Print process list as a tree -> en premier lieu cela permet d'avoir une vision general sur les processuces et les fils puis de specifier le processus suspect et pstree son arborescence");
	$cmd = "pstree";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Process_scan_vadtree($filter) {
	$this->note("Injected DLLs can be extracted with dlldump and injected shellcode with vaddump");
	$this->todo("Extract Injected Shellcode ");
	$cmd = "vadtree";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Dump_MZ_from_exe($filter) {
	
	
	$cmd = "vaddump";
	$this->vol2exec("$cmd --dump-dir=$this->file_dir/",$this->profile_vmem, $filter);
	}
	public function for4win_Process_graphic_vadtree($filter) {
	
	$this->ssTitre("Process VadTree Graph");
	
	$cmd = "vadtree";
	$this->vol2info($cmd);
	if (! file_exists("$this->file_dir/$this->file_name.$cmd.dot"))
	$this->vol2exec4txt($cmd, "--output=dot --output-file=$this->file_dir/$this->file_name.$cmd.dot $filter");
	$this->dot2xdot("$this->file_dir/$this->file_name.$cmd.dot");
	}
	public function for4win_Process_scan_xview($filter) {
	$cmd = "psxview";
	$this->note("POC rootkit hides from pslist and modifies pool tag to hide from psscan");
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Process_scan_psscan($filter) {
	$this->article("psscan", "Scan Physical memory for _EPROCESS pool allocations");
	$cmd = "psscan";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Malware_scan_yarascan($yara_file, $filter) {
	$cmd = "yarascan --yara-file=$yara_file ";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Process_graphic_psscan($filter) {
	
	
	$cmd = "psscan";
	$this->ssTitre("Representation graphique");
	if (! file_exists("$this->file_dir/$this->file_name.$cmd.dot"))
	$this->vol2exec4txt($cmd, "--output=dot --output-file=$this->file_dir/$this->file_name.$cmd.dot $filter");
	$this->dot2xdot("$this->file_dir/$this->file_name.$cmd.dot");
	}
	public function for4win_Malware_hivelist($filter) {
	$cmd = "hivelist";
	$file = $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	$this->ssTitre("Dump All hivelist content");
	$hive_tab = $this->req_ret_tab("cat $file | cut -d' ' -f1 | grep -Po \"0x[0-9a-fA-F]{4,16}\" ");
	$hive_tab = array_map('trim', $hive_tab);
	if (empty($hive_tab))
	return $file;
	foreach($hive_tab as $hive_addr)
	if (! empty($hive_addr))
	$this->for4win_Dump_hivedump($hive_addr, $filter);
	return $file;
	}
	public function for4win_Malware_hivescan($filter) {
	$cmd = "hivescan";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Malware_idt($filter) {
	$cmd = "idt";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Information_sam_file($filter) {
	
	
	$cmd = "hivelist";
	$this->for4win_Malware_hivelist($filter);
	// $query = "vol.py --location=file://$vmem --profile=$profile hivelist"; $this->requette($query);
	$this->ssTitre("SAM File at ");
	$tmp = $this->req_ret_tab("cat $this->file_dir/$this->file_name.$cmd | grep -i 'SAM' | cut -d' ' -f1 ");
	$sam = $tmp [0];
	unset($tmp);
	$this->ssTitre("System File at");
	$tmp = $this->req_ret_tab("cat $this->file_dir/$this->file_name.$cmd | grep -i \"system$\" | cut -d' ' -f1 ");
	$system = $tmp [0];
	unset($tmp);
	$this->ssTitre("Dump Hash Password");
	$file = $this->vol2exec("hashdump -y $system -s $sam",$this->profile_vmem, $filter);
	$this->requette("cat $file");
	return $file;
	}
	public function for4win_Malware_firewall_run_check($filter) {
	$this->note("Trojan usually shuts down our Firewall");
	$this->for4win_Information_registre_value("ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile", $filter);
	}
	public function for4win_Information_find_exe_pid($exec_name) {
	$this->ssTitre("Find PID of $exec_name");
	return $this->vol2exec4txt("psscan", " | grep $exec_name | grep -Po \" [0-9]{1,6} \" | head -1 ");
	}
	public function for4win_Dump_process_exe($filter) {
	 // aquart
	
	$this->note("genere executable.pid.exe -> pas interessant cote msfpescan");
	$cmd = "procexedump";
	return $this->vol2exec("$cmd --dump-dir=$this->file_dir/",$this->profile_vmem,$this->profile_vmem, " $filter");
	}
	public function for4win_Dump_process_exe_and_analysis($filter) {
	 // aquart
	
	$pid = $this->filter_pid_get($filter);
	$this->ssTitre("Process Exec Dump And Analysis");
	$execs = $this->for4win_Dump_process_exe("--pid=$pid");
	foreach($execs as $exec){
	$check = new file("$this->file_dir/$exec");
	$check->file_file2virus2vt();
	$check->file_file2sandbox("cuckoo1");
	}
	
	}
	public function for4win_Dump_process($pid, $filter) {	
	$this->note("genere executable.$pid.exe -> plus verbose a procexedump");
	$cmd = "procmemdump";
	$this->vol2exec("$cmd --dump-dir=$this->file_dir/",$this->profile_vmem, "--pid=$pid $filter");
	}
	
	public function for4win_Dump_file_process_and_analysis($pid, $filter) {
	$this->ssTitre("Process Mem Dump And Analysis");
	$file_dump = $this->for4win_Dump_process_exe("--pid=$pid $filter  ");
	$execs = $this->req_ret_tab("cat $file_dump | grep -Po \"executable.*.exe\" ");
	foreach($execs as $exec){
	$check = new file("$this->file_dir/$exec");
	$check->file_file2virus2vt();$check->file_file2sandbox("cuckoo1");
	}
	}
	public function for4win_Dump_file_process_all($pid, $filter) {
	 // aquart
	
	$cmd = "memdump"; // genere $pid.dmp -> inutilisable avec msfpescan (Couldn't find DOS e_magic)
	$this->vol2exec("$cmd --dump-dir=$this->file_dir/",$this->profile_vmem, "--pid=$pid $filter");
	}
	public function for4win_Dump_file_process_all_and_analysis($pid, $filter) {
	 // aquart
	
	$file_dump = $this->for4win_Dump_process_procdump("--pid=$pid");
	$execs = $this->req_ret_tab("cat $file_dump | grep -Po \"executable.*.exe\" ");
	foreach($execs as $exec)
	{
	$check = new file("$this->file_dir/$exec");
	$check->file_file2virus2vt();$check->file_file2sandbox("cuckoo1");
	}
	}
	public function for4win_Dump_file_name($file_name, $filter) {
	return $this->for4win_Dump_file("-r $file_name", $filter);
	}
	
	
	public function for4win_Dump_file_name_and_analysis($file_name, $filter) {
	$files_tmp = $this->for4win_Dump_file_name($file_name, $filter);
	$files = $this->req_ret_tab("cat $files_tmp");
	// var_dump($files);
	if (empty($files))
	return $this->note("No File name $file_name");
	else
	foreach($files as $file)
	{
	$check = new file("$this->file_dir/$file");
	$check->file_file2virus2vt();
	$check->file_file2sandbox("cuckoo1");
	}
	return $files_tmp;
	}

	public function for4win_Dump_file($command, $filter) {
	$cmd = "dumpfiles";
	return $this->vol2exec("$cmd $command --dump-dir=$this->file_dir/",$this->profile_vmem, " $filter | grep -Po \"file.*$\"");
	}
	
	public function for4win_Dump_registry($filter) {
	$cmd = "dumpregistry";
	$this->vol2exec("$cmd --dump-dir=$this->file_dir/",$this->profile_vmem, " $filter | grep -Po \"file.*$\"");
	}
	
	public function for4win_Dump_moddump($filter) {
	$cmd = "moddump";
	$this->vol2exec("$cmd --dump-dir=$this->file_dir/",$this->profile_vmem,$filter);
	}
	
	
	public function for4win_Dump_file_addr($file_addr) {
	return $this->for4win_Dump_file("-Q $file_addr", "");
	}
	public function for4win_Information_file_filescan($filter) {
	$cmd = "filescan";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	
	public function for4win_Information_file_fileparam($filter) {
	$cmd = "fileparam";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	
	
	
	public function for4win_Information_file_filelist($filter) {
	$cmd = "filelist";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Networking_ethscan($filter) {
	$cmd = "ethscan";
	$this->todo(" python vol.py ethscan -f be2.vmem -F 0x0800 -S -M 1500 -P -R -D ethscan_dump/
	vol.py ethscan -f be2.vmem -R --dump-dir outputfiles -C out.pcap -P -S
	 -R, --save-raw # packets are saved to binary files in the directory outputfiles
	 -P, --enable-proc     Enable Packet to Process Association: Windows Only
	 -C SAVE_PCAP  #saves all packets to the dump directory as out.pcap
	 -S, --disable-checksum
	
	");
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Malware_apihooksdeep($filter) {
	$cmd = "apihooksdeep";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Information_threads($filter) {
	$cmd = "threads";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Information_shellbags($filter) {
	$cmd = "shellbags";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Information_timeliner($filter) {
	$cmd = "timeliner -v";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Malware_scan_filetype($yara_file, $filter) {
	$this->for4win_Malware_scan_yarascan($yara_file, $filter);
	}
	public function for4win_Malware_search_keywords($filter) {
	
	
	$this->titre("Searching Some Key words");
	$this->for4win_Malware_search_mutant($filter);
	
	/*
	 * foreach ($dlls_name as $dll_name)
	 	* {
	 	* $dll_files = $this->for4win_Dump_dll_name( $dll_name, $filter);
	 	* foreach ($dll_files as $dll_file)
	 	* {
	 	* $file = trim($dll_file);
	 	* if(!empty($file)) system("echo \"$file#".hash_file('sha256', "$this->file_dir/$file")."\" >> $this->file_dir/file_analysis_tmp_all.db");
	 	* }
	 	* }
	 *
	 * $this->requette("cat $this->file_dir/file_analysis_tmp_all.db | sort -u | grep -v $this->file_dir/dll_mz_apihook.db ");
	 * // ADD Analyse
	 */
	}
	public function for4win_Malware_search_injection_other_analyse($filter) {
	
	
	$file_malfind = $this->for4win_Malware_malfind_process($filter);
	// $this->for4win_Dump_MZ_from_exe($filter);
	$check_malware_find = file_get_contents("$file_malfind");
	$check_malware_find = trim($check_malware_find);
	if (! empty($check_malware_find)) {
	$tmp = $this->req_ret_tab("cat $file_malfind | grep -e 'Process' | cut -d':' -f2,3,4 | cut -d' ' -f2,4,6");
	$total = count($tmp);
	$i = 1;
	
	foreach($tmp as $process){
	list($process_name, $process_pid, $process_addresse)= explode(" ", $process);
	$this->ssTitre("$i/$total: Dump $process_name=$process_pid @$process_addresse");
	$i ++;
	$files = $this->for4win_Dump_dll_name($process_name, "--pid=$process_pid $filter");
	
	if (! empty($files))
	foreach($files as $file){
	$file = trim($file);
	if (! empty($file)) {
	$this->requette("file $this->file_dir/$file");
	$this->requette("hexdump -C $this->file_dir/$file | head -4 ");
	$check = new file("$this->file_dir/$file"); $check->file_file2virus2vt();
	}
	}
	}
	}
	}
	public function for4win_Malware_search_injection($filter) {
	
	$this->titre("Searching Process Injection - Malfind");
	$cmd = "malfind";
	
	$file_malfind = $this->for4win_Malware_malfind_process($filter);
	$this->for4win_Malware_malfind_kernel($filter);
	$this->note("uniquement les MZ");
	$this->requette("cat $file_malfind | grep -A4 -B5 'MZ' | tee  $this->file_dir/$this->file_name.$cmd.mz");
	$this->requette("cat $this->file_dir/$this->file_name.$cmd.mz | grep -e 'Process' | cut -d':' -f2,3,4 | cut -d' ' -f2,4,6 | tee $this->file_dir/$this->file_name.pid.mz");
	return "$this->file_dir/$this->file_name.pid.mz";
	}
	public function for4win_Malware_search_injection_other($filter) {
	
	$this->titre("Searching Process Injection - Malfind");
	$cmd = "malfind";
	
	$file_malfind = $this->for4win_Malware_malfind_process($filter);
	$file = "$this->file_dir/$this->file_name.$cmd.pid";
	$this->requette("cat $file_malfind  | grep -e 'Process' | cut -d':' -f2,3,4 | cut -d' ' -f2 | sort -u | tee $file");
	return $file;
	}
	public function for4win_Malware_malfind_process($filter) {
	$this->article("malfind", "try to find a hidden or injected code/DLLs in the user mode memory and dump it.
	malfind to automatically locate and extract the injected executable code.
On Windows systems executable files have file signature of (MZ) or hexadecimal characters 4D 5A, which is the first two bytes of the file.");
	$cmd = "malfind";
	$this->todo("combiner malfind + yara exp:
	malfind --dump-dir --yara-file=search_rat.yara ou bien -Y 'chaine a rechercher' ideal pour les lignes de commandes ");
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Malware_malfind_kernel($filter) {
	$cmd = "malfind -K";
	$this->todo("combiner malfind -K + yara exp:
	malfind --dump-dir --yara-file=search_rat.yara ou bien -Y 'chaine a rechercher' ideal pour les lignes de commandes ");
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	
	public function for4win_Malware_injection_mz($filter) {
	$file_malfind = $this->for4win_Malware_malfind_process($filter);
	$this->ssTitre("Traitement sur MZ uniquement");
	// $this->for4win_Dump_MZ_from_exe($filter);
	$check_malware_find = file_get_contents("$file_malfind");
	$check_malware_find = trim($check_malware_find);
	system("echo '' | tee $this->file_dir/file_analysis_MZ_Injection_$this->file_name.db $this->file_dir/file_analysis_ext.db $this->file_dir/file_analysis_keywords.db");
	if (! empty($check_malware_find)) {
	$tmp = $this->req_ret_tab("cat $file_malfind | grep -A4 -B5 'MZ' | grep -e 'Process' | cut -d':' -f2,3,4 | cut -d' ' -f2,4,6");
	$total = count($tmp);
	$i = 1;
	
	foreach($tmp as $process){
	list($process_name, $process_pid, $process_addresse)= explode(" ", $process);
	$this->ssTitre("$i/$total: Dump $process_name=$process_pid @$process_addresse");
	$i ++;
	$files = $this->for4win_Dump_dll_addr($process_addresse, "--pid=$process_pid $filter");
	
	if (! empty($files))
	foreach($files as $file){
	$file = trim($file);
	if (! empty($file)) {
	$this->requette("file $this->file_dir/$file");
	$this->requette("hexdump -C $this->file_dir/$file | head -4 ");
	$check = new file("$this->file_dir/$file");
	$check->file_file2virus2vt();
	//$check->file_file2virus4scan2local4clamav();
	                   }
	                       }
	                   }
	                                   }
	}
	public function for4win_Malware_injection($filter) {
	
	
	$file_malfind = $this->for4win_Malware_malfind_process($filter);
	$this->for4win_Malware_malfind_kernel($filter);
	$this->ssTitre("Traitement sur MZ uniquement");
	// $this->for4win_Dump_MZ_from_exe($filter);
	$check_malware_find = file_get_contents("$file_malfind");
	$check_malware_find = trim($check_malware_find);
	system("echo '' | tee $this->file_dir/file_analysis_MZ_Injection_$this->file_name.db $this->file_dir/file_analysis_ext.db $this->file_dir/file_analysis_keywords.db");
	if (! empty($check_malware_find)) {
	$tmp = $this->req_ret_tab("cat $file_malfind | grep -e 'Process' | cut -d':' -f2,3,4 | cut -d' ' -f2,4,6");
	$tmp = array_map("trim", $tmp);
	$total = count($tmp);
	$i = 1;
	foreach($tmp as $process){
	list($process_name, $process_pid, $process_addresse)= explode(" ", $process);
	$this->ssTitre("$i/$total: Dump $process_name=$process_pid @$process_addresse");
	$tmp_file = $this->for4win_Dump_dll_addr($process_addresse, "--pid=$process_pid $filter");
	$file = trim($tmp_file [0]);
	if (! empty($file)) {
	system("echo \"$file#" .$this->req_ret_str("md5sum $this->file_dir/$file"). "\" >> $this->file_dir/file_analysis_MZ_Injection_$this->file_name.db");
	$i ++;
	$check = new file("$this->file_dir/$file"); $check->file_file2virus2vt();
	}
	}
	$this->requette("cat $this->file_dir/file_analysis_MZ_Injection_$this->file_name.db | cut -d'#' -f2 | sort | uniq -c ");
	$this->requette("cat $this->file_dir/file_analysis_MZ_Injection_$this->file_name.db | cut -d'#' -f2 | sort | uniq -c | grep -v \"^      1 \" ");
	
	$this->ssTitre("Analysing in MZ Injection");
	$tmp_analysis_file_hash = $this->req_ret_tab("cat $this->file_dir/file_analysis_MZ_Injection_$this->file_name.db | cut -d'#' -f2 | cut -d ' ' -f1 | sort -u");
	$tmp_analysis_file_hash = array_map("trim", $tmp_analysis_file_hash);
	foreach($tmp_analysis_file_hash as $hash_file){
	$hash_file = trim($hash_file);
	
	// $this->ssTitre("Lib between MZ and API Hook");
	// $this->requette("cat $this->file_dir/file_analysis_API_Hook.db | cut -d'#' -f2 | sort -u | tee $this->file_dir/file_analysis_API_Hook_uniq.db");
	// $this->requette("cat $this->file_dir/file_analysis_MZ_Injection_$this->file_name.db | cut -d'#' -f2 | sort -u | tee $this->file_dir/file_analysis_MZ_Injection_uniq.db");
	// $this->requette("cat $this->file_dir/file_analysis_API_Hook_uniq.db $this->file_dir/file_analysis_MZ_Injection_uniq.db | cut -d'#' -f2 | sort | uniq -c | grep -v \"^ 1 \" ");
	
	/*
	 * $tmp_analysis_file_hash = req_ret("cat $this->file_dir/file_analysis_API_Hook.db | cut -d'#' -f2 | sort -u");
	 * foreach($tmp_analysis_file_hash as $hash_file)
	 	* { $hash_file = trim($hash_file);
	 	* if (!empty($hash_file)) {
	 	* $dll_name = req_ret("cat $this->file_dir/file_analysis_API_Hook.db | grep $hash_file | cut -d'#' -f1 | tail -1 ");
	 	* //malware_scan_file("$this->dir_tools/yara_rules/all.yara","$this->file_dir/$dll_name[0]",$filter);
	 	* }
	 	* }
	 */
	 
	 
	 	
	 if (! empty($hash_file)) {
	 	$file_name = $this->req_ret_str("cat $this->file_dir/file_analysis_MZ_Injection_$this->file_name.db | grep $hash_file | cut -d'#' -f1 | tail -1 ");
	 	exec("echo '$file_name' | cut -d'.' -f2 | cut -d'.' -f1", $tmp_pid);
	 	$process_pid = $tmp_pid [0];
	 	unset($tmp_pid);
	 	$check = new file("$this->file_dir/$file_name");$check->file_file2virus2vt();
	 	unset($file_name);
	 }
	 $this->note("ne pas oublier qu'il y'a d'autre injection '8d'  ");
	}
	
	$this->ssTitre("Searching in MZ file Injection");
	$dlls = $this->req_ret_tab("cat $this->file_dir/file_analysis_MZ_Injection_$this->file_name.db | cut -d'#' -f1 ");
	foreach($dlls as $dll){
	$dll = trim($dll);
	if (! empty($dll)) {
	$this->requette("cat $this->file_dir/$dll | strings | egrep -i \"(Microsoft|http|system32|windows|pass|user|creat|open|hook|virt|alloc)\" | sort -u >> $this->file_dir/file_analysis_keywords.db");
	$this->requette("cat $this->file_dir/$dll | strings | egrep -i \"\.(dll|exe|sys|drv|bin)\" | sort -u >> $this->file_dir/file_analysis_ext.db");
	}
	}
	$this->ssTitre("Key Words Found");
	$this->requette("cat $this->file_dir/file_analysis_keywords.db | sort -u | tee $this->file_dir/$this->file_name.pid.mz.strings");
	
	$this->ssTitre("Searching in Other File found by strings");
	$dlls_name = $this->req_ret_tab("cat $this->file_dir/file_analysis_ext.db | sort -u ");
	}
	}
	public function for4win_Malware_search_apihooks($filter) {
	
	
	$this->titre("Detecting API Hook - apihook");
	
	$file_apihook = $this->for4win_Malware_apihooks($filter);
	
	$dlls = $this->req_ret_tab("cat $file_apihook | grep -Po -ie \"[a-z0-9_-]*\.(dll|exe|sys|drv|bin)\" | sort -u");
	system("echo '' | tee $this->file_dir/file_analysis_API_Hook.db $this->file_dir/file_analysis_ext.db $this->file_dir/file_analysis_keywords.db");
	
	if (! empty($dlls)) {
	foreach($dlls as $dll)
	if (! empty($dll)) {
	$dlls_name = $this->for4win_Dump_dll_name($dll, $filter);
	if (! empty($dlls_name))
	foreach($dlls_name as $dll_name)
	if (! empty($dll_name)) {
	$file = trim($dll_name);
	if (! empty($file))
system("echo \"$file#" . hash_file('sha256', "$this->file_dir/$file"). "\" >> $this->file_dir/file_analysis_API_Hook.db");
	}
	}
	}
	$this->ssTitre("Analysing in API HOOK");
	$this->requette("cat $this->file_dir/file_analysis_API_Hook.db | cut -d'#' -f2 | sort | uniq -c ");
	$this->requette("cat $this->file_dir/file_analysis_API_Hook.db | cut -d'#' -f2 | sort | uniq -c  | grep -v \"^      1 \"");
	
	$this->ssTitre("Lib between MZ and API Hook");
	$this->requette("cat $this->file_dir/file_analysis_API_Hook.db | cut -d'#' -f2 | sort -u | tee $this->file_dir/file_analysis_API_Hook_uniq.db");
	$this->requette("cat $this->file_dir/file_analysis_MZ_Injection_$this->file_name.db | cut -d'#' -f2 | sort -u | tee $this->file_dir/file_analysis_MZ_Injection_uniq.db");
	$this->requette("cat $this->file_dir/file_analysis_API_Hook_uniq.db $this->file_dir/file_analysis_MZ_Injection_uniq.db | cut -d'#' -f2 | sort | uniq -c  | grep -v \"^      1 \" ");
	
	/*
	 * $tmp_analysis_file_hash = $this->req_ret_tab("cat $this->file_dir/file_analysis_API_Hook.db | cut -d'#' -f2 | sort -u");
	 * foreach($tmp_analysis_file_hash as $hash_file)
	 	* { $hash_file = trim($hash_file);
	 	* if (!empty($hash_file)) {
	 	* $dll_name = $this->req_ret_tab("cat $this->file_dir/file_analysis_API_Hook.db | grep $hash_file | cut -d'#' -f1 | tail -1 ");
	 	* //malware_scan_file("$this->dir_tools/yara_rules/all.yara","$this->file_dir/$dll_name[0]",$filter);
	 	* //volatility_virustotal("$this->file_dir/$dll_name[0]",$filter);
	 	* }
	 	* }
	 */
	
	 $this->ssTitre("Searching in API Hooks");
	 $dlls = $this->req_ret_tab("cat $this->file_dir/file_analysis_API_Hook.db | cut -d'#' -f1 ");
	 foreach($dlls as $dll){
	 	$this->requette("cat $this->file_dir/$dll | strings | egrep -i \"(Microsoft|http|system32|windows|pass|user|creat|open|hook|virt|alloc)\" | sort -u >> $this->file_dir/file_analysis_keywords.db");
	 	$this->requette("cat $this->file_dir/$dll | strings | egrep -i \"\.(dll|exe|sys|drv|bin)\" | sort -u >> $this->file_dir/file_analysis_ext.db");
	 }
	
	 $this->ssTitre("Key Words Found");
	 $this->requette("cat $this->file_dir/file_analysis_keywords.db | sort -u");
	
	 $this->ssTitre("Searching in Other File found by strings");
	 $dlls_name = $this->req_ret_tab("cat $this->file_dir/file_analysis_ext.db | sort -u ");
	
	 // $this->for4win_Malware_scan_yarascan( "$this->dir_tools/yara_rules/dbgdetect.yar", "| grep \"^Owner:\" -A3 ");
	}
	public function for4win_Information_scan_service($filter) {
	$cmd = "svcscan -v";
	$this->article($cmd, "Pour voir quels services sont enregistrés sur votre image de mémoire, utilisez la commande svcscan.
	La sortie montre l ID de processus de chaque service (si son actif et se rapporte à un processus de usermode), le nom du service, le nom du service d affichage, le type de service, et l état actuel.
	Il montre aussi le chemin binaire pour le service déposée - qui sera un fichier EXE pour les services de usermode et un nom de pilote pour les services qui vont du mode noyau.");
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Information_graphic_svcscan($filter) {
	
	$cmd = "svcscan";
	$this->ssTitre("Representation graphique");
	if (! file_exists("$this->file_dir/$this->file_name.$cmd.dot"))
	$this->vol2exec4txt($cmd, "--output=dot --output-file=$this->file_dir/$this->file_name.$cmd.dot $filter");
	$this->dot2xdot("$this->file_dir/$this->file_name.$cmd.dot");
	}
	
	// HKCU\Software\Microsoft\Windows\CurrentVersion\Run
	public function for4win_Information_registre_value($reg_key, $filter) {
	$cmd = "printkey -K \"" . strtoupper($reg_key). "\" ";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Malware_search_path($filter) {
	$cmd = "shimcache";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Information_getservicesids($filter) {
	$cmd = "getservicesids";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Malware_check_process_priv($filter) {
	$cmd = "getsids -v";
	$this->article($cmd, "Pour voir les SID (Security Identifiers) associés à un processus, utilisez la commande 'getsids'.
	Entre autres choses, cela peut vous aider à identifier les processus qui ont malicieusement une escalade des privilèges.
	Un SID '(Security Identifier)'est essentiellement un identifiant unique qui est attribué à un utilisateur ou groupe, et est divisé en plusieurs parties: la révision (actuellement toujours à 1), l autorité d identificateur (décrivant de quelle autorité a créé la SID, et donc la façon d interpréter les subauthoriries), et enfin une liste de subauthorities .
	En général, lorsque les utilisateurs consultent SID (qui ils le font rarement), ils sont dans ce qu on appelle la forme Security Descriptor Definition Language (SDDL).
	Ceci est une chaîne qui ressemble à:
	
S-1-5-21-1957994488-484763869-854245398-513
	
Ici, '1' est la révision,
	 '5' est l'autorité de l'identifiant, et les parties restantes sont les subauthorities. La structure de données exactes pour un SID est:
	
*SECURITY_NULL_SID_AUTHORITY: L autorité 'NULL' Sid est utilisé pour maintenir le compte 'null' SID, ou S-1-0-0.
*SECURITY_WORLD_SID_AUTHORITY: L autorité 'Monde' Sid est utilisée pour le groupe 'Tout le monde ou Everyone', il ya un seul SID dans ce groupe, S-1-1-0.
*SECURITY_LOCAL_SID_AUTHORITY: L autorité Sid 'Local' est utilisée pour le groupe 'Local', encore une fois, il ya un seul SID dans ce groupe, S-1-2-0.
*SECURITY_CREATOR_SID_AUTHORITY: Cette autorité Sid est responsable de la CREATOR_OWNER, CREATOR_GROUP, CREATOR_OWNER_SERVER et CREATOR_GROUP_SERVER SID bien connus, S-1-3-0, S-1-3-1, S-1-3-2 et S-1-3 -3. ");
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Malware_check_process_hidden($filter) {
	$cmd = "userhandles -t TYPE_WINDOW";
	$file = $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	$this->requette("grep -i visible $file");
	}
	public function for4win_Malware_search_ssdt($filter) {
	$cmd = "ssdt";
	$this->article("SSDT", "SSDT (System Service Dispatch Table)
La System Service Dispatch Table est une table qui contient les pointeurs vers des fonctions de services (APIs) dans ntoskrnl.exe (NtOpenProcess, NtOpenThread, …).
Faire un hook dans la table consiste à remplacer la valeur originale du pointeur d’une entrée (prenons NtOpenProcess comme exemple) par l’adresse d’une fonction avec le même prototype dans n’importe quel module chargé dans l’espace noyau.
	En général, détourner une API est seulement fait pour filtrer les paramètres d’entrée (et refuser l’accès si nécessaire) et retourner le pointeur original à la fin du traitement, afin d’appeler la fonction originale.
Les hooks SSDT sont utilisés par les malware pour se protéger et se camoufler, et par les vendeurs d’antivirus (sur les vieux systèmes) pour filtrer les accès système (démarrage du processus, enregistrement du registre, …).");
	$file = $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	$this->requette("cat $file  | egrep -v '(ntoskrnl.exe|win32k)' ");
	}
	public function for4win_Malware_apihooks($filter) {
	$cmd = "apihooks";
	$this->article("API Hooks", "
	- Overwrite the beginning of API functions in order to redirect control flow
	- Allows the malware to hide virtually any data from userland tools and even some in-kernel monitors");
	$file = $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	$this->requette("cat $file | grep -A6 -i 'Hook mode:' ");
	return $file;
	}
	public function for4win_Malware_autoruns($filter) {
	$this->for4win_Malware_autoruns_autoruns($filter);
	$this->for4win_Malware_autoruns_services($filter);
	$this->for4win_Malware_autoruns_appinit($filter);
	$this->for4win_Malware_autoruns_winlogon($filter);
	$this->for4win_Malware_autoruns_task($filter);
	$this->for4win_Malware_autoruns_activesetup($filter);
	}
	public function for4win_Information_dump_evtlog($filter) {
	
	
	$cmd = "evtlogs -v";
	$this->vol2exec("$cmd --dump-dir=$this->file_dir/",$this->profile_vmem, $filter);
	$this->requette("cat $this->file_dir/oalerts.txt");
	$this->requette("cat $this->file_dir/appevent.txt");
	$this->requette("cat $this->file_dir/sysevent.txt");
	$this->requette("cat $this->file_dir/secevent.txt");
	$this->requette("cat $this->file_dir/thinprint.txt");
	}
	public function for4win_Malware_autoruns_autoruns($filter) {
	$cmd = "autoruns -t autoruns -v";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Malware_autoruns_services($filter) {
	$cmd = "autoruns -t services -v";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Malware_autoruns_appinit($filter) {
	$cmd = "autoruns -t appinit -v";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Malware_autoruns_winlogon($filter) {
	$cmd = "autoruns -t winlogon -v";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Malware_autoruns_task($filter) {
	$cmd = "autoruns -t task -v";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Malware_autoruns_activesetup($filter) {
	$cmd = "autoruns -t activesetup -v";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Malware_mbrparser($filter) {
	$cmd = "mbrparser";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Malware_ldrmodules($filter) {
	
	
	$this->article("PEB :Process Environment Block ", "est une structure de données en mode utilisateur qui applique sur lensemble dun processus.
Il est conçu pour être utilisé par le code en mode application dans les bibliothèques du système dexploitation, tels que ntdll.dll, Kernel32.dll.
	Grâce à l utilisation de PEB, on peut obtenir la liste des modules chargés, arguments processus de démarrage, ImageBaseAddress, adresse tas(pile), vérifier si le programme est en cours de débogage ou non, trouver des adresses de base de toutes les DLL importés et beaucoup d autres.
Les codes malicieux effectuer PEB énumération et encore promenade à travers la table de l exportation d un module pour obtenir les adresses de fonction.
Les PEB_LDR_DATA ont 3 liste chaînée:
	
InLoadOrderModuleList
InMemoryOrderModuleList
InInitializationOrderModuleList
	
inload = inloadorder = afin charger
inInit = ininitorder = afin initialisation
inMem = inmemorder = afin de mémo ");
	$this->note("Si vous supprimez un module de tous les 3 listes, il sera essentiellement caché des outils comme ListDLLs.exe, Process Explorer, Process Hacker, etc. est cela est lart des rootkits");
	$cmd = "ldrmodules -v";
	$file = $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	$this->ssTitre("Hidden Modules | Process");
	$this->note("Si vous supprimez un module de tous les 3 listes, il sera essentiellement caché des outils comme ListDLLs.exe, Process Explorer, Process Hacker, etc. est cela est lart des rootkits");
	$this->requette("cat $file| grep -i 'False' -A2 ");
	
	$tmp_pid = $this->req_ret_str("cat $file | grep 'False' | grep -Po \" [0-9]{1,6} \" ");
	$pids = implode(",", $tmp_pid);
	$tmp_addr = $this->req_ret_tab("cat $file | grep 'False' | grep -Po \" 0x[a-f0-9]{6,16} \" ");
	for($i = 0; $i < count($tmp_pid); $i ++) {
	$dll = $this->for4win_Dump_dll_addr(trim($tmp_addr [$i]), "--pid=" . trim($tmp_pid [$i]));
	if (! empty($dll [$i])) {
	$dll [$i] = trim($dll [$i]);
	if (file_exists($dll [$i])) virustotal_scan("$this->file_dir/" . $dll [$i]);
	}
	}
	return $this->req_ret_tab("cat $file");
	}

	public function for4win_Information($filter) {
	$this->gtitre("Information");
	
	
	$this->for4win_Information_antianalysis($filter);
	$this->for4win_Information_apifinder($filter);
	$this->for4win_Information_system_info($filter);
	$this->for4win_Information_usbstor($filter);
	
	
	$this->for4win_Information_auditpol($filter);
	$this->for4win_Information_bigpagepools($filter);
	$this->for4win_Information_bigpools($filter);
	
	$this->for4win_Information_bioskbd($filter);
	
	
		$this->for4win_Information_callback($filter);
		$this->for4win_Information_clipboard($filter);
	 $this->for4win_Information_cmd_history($filter);
	 $this->for4win_Information_computer_name($filter);
	 $this->for4win_Information_crashinfo($filter);
	 $this->for4win_Information_deskscan($filter);

	$this->for4win_Information_dlllist($filter);
	
	 $this->for4win_Information_drivermodule($filter);
	 $this->for4win_Information_dump_evtlog($filter);
	
	$this->for4win_Information_editbox($filter);
	$this->for4win_Information_env_vars($filter);
	$this->for4win_Information_file_filelist($filter);
	
	 $this->for4win_Information_file_filescan($filter);
	// 
	$this->for4win_Information_file_fileparam($filter);
	
	$this->for4win_Information_indx($filter);
	
	// $this->for4win_Information_find_exe_pid( $exec_name);pause();
		$this->for4win_Information_gahti($filter);
		$this->for4win_Information_gditimers($filter);
		$this->for4win_Information_getservicesids($filter);
	 $this->for4win_Information_hibernation_file($filter);

	 $this->for4win_Information_lsadump($filter);
	
	// $this->for4win_Information_memmap( $filter);pause();
	 $this->for4win_Information_mftparser($filter);
	 $this->for4win_Information_notepad($filter);
	 $this->for4win_Information_objtypescan($filter);
	 $this->for4win_Information_poolpeek($filter);
	 $this->for4win_Information_pooltracker($filter);
	 $this->for4win_Information_prefetchparser($filter);
	
	$this->for4win_Information_privileges($filter);
	
	 $this->for4win_Information_qemuinfo($filter);	
	// $this->for4win_Information_registre_value( $reg_key, $filter);pause();
	 $this->for4win_Information_run_start($filter);
	 $this->for4win_Information_sam_file($filter);
	     $this->for4win_Information_scan_driver($filter);
	 $this->for4win_Information_scan_driverirp($filter);
	 $this->for4win_Information_scan_modscan($filter);
	 $this->for4win_Information_scan_modules($filter);
	 $this->for4win_Information_scan_service($filter);
	// $this->for4win_Information_graphic_svcscan($filter);
	 $this->for4win_Information_shellbags($filter);
	 $this->for4win_Information_symlinkscan($filter);

	$this->for4win_Information_threads($filter);

	 $this->for4win_Information_timeliner($filter);
	 $this->for4win_Information_timers($filter);
	 $this->for4win_Information_truecrypt($filter);
	 $this->for4win_Information_trustrecords($filter);
	 $this->for4win_Information_uninstallinfo($filter);
	 $this->for4win_Information_userassist($filter);
	
	$this->for4win_Information_userhandles($filter);	
	$this->for4win_Information_vadinfo($filter);
	$this->for4win_Information_vadwalk($filter);
	
	 $this->for4win_Information_verinfo($filter);
	 $this->for4win_Information_windows($filter);
	 $this->for4win_Information_wintree($filter);
	 $this->for4win_Information_wndscan($filter);
	
	$this->for4win_Information_usnjrnl($filter);
	$this->for4win_Information_usnparser($filter);

	
	
	}
	
	
	

	public function for4win_Information_prefetchparser($filter) {
	$cmd = "prefetchparser";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	
	public function for4win_Information_usnparser($filter) {
	$cmd = "usnparser";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}	

	public function for4win_Information_usnjrnl($filter) {
	$cmd = "usnjrnl";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	
	public function for4win_Information_usbstor($filter) {
	$cmd = "usbstor";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}


	public function for4win_Information_system_info($filter) {
	$cmd = "system_info";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}	
	
	public function for4win_Information_indx($filter) {
	$cmd = "indx";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);
	}
	
	
	public function for4win_Information_antianalysis($filter) {
	$cmd = "antianalysis";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	

	public function for4win_Information_apifinder($filter) {
	$cmd = "apifinder";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}	

	public function for4win_Information_bigpagepools($filter) {
	$cmd = "bigpagepools";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}	
	
	
	public function for4win_Malware_gdt($filter) {
	$cmd = "gdt";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Information_timers($filter) {
	$cmd = "timers";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Information_truecrypt($filter) {
	$this->for4win_Information_truecryptmaster($filter);
	$this->for4win_Information_truecryptsummary($filter);
	$this->for4win_Information_truecryptpassphrase($filter);
	}
	public function for4win_Malware_unloadedmodules($filter) {
	$cmd = "unloadedmodules";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Information_userhandles($filter) {
	$cmd = "userhandles";
	$file = $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	$this->requette("grep -i 'hook' $file ");
	}
	public function for4win_Information_truecryptsummary($filter) {
	$cmd = "truecryptsummary";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Information_truecryptpassphrase($filter) {
	$cmd = "truecryptpassphrase";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Information_truecryptmaster($filter) {
	$cmd = "truecryptmaster";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Information_gditimers($filter) {
	$cmd = "gditimers";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Information_gahti($filter) {
	$cmd = "gahti";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Information_editbox($filter) {
	$cmd = "editbox";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Information_uninstallinfo($filter) {
	$cmd = "uninstallinfo";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Information_trustrecords($filter) {
	$cmd = "trustrecords";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Information_mftparser($filter) {
	$cmd = "mftparser";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Information_userassist($filter) {
	$cmd = "userassist";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Malware_mutant($filter) {
	$cmd = "handles -t Mutant --silent";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Process_scan_thread($filter) {
	$cmd = "thrdscan";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Information_vadwalk($filter) {
	$cmd = "vadwalk";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Information_memmap($filter) {
	$cmd = "memmap";
	$file = $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	$this->requette("head -10 $file");
	}
	public function for4win_Information_vadinfo($filter) {
	$cmd = "vadinfo";
	$file = $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	$this->requette("grep -i none $file");
	}
	public function for4win_Networking_chrome($filter) {
	$this->article("Options", "chromevisits -Q
	chromedownloads --output=csv
	chromedownloadchains
	chromecookies -K \"rq2uadV+VvAD+IBiBeJ75a==\"
	");
	$this->for4win_Networking_chromehistory($filter);
	$this->for4win_Networking_chrome_chromevisits($filter);
	$this->for4win_Networking_chrome_chromesearchterms($filter);
	$this->for4win_Networking_chrome_chromedownloads($filter);
	$this->for4win_Networking_chrome_chromedownloadchains($filter);
	$this->for4win_Networking_chrome_chromecookies($filter);
	}
	public function for4win_Information_clipboard($filter) {
	$cmd = "clipboard";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Information_crashinfo($filter) {
	$cmd = "crashinfo";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Information_deskscan($filter) {
	$cmd = "deskscan";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Networking_chrome_chromecookies($filter) {
	$cmd = "chromecookies";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Networking_chrome_chromedownloadchains($filter) {
	$cmd = "chromedownloadchains";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Networking_chrome_chromedownloads($filter) {
	$cmd = "chromedownloads";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Networking_chrome_chromesearchterms($filter) {
	$cmd = "chromesearchterms";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Networking_chrome_chromevisits($filter) {
	$cmd = "chromevisits";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Networking_chromehistory($filter) {
	$cmd = "chromehistory";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Networking_firefox_history($filter) {
	$cmd = "firefoxhistory";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Networking_java_idx($filter) {
	$cmd = "idxparser";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Networking_openvpn($filter) {
	$cmd = "openvpn";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Networking_rsakey($filter) {
	$cmd = "rsakey";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	
	

	public function for4win_Networking_hpv($filter) {
	$cmd = "hpv";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}	
	
	public function for4win_Networking_atoms($filter) {
	$cmd = "atoms";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	

	public function for4win_Networking_logfile($filter) {
	$cmd = "logfile";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	
	
	

	public function for4win_Networking_lastpass($filter) {
	$cmd = "atoms";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	
	
	public function for4win_Networking_carve_packets($filter) {
	$cmd = "carve_packets";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	
	public function for4win_Networking_atomscan($filter) {
	$cmd = "atomscan";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Information_auditpol($filter) {
	$cmd = "auditpol";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Information_bigpools($filter) {
	$cmd = "bigpools";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Networking_domain_cache_dump($filter) {
	$cmd = "cachedump";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Networking_dumpcerts($filter) {
	$cmd = "dumpcerts";
	$this->vol2exec("$cmd --dump-dir=$this->file_dir/",$this->profile_vmem, $filter);
	}
	public function for4win_Information_bioskbd($filter) {
	$cmd = "bioskbd";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Networking_firefox($filter) {
	$this->for4win_Networking_firefox_history($filter);
	$this->for4win_Networking_firefox_cookies($filter);
	$this->for4win_Networking_firefox_downloads($filter);
	}
	public function for4win_Networking_firefox_cookies($filter) {
	$cmd = "firefoxcookies";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Networking_firefox_downloads($filter) {
	$cmd = "firefoxdownloads";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Networking_iexplorer($filter) {
	$cmd = "iehistory";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Networking($filter) {
	$this->chapitre("Networking");
	
	 $this->for4win_Networking_atoms($filter);
	$this->for4win_Networking_lastpass($filter);
	 $this->for4win_Networking_atomscan($filter);
	$this->for4win_Networking_carve_packets($filter);
	$this->for4win_Networking_logfile($filter);
	 $this->for4win_Networking_chrome($filter);
	 $this->for4win_Networking_domain_cache_dump($filter);
	$this->for4win_Networking_dumpcerts($filter);
	 $this->for4win_Networking_ethscan($filter);
	$this->for4win_Networking_hpv($filter);
	$this->for4win_Networking_ndispktscan($filter);
	 $this->for4win_Networking_facebook($filter);	
	$this->for4win_Networking_facebook_extractor($filter);
	 $this->for4win_Networking_firefox($filter);
	 $this->for4win_Networking_iexplorer($filter);
	 $this->for4win_Networking_java_idx($filter);
	 $this->for4win_Networking_netstat($filter);
	 $this->for4win_Networking_netstat_invest($filter);
	 $this->for4win_Networking_openvpn($filter);
	 $this->for4win_Networking_rsakey($filter);
	 $this->for4win_Networking_scan_netscan($filter);
	 $this->for4win_Networking_scan_xp_2003_connections($filter);
	 $this->for4win_Networking_sessions($filter);
	 $this->for4win_Networking_sockscan($filter);
	 $this->for4win_Networking_twitter($filter);
	 $this->for4win_Networking_webscanner($filter);
	
	}
	
	

	public function for4win_Networking_ndispktscan($filter) {
	$cmd = "ndispktscan";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	
	public function for4win_Networking_webscanner($filter) {
	$cmd = "webrawscanner";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Malware_impscan($filter) {
	$cmd = "impscan";
	$this->todo("add --Base pour que cela fonctionne ");
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Process_joblinks($filter) {
	$cmd = "joblinks";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Malware($filter) {
	$this->chapitre("Malware");
	
	
	$this->for4win_Malware_hollowfind($filter);$this->pause();
	$this->for4win_Malware_apihooks($filter);$this->pause();
	$this->for4win_Malware_apihooksdeep($filter);	$this->pause();
	$this->for4win_Malware_autoruns($filter);$this->pause();
	$this->for4win_Malware_check_process_priv($filter);$this->pause();
	$this->for4win_Malware_check_process_hidden($filter);$this->pause();
	$this->for4win_Malware_cmdline($filter);$this->pause();
	$this->for4win_Malware_yarascan($filter);$this->pause();
	$this->for4win_Malware_eventHooks($filter);$this->pause();
	$this->for4win_Malware_firewall_hook($filter);$this->pause();
	$this->for4win_Malware_firewall_run_check($filter);$this->pause();
	$this->for4win_Malware_gdt($filter);$this->pause();
	$this->for4win_Malware_ghostrat($filter);	$this->pause();
	$this->for4win_Malware_handles($filter);	$this->pause();
	$this->for4win_Malware_scan_device_tree($filter);$this->pause();
	$this->for4win_Malware_hivescan($filter);$this->pause();
	$this->for4win_Malware_idt($filter);$this->pause();
	$this->for4win_Malware_impscan($filter);$this->pause();
	$this->for4win_Malware_injection($filter);$this->pause();
	$this->for4win_Malware_ldrmodules($filter);$this->pause();
	$this->for4win_Malware_malfind_process($filter);$this->pause();
	$this->for4win_Malware_malfind_kernel($filter);$this->pause();
	$this->for4win_Malware_malfinddeep($filter);$this->pause();
	$this->for4win_Malware_malfofind($filter);$this->pause();
	$this->for4win_Malware_injection_mz($filter);$this->pause();
	$this->for4win_Malware_malprocfind($filter);$this->pause();
	$this->for4win_Malware_malthfind($filter);$this->pause();
	$this->for4win_Malware_ssdeepscan($filter);$this->pause();	
	$this->for4win_Malware_mbrparser($filter);$this->pause();
	$this->for4win_Malware_multiscan($filter);$this->pause();
	$this->for4win_Malware_mutant($filter);$this->pause();
	$this->for4win_Malware_search_persistance($filter);$this->pause();
	$this->for4win_Malware_scan_filetype("$this->dir_tools/yara_rules/filetypes.yara", $filter);$this->pause();
	$this->for4win_Malware_scan_yarascan("$this->dir_tools/yara_rules/all.yara $filter ", "| grep -E -A1 \"(Rule|Owner)\" ");
	$this->for4win_Malware_search_apihooks($filter);$this->pause();
	$this->for4win_Malware_search_injection($filter);$this->pause();
	$this->for4win_Malware_search_injection_other_analyse($filter);$this->pause();
	$this->for4win_Malware_search_keywords($filter);$this->pause();
	$this->for4win_Malware_search_mutant($filter);$this->pause();
	$this->for4win_Malware_search_path($filter);$this->pause();
	$this->for4win_Malware_search_ssdt($filter);$this->pause();
	$this->for4win_Malware_unloadedmodules($filter);$this->pause();
	
	}
	
	

	public function for4win_Malware_ssdeepscan($filter) {
	$cmd = "ssdeepscan";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	
	public function for4win_Malware_malthfind($filter) {
	$cmd = "malthfind";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}	

	public function for4win_Malware_malfofind($filter) {
	$cmd = "malfofind";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	
	public function for4win_Malware_hollowfind($filter) {
	$cmd = "hollowfind";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	
	
	public function for4win_Malware_yarascan($filter) {
	$cmd = "yarascan -Y \"/[a-zA-Z0-9\-\.]+\.[a-zA-Z0-9\-\.]+\.[a-zA-Z]{1,4}$\" ";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Information_hibernation_file($filter) {
	$cmd = "hibinfo";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Dump_hivedump($hive_addr, $filter) {
	$cmd = "hivedump -o $hive_addr";
	// $this->vol2exec($cmd,$filter);
	}
	public function for4win_Malware_ghostrat($filter) {
	$cmd = "ghostrat";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Malware_firewall_hook($filter) {
	$cmd = "fwhooks";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Information_prefetch($filter) {
	$cmd = "prefetch";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Information_verinfo($filter) {
	$cmd = "verinfo";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Information_lsadump($filter) {
	$cmd = "lsadump";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Process_scan_psdiff($filter) {
	$cmd = "psdiff";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	
	public function for4win_Process_callstacks($filter) {
	$cmd = "callstacks";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	
	
	public function for4win_Process_heaps($filter) {
	$cmd = "heaps";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	
	public function for4win_Process_kstackps($filter) {
	$cmd = "kstackps";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	
	public function for4win_Process_msdecompress($filter) {
	$cmd = "msdecompress";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	
	
	public function for4win_Process_schtasks($filter) {
	$cmd = "schtasks";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	

	public function for4win_Process_taskmods($filter) {
	$cmd = "taskmods";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	
	
	
	
	public function for4win_Process($filter) {
	$this->chapitre("Process");
	
	$this->for4win_Process_callstacks($filter);
	$this->for4win_Process_heaps($filter);
	$this->for4win_Process_kstackps($filter);
	$this->for4win_Process_msdecompress($filter);
	$this->for4win_Process_schtasks($filter);
	$this->for4win_Process_taskmods($filter);
	
	
	$this->for4win_Process_scan_xview($filter);
	$this->for4win_Process_scan_pstree($filter);
	//$this->for4win_Process_graphic_psscan($filter);
	
	$this->for4win_Process_thread($filter);
	$this->for4win_Process_joblinks($filter);
	$this->for4win_Process_scan_pslist($filter);
	
	$this->for4win_Process_scan_psscan($filter);
	$this->for4win_Process_scan_psdiff($filter);

	$this->for4win_Process_scan_thread($filter);

	$this->for4win_Process_scan_vadtree($filter); 
	//$this->for4win_Process_graphic_vadtree($filter);
	$this->for4win_Process_vadimm($filter);

	$this->for4win_Process_Dump($filter);
	
	}
	public function for4win_Process_Dump($filter) {
	$pid = $this->filter_pid_get($filter);
	$this->for4win_Dump_process_exe_and_analysis($filter);
	$this->for4win_Dump_process($filter);
	$this->for4win_Dump_process_procdump($filter);
	$this->for4win_Dump_MZ_from_exe($filter);
	$this->for4win_Process_Dump_dll($filter);
	//$this->for4win_Process_Dump_files($filter);
	}
	public function for4win_Process_Dump_dll($filter) {
	$this->for4win_Dump_dll($filter);
	// $this->for4win_Dump_dll_addr_and_analysis( $dll_addr, $filter);
	// $this->for4win_Dump_dll_name_and_analysis( $dll_name, $filter);
	}
	public function for4win_Process_Dump_files($filter) {
	    $this->for4win_Dump_file_process_all($filter);
	
	//$this->for4win_Dump_file_addr($file_addr);
	//$this->for4win_Dump_file_name_and_analysis($file_name, $filter);
	
	$this->for4win_Dump_file_process_and_analysis($filter);
	}
	public function for4win_Process_thread($filter) {
	$this->titre("Threads");
	$cmd = "threads";
	$this->vol2exec("$cmd -F OrphanThread",$this->profile_vmem, $filter);
	$this->vol2exec("$cmd -F HideFromDebug",$this->profile_vmem, $filter);
	$this->vol2exec("$cmd -F AttachedProcess",$this->profile_vmem, $filter);
	$this->vol2exec("$cmd -F HookedSSDT",$this->profile_vmem, $filter);
	}
	public function for4win_Process_pid_search_api_hook($pid, $filter) {
	
	$this->for4win_Malware_malfind_process("--pid=$pid $filter");
	$this->for4win_Malware_malfinddeep("--pid=$pid $filter");
	$this->for4win_Malware_malprocfind("--pid=$pid $filter");
	$this->for4win_Dump_process_exe($pid, $filter);
	// vm_download($xp, "","$this->file_dir/ntdll.dll.recovred");
	$this->requette("strings $this->file_dir/ntdll.dll.recovred | sort -u | tee $this->file_dir/ntdll.dll.sort.u");
	$this->requette("strings $this->file_dir/executable.$pid.exe | sort -u | tee $this->file_dir/executable.$pid.exe.sort.u ");
	$this->requette("strings $this->file_dir/executable.$pid.exe | grep -i zw ");
	$this->requette("comm -1 -2 $this->file_dir/ntdll.dll.sort.u $this->file_dir/executable.$pid.exe.sort.u ");
	$this->requette("grep -F -x -f $this->file_dir/executable.$pid.exe.sort.u $this->file_dir/ntdll.dll.sort.u");
	$this->note("confirm hooking by apihook et recuperer les lieu des adresses hooker puis utiliser volshell");
	$this->for4win_Malware_apihooks("--pid=$pid $filter");
	$this->for4win_Malware_apihooksdeep("--pid=$pid $filter");
	$this->note("volshell cc(pid=$pid) -> dis(<0xADDR original>) -> voir ou cela nous mene -> puis dis(<0xADDR new>)
	-> confirm avec apihook aussi dumper aller dans tous les JMP par db(<0xADDR>)");
	}
	public function for4win_Malware_search_persistance($filter) {
	$this->titre("Looking For Persistance");
	$this->article("Running at start", "It is common that a trojan adds a registry key to be sure that it will be running every time the computer is restarted. Take a look at the Winlongon register key.");
	// net("http://www.f-secure.com/weblog/archives/00001207.html");
	$this->for4win_Information_run_start($filter);
	$this->ssTitre("Searching into other keys");
	$this->for4win_Information_registre_value(strtoupper('Software\Microsoft\Windows\CurrentVersion\Run'), $filter);
	$this->for4win_Information_registre_value(strtoupper('Software\Microsoft\Command Processor\AutoRun'), $filter);
	$this->for4win_Information_registre_value(strtoupper('Software\Microsoft\Windows\CurrentVersion\Runonce'), $filter);
	$this->for4win_Information_registre_value(strtoupper('Software\Microsoft\Windows\CurrentVersion\Network'), $filter);
	$this->for4win_Information_registre_value(strtoupper('Classes\.exe\shell\open\Command'), $filter);
	$this->for4win_Information_registre_value(strtoupper('Classes\exefile\shell\open\Command'), $filter);
	$this->for4win_Information_registre_value(strtoupper('Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'), $filter);
	$this->for4win_Information_registre_value(strtoupper('Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects'), $filter);
	$this->for4win_Information_registre_value(strtoupper('Software\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler'), $filter);
	$this->for4win_Information_registre_value(strtoupper('Software\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad'), $filter);
	$this->for4win_Malware_persistence_mz($filter);
	}
	public function for4win_Networking_netstat($filter) {
	$cmd = "connscan";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Networking_sockscan($filter) {
	$cmd = "sockscan";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Malware_persistence($filter) {
	$cmd = "persistence";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Networking_scan_netscan($filter) {
	$cmd = "netscan";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Information_notepad($filter) {
	$cmd = "notepad";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Dump_process_procdump($filter) {
	$cmd = "procdump";
	return $this->vol2exec("$cmd --dump-dir=$this->file_dir/",$this->profile_vmem, $filter);
	}
	public function for4win_Networking_sessions($filter) {
	$cmd = "sessions";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Information_qemuinfo($filter) {
	$cmd = "qemuinfo";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Information_poolpeek($filter) {
	$cmd = "poolpeek -t HookedSSDT";
	$this->todo("You must enter a --tag to find -> tag find in pooltracker donc pooltracker (This command does not support the profile WinXPSP3x86) after poolpeek");
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Information_pooltracker($filter) {
	$cmd = "pooltracker";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Information_objtypescan($filter) {
	$cmd = "objtypescan";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	public function for4win_Malware_search_mutant($filter) {
	
	$this->titre("Searching Mutex");
	$cmd = "mutantscan DMP -s";
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	// $this->vol2exec($cmd,$this->profile_vmem,"| cut -c 40- | grep -Po -i \"[a-z0-9-_.:{}()]{1,}$\" | sort -u $filter");
	}
	public function for4win_Information_callback($filter) {
	$cmd = "callbacks";
	$this->article($cmd, "PsSetCreateProcessNotifyRoutine (création de processus).
PsSetCreateThreadNotifyRoutine (création de fils).
PsSetImageLoadNotifyRoutine (DLL / chargement d'image).
IoRegisterFsRegistrationChange (enregistrement du système de fichiers).
KeRegisterBugCheck et KeRegisterBugCheckReasonCallback.
CmRegisterCallback (rappels de registre sur XP).
CmRegisterCallbackEx (Rappels de registre sur Vista et 7) .
IoRegisterShutdownNotification (Les rappels d'arrêt).
DbgSetDebugPrintCallback (Rappels débogage d'impression sur Vista et 7) .
DbgkLkmdRegisterCallback (Les rappels de débogage sur 7).");
	return $this->vol2exec($cmd,$this->profile_vmem, $filter);;
	}
	
	
	

	function trojan4win_aka_r2d2() {
		/*
		 *
		 *
		 * // pas d'injection de MZ (malfind)
		 * interessant persistance -> trouver le fichier incriminé mfc42ul.dll
		 * Persistance:
		 *
		 *
		 * check AppInit_DLLs entries
		 * mfc42ul.dll: python /home/labs/Bureau/CEH/tools/bof/volatility-read-only/vol.py --location=file:///home/labs/Bureau/CEH/tools/memory/WinXPSP2x86_0zapftis.vmem --profile=WinXPSP2x86 printkey -K "Microsoft\Windows NT\CurrentVersion\windows"
		 *
		 * command history :
		 * sc.exe: python /home/labs/Bureau/CEH/tools/bof/volatility-read-only/vol.py --location=file:///home/labs/Bureau/CEH/tools/memory/WinXPSP2x86_0zapftis.vmem --profile=WinXPSP2x86 consoles
		 *
		 */
		$this->chapitre("Trojan AKA R2D2");
	
	
		$pids = "1956,1884,228,192,544,184"; // (ppid=1884 -> 1956 (explorer.exe) + 228 (reader_sl.exe) + 192 (VMwareUser.exe) + 544 (cmd.exe) + 184 (VMwareTray.exe))
		$filter = "";
	
		$this->article("R2D2", "Identifier par Bitdefender comme Backdoor.R2D2.A, ce Trojan cible uniquement les OS Windows du Windows 2000 à Vista, il intègre une dll qui se charge uniquement si les processus suivant sont executés : Skype.exe, SkypePM.exe, explorer.exe, msnmsgr.exe, yahoomessenger.exe, x-lite.exe ou sipgatexlite.exe
Il espionne et envoie les informations serveur C&C concernant les discussions et conférences de messagerie instantanée, les appels reçus ou manqués, les messages écrits entre deux ou plusieurs utilisateurs, et les conversations orales via Skype, qui est l'utilisateur parle, quand et combien de temps ces conversations dernière, quels messages la personne visée reçoit, identifie les appels qui prend ou rejette.
En outre, il surveille les activités en ligne de l'utilisateur en gardant un oeil attentif sur les navigateurs Internet les plus populaires tels que Opera, Internet Explorer, Mozilla Firefox, le navigateur, et Seamonkey.
Il prend également des captures d'écran de l'écran de l'utilisateur et les envoie à un emplacement distant qui semble être près de Düsseldorf – Allemagne.");
		$this->pause();
	
		$this->net("http://www.microsoft.com/security/portal/threat/encyclopedia/entry.aspx?Name=Backdoor:Win32/R2d2.A#tab=2");
		$this->net("http://www.microsoft.com/security/portal/threat/encyclopedia/entry.aspx?Name=Trojan%3aWin32%2fR2d2.A!rootkit#tab=2");
		$this->net("http://www.symantec.com/connect/blogs/backdoorr2d2-long-arm-law");
		$this->net("http://www.ccc.de/en/updates/2011/staatstrojaner");
		$this->net("http://www.ccc.de/system/uploads/76/original/staatstrojaner-report23.pdf");
		$this->net("http://translate.google.com/translate?hl=en&sl=de&u=http://www.ccc.de/system/uploads/76/original/staatstrojaner-report23.pdf");
		$this->net("http://translate.google.com/translate?hl=en&sl=de&tl=fr&u=http%3A%2F%2Fwww.ccc.de%2Fsystem%2Fuploads%2F76%2Foriginal%2Fstaatstrojaner-report23.pdf&sandbox=1");
		$this->net("http://www.dw.com/en/several-german-states-admit-to-use-of-controversial-spy-software/a-15449054");
		$this->net("https://wikileaks.org/wiki/Skype_and_SSL_Interception_letters_-_Bavaria_-_Digitask");
		$this->net("https://wikileaks.org/wiki/Skype_and_the_Bavarian_trojan_in_the_middle");
		$this->net("https://www.f-secure.com/weblog/archives/00002250.html");
		$this->net("https://nakedsecurity.sophos.com/2011/10/10/german-government-r2d2-trojan-faq/");
		$this->pause();
	
		$this->gtitre("Resume");
		$this->pause();
		$this->for4win_Networking_netstat($filter);
		$this->note("One active connection to the IP address 172.16.98.1 on port 6666 is listed.
	According to the process list, the process ID 1956 don’t belong to a browser process, such as Iexplore.exe or Firefox.exe, but rather to Explorer.exe.
	What is this system process doing on the internet?");
		$this->ssTitre("check AppInit_DLLs entries");
		$this->for4win_Information_registre_value("Microsoft\Windows NT\CurrentVersion\windows", "");
		$this->pause();
	
		$dlls = $this->for4win_Dump_dll_name_and_analysis("mfc42ul.dll", $filter);
		$this->pause();
		$this->article("wscntfy.exe", "wscntfy.exe est le fichier exécutable de Windows XP Service Pack 2.
	Cette application est également connu comme Application de notifier Windows Security Center et est chargée d’afficher les icônes sur le Bureau du PC avec ces informations comme l’état des mises à jour Windows, l’état de protection contre les virus et le statut du pare-feu.
	Toutefois, les experts en sécurité ne recommandent pas cela parce que cela peut rendre votre ordinateur vulnérable à d’autres menaces.");
		foreach($dlls as $dll) {
			$this->requette("cat $dll | strings | egrep -i \".exe|r2d2|mfc42ul\" ");
			$this->pause();
		}
	
		note("The Trojan is called R2D2 because of the “C3PO-r2d2-POE” string inside the binary file.");
		note("it was injected in several exec");
		$this->for4win_Process_graphic_psscan($filter);
		$this->pause();
		$this->for4win_Dump_file_name_and_analysis("sc.exe", $filter);
		$this->pause();
		//$this->for4win_Dump_dll_name_and_analysis("sc.exe", $filter);pause();
	
		$this->for4win_Information_registre_value("ControlSet001\Services\malware", $filter);
		$this->pause();
	
		$file_winsys32 = $this->for4win_Dump_file_name_and_analysis("winsys32.sys", $filter);
		$this->pause();
	
		$file_winsys32 = $this->for4win_Dump_dll_name_and_analysis("winsys32.sys", $filter);
		$this->pause();
		// requette("grep 'winsys32.sys' $file_winsys32");pause();
		// cat mfc42ul.dll winsys32.sys | strings | egrep -i "(r2d2|skype|msn|explorer|yahoo|firefox|opera|seamonkey|sipgatexlite|x-lite|navigator|exe|dll)"
		// requette("cat $rep_path/$dll $file_winsys32 | egrep -i \"(r2d2|exe|dll)\" ");pause();
	
		$filter = "";
		$pid_tab = explode(",", $pids);
		foreach($pid_tab as $pid)
			$this->for4win_all("--pid=$pid");
	
			$this->notify("END R2D2");
	}
	
	
	
	function trojan4win_coreflood() {
		/*
		 * Pas Injection MZ
		 * APIHook dans 2044 iexplore.exe
		 */
	
		$this->chapitre("Trojan COREFLOOD");

		
		$pid = "1724,2044,452,432"; // 1724 (explorer.exe) 2044 (iexplore.exe) 452 (VMwareUser.exe) 432 (VMwareTray.exe) -> graphe process
		$filter = "";
	
		$pid_tab = explode(",", $pids);
		foreach($pid_tab as $pid)
			$this->for4win_all("--pid=$pid");
	
	
		$this->pause();
		$this->note("in netstat we found ");
		$this->net("https://www.virustotal.com/fr/ip-address/4.23.40.126/information/");
		$this->net("https://www.virustotal.com/fr/file/e9434381b4d2c3b94925b90878ddadcab5f9ba3ccb70435f2beaeda57bbf9c4b/analysis/");
		$this->net("https://www.virustotal.com/fr/url/f771e10f007975ea9e3b7ca11eda6491b3394d2ff38d5a3a9e74131a9577e0f8/analysis/");
		$this->net("https://www.virustotal.com/fr/ip-address/209.234.234.16/information/");
		$this->net("https://www.virustotal.com/fr/url/ee99b92b5c385d4e1c2168240a98922c4a921bb3d468fe3e197cda1cdba7eb7d/analysis/");
		$this->remarque("compromised process is 2044 (iexplore.exe) , found iframe + swf file = ? (maybe exploiting (flash 'swf' vulnerability + iframe (for update malware or exploiting vuln))");
	}
	

	function trojan4win_darkcomet() {
	
		/*
		 *
		 * Injection
		 *
		 * To bypass a firewall that might be in use into the victim’s system, DarkComet uses a simple but effective trick: it simply injects the communication code into a process that’s allowed to pass through the firewall, in this case it’s Internet Explorer, thus confirming our suspects. The injection takes place in this way: first of all Internet Explorer is identified, opened in background, suspended, then some “extra” memory is allocated into the process and DarkComet’s code copied inside this new buffer, following that the process is resumed.
		 *
		 * A confirmation that Internet Explorer is used to send the traffic can be obtained simply by inspecting the “hidden” process with ProcessExplorer
		 *
		 *
		 *
		 * Monitor the traffic, KEEPALIVE messages are always sent in clear and the traffic patterns are pretty constant in time
		 * Check for FTP data, keylogger can be configured to deliver keystrokes this way, in clear
		 * Check for hidden instances of iexplore.exe, use ProcessExplorer to see if it’s making traffic
		 * Check for unknown values in HKCU/Software/Microsoft/Windows/CurrentVersion/Run/
		 * Check for unknown values in HKLMSOFTWAREMicrosoftWindows NTCurrentVersionWinlogon into the “Userinit” key, this is another path used by the backdoor to run at startup
		 * Check for an empty link into the programsstartup section in the start menu
		 * Check for the existence of %tmp%/dclogs/ directory, that’s where you’ll find keylogger’s data
		 *
		 */
	
		/*
		 * Pas D'Injection MZ
		 * Apihook -> PID: 1524 2052 340 140 2644 2516 1316 844 588
		 *
		 * Hooking module: pcwum.DLL (Victim module: umpo.dll (0x74410000 - 0x74430000))
		 * Hooking module: wkscli.dll (Victim module: schedsvc.dll (0x722f0000 - 0x723aa000))
		 * Hooking module: LOGONCLI.DLL (Victim module: FVEAPI.dll (0x722a0000 - 0x722e3000))
		 * Hooking module: wfapigp.dll (Victim module: FirewallAPI.dll (0x74300000 - 0x74376000))
		 * Hooking module: ole32.dll (Victim module: urlmon.dll (0x75160000 - 0x75281000))
		 * Victim module: ieframe.dll (0x67f70000 - 0x68c95000)
		 *
		 * Hooking module: version.DLL (Victim module: wininet.dll (0x758d0000 - 0x75a88000))
		 * Hooking module: d3d10_1core.dll (Victim module: d3d10_1.dll (0x72d80000 - 0x72dac000))
		 * Hooking module: dxgi.dll (Victim module: d3d10_1core.dll (0x72b50000 - 0x72b91000))
		 * Hooking module: iertutil.dll Victim module: ieframe.dll (0x67f70000 - 0x68c95000)
		 *
		 *
		 * Persistance :
		 * SystemPropertiesPerformance.exe
		 * IconCodecService.dll
		 * Sidebar.exe
		 * runddl32.exe
		 * mctadmin.exe
		 */
	
		$this->chapitre("Trojan DarkComet_RAT");
		// net("http://la-taverne.info/tag/remote-administration-tool/");pause();
	
		$vmem_orig =  "$this->dir_tools/memory/Win7SP1x86_trojan4win_DarkComet_RAT.vmem";
		$vmem = "$this->dir_tmp/for4win_trojan4win_DarkComet_RAT/Win7SP1x86_trojan4win_DarkComet_RAT.vmem";
		if (!file_exists($vmem)) {$this->requette("mkdir $this->dir_tmp/for4win_trojan4win_DarkComet_RAT/; cp -v $vmem_orig $vmem");}
		$profile = "Win7SP1x86";
		$pid = "1524,1128,3656,1896";
		$filter = "";
	
		$for_vmem = new for4win($vmem, $profile);
	
		$for_vmem->for4win_all($filter);
		$this->pause();
	
	
	
		// ssTitre("Darkcomet RAT (Remote Administration Tools) - Source Code");net("http://darkcomet-rat.com/");pause();
		// ssTitre("vmem infected by Darkcomet");net("https://docs.google.com/file/d/0B-pKvSR-QbsHdDRzeG8xNVNnbEU/edit");pause();
	
		// investigation_win_first($rep_path,$vmem, $profile);
		// investigation_win_pid($rep_path,$vmem, $profile, $pid);
	
		// win_process_scan_pstree($rep_path,$vmem, $profile,"");
		$this->note("runddl32.exe is not rundll32 in C:\WINDOWS\system32\rundll32.exe -> suspiscious PID 1524 runddl32 execute notepad.exe !!!");
		// win_process_graphic($rep_path,$vmem, $profile);
		$this->ssTitre("More Investigation in PID=$pid");
		win_file_process_dump_all_and_analysis($pid, "");
		// virustotal_scan("$dir_tmp/executable.$pid.exe");
		// malware_scan_file("$dir_tmp/executable.$pid.exe");
		win_Malware_scan_yarascan_filter($pid, "$this->dir_tools/yara_rules/rats.yara", "");
		$this->requette("gedit $this->dir_tools/yara_rules/rats.yara");
		$this->pause();
		$this->requette("cat $this->dir_tools/yara_rules/DarkComet.yara");
		$this->pause();
		win_Malware_scan_yarascan_filter($pid, "$this->dir_tools/yara_rules/DarkComet.yara", "");
	
		$file_name = "runddl32";
		win_process_dump_all($pid);
		$mem_dump = "$dir_tmp/$pid.dmp";
		prog_content_strings($mem_dump, " | grep -i -A 22 \"DARKCOMET DATA\" | head -22");
		$this->pause();
		$this->ssTitre("Kelogger");
		prog_content_strings($mem_dump, " | grep -i dclogs");
		$this->requette("python /opt/volatility/vol.py -f $vmem --profile=$profile filescan | grep dclogs");
		$this->pause();
		prog_content_strings("$dir_tmp/executable.$pid.exe", " | grep -i dclogs");
		$file_addr = "0x3eee9330";
		win_file_dump_addr($file_addr);
		$this->ssTitre("Looking into this log file");
		note("This can be useful in finding the initial infection date");
		$this->ssTitre("Looking for Persistance");
		win_run_start($rep_path, $vmem, $profile);
		win_registre_value("Software\Microsoft\Windows\CurrentVersion\Run");
		$this->ssTitre("Find the Mutants!");
		$this->requette("python /opt/volatility/vol.py --location=file://$vmem --profile=$profile --pid=$pid handles -t Mutant");
		note("DarkComet has a default mutex of (DC_MUTEX-<7 alphanumeric characters>). ");
		$this->requette("python /opt/volatility/vol.py --location=file://$vmem --profile=$profile --pid=$pid yarascan -Y \"DC_MUTEX\" ");
		$this->requette("python /opt/volatility/vol.py --location=file://$vmem --profile=$profile --pid=$pid handles -t Mutant | grep \"DC_MUTEX\" ");
		prog_content_strings($rep_path, $vmem, "DC_MUTEX");
		$this->net("http://totalhash.com/search/mutex:*dc*_mutex*");
	
		$this->pause();
		os_timeline_execution($rep_path, $vmem, $profile);
		$this->requette("cat $dir_tmp/mft_parser.csv | grep -i runddl32");
		$this->pause();
		$this->requette("cat $dir_tmp/mft_parser.csv | egrep -i \"(dclogs|msdcsc)\" ");
		$this->pause();
	
		/*
		 * // ADD snort detection signature
		 * Network Detection
		 * Snort signatures for Dark Comet are available. The one shown below has been taken from a recent Emerging Threats [1] signature release. The signature attempts to identify the encrypted command and control traffic; the string of bytes it detects are those seen during the initial connection with the version 3 default key. The signature will match traffic to/from version 3 clients, with no security key configured. If a security key is used or if a later version of the client is used to build the server, the encrypted traffic will differ, and will not be detected by these signatures.
		 * alert tcp $EXTERNAL_NET 1024: -> $HOME_NET any (msg:"ET TROJAN DarkComet-RAT init connection"; flow:from_server,established; dsize:12; content:"|38 45 41 34 41 42 30 35 46 41 37 45|"; flowbits:set,ET.DarkCometJoin; flowbits:noalert; classtype:trojan-activity; reference:url,www.darkcomet-rat.com; reference:url,anubis.iseclab.org/?action=result&task_id=1a7326f61fef1ecb4ed4fbf3de3f3b8cb&format=txt; sid:2013283; rev:2;) alert tcp $HOME_NET any -> $EXTERNAL_NET 1024: (msg:"ET TROJAN DarkComet-RAT server join acknowledgement"; flow:to_server,established; dsize:12; content:"|39 34 41 35 41 44 30 41 45 46 36 39|"; flowbits:isset,ET.DarkCometJoin; classtype:trojan-activity; reference:url,www.darkcomet-rat.com; reference:url,anubis.iseclab.org/?action=result&task_id=1a7326f61fef1ecb4ed4fbf3de3f3b8cb&format=txt; sid:2013284; rev:2;) Emerging Threats Snort Signature [2]
		 * During analysis of the network traffic, a series of common strings were sent to and from the remote hosts; the ‘keepalive’ string. This string was consistent for all versions tested and independent of the security key configuration. Based on this analysis, I wrote the following two signatures to detect the keepalive string:
		 * alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"Context Signature: DarkComet-RAT Incoming Keepalive"; flow:from_server,established; content:"KeepAlive"; pcre:"/KeepAlive\|\d{7}/"; classtype:trojan-activity; sid:1000001; rev:3; reference:url,www.contextis.com/research/blog/malware-analysis-dark-comet-rat/;) alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Context Signature: DarkComet-RAT Outgoing Keepalive"; flow:to_server,established; content:"KEEPALIVE"; pcre:"/KEEPALIVE\d{7}/"; classtype:trojan-activity; sid:1000002; rev:2; reference:url,www.contextis.com/research/blog/malware-analysis-dark-comet-rat/;)
		 *
		 * malware_scan_pcap($pcap);
		 *
		 */
		/*
		 * the network connection is maintained with a series of TCP requests [PSH, ACK]
		 * containing the word ‘keepalive’, followed by a string of digits. This sequence,
		 * as well as the initial command and control conversation in its encrypted form
		 */
	}
	


	function trojan4win_shylock() {
		/*
		 * Injection MZ():
		 * explorer.exe 1752 0x3380000 -> searching strings -> hijackdll.dll HookDLL.dll USERENV.dll userinit.exe maxthon.exe VNCServer.cpp
		 * explorer.exe 1752 0x36e0000
		 * VMwareTray.exe 1876 0xf40000
		 * VMwareUser.exe 1888 0x2070000
		 * msseces.exe 1900 0x10000000
		 * ctfmon.exe 1912 0x10000000
		 * wscntfy.exe 2028 0x10000000
		 * TPAutoConnect.e 3372 0x10000000
		 * cmd.exe 3756 0x10000000
		 * explorer.exe 1752 0x3380000
		 * explorer.exe 1752 0x36e0000
		 * VMwareTray.exe 1876 0xf40000
		 * VMwareUser.exe 1888 0x2070000
		 * msseces.exe 1900 0x10000000
		 * ctfmon.exe 1912 0x10000000
		 * wscntfy.exe 2028 0x10000000
		 * TPAutoConnect.e 3372 0x10000000
		 * cmd.exe 3756 0x10000000
		 *
		 * icmp.dll Imagehlp.dll
		 *
		 */
	
		$this->chapitre("Trojan Shylock");
	

		$pid = "1752,1912,3756,1900,1876,1888,2028,3372"; // + 680 + 3128 + 200
		$filter = "";
	
		$this->for4win_all($filter);
	
	
		$this->chapitre("Resume");
		$this->for4win_Information_registre_value("Software\Microsoft\Windows\CurrentVersion\Run", "");
		$this->for4win_file("| grep \"rdshost.exe\" "); // win_dlldump_name_and_analysis($rep_path,$vmem, $profile,"rdshost.exe","");
		remarque("no rdshost.exe -> no running when memory was dumped");
	
		$this->for4win_file_filescan("| grep \"ctfmon.exe\" ");
		$this->for4win_dlldump_name_and_analysis("ctfmon.exe", "");
	
		note("depend malfind + ldrmodules");
		$this->for4win_file("| grep \"msseces.exe\" ");
		$this->for4win_dlldump_name_and_analysis("msseces.exe", "");
		note("depend ,malfind and psscan graph - 2028");
		$this->for4win_file("| grep \"wscntfy.exe\" ");
		$this->for4win_dlldump_name_and_analysis("wscntfy.exe", "");
		note("deduction d'apres le graphe, mais pas d'injection MZ see apihooks");
		$this->for4win_process_apihook_filter("1076,2068", $filter);
		// 1076,2068
		$this->for4win_file_filelist("--pid=$pid");
		$this->for4win_file("| grep \"winspool.drv\" ");
		$this->for4win_dlldump_name_and_analysis("winspool.drv", "");
	
		// dlllist pids
		$this->for4win_file("| grep \"0.dll\" ");
		$this->for4win_dlldump_name_and_analysis("0.dll", "");
		$this->for4win_file("| grep \"13.dll\" ");
		$this->for4win_dlldump_name_and_analysis("13.dll", "");
	}
	
	
	function trojan4win_spyeye() {
	
		$this->chapitre("Trojan SpyEye");
	

		$pid = "1068,1008,1672,2268,1588,2728,1484,1252,3892,680,888,2912"; // explorer.exe
		$filter = "";
	
		$for_vmem = new for4win($vmem, $profile);
	
		$for_vmem->for4win_all($filter);
		$this->pause();
	
	
	
	
		/*
		 *
		 * investigation_win_pid($rep_path,$vmem,$profile,$pid);pause();
		 *
		 * net("https://www.virustotal.com/fr/ip-address/65.55.185.26/information/");
		 *
		 * 0x01ed9b50 wmiprvse.exe 2912 False True False
		 *
		 * Injection MZ:
		 * winlogon.exe 660 0xea50000
		 * services.exe 704 0xea50000
		 * lsass.exe 716 0xea50000
		 * vmacthlp.exe 872 0xea50000
		 * svchost.exe 904 0xea50000
		 * svchost.exe 972 0xea50000
		 * svchost.exe 1068 0xea50000
		 * svchost.exe 1108 0xea50000
		 * svchost.exe 1232 0xea50000
		 * spoolsv.exe 1456 0xea50000
		 * svchost.exe 1540 0xea50000
		 * jqs.exe 1612 0xea50000
		 * vmtoolsd.exe 1816 0xea50000
		 * VMUpgradeHelper 1872 0xea50000
		 * explorer.exe 1008 0xea00000
		 * explorer.exe 1008 0xea50000
		 * explorer.exe 1008 0xeab0000
		 * TSVNCache.exe 1252 0xea50000
		 * VMwareTray.exe 1484 0xea50000
		 * VMwareUser.exe 1588 0xea50000
		 * jusched.exe 1672 0xea50000
		 * wuauclt.exe 536 0xea50000
		 * imapi.exe 1040 0xea50000
		 * alg.exe 2108 0xea50000
		 * wscntfy.exe 2772 0xea50000
		 * WPFFontCache_v0 3084 0xea50000
		 * jucheck.exe 3892 0xea50000
		 * jucheck.exe 3892 0xeab0000
		 * gmer.exe 2728 0x15d0000
		 * gmer.exe 2728 0xd20000
		 * gmer.exe 2728 0x13d0000
		 * gmer.exe 2728 0xeab0000
		 * gmer.exe 2728 0x1bd0000
		 * gmer.exe 2728 0x19d0000
		 *
		 * ?Software\Microsoft\Internet Explorer
		 * Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2
		 * SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUN
		 *
		 * cleansweep.exe
		 * cleansweepupd.exe
		 * config.bin
		 *
		 *
		 *
		 *
		 *
		 *
		 * // spyeye inject code into explorer.exe to connect to a web site
		 *
		 * ssTitre("SpyEye successor of Zeus");
		 * net("http://www.fbi.gov/news/stories/2014/january/spyeye-malware-mastermind-pleads-guilty");
		 * net("http://lemontrealdz.wordpress.com/2014/01/29/etats-unis-un-co-accuse-du-hacker-hamza-bendelladj-plaide-coupable/");
		 * net("http://www.bitdefender.fr/blog/Top-10-des-pirates-informatiques-arr%C3%AAtes-en-2013-1403.html");
		 * net("http://www.fbi.gov/news/testimony/the-fbis-role-in-cyber-security");
		 * net("http://www.justice.gov/usao/gan/press/2014/01-28-14.html");
		 * pause();
		 * ssTitre("Usage");
		 * net("http://blog.fortinet.com/a-guide-to-spyeye-cc-messages/");pause();
		 * ssTitre("Tracker");
		 * net("https://spyeyetracker.abuse.ch/");
		 * net("https://spyeyetracker.abuse.ch/monitor.php");
		 * pause();
		 *
		 * //os_imageinfo($vmem);os_imageinfo_more($vmem);
		 * os_connection_list($rep_path,$vmem, $profile);
		 * ip2malw($rep_path,"207.46.21.58");net_search("207.46.21.58");
		 * ip2malw($rep_path,"65.55.185.26");net_search("65.55.185.26");
		 * requette("python /opt/volatility/vol.py -f $vmem --profile=$profile handles -p $pid -t Process");
		 * process_dump($rep_path,$vmem, $profile, $pid);
		 * virustotal_scan($rep_path,$vmem, $profile,"$dir_tmp/executable.$pid.exe");
		 *
		 * prog_content_strings($rep_path,$vmem, " | grep -i \"SPYNET\" ");//SPYNET
		 * win_file_scan_filter($rep_path,$vmem, $profile, "spy");
		 * win_file_dump_name($rep_path,$vmem, $profile, "spy\.exe"); // cleansweep.exe
		 * requette("python /opt/volatility/vol.py -f $vmem --profile=$profile mutantscan -s");
		 * requette("python /opt/volatility/vol.py -f $vmem --profile=$profile apihooks");
		 */
	}
	
	function trojan4win_silentbanker() {
	
	
		$this->chapitre("Trojan Silentbanker");
	
		$vmem_orig = "$this->dir_tools/memory/WinXPSP2x86_trojan4win_Silentbanker.vmem";
		$vmem = "$this->dir_tmp/for4win_trojan4win_Silentbanker/WinXPSP2x86_trojan4win_Silentbanker.vmem";
		if (!file_exists($vmem)) {$this->requette("mkdir $this->dir_tmp/for4win_trojan4win_Silentbanker/; cp -v $vmem_orig $vmem");}
		$profile = "WinXPSP2x86";
		$pid = "1884,1724,452,432"; // 468 (graphe)
		$filter = "";
	
		$for_vmem = new for4win($vmem, $profile);
	
		$for_vmem->for4win_all($filter);
		$this->pause();
	
	
		/*
		 * wuauclt.exe
		 * wscntfy.exe
		 *
		 * Software\Microsoft\Internet Account Manager\Accounts
		 * SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\
		 *
		 *
		 *
		 * AcooBrowser.exe
		 * advapi32.dll
		 * comsatac.dll
		 * crypt32.dll
		 * gdi32.dll
		 * gdiplus.dll
		 * iexplore.exe
		 * maxthon.exe
		 * mfcsyrv8.dll
		 * msratnit.dll
		 * MSVCRT.dll
		 * ole32.dll
		 * pstorec.dll
		 * qviexio3.dat
		 * rundll32.exe
		 * shell32.dll
		 * urlmon.dll
		 * user32.dll
		 * wininet.dll
		 * ws2_32.dll
		 *
		 * Injection MZ
		 * module.1884.107e020.10020000.dll
		 *
		 * wscntfy_mtx
		 */
	
	
	
		investigation_win_pid($pid);
		$this->pause();
	
		titre("Resume");
		$this->net("https://www.virustotal.com/fr/ip-address/65.54.81.185/information/");
		$this->net("https://www.virustotal.com/fr/url/1b97ab96dbc50ab021ea2a6404b156e0fc60f007b6ea2b84af781f4f17a8c99e/analysis/");
		$this->net("https://www.virustotal.com/fr/ip-address/69.43.160.4/information/");
		$this->net("https://www.virustotal.com/fr/url/b772addc13009b32a3fd8e1eadac6850da70c0de970ba8c352b972ab3b206fb2/analysis/");
		$this->net("www.trellian.net/bin/div401pt.exe");
		$this->net("https://www.virustotal.com/fr/ip-address/209.234.225.242/information/");
		$this->net("");
		$this->net("");
		$this->net("");
		$this->net("");
		$this->net("");
		$this->net("");
		$this->net("");
		$this->net("");
	
		win_print_registre_value("Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects");
		// + registre de SID trouver
		win_file_scan_filter("| grep mscorews");
		win_file_dump_name("mscorews.dll");
	}
	


	function trojan4win_zeus() {
	
		$this->chapitre("Trojan Zeus");
		$vmem_orig = "$this->dir_tools/memory/WinXPSP2x86_trojan4win_Zeus.vmem";
		$vmem = "$this->dir_tmp/for4win_trojan4win_Zeus/WinXPSP2x86_trojan4win_Zeus.vmem";
		if (!file_exists($vmem)) {$this->requette("mkdir $this->dir_tmp/for4win_trojan4win_Zeus/; cp -v $vmem_orig $vmem");}
		$profile = "WinXPSP2x86";
		$pid = 856;
		$filter = "";
	
		$for_vmem = new for4win($vmem, $profile);
	
		$for_vmem->for4win_all($filter);
		$this->pause();
		;
	
	
		/*
		 * Zeus is a Trojan horse that steals banking information by Man-in-the-browser keystroke logging and Form Grabbing.
		 * Zeus is spread mainly through drive-by downloads and phishing schemes.
		 *
		 * Running the “apihooks” plugin show multiple inline api hooks in the explorer.exe process and also there is a jump into an unknown location that is where the malicious code might be
		 * zeus s'injecte dans explorer.exe
		 *
		 *
		 * Trojan executable
		 * Trojan.Zbot generally creates a copy of itself using one of the following file names:
		 *
		 * ntos.exe
		 * oembios.exe
		 * twext.exe
		 * sdra64.exe
		 * pdfupd.exe
		 *
		 *
		 *
		 * Configuration file
		 * The threat creates a folder named “lowsec” in either the %System% or %UserProfile%\Application Data folder and then drops one of the following files into it:
		 *
		 * video.dll
		 * sysproc32.sys
		 * user.ds
		 * ldx.exe
		 *
		 * Service injection
		 * Depending on the level of privileges, Trojan.Zbot will inject itself into one of two services.
		 * If the account has administrative privileges, the threat injects itself into the winlogon.exe service.
		 * If not, it attempts to do the same with the explorer.exe service.
		 * The threat also injects code into an svchost.exe service, which it later uses when stealing banking information.
		 *
		 * Password stealing
		 * The core purpose of Trojan.Zbot is to steal passwords, which is evident by the different methods it goes about doing this.
		 *
		 * Upon installation, Trojan.Zbot will immediately check Protected Storage (PStore) for passwords.
		 * It specifically targets passwords used in Internet Explorer, along with those for FTP and POP3 accounts.
		 * It also deletes any cookies stored in Internet Explorer.
		 * That way, the user must log in again to any commonly visited Web sites, and the threat can record the login credentials at the time.
		 *
		 * A more versatile method of password-stealing used by the threat is driven by the configuration file during Web browsing.
		 * When the attacker generates the configuration file, he or she can include any URLs they wish to monitor.
		 * When any of these URLs are visited, the threat gathers any user names and passwords typed into these pages.
		 * In order to do this, it hooks the functions of various DLLs, taking control of network functionality.
		 * The following is a list of DLLs and the APIs within them that are used by Trojan.Zbot:
		 *
		 * WININET.DLL
		 *
		 * HttpSendRequestW
		 * HttpSendRequestA
		 * HttpSendRequestExW
		 * HttpSendRequestExA
		 * InternetReadFile
		 * InternetReadFileExW
		 * InternetReadFileExA
		 * InternetQueryDataAvailable
		 * InternetCloseHandle
		 *
		 *
		 * WS2_32.DLL and WSOCK32.DLL
		 *
		 * send
		 * sendto
		 * closesocket
		 * WSASend
		 * WSASendTo
		 *
		 *
		 * USER32.DLL
		 *
		 * GetMessageW
		 * GetMessageA
		 * PeekMessageW
		 * PeekMessageA
		 * GetClipboardData
		 */
	
		$this->ssTitre("Source code Zeus");
		$this->net("https://github.com/Visgean/Zeus");
		$this->pause();
		$this->net("https://zeustracker.abuse.ch/monitor.php");
		$this->net("https://zeustracker.abuse.ch/statistic.php");
		$this->pause();
		$this->ssTitre("Zeus How it works");
		$this->net("http://www.secureworks.com/cyber-threat-intelligence/threats/zeus/");
		$this->pdf("zeus_install.pdf", 15);
		$this->vdo("zeus_work.mp4", 36, 230);
		$this->article("Zeus Functionality", "The main purpose of Zeus is to steal online credentials as specified by the hacker. Zeus performs four main actions:
•	 Gathering system information.
•	 Stealing protected storage information, FTP passwords, and POP3 passwords.
•	 Stealing online credential information as specified by a configuration file.
•	 Contacting the command and control server for additional tasks to perform.	");
		$this->pause();
		$this->article("System Information Gathering", "By default Zeus will automatically gather a variety of system information and send this information to the com-
mand and control server. This information includes:
•	 A unique bot identification string
•	 Name of the botnet
•	 Version of the bot
•	 Operating system version
•	 Operating system language
•	 Local time of the compromised computer
•	 Uptime of the bot
•	 Last report time
•	 Country of the compromised computer
•	 IP address of the compromised computer
•	 Process names");
		$this->ssTitre("More Information about functionality");
		$this->net("http://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/zeus_king_of_bots.pdf");
		$this->pause();
		$this->pause();
		$this->ssTitre("In 2013 Hamza Bendelladj");
		$this->net("http://en.wikipedia.org/wiki/Zeus_%28trojan4win_horse%29");
		$this->net("http://www.jeuneafrique.com/Article/JA2715p048_049.xml2/algerie-usa-fbi-algeralgerie-hamza-bendelladj-cracker-indecryptable.html");
		$this->vdo("hamza_bendelladj.mp4", 5, 80);
		$this->pause();
		$this->ssTitre("Alias of Zeus Trojan");
		$this->article("Zeus Alias", "The Zeus banking trojan is also known as Zbot, WSNPOEM, NTOS and PRG\nThe ZEUS trojan will commonly use names like NTOS.EXE, LD08.EXE, LD12.EXE, PP06.EXE, PP08.EXE, LDnn.EXE and PPnn.EXE etc, so search your PCs for files with names like this. The ZEUS Trojan will typically be between 40KBytes and 150Kbytes in size.
Also look for a folder with the name WSNPOEM, this is also a common sign of infection for the ZEUS Trojan.");
		$this->net("http://upload.wikimedia.org/wikipedia/commons/2/2d/FBI_Fraud_Scheme_Zeus_Trojan.jpg");
		$this->pause();
	
		/*
		 *
		 * note("d'apres nestat -> IP ");
		 * net("https://www.virustotal.com/fr/ip-address/193.104.41.75/information/");
		 * note("d'apes psxview");
		 * // 0x069a7328 VMip.exe 1944 False True False False False False False
		 * note("d'apres psxview + graph");
		 * // PIDs: 1944 124 1668 1724 452 432
		 *
		 * Injection MZ
		 * System 4 0x1a0000
		 * System 4 0x170000
		 * System 4 0x1d0000
		 * winlogon.exe 632 0xae0000
		 * services.exe 676 0x7e0000
		 * lsass.exe 688 0xa10000
		 * vmacthlp.exe 844 0x640000
		 * svchost.exe 856 0xb70000
		 * svchost.exe 936 0x8d0000
		 * svchost.exe 1028 0x2450000
		 * svchost.exe 1088 0x8b0000
		 * svchost.exe 1148 0x9f0000
		 * spoolsv.exe 1432 0x920000
		 * vmtoolsd.exe 1668 0x15e0000
		 * VMUpgradeHelper 1788 0x930000
		 * TPAutoConnSvc.e 1968 0xdf0000
		 * alg.exe 216 0x7b0000
		 * wscntfy.exe 888 0x800000
		 * TPAutoConnect.e 1084 0xc50000
		 * wuauclt.exe 1732 0x1000000
		 * explorer.exe 1724 0x15d0000
		 * VMwareTray.exe 432 0xd70000
		 * VMwareUser.exe 452 0x1530000
		 * wuauclt.exe 468 0x12d0000
		 * // PIDs: 4 632 676 688 844 856 936 1028 1088 1148 1432 1668 1788 1968 216 888 1084 1732 1724 432 452 468
		 * suspect File in MZ (strings) : -> Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)
		 *
		 *
		 *
		 */
	
	
	
	
		// investigation_win_pid($rep_path,$vmem,$profile,$pid);pause();
	
		// os_imageinfo($vmem);pause();
		investigation_win_malware("");
		$this->pause();
		titre("Search for Persistance");
		win_run_start($rep_path, $vmem, $profile);
		$this->pause();
		$this->ssTitre("Investigation in File sdra64.exe");
		$this->article("Our Trojan", "We can see sdra64.exe will run when the computer starts. It seems to be a trojan");
		$this->ssTitre("Voir si il y'a des cas similaires comme le mien");
		net_search("sdra64.exe");
		$this->pause();
		win_file_dump_name("sdra64.exe");
		virustotal_scan("$dir_tmp/file.632.0xff37f270.dat");
		sandbox_scan("$dir_tmp/file.632.0xff37f270.dat");
	
		os_connection_list($rep_path, $vmem, $profile);
		titre("In Connection Scan");
		ip2malw($rep_path, "193.104.41.75");
		$this->ssTitre("More information about PID=$pid for this connection");
		win_process_tree_filter("");
		win_process_tree_filter("| grep $pid");
		note("winlogon.exe 632 -> services.exe 676 -> svchost.exe 856  -> see graphe");
		$this->pause();
		win_process_graphic($rep_path, $vmem, $profile);
		note("We can see that svchost.exe is the process which is making connections with 193.104.47.75 instead of an Internet Browser");
		win_process_malware_search($pid);
		virustotal_scan("$dir_tmp/process.0x80ff88d8.0xb70000.dmp");
		note("It looks for winlogon.exe, increases its privileges, injects its code and a string table into this process, and creates a thread to execute this code.
	The injected code in winlogon injects additional code into svchost.exe.
	It also creates a folder named %System%\lowsec and puts two files inside: local.ds and user.ds.
	Local.ds is the latest dynamic configuration file downloaded from the server.
	User.ds contains stolen credentials and other information to be transmitted to the server.");
		remarque("If Zeus is run using an account that does not have Administrator privileges, code will not be injected into winlogon.exe, but instead into explorer.exe.
	Also, instead of copying itself to the %System% folder, the bot will copy itself to %UserProfile%\Application Data\sdra64.exe, and create the folder %UserProfile%\Application Data\lowsec.
	Finally, the bot will create a load point under the registry key HKEY _ CURRENT _ USER\Software\Microsoft\Windows\CurrentVersion\Run\”userinit”=” %UserProfile%\Application Data\sdra64.exe”.");
		$this->pause();
	
		os_display_all_object($rep_path, $vmem, $profile);
		$this->requette("python /opt/volatility/vol.py -f $vmem mutantscan | grep _AVIRA_21");
		$this->pause();
		net_search("_AVIRA_21");
		note(" The communication between these various injected components is done with mutexes and pipes, maliciously named _AVIRA_x, where x is a number (eg: x=2109 in winlogon.exe, x=2108 in svchost.exe).");
		$this->net("http://www.fortiguard.com/encyclopedia/virus/#id=894653");
		$this->pause();
		win_print_registre_value($rep_path, $vmem, "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Cache\Paths");
		win_print_registre_value($rep_path, $vmem, "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Cache\Paths\path2"); // {1,2,3,4}
		win_print_registre_value($rep_path, $vmem, "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Network");
		os_find_hidden_code_dll($vmem);
	
		$this->requette("python /opt/volatility/vol.py -f $vmem --profile=$profile malfind -p $pid -Y MalwareRules.yara ");
		$this->requette("python /opt/volatility/vol.py -f $vmem --profile=$profile yarascan -y MalwareRules.yara ");
		$this->requette("python /opt/volatility/vol.py -f $vmem --profile=$profile userassist");
		// send sdra64.exe to virustotal
		$this->ssTitre("Zeus Source Code");
		$this->img("bof/ArchInternalDependencies-DirectoryStructure-Zeus.png");
		$this->requette("ls $this->dir_tools/bof/ZeuS.tar.bz2");
		$this->pause();
		$this->net("http://en.wikipedia.org/wiki/Gameover_ZeuS");
		$this->net("http://blog.fortinet.com/Lite-Zeus-----A-New-Zeus-Variant/");
		$this->pause();
		$this->ssTitre("Zeus Childs");
		$this->article("Zeus Childs", "spyeye");
		$this->ssTitre("Kins");
		$this->net("https://blogs.rsa.com/is-cybercrime-ready-to-crown-a-new-kins-inth3wild/");
	}
	
	

	function worm4win_conficker() {
		/*
		 * Intrusion Detection Signatures
		 *
		 * Conficker uses a hardcoded xor-key for encoding its shellcode. This creates static patterns, which allow to detect exploitation attempts and may be used to identify infected machines. The signature we have created for Conficker.A and .B are:
		 *
		 * Conficker.A
		 *
		 * alert tcp any any -> $HOME_NET 445 (msg:
		 * "conficker.a shellcode"; content: "|e8 ff ff ff ff c1|^|8d|N|10
		 * 80|1|c4|Af|81|9EPu|f5 ae c6 9d a0|O|85 ea|O|84 c8|O|84 d8|O|c4|O|9c
		 * cc|IrX|c4 c4 c4|,|ed c4 c4 c4 94|&<O8|92|\;|d3|WG|02 c3|,|dc c4
		 * c4 c4 f7 16 96 96|O|08 a2 03 c5 bc ea 95|\;|b3 c0 96 96 95 92
		 * 96|\;|f3|\;|24|i| 95 92|QO|8f f8|O|88 cf bc c7 0f f7|2I|d0|w|c7 95
		 * e4|O|d6 c7 17 f7 04 05 04 c3 f6 c6 86|D|fe c4 b1|1|ff 01 b0 c2 82 ff b5
		 * dc b6 1b|O|95 e0 c7 17 cb|s|d0 b6|O|85 d8 c7 07|O|c0|T|c7 07 9a 9d 07
		 * a4|fN|b2 e2|Dh|0c b1 b6 a8 a9 ab aa c4|]|e7 99 1d ac b0 b0 b4 fe eb
		 * eb|"; sid: 2000001; rev: 1;)
		 *
		 * Conficker.B
		 *
		 * alert tcp any any -> $HOME_NET 445 (msg: "conficker.b shellcode";
		 * content: "|e8 ff ff ff ff c2|_|8d|O|10 80|1|c4|Af|81|9MSu|f5|8|ae c6 9d
		 * a0|O|85 ea|O|84 c8|O|84 d8|O|c4|O|9c cc|Ise|c4 c4 c4|,|ed c4 c4 c4
		 * 94|&<O8|92|\;|d3|WG|02 c3|,|dc c4 c4 c4 f7 16 96 96|O|08 a2 03
		 * c5 bc ea 95|\;|b3 c0 96 96 95 92 96|\;|f3|\;|24 |i|95 92|QO|8f f8|O|88
		 * cf bc c7 0f f7|2I|d0|w|c7 95 e4|O|d6 c7 17 cb c4 04 cb|{|04 05 04 c3 f6
		 * c6 86|D|fe c4 b1|1|ff 01 b0 c2 82 ff b5 dc b6 1f|O|95 e0 c7 17 cb|s|d0
		 * b6|O|85 d8 c7 07|O|c0|T|c7 07 9a 9d 07 a4|fN|b2 e2|Dh|0c b1 b6 a8 a9 ab
		 * aa c4|]|e7 99 1d ac b0 b0 b4 fe eb eb|"; sid: 2000002; rev: 1;)
		 * Conficker Domain Name Generation
		 *
		 * Different Conficker variants are checking different domains for updates every day. Conficker.A and .B already generate and check 250 domains each per day. Conficker.C will start checking for 50.000 generated domain names on April 1st.
		 */
	
		$this->net("https://technet.microsoft.com/library/security/ms08-067");
		$this->ssTitre("9 Million PCs ");
		$this->net("http://www.switched.com/2009/01/20/tricky-windows-worm-spreads-to-9-million-pcs/");
	
		/*
		 article("Moris Worm","Depuis les années 1970, la communauté académique s'est intéressée à étudier les erreurs, vulnérabilités et défauts présents sur les systèmes informatiques. La documentation sur la faille de débordement de pile (« buffer overflow ») avait été rendue publique, du moins partiellement. En novembre 1988, un ver du nom de Morris avait infecté 10% des systèmes reliés à Internet. Ce ver s’était propagé en exploitant entre autres un « buffer overflow » sur le service « fingerd » sous Unix.");
		 */
	
	}
	
	function worm4win_cridex() {
	
		chapitre("WORM CRIDEX");
		$vmem = "$this->dir_tools/memory/WinXPSP2x86_Worm_cridex.vmem";
		$profile = "WinXPSP2x86";
		$pid = "1484,1640"; // explorer.exe
	
		$this->ssTitre("Analysis");
		$this->net("http://www.microsoft.com/security/portal/threat/encyclopedia/entry.aspx?Name=Win32%2fCridex#tab=2");
		$this->net("http://stopmalvertising.com/malware-reports/analysis-of-dridex-cridex-feodo-bugat.html");
		$this->net("http://blog.malwaremustdie.org/2013/01/cridex-fareit-infection-analysis.html");
		$this->net("https://devcentral.f5.com/articles/malware-analysis-report-cridex-cross-device-online-banking-trojan");
		$this->net("http://sempersecurus.blogspot.com/2012/08/cridex-analysis-using-volatility.html");
		$this->net("http://www.deependresearch.org/2012/10/blackhole-cridex-season-2-episode-1.html");
	
		// C:\Documents and Settings\Robert\Application Data\KB00207877.exe
	
		/*
		 * reader_sl.exe, PID1640 start exactly at the same time as its parent process, explorer.exe, PID1484
		 * Cridex copies itself as KB00[random_numbers].exe in the C:\Documents and Settings\[UserName]\Application Data folder.
		 */
	
		investigation_win_first($rep_path, $vmem, $profile);
		$this->pause();
		// investigation_win_pid($rep_path,$vmem,$profile,$pid);pause();
	}
	
	
	function worm4win_stuxnet() {
	
		chapitre("WORM Stuxnet");
		$vmem = "$this->dir_tools/memory/WinXPSP3x86_Worm_Stuxnet.vmem";
		$profile = "WinXPSP3x86";
		$pid = "680,868,1928";
		$filter = "";
	
	
	
		$this->ssTitre("Stuxnet");
		$this->net("http://www.symantec.com/security_response/writeup.jsp?docid=2010-071400-3123-99");
		$this->net("http://arstechnica.com/security/2013/02/new-version-of-stuxnet-sheds-light-on-iran-targeting-cyberweapon/");
		$this->net("http://www.symantec.com/security_response/writeup.jsp?docid=2010-071400-3123-99&tabid=2");
		$this->pause();
	

		process_list($vmem);
		process_tree($vmem);
		$this->article("Trojan", "we know that malware mostly have a command and control structure, once they infect a system they need to connect back to the command center.
	Knowing that, we now need to look at the network connections established by the malware.
	We can find out about any established connections");
		process_connection_list($vmem);
		$this->article("lsass.exe", "a normal Windows XP installation has just one instance of Lsass.exe that the Winlogon process creates when the system boots (Wininit creates it on Windows Vista and higher).
	The process tree reveals that the two new Lsass.exe instances were both created by Services.exe...the Service Control Manager, which implies that Stuxnet somehow got its code into the Services.exe process.");
		$this->requette("python /opt/volatility/vol.py -f $vmem --profile=$profile pstree | grep -i 'lsass.exe' ");
		$this->pause();
		$this->requette("python /opt/volatility/vol.py -f $vmem --profile=$profile getsids --pid=680,868,1928 ");
		$this->pause();
		$this->article("Process Priority", "...some Windows system processes (such as the Session Manager, service controller, and local security authentication server) have a base process priority slightly higher than the default for the Normal class");
		$this->requette("python /opt/volatility/vol.py -f $vmem --profile=$profile volshell | egrep (\"680|868|1928\") ");
		$this->article("notice", "As you can see, the BasePriority of the legit lsass.exe (pid 680) is 9, whereas the ones created by Stuxnet are 8.");
		$this->pause();
		$this->requette("python /opt/volatility/vol.py -f $vmem --profile=$profile threads --pid=680,868,1928 ");
		$this->pause();
		$this->requette("python /opt/volatility/vol.py -f $vmem --profile=$profile dlllist --pid=680,868,1928 ");
		$this->pause();
		$this->article("Injected Code", "No non-Microsoft DLLs show up in the loaded-module lists for Services.exe, Lsass.exe or Explorer.exe, so they are probably hosting injected executable code. [....] Sure enough, the legitimate Lsass has no executable data regions, but both new Lsass processes have regions with Execute and Write permissions in their address spaces at the same location and same size.");
		$this->requette("python /opt/volatility/vol.py -f $vmem --profile=$profile malfind --pid=680,868,1928 ");
		$this->pause();
		$this->requette("python /opt/volatility/vol.py -f $vmem --profile=$profile procexedump --pid=680,868,1928 --output-dir=$dir_tmp/");
		$this->pause();
		$this->article("legit lsass.exe", "Here are the strings (ANSI only) from the legit lsass.exe");
		$this->requette("strings $dir_tmp/executable.680.exe $dir_tmp/executable.680.txt");
		$this->pause();
		$this->article("malicious lsass.exe", "Here are the strings from one of the malicious lsass.exe");
		$this->requette("strings $dir_tmp/executable.868.exe $dir_tmp/executable.868.txt");
		$this->pause();
		$this->requette("diff $dir_tmp/executable.680.txt $dir_tmp/executable.868.txt");
		$this->pause();
		$this->article("", "");
		$this->requette("");
		$this->pause();
		$this->article("", "");
		$this->requette("");
		$this->pause();
		$this->article("", "");
		$this->requette("");
		$this->pause();
		$this->article("", "");
		$this->requette("");
		$this->pause();
		$this->article("", "");
		$this->requette("");
		$this->pause();
		$this->article("", "");
		$this->requette("");
		$this->pause();
		$this->article("", "");
		$this->requette("");
		$this->pause();
		$this->requette("");
		$this->pause();
		$this->requette("");
		$this->pause();
		$this->requette("python /opt/volatility/vol.py -f $vmem callbacks | grep mrx");
		$this->ssTitre("stuxnet Childs");
		$this->article("stuxnet Childs", "Flame");
		$this->net("http://lexpansion.lexpress.fr/high-tech/flame-et-stuxnet-partagent-du-code-source_1395575.html");
		$this->net("http://www.symantec.com/connect/blogs/flamer-highly-sophisticated-and-discreet-threat-targets-middle-east");
		$this->pause();
		$this->ssTitre("A Trojan|Virus never Dead - there is always other replic");
		$this->img("trojan/malware_never_dead.jpg");
		$this->pause();
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
?>