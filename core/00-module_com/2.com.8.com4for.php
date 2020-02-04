<?php
/*
 Disable your Linux firewall by running:
 # iptables -F
 Disable your Windows firewall by running:
 C:\> netsh firewall set opmode disable
 Or
 C:\> netsh advfirewall set aliprofiles state off
 (For Windows 8+ systems)
 */
/*
 * http://tools.kali.org/reporting-tools/dradis
 */

// flame inject code into iexplorer.exe to connect to windowsupdate.microsoft.com to first test the connection
// faire une etude de duqu trojan

/*
 *
 *
 • utmp: file contains info about currently logged in users
—
Default location on Linux: /var/run/utmp
• wtmp: File contains data about past user logins
Default location on Linux: /var/log/wtmp
• btmp: File contains bad login entries for failed login
attempts
—
Default location on Linux: /var/log/btmp, but often not used
• lastlog: File shows login name, port, and last login time for
each user
—
Default location on Linux: /var/log/lastlog


 *
 *
 * ssTitre("File Signature");
 * net("http://en.wikipedia.org/wiki/List_of_file_signatures");
 *
 *
 * rohff@labs:~/EH/CODE/EH_PHP$ jp2a /home/rohff/EH/IMG/graphic_step_1_gathering_info.png
 * Not a JPEG file: starts with 0x89 0x50
 *
 *
 * gdb> set disassembly-flavor intel|att
 * set follow-fork-mode parent|child : Tells the debugger to follow the child or parent process.
 * set variable *(address)=value Stores value at the memory location specified by address.
 *
 *
 * Voir :
 * Software\Microsoft\Command Processor\AutoRun
 * Software\Microsoft\Windows\CurrentVersion\Runonce
 * Software\Microsoft\Windows\CurrentVersionetwork X
 * Classes\.exe\shell\open\command
 * Classes\exefile\shell\open\command
 * Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
 * Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects
 * Software\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler
 * Software\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad
 *
 * $  ldconfig -p -> List de tous les libraries on Host
 *
 *
 *
 *
 *
 * Open Source
 * ssTitre("Yara Malware Analysis");
 * net("http://plusvic.github.io/yara/");
 * net("http://www.emc.com/security/rsa-ecat.htm"); -> use yara
 * net("https://www.fox-it.com/en/");
 * net("http://www.bluecoat.com/products/malware-analysis-appliance");
 * net("http://www.fireeye.com/");
 * ssTitre("Sandbox");
 * net("http://www.lastline.com/");
 * net("http://www.threatmetrix.com/threatmetrix-labs/web-fraud-map/");
 *
 * ssTitre("test PEid2yara");
 * requette("upx -1 -o setup_upx.exe setup.exe");
 * requette("$this->dir_tools/av/yara/yara $this->dir_tools/av/peid2yara.yara setup_upx.exe");
 * //pause();
 */

/*
 * http://totalhash.com/search/mutex:*dc*_mutex*
 *
 * C:\Volatility>python vol.py -f Bob.vmem filelist -p 1752 -F DataSectionObject,HandleTable
 * C:\Volatility>python vol.py -f Bob.vmem virustotal -p 1752 -F DataSectionObject,HandleTable
 *
 *
 * http://securityxploded.com/malware-analysis-training-reference.php
 * http://www.moonsols.com/windows-memory-toolkit/
 *
 * other ways that malware tries to hide injected code and how to detect the attacks
 * – Remote library injection
 * – Remote shellcode injection
 * – Reflective DLL loading
 * – Process hollowing
 *
 * Injected DLLs can be extracted with dlldump and injected shellcode with vaddump
 *
 *
 *
 *
 * http://sourceforge.net/mirror/volatility/code/HEAD/tree/wiki/FAQ.wiki
 * http://fr.slideshare.net/brendangregg/velocity-2015-linux-perf-tools
 *
 * Extract and check the file with these commands in Linux:
 * 7z e memdump.7z
 *
 *
 * services.exe, svchost.exe, notepad.exe, winlogon.exe, explorer.exe, iexplore.exe
 *
 * // + dump memory process + search with strings : strings dump_856.dmp | grep -ni 'http' | sort | uniq
 *
 * Registry Hives : Table of standard hives and their supporting files
 * Registry hive Supporting files
 * HKEY_CURRENT_CONFIG System, System.alt, System.log, System.sav
 * HKEY_CURRENT_USER Ntuser.dat, Ntuser.dat.log
 * HKEY_LOCAL_MACHINE\SAM Sam, Sam.log, Sam.sav
 * HKEY_LOCAL_MACHINE\Security Security, Security.log, Security.sav
 * HKEY_LOCAL_MACHINE\Software Software, Software.log, Software.sav
 * HKEY_LOCAL_MACHINE\System System, System.alt, System.log, System.sav
 * HKEY_USERS\.DEFAULT Default, Default.log, Default.sav
 *
 *
 *
 *
 * Spyeye:
 * pslist | grep ------ (dans le handles)
 * pstree | grep ------ (dans le handles)
 * malfind -p (ppid dessus)
 * une fois MZ trouver -> malfind -p (ppid dessus) + yarascan + virustotal
 * lors du malfind -> on trouve MZ -> cest pas la peine de tout dumper, il suffit de cibler par ladresse -> dlldump --base (adresse trouver dans MZ du malfind)
 * apres malfind faire toujours dlllist pour voir d eventuelle dll suspects -> puis dlldump en cas ou en trouve qlq chose de suspect
 *
 * scan yara comme clamav: yara -r file.yara ./rep
 *
 * apihook: sert a trouver les CreateThread, copieFileW...etc -> lors du create suivre le jump puis le dumper normalememt on va trouver un MZ -> chercher du cote du copyFileA + volshell dis(addr-0x1000) -> pour dumper ladresse exact (addr-0x1000) on fait un dump de vaddump du pid puis on repere notre adresse = malfind
 * matascan-online.com
 * rajouter -> python vol.py iehistory -> dans le cas ou on trouve qlq chose dans connscan
 * puis : The OpenSaveMRU key tracks whether or not a file has been opened or saved via the windows shell.
 * python vol.py printkey -K "Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU\exe"
 * the LastVisitedMRU reg key tracks the executables used to open the files in OpenSaveMRU and also the last file path used.
 * python vol.py printkey -K "Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU"
 *
 * python vol.py netscan -> netstat -tupan
 * python vol.py yarascan -p 3932,3908,1912 -Y "192.168.81"
 *
 * Where is the backdoor placed on the file system?
 * $ python vol.py filescan |grep HOtdFs.exe
 *
 * malfind: You can see here that HOtdFs.exe and notepad.exe processes have multiple code injection points. (MZ)
 *
 * What level of privileges did the attacker obtain?
 * $ python vol.py getsids
 *
 * What time was the attack delivered?
 * $ python vol.py userassist > /home/sansforensics/Desktop/user.txt
 *
 * volatility psxview
 * No hidden processes are on the list (there would be ‘False’ in pslist or psscan column), couple of them however looks interesting
 *
 * pslist, psscan, pstree :‘-------’ indicate that processes were already paged and we’ll not be able to simply dump them. Let’s check if psscan will find our missing parent
 *
 * Virtual Address Descriptor (VAD)
 * The VAD is a kernel data structure that describes the allocated memory pages of a process, e.g. loaded modules, mapped files or private heap
 * VAD parsing to find injected code with “malfind” Regular loaded libraries in the address space of a process are of type _MMVAD or _MMVAD_LONG
 * Dynamically allocated memory pages created via VirtualAllocEx/WriteProcessMemory are of type _MMVAD_SHORT
 * If these memory pages additionally are marked as PAGE_EXECUTE_READWRITE, this is a good indication
 * for the malfind feature to write this page to a dump directory With the YARA library in combination further malware
 * indicators could be detected
 */

// svn checkout https://github.com/plusvic/yara
/*
 * titre("Antivirus On Linux");
 * ssTitre("ClamAV");
 * net("");
 * ssTitre("YARA");
 * net("");
 * ssTitre("AVG");
 * net("https://help.ubuntu.com/community/Antivirus/Avg");
 * ssTitre("AntiVir");
 * net("http://wiki.ubuntuusers.de/AntiVir");
 * ssTitre("BitDefender");
 * net("http://wiki.ubuntuusers.de/BitDefender");
 *
 *
 * win_threads($rep_path,$vmem, $profile, "-F SystemThread $filter"); -> rootkit
 *
 * //$tab_vmem = array("$this->dir_tools/memory/linux-sample-1.bin","$this->dir_tools/memory/linux-sample-2.bin","$this->dir_tools/memory/linux-sample-3.bin","$this->dir_tools/memory/linux-sample-4.bin","$this->dir_tools/memory/linux-sample-5.bin","$this->dir_tools/memory/linux-sample-6.bin");
 * $tab_vmem = array("$this->dir_tools/memory/","$this->dir_tools/memory/","$this->dir_tools/memory/linux-sample-1.bin","$this->dir_tools/memory/linux-sample-2.bin","$this->dir_tools/memory/linux-sample-3.bin","$this->dir_tools/memory/linux-sample-4.bin","$this->dir_tools/memory/linux-sample-5.bin","$this->dir_tools/memory/linux-sample-6.bin");
 * //$tab_vmem = array_reverse($tab_vmem);
 */










// TEST Profile
// for i in `vol.py --info | grep -i profile | grep -i win | cut -d' ' -f1`;do echo -e "test Profile $i\n"; python /opt/volatility/trunk/vol.py --location=file:///home/rohff/EH/TOOLS/memory/sample001.bin --profile=$i netscan ;done
/*
 * time : (/urs/bin/time) obtenir un rapport d'exécution,
 * : temps de calculs et bien d'autres choses.
 * : /usr/bin/time -a -o mesures.txt prog.exe
 *
 * mtrace -> heap - malloc trace
 * ltrace -> libraries trace
 * strace -> syscall trace
 *
 * http://hack-tools.blackploit.com/2014/02/collection-of-free-computer-forensic.html
 *
 * Sample List of Malware Analysis Tools:
 * System Monitor, Process Explorer, CaptureBAT, Regshot, VMware
 * BinText, LordPE, QuickUnpack, Firebug, PELister, PEiD
 * IDA Pro, OllyDbg and plug-ins such as OllyDump, HideOD
 * Rhino, Malzilla, SpiderMonkey, Jsunpack-n
 * Internet Explorer Developer Toolbar, cscript
 * Honeyd, NetCat, Wireshark, curl, wget, xorsearch
 * OfficeMalScanner, OffVis, Radare, FileInsight
 * Volatility Framework and plug-ins such as malfind2 and apihooks
 * SWFTools, Flare, shellcode2exe, fake DNS server, and others
 */


class com4for extends com4code{
	
	

    public function __construct() {
	parent::__construct();
	

	}
	
	public function vol2start($profile){
	    if(!is_dir("$this->file_dir/$this->file_name")) system("mkdir $this->file_dir/$this->file_name");
	    $this->file_dir = "$this->file_dir/$this->file_name";
	    if(!file_exists("/opt/volatility/vol.py")) $this->install_for_volatility();
	    $check = $this->vol2info("-i Profile | grep -Po $profile ");
	    if(empty($check)) return $this->rouge("Profile $profile DOES NOT EXIST");
	    
	}
	
	public function os_imageinfo_more() {
	$this->article("kdbgscan", "Search for and dump potential KDBG values");
	$this->vol2exec("kdbgscan","", $filter);
	$this->article("kpcrscan","Search for and dump potential KPCR (Kernel Processor Control Region) values");
	$this->vol2exec("kpcrscan","", $filter);
	$this->vol2exec("profilescan","", $filter);
	}
	public function os_imageinfo() {
	$cmd = "imageinfo";
	return $this->vol2exec($cmd,"", $filter);
	}
	public function os_profile() {
	$this->os_imageinfo();
	$this->os_imageinfo_more();
	}


	public function vmem2bulk(){
	$query = "bulk_extractor $this->file_path -o $this->file_dir ";
	if (!file_exists("$this->file_dir/packets.pcap")) $this->requette($query); else $this->cmd("localhost",$query);
	$this->requette("ls $this->file_dir");
	}
	

	public function vmem2rekal(){
	$query = "rekal -f $this->file_path ";
	$this->cmd("localhost",$query);
	}
	
	/*
	 * 	 The malicious PDF file resides in the Adobe Reader process address space. Adobe Reader’s
	 memory can be dumped with volatility.
	 python volatility memdmp -f images/hn_forensics.vmem -p 1752
	 * Using the forensics tool Foremost 1 , the possible PDF files can be extracted from the memory dump.
	 foremost -i 1752.dmp -t pdf -o output
	 */

	public function vmem2win(){
	$all_cmd = $this->vol2list();
	foreach ($all_cmd as $cmd)
	    if (!empty($cmd)) $this->vol2exec($cmd,"","");
	}
	
	 
    
    public function volatility_download() {
        $this->net("https://code.google.com/p/volatility/downloads/list");
        $this->net("http://www.cfreds.nist.gov/mem/memory-images.rar");
        $this->net("https://code.google.com/p/volatility/wiki/SampleMemoryImages");
        $this->pause();
    }
    public function volatility_challenge() {
        $this->net("http://www.honeynet.org/challenges");
    }
    public function volatility_intro() {
        $this->article("forensics", "False positives could be caused by security software like HIPS, AV or personal firewalls,
as they act in a very similar way malware does. \nThe only way to be 100% sure if the code is malicious or not the investigator has
to disassemble the dumped code resp. alerted functions 	");
        $this->ssTitre("Command Reference");
        $this->net("https://code.google.com/p/volatility/wiki/CommandReference");
        
        $this->ssTitre("Memo");
        $this->cmd("localhost", "firefox -new-tab http://forensicmethods.com/wp-content/uploads/2012/04/Memory-Forensics-Cheat-Sheet-v1.pdf");
        
        $this->img("bof/volatility.png");
    }
    
    

	public function vol2info($cmd){
	$file_output = "$this->file_dir/$this->file_name.".__FUNCTION__;
	if (!file_exists($file_output)) $this->requette("python /opt/volatility/vol.py --info > $file_output");
	return $this->req_ret_str("cat $file_output | grep $cmd | tail -1 ");
	}
	

	
	public function vol2exec4xlsx($cmd,$profile){
	$cmd = trim($cmd);
	$file_output = "$this->file_dir/$this->file_name.$cmd";
	$query = "python /opt/volatility/vol.py --location=file://$this->file_path --profile=$profile $cmd -v --output=xlsx  --output-file=$file_output.xlsx";
	if (file_exists("$file_output.xlsx")) $this->cmd("localhost", $query); else $this->requette($query);
	exec("cat $file_output.xlsx 2>/dev/null ",$tmp);
	if(!empty($tmp[0])) {
	$this->requette("xlsx2csv $file_output.xlsx $file_output.csv");
	if (file_exists("$file_output.csv")){
	$this->requette("cat $file_output.csv");
	$csv_file = new file("$file_output.csv");
	$csv_file->file_csv2dot("$file_output.csv");
	return file("$file_output.csv");
	}
	}
	}
	
	
	public function vol2exec4dot($cmd,$profile){
	$cmd = trim($cmd);
	$file_output = "$this->file_dir/$this->file_name.$cmd";
	$query = "python /opt/volatility/vol.py --location=file://$this->file_path --profile=$profile $cmd -v --output=dot  --output-file=$file_output.xdot";
	if (file_exists("$file_output.dot")) $this->cmd("localhost", $query); else $this->requette($query);
	exec("cat $file_output.xdot 2>/dev/null ",$tmp1);
	if(!empty($tmp1[0])) $this->dot2xdot("$file_output.xdot");
	}

	
	public function vol2list(){
	$file_output = "$this->file_dir/$this->file_name.".__FUNCTION__;
	$query = "python /opt/volatility/vol.py -h | grep -A200 'Supported Plugin Commands:' | tr -d \"\t\" | grep -Po \"^[a-z]{1,}\" | tee $file_output";
	if (!file_exists($file_output)) return $this->req_ret_tab($query);
	return file($file_output);
	}
		public function volatility_profile_listing($filter) {
	$this->requette("python /opt/volatility/vol.py --info | grep Profile $filter");
	}
	

	public function vol2exec4txt($cmd,$profile, $filter) {
		$this->article("CMD TXT",$cmd);
		$this->article("FILTER TXT",$filter);
	$cmd = trim($cmd);
	$cmd_right_print = $cmd;
	$cmd_right_print = str_replace("  ", " ", $cmd_right_print);
	$cmd_right_print = str_replace(" ", "_", $cmd_right_print);
	$cmd_right_print = str_replace(",", "_", $cmd_right_print);
	$cmd_right_print = str_replace("-", "_", $cmd_right_print);
	$cmd_right_print = str_replace("/", "_", $cmd_right_print);
	$cmd_right_print = str_replace("\\", "_", $cmd_right_print);
	$cmd_right_print = str_replace("\"", "", $cmd_right_print);
	$file_output = "$this->file_dir/$this->file_name/$this->file_name.$cmd_right_print";
	$query = "vol.py --location=file://$this->file_path --profile=$profile $cmd_right_print -v $filter | tee $file_output";
	if (file_exists("$file_output")) {$this->cmd("localhost", $query); $this->requette("cat $file_output $filter");return $file_output;}else {$this->requette("$query $filter");return $file_output;}	
	}
	
	
	public function vol2exec($cmd,$profile, $filter) {
	$this->article("CMD",$cmd);
	$this->article("FILTER",$filter);
	$cmd = "$cmd ";
	exec("echo '$cmd' | cut -d ' ' -f1 ",$tmp1);
	$cmd_left = trim($tmp1[0]);
	$check = $this->vol2info($cmd_left);
	if(empty($check)) {$this->rouge("$cmd_left DOES NOT EXIST MAYBE YOU DO NOT HAVE SCRIPT");return "";}
	$file_output = "$this->file_dir/$this->file_name.$cmd_left";
	  
	$query = "vol.py --location=file://$this->file_path --profile=$profile $cmd | tee $file_output ";
	if (file_exists("$file_output")) {
	    //if ( filesize( $file_output )==0 ) {system("rm $file_output");$this->requette("$query $filter");return $file_output;}
		$this->cmd("localhost", $query); 
		//sleep(1);
		$this->requette("cat $file_output $filter");
		//$this->pause();
		return $file_output;
			}
	else {$this->requette("$query $filter");return $file_output;}	
	}
	

	public function filter_pid_check($filter) {
	if (! empty($filter)) {
	exec("echo '$filter' | grep 'pid' ", $tmp3);
	if (! empty($tmp3))
	return TRUE;
	else
	return FALSE;
	} else
	return FALSE;
	}
	public function filter_pid_get($filter) {
	$check_pid = $this->filter_pid_check($filter);
	if ($check_pid == TRUE) {
	exec("echo '$filter' | grep 'pid' | grep -Po \"pid=[[:print:]]{1,}\" | sed \"s/pid=//g\"  ", $tmp3);
	if (! empty($tmp3)) {
	$pid = trim($tmp3 [0]);
	unset($tmp3);
	return $pid;
	} else
	return "";
	} else
	return "";
	}
	public function filter_dumpdir_check($filter) {
	if (! empty($filter)) {
	exec("echo '$filter' | grep 'dump-dir' ", $tmp3);
	if (! empty($tmp3))
	return TRUE;
	else
	return FALSE;
	} else
	return FALSE;
	}
	

	
	
	public function volatility_profile_listing_os($os, $arch) {
	$this->ssTitre("GET $os PROFILE for $arch Architecture");
	$tmp = $this->req_ret_tab("python /opt/volatility/vol.py --info | grep Profile | grep -i \"$os\" | grep \"$arch$\" | cut -d ' ' -f1");
	$tab_profile = array_map('trim', $tmp);
	unset($tmp);
	return $tab_profile;
	}

	
	

	/*
	 *
	 * rohff@rohff-PC:~$ pgrep --help
	 *
	 * Usage:
	 * pgrep [options] <pattern>
	 *
	 * Options:
	 * -d, --delimiter <string> specify output delimiter
	 * -l, --list-name list PID and process name
	 * -v, --inverse negates the matching
	 * -w, --lightweight list all TID
	 * -c, --count count of matching processes
	 * -f, --full use full process name to match
	 * -g, --pgroup <id,...> match listed process group IDs
	 * -G, --group <gid,...> match real group IDs
	 * -n, --newest select most recently started
	 * -o, --oldest select least recently started
	 * -P, --parent <ppid,...> match only child processes of the given parent
	 * -s, --session <sid,...> match session IDs
	 * -t, --terminal <tty,...> match by controlling terminal
	 * -u, --euid <id,...> match by effective IDs
	 * -U, --uid <id,...> match by real IDs
	 * -x, --exact match exactly with the command name
	 * -F, --pidfile <file> read PIDs from file
	 * -L, --logpidfile fail if PID file is not locked
	 * --ns <pid> match the processes that belong to the same
	 * namespace as <pid>
	 * --nslist <ns,...> list which namespaces will be considered for
	 * the --ns option.
	 * Available namespaces: ipc, mnt, net, pid, user, uts
	 *
	 * -h, --help display this help and exit
	 * -V, --version output version information and exit
	 *
	 * For more details see pgrep(1).
	 */
	/*
	 * tripwire --check | mail -s "Tripwire report for `uname -n`" your_email@domain.com
	 */

	
	
	
	
	
	
	public function clone_disk() {
	$this->net("http://en.wikipedia.org/wiki/Comparison_of_disk_cloning_software");
	$this->net("http://en.wikipedia.org/wiki/Comparison_of_disc_image_software");
	}
	
	
	public function forensics_malware() {
	/*
	 * VMware Workstation
	 * If you decided to adopt VMware Workstation, you can take the snapshot from the graphical user interface or from the command line:
	 * $ vmrun snapshot "/your/disk/image/path/wmware_image_name.vmx" your_snapshot_name
	 * Where your_snapshot_name is the name you choose for the snapshot. After that power off the machine from the GUI or from the command line:
	 * $ vmrun stop "/your/disk/image/path/wmware_image_name.vmx" hard
	 *
	 *
	 */
	$this->img("Forensics.png");
	}
	
	
	
	
	
}
