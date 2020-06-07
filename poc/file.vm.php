<?php

/*
 * 	// dir C:\TMP /O:D /T:W /A:-D | findstr /C:"*.plt" | more +1
 * 
 * vmrun -T ws -gu USERNAME -gp PASSWORD runProgramInGuest "C:\Virtual Machines\WinXP2\WinXP2.vmx" %COMSPEC% "/c C:\batch.bat"
 * 
 * function vm($vm,$interface){
 * titre("Check VM");
 * exec("vmrun -T ws List | grep $vm",$resu_vm);
 * if(empty($resu_vm[0])){
 * $this->article("Lancement de la VM","$vm ...en cours");
 * $this->requette("vmrun -T ws start $vm");
 * sleep(5); }
 * else $this->article($vm,"deja lancee");
 * exec("vmrun readVariable $vm runtimeConfig ethernet0.vnet | grep $interface",$resu_net);
 * if(empty($resu_net[0])){
 * $this->article("Chargement d'interface","en $interface ...en cours");
 * // ça fonctionne, il faut juste plus de temps pour voir reellement
 * $this->requette("vmrun -T ws writeVariable $vm runtimeConfig ethernet0.vnet /dev/$interface ");
 * }
 * // Running a program in a virtual machine with Workstation on a Windows host with Windows guest
 * // vmrun -T ws -gu guestUser -gp guestPassword runProgramInGuest "c:\my VMs\myVM.vmx" "c:\Program Files\myProgram.exe"
 * // Running a program in a virtual machine with Server on a Linux host with Linux guest
 * // vmrun -T server -h https://myHost.com:8333/sdk -u hostUser -p hostPassword -gu guestUser -gp guestPassword runProgramInGuest "[standard] vm/myVM.vmx" /usr/bin/X11/xclock -display :0
 * // vmrun -T ws start /usr/local/VMs/<virtual_machine_name>.vmx
 * // vmrun -T ws captureScreen /usr/local/VMs/<virtual_machine_name>.vmx
 * // vmrun -T esx -h https://esx/sdk -u cody.bunch -p password -gu guest.user -gp guest.password runProgramInGuest "[datastore] vm/vmx.vmx" c:\windows\system32\route.exe add -p 192.168.100.0 mask 255.255.255.0 192.168.15.1
 * // vmrun -T ws -gu $user_local -gp $user_local captureScreen "/home/$user_local /Bureau/CEH/20_labs/lts.hack.form/lts.hack.form.vmx" "/home/$user_local /Bureau/CEH/capture.png"
 * // vmrun -T server -h https://hostname:8333/sdk -u root -p password list
 * // vmrun -T server -h https://hostname:8333/sdk -u root -p mypassword start "[standard] Maszyna1/Maszyna1.vmx"
 * }
 *
 * $user_local @labs:~/Bureau/CEH$ vmrun -T ws -gu "$user_local " -gp "hacker" runProgramInGuest /home/$user_local /vm/vmware/xp3/xp3.vmx cmd.exe "/c C:\WINDOWS\system32\ipconfig.exe > C:\vmip.txt"
 */
class VM extends BIN{
	var $vms_access ;
	var $vm_login;
	var $vm_pass;
	var $vmx_name ;
	var $vmx_path ;
	
	public function __construct($vmx_name) {
	    $this->vmx_name = trim($vmx_name);
	    $this->vmx_path = "/home/rohff/vmware/$this->vmx_name/$this->vmx_name.vmx";	    
	    $this->article("VMX PATH", $this->vmx_path);
	    $this->pause();
	    parent::__construct($this->vmx_path);



		
		$this->vms_access = array (
				"lts" => array (
						"rohff",
						"rohff"
				),
				"fw" => array (
						"admin",
						"rohff"
				),
				"msf" => array (
						"root",
						"rohff"
				),
				"xp3" => array (
						"XPSP3",
						"xpsp3"
				),
				"xp2" => array (
						"rohff",
						"rohff"
				),
				"xpsp3" => array (
						"XPSP3",
						"xpsp3"
				),
				"sdbx_xp3" => array (
						"XPSP3",
						"xpsp3"
				),
				"ossim" => array (
						"root",
						"rohff"
				),
				"onion" => array (
						"rohff",
						"rohff"
				),
				"dsl" => array (
						"root",
						"dsl"
				),
				"owasp" => array (
						"root",
						"owaspbwa"
				),
				"dvl" => array (
						"root",
						"toor"
				),
				"win7" => array (
						"rohff",
						"rohff"
				),
				"win7x86" => array (
						"rohff",
						"rohff"
				),
				"win08" => array (
						"rohff",
						"h4ck3r94#"
				),
				"win10" => array (
						"rohff",
						"rohff"
				),
				"ub1404" => array (
						"rohff",
						"rohff"
				),
		    "ub10040" => array (
		        "rohff",
		        "rohff"
		    ),
				"ub10040x86" => array (
						"rohff",
						"rohff"
				),
				"ub12042" => array (
						"rohff",
						"rohff"
				),
				"ub910" => array (
						"rohff",
						"rohff"
				),
				"win2012s" => array (
						"administrateur",
						"rohff94#"
				),
				"bof_xp" => array (
						"XPSP3",
						"xpsp3"
				),
				"xp3hd" => array (
						"XPSP3",
						"xpsp3"
				),
				"bof_win7" => array (
						"rohff",
						"rohff"
				),
				"bof_xp3" => array (
						"rohff",
						"hacker"
				),
				"win7sp1" => array (
						"rohff",
						"hacker"
				),
				"xp3_bof" => array (
						"rohff",
						"hacker"
				),
				"xp3bof" => array (
						"rohff",
						"hacker"
				),
				"ub14041" => array (
						"rohff",
						"rohff"
				),
				"win2008x86" => array (
						"rohff",
						"rohff"
				)
		);
		$this->vm_login = $this->vms_access["$this->vmx_name"][0];
		$this->vm_pass = $this->vms_access["$this->vmx_name"][1];
		

	}
	
	
public function vm2ipconfig() {
}

public function vm2process_list() {
	$this->ssTitre("List Program and Process On $this->vmx_path");
	$check = $this->vm2check_online();
	if ($check == FALSE) {
		$this->vm2start();
		$this->important("Waiting until Vm start");
		return $this->vm2process_list();
	}
	$this->requette("vmrun -T ws -gu $this->vm_login -gp $this->vm_pass listProcessesInGuest $this->dir_vm/$this->vmx_name/$this->vmx_name.vmx > $this->vm_tmp_win\\$this->vmx_name.prog.pid.lst");
	return "$this->vm_tmp_win\\$this->vmx_name.prog.pid.lst";
}

	
	function install_for_sandbox_cuckoo(){
		$this->ssTitre(__FUNCTION__);
		
		$this->note("cuckoo work under Python2 so use pip2 and python2 ");
		$this->requette("cd /opt/; sudo git clone https://github.com/cuckoosandbox/cuckoo.git");
		
		$this->requette("echo '$this->root_passwd' | sudo -S apt-get install -y python python-pip python-dev ");
		$this->requette("echo '$this->root_passwd' | sudo -S apt-get install -y libffi-dev libssl-dev libxml2-dev libxslt1-dev libjpeg-dev ");
		$this->requette("echo '$this->root_passwd' | sudo -S apt-get install -y libcap2-bin apparmor-utils swig");
		$this->requette("echo '$this->root_passwd' | sudo -S apt-get install -y samba-common-bin");
		$this->requette("echo '$this->root_passwd' | sudo -S -H pip2 install -r /opt/cuckoo/requirements.txt");
		$this->pause();
	
		$this->requette("echo '$this->root_passwd' | sudo -S chown -R $this->user_local:$this->user_local /opt/cuckoo");
		$this->pause();
		$this->ssTitre("Install pydeep on cuckoo");
		$this->requette("cd /opt/cuckoo/;sudo git clone https://github.com/kbandla/pydeep.git pydeep");
		$this->requette("cd /opt/cuckoo/pydeep;sudo -H python2 setup.py build;sudo -H python2 setup.py test;sudo -H python2 setup.py install");
		$this->pause();
		$this->requette("cd /opt/cuckoo/;sudo -H python2 setup.py build;sudo -H python2 setup.py install");
		$this->pause();
		$this->requette("echo '$this->root_passwd' | sudo -S setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump");
		$this->requette("getcap /usr/sbin/tcpdump");
		$this->pause();
		$this->ssTitre("Install yara on cuckoo");
	
		$this->requette("cd /opt/cuckoo/;sudo git clone https://github.com/plusvic/yara.git yara");
		$this->requette("cd /opt/cuckoo/yara;sudo bash build.sh");
		$this->pause();
		$this->requette("python2 /opt/cuckoo/utils/community.py -wafb monitor");
		$this->pause();
		// useradd : outils non interactifs de création d'un compte d'utilisateur
		$this->cmd("localhost","echo '$this->root_passwd' | sudo -S adduser cuckoo");
		$this->pause();
		$this->requette("echo '$this->root_passwd' | sudo -S chown -R cuckoo:cuckoo /opt/cuckoo");
		
	
		$this->titre("Onto XP Windows");
		$this->ssTitre("Installing python.exe on WindowsXP");
		//$xp3= new VM("xp3");
		//$xp3->vm2upload("$this->dir_install/Win/Exec/Python/python-2.7.10.msi", "$this->vm_tmp_win\\python-2.7.10.msi");
		//$xp3->vm2upload("$this->dir_install/cuckoo/agent.pyw", "C:\Python27\Scripts\\agent.pyw");
		$this->cmd("xp3","reg add \"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\" /f /v \"Agent\" /t REG_SZ /d \"C:\Python27\Scripts\\agent.pyw\"");
		$this->article("run Agent.pyw file in startup process","XP C:\Document and settings\username\StartMenu\Programs\Startup
			Win 7 : C:\Users\Rohff\AppData\Roaming\Microsoft\WIndows\Start Menu\Programs\Startup");
		$this->pause();
		//$xp3->vm2upload("$this->dir_install/cuckoo/agent.pyw", "C:\Documents and Settings\XPSP3\Menu Démarrer\Programmes\Démarrage\\agent.pyw");
		$this->cmd("xp3","C:\> services.msc -> desactiver windows update and firewall");
		$this->pause();
		$this->requette("egrep \"(ip =|internet =|machinery =)\" /opt/cuckoo/conf/cuckoo.conf");
		$this->requette("egrep \"(interface =|vmx_path =|resultserver_ip =|snapshot =|ip =)\" /opt/cuckoo/conf/vmware.conf");
		$this->requette("egrep \"(mongodb)\" /opt/cuckoo/conf/reporting.conf");
		$this->rouge("il ne faut pas que le PATH de la vmx ait un point exp: /home/rohff/EH/VM/vmware/xp3/xp3.vmx -> ne foncitonne pas le mettre dans -> /home/rohff/EH/VM/sdbx_xp3/sdbx_xp3.vmx");
		$this->pause();
		$this->requette("gedit /opt/cuckoo/conf/cuckoo.conf /opt/cuckoo/conf/reporting.conf /opt/cuckoo/conf/vmware.conf");
		$this->pause();
		$this->ssTitre("simulating common internet services");
		$this->article("Linux INetSim"," Linux-based software suite for simulating common internet services. This tool can fake services, allowing you to
analyze the network behaviour of malware samples by emulating services such as DNS, HTTP, HTTPS, FTP, IRC,
SMTP and others");
		$this->pause();
		$this->install_for_sandbox_linux4inetsim();
		$this->pause();
		$this->install_for_sandbox_win();
		$this->pause();
		$this->install_for_sandbox_maltego();
		$this->pause();
	}
	

function vm2process_kill( $pid) {
	$this->ssTitre("Kill Process <$pid> On $this->vmx_path ");
	$check = vm2check_online();
	if ($check == FALSE) {
		$this->vm2start();
		$this->important("Waiting until Vm start");
		return $this->vm2process_kill( $pid);
	}
	
	$this->requette("vmrun -T ws -gu $this->vm_login -gp $this->vm_pass killProcessInGuest $this->dir_vm/$this->vmx_name/$this->vmx_name.vmx $pid");
}

function vm4win2pid($programme_name) {
	$tmp = trim($this->req_ret_str( "echo \"$programme_name\" | grep -Po -i \"[[:print:]]{1,}.exe\" "));
	if (empty($tmp)) {
		$this->important("aucun nom d'executable ...sortie");
		exit ();
	}
	$list_process = $this->vm2process_list ();
	return trim($this->req_ret_str( "cat $list_process | grep -i  \"$programme_name\"   | grep -Po \"pid=[0-9]{1,6}\"  | grep -Po \"[0-9]{1,6}\" "));
}

public function vm2fuzz($fuzz_add, $file_local, $path_remote_file, $ext_file){
	$file_fuzz = new file($file_local);
	$file_dwn = $file_fuzz->fuzz2file($fuzz_add, $ext_file);
	$this->vm2upload($file_dwn, "$path_remote_file.$ext_file");
}

	public function vm4win4pop2ret($rep_path,$prog_name,$dll){
		// 0x00408B44
		// 0x00408d1a
		$dlls = $this->vm2download_dll_programme($rep_path,$prog_name, $dll);
		$this->pause();
		$tab_pop2ret = array();
		
		foreach ($dlls as $tmp_dll){
			$tmp_dll = trim($tmp_dll);
			$bin = new bin4win($tmp_dll);
			$tab_pop = $bin->pe4pop2ret4bin($tmp_dll);
			$this->requette("msfpescan -i $bin->file_path | grep -E -i \"(SEHandler|DllCharacteristics)\" ");
			/*
	 msfpescan -i essfunc.dll | grep -E "SEHandler|DllCharacteristics"
DllCharacteristics           0x00000000

In the output about we don’t see any entries referring to SEHandler. 
This means that there are no registered SEH handlers in the module, and hence, the module was not compiled with the SafeSEH On option. 
In addition, the DllCharacteristics header value shown is all zeros, and this means the module was not compiled with the NO_SEH (the full notation of which is IMAGE_DLLCHARACTERISTICS_NO_SEH) option. 
If the third byte value from the right was 4, 5, 6, 7, C, E, F then this NO_SEH option would be active in this module.

You can refer to the following link for more information on this:
http://msdn.microsoft.com/en-us/library/ms680339%28v=vs.85%29.aspx
			 */
			$tab_pop2ret = array_merge($tab_pop,$tab_pop2ret);
			unset($tab_pop);
			$tab_pop2ret = array_unique($tab_pop2ret);
			array_multisort($tab_pop2ret);
		}
		$file_pop2ret_output = "$rep_path/$prog_name.pop2ret4all.addr";
		$file_pop = fopen($file_pop2ret_output,"w");
		foreach ($tab_pop2ret as $pop)
			fwrite($file_pop, $pop);
		
			fclose($file_pop);
		
	    $this->requette("cat $file_pop2ret_output | grep -v -E \"(00\$|20\$|0a\$)\"  | grep -v -E \"(^0x00|^0x20|^0x0a)\" | grep -v -E \"(00|20|0a)\" | tee $file_pop2ret_output | wc -l");			
		$this->requette("gedit $file_pop2ret_output");
		$this->pause();
		return file($file_pop2ret_output);
	}

function vm2addr4fonction_prog_pid($programme_pid, $fonction) {
	$host = $this->vmx_name;
	$this->ssTitre("Find Addr Fonction: $fonction on $host into pid: $programme_pid");
	$this->vm2exec_prog ("cmd.exe", "/c $this->vm_tmp_win\Debug\\gdb.exe --batch -q -ex \"attach $programme_pid\" -ex \"x/x $fonction\"  > $this->vm_tmp_win\\$programme_pid" . "_$fonction.addr", ""); // C:/TMP
	sleep(1);
	$remote_file = "$this->vm_tmp_win\\$programme_pid" . "_$fonction.addr";
	$dest = "$this->dir_tmp/$programme_pid" . "_$fonction.addr";
	$this->vm2download ($remote_file, $dest);
	$query = "cat $dest";
	$filtre = " | tail -1 | cut -d'x' -f2 | cut -d' ' -f1 ";
	$this->requette($query);
	$fonction_addr = trim($this->req_ret_str( $query . $filtre));
	$fonction_addr = $this->hex2norme_32($fonction_addr);
	$this->article("&$fonction", $fonction_addr);
	return $fonction_addr;
}

function vm2addr4str_prog_pid($programme_pid, $str,$dll) {
	$host = $this->vmx_name;
	$this->ssTitre("Find Addr STRING: $str on $host for DLL:$dll into pid: $programme_pid");
	$this->vm2exec_prog ("cmd.exe", "/c $this->vm_tmp_win\\findit.exe $dll $str  > $this->vm_tmp_win\\$programme_pid" . "_".$str.".$dll.addr", ""); // C:/TMP
	sleep(1);
	$remote_file = "$this->vm_tmp_win\\$programme_pid" . "_".$str.".$dll.addr";
	$dest = "$this->vm_tmp_linux/$programme_pid" . "_".$str.".$dll.addr";
	$this->vm2download ($remote_file, $dest);
	$query = "cat $dest";
	$filtre = " | tail -1 | cut -d'x' -f2 | cut -d' ' -f1 ";
	$this->requette($query);
	$fonction_addr = trim($this->req_ret_str( $query . $filtre));
	$fonction_addr = $this->hex2norme_32($fonction_addr);
	$this->article("&$str", $fonction_addr);
	return $fonction_addr;
}


public function vm4eip($programme_path, $fuzz_add, $file_local, $file_remote,$ext_file) {
	// OK on Host
	// XP: C:\> C:\tmp\tools\gdb.exe --batch -q -ex "run " --args "C:\Program Files\MoviePlay\MoviePlay.exe" "C:\tmp\evil.lst"

	// requette("vmrun -T ws -gu $login -gp $password runProgramInGuest $vmx cmd.exe \"/c cd \ && dir /s /b $programme > \\\"C:\\\\tmp\\\Locate.txt\\\" \" ");exit();
	// $programme_path = "C:\\\Program\ Files\\\\$programme\\\\";
	// $programme_path = "C:\Documents\ and\ Settings\XPSP3\Bureau\ROP_Win\CoolPlayer\ 2.18";

	$file_exe = new file($programme_path);
	$find = FALSE;
	for($i = 4 + $fuzz_add; ! $find; $i = $i + $fuzz_add) {
		$this->vm2fuzz($i,"$this->dir_tmp/Fuzz.$i", "$this->vm_tmp_win\Fuzz.$i",$ext_file);
		// requette("vmrun -T ws -gu $login -gp $password runProgramInGuest $vmx cmd.exe \"/c C:\\\MinGW\\\\bin\\\\gdb.exe --batch -q -ex \\\"run \\\" --args \\\"$programme_path$programme\\\" \\\"$path_remote_file\\\" > \\\"C:\\\TP\\\Eip.txt\\\" \" ");
		// OK
		// requette("vmrun -T ws -gu $login -gp $password runProgramInGuest $vmx C:\TP\Gdb.exe --batch -q -ex \"run \" --args \"C:\TP\Coolplayer.exe\" \"C:\TP\Coolplayer.exe_fuzz_test.m3u\" > \"C:\TP\Eip.txt\" ");
		$args = trim(file_get_contents("$this->dir_tmp/Fuzz.$i.$ext_file"));
		$this->requette("vmrun -T ws -gu $this->vm_login -gp $this->vm_pass runProgramInGuest $this->vmx_path  \"$this->vm_tmp_win\Debug\\gdb.exe\"  --batch -q -ex \"run $args\"  --args \"$file_exe->file_path\" \"$this->vm_tmp_win\Fuzz.$i.$ext_file\" > \"$this->vm_tmp_win\Eip.txt\"  ");
		$this->vm2download("$this->vm_tmp_win\Eip.txt","$this->dir_tmp/Eip.txt");
		
		$tmp_c = $this->req_ret_tab( "cat $this->dir_tmp/Eip.txt | grep 'SIGSEGV';echo ");
		$check = trim($tmp_c [0]);
		if (! empty($check)) {
			$tmp = $this->req_ret_tab( "cat $this->dir_tmp/Eip.txt | grep -Po \"0x[0-9a-fA-F]{7,8}\" | grep -Po \"[0-9a-fA-F]{7,8}\" ");
			$eip_val = $tmp [0];
			unset($tmp);
			$find = TRUE;
		}
	}
	
	//$eip_val = "35724134";$i = "1024";
	$win_offset_eip = $this->offset2eip($eip_val, $i);
	return $win_offset_eip;
}




function vm4jmp2reg($rep_path, $reg, $vmx, $programme, $dll) {

	/*
	 $vmx_name = trim(basename($vmx));
	 $vmx_name = str_replace(".vmx", "", $vmx_name);
	 $vmem_name = trim(basename($programme));
	 $programme_name = trim(basename($programme));
	 */
	 $dll_name = trim(basename($dll));
	 

	$dlls = $this->vm2download_dll_programme($rep_path,$programme, $dll);

	if ($dll == "all") {	
			foreach($dlls as $dll_name){
	$this->requette("msfpescan -j $reg $rep_path/$programme.dll.$dll_name | grep -Po \"0x[0-9a-f-A-F]{6,8}\" | grep -v '00' | grep -v '20' | grep -v '0a' | tee $rep_path/$programme.dll.$dll_name.msfpescan.$reg | wc -l ");
	$this->requette("ropper --jmp $reg --file $rep_path/$programme.dll.$dll_name | grep -Po \"0x[0-9a-f-A-F]{6,8}\" | grep -v '00' | grep -v '20' | grep -v '0a' | tee $rep_path/$programme.dll.$dll_name.ropper.$reg |  wc -l ");
			}
	$this->requette("cat $rep_path/$programme.dll.*.$reg | sort -u | tee $rep_path/$programme.dll.all.$reg | wc -l");		
	} else {
	$this->requette("msfpescan -j $reg $rep_path/$programme.dll.$dll_name | grep -Po \"0x[0-9a-f-A-F]{6,8}\" | grep -v '00' | grep -v '20' | grep -v '0a' | tee $rep_path/$programme.dll.$dll_name.msfpescan.$reg | wc -l ");
    $this->requette("ropper --jmp $reg --file $rep_path/$programme.dll.$dll_name | grep -Po \"0x[0-9a-f-A-F]{6,8}\" | grep -v '00' | grep -v '20' | grep -v '0a' | tee $rep_path/$programme.dll.$dll_name.ropper.$reg |  wc -l ");
	}
	
	$this->requette("cat $rep_path/$programme.dll.$dll_name.msfpescan.$reg $rep_path/$programme.dll.$dll_name.ropper.$reg | sort -u | tee $rep_path/$programme.dll.$dll_name.$reg | wc -l ");
	$this->requette("cat $rep_path/$programme.dll.$dll.$reg | wc -l");
	$this->requette("gedit $rep_path/$programme.dll.$dll.$reg");
	$this->remarque("enlever des $reg dans ce fichier si vous voulez juste qlq exemples");
	return file("$rep_path/$programme.dll.$dll.$reg");
}



function vm2download_dll_programme($rep_path,$programme, $dll) {
	$this->note("check if gdb.exe is installed into folder $this->vm_tmp_win\Win\Debug\\\gdb.exe");
	$tab_dll_name = array ();
		
	$pid = $this->vm4win2pid($programme);
	
	if (empty($pid)) {
		$this->note("Launch $programme before starting");
		sleep(3);
		$this->vm2exec_prog($this->vmx_name, $programme, "", "-noWait");
		
		return $this->vm2download_dll_programme($rep_path,$programme, $dll);
	}
	$this->vm2exec_prog( "cmd.exe", "/c $this->vm_tmp_win"."\Debug\\\gdb.exe --batch -q -ex \"attach $pid\" -ex \"info sharedlibrary\" > $this->vm_tmp_win\\$programme.dlls", "");
	
	// vm2process_kill($pid);
	
	sleep(1);
	$this->vm2download( "$this->vm_tmp_win\\$programme.dlls", "$rep_path/$programme.dlls");
	sleep(1);
	$this->requette("cat $rep_path/$programme.dlls");
	
	if ($dll == "all")
		$this->requette("cat $rep_path/$programme.dlls | sed 's/\"//g' | grep -Po -i \"C:\\\\\\\\[[:print:]]*\" | uniq | tee $rep_path/$programme.dlls.path.lst");
	else
		$this->requette("cat $rep_path/$programme.dlls | sed 's/\"//g' | grep -Po -i \"C:\\\\\\\\[[:print:]]*\" | grep -i '$dll' | uniq | tee $rep_path/$programme.dlls.path.lst");
	
	$this->requette("cat $rep_path/$programme.dlls.path.lst | grep -Po \"[a-z0-9A-Z_-]{1,}\.[0-9a-zA-Z]{1,4}$\" | tee $rep_path/$programme.dlls.name.lst ");	
	$dlls_path = file("$rep_path/$programme.dlls.path.lst");
	$dlls_name = file("$rep_path/$programme.dlls.name.lst");
	
	for($i = 0; $i < count($dlls_path); $i ++) {
		$dll_path = str_replace("\\", "\\\\", $dlls_path [$i]);
		$dll_path = str_replace('\/', '\\', $dlls_path [$i]);
		$dll_path = trim($dll_path);
		// $dll_path = str_replace(' ', '\ ', $dll_path);
		// $this->requette("vmrun -T ws -gu rohff -gp hacker runProgramInGuest $vmx cmd.exe \"/c C:/tmp/findjmp.exe $dll ESP >> $this->vm_tmp_win\\$programme.$dll.esp\" ");
		$dll_path = "$dll_path";
		$dll_path = trim($dll_path);
		$dll_name = $dlls_name [$i];
		$dll_name = trim($dll_name);
		if (! empty($dll_name)) {
			$dll_name_path_local = "$rep_path/$programme.dll.$dll_name";
			$tab_dll_name [] = $dll_name_path_local;
			if (! file_exists($dll_name_path_local))
				$this->vm2download( $dll_path, $dll_name_path_local);
			else
				$this->note("File Already Downloaded: $dll_name_path_local");
		}
	}
	
	$programme_path = $this->vm2pid2path($programme, $pid, $rep_path);
	$prog_name_exe_local = "$rep_path/$programme";
	$tab_dll_name [] = $prog_name_exe_local;
	if (! file_exists($prog_name_exe_local))
		$this->vm2download($programme_path, $prog_name_exe_local);
	else
		$this->note("File Already Downloaded: $prog_name_exe_local");	
	$prog_name_exe_dll = "$rep_path/$programme.dll.$programme";
	system("cp $prog_name_exe_local $prog_name_exe_dll");	
	return $tab_dll_name;
}


function vm2pid2path($programme_name, $programme_pid, $rep_path) {
	$this->vm2exec_prog ("cmd.exe", "/c $this->vm_tmp_win\Debug\\gdb.exe --batch -q -ex \"attach $programme_pid\" -ex \"info files\" > $this->vm_tmp_win\\$programme_name.path", "");
	sleep(1);
	$programme_name_path_local = "$rep_path/$programme_name.path";
	$this->vm2download("$this->vm_tmp_win\\$programme_name.path", $programme_name_path_local);
	$tmp_prog_name = trim($this->req_ret_str( "cat $rep_path/$programme_name.path | grep 'Symbols from' | grep -Po -i \"C:\\\\\\\\[[:print:]]*.exe\" | uniq "));
	$programme_path = str_replace("\\", "\\\\", $tmp_prog_name);
	$programme_path = str_replace('\/', '\\', $tmp_prog_name);
	$programme_path = trim($programme_path);
	return $programme_path;
}


function vm2exec_prog( $cmd, $argv, $options) {
	$check = $this->vm2check_online();
	if ($check == FALSE) {
		$this->vm2start();
		$this->important("Waiting until Vm start");
		return $this->vm2exec_prog( $cmd, $argv, $options);
	}	
	$this->requette("vmrun -T ws -gu $this->vm_login -gp $this->vm_pass runProgramInGuest '$check' $options '$cmd' '$argv' "); // -noWait -activeWindow --display=:0
}


function vm2exec_script( $cmd) {
	$check = $this->vm2check_online();
	if ($check == FALSE) {
		$this->vm2start();
		$this->important("Waiting until Vm start");
		return $this->vm2exec_script( $cmd);
	}	
	$this->requette("vmrun -T ws -gu $this->vm_login -gp $this->vm_pass runScriptInGuest '$check' \"$cmd\" ");
}


function remote_vm2exec_script( $cmd, $argv) {
	$check = $this->vm2check_online();
	if ($check == FALSE) {
		$this->vm2start();
		$this->important("Waiting until Vm start");
		return $this->vm2exec_script( $cmd);
	}
	
	$this->requette("vmrun -T ws -gu '$this->vm_login' -gp '$this->vm_pass' runScriptInGuest '$check' \"$cmd\" \"$argv\" ");
}


function vm2upload( $file, $dest) {
	$this->ssTitre("Uploading $file into $this->vmx_name");
	$check = $this->vm2check_online();
	if ($check == FALSE) {
		$this->vm2start();
		$this->important("Waiting until Vm start");
		return $this->vm2upload( $file, $dest);
	}	
	$file_upload = new file($file);
	$this->requette("vmrun -T ws -gu '$this->vm_login' -gp '$this->vm_pass' copyFileFromHostToGuest '$check' '$file' '$dest' ");
}


function vm2download( $remote_file, $dest) {
	$this->ssTitre("downloading from $this->vmx_path $remote_file to $dest");
	$check = $this->vm2check_online();
	if ($check == FALSE) {
		$this->vm2start();
		$this->important("Waiting until Vm start");
		return $this->vm2download( $remote_file, $dest);
	}
	
	// if(file_exists($dest)) {note("File already exist"); return $dest ;}
	$this->requette("vmrun -T ws -gu $this->vm_login -gp $this->vm_pass copyFileFromGuestToHost '$check' '$remote_file' '$dest'");
	return $dest;
}

function vm2exec_ret( $cmd) {
}

function vm2check_online() {
    $resu_vm = array();
	exec("vmrun -T ws List | grep $this->vmx_name", $resu_vm);
	if (empty($resu_vm [0]))
		return FALSE;
	else
		return TRUE;
}

function vm2start() {
	$this->article("Running VM", "$this->vmx_path ... in progress");
	$this->requette("vmrun -T ws start $this->dir_vm/$this->vmx_name/$this->vmx_name.vmx gui");
	sleep(5);
}

function vm2stop() {
	$this->article("Stop VM", "$this->vmx_path ... in progress");
	$this->requette("vmrun -T ws stop $this->dir_vm/$this->vmx_name/$this->vmx_name.vmx hard");
	sleep(5);
}

function vm2reset() {
	$this->article("Reset VM", "$this->vmx_path ... in progress");
	$this->requette("vmrun -T ws reset $this->dir_vm/$this->vmx_name/$this->vmx_name.vmx soft");
	sleep(5);
}

function vm2suspend() {
	$check = $this->vm2check_online();
	if ($check == FALSE) {
		$this->vm2start();
		$this->important("Waiting until Vm start");
		return $this->vm2suspend();
	}
	$this->article("Suspending VM", "$this->vmx_path ... in progress");
	$this->requette("nautilus $this->dir_vm$this->vm/");
	$this->requette("vmrun -T ws suspend $this->dir_vm/$this->vmx_name/ hard"); // nogui
	sleep(5);
}

function vm2screenshot() {
	$this->ssTitre("Screen Shot");	
	$check = $this->vm2check_online();
	if ($check == FALSE) {
		$this->vm2start();
		$this->important("Waiting until Vm start");
		return $this->vm2screenshot();
	}
	$this->requette("vmrun -T ws -gu $this->vm_login -gp $this->vm_pass captureScreen $this->dir_tmp/$this->vmx_name.png");
	sleep(2);
	$this->img("$this->dir_tmp/$this->vm.png");
}

function vm2snapshot() {
	$this->ssTitre("Snap Shot");	
	$check = $this->vm2check_online();
	if ($check == FALSE) {
		$this->vm2start();
		$this->important("Waiting until $this->vmx_path start");
		return $this->vm2snapshot();
	}
	$this->requette("vmrun -T ws -gu $this->vm_login -gp $this->vm_pass snapshot $check $this->dir_tmp/SnapShot_$this->vmx_name");
}

function vm2revert2snapshot( $snapshot) {
	$this->ssTitre(__FUNCTION__);
	$check = $this->vm2check_online();
	if ($check == FALSE) {
		$this->vm2start();
		$this->important("Waiting until Vm start");
		return $this->vm2revert2snapshot( $snapshot);
	}
	$this->requette("vmrun -T ws revertToSnapshot  $check \"$snapshot\" ");
}

/*
 function win_addr_fonction_prog_path($vmx, $programme_path, $fonction) {
	ssTitre ( "Find Addr Fonction: $fonction on $host into Prog Path: $programme_path" );
	vm_exec_prog ( $host, "cmd.exe", "/c C:\\TMP\\tools\\gdb.exe --batch -q -ex \"r AAAA\" -ex \"x/x $fonction\"  $programme_path > C:/TMP/$programme_name" . "_$fonction.addr", "" );
	sleep ( 1 );
	$remote_file = "C:\TMP\\$programme_name" . "_$fonction.addr";
	$dest = "$dir_tmp/$programme_name" . "_$fonction.addr";
	vm_download ( $host, $remote_file, $dest );
	$query = "cat $dest";
	$filtre = " | tail -1 | cut -d'x' -f2 | cut -d' ' -f1 ";
	requette ( $query );
	$tmp = req_ret ( $query . $filtre );
	$fonction_addr = trim ( $tmp [0] );
	unset ( $tmp );
	$fonction_addr = hex_norme_32 ( $fonction_addr );
	article ( "&$fonction", $fonction_addr );
	return $fonction_addr;
}
function win_addr_fonction_prog_pid($host, $programme_pid, $fonction) {
	global $dir_tmp, $dir_vm;
	ssTitre ( "Find Addr Fonction: $fonction on $host into pid: $programme_pid" );
	vm_exec_prog ( $host, "cmd.exe", "/c C:\\TMP\\tools\\gdb.exe --batch -q -ex \"attach $programme_pid\" -ex \"x/x $fonction\"  > C:/TMP/$programme_pid" . "_$fonction.addr", "" );
	sleep ( 1 );
	$remote_file = "C:\TMP\\$programme_pid" . "_$fonction.addr";
	$dest = "$dir_tmp/$programme_pid" . "_$fonction.addr";
	vm_download ( $host, $remote_file, $dest );
	$query = "cat $dest";
	$filtre = " | tail -1 | cut -d'x' -f2 | cut -d' ' -f1 ";
	requette ( $query );
	$tmp = req_ret ( $query . $filtre );
	$fonction_addr = trim ( $tmp [0] );
	unset ( $tmp );
	$fonction_addr = hex_norme_32 ( $fonction_addr );
	article ( "&$fonction", $fonction_addr );
	return $fonction_addr;
}
function win_search_txt($rep_path, $host, $programme_name, $programme_pid, $search_txt, $dll_search) {
	global $dir_tmp, $dir_tools;
	ssTitre ( "Search Addr of Strings $search_txt into $programme_pid" );
	$dlls = win_get_dlls ( $rep_path, $host, $programme_name, $programme_pid, $dll_search );
	foreach ( $dlls as $dll ) {
		question ( "is there a $search_txt in $dll ?" );
		$flag = prog_content_strings ( "$rep_path/$programme_name.dll.$dll", "| grep -i \"$search_txt\" " );
		if ($flag == TRUE) {
			$dll_start = win_get_dll_start ( $rep_path, $programme_name, $programme_pid, $dll );
			$dll_end = win_get_dll_end ( $rep_path, $programme_name, $programme_pid, $dll );
			vm_exec_prog ( $host, "cmd.exe", "/c C:\\TMP\\tools\\gdb.exe --batch -q -ex \"attach $programme_pid\" -ex \"find  $dll_start,$dll_end,\\\"$search_txt\\\" \"  > C:/TMP/$programme_pid" . "_$search_txt.addr", "" );
			sleep ( 1 );
			$remote_file = "C:\TMP\\$programme_pid" . "_$search_txt.addr";
			$dest = "$rep_path/$programme_name" . "_$search_txt.addr";
			vm_download ( $host, $remote_file, $dest );
			$tmp = req_ret ( "cat $dest | grep -v 'DbgBreakPoint' | grep -Po \"^0x[0-9a-f]{7,8}\" " );
			$cmd = $tmp [0];
			unset ( $tmp );
			$cmd = hex_norme_32 ( $cmd );
			article ( "&$search_txt", $cmd );
			win_hex_symbol ( $rep_path, $host, $cmd, "$programme_name.dll.$dll", $programme_pid );
			$tab_cmd_addr [] = $cmd;
		}
	}
	
	ssTitre ( "Display All $search_txt Addr" );
	if (empty ( $tab_cmd_addr )) {
		important ( "No cmd Addr" );
		return "";
	} else {
		tab ( $tab_cmd_addr );
		foreach ( $tab_cmd_addr as $cmd_addr )
			win_addr2char ( $rep_path, $host, $programme_name, $programme_pid, $cmd_addr, 8 );
		important ( "look \"0 '\\000'\" at the end" );
		return $tab_cmd_addr;
	}
}
function win_get_dll_start($rep_path, $programme_name, $programme_pid, $dll_search) {
	if (! file_exists ( "$rep_path/$programme_name.dlls" ))
		win_get_dlls ( $rep_path, $host, $programme_name, $programme_pid, $dll_search );
	$tmp = req_ret ( "cat $rep_path/$programme_name.dlls | grep '$dll_search' | tail -1 | grep -Po \"^0x[0-9a-f]{7,8}\"  " );
	$dll_start = trim ( $tmp [0] );
	unset ( $tmp );
	return hex_norme_32 ( $dll_start );
}
function win_get_dll_end($rep_path, $programme_name, $programme_pid, $dll_search) {
	if (! file_exists ( "$rep_path/$programme_name.dlls" ))
		win_get_dlls ( $rep_path, $host, $programme_name, $programme_pid, $dll_search );
	$tmp = req_ret ( "cat $rep_path/$programme_name.dlls | grep '$dll_search' | tail -1 | cut -d'x' -f3 | grep -Po \"[0-9a-f]{7,8} \"  " );
	$dll_end = trim ( $tmp [0] );
	unset ( $tmp );
	return hex_norme_32 ( $dll_end );
}
function win_get_dlls($rep_path, $host, $programme_name, $programme_pid, $dll) {
	global $dir_tmp;
	
	if (empty ( $programme_pid )) {
		note ( "Launch $programme before starting" );
		vm_exec_prog ( $vmx_name, $programme, "", "-noWait" );
		sleep ( 3 );
		return vm_download_dll_programme ( $vmx, $login, $password, $programme, $dll );
	}
	vm_exec_prog ( $host, "cmd.exe", "/c C:\\TMP\\tools\\gdb.exe --batch -q -ex \"attach $programme_pid\" -ex \"info sharedlibrary\" > C:/TMP/$programme_name.dlls", "" );
	
	// vm_process_kill($host,$pid);
	
	sleep ( 1 );
	vm_download ( $host, "C:\TMP\\$programme_name.dlls", "$rep_path/$programme_name.dlls" );
	requette ( "cat $rep_path/$programme_name.dlls" );
	
	if ($dll == "all")
		$this->requette ( "cat $rep_path/$programme_name.dlls | sed 's/\"//g' | grep -Po -i \"C:\\\\\\\\[[:print:]]*\" | uniq | tee $rep_path/$programme_name.dlls.path.lst" );
	else
		$this->requette ( "cat $rep_path/$programme_name.dlls | sed 's/\"//g' | grep -Po -i \"C:\\\\\\\\[[:print:]]*\" | grep -i '$dll' | uniq | tee $rep_path/$programme_name.dlls.path.lst" );
	
	requette ( "cat $rep_path/$programme_name.dlls.path.lst | grep -Po \"[a-z0-9A-Z_-]{1,}\.[0-9a-zA-Z]{1,4}$\" | tee $rep_path/$programme_name.dlls.name.lst " );
	
	$dlls_path = file ( "$rep_path/$programme_name.dlls.path.lst" );
	$dlls_name = file ( "$rep_path/$programme_name.dlls.name.lst" );
	
	for($i = 0; $i < count ( $dlls_path ); $i ++) {
		$dll_path = str_replace ( "\\", "\\\\", $dlls_path [$i] );
		$dll_path = str_replace ( '\/', '\\', $dlls_path [$i] );
		$dll_path = trim ( $dll_path );
		// $dll_path = str_replace(' ', '\ ', $dll_path);
		// requette("vmrun -T ws -gu rohff -gp hacker runProgramInGuest $vmx cmd.exe \"/c C:/tmp/findjmp.exe $dll ESP >> C:/tmp/$programme_name.$dll.esp\" ");
		$dll_path = "$dll_path";
		$dll_path = trim ( $dll_path );
		$dll_name = $dlls_name [$i];
		$dll_name = trim ( $dll_name );
		if (! empty ( $dll_name )) {
			$tab_dll_name [] = $dll_name;
			$dll_name_path_local = "$rep_path/$programme_name.dll.$dll_name";
			if (! file_exists ( $dll_name_path_local ))
				vm_download ( $host, $dll_path, $dll_name_path_local );
			else
				note ( "File Already Downloaded: $dll_name_path_local" );
		}
	}
	
	$programme_path = win_pid2path ( $host, $programme_name, $programme_pid, $rep_path );
	$prog_name_exe_local = "$rep_path/$programme_name";
	$tab_dll_name [] = $programme_name;
	if (! file_exists ( $prog_name_exe_local ))
		vm_download ( $host, $programme_path, $prog_name_exe_local );
	else
		note ( "File Already Downloaded: $prog_name_exe_local" );
	
	$prog_name_exe_dll = "$rep_path/$programme_name.dll.$programme_name";
	system ( "cp $prog_name_exe_local $prog_name_exe_dll" );
	
	return $tab_dll_name;
}
function win_pid2path($host, $programme_name, $programme_pid, $rep_path) {
	vm_exec_prog ( $host, "cmd.exe", "/c C:\\TMP\\tools\\gdb.exe --batch -q -ex \"attach $programme_pid\" -ex \"info files\" > C:/TMP/$programme_name.path", "" );
	sleep ( 1 );
	$programme_name_path_local = "$rep_path/$programme_name.path";
	vm_download ( $host, "C:\TMP\\$programme_name.path", $programme_name_path_local );
	$tmp = req_ret ( "cat $rep_path/$programme_name.path | grep 'Symbols from' | grep -Po -i \"C:\\\\\\\\[[:print:]]*.exe\" | uniq " );
	$tmp_prog_name = $tmp [0];
	unset ( $tmp );
	$programme_path = str_replace ( "\\", "\\\\", $tmp_prog_name );
	$programme_path = str_replace ( '\/', '\\', $tmp_prog_name );
	$programme_path = trim ( $programme_path );
	return $programme_path;
}
function win_get_pid($host, $programme_name) {
	exec ( "echo '$programme_name' | grep -Po \"[[:print:]]{1,}.exe\" ", $tmp );
	if (empty ( $tmp )) {
		important ( "aucun nom d'executable ...sortie" );
		exit ();
	}
	$list_process = vm_process_list ( $host );
	$pid_tmp = req_ret ( "cat $list_process | grep -i '$programme_name'   | grep -Po \"pid=[0-9]{1,6}\"  | grep -Po \"[0-9]{1,6}\" " );
	$pid = $pid_tmp [0];
	unset ( $pid_tmp );
	return $pid;
}
function win_hex_symbol($rep_path, $host, $hex, $programme_name, $programme_pid) {
	$hex = hex_norme_32 ( $hex );
	ssTitre ( "Symbol in $hex" );
	vm_exec_prog ( $host, "cmd.exe", "/c C:\\TMP\\tools\\gdb.exe --batch -q -ex \"attach $programme_pid\" -ex \"info symbol $hex\" > C:/TMP/$programme_name" . "_$hex.sym", "" );
	sleep ( 1 );
	$hex_sym = "$rep_path/$programme_name" . "_$hex.sym";
	vm_download ( $host, "C:\TMP\\$programme_name" . "_$hex.sym", $hex_sym );
	return requette ( "cat $hex_sym" );
}
function win_addr2str($rep_path, $host, $programme_name, $programme_pid, $addr) {
	$addr = hex_norme_32 ( $addr );
	ssTitre ( "Strings in $addr" );
	vm_exec_prog ( $host, "cmd.exe", "/c C:\\TMP\\tools\\gdb.exe --batch -q -ex \"attach $programme_pid\" -ex \"x/s $addr\" > C:/TMP/$programme_name" . "_$addr.str", "" );
	sleep ( 1 );
	$addr2str = "$rep_path/$programme_name" . "_$addr.str";
	vm_download ( $host, "C:\TMP\\$programme_name" . "_$addr.str", $addr2str );
	return requette ( "cat $addr2str" );
}
function win_addr2char($rep_path, $host, $programme_name, $programme_pid, $addr, $size_display) {
	$addr = hex_norme_32 ( $addr );
	ssTitre ( "Display in Char MODE on $addr" );
	vm_exec_prog ( $host, "cmd.exe", "/c C:\\TMP\\tools\\gdb.exe --batch -q -ex \"attach $programme_pid\" -ex \"x/$size_display" . "c" . " $addr\" > C:/TMP/$programme_name" . "_$addr.char", "" );
	sleep ( 1 );
	$addr2char = "$rep_path/$programme_name" . "_$addr.char";
	vm_download ( $host, "C:\TMP\\$programme_name" . "_$addr.char", $addr2char );
	return requette ( "cat $addr2char" );
}
function win_get_jmp($rep_path, $reg, $vmx, $login, $pass, $programme, $dll) {
	global $dir_tmp;
	$vmx_name = trim ( basename ( $vmx ) );
	$vmx_name = str_replace ( ".vmx", "", $vmx_name );
	$vmem_name = trim ( basename ( $programme ) );
	$programme_name = trim ( basename ( $programme ) );
	$dll_name = trim ( basename ( $dll ) );
	
	$dlls = vm_download_dll_programme ( $vmx, $login, $pass, $programme, $dll );
	
	if ($dll == "all") {
		if (! file_exists ( "$dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme.dll.all.$reg" )) {
			foreach ( $dlls as $dll_name ) {
				if (! file_exists ( "$dir_tmp/bof.$vmx_name.$vmem_name.rep/$dll_name.msfpescan.$reg" ))
					$this->requette ( "msfpescan -j $reg $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme.dll.$dll_name | grep -Po \"0x[0-9a-f-A-F]{6,8}\" | grep -v '00' | grep -v '20' | grep -v '0a' | tee $dir_tmp/bof.$vmx_name.$vmem_name.rep/$dll_name.msfpescan.$reg | wc -l " );
				if (! file_exists ( "$dir_tmp/bof.$vmx_name.$vmem_name.rep/$dll_name.ropper.$reg" ))
					$this->requette ( "ropper --jmp $reg --file $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme.dll.$dll_name | grep -Po \"0x[0-9a-f-A-F]{6,8}\" | grep -v '00' | grep -v '20' | grep -v '0a' | tee $dir_tmp/bof.$vmx_name.$vmem_name.rep/$dll_name.ropper.$reg |  wc -l " );
				$this->requette ( "cat $dir_tmp/bof.$vmx_name.$vmem_name.rep/$dll_name.msfpescan.$reg $dir_tmp/bof.$vmx_name.$vmem_name.rep/$dll_name.ropper.$reg | sort -u | tee $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme.dll.$dll_name.$reg | wc -l " );
			}
			$this->requette ( "cat $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme.dll.*.$reg | sort -u | tee $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme.dll.all.$reg | wc -l" );
		}
	} else {
		if (! file_exists ( "$dir_tmp/bof.$vmx_name.$vmem_name.rep/$dll_name.msfpescan.$reg" ))
			$this->requette ( "msfpescan -j $reg $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme.dll.$dll_name | grep -Po \"0x[0-9a-f-A-F]{6,8}\" | grep -v '00' | grep -v '20' | grep -v '0a' | tee $dir_tmp/bof.$vmx_name.$vmem_name.rep/$dll_name.msfpescan.$reg | wc -l " );
		if (! file_exists ( "$dir_tmp/bof.$vmx_name.$vmem_name.rep/$dll_name.ropper.$reg" ))
			$this->requette ( "ropper --jmp $reg --file $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme.dll.$dll_name | grep -Po \"0x[0-9a-f-A-F]{6,8}\" | grep -v '00' | grep -v '20' | grep -v '0a' | tee $dir_tmp/bof.$vmx_name.$vmem_name.rep/$dll_name.ropper.$reg |  wc -l " );
		$this->requette ( "cat $dir_tmp/bof.$vmx_name.$vmem_name.rep/$dll_name.msfpescan.$reg $dir_tmp/bof.$vmx_name.$vmem_name.rep/$dll_name.ropper.$reg | sort -u | tee $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme.dll.$dll_name.$reg | wc -l " );
	}
	requette ( "cat $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme.dll.$dll.$reg | wc -l" );
	requette ( "gedit $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme.dll.$dll.$reg" );
	remarque ( "enlever des $reg dans ce fichier si vous voulez juste qlq exemples" );
	return file ( "$dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme.dll.$dll.$reg" );
}
function win_get_jmp_reg_offset($reg, $vmx, $login, $pass, $programme, $dll) {
	global $dir_tmp;
	
	ssTitre ( "GET Local JMP $reg and OFFSET from $programme with specific Library $dll" );
	$vmx_name = trim ( basename ( $vmx ) );
	$vmx_name = str_replace ( ".vmx", "", $vmx_name );
	$vmem_name = trim ( basename ( $programme ) );
	$programme_name = trim ( basename ( $programme ) );
	$dll_name = trim ( basename ( $dll ) );
	
	$dlls = vm_download_dll_programme ( $vmx, $login, $pass, $programme, $dll );
	
	if ($dll == "all") {
		if (! empty ( $dlls ))
			foreach ( $dlls as $dll_path ) {
				$dll_name = trim ( basename ( $dll_path ) );
				$this->requette ( "ropper --nocolor --search \"jmp % [$reg + %]\" --file $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme_name.dll.$dll_path  | grep $reg | sed \"s/ jmp dword ptr \[$reg + //g\" | grep -Po \"^0x[0-9a-fA-F]{7,8}:0x[0-9a-fA-F]{1,}]\" | sed \"s/\]//g\" | grep -v '00' | grep -v '20' | grep -v '0a' | tee $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme_name.dll.$dll_name.jmp.$reg.offset | wc -l " );
			}
		$this->requette ( "ropper --nocolor --search \"jmp % [$reg + %]\" --file $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme  | grep $reg | sed \"s/ jmp dword ptr \[$reg + //g\" | grep -Po \"^0x[0-9a-fA-F]{7,8}:0x[0-9a-fA-F]{1,}]\" | sed \"s/\]//g\" | grep -v '00' | grep -v '20' | grep -v '0a' | tee $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme_name.dll.self.jmp.$reg.offset | wc -l" );
		$this->requette ( "cat $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme_name.dll.*.jmp.$reg.offset | sort -u | tee $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme_name.dll.all.jmp.$reg.offset | wc -l " );
	} else {
		$this->requette ( "ropper --nocolor --search \"jmp % [$reg + %]\" --file $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme_name.dll.$dll | grep $reg | sed \"s/ jmp dword ptr \[$reg + //g\" | grep -Po \"^0x[0-9a-fA-F]{7,8}:0x[0-9a-fA-F]{1,}]\" | sed \"s/\]//g\" | grep -v '00' | grep -v '20' | grep -v '0a' | tee $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme_name.dll.$dll.jmp.$reg.offset | wc -l  " );
	}
	
	requette ( "cat $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme_name.dll.$dll.jmp.$reg.offset | wc -l " );
	requette ( "gedit $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme_name.dll.$dll.jmp.$reg.offset" );
	remarque ( "enlever des $reg dans ce fichier si vous voulez juste qlq exemples" );
	return file ( "$dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme_name.dll.$dll.jmp.$reg.offset" );
}
function win_get_pop1ret($vmx_path, $vmx_login, $vmx_pass, $programme, $dll) {
	global $dir_tmp;
	ssTitre ( "GET POP from $programme with specific Library $dll" );
	
	$vmx_name = trim ( basename ( $vmx_path ) );
	$vmx_name = str_replace ( ".vmx", "", $vmx_name );
	$vmem_name = trim ( basename ( $programme ) );
	$programme_name = trim ( basename ( $programme ) );
	$dll_name = trim ( basename ( $dll ) );
	
	$dlls = vm_download_dll_programme ( $vmx_path, $vmx_login, $vmx_pass, $programme, $dll );
	
	if ($dll == "all") {
		
		if (! empty ( $dlls ))
			foreach ( $dlls as $dll_path ) {
				$dll_name = trim ( basename ( $dll_path ) );
				$this->requette ( "objdump -M intel -d $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme.dll.$dll_path | grep pop -A1 | grep ret -B1 | grep pop | grep -Po \"[0-9a-fA-F]{7,8}\" | sed \"s/^/0x/g\" | grep -v '00' | grep -v '20' | grep -v '0a' | tee $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme_name.pop.ret.$dll_name | wc -l" );
			}
	} else {
		$this->requette ( "objdump -M intel -d $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme.dll.$dll | grep pop -A1 | grep ret -B1 | grep pop | grep -Po \"[0-9a-fA-F]{7,8}\" | sed \"s/^/0x/g\" | grep -v '00' | grep -v '20' | grep -v '0a' | tee $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme_name.pop.ret.$dll_name | wc -l" );
	}
	
	requette ( "objdump -M intel -d $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme | grep pop -A1 | grep ret -B1 | grep pop | grep -Po \"[0-9a-fA-F]{7,8}\" | sed \"s/^/0x/g\" | grep -v '00' | grep -v '20' | grep -v '0a' | tee $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme_name.pop.ret.$programme_name | wc -l" );
	requette ( "cat $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme_name.pop.ret.* | sort -u | tee $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme_name.pop.ret.all | wc -l " );
	
	requette ( "gedit $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme_name.pop.ret.$dll" );
	remarque ( "enlever des POP dans ce fichier si vous voulez juste qlq exemples" );
	return file ( "$dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme_name.pop.ret.$dll" );
}
function win_get_pop2ret($vmx_path, $vmx_login, $vmx_pass, $programme, $dll) {
	global $dir_tmp;
	ssTitre ( "GET POP POP RET from $programme with specific Library $dll" );
	
	$vmx_name = trim ( basename ( $vmx_path ) );
	$vmx_name = str_replace ( ".vmx", "", $vmx_name );
	$vmem_name = trim ( basename ( $programme ) );
	$programme_name = trim ( basename ( $programme ) );
	$dll_name = trim ( basename ( $dll ) );
	
	$dlls = vm_download_dll_programme ( $vmx_path, $vmx_login, $vmx_pass, $programme, $dll );
	
	if ($dll == "all") {
		if (! empty ( $dlls ))
			foreach ( $dlls as $dll_path ) {
				$dll_name = trim ( basename ( $dll_path ) );
				$this->requette ( "msfpescan -p $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme.dll.$dll_path | grep pop  | grep -Po \"0x[0-9a-fA-F]{7,8}\" | grep -v '00' | grep -v '20' | grep -v '0a' | tee $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme_name.pop.pop.ret.$dll_name.msfpescan | wc -l" );
				$this->requette ( "ropper --ppr --file $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme.dll.$dll_path | grep pop  | grep -Po \"0x[0-9a-fA-F]{7,8}\" | grep -v '00' | grep -v '20' | grep -v '0a' | tee $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme_name.pop.pop.ret.$dll_name.ropper | wc -l" );
			}
	} else {
		$this->requette ( "msfpescan -p $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme.dll.$dll | grep pop | grep -Po \"0x[0-9a-fA-F]{7,8}\" | grep -v '00' | grep -v '20' | grep -v '0a' | tee $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme_name.pop.pop.ret.$dll_name.msfpescan | wc -l" );
		$this->requette ( "ropper --ppr --file $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme.dll.$dll_path | grep pop  | grep -Po \"0x[0-9a-fA-F]{7,8}\" | grep -v '00' | grep -v '20' | grep -v '0a' | tee $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme_name.pop.pop.ret.$dll_name.ropper | wc -l" );
	}
	
	requette ( "msfpescan -p $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme.dll.$programme |  grep pop | grep -Po \"0x[0-9a-fA-F]{7,8}\" | grep -v '00' | grep -v '20' | grep -v '0a' | tee $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme_name.pop.pop.ret.$programme_name.msfpescan | wc -l" );
	requette ( "ropper --ppr --file $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme.dll.$dll_path | grep pop  | grep -Po \"0x[0-9a-fA-F]{7,8}\" | grep -v '00' | grep -v '20' | grep -v '0a' | tee $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme_name.pop.pop.ret.$dll_name.ropper | wc -l" );
	
	requette ( "cat $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme_name.pop.pop.ret.* | sort -u | tee $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme_name.pop.pop.ret.all | wc -l " );
	
	requette ( "gedit $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme_name.pop.pop.ret.$dll" );
	remarque ( "enlever des POP dans ce fichier si vous voulez juste qlq exemples" );
	return file ( "$dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme_name.pop.pop.ret.$dll" );
}
function win_get_pop3ret($vmx_path, $vmx_login, $vmx_pass, $programme, $dll) {
	global $dir_tmp;
	ssTitre ( "GET POP POP RET from $programme with specific Library $dll" );
	
	$vmx_name = trim ( basename ( $vmx_path ) );
	$vmx_name = str_replace ( ".vmx", "", $vmx_name );
	$vmem_name = trim ( basename ( $programme ) );
	$programme_name = trim ( basename ( $programme ) );
	$dll_name = trim ( basename ( $dll ) );
	
	$dlls = vm_download_dll_programme ( $vmx_path, $vmx_login, $vmx_pass, $programme, $dll );
	
	if ($dll == "all") {
		if (! empty ( $dlls ))
			foreach ( $dlls as $dll_path ) {
				$dll_name = trim ( basename ( $dll_path ) );
				$this->requette ( "ropper --search \"pop ???; pop ???; pop ???; ret;\" --file  $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme.dll.$dll_path | grep pop  | grep -Po \"0x[0-9a-fA-F]{7,8}\" | grep -v '00' | grep -v '20' | grep -v '0a' | tee $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme_name.pop.pop.pop.ret.$dll_name | wc -l" );
			}
	} else {
		$this->requette ( "ropper --search \"pop ???; pop ???; pop ???; ret;\" --file  $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme.dll.$dll | grep pop | grep -Po \"0x[0-9a-fA-F]{7,8}\" | grep -v '00' | grep -v '20' | grep -v '0a' | tee $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme_name.pop.pop.pop.ret.$dll_name | wc -l" );
	}
	
	requette ( "ropper --search \"pop ???; pop ???; pop ???; ret;\" --file  $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme.dll.$programme |  grep pop | grep -Po \"0x[0-9a-fA-F]{7,8}\" | grep -v '00' | grep -v '20' | grep -v '0a' | tee $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme_name.pop.pop.pop.ret.$programme_name | wc -l" );
	requette ( "cat $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme_name.pop.pop.pop.ret.* | sort -u | tee $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme_name.pop.pop.pop.ret.all | wc -l " );
	
	requette ( "gedit $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme_name.pop.pop.pop.ret.$dll" );
	remarque ( "enlever des POP dans ce fichier si vous voulez juste qlq exemples" );
	return file ( "$dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme_name.pop.pop.pop.ret.$dll" );
}
function win_find_bad_char_exploit($remove_char) {
	$all_asci_char = '\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff';
}
function win_find_bad_char_generate_payload($header, $payload, $footer, $remove_char) {
	global $dir_tmp;
	if (! empty ( $remove_char ))
		$payload = str_replace ( $remove_char, '', $payload );
	requette ( "bash -c \"/bin/echo -e \\\"$header$payload$footer\\\"\" | tee $dir_tmp/badchars.fuzz" );
	return "$dir_tmp/badchars.fuzz";
}
function win_get_pop8ret($vmx_path, $vmx_login, $vmx_pass, $programme, $dll) {
	global $dir_tmp;
	ssTitre ( "GET POPAD RET from $programme with specific Library $dll" );
	
	$vmx_name = trim ( basename ( $vmx_path ) );
	$vmx_name = str_replace ( ".vmx", "", $vmx_name );
	$vmem_name = trim ( basename ( $programme ) );
	$programme_name = trim ( basename ( $programme ) );
	$dll_name = trim ( basename ( $dll ) );
	
	$dlls = vm_download_dll_programme ( $vmx_path, $vmx_login, $vmx_pass, $programme, $dll );
	
	if ($dll == "all") {
		if (! empty ( $dlls ))
			foreach ( $dlls as $dll_path ) {
				$dll_name = trim ( basename ( $dll_path ) );
				$this->requette ( "ropper --search \"popad ret;\" --file  $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme.dll.$dll_path | grep pop  | grep -Po \"0x[0-9a-fA-F]{7,8}\" | grep -v '00' | grep -v '20' | grep -v '0a' | tee $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme_name.popad.ret.$dll_name | wc -l" );
			}
	} else {
		$this->requette ( "ropper --search \"popad ret;\" --file  $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme.dll.$dll | grep pop | grep -Po \"0x[0-9a-fA-F]{7,8}\" | grep -v '00' | grep -v '20' | grep -v '0a' | tee $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme_name.popad.ret.$dll_name | wc -l" );
	}
	
	requette ( "ropper --search \"popad ret;\" --file  $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme.dll.$programme |  grep pop | grep -Po \"0x[0-9a-fA-F]{7,8}\" | grep -v '00' | grep -v '20' | grep -v '0a' | tee $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme_name.popad.ret.$programme_name | wc -l" );
	requette ( "cat $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme_name.popad.ret.* | sort -u | tee $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme_name.popad.ret.all | wc -l " );
	
	requette ( "gedit $dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme_name.popad.ret.$dll" );
	remarque ( "enlever des POP dans ce fichier si vous voulez juste qlq exemples" );
	return file ( "$dir_tmp/bof.$vmx_name.$vmem_name.rep/$programme_name.popad.ret.$dll" );
}





 */
		
		
		
}
?>
